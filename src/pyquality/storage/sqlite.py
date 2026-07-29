"""SQLite-backed state transitions for a single pyquality task repository."""

from __future__ import annotations

import json
import os
import re
import sqlite3
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory
from threading import RLock
from typing import Literal

from pydantic import ConfigDict

from pyquality.domain.models import (
    MAX_ACTION_ARGUMENTS_BYTES,
    MAX_CONFIG_PATTERN_BYTES,
    ApprovalDecision,
    Finding,
    PolicyDecision,
    PolicyOutcome,
    PublicModel,
    TaskResult,
    TaskStatus,
)
from pyquality.storage.local_lock import LocalProjectLock


class StorageStateError(RuntimeError):
    """Raised when persisted state cannot make the requested transition."""


class LeaseRecoveryBlocked(StorageStateError):
    """Raised when durable lease evidence predates the safe lock protocol."""


class _StorageRecord(PublicModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class TaskRecord(_StorageRecord):
    id: str
    project_id: str
    request: str
    status: TaskStatus
    round_limit: int
    deadline: datetime | None
    result: TaskResult | None


class IterationRecord(_StorageRecord):
    id: str
    task_id: str
    sequence: int
    context_digest: str
    action_json: str | None
    policy_outcome: PolicyOutcome | None
    tool_result_digest: str | None
    fingerprint: str | None
    relevant_digest: str | None
    quality_outcome: Literal["passed", "failed", "blocked", "not_run"] | None = None
    created_at: datetime


class FindingRecord(_StorageRecord):
    id: str
    iteration_id: str
    finding: Finding
    created_at: datetime
    resolved_at: datetime | None


class ApprovalRecord(_StorageRecord):
    id: str
    task_id: str
    iteration_id: str
    action_json: str
    action_digest: str
    repository_snapshot_digest: str
    policy_decision: PolicyDecision | None
    decision: ApprovalDecision | None
    execution_state: Literal["pending", "intent_recorded", "completed"]
    expected_after_digests: dict[str, str | None]
    result_digest: str | None
    decided_at: datetime | None
    executed_at: datetime | None


class TransitionIntentRecord(_StorageRecord):
    id: str
    task_id: str
    kind: str
    evidence_digest: str
    summary: str
    state: Literal["pending", "completed"]
    result_digest: str | None
    result_payload: dict[str, object] | None
    completion_summary: str | None
    created_at: datetime
    completed_at: datetime | None
    consumed_at: datetime | None


class DecisionRecord(_StorageRecord):
    id: str
    project_id: str
    scope_type: str
    scope_value: str
    content: str
    source: str
    created_at: datetime
    updated_at: datetime


class RecoverySnapshot(_StorageRecord):
    task: TaskRecord
    iterations: tuple[IterationRecord, ...]
    findings: tuple[FindingRecord, ...]
    decisions: tuple[DecisionRecord, ...]
    pending_approval: ApprovalRecord | None
    decided_approval: ApprovalRecord | None
    executable_approval: ApprovalRecord | None
    transition_intents: tuple[TransitionIntentRecord, ...]


_TERMINAL_STATUSES = frozenset(
    {
        TaskStatus.SUCCEEDED,
        TaskStatus.STALLED,
        TaskStatus.BUDGET_EXHAUSTED,
        TaskStatus.BLOCKED,
        TaskStatus.FAILED,
    }
)
_ALLOWED_TRANSITIONS = {
    TaskStatus.CREATED: frozenset({TaskStatus.RUNNING}),
    TaskStatus.RUNNING: frozenset({TaskStatus.WAITING_APPROVAL, *_TERMINAL_STATUSES}),
    TaskStatus.WAITING_APPROVAL: frozenset({TaskStatus.RUNNING}),
}
_LEASE_PROTOCOL = "os-file-v1"


class SQLiteTaskRepository:
    """Owns atomic persistence of task state and recovery records."""

    def __init__(self, db_path: Path) -> None:
        raw_path = str(db_path)
        self._temporary_lock_directory: TemporaryDirectory[str] | None = None
        if raw_path == ":memory:":
            self._temporary_lock_directory = TemporaryDirectory(
                prefix="pyquality-memory-lease-"
            )
            connection_path: str | Path = ":memory:"
            self._lock_root = Path(self._temporary_lock_directory.name)
        elif raw_path.casefold().startswith("file:"):
            raise StorageStateError("SQLite URI database paths are not supported")
        else:
            connection_path = db_path.resolve(strict=False)
            lock_identity_path = (
                Path(os.path.normcase(str(connection_path)))
                if os.name == "nt"
                else connection_path
            )
            self._lock_root = (
                lock_identity_path.parent
                / f".{lock_identity_path.name}.lease-locks"
            )
        self._held_leases: dict[str, tuple[str, str, LocalProjectLock]] = {}
        self._connection_lock = RLock()
        self._connection = sqlite3.connect(
            connection_path, isolation_level=None, check_same_thread=False
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA journal_mode = WAL")
        self._create_schema()

    def create_task(
        self,
        canonical_path: str,
        request: str,
        round_limit: int,
        deadline: datetime | None = None,
    ) -> TaskRecord:
        project_id = _new_id()
        task_id = _new_id()
        created_at = _utc_now()
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT id FROM projects WHERE canonical_path = ?", (canonical_path,)
            ).fetchone()
            if row is not None:
                project_id = row["id"]
            else:
                connection.execute(
                    "INSERT INTO projects (id, canonical_path, created_at) VALUES (?, ?, ?)",
                    (project_id, canonical_path, _dump_datetime(created_at)),
                )
            connection.execute(
                """INSERT INTO tasks
                   (id, project_id, request, status, round_limit, deadline, result_json, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, NULL, ?)""",
                (
                    task_id,
                    project_id,
                    request,
                    TaskStatus.CREATED.value,
                    round_limit,
                    _dump_datetime(deadline),
                    _dump_datetime(created_at),
                ),
            )
        return TaskRecord(
            id=task_id,
            project_id=project_id,
            request=request,
            status=TaskStatus.CREATED,
            round_limit=round_limit,
            deadline=deadline,
            result=None,
        )

    def append_iteration(
        self,
        task_id: str,
        *,
        sequence: int,
        context_digest: str,
        action_json: str | None = None,
        policy_outcome: PolicyOutcome | None = None,
        tool_result_digest: str | None = None,
        fingerprint: str | None = None,
        relevant_digest: str | None = None,
        quality_outcome: Literal["passed", "failed", "blocked", "not_run"] | None = None,
        findings: tuple[Finding, ...] = (),
        source_intent_ids: tuple[str, ...] = (),
        owner_token: str | None = None,
    ) -> IterationRecord:
        iteration_id = _new_id()
        created_at = _utc_now()
        normalized_action = _canonical_json(action_json) if action_json is not None else None
        with self._transaction() as connection:
            self._require_task(connection, task_id)
            if source_intent_ids:
                self._require_running_lease(connection, task_id, owner_token)
            try:
                connection.execute(
                    """INSERT INTO iterations
                       (id, task_id, sequence, context_digest, action_json, policy_outcome,
                        tool_result_digest, fingerprint, relevant_digest, quality_outcome, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        iteration_id,
                        task_id,
                        sequence,
                        context_digest,
                        normalized_action,
                        policy_outcome.value if policy_outcome is not None else None,
                        tool_result_digest,
                        fingerprint,
                        relevant_digest,
                        quality_outcome,
                        _dump_datetime(created_at),
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise StorageStateError("iteration sequence already exists") from error
            for finding in findings:
                finding_created_at = _utc_now()
                connection.execute(
                    """INSERT INTO findings
                       (id, iteration_id, payload_json, created_at, resolved_at)
                       VALUES (?, ?, ?, ?, NULL)""",
                    (
                        _new_id(),
                        iteration_id,
                        _canonical_json(finding.model_dump(mode="json")),
                        _dump_datetime(finding_created_at),
                    ),
                )
            self._consume_transition_intents(
                connection, task_id, source_intent_ids
            )
        return IterationRecord(
            id=iteration_id,
            task_id=task_id,
            sequence=sequence,
            context_digest=context_digest,
            action_json=normalized_action,
            policy_outcome=policy_outcome,
            tool_result_digest=tool_result_digest,
            fingerprint=fingerprint,
            relevant_digest=relevant_digest,
            quality_outcome=quality_outcome,
            created_at=created_at,
        )

    def set_status(
        self,
        task_id: str,
        expected: TaskStatus,
        new: TaskStatus,
        result: TaskResult | None = None,
        *,
        owner_token: str | None = None,
    ) -> bool:
        release_local = False
        with self._transaction() as connection:
            current = connection.execute("SELECT status FROM tasks WHERE id = ?", (task_id,)).fetchone()
            if current is None or current["status"] != expected.value:
                return False
            if expected is TaskStatus.RUNNING:
                self._require_running_lease(connection, task_id, owner_token)
            if new not in _ALLOWED_TRANSITIONS.get(expected, frozenset()):
                raise StorageStateError(f"illegal task transition: {expected.value} -> {new.value}")
            if result is not None and result.status is not new:
                raise StorageStateError("task result status does not match transition")
            cursor = connection.execute(
                "UPDATE tasks SET status = ?, result_json = ? WHERE id = ? AND status = ?",
                (
                    new.value,
                    _canonical_json(result.model_dump(mode="json")) if result is not None else None,
                    task_id,
                    expected.value,
                ),
            )
            if cursor.rowcount == 0:
                return False
            if new in _TERMINAL_STATUSES or new is TaskStatus.WAITING_APPROVAL:
                connection.execute(
                    "DELETE FROM project_leases WHERE task_id = ? AND owner_token = ?",
                    (task_id, owner_token),
                )
                release_local = owner_token is not None
        if release_local:
            self._release_local_lease(owner_token)
        return True

    def complete_iteration_outcome(
        self,
        task_id: str,
        iteration_id: str,
        *,
        tool_result_digest: str,
        fingerprint: str | None,
        relevant_digest: str | None,
        quality_outcome: Literal["passed", "failed", "blocked", "not_run"],
        findings: tuple[Finding, ...] = (),
        source_intent_ids: tuple[str, ...] = (),
        owner_token: str | None = None,
    ) -> IterationRecord:
        _require_digest(tool_result_digest, "tool_result_digest")
        if fingerprint is not None:
            _require_digest(fingerprint, "fingerprint")
        if relevant_digest is not None:
            _require_digest(relevant_digest, "relevant_digest")
        expected_findings = tuple(
            _canonical_json(finding.model_dump(mode="json")) for finding in findings
        )
        with self._transaction() as connection:
            row = self._require_iteration(connection, task_id, iteration_id)
            self._require_running_lease(connection, task_id, owner_token)
            existing_findings = tuple(
                item["payload_json"]
                for item in connection.execute(
                    "SELECT payload_json FROM findings WHERE iteration_id = ? ORDER BY created_at, id",
                    (iteration_id,),
                )
            )
            existing = (
                row["tool_result_digest"],
                row["fingerprint"],
                row["relevant_digest"],
                row["quality_outcome"],
                existing_findings,
            )
            proposed = (
                tool_result_digest,
                fingerprint,
                relevant_digest,
                quality_outcome,
                expected_findings,
            )
            if any(value is not None for value in existing[:4]) or existing_findings:
                if existing != proposed:
                    raise StorageStateError("iteration outcome is already completed")
                return _iteration_from_row(row)
            connection.execute(
                """UPDATE iterations
                   SET tool_result_digest = ?, fingerprint = ?, relevant_digest = ?,
                       quality_outcome = ? WHERE id = ? AND task_id = ?""",
                (
                    tool_result_digest,
                    fingerprint,
                    relevant_digest,
                    quality_outcome,
                    iteration_id,
                    task_id,
                ),
            )
            for payload in expected_findings:
                connection.execute(
                    """INSERT INTO findings
                       (id, iteration_id, payload_json, created_at, resolved_at)
                       VALUES (?, ?, ?, ?, NULL)""",
                    (_new_id(), iteration_id, payload, _dump_datetime(_utc_now())),
                )
            self._consume_transition_intents(
                connection, task_id, source_intent_ids
            )
        return self._iteration_by_id(iteration_id)

    def consume_intents_for_completed_iteration(
        self,
        task_id: str,
        iteration_id: str,
        *,
        source_intent_ids: tuple[str, ...],
        owner_token: str,
    ) -> None:
        """Atomically reconcile leftover intents into an already-saved outcome."""
        if not source_intent_ids:
            return
        with self._transaction() as connection:
            row = self._require_iteration(connection, task_id, iteration_id)
            self._require_running_lease(connection, task_id, owner_token)
            if row["tool_result_digest"] is None or row["quality_outcome"] is None:
                raise StorageStateError(
                    "transition intents require a completed iteration outcome"
                )
            self._consume_transition_intents(
                connection, task_id, source_intent_ids
            )

    def record_approval(
        self,
        task_id: str,
        iteration_id: str,
        action_json: str,
        action_digest: str,
        repository_snapshot_digest: str,
        *,
        policy_decision: PolicyDecision | None = None,
    ) -> ApprovalRecord:
        _require_digest(action_digest, "action_digest")
        _require_digest(repository_snapshot_digest, "repository_snapshot_digest")
        if policy_decision is not None and (
            policy_decision.action_digest != action_digest
            or policy_decision.repository_snapshot_digest != repository_snapshot_digest
        ):
            raise StorageStateError("policy decision does not match approval digests")
        approval_id = _new_id()
        normalized_action = _bounded_action_json(action_json)
        with self._transaction() as connection:
            self._require_iteration(connection, task_id, iteration_id)
            connection.execute(
                """INSERT INTO approvals
                   (id, task_id, iteration_id, action_json, action_digest, repository_snapshot_digest,
                    policy_decision_json, decision, execution_state, expected_after_digests_json,
                    result_digest, decided_at, executed_at, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, NULL, 'pending', '{}', NULL, NULL, NULL, ?)""",
                (
                    approval_id,
                    task_id,
                    iteration_id,
                    normalized_action,
                    action_digest,
                    repository_snapshot_digest,
                    _canonical_json(policy_decision.model_dump(mode="json"))
                    if policy_decision is not None
                    else None,
                    _dump_datetime(_utc_now()),
                ),
            )
        return self._approval_by_id(approval_id)

    def request_approval_and_wait(
        self,
        task_id: str,
        iteration_id: str,
        action_json: str,
        action_digest: str,
        repository_snapshot_digest: str,
        *,
        policy_decision: PolicyDecision,
        waiting_result: TaskResult,
        owner_token: str,
    ) -> ApprovalRecord:
        """Atomically create one approval, enter WAITING, and release its owner lease."""
        _require_digest(action_digest, "action_digest")
        _require_digest(repository_snapshot_digest, "repository_snapshot_digest")
        _require_owner_token(owner_token)
        if waiting_result.status is not TaskStatus.WAITING_APPROVAL:
            raise StorageStateError("approval result must be waiting")
        if waiting_result.task_id != task_id:
            raise StorageStateError("approval result belongs to another task")
        if (
            policy_decision.action_digest != action_digest
            or policy_decision.repository_snapshot_digest != repository_snapshot_digest
        ):
            raise StorageStateError("policy decision does not match approval digests")
        approval_id = _new_id()
        normalized_action = _bounded_action_json(action_json)
        try:
            with self._transaction() as connection:
                self._require_iteration(connection, task_id, iteration_id)
                self._require_running_lease(connection, task_id, owner_token)
                connection.execute(
                    """INSERT INTO approvals
                       (id, task_id, iteration_id, action_json, action_digest,
                        repository_snapshot_digest, policy_decision_json, decision,
                        execution_state, expected_after_digests_json, result_digest,
                        decided_at, executed_at, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, NULL, 'pending', '{}', NULL,
                               NULL, NULL, ?)""",
                    (
                        approval_id,
                        task_id,
                        iteration_id,
                        normalized_action,
                        action_digest,
                        repository_snapshot_digest,
                        _canonical_json(policy_decision.model_dump(mode="json")),
                        _dump_datetime(_utc_now()),
                    ),
                )
                cursor = connection.execute(
                    """UPDATE tasks SET status = ?, result_json = ?
                       WHERE id = ? AND status = ?""",
                    (
                        TaskStatus.WAITING_APPROVAL.value,
                        _canonical_json(waiting_result.model_dump(mode="json")),
                        task_id,
                        TaskStatus.RUNNING.value,
                    ),
                )
                if cursor.rowcount != 1:
                    raise StorageStateError("approval transition lost compare-and-set")
                connection.execute(
                    "DELETE FROM project_leases WHERE task_id = ? AND owner_token = ?",
                    (task_id, owner_token),
                )
        except sqlite3.Error as error:
            raise StorageStateError("approval transition failed") from error
        self._release_local_lease(owner_token)
        return self._approval_by_id(approval_id)

    def request_approval_round_and_wait(
        self,
        task_id: str,
        sequence: int,
        context_digest: str,
        action_json: str,
        action_digest: str,
        repository_snapshot_digest: str,
        *,
        policy_decision: PolicyDecision,
        waiting_result: TaskResult,
        source_intent_ids: tuple[str, ...],
        owner_token: str,
    ) -> ApprovalRecord:
        """Persist the model round, approval, wait result, and lease release atomically."""
        _require_digest(context_digest, "context_digest")
        _require_digest(action_digest, "action_digest")
        _require_digest(repository_snapshot_digest, "repository_snapshot_digest")
        _require_owner_token(owner_token)
        if waiting_result.status is not TaskStatus.WAITING_APPROVAL:
            raise StorageStateError("approval result must be waiting")
        if waiting_result.task_id != task_id:
            raise StorageStateError("approval result belongs to another task")
        if (
            policy_decision.action_digest != action_digest
            or policy_decision.repository_snapshot_digest
            != repository_snapshot_digest
        ):
            raise StorageStateError("policy decision does not match approval digests")
        approval_id = _new_id()
        iteration_id = _new_id()
        normalized_action = _bounded_action_json(action_json)
        try:
            with self._transaction() as connection:
                self._require_running_lease(connection, task_id, owner_token)
                connection.execute(
                    """INSERT INTO iterations
                       (id, task_id, sequence, context_digest, action_json, policy_outcome,
                        tool_result_digest, fingerprint, relevant_digest, quality_outcome,
                        created_at)
                       VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, ?)""",
                    (
                        iteration_id,
                        task_id,
                        sequence,
                        context_digest,
                        normalized_action,
                        policy_decision.outcome.value,
                        _dump_datetime(_utc_now()),
                    ),
                )
                self._consume_transition_intents(
                    connection, task_id, source_intent_ids
                )
                connection.execute(
                    """INSERT INTO approvals
                       (id, task_id, iteration_id, action_json, action_digest,
                        repository_snapshot_digest, policy_decision_json, decision,
                        execution_state, expected_after_digests_json, result_digest,
                        decided_at, executed_at, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, NULL, 'pending', '{}', NULL,
                               NULL, NULL, ?)""",
                    (
                        approval_id,
                        task_id,
                        iteration_id,
                        normalized_action,
                        action_digest,
                        repository_snapshot_digest,
                        _canonical_json(policy_decision.model_dump(mode="json")),
                        _dump_datetime(_utc_now()),
                    ),
                )
                cursor = connection.execute(
                    """UPDATE tasks SET status = ?, result_json = ?
                       WHERE id = ? AND status = ?""",
                    (
                        TaskStatus.WAITING_APPROVAL.value,
                        _canonical_json(waiting_result.model_dump(mode="json")),
                        task_id,
                        TaskStatus.RUNNING.value,
                    ),
                )
                if cursor.rowcount != 1:
                    raise StorageStateError("approval transition lost compare-and-set")
                connection.execute(
                    "DELETE FROM project_leases WHERE task_id = ? AND owner_token = ?",
                    (task_id, owner_token),
                )
        except sqlite3.Error as error:
            raise StorageStateError("approval round transition failed") from error
        self._release_local_lease(owner_token)
        return self._approval_by_id(approval_id)

    def replace_approval_and_wait(
        self,
        approval_id: str,
        policy_decision: PolicyDecision,
        *,
        waiting_result: TaskResult,
        owner_token: str,
    ) -> ApprovalRecord:
        """Atomically retire an approved proposal and bind its replacement wait."""
        _require_owner_token(owner_token)
        if waiting_result.status is not TaskStatus.WAITING_APPROVAL:
            raise StorageStateError("approval result must be waiting")
        replacement_id = _new_id()
        try:
            with self._transaction() as connection:
                current = self._require_approval(connection, approval_id)
                if (
                    current["decision"] != ApprovalDecision.APPROVE.value
                    or current["execution_state"] != "pending"
                ):
                    raise StorageStateError("approval cannot be replaced")
                task_id = current["task_id"]
                self._require_running_lease(connection, task_id, owner_token)
                if waiting_result.task_id != task_id:
                    raise StorageStateError("approval result belongs to another task")
                if policy_decision.action_digest != current["action_digest"]:
                    raise StorageStateError("replacement action digest changed")
                connection.execute(
                    """UPDATE approvals SET execution_state = 'completed', executed_at = ?
                       WHERE id = ?""",
                    (_dump_datetime(_utc_now()), approval_id),
                )
                connection.execute(
                    """INSERT INTO approvals
                       (id, task_id, iteration_id, action_json, action_digest,
                        repository_snapshot_digest, policy_decision_json, decision,
                        execution_state, expected_after_digests_json, result_digest,
                        decided_at, executed_at, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, NULL, 'pending', '{}', NULL,
                               NULL, NULL, ?)""",
                    (
                        replacement_id,
                        task_id,
                        current["iteration_id"],
                        current["action_json"],
                        policy_decision.action_digest,
                        policy_decision.repository_snapshot_digest,
                        _canonical_json(policy_decision.model_dump(mode="json")),
                        _dump_datetime(_utc_now()),
                    ),
                )
                cursor = connection.execute(
                    """UPDATE tasks SET status = ?, result_json = ?
                       WHERE id = ? AND status = ?""",
                    (
                        TaskStatus.WAITING_APPROVAL.value,
                        _canonical_json(waiting_result.model_dump(mode="json")),
                        task_id,
                        TaskStatus.RUNNING.value,
                    ),
                )
                if cursor.rowcount != 1:
                    raise StorageStateError("replacement transition lost compare-and-set")
                connection.execute(
                    "DELETE FROM project_leases WHERE task_id = ? AND owner_token = ?",
                    (task_id, owner_token),
                )
        except sqlite3.Error as error:
            raise StorageStateError("replacement approval transition failed") from error
        self._release_local_lease(owner_token)
        return self._approval_by_id(replacement_id)

    def pending_approval(self, task_id: str) -> ApprovalRecord | None:
        row = self._connection.execute(
            """SELECT approvals.* FROM approvals
               JOIN tasks ON tasks.id = approvals.task_id
               WHERE approvals.task_id = ? AND approvals.decision IS NULL
                 AND tasks.status = ?
               ORDER BY approvals.created_at DESC, approvals.id DESC LIMIT 1""",
            (task_id, TaskStatus.WAITING_APPROVAL.value),
        ).fetchone()
        return _approval_from_row(row) if row is not None else None

    def decide_approval(self, approval_id: str, decision: ApprovalDecision) -> ApprovalRecord:
        decided_at = _utc_now()
        with self._transaction() as connection:
            row = self._require_approval(connection, approval_id)
            status = connection.execute(
                "SELECT status FROM tasks WHERE id = ?", (row["task_id"],)
            ).fetchone()["status"]
            if TaskStatus(status) in _TERMINAL_STATUSES or row["decision"] is not None:
                raise StorageStateError("approval cannot be decided")
            connection.execute(
                "UPDATE approvals SET decision = ?, decided_at = ? WHERE id = ?",
                (decision.value, _dump_datetime(decided_at), approval_id),
            )
        return self._approval_by_id(approval_id)

    def decide_approval_and_resume(
        self, approval_id: str, decision: ApprovalDecision
    ) -> ApprovalRecord:
        """Atomically consume one waiting approval and return its task to RUNNING."""
        decided_at = _utc_now()
        with self._transaction() as connection:
            row = self._require_approval(connection, approval_id)
            task = self._require_task(connection, row["task_id"])
            if row["decision"] is not None or task["status"] != TaskStatus.WAITING_APPROVAL.value:
                raise StorageStateError("approval cannot be decided")
            connection.execute(
                "UPDATE approvals SET decision = ?, decided_at = ? WHERE id = ?",
                (decision.value, _dump_datetime(decided_at), approval_id),
            )
            connection.execute(
                """UPDATE tasks SET status = ?, result_json = NULL
                   WHERE id = ? AND status = ?""",
                (
                    TaskStatus.RUNNING.value,
                    row["task_id"],
                    TaskStatus.WAITING_APPROVAL.value,
                ),
            )
        return self._approval_by_id(approval_id)

    def mark_execution_intent(
        self,
        approval_id: str,
        *,
        expected_after_digests: dict[str, str | None] | None = None,
        owner_token: str | None = None,
    ) -> ApprovalRecord:
        normalized_digests = _validated_path_digests(expected_after_digests or {})
        with self._transaction() as connection:
            row = self._require_approval(connection, approval_id)
            if row["decision"] != ApprovalDecision.APPROVE.value or row["execution_state"] != "pending":
                raise StorageStateError("approval is not ready for execution intent")
            self._require_running_lease(connection, row["task_id"], owner_token)
            action = json.loads(row["action_json"])
            if action.get("kind") == "apply_patch" and not normalized_digests:
                raise StorageStateError("patch approval requires non-empty expected effect evidence")
            connection.execute(
                """UPDATE approvals
                   SET execution_state = 'intent_recorded', expected_after_digests_json = ?
                   WHERE id = ?""",
                (_canonical_json(normalized_digests), approval_id),
            )
        return self._approval_by_id(approval_id)

    def mark_execution_completed(
        self,
        approval_id: str,
        *,
        result_digest: str | None = None,
        source_intent_ids: tuple[str, ...] = (),
        owner_token: str | None = None,
    ) -> ApprovalRecord:
        if result_digest is not None:
            _require_digest(result_digest, "result_digest")
        executed_at = _utc_now()
        with self._transaction() as connection:
            row = self._require_approval(connection, approval_id)
            if (
                row["decision"] != ApprovalDecision.APPROVE.value
                or row["execution_state"] != "intent_recorded"
            ):
                raise StorageStateError("approval execution intent is not recorded")
            self._require_running_lease(connection, row["task_id"], owner_token)
            connection.execute(
                """UPDATE approvals
                   SET execution_state = 'completed', result_digest = ?, executed_at = ?
                   WHERE id = ?""",
                (result_digest, _dump_datetime(executed_at), approval_id),
            )
            self._consume_transition_intents(
                connection, row["task_id"], source_intent_ids
            )
        return self._approval_by_id(approval_id)

    def mark_rejection_consumed(
        self,
        approval_id: str,
        *,
        finding: Finding | None = None,
        owner_token: str | None = None,
    ) -> ApprovalRecord:
        consumed_at = _utc_now()
        with self._transaction() as connection:
            row = self._require_approval(connection, approval_id)
            if (
                row["decision"] != ApprovalDecision.REJECT.value
                or row["execution_state"] != "pending"
            ):
                raise StorageStateError("rejected approval is not ready to be consumed")
            self._require_running_lease(connection, row["task_id"], owner_token)
            connection.execute(
                """UPDATE approvals
                   SET execution_state = 'completed', executed_at = ? WHERE id = ?""",
                (_dump_datetime(consumed_at), approval_id),
            )
            if finding is not None:
                connection.execute(
                    """INSERT INTO findings
                       (id, iteration_id, payload_json, created_at, resolved_at)
                       VALUES (?, ?, ?, ?, NULL)""",
                    (
                        _new_id(),
                        row["iteration_id"],
                        _canonical_json(finding.model_dump(mode="json")),
                        _dump_datetime(consumed_at),
                    ),
                )
        return self._approval_by_id(approval_id)

    def record_transition_intent(
        self,
        task_id: str,
        *,
        kind: str,
        evidence_digest: str,
        summary: str,
        owner_token: str | None = None,
    ) -> TransitionIntentRecord:
        _require_transition_text(kind, 64, "kind")
        _require_transition_text(summary, 1_024, "summary")
        _require_digest(evidence_digest, "evidence_digest")
        intent_id = _new_id()
        created_at = _utc_now()
        with self._transaction() as connection:
            self._require_running_lease(connection, task_id, owner_token)
            connection.execute(
                """INSERT INTO transition_intents
                   (id, task_id, kind, evidence_digest, summary, state, result_digest,
                    completion_summary, created_at, completed_at)
                   VALUES (?, ?, ?, ?, ?, 'pending', NULL, NULL, ?, NULL)""",
                (
                    intent_id,
                    task_id,
                    kind,
                    evidence_digest,
                    summary,
                    _dump_datetime(created_at),
                ),
            )
        return self._transition_intent_by_id(intent_id)

    def complete_transition_intent(
        self,
        intent_id: str,
        *,
        result_digest: str,
        summary: str,
        result_payload: dict[str, object] | None = None,
        owner_token: str | None = None,
    ) -> TransitionIntentRecord:
        _require_digest(result_digest, "result_digest")
        _require_transition_text(summary, 1_024, "summary")
        payload_json = _bounded_payload_json(result_payload)
        completed_at = _utc_now()
        with self._transaction() as connection:
            row = self._require_transition_intent(connection, intent_id)
            if row["state"] != "pending":
                raise StorageStateError("transition intent is already completed")
            self._require_running_lease(connection, row["task_id"], owner_token)
            connection.execute(
                """UPDATE transition_intents
                   SET state = 'completed', result_digest = ?, result_payload_json = ?,
                       completion_summary = ?, completed_at = ? WHERE id = ?""",
                (
                    result_digest,
                    payload_json,
                    summary,
                    _dump_datetime(completed_at),
                    intent_id,
                ),
            )
        return self._transition_intent_by_id(intent_id)

    def close(self) -> None:
        try:
            for owner_token in tuple(self._held_leases):
                self._release_local_lease(owner_token)
        finally:
            try:
                self._connection.close()
            finally:
                if self._temporary_lock_directory is not None:
                    self._temporary_lock_directory.cleanup()
                    self._temporary_lock_directory = None

    def fail_inconsistent_task(self, task_id: str, summary: str) -> TaskResult:
        """Durably fail a task whose typed snapshot cannot be reconstructed."""
        _require_transition_text(summary, 1_024, "summary")
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT id FROM tasks WHERE id = ?", (task_id,)
            ).fetchone()
            if row is None:
                raise StorageStateError("task does not exist")
            iterations = connection.execute(
                "SELECT COUNT(*) AS count FROM iterations WHERE task_id = ?", (task_id,)
            ).fetchone()["count"]
            result = TaskResult(
                task_id=task_id,
                status=TaskStatus.FAILED,
                iterations=iterations,
                verification_summary=summary,
            )
            connection.execute(
                """UPDATE tasks SET status = ?, result_json = ?, deadline = NULL
                   WHERE id = ?""",
                (
                    TaskStatus.FAILED.value,
                    _canonical_json(result.model_dump(mode="json")),
                    task_id,
                ),
            )
            connection.execute("DELETE FROM project_leases WHERE task_id = ?", (task_id,))
        self._release_local_leases_for_task(task_id)
        return result

    def acquire_project_lease(self, task_id: str, *, owner_token: str) -> bool:
        _require_owner_token(owner_token)
        held = self._held_leases.get(owner_token)
        if held is not None:
            return held[1] == task_id

        task = self._require_task(self._connection, task_id)
        if task["status"] != TaskStatus.RUNNING.value:
            raise StorageStateError("only running tasks can acquire a project lease")
        project_id = task["project_id"]
        local_lock = LocalProjectLock.try_acquire(self._lock_root, project_id)
        if local_lock is None:
            return False
        try:
            with self._transaction() as connection:
                task = self._require_task(connection, task_id)
                if task["status"] != TaskStatus.RUNNING.value:
                    raise StorageStateError(
                        "only running tasks can acquire a project lease"
                    )
                row = connection.execute(
                    """SELECT project_leases.*, tasks.status AS leased_task_status
                       FROM project_leases
                       JOIN tasks ON tasks.id = project_leases.task_id
                       WHERE project_leases.project_id = ?""",
                    (project_id,),
                ).fetchone()
                if row is not None and row["protocol"] != _LEASE_PROTOCOL:
                    if row["leased_task_status"] == TaskStatus.RUNNING.value:
                        raise LeaseRecoveryBlocked(
                            "legacy project lease blocks safe takeover; manual recovery "
                            "is required after confirming no runner is live"
                        )
                    connection.execute(
                        "DELETE FROM project_leases WHERE project_id = ?", (project_id,)
                    )
                    row = None
                if row is not None and row["task_id"] != task_id:
                    if row["leased_task_status"] == TaskStatus.RUNNING.value:
                        raise LeaseRecoveryBlocked(
                            "another RUNNING task has durable lease evidence; manual "
                            "recovery is required after confirming it is abandoned"
                        )
                    connection.execute(
                        "DELETE FROM project_leases WHERE project_id = ?", (project_id,)
                    )
                    row = None
                if row is None:
                    connection.execute(
                        """INSERT INTO project_leases
                           (project_id, task_id, owner_token, acquired_at, protocol)
                           VALUES (?, ?, ?, ?, ?)""",
                        (
                            project_id,
                            task_id,
                            owner_token,
                            _dump_datetime(_utc_now()),
                            _LEASE_PROTOCOL,
                        ),
                    )
                else:
                    connection.execute(
                        """UPDATE project_leases
                           SET owner_token = ?, acquired_at = ?, protocol = ?
                           WHERE project_id = ? AND task_id = ?""",
                        (
                            owner_token,
                            _dump_datetime(_utc_now()),
                            _LEASE_PROTOCOL,
                            project_id,
                            task_id,
                        ),
                    )
            self._held_leases[owner_token] = (project_id, task_id, local_lock)
            return True
        except Exception:
            local_lock.release()
            raise

    def release_project_lease(self, task_id: str, *, owner_token: str) -> None:
        _require_owner_token(owner_token)
        try:
            with self._transaction() as connection:
                connection.execute(
                    """DELETE FROM project_leases
                       WHERE task_id = ? AND owner_token = ? AND protocol = ?""",
                    (task_id, owner_token, _LEASE_PROTOCOL),
                )
        finally:
            self._release_local_lease(owner_token)

    def owns_project_lease(self, task_id: str, *, owner_token: str) -> bool:
        """Confirm the caller owns both durable evidence and the live kernel lock."""
        _require_owner_token(owner_token)
        with self._connection_lock:
            held = self._held_leases.get(owner_token)
            if held is None or held[1] != task_id:
                return False
            row = self._connection.execute(
                """SELECT 1 FROM project_leases
                   WHERE task_id = ? AND owner_token = ? AND protocol = ?""",
                (task_id, owner_token, _LEASE_PROTOCOL),
            ).fetchone()
            return row is not None

    def mark_findings_resolved(
        self, finding_ids: tuple[str, ...], resolved_at: datetime | None = None
    ) -> int:
        if not finding_ids:
            return 0
        timestamp = resolved_at or _utc_now()
        placeholders = ", ".join("?" for _ in finding_ids)
        with self._transaction() as connection:
            cursor = connection.execute(
                f"""UPDATE findings SET resolved_at = ?
                    WHERE id IN ({placeholders}) AND resolved_at IS NULL""",
                (_dump_datetime(timestamp), *finding_ids),
            )
        return cursor.rowcount

    def add_decision(
        self,
        project_id: str,
        scope_type: str,
        scope_value: str,
        content: str,
        source: str,
    ) -> DecisionRecord:
        decision_id = _new_id()
        created_at = _utc_now()
        with self._transaction() as connection:
            row = connection.execute("SELECT id FROM projects WHERE id = ?", (project_id,)).fetchone()
            if row is None:
                raise StorageStateError("project does not exist")
            connection.execute(
                """INSERT INTO decisions
                   (id, project_id, scope_type, scope_value, content, source, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    decision_id,
                    project_id,
                    scope_type,
                    scope_value,
                    content,
                    source,
                    _dump_datetime(created_at),
                    _dump_datetime(created_at),
                ),
            )
        return DecisionRecord(
            id=decision_id,
            project_id=project_id,
            scope_type=scope_type,
            scope_value=scope_value,
            content=content,
            source=source,
            created_at=created_at,
            updated_at=created_at,
        )

    def resume_snapshot(
        self, task_id: str, *, owner_token: str | None = None
    ) -> RecoverySnapshot:
        with self._read_transaction() as connection:
            task_row = connection.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
            if task_row is None:
                raise StorageStateError("task does not exist")
            iterations = tuple(
                _iteration_from_row(row)
                for row in connection.execute(
                    "SELECT * FROM iterations WHERE task_id = ? ORDER BY sequence, created_at, id", (task_id,)
                )
            )
            findings = tuple(
                _finding_from_row(row)
                for row in connection.execute(
                    """SELECT findings.* FROM findings
                       JOIN iterations ON iterations.id = findings.iteration_id
                       WHERE iterations.task_id = ? ORDER BY findings.created_at, findings.id""",
                    (task_id,),
                )
            )
            decisions = tuple(
                _decision_from_row(row)
                for row in connection.execute(
                    "SELECT * FROM decisions WHERE project_id = ? ORDER BY created_at, id",
                    (task_row["project_id"],),
                )
            )
            pending_row = connection.execute(
                """SELECT * FROM approvals WHERE task_id = ? AND decision IS NULL
                   ORDER BY created_at DESC, id DESC LIMIT 1""",
                (task_id,),
            ).fetchone()
            decided_row = connection.execute(
                """SELECT * FROM approvals WHERE task_id = ? AND decision IS NOT NULL
                   ORDER BY decided_at DESC, id DESC LIMIT 1""",
                (task_id,),
            ).fetchone()
            transition_intents = tuple(
                _transition_intent_from_row(row)
                for row in connection.execute(
                    """SELECT * FROM transition_intents
                       WHERE task_id = ? ORDER BY created_at, id""",
                    (task_id,),
                )
            )
            lease_row = connection.execute(
                """SELECT task_id, owner_token, protocol FROM project_leases
                   WHERE project_id = ?""",
                (task_row["project_id"],),
            ).fetchone()
            executable_row = None
            if (
                task_row["status"] == TaskStatus.RUNNING.value
                and lease_row is not None
                and lease_row["task_id"] == task_id
                and lease_row["protocol"] == _LEASE_PROTOCOL
                and owner_token is not None
                and lease_row["owner_token"] == owner_token
                and owner_token in self._held_leases
                and self._held_leases[owner_token][1] == task_id
            ):
                executable_row = connection.execute(
                    """SELECT * FROM approvals
                       WHERE task_id = ? AND decision = ? AND execution_state != 'completed'
                       ORDER BY decided_at, id LIMIT 1""",
                    (task_id, ApprovalDecision.APPROVE.value),
                ).fetchone()
            return RecoverySnapshot(
                task=_task_from_row(task_row),
                iterations=iterations,
                findings=findings,
                decisions=decisions,
                pending_approval=_approval_from_row(pending_row) if pending_row is not None else None,
                decided_approval=_approval_from_row(decided_row) if decided_row is not None else None,
                executable_approval=_approval_from_row(executable_row)
                if executable_row is not None
                else None,
                transition_intents=transition_intents,
            )

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._connection_lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                yield self._connection
            except Exception:
                self._connection.rollback()
                raise
            else:
                self._connection.commit()

    @contextmanager
    def _read_transaction(self) -> Iterator[sqlite3.Connection]:
        with self._connection_lock:
            self._connection.execute("BEGIN")
            try:
                yield self._connection
            except Exception:
                self._connection.rollback()
                raise
            else:
                self._connection.commit()

    def _create_schema(self) -> None:
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS projects (
                id TEXT PRIMARY KEY,
                canonical_path TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS tasks (
                id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL REFERENCES projects(id),
                request TEXT NOT NULL,
                status TEXT NOT NULL,
                round_limit INTEGER NOT NULL,
                deadline TEXT,
                result_json TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS iterations (
                id TEXT PRIMARY KEY,
                task_id TEXT NOT NULL REFERENCES tasks(id),
                sequence INTEGER NOT NULL,
                context_digest TEXT NOT NULL,
                action_json TEXT,
                policy_outcome TEXT,
                tool_result_digest TEXT,
                fingerprint TEXT,
                relevant_digest TEXT,
                quality_outcome TEXT,
                created_at TEXT NOT NULL,
                UNIQUE(task_id, sequence)
            );
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                iteration_id TEXT NOT NULL REFERENCES iterations(id),
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                resolved_at TEXT
            );
            CREATE TABLE IF NOT EXISTS approvals (
                id TEXT PRIMARY KEY,
                task_id TEXT NOT NULL REFERENCES tasks(id),
                iteration_id TEXT NOT NULL REFERENCES iterations(id),
                action_json TEXT NOT NULL,
                action_digest TEXT NOT NULL,
                repository_snapshot_digest TEXT NOT NULL,
                policy_decision_json TEXT,
                decision TEXT,
                execution_state TEXT NOT NULL,
                expected_after_digests_json TEXT NOT NULL DEFAULT '{}',
                result_digest TEXT,
                decided_at TEXT,
                executed_at TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS decisions (
                id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL REFERENCES projects(id),
                scope_type TEXT NOT NULL,
                scope_value TEXT NOT NULL,
                content TEXT NOT NULL,
                source TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_events (
                id TEXT PRIMARY KEY,
                task_id TEXT REFERENCES tasks(id),
                iteration_id TEXT REFERENCES iterations(id),
                event_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS project_leases (
                project_id TEXT PRIMARY KEY REFERENCES projects(id),
                task_id TEXT NOT NULL UNIQUE REFERENCES tasks(id),
                owner_token TEXT,
                acquired_at TEXT NOT NULL,
                protocol TEXT
            );
            CREATE TABLE IF NOT EXISTS transition_intents (
                id TEXT PRIMARY KEY,
                task_id TEXT NOT NULL REFERENCES tasks(id),
                kind TEXT NOT NULL,
                evidence_digest TEXT NOT NULL,
                summary TEXT NOT NULL,
                state TEXT NOT NULL,
                result_digest TEXT,
                result_payload_json TEXT,
                completion_summary TEXT,
                created_at TEXT NOT NULL,
                completed_at TEXT,
                consumed_at TEXT
            );
            """
        )
        self._ensure_column("approvals", "policy_decision_json", "TEXT")
        self._ensure_column(
            "approvals", "expected_after_digests_json", "TEXT NOT NULL DEFAULT '{}'"
        )
        self._ensure_column("approvals", "result_digest", "TEXT")
        self._ensure_column("iterations", "quality_outcome", "TEXT")
        self._ensure_column("project_leases", "owner_token", "TEXT")
        self._ensure_column("project_leases", "protocol", "TEXT")
        self._ensure_column("transition_intents", "result_payload_json", "TEXT")
        self._ensure_column("transition_intents", "consumed_at", "TEXT")

    def _ensure_column(self, table: str, column: str, declaration: str) -> None:
        columns = {
            row["name"] for row in self._connection.execute(f"PRAGMA table_info({table})")
        }
        if column not in columns:
            self._connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {declaration}")

    @staticmethod
    def _require_task(connection: sqlite3.Connection, task_id: str) -> sqlite3.Row:
        row = connection.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
        if row is None:
            raise StorageStateError("task does not exist")
        return row

    @staticmethod
    def _require_iteration(
        connection: sqlite3.Connection, task_id: str, iteration_id: str
    ) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM iterations WHERE id = ? AND task_id = ?", (iteration_id, task_id)
        ).fetchone()
        if row is None:
            raise StorageStateError("iteration does not belong to task")
        return row

    @staticmethod
    def _require_approval(connection: sqlite3.Connection, approval_id: str) -> sqlite3.Row:
        row = connection.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,)).fetchone()
        if row is None:
            raise StorageStateError("approval does not exist")
        return row

    @staticmethod
    def _require_transition_intent(
        connection: sqlite3.Connection, intent_id: str
    ) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM transition_intents WHERE id = ?", (intent_id,)
        ).fetchone()
        if row is None:
            raise StorageStateError("transition intent does not exist")
        return row

    def _require_running_lease(
        self,
        connection: sqlite3.Connection,
        task_id: str,
        owner_token: str | None,
    ) -> None:
        if owner_token is None:
            raise StorageStateError("running mutation requires a lease owner token")
        _require_owner_token(owner_token)
        held = self._held_leases.get(owner_token)
        if held is None or held[1] != task_id:
            raise StorageStateError(
                "running mutation requires ownership of the local kernel lock"
            )
        task = self._require_task(connection, task_id)
        lease = connection.execute(
            """SELECT task_id, owner_token, protocol FROM project_leases
               WHERE project_id = ?""",
            (task["project_id"],),
        ).fetchone()
        if (
            task["status"] != TaskStatus.RUNNING.value
            or lease is None
            or lease["task_id"] != task_id
            or lease["owner_token"] != owner_token
            or lease["protocol"] != _LEASE_PROTOCOL
        ):
            raise StorageStateError("running task does not own the project lease owner token")

    def _release_local_lease(self, owner_token: str) -> None:
        held = self._held_leases.pop(owner_token, None)
        if held is not None:
            held[2].release()

    def _release_local_leases_for_task(self, task_id: str) -> None:
        for owner_token, held in tuple(self._held_leases.items()):
            if held[1] == task_id:
                self._release_local_lease(owner_token)

    def _approval_by_id(self, approval_id: str) -> ApprovalRecord:
        row = self._connection.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,)).fetchone()
        if row is None:
            raise StorageStateError("approval does not exist")
        return _approval_from_row(row)

    def _iteration_by_id(self, iteration_id: str) -> IterationRecord:
        row = self._connection.execute(
            "SELECT * FROM iterations WHERE id = ?", (iteration_id,)
        ).fetchone()
        if row is None:
            raise StorageStateError("iteration does not exist")
        return _iteration_from_row(row)

    def _transition_intent_by_id(self, intent_id: str) -> TransitionIntentRecord:
        row = self._connection.execute(
            "SELECT * FROM transition_intents WHERE id = ?", (intent_id,)
        ).fetchone()
        if row is None:
            raise StorageStateError("transition intent does not exist")
        return _transition_intent_from_row(row)

    @staticmethod
    def _consume_transition_intents(
        connection: sqlite3.Connection,
        task_id: str,
        intent_ids: tuple[str, ...],
    ) -> None:
        consumed_at = _dump_datetime(_utc_now())
        for intent_id in intent_ids:
            row = connection.execute(
                "SELECT * FROM transition_intents WHERE id = ? AND task_id = ?",
                (intent_id, task_id),
            ).fetchone()
            if row is None or row["state"] != "completed" or row["consumed_at"] is not None:
                raise StorageStateError("transition intent is not consumable")
            connection.execute(
                "UPDATE transition_intents SET consumed_at = ? WHERE id = ?",
                (consumed_at, intent_id),
            )


def _new_id() -> str:
    return str(uuid.uuid4())


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _dump_datetime(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _load_datetime(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value is not None else None


def _canonical_json(value: object) -> str:
    payload = json.loads(value) if isinstance(value, str) else value
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _task_from_row(row: sqlite3.Row) -> TaskRecord:
    return TaskRecord(
        id=row["id"],
        project_id=row["project_id"],
        request=row["request"],
        status=TaskStatus(row["status"]),
        round_limit=row["round_limit"],
        deadline=_load_datetime(row["deadline"]),
        result=TaskResult.model_validate(json.loads(row["result_json"])) if row["result_json"] else None,
    )


def _iteration_from_row(row: sqlite3.Row) -> IterationRecord:
    return IterationRecord(
        id=row["id"],
        task_id=row["task_id"],
        sequence=row["sequence"],
        context_digest=row["context_digest"],
        action_json=row["action_json"],
        policy_outcome=PolicyOutcome(row["policy_outcome"]) if row["policy_outcome"] else None,
        tool_result_digest=row["tool_result_digest"],
        fingerprint=row["fingerprint"],
        relevant_digest=row["relevant_digest"],
        quality_outcome=row["quality_outcome"],
        created_at=_load_datetime(row["created_at"]),
    )


def _approval_from_row(row: sqlite3.Row) -> ApprovalRecord:
    return ApprovalRecord(
        id=row["id"],
        task_id=row["task_id"],
        iteration_id=row["iteration_id"],
        action_json=row["action_json"],
        action_digest=row["action_digest"],
        repository_snapshot_digest=row["repository_snapshot_digest"],
        policy_decision=PolicyDecision.model_validate(json.loads(row["policy_decision_json"]))
        if row["policy_decision_json"]
        else None,
        decision=ApprovalDecision(row["decision"]) if row["decision"] else None,
        execution_state=row["execution_state"],
        expected_after_digests=json.loads(row["expected_after_digests_json"]),
        result_digest=row["result_digest"],
        decided_at=_load_datetime(row["decided_at"]),
        executed_at=_load_datetime(row["executed_at"]),
    )


def _transition_intent_from_row(row: sqlite3.Row) -> TransitionIntentRecord:
    created_at = _load_datetime(row["created_at"])
    assert created_at is not None
    return TransitionIntentRecord(
        id=row["id"],
        task_id=row["task_id"],
        kind=row["kind"],
        evidence_digest=row["evidence_digest"],
        summary=row["summary"],
        state=row["state"],
        result_digest=row["result_digest"],
        result_payload=json.loads(row["result_payload_json"])
        if row["result_payload_json"]
        else None,
        completion_summary=row["completion_summary"],
        created_at=created_at,
        completed_at=_load_datetime(row["completed_at"]),
        consumed_at=_load_datetime(row["consumed_at"]),
    )


def _finding_from_row(row: sqlite3.Row) -> FindingRecord:
    created_at = _load_datetime(row["created_at"])
    assert created_at is not None
    return FindingRecord(
        id=row["id"],
        iteration_id=row["iteration_id"],
        finding=Finding.model_validate(json.loads(row["payload_json"])),
        created_at=created_at,
        resolved_at=_load_datetime(row["resolved_at"]),
    )


def _decision_from_row(row: sqlite3.Row) -> DecisionRecord:
    created_at = _load_datetime(row["created_at"])
    updated_at = _load_datetime(row["updated_at"])
    assert created_at is not None
    assert updated_at is not None
    return DecisionRecord(
        id=row["id"],
        project_id=row["project_id"],
        scope_type=row["scope_type"],
        scope_value=row["scope_value"],
        content=row["content"],
        source=row["source"],
        created_at=created_at,
        updated_at=updated_at,
    )


def _require_digest(value: str, field: str) -> None:
    if re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise StorageStateError(f"{field} must be lowercase SHA-256 hex")


def _validated_path_digests(values: dict[str, str | None]) -> dict[str, str | None]:
    normalized: dict[str, str | None] = {}
    for path, digest in values.items():
        candidate = PurePosixPath(path)
        if not path or "\\" in path or candidate.is_absolute() or ".." in candidate.parts:
            raise StorageStateError("digest path must be repository-relative POSIX text")
        if len(path.encode("utf-8")) > MAX_CONFIG_PATTERN_BYTES:
            raise StorageStateError("digest path exceeds UTF-8 byte limit")
        if digest is not None:
            _require_digest(digest, "expected after digest")
        normalized[candidate.as_posix()] = digest
    return dict(sorted(normalized.items()))


def _require_transition_text(value: str, limit: int, field: str) -> None:
    if not value or len(value.encode("utf-8")) > limit:
        raise StorageStateError(f"{field} must contain at most {limit} UTF-8 bytes")


def _require_owner_token(value: str) -> None:
    if not value or len(value.encode("utf-8")) > 128:
        raise StorageStateError("owner token must contain at most 128 UTF-8 bytes")


def _bounded_payload_json(value: dict[str, object] | None) -> str | None:
    if value is None:
        return None
    payload = _canonical_json(value)
    if len(payload.encode("utf-8")) > 65_536:
        raise StorageStateError("transition payload exceeds UTF-8 byte limit")
    return payload


def _bounded_action_json(value: str) -> str:
    payload = _canonical_json(value)
    if len(payload.encode("utf-8")) > MAX_ACTION_ARGUMENTS_BYTES + 8_192:
        raise StorageStateError("action payload exceeds UTF-8 byte limit")
    return payload
