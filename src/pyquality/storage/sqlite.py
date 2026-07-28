"""SQLite-backed state transitions for a single pyquality task repository."""

from __future__ import annotations

import json
import re
import sqlite3
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Literal

from pydantic import ConfigDict

from pyquality.domain.models import (
    ApprovalDecision,
    Finding,
    PolicyDecision,
    PolicyOutcome,
    PublicModel,
    TaskResult,
    TaskStatus,
)


class StorageStateError(RuntimeError):
    """Raised when persisted state cannot make the requested transition."""


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
    completion_summary: str | None
    created_at: datetime
    completed_at: datetime | None


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


class SQLiteTaskRepository:
    """Owns atomic persistence of task state and recovery records."""

    def __init__(self, db_path: Path) -> None:
        self._connection = sqlite3.connect(db_path, isolation_level=None)
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
        findings: tuple[Finding, ...] = (),
    ) -> IterationRecord:
        iteration_id = _new_id()
        created_at = _utc_now()
        normalized_action = _canonical_json(action_json) if action_json is not None else None
        with self._transaction() as connection:
            self._require_task(connection, task_id)
            try:
                connection.execute(
                    """INSERT INTO iterations
                       (id, task_id, sequence, context_digest, action_json, policy_outcome,
                        tool_result_digest, fingerprint, relevant_digest, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
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
            created_at=created_at,
        )

    def set_status(
        self,
        task_id: str,
        expected: TaskStatus,
        new: TaskStatus,
        result: TaskResult | None = None,
    ) -> bool:
        with self._transaction() as connection:
            current = connection.execute("SELECT status FROM tasks WHERE id = ?", (task_id,)).fetchone()
            if current is None or current["status"] != expected.value:
                return False
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
                connection.execute("DELETE FROM project_leases WHERE task_id = ?", (task_id,))
        return True

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
                    _canonical_json(action_json),
                    action_digest,
                    repository_snapshot_digest,
                    _canonical_json(policy_decision.model_dump(mode="json"))
                    if policy_decision is not None
                    else None,
                    _dump_datetime(_utc_now()),
                ),
            )
        return self._approval_by_id(approval_id)

    def pending_approval(self, task_id: str) -> ApprovalRecord | None:
        row = self._connection.execute(
            """SELECT * FROM approvals WHERE task_id = ? AND decision IS NULL
               ORDER BY created_at DESC, id DESC LIMIT 1""",
            (task_id,),
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

    def mark_execution_intent(
        self,
        approval_id: str,
        *,
        expected_after_digests: dict[str, str | None] | None = None,
    ) -> ApprovalRecord:
        normalized_digests = _validated_path_digests(expected_after_digests or {})
        with self._transaction() as connection:
            row = self._require_approval(connection, approval_id)
            if row["decision"] != ApprovalDecision.APPROVE.value or row["execution_state"] != "pending":
                raise StorageStateError("approval is not ready for execution intent")
            self._require_running_lease(connection, row["task_id"])
            connection.execute(
                """UPDATE approvals
                   SET execution_state = 'intent_recorded', expected_after_digests_json = ?
                   WHERE id = ?""",
                (_canonical_json(normalized_digests), approval_id),
            )
        return self._approval_by_id(approval_id)

    def mark_execution_completed(
        self, approval_id: str, *, result_digest: str | None = None
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
            connection.execute(
                """UPDATE approvals
                   SET execution_state = 'completed', result_digest = ?, executed_at = ?
                   WHERE id = ?""",
                (result_digest, _dump_datetime(executed_at), approval_id),
            )
        return self._approval_by_id(approval_id)

    def mark_rejection_consumed(self, approval_id: str) -> ApprovalRecord:
        consumed_at = _utc_now()
        with self._transaction() as connection:
            row = self._require_approval(connection, approval_id)
            if (
                row["decision"] != ApprovalDecision.REJECT.value
                or row["execution_state"] != "pending"
            ):
                raise StorageStateError("rejected approval is not ready to be consumed")
            self._require_running_lease(connection, row["task_id"])
            connection.execute(
                """UPDATE approvals
                   SET execution_state = 'completed', executed_at = ? WHERE id = ?""",
                (_dump_datetime(consumed_at), approval_id),
            )
        return self._approval_by_id(approval_id)

    def record_transition_intent(
        self,
        task_id: str,
        *,
        kind: str,
        evidence_digest: str,
        summary: str,
    ) -> TransitionIntentRecord:
        _require_transition_text(kind, 64, "kind")
        _require_transition_text(summary, 1_024, "summary")
        _require_digest(evidence_digest, "evidence_digest")
        intent_id = _new_id()
        created_at = _utc_now()
        with self._transaction() as connection:
            self._require_running_lease(connection, task_id)
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
    ) -> TransitionIntentRecord:
        _require_digest(result_digest, "result_digest")
        _require_transition_text(summary, 1_024, "summary")
        completed_at = _utc_now()
        with self._transaction() as connection:
            row = self._require_transition_intent(connection, intent_id)
            if row["state"] != "pending":
                raise StorageStateError("transition intent is already completed")
            self._require_running_lease(connection, row["task_id"])
            connection.execute(
                """UPDATE transition_intents
                   SET state = 'completed', result_digest = ?, completion_summary = ?,
                       completed_at = ? WHERE id = ?""",
                (result_digest, summary, _dump_datetime(completed_at), intent_id),
            )
        return self._transition_intent_by_id(intent_id)

    def acquire_project_lease(self, task_id: str) -> bool:
        with self._transaction() as connection:
            task = self._require_task(connection, task_id)
            if task["status"] != TaskStatus.RUNNING.value:
                raise StorageStateError("only running tasks can acquire a project lease")
            try:
                connection.execute(
                    "INSERT INTO project_leases (project_id, task_id, acquired_at) VALUES (?, ?, ?)",
                    (task["project_id"], task_id, _dump_datetime(_utc_now())),
                )
            except sqlite3.IntegrityError:
                row = connection.execute(
                    "SELECT task_id FROM project_leases WHERE project_id = ?", (task["project_id"],)
                ).fetchone()
                return row is not None and row["task_id"] == task_id
        return True

    def release_project_lease(self, task_id: str) -> None:
        with self._transaction() as connection:
            connection.execute("DELETE FROM project_leases WHERE task_id = ?", (task_id,))

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

    def resume_snapshot(self, task_id: str) -> RecoverySnapshot:
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
                "SELECT task_id FROM project_leases WHERE project_id = ?", (task_row["project_id"],)
            ).fetchone()
            executable_row = None
            if (
                task_row["status"] == TaskStatus.RUNNING.value
                and lease_row is not None
                and lease_row["task_id"] == task_id
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
                acquired_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS transition_intents (
                id TEXT PRIMARY KEY,
                task_id TEXT NOT NULL REFERENCES tasks(id),
                kind TEXT NOT NULL,
                evidence_digest TEXT NOT NULL,
                summary TEXT NOT NULL,
                state TEXT NOT NULL,
                result_digest TEXT,
                completion_summary TEXT,
                created_at TEXT NOT NULL,
                completed_at TEXT
            );
            """
        )
        self._ensure_column("approvals", "policy_decision_json", "TEXT")
        self._ensure_column(
            "approvals", "expected_after_digests_json", "TEXT NOT NULL DEFAULT '{}'"
        )
        self._ensure_column("approvals", "result_digest", "TEXT")

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

    @classmethod
    def _require_running_lease(cls, connection: sqlite3.Connection, task_id: str) -> None:
        task = cls._require_task(connection, task_id)
        lease = connection.execute(
            "SELECT task_id FROM project_leases WHERE project_id = ?", (task["project_id"],)
        ).fetchone()
        if task["status"] != TaskStatus.RUNNING.value or lease is None or lease["task_id"] != task_id:
            raise StorageStateError("running task does not own the project lease")

    def _approval_by_id(self, approval_id: str) -> ApprovalRecord:
        row = self._connection.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,)).fetchone()
        if row is None:
            raise StorageStateError("approval does not exist")
        return _approval_from_row(row)

    def _transition_intent_by_id(self, intent_id: str) -> TransitionIntentRecord:
        row = self._connection.execute(
            "SELECT * FROM transition_intents WHERE id = ?", (intent_id,)
        ).fetchone()
        if row is None:
            raise StorageStateError("transition intent does not exist")
        return _transition_intent_from_row(row)


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
        completion_summary=row["completion_summary"],
        created_at=created_at,
        completed_at=_load_datetime(row["completed_at"]),
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
        if digest is not None:
            _require_digest(digest, "expected after digest")
        normalized[candidate.as_posix()] = digest
    return dict(sorted(normalized.items()))


def _require_transition_text(value: str, limit: int, field: str) -> None:
    if not value or len(value.encode("utf-8")) > limit:
        raise StorageStateError(f"{field} must contain at most {limit} UTF-8 bytes")
