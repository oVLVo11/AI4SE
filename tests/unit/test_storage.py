from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier, Event

import pytest

from pyquality.domain.models import (
    ApprovalDecision,
    Finding,
    PolicyDecision,
    PolicyOutcome,
    TaskResult,
    TaskStatus,
)
from pyquality.storage.sqlite import (
    LeaseRecoveryBlocked,
    ProjectReservationError,
    SQLiteTaskRepository,
    StorageStateError,
    TaskCreationConflictError,
)


@pytest.fixture
def repo(tmp_path: Path) -> SQLiteTaskRepository:
    return SQLiteTaskRepository(tmp_path / "state.sqlite")


def _start(repo: SQLiteTaskRepository, task_id: str) -> None:
    assert repo.set_status(task_id, TaskStatus.CREATED, TaskStatus.RUNNING) is True


def _approval_decision() -> PolicyDecision:
    return PolicyDecision(
        outcome=PolicyOutcome.REQUIRE_APPROVAL,
        matched_rule="dependency_manifest",
        impact_summary="Dependency declarations require explicit approval.",
        action_digest="b" * 64,
        repository_snapshot_digest="c" * 64,
    )


OWNER_A = "runner-a"
OWNER_B = "runner-b"
CREATION_NONCE_A = "a" * 64
CREATION_NONCE_B = "b" * 64


def test_creation_identity_replay_is_idempotent_for_exact_reserved_task(
    repo: SQLiteTaskRepository,
) -> None:
    task_id = "caller-owned-creation-identity"

    first = repo.create_task_with_project_reservation(
        "C:/work/creation-replay",
        "same request",
        round_limit=8,
        task_id=task_id,
        creation_nonce=CREATION_NONCE_A,
    )
    replay = repo.create_task_with_project_reservation(
        "C:/work/creation-replay",
        "same request",
        round_limit=8,
        task_id=task_id,
        creation_nonce=CREATION_NONCE_A,
    )

    assert first == replay
    assert replay.id == task_id
    with repo._connection_lock:
        counts = repo._connection.execute(
            """SELECT
                 (SELECT COUNT(*) FROM tasks WHERE id = ?) AS tasks,
                 (SELECT COUNT(*) FROM project_reservations
                  WHERE task_id = ? AND migrated = 0
                    AND creation_nonce = ?) AS reservations""",
            (task_id, task_id, CREATION_NONCE_A),
        ).fetchone()
    assert tuple(counts) == (1, 1)


def test_creation_identity_conflict_preserves_original_reserved_task(
    repo: SQLiteTaskRepository,
) -> None:
    task_id = "conflicting-creation-identity"
    original = repo.create_task_with_project_reservation(
        "C:/work/creation-conflict",
        "original request",
        round_limit=8,
        task_id=task_id,
        creation_nonce=CREATION_NONCE_A,
    )

    with pytest.raises(TaskCreationConflictError) as captured:
        repo.create_task_with_project_reservation(
            "C:/work/creation-conflict",
            "sensitive conflicting request",
            round_limit=8,
            task_id=task_id,
            creation_nonce=CREATION_NONCE_A,
        )

    assert str(captured.value) == "task creation identity conflicts with stored work"
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert repo.resume_snapshot(task_id).task == original
    with repo._connection_lock:
        reservation = repo._connection.execute(
            "SELECT task_id FROM project_reservations WHERE task_id = ?",
            (task_id,),
        ).fetchone()
    assert reservation["task_id"] == task_id


def test_creation_nonce_mismatch_conflicts_even_for_exact_task_inputs(
    repo: SQLiteTaskRepository,
) -> None:
    task_id = "nonce-conflicting-creation-identity"
    original = repo.create_task_with_project_reservation(
        "C:/work/creation-nonce-conflict",
        "same request",
        round_limit=8,
        task_id=task_id,
        creation_nonce=CREATION_NONCE_A,
    )

    with pytest.raises(TaskCreationConflictError) as captured:
        repo.create_task_with_project_reservation(
            "C:/work/creation-nonce-conflict",
            "same request",
            round_limit=8,
            task_id=task_id,
            creation_nonce=CREATION_NONCE_B,
        )

    assert str(captured.value) == "task creation identity conflicts with stored work"
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert repo.resume_snapshot(task_id).task == original


def test_rollback_created_task_deletes_only_matching_nonce_owned_work(
    repo: SQLiteTaskRepository,
) -> None:
    task = repo.create_task_with_project_reservation(
        "C:/work/rollback-created",
        "rollback exact owner",
        round_limit=8,
        creation_nonce=CREATION_NONCE_A,
    )

    assert (
        repo.rollback_created_task(task.id, creation_nonce=CREATION_NONCE_A)
        is True
    )
    assert repo.task_exists(task.id) is False
    with repo._connection_lock:
        counts = repo._connection.execute(
            """SELECT
                 (SELECT COUNT(*) FROM projects) AS projects,
                 (SELECT COUNT(*) FROM project_reservations) AS reservations"""
        ).fetchone()
    assert tuple(counts) == (0, 0)


def test_rollback_created_task_wrong_nonce_preserves_task_and_reservation(
    repo: SQLiteTaskRepository,
) -> None:
    task = repo.create_task_with_project_reservation(
        "C:/work/rollback-created-wrong-owner",
        "preserve exact owner",
        round_limit=8,
        creation_nonce=CREATION_NONCE_A,
    )

    assert (
        repo.rollback_created_task(task.id, creation_nonce=CREATION_NONCE_B)
        is False
    )
    assert repo.resume_snapshot(task.id).task == task
    with repo._connection_lock:
        reservation = repo._connection.execute(
            "SELECT task_id, creation_nonce FROM project_reservations WHERE task_id = ?",
            (task.id,),
        ).fetchone()
    assert tuple(reservation) == (task.id, CREATION_NONCE_A)


@pytest.mark.parametrize("evidence", ["iteration", "approval", "lease"])
def test_rollback_created_task_rejects_execution_evidence(
    repo: SQLiteTaskRepository,
    evidence: str,
) -> None:
    task = repo.create_task_with_project_reservation(
        f"C:/work/rollback-created-{evidence}",
        "preserve evidence",
        round_limit=8,
        creation_nonce=CREATION_NONCE_A,
    )
    if evidence in {"iteration", "approval"}:
        iteration = repo.append_iteration(
            task.id, sequence=1, context_digest="a" * 64
        )
        if evidence == "approval":
            repo.record_approval(
                task.id,
                iteration.id,
                '{"arguments":{},"kind":"finish","rationale":"pause"}',
                "b" * 64,
                "c" * 64,
            )
    else:
        with repo._connection_lock:
            repo._connection.execute(
                """INSERT INTO project_leases
                   (project_id, task_id, owner_token, acquired_at, protocol)
                   VALUES (?, ?, ?, ?, ?)""",
                (
                    task.project_id,
                    task.id,
                    OWNER_A,
                    "2026-07-29T00:00:00+00:00",
                    "os-file-v1",
                ),
            )

    assert (
        repo.rollback_created_task(task.id, creation_nonce=CREATION_NONCE_A)
        is False
    )
    assert repo.task_exists(task.id) is True


def test_rollback_created_task_unknown_task_raises_sanitized_error(
    repo: SQLiteTaskRepository,
) -> None:
    unknown = "missing-created-task-sensitive-token"

    with pytest.raises(StorageStateError) as captured:
        repo.rollback_created_task(unknown, creation_nonce=CREATION_NONCE_A)

    assert str(captured.value) == "task does not exist"
    assert unknown not in str(captured.value)
    assert CREATION_NONCE_A not in str(captured.value)
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


def test_cancel_created_task_deletes_reserved_task_and_unused_project(
    repo: SQLiteTaskRepository,
) -> None:
    task = repo.create_task_with_project_reservation(
        "C:/work/cancel-created", "cancel me", round_limit=8
    )

    assert repo.cancel_created_task(task.id) is True
    assert repo.task_exists(task.id) is False
    with repo._connection_lock:
        counts = repo._connection.execute(
            """SELECT
                 (SELECT COUNT(*) FROM projects) AS projects,
                 (SELECT COUNT(*) FROM project_reservations) AS reservations"""
        ).fetchone()
    assert tuple(counts) == (0, 0)


def test_cancel_created_task_does_not_transfer_service_reservation(
    repo: SQLiteTaskRepository,
) -> None:
    low_level = repo.create_task(
        "C:/work/cancel-created-shared", "low-level", round_limit=8
    )
    service_task = repo.create_task_with_project_reservation(
        "C:/work/cancel-created-shared", "service", round_limit=8
    )

    assert repo.cancel_created_task(service_task.id) is True
    assert repo.task_exists(low_level.id) is True
    replacement = repo.create_task_with_project_reservation(
        "C:/work/cancel-created-shared", "replacement", round_limit=8
    )

    assert replacement.status is TaskStatus.CREATED


@pytest.mark.parametrize("evidence", ["iteration", "approval", "lease"])
def test_cancel_created_task_rejects_durable_execution_evidence(
    repo: SQLiteTaskRepository, evidence: str
) -> None:
    task = repo.create_task_with_project_reservation(
        f"C:/work/cancel-created-{evidence}", "keep me", round_limit=8
    )
    if evidence in {"iteration", "approval"}:
        iteration = repo.append_iteration(
            task.id, sequence=1, context_digest="a" * 64
        )
        if evidence == "approval":
            repo.record_approval(
                task.id,
                iteration.id,
                '{"arguments":{},"kind":"finish","rationale":"pause"}',
                "b" * 64,
                "c" * 64,
            )
    else:
        with repo._connection_lock:
            repo._connection.execute(
                """INSERT INTO project_leases
                   (project_id, task_id, owner_token, acquired_at, protocol)
                   VALUES (?, ?, ?, ?, ?)""",
                (
                    task.project_id,
                    task.id,
                    OWNER_A,
                    "2026-07-29T00:00:00+00:00",
                    "os-file-v1",
                ),
            )

    assert repo.cancel_created_task(task.id) is False
    assert repo.task_exists(task.id) is True
    with repo._connection_lock:
        reservation = repo._connection.execute(
            "SELECT task_id FROM project_reservations WHERE project_id = ?",
            (task.project_id,),
        ).fetchone()
    assert reservation["task_id"] == task.id


def test_cancellation_cas_loses_to_running_lease_without_deleting_live_state(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "state.sqlite"
    runner = SQLiteTaskRepository(db_path)
    canceller = SQLiteTaskRepository(db_path)
    task = runner.create_task_with_project_reservation(
        "C:/work/cancel-race", "run me", round_limit=8
    )
    cancellation_started = Barrier(2)
    transition_committed = Event()

    def cancel_after_transition() -> bool:
        cancellation_started.wait()
        assert transition_committed.wait(2)
        return canceller.cancel_created_task(task.id)

    with ThreadPoolExecutor(max_workers=1) as pool:
        outcome = pool.submit(cancel_after_transition)
        cancellation_started.wait()
        assert runner.set_status(
            task.id, TaskStatus.CREATED, TaskStatus.RUNNING
        ) is True
        assert runner.acquire_project_lease(task.id, owner_token=OWNER_A) is True
        transition_committed.set()
        assert outcome.result() is False

    snapshot = runner.resume_snapshot(task.id)
    assert snapshot.task.status is TaskStatus.RUNNING
    assert runner.owns_project_lease(task.id, owner_token=OWNER_A) is True
    with runner._connection_lock:
        rows = runner._connection.execute(
            """SELECT
                 (SELECT COUNT(*) FROM projects WHERE id = ?) AS projects,
                 (SELECT COUNT(*) FROM project_reservations
                  WHERE project_id = ? AND task_id = ?) AS reservations,
                 (SELECT COUNT(*) FROM project_leases
                  WHERE project_id = ? AND task_id = ? AND owner_token = ?) AS leases""",
            (
                task.project_id,
                task.project_id,
                task.id,
                task.project_id,
                task.id,
                OWNER_A,
            ),
        ).fetchone()
    assert tuple(rows) == (1, 1, 1)


def test_two_cancellation_cas_callers_have_exactly_one_success(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "state.sqlite"
    creator = SQLiteTaskRepository(db_path)
    first = SQLiteTaskRepository(db_path)
    second = SQLiteTaskRepository(db_path)
    task = creator.create_task_with_project_reservation(
        "C:/work/two-cancellers", "cancel once", round_limit=8
    )
    ready = Barrier(3)

    def cancel(repository: SQLiteTaskRepository) -> bool:
        ready.wait()
        try:
            return repository.cancel_created_task(task.id)
        except StorageStateError:
            return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = [pool.submit(cancel, repository) for repository in (first, second)]
        ready.wait()
        values = [outcome.result() for outcome in outcomes]

    assert values.count(True) == 1
    assert creator.task_exists(task.id) is False


def test_cancel_created_task_unknown_task_raises_sanitized_error(
    repo: SQLiteTaskRepository,
) -> None:
    unknown = "missing-task-sensitive-token"

    with pytest.raises(StorageStateError) as captured:
        repo.cancel_created_task(unknown)

    assert str(captured.value) == "task does not exist"
    assert unknown not in str(captured.value)


def test_cancel_sqlite_error_is_normalized_without_sensitive_chain(
    repo: SQLiteTaskRepository,
) -> None:
    task = repo.create_task_with_project_reservation(
        "C:/work/cancel-sqlite-error", "keep after abort", round_limit=8
    )
    sensitive = "cancel-sqlite-sensitive-token"
    with repo._connection_lock:
        repo._connection.execute(
            """CREATE TRIGGER abort_cancel_with_sensitive_message
                BEFORE DELETE ON tasks
                BEGIN SELECT RAISE(ABORT, 'cancel-sqlite-sensitive-token'); END"""
        )

    with pytest.raises(StorageStateError) as captured:
        repo.cancel_created_task(task.id)

    assert type(captured.value) is StorageStateError
    assert str(captured.value) == "task cancellation is unavailable"
    assert sensitive not in str(captured.value)
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert repo.task_exists(task.id) is True
    with repo._connection_lock:
        reservation = repo._connection.execute(
            "SELECT task_id FROM project_reservations WHERE task_id = ?",
            (task.id,),
        ).fetchone()
    assert reservation["task_id"] == task.id


def test_rollback_running_task_deletes_owned_task_lease_reservation_and_project(
    repo: SQLiteTaskRepository,
) -> None:
    task = repo.create_task_with_project_reservation(
        "C:/work/rollback-running", "roll back", round_limit=8
    )
    _start(repo, task.id)
    assert repo.acquire_project_lease(task.id, owner_token=OWNER_A) is True

    assert repo.rollback_running_task(task.id, owner_token=OWNER_A) is True
    assert repo.task_exists(task.id) is False
    assert OWNER_A not in repo._held_leases
    with repo._connection_lock:
        counts = repo._connection.execute(
            """SELECT
                 (SELECT COUNT(*) FROM projects) AS projects,
                 (SELECT COUNT(*) FROM project_reservations) AS reservations,
                 (SELECT COUNT(*) FROM project_leases) AS leases"""
        ).fetchone()
    assert tuple(counts) == (0, 0, 0)


def test_rollback_running_task_does_not_transfer_service_reservation(
    repo: SQLiteTaskRepository,
) -> None:
    low_level = repo.create_task(
        "C:/work/rollback-running-shared", "low-level", round_limit=8
    )
    service_task = repo.create_task_with_project_reservation(
        "C:/work/rollback-running-shared", "service", round_limit=8
    )
    _start(repo, service_task.id)
    assert repo.acquire_project_lease(
        service_task.id, owner_token=OWNER_A
    ) is True

    assert repo.rollback_running_task(
        service_task.id, owner_token=OWNER_A
    ) is True
    assert repo.task_exists(low_level.id) is True
    replacement = repo.create_task_with_project_reservation(
        "C:/work/rollback-running-shared", "replacement", round_limit=8
    )

    assert replacement.status is TaskStatus.CREATED


def test_rollback_running_task_wrong_owner_preserves_live_owner_state(
    repo: SQLiteTaskRepository,
) -> None:
    task = repo.create_task_with_project_reservation(
        "C:/work/rollback-wrong-owner", "keep running", round_limit=8
    )
    _start(repo, task.id)
    assert repo.acquire_project_lease(task.id, owner_token=OWNER_A) is True

    assert repo.rollback_running_task(task.id, owner_token=OWNER_B) is False

    assert repo.resume_snapshot(task.id).task.status is TaskStatus.RUNNING
    assert repo.owns_project_lease(task.id, owner_token=OWNER_A) is True
    with repo._connection_lock:
        reservation = repo._connection.execute(
            "SELECT task_id FROM project_reservations WHERE project_id = ?",
            (task.project_id,),
        ).fetchone()
    assert reservation["task_id"] == task.id


def test_rollback_running_task_wrong_protocol_preserves_local_and_durable_lease(
    repo: SQLiteTaskRepository,
) -> None:
    task = repo.create_task_with_project_reservation(
        "C:/work/rollback-wrong-protocol", "keep running", round_limit=8
    )
    _start(repo, task.id)
    assert repo.acquire_project_lease(task.id, owner_token=OWNER_A) is True
    with repo._connection_lock:
        repo._connection.execute(
            "UPDATE project_leases SET protocol = 'legacy' WHERE task_id = ?",
            (task.id,),
        )

    assert repo.rollback_running_task(task.id, owner_token=OWNER_A) is False

    assert repo.resume_snapshot(task.id).task.status is TaskStatus.RUNNING
    assert repo._held_leases[OWNER_A][1] == task.id
    with repo._connection_lock:
        lease = repo._connection.execute(
            "SELECT owner_token, protocol FROM project_leases WHERE task_id = ?",
            (task.id,),
        ).fetchone()
    assert tuple(lease) == (OWNER_A, "legacy")


@pytest.mark.parametrize(
    "status",
    [TaskStatus.CREATED, TaskStatus.WAITING_APPROVAL, TaskStatus.SUCCEEDED],
)
def test_rollback_running_task_rejects_non_running_status_without_mutation(
    repo: SQLiteTaskRepository, status: TaskStatus
) -> None:
    task = repo.create_task_with_project_reservation(
        f"C:/work/rollback-{status.value}", "keep task", round_limit=8
    )
    if status is not TaskStatus.CREATED:
        _start(repo, task.id)
        assert repo.acquire_project_lease(task.id, owner_token=OWNER_A) is True
        assert repo.set_status(
            task.id,
            TaskStatus.RUNNING,
            status,
            owner_token=OWNER_A,
        ) is True

    assert repo.rollback_running_task(task.id, owner_token=OWNER_A) is False
    assert repo.resume_snapshot(task.id).task.status is status


@pytest.mark.parametrize("evidence", ["iteration", "approval"])
def test_rollback_running_task_rejects_execution_evidence(
    repo: SQLiteTaskRepository, evidence: str
) -> None:
    task = repo.create_task_with_project_reservation(
        f"C:/work/rollback-{evidence}", "keep evidence", round_limit=8
    )
    _start(repo, task.id)
    assert repo.acquire_project_lease(task.id, owner_token=OWNER_A) is True
    iteration = repo.append_iteration(
        task.id, sequence=1, context_digest="a" * 64
    )
    if evidence == "approval":
        repo.record_approval(
            task.id,
            iteration.id,
            '{"arguments":{},"kind":"finish","rationale":"pause"}',
            "b" * 64,
            "c" * 64,
        )

    assert repo.rollback_running_task(task.id, owner_token=OWNER_A) is False

    assert repo.resume_snapshot(task.id).task.status is TaskStatus.RUNNING
    assert repo.owns_project_lease(task.id, owner_token=OWNER_A) is True


def test_rollback_running_task_unknown_task_raises_sanitized_error(
    repo: SQLiteTaskRepository,
) -> None:
    unknown = "missing-running-task-sensitive-token"

    with pytest.raises(StorageStateError) as captured:
        repo.rollback_running_task(unknown, owner_token=OWNER_A)

    assert str(captured.value) == "task does not exist"
    assert unknown not in str(captured.value)


def test_rollback_running_task_validates_owner_token(
    repo: SQLiteTaskRepository,
) -> None:
    task = repo.create_task_with_project_reservation(
        "C:/work/rollback-invalid-owner", "keep task", round_limit=8
    )

    with pytest.raises(StorageStateError, match="owner token"):
        repo.rollback_running_task(task.id, owner_token="")


def test_nonterminal_project_reservation_is_atomic_across_repository_instances(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "state.sqlite"
    first = SQLiteTaskRepository(db_path)
    second = SQLiteTaskRepository(db_path)
    barrier = Barrier(2)

    def claim(repository: SQLiteTaskRepository, request: str) -> str:
        barrier.wait()
        try:
            repository.create_task_with_project_reservation(
                "C:/work/reserved", request, round_limit=8
            )
        except ProjectReservationError:
            return "busy"
        return "created"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = tuple(
            future.result()
            for future in (
                pool.submit(claim, first, "first"),
                pool.submit(claim, second, "second"),
            )
        )

    assert sorted(outcomes) == ["busy", "created"]
    with first._connection_lock:
        count = first._connection.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]
    assert count == 1


def test_terminal_task_does_not_leave_a_stale_project_reservation(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "state.sqlite"
    first = SQLiteTaskRepository(db_path)
    task = first.create_task_with_project_reservation(
        "C:/work/reserved", "first", round_limit=8
    )
    _start(first, task.id)
    assert first.acquire_project_lease(task.id, owner_token=OWNER_A)
    result = TaskResult(
        task_id=task.id,
        status=TaskStatus.SUCCEEDED,
        iterations=0,
        verification_summary="done",
    )
    assert first.set_status(
        task.id,
        TaskStatus.RUNNING,
        TaskStatus.SUCCEEDED,
        result,
        owner_token=OWNER_A,
    )
    first.close()

    reopened = SQLiteTaskRepository(db_path)
    replacement = reopened.create_task_with_project_reservation(
        "C:/work/reserved", "second", round_limit=8
    )

    assert replacement.status is TaskStatus.CREATED


def test_terminal_service_reservation_does_not_transfer_to_unreserved_task(
    repo: SQLiteTaskRepository,
) -> None:
    repo.create_task("C:/work/reserved", "low-level", round_limit=8)
    reserved = repo.create_task_with_project_reservation(
        "C:/work/reserved", "service", round_limit=8
    )
    _start(repo, reserved.id)
    assert repo.acquire_project_lease(reserved.id, owner_token=OWNER_A)
    result = TaskResult(
        task_id=reserved.id,
        status=TaskStatus.SUCCEEDED,
        iterations=0,
        verification_summary="done",
    )
    assert repo.set_status(
        reserved.id,
        TaskStatus.RUNNING,
        TaskStatus.SUCCEEDED,
        result,
        owner_token=OWNER_A,
    )

    replacement = repo.create_task_with_project_reservation(
        "C:/work/reserved", "next service", round_limit=8
    )

    assert replacement.status is TaskStatus.CREATED


def test_legacy_database_open_backfills_nonterminal_project_reservation(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "legacy.sqlite"
    connection = sqlite3.connect(db_path)
    connection.executescript(
        """
        CREATE TABLE projects (
            id TEXT PRIMARY KEY,
            canonical_path TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL
        );
        CREATE TABLE tasks (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(id),
            request TEXT NOT NULL,
            status TEXT NOT NULL,
            round_limit INTEGER NOT NULL,
            deadline TEXT,
            result_json TEXT,
            created_at TEXT NOT NULL
        );
        INSERT INTO projects VALUES ('legacy-project', 'C:/work/legacy', '2026-07-29T00:00:00+00:00');
        INSERT INTO tasks VALUES (
            'legacy-task', 'legacy-project', 'repair', 'created', 8,
            NULL, NULL, '2026-07-29T00:00:00+00:00'
        );
        """
    )
    connection.close()

    reopened = SQLiteTaskRepository(db_path)

    with reopened._connection_lock:
        reservation = reopened._connection.execute(
            "SELECT task_id, migrated, creation_nonce FROM project_reservations"
        ).fetchone()
    assert tuple(reservation) == ("legacy-task", 1, None)
    assert (
        reopened.rollback_created_task(
            "legacy-task", creation_nonce=CREATION_NONCE_A
        )
        is False
    )
    assert reopened.task_exists("legacy-task") is True
    with pytest.raises(ProjectReservationError, match="active work"):
        reopened.create_task_with_project_reservation(
            "C:/work/legacy", "second", round_limit=8
        )


def test_interrupted_reservation_migration_is_retried_on_reopen(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "interrupted.sqlite"
    connection = sqlite3.connect(db_path)
    connection.executescript(
        """
        CREATE TABLE projects (
            id TEXT PRIMARY KEY,
            canonical_path TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL
        );
        CREATE TABLE tasks (
            id TEXT PRIMARY KEY,
            project_id TEXT NOT NULL REFERENCES projects(id),
            request TEXT NOT NULL,
            status TEXT NOT NULL,
            round_limit INTEGER NOT NULL,
            deadline TEXT,
            result_json TEXT,
            created_at TEXT NOT NULL
        );
        CREATE TABLE project_reservations (
            project_id TEXT PRIMARY KEY REFERENCES projects(id),
            task_id TEXT NOT NULL UNIQUE REFERENCES tasks(id) ON DELETE CASCADE,
            acquired_at TEXT NOT NULL,
            migrated INTEGER NOT NULL DEFAULT 0
        );
        INSERT INTO projects VALUES ('legacy-project', 'C:/work/legacy', '2026-07-29T00:00:00+00:00');
        INSERT INTO tasks VALUES (
            'legacy-task', 'legacy-project', 'repair', 'waiting_approval', 8,
            NULL, NULL, '2026-07-29T00:00:00+00:00'
        );
        """
    )
    connection.close()

    reopened = SQLiteTaskRepository(db_path)

    with pytest.raises(ProjectReservationError, match="active work"):
        reopened.create_task_with_project_reservation(
            "C:/work/legacy", "second", round_limit=8
        )


def test_second_active_task_cannot_lease_same_project(repo: SQLiteTaskRepository) -> None:
    """Dropping the unique active-path constraint would allow conflicting repository mutations."""
    first = repo.create_task("C:/work/demo", "fix sum", round_limit=8)
    second = repo.create_task("C:/work/demo", "fix subtract", round_limit=8)
    _start(repo, first.id)
    _start(repo, second.id)

    assert repo.acquire_project_lease(first.id, owner_token=OWNER_A) is True
    assert repo.acquire_project_lease(second.id, owner_token=OWNER_B) is False


def test_resume_does_not_return_unapproved_action_as_executable(repo: SQLiteTaskRepository) -> None:
    """Treating a pending approval as executable would bypass the required human decision."""
    task = repo.create_task("C:/work/demo", "fix sum", round_limit=8)
    iteration = repo.append_iteration(task.id, sequence=1, context_digest="a" * 64)
    repo.record_approval(
        task.id,
        iteration.id,
        action_json='{"kind":"apply_patch"}',
        action_digest="b" * 64,
        repository_snapshot_digest="c" * 64,
    )

    snapshot = repo.resume_snapshot(task.id)

    assert snapshot.pending_approval is not None
    assert snapshot.executable_approval is None


def test_approved_intent_becomes_executable_until_completion(repo: SQLiteTaskRepository) -> None:
    """Marking an approval completed before dispatch recovery would hide a durable pending effect."""
    task = repo.create_task("C:/work/demo", "fix sum", round_limit=8)
    _start(repo, task.id)
    assert repo.acquire_project_lease(task.id, owner_token=OWNER_A) is True
    iteration = repo.append_iteration(task.id, sequence=1, context_digest="a" * 64)
    approval = repo.record_approval(
        task.id,
        iteration.id,
        action_json='{"kind":"apply_patch"}',
        action_digest="b" * 64,
        repository_snapshot_digest="c" * 64,
    )

    decided = repo.decide_approval(approval.id, ApprovalDecision.APPROVE)
    intended = repo.mark_execution_intent(
        decided.id, expected_after_digests={"demo.py": "d" * 64}, owner_token=OWNER_A
    )

    assert (
        repo.resume_snapshot(task.id, owner_token=OWNER_A).executable_approval
        == intended
    )
    assert repo.mark_execution_completed(
        intended.id, owner_token=OWNER_A
    ).execution_state == "completed"
    assert repo.resume_snapshot(task.id).executable_approval is None


def test_approval_decision_is_single_use(repo: SQLiteTaskRepository) -> None:
    """Allowing a second decision would let a rejected action later become approved."""
    task = repo.create_task("C:/work/demo", "fix sum", round_limit=8)
    iteration = repo.append_iteration(task.id, sequence=1, context_digest="a" * 64)
    approval = repo.record_approval(
        task.id,
        iteration.id,
        action_json='{"kind":"apply_patch"}',
        action_digest="b" * 64,
        repository_snapshot_digest="c" * 64,
    )
    repo.decide_approval(approval.id, ApprovalDecision.REJECT)

    with pytest.raises(StorageStateError):
        repo.decide_approval(approval.id, ApprovalDecision.APPROVE)


def test_compare_and_set_rejects_stale_status_and_releases_terminal_lease(
    repo: SQLiteTaskRepository,
) -> None:
    """A stale writer must not advance status or retain a lease after a terminal transition."""
    task = repo.create_task("C:/work/demo", "fix sum", round_limit=8)
    _start(repo, task.id)
    assert repo.acquire_project_lease(task.id, owner_token=OWNER_A) is True
    assert repo.set_status(task.id, TaskStatus.CREATED, TaskStatus.SUCCEEDED) is False
    result = TaskResult(
        task_id=task.id,
        status=TaskStatus.SUCCEEDED,
        iterations=0,
        verification_summary="All checks passed.",
    )
    assert repo.set_status(
        task.id,
        TaskStatus.RUNNING,
        TaskStatus.SUCCEEDED,
        result,
        owner_token=OWNER_A,
    ) is True

    next_task = repo.create_task("C:/work/demo", "fix subtract", round_limit=8)
    _start(repo, next_task.id)
    assert repo.acquire_project_lease(next_task.id, owner_token=OWNER_B) is True
    assert repo.resume_snapshot(task.id).task.result == result


def test_snapshot_returns_iteration_findings_and_rejects_duplicate_sequences(
    repo: SQLiteTaskRepository,
) -> None:
    """Losing persisted findings or accepting duplicate order would corrupt recovery context."""
    task = repo.create_task("C:/work/demo", "fix sum", round_limit=8)
    finding = Finding(
        source="pytest",
        category="assertion",
        severity="error",
        path="src/math.py",
        line=7,
        summary="expected 4",
        evidence="assert 2 + 2 == 5",
        group_key="assert:math:7",
    )
    repo.append_iteration(
        task.id,
        sequence=1,
        context_digest="a" * 64,
        policy_outcome=PolicyOutcome.DENY,
        findings=(finding,),
    )

    records = repo.resume_snapshot(task.id).findings
    assert tuple(record.finding for record in records) == (finding,)
    with pytest.raises(StorageStateError):
        repo.append_iteration(task.id, sequence=1, context_digest="b" * 64)


def test_resolved_findings_remain_persisted_but_are_marked_resolved(
    repo: SQLiteTaskRepository,
) -> None:
    """Deleting or retaining a resolved finding as active would corrupt recovery feedback."""
    task = repo.create_task("C:/work/demo", "fix sum", round_limit=8)
    finding = Finding(
        source="ruff",
        category="ruff",
        severity="warning",
        path="src/math.py",
        line=1,
        summary="unused import",
        evidence="F401",
        group_key="ruff:F401",
    )
    repo.append_iteration(task.id, sequence=1, context_digest="a" * 64, findings=(finding,))
    finding_id = repo.resume_snapshot(task.id).findings[0].id

    assert repo.mark_findings_resolved((finding_id,)) == 1
    record = repo.resume_snapshot(task.id).findings[0]
    assert record.finding == finding
    assert record.resolved_at is not None


@pytest.mark.parametrize("status", [TaskStatus.CREATED, TaskStatus.WAITING_APPROVAL, TaskStatus.SUCCEEDED])
def test_acquire_project_lease_rejects_non_running_tasks(
    repo: SQLiteTaskRepository, status: TaskStatus
) -> None:
    """Leasing outside active execution would allow stale recovery to mutate a repository."""
    task = repo.create_task(f"C:/work/{status.value}", "fix sum", round_limit=8)
    if status is TaskStatus.WAITING_APPROVAL:
        _start(repo, task.id)
        assert repo.acquire_project_lease(task.id, owner_token=OWNER_A) is True
        assert repo.set_status(
            task.id,
            TaskStatus.RUNNING,
            TaskStatus.WAITING_APPROVAL,
            owner_token=OWNER_A,
        ) is True
    elif status is TaskStatus.SUCCEEDED:
        _start(repo, task.id)
        assert repo.acquire_project_lease(task.id, owner_token=OWNER_A) is True
        assert repo.set_status(
            task.id,
            TaskStatus.RUNNING,
            TaskStatus.SUCCEEDED,
            owner_token=OWNER_A,
        ) is True

    with pytest.raises(StorageStateError):
        repo.acquire_project_lease(task.id, owner_token=OWNER_A)


def test_execution_intent_requires_running_task_lease(repo: SQLiteTaskRepository) -> None:
    """Recording an intent without the running task's lease would make recovery unsafe."""
    task = repo.create_task("C:/work/demo", "fix sum", round_limit=8)
    _start(repo, task.id)
    iteration = repo.append_iteration(task.id, sequence=1, context_digest="a" * 64)
    approval = repo.record_approval(
        task.id, iteration.id, '{"kind":"apply_patch"}', "b" * 64, "c" * 64
    )
    repo.decide_approval(approval.id, ApprovalDecision.APPROVE)

    with pytest.raises(StorageStateError):
        repo.mark_execution_intent(approval.id)


def test_execution_intent_rejects_another_tasks_lease(repo: SQLiteTaskRepository) -> None:
    """A lease held by a different task must not authorize this approval's filesystem intent."""
    owner = repo.create_task("C:/work/demo", "fix sum", round_limit=8)
    target = repo.create_task("C:/work/demo", "fix subtract", round_limit=8)
    _start(repo, owner.id)
    _start(repo, target.id)
    assert repo.acquire_project_lease(owner.id, owner_token=OWNER_A) is True
    iteration = repo.append_iteration(target.id, sequence=1, context_digest="a" * 64)
    approval = repo.record_approval(
        target.id, iteration.id, '{"kind":"apply_patch"}', "b" * 64, "c" * 64
    )
    repo.decide_approval(approval.id, ApprovalDecision.APPROVE)

    with pytest.raises(StorageStateError):
        repo.mark_execution_intent(
            approval.id,
            expected_after_digests={"demo.py": "d" * 64},
            owner_token=OWNER_B,
        )


def test_terminal_snapshot_hides_an_approved_incomplete_action(repo: SQLiteTaskRepository) -> None:
    """A terminal task must never expose an unfinished approval for later dispatch."""
    task = repo.create_task("C:/work/demo", "fix sum", round_limit=8)
    _start(repo, task.id)
    assert repo.acquire_project_lease(task.id, owner_token=OWNER_A) is True
    iteration = repo.append_iteration(task.id, sequence=1, context_digest="a" * 64)
    approval = repo.record_approval(
        task.id, iteration.id, '{"kind":"apply_patch"}', "b" * 64, "c" * 64
    )
    repo.decide_approval(approval.id, ApprovalDecision.APPROVE)
    assert repo.set_status(
        task.id,
        TaskStatus.RUNNING,
        TaskStatus.SUCCEEDED,
        owner_token=OWNER_A,
    ) is True

    assert repo.resume_snapshot(task.id).executable_approval is None


def test_repositories_contend_for_a_running_project_lease(tmp_path: Path) -> None:
    """Separate repository instances must observe the same durable lease contention."""
    db_path = tmp_path / "state.sqlite"
    first_repo = SQLiteTaskRepository(db_path)
    second_repo = SQLiteTaskRepository(db_path)
    first = first_repo.create_task("C:/work/demo", "fix sum", round_limit=8)
    second = second_repo.create_task("C:/work/demo", "fix subtract", round_limit=8)
    _start(first_repo, first.id)
    _start(second_repo, second.id)

    assert first_repo.acquire_project_lease(first.id, owner_token=OWNER_A) is True
    assert second_repo.acquire_project_lease(second.id, owner_token=OWNER_B) is False


def test_same_task_cannot_be_leased_by_two_independent_runner_tokens(tmp_path: Path) -> None:
    db_path = tmp_path / "state.sqlite"
    first_repo = SQLiteTaskRepository(db_path)
    second_repo = SQLiteTaskRepository(db_path)
    task = first_repo.create_task("C:/work/demo", "fix sum", round_limit=8)
    _start(first_repo, task.id)

    assert first_repo.acquire_project_lease(task.id, owner_token=OWNER_A) is True
    assert second_repo.acquire_project_lease(task.id, owner_token=OWNER_B) is False
    assert first_repo.acquire_project_lease(task.id, owner_token=OWNER_A) is True

    with pytest.raises(StorageStateError, match="owner"):
        second_repo.record_transition_intent(
            task.id,
            kind="model_call",
            evidence_digest="a" * 64,
            summary="context prepared",
            owner_token=OWNER_B,
        )
    with pytest.raises(StorageStateError, match="local kernel lock"):
        second_repo.record_transition_intent(
            task.id,
            kind="model_call",
            evidence_digest="b" * 64,
            summary="stolen durable token",
            owner_token=OWNER_A,
        )


def test_running_legacy_lease_fails_closed_with_actionable_recovery(
    repo: SQLiteTaskRepository,
) -> None:
    task = repo.create_task("C:/work/demo", "fix sum", round_limit=8)
    _start(repo, task.id)
    repo._connection.execute(
        """INSERT INTO project_leases
           (project_id, task_id, owner_token, acquired_at, protocol)
           VALUES (?, ?, NULL, ?, NULL)""",
        (task.project_id, task.id, "2026-07-29T00:00:00+00:00"),
    )

    with pytest.raises(LeaseRecoveryBlocked, match="legacy.*manual recovery"):
        repo.acquire_project_lease(task.id, owner_token=OWNER_A)


def test_non_running_legacy_lease_is_cleaned_before_new_task_acquires(
    repo: SQLiteTaskRepository,
) -> None:
    stale = repo.create_task("C:/work/demo", "old task", round_limit=8)
    active = repo.create_task("C:/work/demo", "new task", round_limit=8)
    repo._connection.execute(
        """INSERT INTO project_leases
           (project_id, task_id, owner_token, acquired_at, protocol)
           VALUES (?, ?, NULL, ?, NULL)""",
        (stale.project_id, stale.id, "2026-07-29T00:00:00+00:00"),
    )
    _start(repo, active.id)

    assert repo.acquire_project_lease(active.id, owner_token=OWNER_A) is True


def test_failed_durable_release_still_closes_local_kernel_lock(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "state.sqlite"
    first = SQLiteTaskRepository(db_path)
    task = first.create_task("C:/work/demo", "fix sum", round_limit=8)
    _start(first, task.id)
    assert first.acquire_project_lease(task.id, owner_token=OWNER_A) is True
    first._connection.execute(
        """CREATE TRIGGER abort_lease_release BEFORE DELETE ON project_leases
           BEGIN SELECT RAISE(ABORT, 'simulated release failure'); END"""
    )

    with pytest.raises(sqlite3.Error, match="simulated release failure"):
        first.release_project_lease(task.id, owner_token=OWNER_A)
    first._connection.execute("DROP TRIGGER abort_lease_release")

    second = SQLiteTaskRepository(db_path)
    assert second.acquire_project_lease(task.id, owner_token=OWNER_B) is True


def test_in_memory_repositories_have_isolated_temporary_lock_roots() -> None:
    first = SQLiteTaskRepository(Path(":memory:"))
    second = SQLiteTaskRepository(Path(":memory:"))
    first_task = first.create_task("C:/work/first", "fix sum", round_limit=8)
    second_task = second.create_task("C:/work/second", "fix sum", round_limit=8)
    _start(first, first_task.id)
    _start(second, second_task.id)

    assert first.acquire_project_lease(first_task.id, owner_token=OWNER_A) is True
    assert second.acquire_project_lease(second_task.id, owner_token=OWNER_B) is True
    first_root = first._lock_root
    second_root = second._lock_root
    assert first_root != second_root
    assert first_root.is_dir()
    assert second_root.is_dir()

    first.close()
    assert not first_root.exists()
    assert second_root.is_dir()
    second.close()
    assert not second_root.exists()


def test_sqlite_uri_is_rejected_with_redacted_typed_error() -> None:
    uri = Path("file:state.sqlite?mode=memory&token=sensitive-value")

    with pytest.raises(StorageStateError) as captured:
        SQLiteTaskRepository(uri)

    assert "URI database paths are not supported" in str(captured.value)
    assert "sensitive-value" not in str(captured.value)


def test_approval_insert_and_waiting_transition_are_one_transaction(
    repo: SQLiteTaskRepository,
) -> None:
    task = repo.create_task("C:/work/demo", "fix sum", round_limit=8)
    _start(repo, task.id)
    assert repo.acquire_project_lease(task.id, owner_token=OWNER_A) is True
    iteration = repo.append_iteration(task.id, sequence=1, context_digest="a" * 64)
    waiting = TaskResult(
        task_id=task.id,
        status=TaskStatus.WAITING_APPROVAL,
        iterations=1,
        verification_summary="Approval required.",
    )

    repo._connection.execute(
        """CREATE TRIGGER abort_wait BEFORE UPDATE OF status ON tasks
           WHEN NEW.status = 'waiting_approval'
           BEGIN SELECT RAISE(ABORT, 'simulated crash'); END"""
    )
    with pytest.raises(StorageStateError):
        repo.request_approval_and_wait(
            task.id,
            iteration.id,
            '{"arguments":{},"kind":"finish","rationale":"pause"}',
            "b" * 64,
            "c" * 64,
            policy_decision=_approval_decision(),
            waiting_result=waiting,
            owner_token=OWNER_A,
        )

    snapshot = repo.resume_snapshot(task.id)
    assert snapshot.task.status is TaskStatus.RUNNING
    assert snapshot.pending_approval is None


def test_replacement_approval_and_waiting_transition_are_one_transaction(
    repo: SQLiteTaskRepository,
) -> None:
    task = repo.create_task("C:/work/demo", "fix sum", round_limit=8)
    _start(repo, task.id)
    assert repo.acquire_project_lease(task.id, owner_token=OWNER_A) is True
    iteration = repo.append_iteration(task.id, sequence=1, context_digest="a" * 64)
    original = repo.record_approval(
        task.id,
        iteration.id,
        '{"arguments":{"patch":"x"},"kind":"apply_patch","rationale":"patch"}',
        "b" * 64,
        "c" * 64,
        policy_decision=_approval_decision(),
    )
    repo.decide_approval(original.id, ApprovalDecision.APPROVE)
    waiting = TaskResult(
        task_id=task.id,
        status=TaskStatus.WAITING_APPROVAL,
        iterations=1,
        verification_summary="Approval changed.",
    )
    refreshed = _approval_decision().model_copy(
        update={"matched_rule": "new_rule", "impact_summary": "Changed policy."}
    )
    repo._connection.execute(
        """CREATE TRIGGER abort_rewait BEFORE UPDATE OF status ON tasks
           WHEN NEW.status = 'waiting_approval'
           BEGIN SELECT RAISE(ABORT, 'simulated crash'); END"""
    )

    with pytest.raises(StorageStateError):
        repo.replace_approval_and_wait(
            original.id,
            refreshed,
            waiting_result=waiting,
            owner_token=OWNER_A,
        )

    snapshot = repo.resume_snapshot(task.id)
    assert snapshot.task.status is TaskStatus.RUNNING
    assert snapshot.pending_approval is None
    assert snapshot.decided_approval.execution_state == "pending"


def test_empty_expected_patch_effect_cannot_mean_already_applied(
    repo: SQLiteTaskRepository,
) -> None:
    task = repo.create_task("C:/work/demo", "fix sum", round_limit=8)
    _start(repo, task.id)
    assert repo.acquire_project_lease(task.id, owner_token=OWNER_A) is True
    iteration = repo.append_iteration(task.id, sequence=1, context_digest="a" * 64)
    approval = repo.record_approval(
        task.id,
        iteration.id,
        '{"arguments":{"patch":"x"},"kind":"apply_patch","rationale":"patch"}',
        "b" * 64,
        "c" * 64,
    )
    repo.decide_approval(approval.id, ApprovalDecision.APPROVE)

    with pytest.raises(StorageStateError, match="expected effect"):
        repo.mark_execution_intent(
            approval.id, expected_after_digests={}, owner_token=OWNER_A
        )


def test_expected_effect_paths_enforce_utf8_byte_limit(repo: SQLiteTaskRepository) -> None:
    task = repo.create_task("C:/work/demo", "fix sum", round_limit=8)
    _start(repo, task.id)
    assert repo.acquire_project_lease(task.id, owner_token=OWNER_A) is True
    iteration = repo.append_iteration(task.id, sequence=1, context_digest="a" * 64)
    approval = repo.record_approval(
        task.id,
        iteration.id,
        '{"arguments":{"patch":"x"},"kind":"apply_patch","rationale":"patch"}',
        "b" * 64,
        "c" * 64,
    )
    repo.decide_approval(approval.id, ApprovalDecision.APPROVE)

    with pytest.raises(StorageStateError, match="UTF-8"):
        repo.mark_execution_intent(
            approval.id,
            expected_after_digests={"界" * 4_000: "d" * 64},
            owner_token=OWNER_A,
        )


def test_approval_action_payload_enforces_utf8_byte_limit(repo: SQLiteTaskRepository) -> None:
    task = repo.create_task("C:/work/demo", "fix sum", round_limit=8)
    iteration = repo.append_iteration(task.id, sequence=1, context_digest="a" * 64)
    oversized = (
        '{"arguments":{},"kind":"finish","rationale":"'
        + "界" * 30_000
        + '"}'
    )

    with pytest.raises(StorageStateError, match="action payload"):
        repo.record_approval(
            task.id, iteration.id, oversized, "b" * 64, "c" * 64
        )


def test_reopen_recovers_rejected_approval_and_saved_policy_decision(tmp_path: Path) -> None:
    """Dropping decided approval data would lose rejection feedback after a restart."""
    db_path = tmp_path / "state.sqlite"
    repo = SQLiteTaskRepository(db_path)
    task = repo.create_task("C:/work/demo", "fix sum", round_limit=8)
    _start(repo, task.id)
    iteration = repo.append_iteration(task.id, sequence=1, context_digest="a" * 64)
    approval = repo.record_approval(
        task.id,
        iteration.id,
        '{"arguments":{},"kind":"apply_patch","rationale":"update deps"}',
        "b" * 64,
        "c" * 64,
        policy_decision=_approval_decision(),
    )
    assert repo.acquire_project_lease(task.id, owner_token=OWNER_A) is True
    assert repo.set_status(
        task.id,
        TaskStatus.RUNNING,
        TaskStatus.WAITING_APPROVAL,
        owner_token=OWNER_A,
    ) is True
    repo.decide_approval(approval.id, ApprovalDecision.REJECT)

    recovered = SQLiteTaskRepository(db_path).resume_snapshot(task.id).decided_approval

    assert recovered is not None
    assert recovered.id == approval.id
    assert recovered.decision is ApprovalDecision.REJECT
    assert recovered.policy_decision == _approval_decision()

    assert repo.set_status(task.id, TaskStatus.WAITING_APPROVAL, TaskStatus.RUNNING) is True
    assert repo.acquire_project_lease(task.id, owner_token=OWNER_A) is True
    consumed = repo.mark_rejection_consumed(approval.id, owner_token=OWNER_A)
    assert consumed.execution_state == "completed"
    assert SQLiteTaskRepository(db_path).resume_snapshot(task.id).decided_approval == consumed


def test_reopen_recovers_expected_after_digests_before_dispatch_completion(
    tmp_path: Path,
) -> None:
    """Losing expected digests at the crash boundary would force blind patch replay."""
    db_path = tmp_path / "state.sqlite"
    repo = SQLiteTaskRepository(db_path)
    task = repo.create_task("C:/work/demo", "fix sum", round_limit=8)
    _start(repo, task.id)
    assert repo.acquire_project_lease(task.id, owner_token=OWNER_A) is True
    iteration = repo.append_iteration(task.id, sequence=1, context_digest="a" * 64)
    approval = repo.record_approval(
        task.id,
        iteration.id,
        '{"arguments":{},"kind":"apply_patch","rationale":"update deps"}',
        "b" * 64,
        "c" * 64,
        policy_decision=_approval_decision(),
    )
    repo.decide_approval(approval.id, ApprovalDecision.APPROVE)
    repo.mark_execution_intent(
        approval.id,
        expected_after_digests={"pyproject.toml": "d" * 64, "requirements.txt": None},
        owner_token=OWNER_A,
    )
    repo.close()

    reopened = SQLiteTaskRepository(db_path)
    assert reopened.acquire_project_lease(task.id, owner_token=OWNER_B) is True
    recovered = reopened.resume_snapshot(
        task.id, owner_token=OWNER_B
    ).executable_approval

    assert recovered is not None
    assert recovered.execution_state == "intent_recorded"
    assert recovered.expected_after_digests == {
        "pyproject.toml": "d" * 64,
        "requirements.txt": None,
    }
    completed = reopened.mark_execution_completed(
        approval.id, result_digest="e" * 64, owner_token=OWNER_B
    )
    assert completed.result_digest == "e" * 64


def test_transition_intent_evidence_survives_reopen_and_completion(tmp_path: Path) -> None:
    """Without durable pre/post evidence, resume could repeat an external transition."""
    db_path = tmp_path / "state.sqlite"
    repo = SQLiteTaskRepository(db_path)
    task = repo.create_task("C:/work/demo", "fix sum", round_limit=8)
    _start(repo, task.id)
    assert repo.acquire_project_lease(task.id, owner_token=OWNER_A) is True
    intent = repo.record_transition_intent(
        task.id,
        kind="model_call",
        evidence_digest="a" * 64,
        summary="context prepared",
        owner_token=OWNER_A,
    )
    repo.close()

    reopened = SQLiteTaskRepository(db_path)
    assert reopened.acquire_project_lease(task.id, owner_token=OWNER_B) is True
    pending = reopened.resume_snapshot(task.id).transition_intents
    assert len(pending) == 1
    assert pending[0].id == intent.id
    assert pending[0].state == "pending"
    completed = reopened.complete_transition_intent(
        intent.id,
        result_digest="b" * 64,
        summary="response persisted",
        owner_token=OWNER_B,
    )
    assert completed.state == "completed"
    assert completed.result_digest == "b" * 64
    assert completed.completion_summary == "response persisted"


def test_completed_transition_payload_is_bounded_and_consumed_with_iteration(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "state.sqlite"
    repo = SQLiteTaskRepository(db_path)
    task = repo.create_task("C:/work/demo", "fix sum", round_limit=8)
    _start(repo, task.id)
    assert repo.acquire_project_lease(task.id, owner_token=OWNER_A) is True
    intent = repo.record_transition_intent(
        task.id,
        kind="model_call",
        evidence_digest="a" * 64,
        summary="context prepared",
        owner_token=OWNER_A,
    )
    completed = repo.complete_transition_intent(
        intent.id,
        result_digest="b" * 64,
        summary="normalized action persisted",
        result_payload={
            "outcome": "action",
            "action": {"kind": "finish", "arguments": {}, "rationale": "verify"},
        },
        owner_token=OWNER_A,
    )
    assert completed.result_payload["outcome"] == "action"
    repo.close()

    reopened = SQLiteTaskRepository(db_path)
    assert reopened.acquire_project_lease(task.id, owner_token=OWNER_B) is True
    recovered = reopened.resume_snapshot(task.id).transition_intents[0]
    assert recovered.result_payload == completed.result_payload
    assert recovered.consumed_at is None
    reopened.append_iteration(
        task.id,
        sequence=1,
        context_digest="a" * 64,
        action_json='{"arguments":{},"kind":"finish","rationale":"verify"}',
        source_intent_ids=(intent.id,),
        owner_token=OWNER_B,
    )
    assert reopened.resume_snapshot(task.id).transition_intents[0].consumed_at is not None


def test_transition_payload_rejects_unbounded_utf8(repo: SQLiteTaskRepository) -> None:
    task = repo.create_task("C:/work/demo", "fix sum", round_limit=8)
    _start(repo, task.id)
    assert repo.acquire_project_lease(task.id, owner_token=OWNER_A) is True
    intent = repo.record_transition_intent(
        task.id,
        kind="model_call",
        evidence_digest="a" * 64,
        summary="context prepared",
        owner_token=OWNER_A,
    )

    with pytest.raises(StorageStateError, match="payload"):
        repo.complete_transition_intent(
            intent.id,
            result_digest="b" * 64,
            summary="response persisted",
            result_payload={"summary": "界" * 30_000},
            owner_token=OWNER_A,
        )


def test_deferred_approval_outcome_completes_original_iteration_idempotently(
    tmp_path: Path,
) -> None:
    """Appending a second round or duplicating findings would corrupt approval recovery."""
    db_path = tmp_path / "state.sqlite"
    repo = SQLiteTaskRepository(db_path)
    task = repo.create_task("C:/work/demo", "fix sum", round_limit=8)
    _start(repo, task.id)
    assert repo.acquire_project_lease(task.id, owner_token=OWNER_A) is True
    iteration = repo.append_iteration(task.id, sequence=1, context_digest="a" * 64)
    finding = Finding(
        source="pytest",
        category="assertion",
        severity="error",
        path="tests/test_demo.py",
        line=3,
        summary="still failing",
        evidence="assert 0 == 1",
        group_key="pytest:assertion:demo:3",
    )

    completed = repo.complete_iteration_outcome(
        task.id,
        iteration.id,
        tool_result_digest="b" * 64,
        fingerprint="c" * 64,
        relevant_digest="d" * 64,
        quality_outcome="failed",
        findings=(finding,),
        owner_token=OWNER_A,
    )
    repeated = repo.complete_iteration_outcome(
        task.id,
        iteration.id,
        tool_result_digest="b" * 64,
        fingerprint="c" * 64,
        relevant_digest="d" * 64,
        quality_outcome="failed",
        findings=(finding,),
        owner_token=OWNER_A,
    )
    reopened = SQLiteTaskRepository(db_path).resume_snapshot(task.id)

    assert completed == repeated
    assert len(reopened.iterations) == 1
    assert reopened.iterations[0].quality_outcome == "failed"
    assert tuple(record.finding for record in reopened.findings) == (finding,)


def test_every_shared_connection_execute_is_serialized_by_repository_lock(
    repo: SQLiteTaskRepository, tmp_path: Path
) -> None:
    root = tmp_path / "serialized"
    root.mkdir()
    task = repo.create_task(str(root.resolve()), "read", round_limit=2)
    connection = repo._connection

    class GuardedConnection:
        def execute(self, *args, **kwargs):
            assert repo._connection_lock._is_owned()
            return connection.execute(*args, **kwargs)

        def __getattr__(self, name: str):
            return getattr(connection, name)

    repo._connection = GuardedConnection()
    try:
        assert repo.pending_approval(task.id) is None
    finally:
        repo._connection = connection


def test_concurrent_snapshot_readers_and_iteration_writer_share_one_connection_lock(
    repo: SQLiteTaskRepository, tmp_path: Path
) -> None:
    root = tmp_path / "reader-writer"
    root.mkdir()
    task = repo.create_task(str(root.resolve()), "stress", round_limit=8)

    def write() -> None:
        for sequence in range(1, 21):
            repo.append_iteration(
                task.id,
                sequence=sequence,
                context_digest=f"{sequence:064x}",
            )

    def read() -> None:
        for _ in range(40):
            assert repo.resume_snapshot(task.id).task.id == task.id

    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(write), pool.submit(read), pool.submit(read)]
        for future in futures:
            future.result()

    assert len(repo.resume_snapshot(task.id).iterations) == 20
