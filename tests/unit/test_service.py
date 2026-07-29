from __future__ import annotations

import json
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from threading import Event

import pytest

from pyquality.config import Settings
from pyquality.domain.models import ApprovalDecision, AuditEvent, TaskResult, TaskStatus
from pyquality.security import CredentialStatus
from pyquality.service import HarnessService, PreflightError, ProjectBusyError
from pyquality.storage.sqlite import SQLiteTaskRepository


class StubLoop:
    def __init__(self, repository: SQLiteTaskRepository) -> None:
        self.repository = repository
        self.runs: list[str] = []
        self.leased_runs: list[tuple[str, str, bool]] = []
        self.decisions: list[tuple[str, ApprovalDecision]] = []

    def run(self, task_id: str) -> TaskResult:
        self.runs.append(task_id)
        return TaskResult(
            task_id=task_id,
            status=TaskStatus.SUCCEEDED,
            iterations=1,
            verification_summary="Quality checks passed.",
        )

    def resume(self, task_id: str) -> TaskResult:
        return self.run(task_id)

    def run_leased(self, task_id: str, owner_token: str, *, resume: bool) -> TaskResult:
        assert self.repository.acquire_project_lease(task_id, owner_token=owner_token)
        self.leased_runs.append((task_id, owner_token, resume))
        result = self.resume(task_id) if resume else self.run(task_id)
        assert self.repository.set_status(
            task_id,
            TaskStatus.RUNNING,
            result.status,
            result,
            owner_token=owner_token,
        )
        return result

    def decide_approval(self, approval_id: str, decision: ApprovalDecision) -> str:
        self.decisions.append((approval_id, decision))
        return "task-for-approval"


class CredentialProbe:
    def __init__(self, present: bool) -> None:
        self.present = present

    def status(self, account: str) -> CredentialStatus:
        assert account == "provider"
        return CredentialStatus(present=self.present, source="keyring")


class FailOnceExecutor:
    def __init__(self, delegate: ThreadPoolExecutor) -> None:
        self._delegate = delegate
        self._failed = False

    def submit(self, *args, **kwargs):
        if not self._failed:
            self._failed = True
            raise RuntimeError("submit failed")
        return self._delegate.submit(*args, **kwargs)

    def shutdown(self, *, wait: bool, cancel_futures: bool) -> None:
        self._delegate.shutdown(wait=wait, cancel_futures=cancel_futures)


@pytest.fixture
def repository(tmp_path: Path) -> SQLiteTaskRepository:
    return SQLiteTaskRepository(tmp_path / "state.sqlite")


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    return root


def make_service(repository: SQLiteTaskRepository, **kwargs: object) -> HarnessService:
    return HarnessService(
        repository=repository,
        loop=StubLoop(repository),
        settings=Settings(global_concurrency=1),
        verifier_finder=lambda name: f"/tools/{name}",
        **kwargs,
    )


def test_service_rejects_second_active_task_for_same_repository(
    repository: SQLiteTaskRepository, repo: Path
) -> None:
    entered = Event()
    release = Event()

    class BlockingLoop(StubLoop):
        def run(self, task_id: str) -> TaskResult:
            entered.set()
            assert release.wait(2)
            return super().run(task_id)

    service = HarnessService(
        repository=repository,
        loop=BlockingLoop(repository),
        settings=Settings(),
        verifier_finder=lambda name: name,
    )
    service.create_task(repo, "first")
    assert entered.wait(1)

    with pytest.raises(ProjectBusyError, match="already has active work"):
        service.create_task(repo, "second")
    release.set()


def test_fresh_service_rejects_same_repository_while_first_task_waits(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "state.sqlite"
    repo = tmp_path / "repo"
    repo.mkdir()
    first_repository = SQLiteTaskRepository(db_path)

    class WaitingLoop(StubLoop):
        def run_leased(
            self, task_id: str, owner_token: str, *, resume: bool
        ) -> TaskResult:
            assert self.repository.acquire_project_lease(
                task_id, owner_token=owner_token
            )
            result = TaskResult(
                task_id=task_id,
                status=TaskStatus.WAITING_APPROVAL,
                iterations=1,
                verification_summary="Waiting for approval.",
            )
            assert self.repository.set_status(
                task_id,
                TaskStatus.RUNNING,
                TaskStatus.WAITING_APPROVAL,
                result,
                owner_token=owner_token,
            )
            return result

    first = HarnessService(
        repository=first_repository,
        loop=WaitingLoop(first_repository),
        settings=Settings(global_concurrency=1),
        verifier_finder=lambda name: name,
    )
    waiting = first.create_task(repo, "first")
    assert first.start_task(waiting.id).result(timeout=2).status is TaskStatus.WAITING_APPROVAL
    first.close()
    first_repository.close()

    reopened_repository = SQLiteTaskRepository(db_path)
    reopened = HarnessService(
        repository=reopened_repository,
        loop=StubLoop(reopened_repository),
        settings=Settings(global_concurrency=1),
        verifier_finder=lambda name: name,
    )
    try:
        with pytest.raises(ProjectBusyError, match="active work"):
            reopened.create_task(repo, "second")
    finally:
        reopened.close()
        reopened_repository.close()


def test_preflight_reports_missing_verifier_and_invalid_repository(
    repository: SQLiteTaskRepository, repo: Path
) -> None:
    missing = HarnessService(
        repository=repository,
        loop=StubLoop(repository),
        settings=Settings(),
        verifier_finder=lambda name: None if name == "pytest" else name,
    )
    with pytest.raises(PreflightError, match="pytest"):
        missing.create_task(repo, "fix")
    with pytest.raises(PreflightError, match="repository"):
        make_service(repository).create_task(repo / "missing", "fix")


def test_real_provider_requires_credential(repository: SQLiteTaskRepository, repo: Path) -> None:
    service = make_service(
        repository,
        provider="openai",
        credentials=CredentialProbe(False),
    )
    with pytest.raises(PreflightError, match="credential"):
        service.create_task(repo, "fix")


def test_bounded_submission_releases_capacity_and_repository_on_terminal_result(
    repository: SQLiteTaskRepository, repo: Path
) -> None:
    service = make_service(repository)
    first = service.create_task(repo, "first")
    future = service.start_task(first.id)
    assert isinstance(future, Future)
    assert future.result(timeout=2).status is TaskStatus.SUCCEEDED
    assert service._loop.leased_runs[0][0] == first.id

    second = service.create_task(repo, "second")
    assert service.start_task(second.id).result(timeout=2).status is TaskStatus.SUCCEEDED


def test_terminal_future_is_not_published_until_cleanup_allows_new_task(
    repository: SQLiteTaskRepository, repo: Path
) -> None:
    cleanup_entered = Event()
    allow_cleanup = Event()
    original_owns = repository.owns_project_lease

    def block_terminal_cleanup(task_id: str, *, owner_token: str) -> bool:
        snapshot = repository.resume_snapshot(task_id)
        if snapshot.task.status in {
            TaskStatus.SUCCEEDED,
            TaskStatus.STALLED,
            TaskStatus.BUDGET_EXHAUSTED,
            TaskStatus.BLOCKED,
            TaskStatus.FAILED,
        }:
            cleanup_entered.set()
            assert allow_cleanup.wait(2)
        return original_owns(task_id, owner_token=owner_token)

    repository.owns_project_lease = block_terminal_cleanup
    service = make_service(repository)
    task = service.create_task(repo, "first")
    future = service.start_task(task.id)
    assert cleanup_entered.wait(1)

    published_before_cleanup = future.done()
    capacity_available_before_cleanup = True
    try:
        service.create_task(repo, "too early")
    except PreflightError:
        capacity_available_before_cleanup = False
    allow_cleanup.set()
    assert not published_before_cleanup
    assert not capacity_available_before_cleanup
    assert future.result(timeout=2).status is TaskStatus.SUCCEEDED
    replacement = service.create_task(repo, "after cleanup")
    assert service.start_task(replacement.id).result(timeout=2).status is TaskStatus.SUCCEEDED


def test_completed_submissions_are_evicted_and_terminal_start_is_reconstructed(
    repository: SQLiteTaskRepository, repo: Path
) -> None:
    service = make_service(repository)
    task_ids: list[str] = []

    for sequence in range(20):
        task = service.create_task(repo, f"task {sequence}")
        task_ids.append(task.id)
        assert service.start_task(task.id).result(timeout=2).status is TaskStatus.SUCCEEDED

    assert service._futures == {}
    reconstructed = service.start_task(task_ids[-1])
    duplicate = service.start_task(task_ids[-1])
    assert reconstructed.result(timeout=2).status is TaskStatus.SUCCEEDED
    assert duplicate.result(timeout=2) == reconstructed.result(timeout=2)
    assert service._futures == {}


def test_cleanup_exception_is_published_after_remaining_resources_are_released(
    repository: SQLiteTaskRepository, tmp_path: Path
) -> None:
    first_repo = tmp_path / "cleanup-error"
    second_repo = tmp_path / "after-cleanup-error"
    first_repo.mkdir()
    second_repo.mkdir()
    original_release = repository.release_project_lease
    original_owns = repository.owns_project_lease
    failed_once = False

    def own_terminal_cleanup(task_id: str, *, owner_token: str) -> bool:
        if repository.resume_snapshot(task_id).task.status is TaskStatus.SUCCEEDED:
            return True
        return original_owns(task_id, owner_token=owner_token)

    def release_then_fail(task_id: str, *, owner_token: str) -> None:
        nonlocal failed_once
        original_release(task_id, owner_token=owner_token)
        if not failed_once:
            failed_once = True
            raise RuntimeError("cleanup failed")

    repository.owns_project_lease = own_terminal_cleanup
    repository.release_project_lease = release_then_fail
    service = make_service(repository)
    task = service.create_task(first_repo, "first")

    with pytest.raises(RuntimeError, match="cleanup failed"):
        service.start_task(task.id).result(timeout=2)

    assert service._futures == {}
    replacement = service.create_task(second_repo, "capacity was released")
    assert service.start_task(replacement.id).result(timeout=2).status is TaskStatus.SUCCEEDED


def test_create_submit_failure_completes_cleanup_when_lease_release_raises(
    repository: SQLiteTaskRepository,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    failed_repo = tmp_path / "failed-submit"
    replacement_repo = tmp_path / "replacement"
    failed_repo.mkdir()
    replacement_repo.mkdir()
    service = make_service(repository)
    service._executor = FailOnceExecutor(service._executor)
    original_release = repository.release_project_lease
    release_calls = 0

    def fail_release_once(task_id: str, *, owner_token: str) -> None:
        nonlocal release_calls
        release_calls += 1
        if release_calls == 1:
            raise RuntimeError("release failed")
        original_release(task_id, owner_token=owner_token)

    monkeypatch.setattr(repository, "release_project_lease", fail_release_once)

    with pytest.raises(RuntimeError, match="submit failed"):
        service.create_task(failed_repo, "first")

    with repository._connection_lock:
        task_count = repository._connection.execute(
            "SELECT COUNT(*) FROM tasks"
        ).fetchone()[0]
    assert task_count == 0
    assert service._futures == {}
    assert service._pending_owners == {}
    assert service._active_repositories == {}
    replacement = service.create_task(replacement_repo, "capacity is reusable")
    assert service.start_task(replacement.id).result(timeout=2).status is TaskStatus.SUCCEEDED
    service.close()


def test_same_nonce_post_commit_failure_uses_authorized_creation_rollback(
    repository: SQLiteTaskRepository,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "post-commit-create"
    project.mkdir()
    service = make_service(repository)
    original_create = repository.create_task_with_project_reservation
    committed_ids: list[str] = []
    public_cancel_called = Event()

    def commit_then_fail(*args, **kwargs):
        record = original_create(*args, **kwargs)
        committed_ids.append(record.id)
        raise RuntimeError("primary post-commit failure")

    def forbid_public_cancel(task_id: str) -> bool:
        del task_id
        public_cancel_called.set()
        raise RuntimeError("public cancellation is forbidden for compensation")

    monkeypatch.setattr(
        repository, "create_task_with_project_reservation", commit_then_fail
    )
    monkeypatch.setattr(repository, "cancel_created_task", forbid_public_cancel)

    with pytest.raises(RuntimeError, match="primary post-commit failure") as captured:
        service.create_task(project, "first")

    task_id = committed_ids[-1]
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert public_cancel_called.is_set() is False
    assert repository.task_exists(task_id) is False
    with repository._connection_lock:
        counts = repository._connection.execute(
            """SELECT
                 (SELECT COUNT(*) FROM tasks) AS tasks,
                 (SELECT COUNT(*) FROM project_reservations) AS reservations"""
        ).fetchone()
    assert tuple(counts) == (0, 0)
    assert service._futures == {}
    assert service._pending_owners == {}
    assert service._task_repositories == {}
    assert service._active_repositories == {}
    assert service._capacity.acquire(blocking=False) is True
    service._capacity.release()

    monkeypatch.setattr(
        repository, "create_task_with_project_reservation", original_create
    )
    replacement = service.create_task(project, "replacement")
    assert service.start_task(replacement.id).result(timeout=2).status is TaskStatus.SUCCEEDED
    service.close()


def test_creation_identity_conflict_never_deletes_preexisting_task(
    repository: SQLiteTaskRepository,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_project = tmp_path / "identity-owner"
    new_project = tmp_path / "identity-collision"
    original_project.mkdir()
    new_project.mkdir()
    task_id = "service-owned-identity-collision"
    original = repository.create_task_with_project_reservation(
        str(original_project.resolve()),
        "original",
        round_limit=8,
        task_id=task_id,
        creation_nonce="original-creation-nonce",
    )
    service = make_service(repository)

    class FixedIdentity:
        hex = task_id

    monkeypatch.setattr("pyquality.service.uuid4", lambda: FixedIdentity())

    with pytest.raises(PreflightError, match="task creation is unavailable") as captured:
        service.create_task(new_project, "different work")

    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert repository.resume_snapshot(task_id).task == original
    with repository._connection_lock:
        reservation = repository._connection.execute(
            "SELECT task_id FROM project_reservations WHERE task_id = ?",
            (task_id,),
        ).fetchone()
    assert reservation["task_id"] == task_id
    assert service._capacity.acquire(blocking=False) is True
    service._capacity.release()
    service.close()


@pytest.mark.parametrize("same_inputs", [False, True], ids=["fixed-id", "exact-inputs"])
def test_creation_nonce_setup_failure_never_cancels_unowned_collision(
    repository: SQLiteTaskRepository,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    same_inputs: bool,
) -> None:
    original_project = tmp_path / "nonce-owner"
    attempted_project = original_project if same_inputs else tmp_path / "nonce-collision"
    original_project.mkdir()
    if attempted_project != original_project:
        attempted_project.mkdir()
    task_id = "fixed-colliding-task-id"
    original_request = "same immutable request"
    attempted_request = original_request if same_inputs else "different work"
    original_nonce = "original-durable-creation-nonce"
    attempted_nonce = "different-attempt-creation-nonce"
    original = repository.create_task_with_project_reservation(
        str(original_project.resolve()),
        original_request,
        round_limit=8,
        task_id=task_id,
        creation_nonce=original_nonce,
    )
    service = make_service(repository)
    identities = iter((task_id, attempted_nonce))

    class FixedIdentity:
        def __init__(self, value: str) -> None:
            self.hex = value

    monkeypatch.setattr(
        "pyquality.service.uuid4", lambda: FixedIdentity(next(identities))
    )

    def fail_before_storage(*args, **kwargs):
        del args, kwargs
        raise RuntimeError("primary setup failure before storage")

    monkeypatch.setattr(
        repository, "create_task_with_project_reservation", fail_before_storage
    )

    with pytest.raises(RuntimeError, match="primary setup failure") as captured:
        service.create_task(attempted_project, attempted_request)

    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert repository.resume_snapshot(task_id).task == original
    with repository._connection_lock:
        reservation = repository._connection.execute(
            """SELECT task_id, creation_nonce FROM project_reservations
               WHERE task_id = ?""",
            (task_id,),
        ).fetchone()
    assert tuple(reservation) == (task_id, original_nonce)
    assert service._capacity.acquire(blocking=False) is True
    service._capacity.release()
    service.close()


def test_incomplete_create_rollback_keeps_running_task_recoverable_and_frees_capacity(
    repository: SQLiteTaskRepository,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    failed_repo = tmp_path / "recoverable-submit"
    other_repo = tmp_path / "other"
    failed_repo.mkdir()
    other_repo.mkdir()
    service = make_service(repository)
    service._executor = FailOnceExecutor(service._executor)
    original_release = repository.release_project_lease
    original_rollback = repository.rollback_running_task
    release_calls = 0
    rollback_calls = 0

    def fail_release_once(task_id: str, *, owner_token: str) -> None:
        nonlocal release_calls
        release_calls += 1
        if release_calls == 1:
            raise RuntimeError("release failed")
        original_release(task_id, owner_token=owner_token)

    def fail_rollback_once(task_id: str, *, owner_token: str) -> bool:
        nonlocal rollback_calls
        rollback_calls += 1
        if rollback_calls == 1:
            raise RuntimeError("rollback failed")
        return original_rollback(task_id, owner_token=owner_token)

    monkeypatch.setattr(repository, "release_project_lease", fail_release_once)
    monkeypatch.setattr(repository, "rollback_running_task", fail_rollback_once)

    with pytest.raises(RuntimeError, match="submit failed"):
        service.create_task(failed_repo, "first")

    with repository._connection_lock:
        row = repository._connection.execute(
            "SELECT id, status FROM tasks"
        ).fetchone()
    task_id = row["id"]
    assert row["status"] == TaskStatus.RUNNING.value
    assert task_id not in service._futures
    assert task_id in service._pending_owners
    assert service._active_repositories[str(failed_repo.resolve())] == task_id
    assert service.get_task(task_id).resume_available

    replacement = service.create_task(other_repo, "capacity is reusable")
    assert service.start_task(replacement.id).result(timeout=2).status is TaskStatus.SUCCEEDED
    assert service.resume_task(task_id).result(timeout=2).status is TaskStatus.SUCCEEDED
    service.close()


def test_create_rollback_recognizes_atomic_commit_before_cleanup_error(
    repository: SQLiteTaskRepository,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    failed_repo = tmp_path / "committed-discard"
    replacement_repo = tmp_path / "after-committed-discard"
    failed_repo.mkdir()
    replacement_repo.mkdir()
    service = make_service(repository)
    service._executor = FailOnceExecutor(service._executor)
    original_rollback = repository.rollback_running_task

    def rollback_then_fail(task_id: str, *, owner_token: str) -> bool:
        assert original_rollback(task_id, owner_token=owner_token) is True
        raise RuntimeError("post-rollback cleanup failed")

    monkeypatch.setattr(repository, "rollback_running_task", rollback_then_fail)

    with pytest.raises(RuntimeError, match="submit failed"):
        service.create_task(failed_repo, "first")

    with repository._connection_lock:
        task_count = repository._connection.execute(
            "SELECT COUNT(*) FROM tasks"
        ).fetchone()[0]
    assert task_count == 0
    assert service._futures == {}
    assert service._pending_owners == {}
    assert service._active_repositories == {}
    replacement = service.create_task(replacement_repo, "capacity is reusable")
    assert service.start_task(replacement.id).result(timeout=2).status is TaskStatus.SUCCEEDED
    service.close()


def test_submission_queue_is_bounded_by_global_concurrency(
    repository: SQLiteTaskRepository, tmp_path: Path
) -> None:
    entered = Event()
    release = Event()

    class BlockingLoop(StubLoop):
        def run(self, task_id: str) -> TaskResult:
            entered.set()
            assert release.wait(2)
            return super().run(task_id)

    first_repo = tmp_path / "first"
    second_repo = tmp_path / "second"
    first_repo.mkdir()
    second_repo.mkdir()
    service = HarnessService(
        repository=repository,
        loop=BlockingLoop(repository),
        settings=Settings(global_concurrency=1),
        verifier_finder=lambda name: name,
    )
    first = service.create_task(first_repo, "first")
    assert entered.wait(1)

    with pytest.raises(PreflightError, match="capacity"):
        service.create_task(second_repo, "second")

    release.set()
    assert service.start_task(first.id).result(timeout=2).status is TaskStatus.SUCCEEDED
    replacement = service.create_task(second_repo, "replacement")
    assert service.start_task(replacement.id).result(timeout=2).status is TaskStatus.SUCCEEDED


def test_lease_is_cross_repository_instance_safe_before_executor_submit(
    tmp_path: Path,
) -> None:
    entered = Event()
    release = Event()

    class BlockingLoop(StubLoop):
        def run(self, task_id: str) -> TaskResult:
            entered.set()
            assert release.wait(2)
            return super().run(task_id)

    db_path = tmp_path / "state.sqlite"
    first_repository = SQLiteTaskRepository(db_path)
    second_repository = SQLiteTaskRepository(db_path)
    repo = tmp_path / "repo"
    repo.mkdir()
    first = HarnessService(
        repository=first_repository,
        loop=BlockingLoop(first_repository),
        settings=Settings(),
        verifier_finder=lambda name: name,
    )
    second = HarnessService(
        repository=second_repository,
        loop=StubLoop(second_repository),
        settings=Settings(),
        verifier_finder=lambda name: name,
    )
    running_task = first.create_task(repo, "first")
    assert entered.wait(1)

    with pytest.raises(ProjectBusyError, match="busy"):
        second.create_task(repo, "second")

    release.set()
    assert first.start_task(running_task.id).result(timeout=2).status is TaskStatus.SUCCEEDED


def test_create_atomically_submits_and_duplicate_start_returns_same_future(
    repository: SQLiteTaskRepository, repo: Path
) -> None:
    entered = Event()
    release = Event()

    class BlockingLoop(StubLoop):
        def run(self, task_id: str) -> TaskResult:
            entered.set()
            assert release.wait(2)
            return super().run(task_id)

    service = HarnessService(
        repository=repository,
        loop=BlockingLoop(repository),
        settings=Settings(global_concurrency=1),
        verifier_finder=lambda name: name,
    )
    task = service.create_task(repo, "atomic")
    assert entered.wait(1)

    with ThreadPoolExecutor(max_workers=2) as callers:
        returned = list(callers.map(lambda _: service.start_task(task.id), range(2)))
    first, second = returned

    assert first is second
    release.set()
    assert first.result(timeout=2).status is TaskStatus.SUCCEEDED


def test_capacity_rejection_persists_no_task(
    repository: SQLiteTaskRepository, tmp_path: Path
) -> None:
    entered = Event()
    release = Event()

    class BlockingLoop(StubLoop):
        def run(self, task_id: str) -> TaskResult:
            entered.set()
            assert release.wait(2)
            return super().run(task_id)

    first_repo = tmp_path / "first-atomic"
    second_repo = tmp_path / "second-atomic"
    first_repo.mkdir()
    second_repo.mkdir()
    service = HarnessService(
        repository=repository,
        loop=BlockingLoop(repository),
        settings=Settings(global_concurrency=1),
        verifier_finder=lambda name: name,
    )
    first = service.create_task(first_repo, "first")
    assert entered.wait(1)
    before = repository._connection.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]

    with pytest.raises(PreflightError, match="capacity"):
        service.create_task(second_repo, "second")

    after = repository._connection.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]
    assert before == after == 1
    release.set()
    assert service.start_task(first.id).result(timeout=2).status is TaskStatus.SUCCEEDED


def test_accepted_task_is_never_left_created(
    repository: SQLiteTaskRepository, repo: Path
) -> None:
    service = make_service(repository)

    task = service.create_task(repo, "submitted")

    assert repository.resume_snapshot(task.id).task.status is not TaskStatus.CREATED
    assert service.start_task(task.id).result(timeout=2).status is TaskStatus.SUCCEEDED


def test_get_task_is_a_typed_safe_view(repository: SQLiteTaskRepository, repo: Path) -> None:
    service = make_service(repository)
    task = service.create_task(repo, "fix escaped <source>")

    view = service.get_task(task.id)

    assert view.id == task.id
    assert view.status is TaskStatus.SUCCEEDED
    assert "fix escaped" not in view.model_dump_json()
    assert view.remaining_rounds == Settings().round_limit
    assert "result_json" not in view.model_dump()


def test_cancel_rejects_an_already_submitted_task(
    repository: SQLiteTaskRepository, repo: Path
) -> None:
    entered = Event()
    release = Event()

    class BlockingLoop(StubLoop):
        def run(self, task_id: str) -> TaskResult:
            entered.set()
            assert release.wait(2)
            return super().run(task_id)

    service = HarnessService(
        repository=repository,
        loop=BlockingLoop(repository),
        settings=Settings(),
        verifier_finder=lambda name: name,
    )
    submitted = service.create_task(repo, "submitted")
    assert entered.wait(1)

    with pytest.raises(PreflightError, match="running"):
        service.cancel_task(submitted.id)

    release.set()


def test_cancel_sqlite_error_becomes_sanitized_preflight_error(
    repository: SQLiteTaskRepository,
    tmp_path: Path,
) -> None:
    project = tmp_path / "cancel-sqlite-error"
    project.mkdir()
    task = repository.create_task_with_project_reservation(
        str(project.resolve()), "keep after abort", round_limit=8
    )
    service = make_service(repository)
    sensitive = "cancel-service-sensitive-token"
    with repository._connection_lock:
        repository._connection.execute(
            """CREATE TRIGGER abort_service_cancel_with_sensitive_message
                BEFORE DELETE ON tasks
                BEGIN SELECT RAISE(ABORT, 'cancel-service-sensitive-token'); END"""
        )

    with pytest.raises(PreflightError) as captured:
        service.cancel_task(task.id)

    assert type(captured.value) is PreflightError
    assert str(captured.value) == "task cancellation is unavailable"
    assert sensitive not in str(captured.value)
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert repository.task_exists(task.id) is True
    with repository._connection_lock:
        reservation = repository._connection.execute(
            "SELECT task_id FROM project_reservations WHERE task_id = ?",
            (task.id,),
        ).fetchone()
    assert reservation["task_id"] == task.id
    service.close()


def test_cancel_race_loses_then_reconciles_stale_registry_after_winner_finishes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = tmp_path / "state.sqlite"
    project = tmp_path / "cancel-race"
    project.mkdir()
    cancellation_repository = SQLiteTaskRepository(db_path)
    runner_repository = SQLiteTaskRepository(db_path)
    task = cancellation_repository.create_task_with_project_reservation(
        str(project.resolve()), "run me", round_limit=8
    )
    cancellation_started = Event()
    allow_cancellation = Event()
    worker_entered = Event()
    release_worker = Event()

    class BlockingLoop(StubLoop):
        def run(self, task_id: str) -> TaskResult:
            worker_entered.set()
            assert release_worker.wait(2)
            return super().run(task_id)

    cancellation_service = HarnessService(
        repository=cancellation_repository,
        loop=StubLoop(cancellation_repository),
        settings=Settings(global_concurrency=1),
        verifier_finder=lambda name: name,
    )
    runner_service = HarnessService(
        repository=runner_repository,
        loop=BlockingLoop(runner_repository),
        settings=Settings(global_concurrency=1),
        verifier_finder=lambda name: name,
    )
    canonical = str(project.resolve())
    with cancellation_service._lock:
        cancellation_service._task_repositories[task.id] = canonical
        cancellation_service._active_repositories[canonical] = task.id

    def pause_cancellation() -> None:
        cancellation_started.set()
        assert allow_cancellation.wait(2)

    original_snapshot = cancellation_service._snapshot

    def paused_snapshot(task_id: str):
        snapshot = original_snapshot(task_id)
        if snapshot.task.status is TaskStatus.CREATED:
            pause_cancellation()
        return snapshot

    original_cancel = cancellation_repository.cancel_created_task

    def paused_cancel_created_task(task_id: str) -> bool:
        assert (
            cancellation_repository.resume_snapshot(task_id).task.status
            is TaskStatus.CREATED
        )
        pause_cancellation()
        return original_cancel(task_id)

    monkeypatch.setattr(cancellation_service, "_snapshot", paused_snapshot)
    monkeypatch.setattr(
        cancellation_repository, "cancel_created_task", paused_cancel_created_task
    )

    runner_future: Future[TaskResult] | None = None
    try:
        with ThreadPoolExecutor(max_workers=1) as callers:
            cancelled = callers.submit(cancellation_service.cancel_task, task.id)
            assert cancellation_started.wait(1)
            runner_future = runner_service.start_task(task.id)
            assert worker_entered.wait(1)
            owner_token = runner_service._pending_owners[task.id]
            allow_cancellation.set()

            with pytest.raises(PreflightError) as captured:
                cancelled.result(timeout=2)

            assert captured.value.__cause__ is None
            assert captured.value.__context__ is None
            message = str(captured.value)
            assert task.id not in message
            assert canonical not in message
            assert owner_token not in message
            assert (
                runner_repository.resume_snapshot(task.id).task.status
                is TaskStatus.RUNNING
            )
            assert runner_repository.owns_project_lease(
                task.id, owner_token=owner_token
            ) is True
            assert runner_service._futures[task.id] is runner_future
            assert cancellation_service._task_repositories[task.id] == canonical
            assert cancellation_service._active_repositories[canonical] == task.id
            with runner_repository._connection_lock:
                reservation = runner_repository._connection.execute(
                    """SELECT task_id FROM project_reservations
                       WHERE project_id = ?""",
                    (task.project_id,),
                ).fetchone()
            assert reservation["task_id"] == task.id

            with pytest.raises(ProjectBusyError, match="active work"):
                cancellation_service.create_task(project, "too early")

        release_worker.set()
        assert runner_future.result(timeout=2).status is TaskStatus.SUCCEEDED
        with cancellation_repository._connection_lock:
            reservation = cancellation_repository._connection.execute(
                "SELECT task_id FROM project_reservations WHERE project_id = ?",
                (task.project_id,),
            ).fetchone()
        assert reservation is None

        replacement = cancellation_service.create_task(project, "replacement")
        assert (
            cancellation_service.start_task(replacement.id)
            .result(timeout=2)
            .status
            is TaskStatus.SUCCEEDED
        )
    finally:
        allow_cancellation.set()
        release_worker.set()
        runner_service.close()
        cancellation_service.close()
        runner_repository.close()
        cancellation_repository.close()


def test_stale_cancel_registry_keeps_waiting_winner_busy(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "state.sqlite"
    project = tmp_path / "waiting-winner"
    project.mkdir()
    cancellation_repository = SQLiteTaskRepository(db_path)
    runner_repository = SQLiteTaskRepository(db_path)
    task = cancellation_repository.create_task_with_project_reservation(
        str(project.resolve()), "wait for approval", round_limit=8
    )

    class WaitingLoop(StubLoop):
        def run(self, task_id: str) -> TaskResult:
            return TaskResult(
                task_id=task_id,
                status=TaskStatus.WAITING_APPROVAL,
                iterations=1,
                verification_summary="Waiting for approval.",
            )

    cancellation_service = make_service(cancellation_repository)
    runner_service = HarnessService(
        repository=runner_repository,
        loop=WaitingLoop(runner_repository),
        settings=Settings(global_concurrency=1),
        verifier_finder=lambda name: name,
    )
    canonical = str(project.resolve())
    with cancellation_service._lock:
        cancellation_service._task_repositories[task.id] = canonical
        cancellation_service._active_repositories[canonical] = task.id

    try:
        assert (
            runner_service.start_task(task.id).result(timeout=2).status
            is TaskStatus.WAITING_APPROVAL
        )

        with pytest.raises(PreflightError, match="running"):
            cancellation_service.cancel_task(task.id)
        with pytest.raises(ProjectBusyError, match="active work"):
            cancellation_service.create_task(project, "must stay busy")

        assert (
            cancellation_repository.resume_snapshot(task.id).task.status
            is TaskStatus.WAITING_APPROVAL
        )
        assert cancellation_service._task_repositories[task.id] == canonical
        assert cancellation_service._active_repositories[canonical] == task.id
        with cancellation_repository._connection_lock:
            reservation = cancellation_repository._connection.execute(
                "SELECT task_id FROM project_reservations WHERE project_id = ?",
                (task.project_id,),
            ).fetchone()
        assert reservation["task_id"] == task.id
    finally:
        runner_service.close()
        cancellation_service.close()
        runner_repository.close()
        cancellation_repository.close()


def test_cancellation_winner_leaves_start_without_placeholder_or_capacity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db_path = tmp_path / "state.sqlite"
    project = tmp_path / "cancellation-winner"
    project.mkdir()
    cancellation_repository = SQLiteTaskRepository(db_path)
    runner_repository = SQLiteTaskRepository(db_path)
    task = cancellation_repository.create_task_with_project_reservation(
        str(project.resolve()), "cancel me", round_limit=8
    )
    cancellation_service = make_service(cancellation_repository)
    runner_service = make_service(runner_repository)
    canonical = str(project.resolve())
    with cancellation_service._lock:
        cancellation_service._task_repositories[task.id] = canonical
        cancellation_service._active_repositories[canonical] = task.id
    candidate_observed = Event()
    cancellation_committed = Event()
    original_snapshot = runner_service._snapshot

    def stale_created_snapshot(task_id: str):
        snapshot = original_snapshot(task_id)
        if snapshot.task.status is TaskStatus.CREATED:
            candidate_observed.set()
            assert cancellation_committed.wait(2)
        return snapshot

    monkeypatch.setattr(runner_service, "_snapshot", stale_created_snapshot)

    try:
        with ThreadPoolExecutor(max_workers=1) as callers:
            started = callers.submit(runner_service.start_task, task.id)
            assert candidate_observed.wait(1)
            cancellation_service.cancel_task(task.id)
            assert cancellation_repository.task_exists(task.id) is False
            assert cancellation_service._task_repositories == {}
            assert cancellation_service._active_repositories == {}
            cancellation_committed.set()
            try:
                started.result(timeout=2)
            except Exception as caught:  # noqa: BLE001 - assert exact public type below.
                error = caught
            else:
                raise AssertionError("stale start unexpectedly succeeded")

        assert runner_service._futures == {}
        assert runner_service._pending_owners == {}
        assert runner_service._task_repositories == {}
        assert runner_service._active_repositories == {}
        assert runner_service._capacity.acquire(blocking=False) is True
        runner_service._capacity.release()
        assert type(error) is PreflightError
        assert error.__cause__ is None
        assert error.__context__ is None
        assert task.id not in str(error)
        assert canonical not in str(error)
    finally:
        cancellation_committed.set()
        runner_service.close()
        cancellation_service.close()
        runner_repository.close()
        cancellation_repository.close()


@pytest.mark.parametrize(
    ("primary_stage", "cleanup_stage"),
    [
        pytest.param("snapshot", "local", id="snapshot-local"),
        pytest.param("path", "inspection", id="path-inspection"),
        pytest.param("transition", "rollback", id="transition-rollback"),
        pytest.param("lease", "release", id="lease-release"),
        pytest.param("busy", "inspection", id="busy-inspection"),
        pytest.param("executor", "release", id="executor-release"),
        pytest.param("executor", "rollback", id="executor-rollback"),
        pytest.param("executor", "local", id="executor-local"),
    ],
)
def test_setup_compensation_primary_error_wins_failure_matrix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    primary_stage: str,
    cleanup_stage: str,
) -> None:
    class PrimarySetupFailure(RuntimeError):
        pass

    class CleanupSetupFailure(RuntimeError):
        pass

    db_path = tmp_path / "state.sqlite"
    project = tmp_path / f"matrix-{primary_stage}-{cleanup_stage}"
    project.mkdir()
    canonical = str(project.resolve())
    request_text = "request-sensitive-matrix-value"
    cleanup_details = (
        "cleanup-sensitive-token C:/cleanup/private request-sensitive-cleanup"
    )
    repository = SQLiteTaskRepository(db_path)
    service = make_service(repository)
    created_ids: list[str] = []
    cleanup_armed = Event()
    cleanup_injected = Event()
    original_create = repository.create_task_with_project_reservation

    def tracked_create(*args, **kwargs):
        record = original_create(*args, **kwargs)
        created_ids.append(record.id)
        return record

    monkeypatch.setattr(
        repository, "create_task_with_project_reservation", tracked_create
    )

    if cleanup_stage == "release":
        def fail_release(task_id: str, *, owner_token: str) -> None:
            del task_id, owner_token
            assert cleanup_armed.is_set()
            cleanup_injected.set()
            raise CleanupSetupFailure(cleanup_details)

        monkeypatch.setattr(repository, "release_project_lease", fail_release)
    elif cleanup_stage == "rollback":
        def fail_rollback(task_id: str, *, owner_token: str) -> bool:
            del task_id, owner_token
            assert cleanup_armed.is_set()
            cleanup_injected.set()
            raise CleanupSetupFailure(cleanup_details)

        monkeypatch.setattr(repository, "rollback_running_task", fail_rollback)
    elif cleanup_stage == "inspection":
        original_exists = repository.task_exists
        original_resume = repository.resume_snapshot
        inspection_failed = False

        def fail_inspection_once() -> None:
            nonlocal inspection_failed
            if cleanup_armed.is_set() and not inspection_failed:
                inspection_failed = True
                cleanup_injected.set()
                raise CleanupSetupFailure(cleanup_details)

        def inspected_exists(task_id: str) -> bool:
            fail_inspection_once()
            return original_exists(task_id)

        def inspected_resume(task_id: str, *, owner_token: str | None = None):
            fail_inspection_once()
            return original_resume(task_id, owner_token=owner_token)

        monkeypatch.setattr(repository, "task_exists", inspected_exists)
        monkeypatch.setattr(repository, "resume_snapshot", inspected_resume)
    else:
        class FailOnceActiveMap(dict[str, str]):
            failed = False

            def get(self, key: str, default: str | None = None):
                if cleanup_armed.is_set() and not self.failed:
                    self.failed = True
                    cleanup_injected.set()
                    raise CleanupSetupFailure(cleanup_details)
                return super().get(key, default)

        service._active_repositories = FailOnceActiveMap()

    if primary_stage == "snapshot":
        def fail_snapshot(task_id: str):
            del task_id
            cleanup_armed.set()
            raise PrimarySetupFailure("primary snapshot failure")

        monkeypatch.setattr(service, "_snapshot", fail_snapshot)
    elif primary_stage == "path":
        task = repository.create_task_with_project_reservation(
            canonical, request_text, round_limit=8
        )

        def fail_path(task_id: str) -> str:
            del task_id
            cleanup_armed.set()
            raise PrimarySetupFailure("primary path failure")

        monkeypatch.setattr(repository, "task_project_path", fail_path)
    elif primary_stage == "transition":
        def fail_transition(*args, **kwargs) -> bool:
            del args, kwargs
            cleanup_armed.set()
            raise PrimarySetupFailure("primary transition failure")

        monkeypatch.setattr(repository, "set_status", fail_transition)
    elif primary_stage in {"lease", "busy"}:
        def fail_or_refuse_lease(*args, **kwargs) -> bool:
            del args, kwargs
            cleanup_armed.set()
            if primary_stage == "busy":
                return False
            raise PrimarySetupFailure("primary lease failure")

        monkeypatch.setattr(
            repository, "acquire_project_lease", fail_or_refuse_lease
        )
    else:
        class FailingExecutor:
            def __init__(self, delegate: ThreadPoolExecutor) -> None:
                self._delegate = delegate

            def submit(self, *args, **kwargs):
                del args, kwargs
                cleanup_armed.set()
                raise PrimarySetupFailure("primary executor failure")

            def shutdown(self, *, wait: bool, cancel_futures: bool) -> None:
                self._delegate.shutdown(
                    wait=wait, cancel_futures=cancel_futures
                )

        service._executor = FailingExecutor(service._executor)

    observer: SQLiteTaskRepository | None = None
    try:
        try:
            if primary_stage == "path":
                service.start_task(task.id)
            else:
                service.create_task(project, request_text)
        except Exception as caught:  # noqa: BLE001 - assert exact primary below.
            error = caught
        else:
            raise AssertionError("injected setup failure unexpectedly succeeded")

        expected_type = (
            ProjectBusyError if primary_stage == "busy" else PrimarySetupFailure
        )
        assert type(error) is expected_type
        assert cleanup_injected.is_set()
        assert service._futures == {}
        assert service._capacity.acquire(blocking=False) is True
        service._capacity.release()

        chain: list[BaseException] = []
        pending: list[BaseException] = [error]
        while pending:
            current = pending.pop()
            if current in chain:
                continue
            chain.append(current)
            if current.__cause__ is not None:
                pending.append(current.__cause__)
            if current.__context__ is not None:
                pending.append(current.__context__)
        exposed = " ".join(str(item) for item in chain)
        assert cleanup_details not in exposed
        assert "cleanup-sensitive-token" not in exposed
        assert "C:/cleanup/private" not in exposed
        assert request_text not in exposed
        assert canonical not in exposed

        task_id = created_ids[-1]
        observer = SQLiteTaskRepository(db_path)
        if observer.task_exists(task_id):
            snapshot = observer.resume_snapshot(task_id)
            assert snapshot.task.status in {
                TaskStatus.CREATED,
                TaskStatus.RUNNING,
            }
            assert service._futures == {}
            if snapshot.task.status is TaskStatus.RUNNING:
                assert service.get_task(task_id).resume_available is True
            with observer._connection_lock:
                reservation = observer._connection.execute(
                    "SELECT task_id FROM project_reservations WHERE task_id = ?",
                    (task_id,),
                ).fetchone()
            assert reservation["task_id"] == task_id
        else:
            assert service._pending_owners == {}
            assert service._task_repositories == {}
            assert service._active_repositories == {}
    finally:
        service.close()
        if observer is not None:
            observer.close()
        repository.close()


def test_setup_compensation_rollback_failure_keeps_running_web_recovery(
    repository: SQLiteTaskRepository,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "rollback-recovery"
    project.mkdir()
    service = make_service(repository)
    service._executor = FailOnceExecutor(service._executor)
    original_create = repository.create_task_with_project_reservation
    original_rollback = repository.rollback_running_task
    created_ids: list[str] = []

    def tracked_create(*args, **kwargs):
        record = original_create(*args, **kwargs)
        created_ids.append(record.id)
        return record

    def fail_rollback(task_id: str, *, owner_token: str) -> bool:
        del task_id, owner_token
        raise RuntimeError("cleanup-sensitive-token")

    monkeypatch.setattr(
        repository, "create_task_with_project_reservation", tracked_create
    )
    monkeypatch.setattr(repository, "rollback_running_task", fail_rollback)

    with pytest.raises(RuntimeError, match="submit failed") as captured:
        service.create_task(project, "recover me")

    task_id = created_ids[-1]
    assert "cleanup-sensitive-token" not in str(captured.value)
    assert service._futures == {}
    assert service._capacity.acquire(blocking=False) is True
    service._capacity.release()
    assert repository.resume_snapshot(task_id).task.status is TaskStatus.RUNNING
    view = service.get_task(task_id)
    assert view.resume_available is True

    monkeypatch.setattr(repository, "rollback_running_task", original_rollback)
    assert service.resume_task(task_id).result(timeout=2).status is TaskStatus.SUCCEEDED
    service.close()


def test_export_audit_returns_only_redacted_structured_events(
    repository: SQLiteTaskRepository, tmp_path: Path
) -> None:
    audit = tmp_path / "audit.jsonl"
    audit.write_text(
        json.dumps(
            {
                "task_id": "task-1",
                "iteration": None,
                "component": "loop",
                "event_type": "transition",
                "duration": None,
                "outcome": "ok",
                "metadata": {"intent_id": "safe"},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    service = make_service(repository, audit_path=audit)

    events = service.export_audit()

    assert events == (
        AuditEvent(
            task_id="task-1",
            component="loop",
            event_type="transition",
            metadata={"intent_id": "safe", "outcome": "ok"},
        ),
    )
    assert "prompt" not in events[0].model_dump_json()


def test_export_audit_recursively_redacts_nested_auth_urls_and_known_secrets(
    repository: SQLiteTaskRepository, tmp_path: Path
) -> None:
    audit = tmp_path / "audit.jsonl"
    audit.write_text(
        json.dumps(
            {
                "task_id": "task-1",
                "iteration": None,
                "component": "loop",
                "event_type": "transition",
                "duration": None,
                "outcome": "https://example.invalid/x?api_key=token-value&safe=yes",
                "metadata": {
                    "nested": {"authorization": "Bearer token-value"},
                    "url": "https://example.invalid/x?api_key=token-value&safe=yes",
                    "intent_id": "known-secret",
                    "status": "Bearer token-value",
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    service = make_service(
        repository,
        audit_path=audit,
        audit_secrets={"known-secret", "token-value"},
    )

    encoded = "\n".join(event.model_dump_json() for event in service.export_audit())

    assert "known-secret" not in encoded
    assert "token-value" not in encoded
    assert "Bearer [REDACTED]" in encoded
    assert "api_key=%5BREDACTED%5D" in encoded
    assert "nested" not in encoded
    assert '"url"' not in encoded
