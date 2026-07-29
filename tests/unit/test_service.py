from __future__ import annotations

import json
from concurrent.futures import Future
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
    service = make_service(repository)
    service.create_task(repo, "first")

    with pytest.raises(ProjectBusyError, match="already has active work"):
        service.create_task(repo, "second")


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
    second = service.create_task(second_repo, "second")
    running = service.start_task(first.id)
    assert entered.wait(1)

    with pytest.raises(PreflightError, match="capacity"):
        service.start_task(second.id)

    release.set()
    assert running.result(timeout=2).status is TaskStatus.SUCCEEDED
    assert repository.resume_snapshot(second.id).task.status is TaskStatus.FAILED
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
    contender = second.create_task(repo, "second")
    running = first.start_task(running_task.id)
    assert entered.wait(1)

    with pytest.raises(ProjectBusyError, match="busy"):
        second.start_task(contender.id)

    assert second_repository.resume_snapshot(contender.id).task.status is TaskStatus.FAILED
    release.set()
    assert running.result(timeout=2).status is TaskStatus.SUCCEEDED


def test_get_task_is_a_typed_safe_view(repository: SQLiteTaskRepository, repo: Path) -> None:
    service = make_service(repository)
    task = service.create_task(repo, "fix escaped <source>")

    view = service.get_task(task.id)

    assert view.id == task.id
    assert view.status is TaskStatus.CREATED
    assert "fix escaped" not in view.model_dump_json()
    assert view.remaining_rounds == Settings().round_limit
    assert "result_json" not in view.model_dump()


def test_cancel_releases_never_started_repository_reservation(
    repository: SQLiteTaskRepository, repo: Path
) -> None:
    service = make_service(repository)
    abandoned = service.create_task(repo, "abandoned")

    service.cancel_task(abandoned.id)

    replacement = service.create_task(repo, "replacement")
    assert replacement.status is TaskStatus.CREATED


@pytest.mark.parametrize("decision", [ApprovalDecision.APPROVE, ApprovalDecision.REJECT])
def test_approval_decision_bounded_resumes_to_terminal(
    repository: SQLiteTaskRepository, repo: Path, decision: ApprovalDecision
) -> None:
    class ApprovalLoop(StubLoop):
        task_id: str

        def decide_approval(self, approval_id: str, selected: ApprovalDecision) -> str:
            self.decisions.append((approval_id, selected))
            assert repository.set_status(
                self.task_id, TaskStatus.WAITING_APPROVAL, TaskStatus.RUNNING
            )
            return self.task_id

        def run_leased(self, task_id: str, owner_token: str, *, resume: bool) -> TaskResult:
            self.leased_runs.append((task_id, owner_token, resume))
            result = TaskResult(
                task_id=task_id,
                status=TaskStatus.SUCCEEDED,
                iterations=1,
                verification_summary="continued",
            )
            assert repository.set_status(
                task_id,
                TaskStatus.RUNNING,
                TaskStatus.SUCCEEDED,
                result,
                owner_token=owner_token,
            )
            return result

    loop = ApprovalLoop(repository)
    service = HarnessService(
        repository=repository,
        loop=loop,
        settings=Settings(),
        verifier_finder=lambda name: name,
    )
    task = service.create_task(repo, "fix")
    loop.task_id = task.id
    assert repository.set_status(task.id, TaskStatus.CREATED, TaskStatus.RUNNING)
    assert repository.acquire_project_lease(task.id, owner_token="setup-owner")
    waiting = TaskResult(
        task_id=task.id,
        status=TaskStatus.WAITING_APPROVAL,
        iterations=1,
        verification_summary="waiting",
    )
    assert repository.set_status(
        task.id,
        TaskStatus.RUNNING,
        TaskStatus.WAITING_APPROVAL,
        waiting,
        owner_token="setup-owner",
    )

    future = service.approve("approval-1") if decision is ApprovalDecision.APPROVE else service.reject("approval-1")

    assert future.result(timeout=2).status is TaskStatus.SUCCEEDED
    assert loop.decisions == [("approval-1", decision)]
    assert loop.leased_runs[0][2] is True


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
