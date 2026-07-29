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

    def decide_approval(self, approval_id: str, decision: ApprovalDecision) -> None:
        self.decisions.append((approval_id, decision))


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
    assert service.start_task(second.id).result(timeout=2).status is TaskStatus.SUCCEEDED


def test_get_task_is_a_typed_safe_view(repository: SQLiteTaskRepository, repo: Path) -> None:
    service = make_service(repository)
    task = service.create_task(repo, "fix escaped <source>")

    view = service.get_task(task.id)

    assert view.id == task.id
    assert view.status is TaskStatus.CREATED
    assert view.request == "fix escaped <source>"
    assert view.remaining_rounds == Settings().round_limit
    assert "result_json" not in view.model_dump()


def test_approval_methods_delegate_typed_decisions(repository: SQLiteTaskRepository) -> None:
    loop = StubLoop(repository)
    service = HarnessService(
        repository=repository,
        loop=loop,
        settings=Settings(),
        verifier_finder=lambda name: name,
    )
    service.approve("approval-1")
    service.reject("approval-2")
    assert loop.decisions == [
        ("approval-1", ApprovalDecision.APPROVE),
        ("approval-2", ApprovalDecision.REJECT),
    ]


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
