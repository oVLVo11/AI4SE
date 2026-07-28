from __future__ import annotations

from pathlib import Path

import pytest

from pyquality.domain.models import ApprovalDecision, Finding, PolicyOutcome, TaskResult, TaskStatus
from pyquality.storage.sqlite import SQLiteTaskRepository, StorageStateError


@pytest.fixture
def repo(tmp_path: Path) -> SQLiteTaskRepository:
    return SQLiteTaskRepository(tmp_path / "state.sqlite")


def _start(repo: SQLiteTaskRepository, task_id: str) -> None:
    assert repo.set_status(task_id, TaskStatus.CREATED, TaskStatus.RUNNING) is True


def test_second_active_task_cannot_lease_same_project(repo: SQLiteTaskRepository) -> None:
    """Dropping the unique active-path constraint would allow conflicting repository mutations."""
    first = repo.create_task("C:/work/demo", "fix sum", round_limit=8)
    second = repo.create_task("C:/work/demo", "fix subtract", round_limit=8)
    _start(repo, first.id)
    _start(repo, second.id)

    assert repo.acquire_project_lease(first.id) is True
    assert repo.acquire_project_lease(second.id) is False


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
    assert repo.acquire_project_lease(task.id) is True
    iteration = repo.append_iteration(task.id, sequence=1, context_digest="a" * 64)
    approval = repo.record_approval(
        task.id,
        iteration.id,
        action_json='{"kind":"apply_patch"}',
        action_digest="b" * 64,
        repository_snapshot_digest="c" * 64,
    )

    decided = repo.decide_approval(approval.id, ApprovalDecision.APPROVE)
    intended = repo.mark_execution_intent(decided.id)

    assert repo.resume_snapshot(task.id).executable_approval == intended
    assert repo.mark_execution_completed(intended.id).execution_state == "completed"
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
    assert repo.acquire_project_lease(task.id) is True
    assert repo.set_status(task.id, TaskStatus.CREATED, TaskStatus.SUCCEEDED) is False
    result = TaskResult(
        task_id=task.id,
        status=TaskStatus.SUCCEEDED,
        iterations=0,
        verification_summary="All checks passed.",
    )
    assert repo.set_status(task.id, TaskStatus.RUNNING, TaskStatus.SUCCEEDED, result) is True

    next_task = repo.create_task("C:/work/demo", "fix subtract", round_limit=8)
    _start(repo, next_task.id)
    assert repo.acquire_project_lease(next_task.id) is True
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
        assert repo.set_status(task.id, TaskStatus.RUNNING, TaskStatus.WAITING_APPROVAL) is True
    elif status is TaskStatus.SUCCEEDED:
        _start(repo, task.id)
        assert repo.set_status(task.id, TaskStatus.RUNNING, TaskStatus.SUCCEEDED) is True

    with pytest.raises(StorageStateError):
        repo.acquire_project_lease(task.id)


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
    assert repo.acquire_project_lease(owner.id) is True
    iteration = repo.append_iteration(target.id, sequence=1, context_digest="a" * 64)
    approval = repo.record_approval(
        target.id, iteration.id, '{"kind":"apply_patch"}', "b" * 64, "c" * 64
    )
    repo.decide_approval(approval.id, ApprovalDecision.APPROVE)

    with pytest.raises(StorageStateError):
        repo.mark_execution_intent(approval.id)


def test_terminal_snapshot_hides_an_approved_incomplete_action(repo: SQLiteTaskRepository) -> None:
    """A terminal task must never expose an unfinished approval for later dispatch."""
    task = repo.create_task("C:/work/demo", "fix sum", round_limit=8)
    _start(repo, task.id)
    assert repo.acquire_project_lease(task.id) is True
    iteration = repo.append_iteration(task.id, sequence=1, context_digest="a" * 64)
    approval = repo.record_approval(
        task.id, iteration.id, '{"kind":"apply_patch"}', "b" * 64, "c" * 64
    )
    repo.decide_approval(approval.id, ApprovalDecision.APPROVE)
    assert repo.set_status(task.id, TaskStatus.RUNNING, TaskStatus.SUCCEEDED) is True

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

    assert first_repo.acquire_project_lease(first.id) is True
    assert second_repo.acquire_project_lease(second.id) is False
