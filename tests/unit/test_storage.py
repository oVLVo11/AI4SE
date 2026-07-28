from __future__ import annotations

from pathlib import Path

import pytest

from pyquality.domain.models import ApprovalDecision, Finding, PolicyOutcome, TaskResult, TaskStatus
from pyquality.storage.sqlite import SQLiteTaskRepository, StorageStateError


@pytest.fixture
def repo(tmp_path: Path) -> SQLiteTaskRepository:
    return SQLiteTaskRepository(tmp_path / "state.sqlite")


def test_second_active_task_cannot_lease_same_project(repo: SQLiteTaskRepository) -> None:
    """Dropping the unique active-path constraint would allow conflicting repository mutations."""
    first = repo.create_task("C:/work/demo", "fix sum", round_limit=8)
    second = repo.create_task("C:/work/demo", "fix subtract", round_limit=8)

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
    assert repo.acquire_project_lease(task.id) is True

    assert repo.set_status(task.id, TaskStatus.CREATED, TaskStatus.RUNNING) is True
    assert repo.set_status(task.id, TaskStatus.CREATED, TaskStatus.SUCCEEDED) is False
    result = TaskResult(
        task_id=task.id,
        status=TaskStatus.SUCCEEDED,
        iterations=0,
        verification_summary="All checks passed.",
    )
    assert repo.set_status(task.id, TaskStatus.RUNNING, TaskStatus.SUCCEEDED, result) is True

    next_task = repo.create_task("C:/work/demo", "fix subtract", round_limit=8)
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
