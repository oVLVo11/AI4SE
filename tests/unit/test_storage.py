from __future__ import annotations

from pathlib import Path

import pytest

from pyquality.domain.models import (
    ApprovalDecision,
    Finding,
    PolicyDecision,
    PolicyOutcome,
    TaskResult,
    TaskStatus,
)
from pyquality.storage.sqlite import SQLiteTaskRepository, StorageStateError


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
    assert repo.set_status(task.id, TaskStatus.RUNNING, TaskStatus.WAITING_APPROVAL) is True
    repo.decide_approval(approval.id, ApprovalDecision.REJECT)

    recovered = SQLiteTaskRepository(db_path).resume_snapshot(task.id).decided_approval

    assert recovered is not None
    assert recovered.id == approval.id
    assert recovered.decision is ApprovalDecision.REJECT
    assert recovered.policy_decision == _approval_decision()

    assert repo.set_status(task.id, TaskStatus.WAITING_APPROVAL, TaskStatus.RUNNING) is True
    assert repo.acquire_project_lease(task.id) is True
    consumed = repo.mark_rejection_consumed(approval.id)
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
    assert repo.acquire_project_lease(task.id) is True
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
    )

    recovered = SQLiteTaskRepository(db_path).resume_snapshot(task.id).executable_approval

    assert recovered is not None
    assert recovered.execution_state == "intent_recorded"
    assert recovered.expected_after_digests == {
        "pyproject.toml": "d" * 64,
        "requirements.txt": None,
    }
    completed = repo.mark_execution_completed(approval.id, result_digest="e" * 64)
    assert completed.result_digest == "e" * 64


def test_transition_intent_evidence_survives_reopen_and_completion(tmp_path: Path) -> None:
    """Without durable pre/post evidence, resume could repeat an external transition."""
    db_path = tmp_path / "state.sqlite"
    repo = SQLiteTaskRepository(db_path)
    task = repo.create_task("C:/work/demo", "fix sum", round_limit=8)
    _start(repo, task.id)
    assert repo.acquire_project_lease(task.id) is True
    intent = repo.record_transition_intent(
        task.id,
        kind="model_call",
        evidence_digest="a" * 64,
        summary="context prepared",
    )

    reopened = SQLiteTaskRepository(db_path)
    pending = reopened.resume_snapshot(task.id).transition_intents
    assert len(pending) == 1
    assert pending[0].id == intent.id
    assert pending[0].state == "pending"
    completed = reopened.complete_transition_intent(
        intent.id,
        result_digest="b" * 64,
        summary="response persisted",
    )
    assert completed.state == "completed"
    assert completed.result_digest == "b" * 64
    assert completed.completion_summary == "response persisted"
