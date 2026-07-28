from __future__ import annotations

import sqlite3
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
from pyquality.storage.sqlite import (
    LeaseRecoveryBlocked,
    SQLiteTaskRepository,
    StorageStateError,
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
