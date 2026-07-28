from __future__ import annotations

from datetime import timedelta

import pytest
from conftest import (
    NOW,
    FixedClock,
    ScriptedPipeline,
    dependency_patch_json,
    failed_report,
    finish_json,
    successful_report,
)

from pyquality.domain.models import (
    ApprovalDecision,
    PolicyDecision,
    PolicyOutcome,
    TaskStatus,
    ToolResult,
)
from pyquality.llm import Message, ScriptedLLM
from pyquality.loop import ApprovalStateError
from pyquality.policy import PolicyEngine


def test_approval_pauses_and_executes_once(loop_fixture) -> None:
    action = dependency_patch_json()
    harness = loop_fixture(
        responses=[action, finish_json()],
        reports=[successful_report(), successful_report()],
    )

    assert harness.loop.run(harness.task_id).status is TaskStatus.WAITING_APPROVAL
    calls = len(harness.llm.calls)
    assert harness.loop.resume(harness.task_id).status is TaskStatus.WAITING_APPROVAL
    assert len(harness.llm.calls) == calls
    approval = harness.loop.pending_approval(harness.task_id)
    harness.loop.decide_approval(approval.id, ApprovalDecision.APPROVE)
    first = harness.loop.resume(harness.task_id)
    second = harness.loop.resume(harness.task_id)

    assert first.status is TaskStatus.SUCCEEDED
    assert second == first
    assert harness.dispatcher.dispatch_count(action) == 1
    assert harness.dispatcher.approved_flags == [True]

    try:
        harness.loop.decide_approval(approval.id, ApprovalDecision.REJECT)
    except ApprovalStateError:
        pass
    else:
        raise AssertionError("terminal approval decision did not fail")


def test_rejected_action_becomes_feedback_once_after_reopen(loop_fixture) -> None:
    harness = loop_fixture(
        responses=[dependency_patch_json(), finish_json()],
        reports=[successful_report()],
    )
    harness.loop.run(harness.task_id)
    approval = harness.loop.pending_approval(harness.task_id)
    harness.loop.decide_approval(approval.id, ApprovalDecision.REJECT)

    result = harness.loop.resume(harness.task_id)

    assert result.status is TaskStatus.SUCCEEDED
    assert "rejected by user" in harness.llm.calls[-1][-1].content
    assert harness.dispatcher.actions == []
    assert harness.repository.resume_snapshot(harness.task_id).decided_approval.execution_state == "completed"


def test_duplicate_approval_decision_raises_approval_state_error(loop_fixture) -> None:
    harness = loop_fixture(responses=[dependency_patch_json()])
    harness.loop.run(harness.task_id)
    approval = harness.loop.pending_approval(harness.task_id)
    harness.loop.decide_approval(approval.id, ApprovalDecision.REJECT)

    try:
        harness.loop.decide_approval(approval.id, ApprovalDecision.APPROVE)
    except ApprovalStateError:
        pass
    else:
        raise AssertionError("duplicate approval decision did not fail")


def test_repository_drift_blocks_approved_action_before_dispatch(loop_fixture) -> None:
    harness = loop_fixture(responses=[dependency_patch_json()])
    harness.loop.run(harness.task_id)
    approval = harness.loop.pending_approval(harness.task_id)
    harness.loop.decide_approval(approval.id, ApprovalDecision.APPROVE)
    (harness.repo_root / "unrelated.txt").write_text("drift\n", encoding="utf-8")

    result = harness.loop.resume(harness.task_id)

    assert result.status is TaskStatus.BLOCKED
    assert harness.dispatcher.actions == []


def test_recovery_marks_already_applied_intent_complete_without_replay(loop_fixture) -> None:
    action = dependency_patch_json()
    harness = loop_fixture(
        responses=[action], reports=[successful_report()], round_limit=1
    )
    harness.loop.run(harness.task_id)
    approval = harness.loop.pending_approval(harness.task_id)
    harness.loop.decide_approval(approval.id, ApprovalDecision.APPROVE)
    assert harness.repository.acquire_project_lease(
        harness.task_id, owner_token="seed-owner"
    ) is True
    harness.repository.mark_execution_intent(
        approval.id,
        expected_after_digests=harness.dispatcher.expected,
        owner_token="seed-owner",
    )
    harness.repository.release_project_lease(
        harness.task_id, owner_token="seed-owner"
    )
    harness.dispatcher.effect_already_matches = True

    result = harness.loop.resume(harness.task_id)

    assert result.status is TaskStatus.SUCCEEDED
    assert harness.dispatcher.actions == []
    assert len(harness.pipeline.calls) == 1
    recovered = harness.repository.resume_snapshot(harness.task_id).decided_approval
    assert recovered.execution_state == "completed"


def test_applied_intent_evidence_wins_over_the_expected_repository_snapshot_change(
    loop_fixture,
) -> None:
    policies = []

    class EffectAwarePolicy(PolicyEngine):
        drifted = False

        def evaluate(self, action):
            decision = super().evaluate(action)
            if self.drifted:
                return decision.model_copy(
                    update={"repository_snapshot_digest": "e" * 64}
                )
            return decision

    def policy_factory(path):
        policy = EffectAwarePolicy(path)
        policies.append(policy)
        return policy

    action = dependency_patch_json()
    harness = loop_fixture(
        responses=[action],
        reports=[successful_report()],
        round_limit=1,
        policy_factory=policy_factory,
    )
    harness.loop.run(harness.task_id)
    approval = harness.loop.pending_approval(harness.task_id)
    harness.loop.decide_approval(approval.id, ApprovalDecision.APPROVE)
    assert harness.repository.acquire_project_lease(
        harness.task_id, owner_token="seed-owner"
    ) is True
    harness.repository.mark_execution_intent(
        approval.id,
        expected_after_digests=harness.dispatcher.expected,
        owner_token="seed-owner",
    )
    harness.repository.release_project_lease(
        harness.task_id, owner_token="seed-owner"
    )
    harness.dispatcher.effect_already_matches = True
    policies[0].drifted = True

    result = harness.loop.resume(harness.task_id)

    assert result.status is TaskStatus.SUCCEEDED
    assert harness.dispatcher.actions == []


def test_recovery_replays_intent_only_when_original_snapshot_is_still_current(
    loop_fixture,
) -> None:
    action = dependency_patch_json()
    harness = loop_fixture(
        responses=[action], reports=[successful_report()], round_limit=1
    )
    harness.loop.run(harness.task_id)
    approval = harness.loop.pending_approval(harness.task_id)
    harness.loop.decide_approval(approval.id, ApprovalDecision.APPROVE)
    assert harness.repository.acquire_project_lease(
        harness.task_id, owner_token="seed-owner"
    ) is True
    harness.repository.mark_execution_intent(
        approval.id,
        expected_after_digests=harness.dispatcher.expected,
        owner_token="seed-owner",
    )
    harness.repository.release_project_lease(
        harness.task_id, owner_token="seed-owner"
    )

    result = harness.loop.resume(harness.task_id)

    assert result.status is TaskStatus.SUCCEEDED
    assert harness.dispatcher.dispatch_count(action) == 1


def test_out_of_state_decision_does_not_consume_pending_approval(loop_fixture) -> None:
    harness = loop_fixture(responses=[dependency_patch_json()])
    harness.loop.run(harness.task_id)
    approval = harness.loop.pending_approval(harness.task_id)
    assert harness.repository.set_status(
        harness.task_id, TaskStatus.WAITING_APPROVAL, TaskStatus.RUNNING
    ) is True

    try:
        harness.loop.decide_approval(approval.id, ApprovalDecision.APPROVE)
    except ApprovalStateError:
        pass
    else:
        raise AssertionError("out-of-state decision did not fail")

    snapshot = harness.repository.resume_snapshot(harness.task_id)
    assert snapshot.pending_approval == approval
    assert harness.repository.pending_approval(harness.task_id) is None


def test_revalidation_policy_change_requires_a_new_bound_approval(loop_fixture) -> None:
    class ChangedPolicy(PolicyEngine):
        def revalidate(self, decision, action, current_snapshot_digest):
            refreshed = super().revalidate(decision, action, current_snapshot_digest)
            return refreshed.model_copy(
                update={
                    "matched_rule": "new_protected_rule",
                    "impact_summary": "A newly active policy rule requires approval.",
                }
            )

    harness = loop_fixture(
        responses=[dependency_patch_json()],
        policy_factory=ChangedPolicy,
    )
    harness.loop.run(harness.task_id)
    original = harness.loop.pending_approval(harness.task_id)
    harness.loop.decide_approval(original.id, ApprovalDecision.APPROVE)

    result = harness.loop.resume(harness.task_id)
    replacement = harness.loop.pending_approval(harness.task_id)

    assert result.status is TaskStatus.WAITING_APPROVAL
    assert replacement.id != original.id
    assert replacement.policy_decision.matched_rule == "new_protected_rule"
    assert harness.dispatcher.actions == []


def test_reapproval_storage_failure_maps_to_failed(loop_fixture, monkeypatch) -> None:
    class ChangedPolicy(PolicyEngine):
        def revalidate(self, decision, action, current_snapshot_digest):
            refreshed = super().revalidate(decision, action, current_snapshot_digest)
            return refreshed.model_copy(
                update={
                    "matched_rule": "new_protected_rule",
                    "impact_summary": "A newly active policy rule requires approval.",
                }
            )

    harness = loop_fixture(
        responses=[dependency_patch_json()], policy_factory=ChangedPolicy
    )
    harness.loop.run(harness.task_id)
    original = harness.loop.pending_approval(harness.task_id)
    harness.loop.decide_approval(original.id, ApprovalDecision.APPROVE)
    def fail_reapproval(*args, **kwargs):
        del args, kwargs
        from pyquality.storage.sqlite import StorageStateError

        raise StorageStateError("simulated atomic replacement failure")

    monkeypatch.setattr(
        harness.repository, "replace_approval_and_wait", fail_reapproval
    )

    result = harness.loop.resume(harness.task_id)

    assert result.status is TaskStatus.FAILED
    assert (
        harness.repository.resume_snapshot(harness.task_id).task.status
        is TaskStatus.FAILED
    )


def test_failed_approved_verification_survives_cold_restart_without_redispatch(
    loop_fixture,
) -> None:
    class SimulatedCrash(BaseException):
        pass

    class CrashBeforeNextRound(ScriptedLLM):
        def complete(self, messages: tuple[Message, ...]) -> str:
            if self.calls:
                raise SimulatedCrash
            return super().complete(messages)

    action = dependency_patch_json()
    crashing_llm = CrashBeforeNextRound([action])
    harness = loop_fixture(llm=crashing_llm, reports=[failed_report()])
    harness.loop.run(harness.task_id)
    approval = harness.loop.pending_approval(harness.task_id)
    harness.loop.decide_approval(approval.id, ApprovalDecision.APPROVE)

    with pytest.raises(SimulatedCrash):
        harness.loop.resume(harness.task_id)

    persisted = harness.repository.resume_snapshot(harness.task_id)
    assert persisted.iterations[0].quality_outcome == "failed"
    assert persisted.findings[0].finding.category == "assertion"
    restarted_llm = ScriptedLLM([finish_json()])
    harness.restart(restarted_llm, ScriptedPipeline([successful_report()]))

    result = harness.loop.resume(harness.task_id)

    assert result.status is TaskStatus.SUCCEEDED
    assert "assertion" in restarted_llm.calls[0][-1].content
    assert harness.dispatcher.dispatch_count(action) == 1


def test_malformed_persisted_approval_action_maps_to_failed(loop_fixture) -> None:
    harness = loop_fixture(responses=[])
    assert harness.repository.set_status(
        harness.task_id, TaskStatus.CREATED, TaskStatus.RUNNING
    ) is True
    assert harness.repository.acquire_project_lease(
        harness.task_id, owner_token="seed-owner"
    ) is True
    iteration = harness.repository.append_iteration(
        harness.task_id, sequence=1, context_digest="a" * 64
    )
    approval = harness.repository.record_approval(
        harness.task_id,
        iteration.id,
        '{"kind":"not-an-action"}',
        "b" * 64,
        "c" * 64,
        policy_decision=PolicyDecision(
            outcome=PolicyOutcome.REQUIRE_APPROVAL,
            matched_rule="seeded_corruption",
            impact_summary="Seeded malformed approval.",
            action_digest="b" * 64,
            repository_snapshot_digest="c" * 64,
        ),
    )
    assert harness.repository.set_status(
        harness.task_id,
        TaskStatus.RUNNING,
        TaskStatus.WAITING_APPROVAL,
        owner_token="seed-owner",
    ) is True
    harness.loop.decide_approval(approval.id, ApprovalDecision.APPROVE)
    harness.repository.release_project_lease(
        harness.task_id, owner_token="seed-owner"
    )

    result = harness.loop.resume(harness.task_id)

    assert result.status is TaskStatus.FAILED
    assert harness.dispatcher.actions == []


def test_failed_approved_effect_is_persisted_before_blocked_terminal(loop_fixture) -> None:
    failed = ToolResult(
        effect_kind="apply_patch",
        code_changed=False,
        normalized_metadata={"code": "patch_context_mismatch"},
    )
    harness = loop_fixture(
        responses=[dependency_patch_json()], dispatch_results=[failed]
    )
    harness.loop.run(harness.task_id)
    approval = harness.loop.pending_approval(harness.task_id)
    harness.loop.decide_approval(approval.id, ApprovalDecision.APPROVE)

    result = harness.loop.resume(harness.task_id)
    iteration = harness.repository.resume_snapshot(harness.task_id).iterations[0]

    assert result.status is TaskStatus.BLOCKED
    assert iteration.tool_result_digest is not None
    assert iteration.quality_outcome == "not_run"


def test_non_code_approved_effect_is_persisted_before_next_round(loop_fixture) -> None:
    non_code = ToolResult(
        effect_kind="apply_patch",
        code_changed=False,
        normalized_metadata={"code": "ok"},
    )
    harness = loop_fixture(
        responses=[dependency_patch_json()],
        dispatch_results=[non_code],
        round_limit=1,
    )
    harness.loop.run(harness.task_id)
    approval = harness.loop.pending_approval(harness.task_id)
    harness.loop.decide_approval(approval.id, ApprovalDecision.APPROVE)

    result = harness.loop.resume(harness.task_id)
    iteration = harness.repository.resume_snapshot(harness.task_id).iterations[0]

    assert result.status is TaskStatus.BUDGET_EXHAUSTED
    assert iteration.tool_result_digest is not None
    assert iteration.quality_outcome == "not_run"


def test_verifier_deadline_persists_approved_effect_before_budget_terminal(
    loop_fixture,
) -> None:
    clock = FixedClock(NOW)
    deadline = NOW + timedelta(seconds=1)
    harness = loop_fixture(
        responses=[dependency_patch_json()],
        reports=[successful_report()],
        deadline=deadline,
        clock=clock,
    )
    harness.dispatcher.on_dispatch = lambda: setattr(clock, "value", deadline)
    harness.loop.run(harness.task_id)
    approval = harness.loop.pending_approval(harness.task_id)
    harness.loop.decide_approval(approval.id, ApprovalDecision.APPROVE)

    result = harness.loop.resume(harness.task_id)
    snapshot = harness.repository.resume_snapshot(harness.task_id)

    assert result.status is TaskStatus.BUDGET_EXHAUSTED
    assert snapshot.iterations[0].tool_result_digest is not None
    assert snapshot.iterations[0].quality_outcome == "not_run"
    assert snapshot.decided_approval.execution_state == "completed"
    assert harness.pipeline.calls == []
