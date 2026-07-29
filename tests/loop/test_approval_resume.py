from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier, Event

import pytest
from conftest import (
    NOW,
    FixedClock,
    ScriptedPipeline,
    dependency_patch_json,
    failed_report,
    finish_json,
    quality_json,
    successful_report,
)
from fastapi.testclient import TestClient

from pyquality.config import Settings
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
from pyquality.service import HarnessService, PreflightError
from pyquality.storage.sqlite import StorageStateError
from pyquality.web.app import create_app


@pytest.mark.parametrize("decision", [ApprovalDecision.APPROVE, ApprovalDecision.REJECT])
def test_service_approval_decision_resumes_real_loop_to_terminal(
    loop_fixture, decision: ApprovalDecision
) -> None:
    continuation = (
        [finish_json()]
        if decision is ApprovalDecision.APPROVE
        else [quality_json(), finish_json()]
    )
    harness = loop_fixture(
        responses=[dependency_patch_json(), *continuation],
        reports=[successful_report(), successful_report(), successful_report()],
    )
    service = HarnessService(
        repository=harness.repository,
        loop=harness.loop,
        settings=Settings(global_concurrency=1),
        verifier_finder=lambda name: name,
    )
    task = service.create_task(harness.repo_root, "repair")
    assert service.start_task(task.id).result(timeout=2).status is TaskStatus.WAITING_APPROVAL
    approval = harness.loop.pending_approval(task.id)

    future = (
        service.approve(approval.id)
        if decision is ApprovalDecision.APPROVE
        else service.reject(approval.id)
    )

    assert future.result(timeout=2).status is TaskStatus.SUCCEEDED


def test_waiting_future_is_not_published_until_capacity_allows_approval(
    loop_fixture,
) -> None:
    harness = loop_fixture(
        responses=[dependency_patch_json(), finish_json()],
        reports=[successful_report(), successful_report()],
    )
    service = HarnessService(
        repository=harness.repository,
        loop=harness.loop,
        settings=Settings(global_concurrency=1),
        verifier_finder=lambda name: name,
    )
    cleanup_entered = Event()
    allow_cleanup = Event()
    original_owns = harness.repository.owns_project_lease

    def block_waiting_cleanup(task_id: str, *, owner_token: str) -> bool:
        if harness.repository.resume_snapshot(task_id).task.status is TaskStatus.WAITING_APPROVAL:
            cleanup_entered.set()
            assert allow_cleanup.wait(2)
        return original_owns(task_id, owner_token=owner_token)

    harness.repository.owns_project_lease = block_waiting_cleanup
    task = service.create_task(harness.repo_root, "repair")
    future = service.start_task(task.id)
    assert cleanup_entered.wait(1)
    approval = harness.loop.pending_approval(task.id)

    published_before_cleanup = future.done()
    capacity_available_before_cleanup = True
    try:
        service.approve(approval.id)
    except PreflightError:
        capacity_available_before_cleanup = False
    allow_cleanup.set()
    assert not published_before_cleanup
    assert not capacity_available_before_cleanup
    assert future.result(timeout=2).status is TaskStatus.WAITING_APPROVAL
    assert service.approve(approval.id).result(timeout=2).status is TaskStatus.SUCCEEDED


@pytest.mark.parametrize("decision", [ApprovalDecision.APPROVE, ApprovalDecision.REJECT])
def test_web_recovers_approval_dispatch_after_service_and_repository_restart(
    loop_fixture, decision: ApprovalDecision
) -> None:
    continuation = (
        [finish_json()]
        if decision is ApprovalDecision.APPROVE
        else [quality_json(), finish_json()]
    )
    harness = loop_fixture(
        responses=[dependency_patch_json(), *continuation],
        reports=[successful_report(), successful_report()],
    )
    service = HarnessService(
        repository=harness.repository,
        loop=harness.loop,
        settings=Settings(global_concurrency=1),
        verifier_finder=lambda name: name,
    )
    task = service.create_task(harness.repo_root, "repair")
    assert service.start_task(task.id).result(timeout=2).status is TaskStatus.WAITING_APPROVAL
    approval = harness.loop.pending_approval(task.id)

    class FailingExecutor:
        def __init__(self, delegate: ThreadPoolExecutor) -> None:
            self._delegate = delegate

        def submit(self, *args, **kwargs):
            raise RuntimeError("submit failed")

        def shutdown(self, *, wait: bool, cancel_futures: bool) -> None:
            self._delegate.shutdown(wait=wait, cancel_futures=cancel_futures)

    service._executor = FailingExecutor(service._executor)
    client = TestClient(create_app(service, mode="local"))
    page = client.get(f"/tasks/{task.id}")
    token = page.text.split('name="csrf_token" value="', 1)[1].split('"', 1)[0]
    failed = client.post(
        f"/approvals/{approval.id}/{decision.value}",
        data={"csrf_token": token},
        follow_redirects=False,
    )
    assert failed.status_code == 409

    snapshot = harness.repository.resume_snapshot(task.id)
    assert snapshot.task.status is TaskStatus.RUNNING
    assert snapshot.decided_approval is not None
    assert snapshot.decided_approval.decision is decision

    contender_repository = type(harness.repository)(harness.db_path)
    contender = HarnessService(
        repository=contender_repository,
        loop=harness.loop,
        settings=Settings(global_concurrency=1),
        verifier_finder=lambda name: name,
    )
    contender_client = TestClient(create_app(contender, mode="local"))
    contender_page = contender_client.get(f"/tasks/{task.id}")
    assert f'/tasks/{task.id}/resume' in contender_page.text
    contender_token = contender_page.text.split(
        'name="csrf_token" value="', 1
    )[1].split('"', 1)[0]
    refused = contender_client.post(
        f"/tasks/{task.id}/resume",
        data={"csrf_token": contender_token},
        follow_redirects=False,
    )
    assert refused.status_code == 409
    assert "busy" in refused.text
    contender.close()
    contender_repository.close()

    service.close()
    harness.restart(
        ScriptedLLM([quality_json(), finish_json()]),
        ScriptedPipeline(
            [successful_report(), successful_report(), successful_report()]
        ),
    )
    restarted = HarnessService(
        repository=harness.repository,
        loop=harness.loop,
        settings=Settings(global_concurrency=1),
        verifier_finder=lambda name: name,
    )
    restarted_client = TestClient(create_app(restarted, mode="local"))
    recovery_page = restarted_client.get(f"/tasks/{task.id}")
    assert f'/tasks/{task.id}/resume' in recovery_page.text
    assert restarted_client.post(f"/tasks/{task.id}/resume").status_code == 403
    restart_token = recovery_page.text.split(
        'name="csrf_token" value="', 1
    )[1].split('"', 1)[0]
    retried = restarted_client.post(
        f"/tasks/{task.id}/resume",
        data={"csrf_token": restart_token},
        follow_redirects=False,
    )
    assert retried.status_code == 303
    assert retried.headers["location"] == f"/tasks/{task.id}"
    assert restarted.start_task(task.id).result(timeout=2).status is TaskStatus.SUCCEEDED
    restarted.close()


def test_web_recovers_running_task_after_worker_and_pre_release_cleanup_failures(
    loop_fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = loop_fixture(
        responses=[quality_json(), finish_json()],
        reports=[successful_report(), successful_report()],
    )
    original_run_leased = harness.loop.run_leased
    run_count = 0

    def fail_worker_once(
        task_id: str, owner_token: str, *, resume: bool
    ):
        nonlocal run_count
        run_count += 1
        if run_count == 1:
            raise RuntimeError("worker failed before terminal state")
        return original_run_leased(task_id, owner_token, resume=resume)

    original_release = harness.repository.release_project_lease
    release_count = 0

    def fail_before_release(task_id: str, *, owner_token: str) -> None:
        nonlocal release_count
        release_count += 1
        if release_count == 1:
            raise RuntimeError("cleanup failed before lease release")
        original_release(task_id, owner_token=owner_token)

    monkeypatch.setattr(harness.loop, "run_leased", fail_worker_once)
    monkeypatch.setattr(
        harness.repository, "release_project_lease", fail_before_release
    )
    service = HarnessService(
        repository=harness.repository,
        loop=harness.loop,
        settings=Settings(global_concurrency=1),
        verifier_finder=lambda name: name,
    )
    cleanup_complete = Event()
    original_complete = service._complete_submission

    def signal_cleanup(*args, **kwargs) -> None:
        try:
            original_complete(*args, **kwargs)
        finally:
            cleanup_complete.set()

    monkeypatch.setattr(service, "_complete_submission", signal_cleanup)

    failed = service.start_task(harness.task_id)
    with pytest.raises(RuntimeError, match="worker failed before terminal"):
        failed.result(timeout=2)
    assert cleanup_complete.wait(1)
    assert harness.repository.resume_snapshot(harness.task_id).task.status is TaskStatus.RUNNING
    assert harness.repository._held_leases

    client = TestClient(create_app(service, mode="local"))
    recovery_page = client.get(f"/tasks/{harness.task_id}")
    assert f'/tasks/{harness.task_id}/resume' in recovery_page.text
    token = recovery_page.text.split('name="csrf_token" value="', 1)[1].split(
        '"', 1
    )[0]
    retried = client.post(
        f"/tasks/{harness.task_id}/resume",
        data={"csrf_token": token},
        follow_redirects=False,
    )

    assert retried.status_code == 303
    assert service.start_task(harness.task_id).result(timeout=2).status is TaskStatus.SUCCEEDED
    service.close()


@pytest.mark.parametrize("decision", [ApprovalDecision.APPROVE, ApprovalDecision.REJECT])
def test_service_approval_submit_failure_keeps_recoverable_decision_and_lease(
    loop_fixture, decision: ApprovalDecision
) -> None:
    continuation = (
        [finish_json()]
        if decision is ApprovalDecision.APPROVE
        else [quality_json(), finish_json()]
    )
    harness = loop_fixture(
        responses=[dependency_patch_json(), *continuation],
        reports=[successful_report(), successful_report()],
    )
    service = HarnessService(
        repository=harness.repository,
        loop=harness.loop,
        settings=Settings(global_concurrency=1),
        verifier_finder=lambda name: name,
    )
    task = service.create_task(harness.repo_root, "repair")
    assert service.start_task(task.id).result(timeout=2).status is TaskStatus.WAITING_APPROVAL
    approval = harness.loop.pending_approval(task.id)

    class FailingExecutor:
        def submit(self, *args, **kwargs):
            raise RuntimeError("submit failed")

    service._executor = FailingExecutor()
    with pytest.raises(RuntimeError, match="submit failed"):
        if decision is ApprovalDecision.APPROVE:
            service.approve(approval.id)
        else:
            service.reject(approval.id)

    snapshot = harness.repository.resume_snapshot(task.id)
    assert snapshot.task.status is TaskStatus.RUNNING
    assert snapshot.decided_approval is not None
    assert snapshot.decided_approval.decision is decision
    assert harness.repository._held_leases
    service._executor = ThreadPoolExecutor(max_workers=1)
    assert service.start_task(task.id).result(timeout=2).status is TaskStatus.SUCCEEDED


def test_approval_contention_consumes_exactly_one_decision(loop_fixture) -> None:
    harness = loop_fixture(responses=[dependency_patch_json()])
    service = HarnessService(
        repository=harness.repository,
        loop=harness.loop,
        settings=Settings(global_concurrency=1),
        verifier_finder=lambda name: name,
    )
    task = service.create_task(harness.repo_root, "repair")
    assert service.start_task(task.id).result(timeout=2).status is TaskStatus.WAITING_APPROVAL
    approval = harness.loop.pending_approval(task.id)
    contender = type(harness.repository)(harness.db_path)
    barrier = Barrier(2)

    def decide(repository, decision: ApprovalDecision, token: str) -> str:
        barrier.wait()
        try:
            repository.decide_approval_and_acquire_lease(
                approval.id, decision, owner_token=token
            )
            return decision.value
        except StorageStateError:
            return "lost"

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(decide, harness.repository, ApprovalDecision.APPROVE, "approve-owner"),
            pool.submit(decide, contender, ApprovalDecision.REJECT, "reject-owner"),
        ]
        values = [future.result() for future in futures]

    assert values.count("lost") == 1
    assert len({value for value in values if value != "lost"}) == 1


def test_approval_pauses_and_executes_once(loop_fixture) -> None:
    action = dependency_patch_json()
    harness = loop_fixture(
        responses=[action, finish_json()],
        reports=[successful_report(), successful_report(), successful_report()],
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
    lifecycle = [
        event.event_type
        for event in harness.audit.events
        if event.event_type
        in {"quality_candidate_ready", "finish_verification", "task_terminal"}
    ]
    assert lifecycle == [
        "quality_candidate_ready",
        "finish_verification",
        "task_terminal",
    ]

    try:
        harness.loop.decide_approval(approval.id, ApprovalDecision.REJECT)
    except ApprovalStateError:
        pass
    else:
        raise AssertionError("terminal approval decision did not fail")


def test_rejected_action_becomes_feedback_once_after_reopen(loop_fixture) -> None:
    harness = loop_fixture(
        responses=[dependency_patch_json(), quality_json(), finish_json()],
        reports=[successful_report(), successful_report()],
    )
    harness.loop.run(harness.task_id)
    approval = harness.loop.pending_approval(harness.task_id)
    harness.loop.decide_approval(approval.id, ApprovalDecision.REJECT)

    result = harness.loop.resume(harness.task_id)

    assert result.status is TaskStatus.SUCCEEDED
    assert "rejected by user" in harness.llm.calls[1][-1].content
    assert all(
        "rejected by user" not in call[-1].content
        for call in harness.llm.calls[2:]
    )
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
        responses=[action, finish_json()],
        reports=[successful_report(), successful_report()],
        round_limit=3,
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
    assert len(harness.pipeline.calls) == 2
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
        responses=[action, finish_json()],
        reports=[successful_report(), successful_report()],
        round_limit=3,
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
        responses=[action, finish_json()],
        reports=[successful_report(), successful_report()],
        round_limit=3,
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
    restarted_llm = ScriptedLLM([quality_json(), finish_json()])
    harness.restart(
        restarted_llm,
        ScriptedPipeline([successful_report(), successful_report()]),
    )

    result = harness.loop.resume(harness.task_id)

    assert result.status is TaskStatus.SUCCEEDED
    assert "assertion" in restarted_llm.calls[0][-1].content
    assert harness.dispatcher.dispatch_count(action) == 1


def test_passing_approved_verification_crash_recovers_candidate_then_finishes(
    loop_fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A crash after persisted approval pass must await a distinct finish, not terminalize."""
    class CrashAfterApprovedPass(BaseException):
        pass

    action = dependency_patch_json()
    harness = loop_fixture(
        responses=[action, finish_json()],
        reports=[successful_report(), successful_report()],
    )
    assert harness.loop.run(harness.task_id).status is TaskStatus.WAITING_APPROVAL
    approval = harness.loop.pending_approval(harness.task_id)
    harness.loop.decide_approval(approval.id, ApprovalDecision.APPROVE)
    complete = harness.repository.complete_iteration_outcome

    def crash_after_atomic_pass(*args, **kwargs):
        complete(*args, **kwargs)
        raise CrashAfterApprovedPass

    monkeypatch.setattr(
        harness.repository, "complete_iteration_outcome", crash_after_atomic_pass
    )
    with pytest.raises(CrashAfterApprovedPass):
        harness.loop.resume(harness.task_id)
    snapshot = harness.repository.resume_snapshot(harness.task_id)
    assert snapshot.task.status is TaskStatus.RUNNING
    assert snapshot.decided_approval is not None
    assert snapshot.decided_approval.execution_state == "completed"
    assert harness.repository.green_candidate(harness.task_id) is not None
    monkeypatch.setattr(harness.repository, "complete_iteration_outcome", complete)

    harness.repository._connection.execute(
        "DELETE FROM green_candidates WHERE task_id = ?", (harness.task_id,)
    )
    harness.repository._connection.execute(
        "UPDATE approvals SET execution_state = 'intent_recorded' WHERE id = ?",
        (approval.id,),
    )
    harness.repository._connection.commit()
    class CrashBeforeFinish(ScriptedLLM):
        def complete(self, messages):
            raise CrashAfterApprovedPass

    harness.llm = CrashBeforeFinish([])
    harness.loop._llm = harness.llm
    with pytest.raises(CrashAfterApprovedPass):
        harness.loop.resume(harness.task_id)
    candidate = harness.repository.green_candidate(harness.task_id)
    assert candidate is not None
    from pyquality.loop import _digest_model

    assert candidate.report_digest == _digest_model(successful_report())
    assert candidate.report_digest != snapshot.iterations[0].tool_result_digest
    harness.llm = ScriptedLLM([finish_json()])
    harness.loop._llm = harness.llm

    result = harness.loop.resume(harness.task_id)

    assert result.status is TaskStatus.SUCCEEDED
    assert harness.dispatcher.dispatch_count(action) == 1
    assert len(harness.pipeline.calls) == 2


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
