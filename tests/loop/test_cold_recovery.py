from __future__ import annotations

import hashlib
from datetime import timedelta
from threading import Event, Thread

import pytest
from conftest import (
    NOW,
    FixedClock,
    RecordingAuditSink,
    RecordingDispatcher,
    ScriptedPipeline,
    action_json,
    dependency_patch_json,
    failed_report,
    finish_json,
    ordinary_patch_json,
    quality_json,
    successful_report,
)

from pyquality.context import ContextBuilder
from pyquality.domain.models import (
    Action,
    ApprovalDecision,
    PolicyDecision,
    PolicyOutcome,
    TaskStatus,
    ToolResult,
)
from pyquality.feedback import ProgressTracker
from pyquality.llm import ActionParser, Message, ScriptedLLM
from pyquality.loop import AgentLoop
from pyquality.policy import PolicyEngine
from pyquality.storage.sqlite import SQLiteTaskRepository


class SimulatedCrash(BaseException):
    pass


class SnapshotSwitchPolicy:
    def __init__(self, root) -> None:
        self._delegate = PolicyEngine(root)
        self.allow_same_action = False

    def evaluate(self, action: Action) -> PolicyDecision:
        decision = self._delegate.evaluate(action)
        if self.allow_same_action and action.kind == "apply_patch":
            return decision.model_copy(
                update={
                    "outcome": PolicyOutcome.ALLOW,
                    "matched_rule": "test_snapshot_allow",
                    "impact_summary": "same action allowed in a later snapshot",
                    "repository_snapshot_digest": "e" * 64,
                }
            )
        return decision

    def revalidate(
        self,
        previous: PolicyDecision,
        action: Action,
        current_snapshot_digest: str,
    ) -> PolicyDecision:
        return self._delegate.revalidate(previous, action, current_snapshot_digest)


def crash_after_completed_transition(harness, monkeypatch, kind: str) -> None:
    complete = harness.repository.complete_transition_intent

    def crashing_complete(intent_id, **kwargs):
        record = complete(intent_id, **kwargs)
        if record.kind == kind:
            raise SimulatedCrash
        return record

    monkeypatch.setattr(
        harness.repository, "complete_transition_intent", crashing_complete
    )


def test_completed_model_response_cold_reopen_does_not_call_provider_again(
    loop_fixture, monkeypatch
) -> None:
    harness = loop_fixture(
        responses=[quality_json(), finish_json()],
        reports=[successful_report(), successful_report()],
    )
    crash_after_completed_transition(harness, monkeypatch, "model_call")

    with pytest.raises(SimulatedCrash):
        harness.loop.run(harness.task_id)
    assert len(harness.llm.calls) == 1
    assert harness.repository.resume_snapshot(harness.task_id).iterations == ()

    restarted_llm = ScriptedLLM([finish_json()])
    restarted_pipeline = ScriptedPipeline(
        [successful_report(), successful_report()]
    )
    harness.restart(restarted_llm, restarted_pipeline)
    result = harness.loop.resume(harness.task_id)

    assert result.status is TaskStatus.SUCCEEDED
    assert len(restarted_llm.calls) == 1
    assert len(restarted_pipeline.calls) == 2


def test_completed_rejection_cold_reopen_restores_feedback_once(
    loop_fixture, monkeypatch
) -> None:
    harness = loop_fixture(
        responses=[dependency_patch_json()], reports=[]
    )
    harness.loop.run(harness.task_id)
    approval = harness.loop.pending_approval(harness.task_id)
    harness.loop.decide_approval(approval.id, ApprovalDecision.REJECT)
    consume = harness.repository.mark_rejection_consumed

    def crash_after_consume(approval_id, **kwargs):
        consume(approval_id, **kwargs)
        raise SimulatedCrash

    monkeypatch.setattr(harness.repository, "mark_rejection_consumed", crash_after_consume)
    with pytest.raises(SimulatedCrash):
        harness.loop.resume(harness.task_id)

    restarted_llm = ScriptedLLM([quality_json(), finish_json()])
    harness.restart(
        restarted_llm,
        ScriptedPipeline([successful_report(), successful_report()]),
    )
    result = harness.loop.resume(harness.task_id)

    assert result.status is TaskStatus.SUCCEEDED
    assert "rejected by user" in restarted_llm.calls[0][-1].content
    snapshot = harness.repository.resume_snapshot(harness.task_id)
    rejection_findings = [
        item for item in snapshot.findings if "rejected" in item.finding.summary
    ]
    assert len(rejection_findings) == 1


def test_completed_verifier_report_cold_reopen_is_not_rerun(
    loop_fixture, monkeypatch
) -> None:
    harness = loop_fixture(
        responses=[ordinary_patch_json()], reports=[failed_report()]
    )
    crash_after_completed_transition(harness, monkeypatch, "verifier")
    with pytest.raises(SimulatedCrash):
        harness.loop.run(harness.task_id)
    assert len(harness.dispatcher.actions) == 1
    assert len(harness.pipeline.calls) == 1

    restarted_llm = ScriptedLLM([quality_json(), finish_json()])
    restarted_pipeline = ScriptedPipeline(
        [successful_report(), successful_report()]
    )
    harness.restart(restarted_llm, restarted_pipeline)
    result = harness.loop.resume(harness.task_id)

    assert result.status is TaskStatus.SUCCEEDED
    assert len(harness.dispatcher.actions) == 1
    assert len(restarted_pipeline.calls) == 2
    assert "assertion" in restarted_llm.calls[0][-1].content


def test_approved_completed_verifier_cold_reopen_is_not_rerun(
    loop_fixture, monkeypatch
) -> None:
    harness = loop_fixture(
        responses=[dependency_patch_json()], reports=[failed_report()]
    )
    harness.loop.run(harness.task_id)
    approval = harness.loop.pending_approval(harness.task_id)
    harness.loop.decide_approval(approval.id, ApprovalDecision.APPROVE)
    crash_after_completed_transition(harness, monkeypatch, "verifier")

    with pytest.raises(SimulatedCrash):
        harness.loop.resume(harness.task_id)

    restarted_llm = ScriptedLLM([quality_json(), finish_json()])
    restarted_pipeline = ScriptedPipeline(
        [successful_report(), successful_report()]
    )
    harness.restart(restarted_llm, restarted_pipeline)
    result = harness.loop.resume(harness.task_id)

    assert result.status is TaskStatus.SUCCEEDED
    assert len(harness.dispatcher.actions) == 1
    assert len(restarted_pipeline.calls) == 2
    assert "assertion" in restarted_llm.calls[0][-1].content


def test_approved_failed_report_persisted_before_completion_recovers_as_feedback(
    loop_fixture, monkeypatch
) -> None:
    harness = loop_fixture(
        responses=[dependency_patch_json()], reports=[failed_report()]
    )
    harness.loop.run(harness.task_id)
    approval = harness.loop.pending_approval(harness.task_id)
    harness.loop.decide_approval(approval.id, ApprovalDecision.APPROVE)
    persist = harness.repository.complete_iteration_outcome

    def crash_after_report(*args, **kwargs):
        persist(*args, **kwargs)
        raise SimulatedCrash

    monkeypatch.setattr(harness.repository, "complete_iteration_outcome", crash_after_report)
    with pytest.raises(SimulatedCrash):
        harness.loop.resume(harness.task_id)

    restarted_llm = ScriptedLLM([quality_json(), finish_json()])
    restarted_pipeline = ScriptedPipeline(
        [successful_report(), successful_report()]
    )
    harness.restart(restarted_llm, restarted_pipeline)
    result = harness.loop.resume(harness.task_id)

    assert result.status is TaskStatus.SUCCEEDED
    assert len(harness.dispatcher.actions) == 1
    assert len(restarted_pipeline.calls) == 2
    assert "assertion" in restarted_llm.calls[0][-1].content


def test_already_applied_recovery_atomically_consumes_dispatch_with_verifier(
    loop_fixture,
) -> None:
    policy: SnapshotSwitchPolicy | None = None

    def policy_factory(root):
        nonlocal policy
        policy = SnapshotSwitchPolicy(root)
        return policy

    action_json = dependency_patch_json()
    harness = loop_fixture(
        responses=[action_json], reports=[], policy_factory=policy_factory
    )
    assert harness.loop.run(harness.task_id).status is TaskStatus.WAITING_APPROVAL
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
    applied = ToolResult(
        effect_kind="apply_patch",
        code_changed=True,
        changed_paths=("pyproject.toml",),
        before_digests={"pyproject.toml": "c" * 64},
        after_digests=harness.dispatcher.expected,
        normalized_metadata={"code": "ok"},
    )
    dispatch_intent = harness.repository.record_transition_intent(
        harness.task_id,
        kind="dispatch",
        evidence_digest=approval.action_digest,
        summary="dispatch authorized",
        owner_token="seed-owner",
    )
    harness.repository.complete_transition_intent(
        dispatch_intent.id,
        result_digest=hashlib.sha256(applied.model_dump_json().encode()).hexdigest(),
        summary="tool result persisted",
        result_payload={"tool_result": applied.model_dump(mode="json")},
        owner_token="seed-owner",
    )
    harness.repository.release_project_lease(
        harness.task_id, owner_token="seed-owner"
    )

    assert policy is not None
    policy.allow_same_action = True
    harness.dispatcher.effect_already_matches = True
    harness.restart(
        ScriptedLLM([action_json, finish_json()]),
        ScriptedPipeline(
            [failed_report(), successful_report(), successful_report()]
        ),
        policy=policy,
    )

    result = harness.loop.resume(harness.task_id)

    assert result.status is TaskStatus.SUCCEEDED
    assert harness.dispatcher.dispatch_count(action_json) == 1
    transitions = harness.repository.resume_snapshot(
        harness.task_id
    ).transition_intents
    seeded = next(item for item in transitions if item.id == dispatch_intent.id)
    verifiers = [item for item in transitions if item.kind == "verifier"]
    assert seeded.consumed_at is not None
    assert len(verifiers) == 3
    assert seeded.consumed_at == verifiers[0].consumed_at


def test_recovery_drains_all_legacy_and_exact_snapshot_dispatches_atomically(
    loop_fixture,
) -> None:
    policy: SnapshotSwitchPolicy | None = None

    def policy_factory(root):
        nonlocal policy
        policy = SnapshotSwitchPolicy(root)
        return policy

    raw_action = dependency_patch_json()
    harness = loop_fixture(
        responses=[raw_action], reports=[], policy_factory=policy_factory
    )
    assert harness.loop.run(harness.task_id).status is TaskStatus.WAITING_APPROVAL
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
    applied = ToolResult(
        effect_kind="apply_patch",
        code_changed=True,
        changed_paths=("pyproject.toml",),
        before_digests={"pyproject.toml": "c" * 64},
        after_digests=harness.dispatcher.expected,
        normalized_metadata={"code": "ok"},
    )
    def seed_dispatch(
        evidence_digest: str, *, repository_snapshot_digest: str | None = None
    ):
        intent = harness.repository.record_transition_intent(
            harness.task_id,
            kind="dispatch",
            evidence_digest=evidence_digest,
            summary="dispatch authorized",
            owner_token="seed-owner",
        )
        payload: dict[str, object] = {
            "tool_result": applied.model_dump(mode="json")
        }
        if repository_snapshot_digest is not None:
            payload["repository_snapshot_digest"] = repository_snapshot_digest
        harness.repository.complete_transition_intent(
            intent.id,
            result_digest=hashlib.sha256(applied.model_dump_json().encode()).hexdigest(),
            summary="tool result persisted",
            result_payload=payload,
            owner_token="seed-owner",
        )
        return intent

    legacy_dispatches = (
        seed_dispatch(approval.action_digest),
        seed_dispatch(approval.action_digest),
    )
    exact_dispatch = seed_dispatch(
        approval.action_digest,
        repository_snapshot_digest=approval.repository_snapshot_digest,
    )
    other_snapshot_dispatch = seed_dispatch(
        approval.action_digest,
        repository_snapshot_digest="9" * 64,
    )
    other_action_dispatch = seed_dispatch(
        "8" * 64,
        repository_snapshot_digest=approval.repository_snapshot_digest,
    )
    report = failed_report()
    verifier_intent = harness.repository.record_transition_intent(
        harness.task_id,
        kind="verifier",
        evidence_digest="f" * 64,
        summary="quality requested",
        owner_token="seed-owner",
    )
    harness.repository.complete_transition_intent(
        verifier_intent.id,
        result_digest="a" * 64,
        summary="quality report persisted",
        result_payload={"quality_report": report.model_dump(mode="json")},
        owner_token="seed-owner",
    )
    harness.repository.complete_iteration_outcome(
        harness.task_id,
        approval.iteration_id,
        tool_result_digest="b" * 64,
        fingerprint="c" * 64,
        relevant_digest="d" * 64,
        quality_outcome="failed",
        findings=report.findings,
        source_intent_ids=(verifier_intent.id,),
        owner_token="seed-owner",
    )
    harness.repository.release_project_lease(
        harness.task_id, owner_token="seed-owner"
    )
    seeded_ids = {
        *(item.id for item in legacy_dispatches),
        exact_dispatch.id,
        other_snapshot_dispatch.id,
        other_action_dispatch.id,
    }
    seeded_before = {
        item.id: item
        for item in harness.repository.resume_snapshot(
            harness.task_id
        ).transition_intents
        if item.id in seeded_ids
    }
    assert all(item.consumed_at is None for item in seeded_before.values())

    assert policy is not None
    policy.allow_same_action = True
    harness.restart(
        ScriptedLLM([raw_action, finish_json()]),
        ScriptedPipeline([successful_report(), successful_report()]),
        policy=policy,
    )

    result = harness.loop.resume(harness.task_id)

    assert result.status is TaskStatus.SUCCEEDED
    assert harness.dispatcher.dispatch_count(raw_action) == 1
    seeded_after = {
        item.id: item
        for item in harness.repository.resume_snapshot(
            harness.task_id
        ).transition_intents
        if item.id in seeded_ids
    }
    matching_ids = {
        *(item.id for item in legacy_dispatches),
        exact_dispatch.id,
    }
    consumed_times = {
        seeded_after[intent_id].consumed_at for intent_id in matching_ids
    }
    assert None not in consumed_times
    assert len(consumed_times) == 1
    assert seeded_after[other_snapshot_dispatch.id].consumed_at is None
    assert seeded_after[other_action_dispatch.id].consumed_at is None


@pytest.mark.parametrize(
    "invalid_snapshot_digest",
    [pytest.param(None, id="null"), pytest.param("not-a-sha256", id="malformed")],
)
def test_present_invalid_snapshot_digest_is_not_recovered_as_legacy(
    loop_fixture, invalid_snapshot_digest: object,
) -> None:
    """Treating an annotated invalid digest as absent could replay another snapshot."""
    raw_action = ordinary_patch_json()
    harness = loop_fixture(
        responses=[raw_action, finish_json()],
        reports=[successful_report(), successful_report()],
    )
    action = ActionParser().parse(raw_action)
    decision = harness.loop._policy.evaluate(action)
    assert harness.repository.set_status(
        harness.task_id, TaskStatus.CREATED, TaskStatus.RUNNING
    ) is True
    assert harness.repository.acquire_project_lease(
        harness.task_id, owner_token="seed-owner"
    ) is True
    applied = ToolResult(
        effect_kind="apply_patch",
        code_changed=True,
        changed_paths=("src/calc.py",),
        before_digests={"src/calc.py": "c" * 64},
        after_digests={"src/calc.py": "d" * 64},
        normalized_metadata={"code": "ok"},
    )
    invalid_dispatch = harness.repository.record_transition_intent(
        harness.task_id,
        kind="dispatch",
        evidence_digest=decision.action_digest,
        summary="dispatch authorized",
        owner_token="seed-owner",
    )
    harness.repository.complete_transition_intent(
        invalid_dispatch.id,
        result_digest="e" * 64,
        summary="tool result persisted",
        result_payload={
            "tool_result": applied.model_dump(mode="json"),
            "repository_snapshot_digest": invalid_snapshot_digest,
        },
        owner_token="seed-owner",
    )
    harness.repository.release_project_lease(
        harness.task_id, owner_token="seed-owner"
    )

    persisted_before = next(
        intent
        for intent in harness.repository.resume_snapshot(
            harness.task_id
        ).transition_intents
        if intent.id == invalid_dispatch.id
    )
    assert "repository_snapshot_digest" in (persisted_before.result_payload or {})

    result = harness.loop.resume(harness.task_id)

    assert result.status is TaskStatus.SUCCEEDED
    assert harness.dispatcher.dispatch_count(raw_action) == 1
    persisted_after = next(
        intent
        for intent in harness.repository.resume_snapshot(
            harness.task_id
        ).transition_intents
        if intent.id == invalid_dispatch.id
    )
    assert persisted_after.consumed_at is None


def test_schema_repair_cap_survives_cold_reopen(loop_fixture) -> None:
    class CrashBeforeSecondRound(ScriptedLLM):
        def complete(self, messages: tuple[Message, ...]) -> str:
            if self.calls:
                raise SimulatedCrash
            return super().complete(messages)

    harness = loop_fixture(llm=CrashBeforeSecondRound(["not json"]))
    with pytest.raises(SimulatedCrash):
        harness.loop.run(harness.task_id)
    assert len(harness.repository.resume_snapshot(harness.task_id).iterations) == 1

    restarted_llm = ScriptedLLM(["[]", '{"kind":"unknown"}'])
    harness.restart(restarted_llm, ScriptedPipeline([]))
    result = harness.loop.resume(harness.task_id)

    assert result.status is TaskStatus.FAILED
    assert len(restarted_llm.calls) == 2
    assert all("schema" in call[-1].content.casefold() for call in restarted_llm.calls)


def test_non_mutating_tool_feedback_survives_exact_dispatch_crash(
    loop_fixture, monkeypatch
) -> None:
    output = ToolResult(
        effect_kind="read_file",
        code_changed=False,
        evidence="persisted tool output",
        normalized_metadata={"code": "ok"},
    )
    harness = loop_fixture(
        responses=[action_json("read_file", {"path": "src/calc.py"})],
        dispatch_results=[output],
    )
    crash_after_completed_transition(harness, monkeypatch, "dispatch")
    with pytest.raises(SimulatedCrash):
        harness.loop.run(harness.task_id)

    restarted_llm = ScriptedLLM([quality_json(), finish_json()])
    harness.restart(
        restarted_llm,
        ScriptedPipeline([successful_report(), successful_report()]),
    )
    result = harness.loop.resume(harness.task_id)

    assert result.status is TaskStatus.SUCCEEDED
    assert len(harness.dispatcher.actions) == 1
    assert "persisted tool output" in restarted_llm.calls[0][-1].content


def test_non_mutating_tool_feedback_survives_crash_after_iteration_commit(
    loop_fixture, monkeypatch
) -> None:
    output = ToolResult(
        effect_kind="read_file",
        code_changed=False,
        evidence="committed tool output",
        normalized_metadata={"code": "ok"},
    )
    harness = loop_fixture(
        responses=[action_json("read_file", {"path": "src/calc.py"})],
        dispatch_results=[output],
    )
    append = harness.repository.append_iteration

    def crash_after_iteration(*args, **kwargs):
        record = append(*args, **kwargs)
        if record.tool_result_digest is not None:
            raise SimulatedCrash
        return record

    monkeypatch.setattr(harness.repository, "append_iteration", crash_after_iteration)
    with pytest.raises(SimulatedCrash):
        harness.loop.run(harness.task_id)

    restarted_llm = ScriptedLLM([quality_json(), finish_json()])
    harness.restart(
        restarted_llm,
        ScriptedPipeline([successful_report(), successful_report()]),
    )
    result = harness.loop.resume(harness.task_id)

    assert result.status is TaskStatus.SUCCEEDED
    assert len(harness.dispatcher.actions) == 1
    assert "committed tool output" in restarted_llm.calls[0][-1].content


def test_cumulative_changed_paths_survive_cold_reopen(loop_fixture) -> None:
    class CrashBeforeNextRound(ScriptedLLM):
        def complete(self, messages: tuple[Message, ...]) -> str:
            if self.calls:
                raise SimulatedCrash
            return super().complete(messages)

    harness = loop_fixture(
        llm=CrashBeforeNextRound([ordinary_patch_json()]), reports=[failed_report()]
    )
    with pytest.raises(SimulatedCrash):
        harness.loop.run(harness.task_id)

    harness.restart(
        ScriptedLLM([quality_json(), finish_json()]),
        ScriptedPipeline([successful_report(), successful_report()]),
    )
    result = harness.loop.resume(harness.task_id)

    assert result.status is TaskStatus.SUCCEEDED
    assert result.changed_paths == ("src/calc.py",)


def test_deadline_after_model_response_wins_before_approval(loop_fixture) -> None:
    clock = FixedClock(NOW)

    class DeadlineAdvancingLLM(ScriptedLLM):
        def complete(self, messages: tuple[Message, ...]) -> str:
            response = super().complete(messages)
            clock.value = NOW + timedelta(seconds=1)
            return response

    harness = loop_fixture(
        llm=DeadlineAdvancingLLM([dependency_patch_json()]),
        deadline=NOW + timedelta(seconds=1),
        clock=clock,
    )

    result = harness.loop.run(harness.task_id)

    assert result.status is TaskStatus.BUDGET_EXHAUSTED
    assert harness.repository.pending_approval(harness.task_id) is None
    assert harness.dispatcher.actions == []


def test_two_independent_loops_cannot_enter_drive_for_same_task(loop_fixture) -> None:
    entered = Event()
    release = Event()

    class BlockingLLM(ScriptedLLM):
        def complete(self, messages: tuple[Message, ...]) -> str:
            entered.set()
            assert release.wait(timeout=5)
            return super().complete(messages)

    harness = loop_fixture(responses=[], reports=[])
    first_client = BlockingLLM([quality_json(), finish_json()])
    second_repo = SQLiteTaskRepository(harness.db_path)
    second_client = ScriptedLLM([finish_json()])
    second_loop = AgentLoop(
        repository=second_repo,
        policy=PolicyEngine(harness.repo_root),
        dispatcher=RecordingDispatcher(),
        pipeline=ScriptedPipeline([successful_report(), successful_report()]),
        parser=ActionParser(),
        llm=second_client,
        context_builder=ContextBuilder(),
        progress_tracker=ProgressTracker(),
        clock=FixedClock(),
        audit_sink=RecordingAuditSink(),
    )
    first_result = []

    def run_first() -> None:
        first_loop = AgentLoop(
            repository=SQLiteTaskRepository(harness.db_path),
            policy=PolicyEngine(harness.repo_root),
            dispatcher=RecordingDispatcher(),
            pipeline=ScriptedPipeline([successful_report(), successful_report()]),
            parser=ActionParser(),
            llm=first_client,
            context_builder=ContextBuilder(),
            progress_tracker=ProgressTracker(),
            clock=FixedClock(),
            audit_sink=RecordingAuditSink(),
        )
        first_result.append(first_loop.run(harness.task_id))

    thread = Thread(
        target=run_first,
        daemon=True,
    )
    thread.start()
    assert entered.wait(timeout=5)

    competing = second_loop.resume(harness.task_id)
    release.set()
    thread.join(timeout=5)

    assert competing.status is TaskStatus.BLOCKED
    assert second_client.calls == []
    assert first_result[0].status is TaskStatus.SUCCEEDED


@pytest.mark.parametrize(
    ("component", "response"),
    [
        ("context", finish_json()),
        ("policy", finish_json()),
        ("dispatcher", action_json("read_file", {"path": "src/calc.py"})),
        ("pipeline", finish_json()),
        ("progress", finish_json()),
        ("audit", finish_json()),
    ],
)
def test_injected_internal_exception_fails_and_releases_lease(
    loop_fixture, monkeypatch, component: str, response: str
) -> None:
    harness = loop_fixture(responses=[response], reports=[successful_report()])

    def explode(*args, **kwargs):
        del args, kwargs
        raise RuntimeError(f"{component} failed")

    target, method = {
        "context": (harness.loop._context_builder, "build"),
        "policy": (harness.loop._policy, "evaluate"),
        "dispatcher": (harness.dispatcher, "dispatch"),
        "pipeline": (harness.pipeline, "run"),
        "progress": (harness.loop._progress_tracker, "decide"),
        "audit": (harness.audit, "emit"),
    }[component]
    monkeypatch.setattr(target, method, explode)

    result = harness.loop.run(harness.task_id)

    assert result.status is TaskStatus.FAILED
    next_task = harness.repository.create_task(
        str(harness.repo_root.resolve()), "next task", round_limit=2
    )
    assert harness.repository.set_status(
        next_task.id, TaskStatus.CREATED, TaskStatus.RUNNING
    ) is True
    assert harness.repository.acquire_project_lease(
        next_task.id, owner_token="next-owner"
    ) is True


def test_injected_availability_exception_blocks_and_releases_lease(
    loop_fixture, monkeypatch
) -> None:
    harness = loop_fixture(responses=[finish_json()])
    monkeypatch.setattr(
        harness.loop._context_builder,
        "build",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("unavailable")),
    )

    result = harness.loop.run(harness.task_id)

    assert result.status is TaskStatus.BLOCKED


def test_audit_failure_after_atomic_wait_returns_saved_waiting_state(
    loop_fixture, monkeypatch
) -> None:
    harness = loop_fixture(responses=[dependency_patch_json()])
    original_emit = harness.audit.emit

    def fail_requested(event):
        if event.event_type == "approval_requested":
            raise RuntimeError("audit unavailable after wait")
        original_emit(event)

    monkeypatch.setattr(harness.audit, "emit", fail_requested)

    result = harness.loop.run(harness.task_id)

    assert result.status is TaskStatus.WAITING_APPROVAL
    assert harness.loop.pending_approval(harness.task_id) is not None


def test_audit_failure_after_atomic_approval_decision_does_not_escape(
    loop_fixture, monkeypatch
) -> None:
    harness = loop_fixture(responses=[dependency_patch_json()])
    harness.loop.run(harness.task_id)
    approval = harness.loop.pending_approval(harness.task_id)
    monkeypatch.setattr(
        harness.audit,
        "emit",
        lambda event: (_ for _ in ()).throw(RuntimeError(event.event_type)),
    )

    harness.loop.decide_approval(approval.id, ApprovalDecision.REJECT)

    snapshot = harness.repository.resume_snapshot(harness.task_id)
    assert snapshot.task.status is TaskStatus.RUNNING
    assert snapshot.decided_approval.decision is ApprovalDecision.REJECT


@pytest.mark.parametrize(
    "corruption",
    [
        "UPDATE tasks SET deadline = 'not-a-datetime' WHERE id = ?",
        "UPDATE tasks SET status = 'not-a-state' WHERE id = ?",
    ],
)
def test_corrupt_persisted_task_state_maps_durably_to_failed(
    loop_fixture, corruption: str
) -> None:
    harness = loop_fixture(responses=[])
    harness.repository._connection.execute(
        corruption, (harness.task_id,)
    )

    result = harness.loop.resume(harness.task_id)

    assert result.status is TaskStatus.FAILED
    assert harness.repository.resume_snapshot(harness.task_id).task.status is TaskStatus.FAILED


@pytest.mark.parametrize(
    "corruption",
    [
        "UPDATE approvals SET execution_state = 'not-a-state' WHERE id = ?",
        "UPDATE approvals SET policy_decision_json = '{' WHERE id = ?",
        "UPDATE approvals SET decided_at = 'not-a-datetime' WHERE id = ?",
        "UPDATE approvals SET expected_after_digests_json = '{' WHERE id = ?",
    ],
)
def test_corrupt_persisted_approval_maps_durably_to_failed(
    loop_fixture, corruption: str
) -> None:
    harness = loop_fixture(responses=[dependency_patch_json()])
    harness.loop.run(harness.task_id)
    approval = harness.loop.pending_approval(harness.task_id)
    harness.loop.decide_approval(approval.id, ApprovalDecision.APPROVE)
    harness.repository._connection.execute(
        corruption, (approval.id,)
    )

    result = harness.loop.resume(harness.task_id)
    repeated = harness.loop.resume(harness.task_id)

    assert result.status is TaskStatus.FAILED
    assert repeated == result
