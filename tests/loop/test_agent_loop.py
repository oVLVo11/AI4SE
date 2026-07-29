from __future__ import annotations

import json
from datetime import timedelta

import httpx
import pytest
from conftest import (
    NOW,
    FixedClock,
    action_json,
    dependency_patch_json,
    failed_report,
    finish_json,
    ordinary_patch_json,
    quality_json,
    successful_report,
)

from pyquality.context import ContextBuilder
from pyquality.domain.models import ApprovalDecision, TaskStatus, ToolResult
from pyquality.feedback import FeedbackPacket
from pyquality.llm import Message, OpenAICompatibleLLM, ScriptedLLM


def test_passing_patch_requires_finish_and_exposes_green_context(loop_fixture) -> None:
    """Implicit success after a patch would skip the model's explicit completion decision."""
    client = ScriptedLLM([ordinary_patch_json("1"), finish_json()])
    harness = loop_fixture(
        llm=client,
        reports=[successful_report(), successful_report()],
    )

    result = harness.loop.run(harness.task_id)

    assert result.status is TaskStatus.SUCCEEDED
    assert len(client.calls) == 2
    assert "quality is green" in client.calls[1][-1].content.casefold()
    assert "finish" in client.calls[1][-1].content.casefold()
    assert "src/calc.py" in client.calls[1][-1].content
    assert "remaining rounds: 7" in client.calls[1][-1].content.casefold()
    snapshot = harness.repository.resume_snapshot(harness.task_id)
    assert [json.loads(item.action_json)["kind"] for item in snapshot.iterations] == [
        "apply_patch",
        "finish",
    ]


def test_finish_without_green_candidate_cannot_succeed(loop_fixture) -> None:
    """Accepting an unsupported finish would bypass action-triggered verification evidence."""
    harness = loop_fixture(responses=[finish_json()], round_limit=1)

    result = harness.loop.run(harness.task_id)

    assert result.status is TaskStatus.BUDGET_EXHAUSTED
    assert harness.pipeline.calls == []


def test_failing_final_verification_cannot_consume_green_candidate(loop_fixture) -> None:
    """Trusting the earlier candidate would hide a failure at the final verification boundary."""
    harness = loop_fixture(
        responses=[ordinary_patch_json("1"), finish_json()],
        reports=[successful_report(), failed_report()],
        round_limit=2,
    )

    result = harness.loop.run(harness.task_id)

    assert result.status is TaskStatus.BUDGET_EXHAUSTED
    assert len(harness.pipeline.calls) == 2
    assert harness.repository.green_candidate(harness.task_id) is None


def test_repository_drift_rejects_stale_finish_until_quality_runs_again(
    loop_fixture,
) -> None:
    """Digest-free finish acceptance would certify repository bytes never verified green."""
    responses = [
        ordinary_patch_json("1"),
        finish_json(),
        action_json("run_quality", rationale="verify drifted state"),
        finish_json(),
    ]

    class DriftingLLM(ScriptedLLM):
        def complete(self, messages):
            if len(self.calls) == 1:
                (harness.repo_root / "drift.txt").write_text("drift\n", encoding="utf-8")
            return super().complete(messages)

    client = DriftingLLM(responses)
    harness = loop_fixture(
        llm=client,
        reports=[successful_report(), successful_report(), successful_report()],
    )

    result = harness.loop.run(harness.task_id)

    assert result.status is TaskStatus.SUCCEEDED
    assert len(harness.pipeline.calls) == 3
    assert [
        json.loads(item.action_json)["kind"]
        for item in harness.repository.resume_snapshot(harness.task_id).iterations
    ] == ["apply_patch", "finish", "run_quality", "finish"]


def test_stale_finish_rejection_crash_keeps_candidate_and_iteration_atomic(
    loop_fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A crash persisting stale-finish feedback cannot split candidate cleanup from its round."""
    class PersistCrash(BaseException):
        pass

    class DriftingLLM(ScriptedLLM):
        def complete(self, messages):
            if len(self.calls) == 1:
                (harness.repo_root / "drift.txt").write_text("drift\n", encoding="utf-8")
                monkeypatch.setattr(
                    harness.repository,
                    "append_iteration",
                    lambda *args, **kwargs: (_ for _ in ()).throw(PersistCrash()),
                )
            return super().complete(messages)

    harness = loop_fixture(
        llm=DriftingLLM([ordinary_patch_json("1"), finish_json()]),
        reports=[successful_report()],
    )
    with pytest.raises(PersistCrash):
        harness.loop.run(harness.task_id)

    assert len(harness.repository.resume_snapshot(harness.task_id).iterations) == 1
    assert harness.repository.green_candidate(harness.task_id) is not None


def test_green_candidate_survives_crash_and_resume_consumes_finish(loop_fixture) -> None:
    """Keeping the candidate only in loop memory would strand a verified task after restart."""

    class PlannedCrash(BaseException):
        pass

    class CrashAfterGreen(ScriptedLLM):
        def complete(self, messages):
            if self.calls:
                raise PlannedCrash
            return super().complete(messages)

    harness = loop_fixture(
        llm=CrashAfterGreen([ordinary_patch_json("1")]),
        reports=[successful_report()],
    )
    with pytest.raises(PlannedCrash):
        harness.loop.run(harness.task_id)
    candidate = harness.repository.green_candidate(harness.task_id)
    assert candidate is not None

    resumed = ScriptedLLM([finish_json()])
    harness.restart(resumed, type(harness.pipeline)([successful_report()]))
    result = harness.loop.resume(harness.task_id)

    assert result.status is TaskStatus.SUCCEEDED
    assert "quality is green" in resumed.calls[0][-1].content.casefold()
    assert harness.repository.green_candidate(harness.task_id) is None


def test_green_context_is_byte_truncated_and_never_contains_absolute_path(
    loop_fixture,
) -> None:
    """Long candidate paths must stay bounded and may never expose the host repository path."""
    long_relative = "src/" + "nested/" * 80 + "calc.py"
    report = successful_report().model_copy(update={"changed_paths": (long_relative,)})
    client = ScriptedLLM([quality_json(), finish_json()])
    harness = loop_fixture(llm=client, reports=[report, successful_report()])
    harness.loop._context_builder = ContextBuilder(source_bytes=64, total_bytes=360)

    assert harness.loop.run(harness.task_id).status is TaskStatus.SUCCEEDED

    green_prompt = client.calls[1][-1].content
    assert len(green_prompt.encode("utf-8")) <= 360
    assert "[context truncated]" in green_prompt
    assert str(harness.repo_root) not in green_prompt


def test_green_and_finish_audit_events_are_bounded_and_path_free(loop_fixture) -> None:
    """Candidate telemetry must not expose repository paths or raw verifier output."""
    harness = loop_fixture(
        responses=[ordinary_patch_json("1"), finish_json()],
        reports=[successful_report(), successful_report()],
    )

    assert harness.loop.run(harness.task_id).status is TaskStatus.SUCCEEDED

    events = [
        event
        for event in harness.audit.events
        if event.event_type in {"quality_candidate_ready", "finish_verification"}
    ]
    assert [event.event_type for event in events] == [
        "quality_candidate_ready",
        "finish_verification",
    ]
    encoded = "".join(event.model_dump_json() for event in events)
    assert str(harness.repo_root) not in encoded
    assert "assert 0 == 1" not in encoded
    lifecycle_before_resume = [
        event.event_type
        for event in harness.audit.events
        if event.event_type
        in {"quality_candidate_ready", "finish_verification", "task_terminal"}
    ]
    assert lifecycle_before_resume == [
        "quality_candidate_ready",
        "finish_verification",
        "task_terminal",
    ]
    harness.loop.resume(harness.task_id)
    assert [
        event.event_type
        for event in harness.audit.events
        if event.event_type
        in {"quality_candidate_ready", "finish_verification", "task_terminal"}
    ] == lifecycle_before_resume


def test_later_failed_quality_clears_green_candidate_before_finish(loop_fixture) -> None:
    """A failed report after green must make the earlier candidate unconsumable."""
    harness = loop_fixture(
        responses=[quality_json(), quality_json(), finish_json()],
        reports=[successful_report(), failed_report()],
        round_limit=3,
    )

    result = harness.loop.run(harness.task_id)

    assert result.status is not TaskStatus.SUCCEEDED
    assert harness.repository.green_candidate(harness.task_id) is None
    assert len(harness.pipeline.calls) == 2


def test_finish_rechecks_deadline_after_final_verifier(loop_fixture) -> None:
    """A verifier crossing the deadline must not publish success from a late report."""
    clock = FixedClock(NOW)

    class AdvancingPipeline:
        def __init__(self) -> None:
            self.calls = []

        def run(self, changed_paths):
            self.calls.append(changed_paths)
            if len(self.calls) == 2:
                clock.value = NOW + timedelta(seconds=2)
            return successful_report()

    harness = loop_fixture(
        responses=[quality_json(), finish_json()],
        reports=[],
        clock=clock,
        deadline=NOW + timedelta(seconds=1),
    )
    harness.pipeline = AdvancingPipeline()
    harness.loop._pipeline = harness.pipeline

    result = harness.loop.run(harness.task_id)

    assert result.status is TaskStatus.BUDGET_EXHAUSTED


def test_late_finish_terminal_crash_rolls_back_report_candidate_and_status(
    loop_fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Late verifier evidence, candidate cleanup, and budget terminalization are one commit."""
    clock = FixedClock(NOW)

    class AdvancingPipeline:
        def __init__(self) -> None:
            self.calls = []

        def run(self, changed_paths):
            self.calls.append(changed_paths)
            if len(self.calls) == 2:
                clock.value = NOW + timedelta(seconds=2)
            return successful_report()

    harness = loop_fixture(
        responses=[quality_json(), finish_json()], reports=[], clock=clock,
        deadline=NOW + timedelta(seconds=1),
    )
    harness.pipeline = AdvancingPipeline()
    harness.loop._pipeline = harness.pipeline
    monkeypatch.setattr(
        harness.repository,
        "_release_or_transfer_project_reservation",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("terminal crash")),
    )

    with pytest.raises(RuntimeError, match="terminal crash"):
        harness.loop.run(harness.task_id)

    snapshot = harness.repository.resume_snapshot(harness.task_id)
    assert snapshot.task.status is TaskStatus.RUNNING
    assert len(snapshot.iterations) == 1
    assert harness.repository.green_candidate(harness.task_id) is not None


def test_recovered_finish_verifier_is_rejected_after_repository_drift(
    loop_fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A recovered passing verifier intent must be bound to the verified repository bytes."""
    class CrashAfterVerifier(BaseException):
        pass

    harness = loop_fixture(
        responses=[quality_json(), finish_json()],
        reports=[successful_report(), successful_report()],
    )
    completed = harness.repository.complete_transition_intent
    verifier_completions = 0

    def crash_second_verifier(intent_id, **kwargs):
        nonlocal verifier_completions
        record = completed(intent_id, **kwargs)
        if record.kind == "verifier":
            verifier_completions += 1
            if verifier_completions == 2:
                raise CrashAfterVerifier
        return record

    monkeypatch.setattr(
        harness.repository, "complete_transition_intent", crash_second_verifier
    )
    with pytest.raises(CrashAfterVerifier):
        harness.loop.run(harness.task_id)
    (harness.repo_root / "drift-after-verifier.txt").write_text(
        "drift\n", encoding="utf-8"
    )
    monkeypatch.setattr(
        harness.repository, "complete_transition_intent", completed
    )
    harness.restart(ScriptedLLM([quality_json(), finish_json()]), type(harness.pipeline)([
        successful_report(), successful_report()
    ]))

    result = harness.loop.resume(harness.task_id)

    assert result.status is TaskStatus.SUCCEEDED
    assert len(harness.pipeline.calls) == 2


def test_loop_adopts_service_lease_without_reacquiring(loop_fixture) -> None:
    harness = loop_fixture(
        responses=[quality_json(), finish_json()],
        reports=[successful_report(), successful_report()],
    )
    assert harness.repository.set_status(
        harness.task_id, TaskStatus.CREATED, TaskStatus.RUNNING
    )
    assert harness.repository.acquire_project_lease(
        harness.task_id, owner_token="service-owner"
    )

    result = harness.loop.run_leased(
        harness.task_id, "service-owner", resume=False
    )

    assert result.status is TaskStatus.SUCCEEDED
    assert harness.repository._held_leases == {}


def test_many_terminal_tasks_evict_per_task_transient_loop_state(loop_fixture) -> None:
    denied = action_json("read_file", {"path": ".env"}, "inspect secret")
    harness = loop_fixture(responses=[denied] * 24, round_limit=1)
    task_ids = [harness.task_id]
    for sequence in range(1, 24):
        task_ids.append(
            harness.repository.create_task(
                str(harness.repo_root.resolve()),
                f"terminal task {sequence}",
                round_limit=1,
            ).id
        )

    for task_id in task_ids:
        assert harness.loop.run(task_id).status is TaskStatus.BUDGET_EXHAUSTED

    assert harness.loop._feedback == {}
    assert harness.loop._changed_paths == {}


def test_waiting_transients_survive_and_terminal_resume_evicts_them(
    loop_fixture,
) -> None:
    harness = loop_fixture(
        responses=[dependency_patch_json(), quality_json(), finish_json()],
        reports=[successful_report(), successful_report(), successful_report()],
    )
    feedback = FeedbackPacket(
        findings=(),
        omitted_count=0,
        truncated=False,
        byte_budget=64,
        text="preserve across approval",
    )
    harness.loop._feedback[harness.task_id] = feedback
    harness.loop._changed_paths[harness.task_id] = {"src/preserved.py"}

    waiting = harness.loop.run(harness.task_id)

    assert waiting.status is TaskStatus.WAITING_APPROVAL
    assert harness.loop._feedback[harness.task_id] == feedback
    assert harness.loop._changed_paths[harness.task_id] == {"src/preserved.py"}
    approval = harness.loop.pending_approval(harness.task_id)
    harness.loop.decide_approval(approval.id, ApprovalDecision.APPROVE)

    completed = harness.loop.resume(harness.task_id)

    assert completed.status is TaskStatus.SUCCEEDED
    assert "src/preserved.py" in completed.changed_paths
    assert harness.task_id not in harness.loop._feedback
    assert harness.task_id not in harness.loop._changed_paths


def test_running_recovery_retains_transient_loop_state(loop_fixture) -> None:
    class SimulatedCrash(BaseException):
        pass

    class CrashingLLM:
        def complete(self, messages: tuple[Message, ...]) -> str:
            del messages
            raise SimulatedCrash

    harness = loop_fixture(llm=CrashingLLM())
    feedback = FeedbackPacket(
        findings=(),
        omitted_count=0,
        truncated=False,
        byte_budget=64,
        text="preserve for recovery",
    )
    harness.loop._feedback[harness.task_id] = feedback
    harness.loop._changed_paths[harness.task_id] = {"src/recovery.py"}

    with pytest.raises(SimulatedCrash):
        harness.loop.run(harness.task_id)

    assert harness.repository.resume_snapshot(harness.task_id).task.status is TaskStatus.RUNNING
    assert harness.loop._feedback[harness.task_id] == feedback
    assert harness.loop._changed_paths[harness.task_id] == {"src/recovery.py"}


def test_failed_patch_feedback_changes_next_action(loop_fixture) -> None:
    bad_patch = ordinary_patch_json("1")
    corrected_patch = ordinary_patch_json("2")
    harness = loop_fixture(
        responses=[bad_patch, corrected_patch, finish_json()],
        reports=[failed_report(), successful_report(), successful_report()],
    )

    result = harness.loop.run(harness.task_id)

    assert result.status is TaskStatus.SUCCEEDED
    assert "assertion" in harness.llm.calls[1][-1].content
    assert bad_patch != corrected_patch
    assert result.iterations == 3
    assert len(harness.pipeline.calls) == 3


def test_invalid_output_allows_exactly_two_schema_only_repair_responses(loop_fixture) -> None:
    harness = loop_fixture(responses=["not json", "[]", '{"kind":"unknown"}'])

    result = harness.loop.run(harness.task_id)

    assert result.status is TaskStatus.FAILED
    assert result.iterations == 3
    assert len(harness.llm.calls) == 3
    assert "schema" in harness.llm.calls[1][-1].content.casefold()
    assert "not json" not in harness.llm.calls[1][-1].content


def test_unrecoverable_model_client_consistency_error_maps_to_failed(loop_fixture) -> None:
    harness = loop_fixture(responses=[])

    result = harness.loop.run(harness.task_id)

    assert result.status is TaskStatus.FAILED
    assert result.iterations == 0


def test_legacy_running_lease_returns_actionable_blocked_result(loop_fixture) -> None:
    harness = loop_fixture(responses=[])
    task = harness.repository.resume_snapshot(harness.task_id).task
    harness.repository._connection.execute(
        """INSERT INTO project_leases
           (project_id, task_id, owner_token, acquired_at, protocol)
           VALUES (?, ?, NULL, ?, NULL)""",
        (task.project_id, task.id, "2026-07-29T00:00:00+00:00"),
    )

    result = harness.loop.run(harness.task_id)

    assert result.status is TaskStatus.BLOCKED
    assert "manual recovery" in result.verification_summary
    assert harness.repository.resume_snapshot(harness.task_id).task.status is TaskStatus.RUNNING


def test_round_limit_stops_before_another_model_call(loop_fixture) -> None:
    denied = action_json("read_file", {"path": ".env"}, "inspect credential")
    harness = loop_fixture(responses=[denied, finish_json()], round_limit=1)

    result = harness.loop.run(harness.task_id)

    assert result.status is TaskStatus.BUDGET_EXHAUSTED
    assert result.iterations == 1
    assert len(harness.llm.calls) == 1
    assert harness.dispatcher.actions == []


def test_repeated_denial_stalls_without_dispatch(loop_fixture) -> None:
    denied = action_json("read_file", {"path": ".env"}, "inspect credential")
    harness = loop_fixture(responses=[denied, denied, finish_json()])

    result = harness.loop.run(harness.task_id)

    assert result.status is TaskStatus.STALLED
    assert result.iterations == 2
    assert len(harness.llm.calls) == 2
    assert harness.dispatcher.actions == []


def test_expired_deadline_stops_before_first_model_call(loop_fixture) -> None:
    harness = loop_fixture(
        responses=[finish_json()],
        deadline=NOW - timedelta(seconds=1),
    )

    result = harness.loop.run(harness.task_id)

    assert result.status is TaskStatus.BUDGET_EXHAUSTED
    assert result.iterations == 0
    assert harness.llm.calls == []


def test_failed_finish_returns_feedback_and_verifies_again(loop_fixture) -> None:
    harness = loop_fixture(
        responses=[quality_json(), quality_json(), finish_json()],
        reports=[failed_report(), successful_report(), successful_report()],
    )

    result = harness.loop.run(harness.task_id)

    assert result.status is TaskStatus.SUCCEEDED
    assert result.iterations == 3
    assert "assertion" in harness.llm.calls[1][-1].content


def test_terminal_resume_is_idempotent_and_never_calls_model(loop_fixture) -> None:
    harness = loop_fixture(responses=[finish_json()], reports=[successful_report()])
    first = harness.loop.run(harness.task_id)
    calls = len(harness.llm.calls)

    second = harness.loop.resume(harness.task_id)

    assert second == first
    assert len(harness.llm.calls) == calls


def test_resume_recovers_persisted_passing_verifier_transition_before_finish(
    loop_fixture,
) -> None:
    class CrashAfterGreen(BaseException):
        pass

    class CrashingClient(ScriptedLLM):
        def complete(self, messages):
            if self.calls:
                raise CrashAfterGreen
            return super().complete(messages)

    harness = loop_fixture(
        llm=CrashingClient([quality_json()]), reports=[successful_report()]
    )
    with pytest.raises(CrashAfterGreen):
        harness.loop.run(harness.task_id)
    harness.restart(ScriptedLLM([finish_json()]), type(harness.pipeline)([successful_report()]))

    result = harness.loop.resume(harness.task_id)

    assert result.status is TaskStatus.SUCCEEDED
    assert result.iterations == 2
    assert len(harness.llm.calls) == 1


def test_audit_metadata_contains_digests_not_full_model_content(loop_fixture) -> None:
    unique_response = finish_json().replace("completion", "secret-shaped-response")
    harness = loop_fixture(responses=[unique_response], reports=[successful_report()])

    harness.loop.run(harness.task_id)

    serialized = " ".join(str(event.model_dump(mode="json")) for event in harness.audit.events)
    assert "secret-shaped-response" not in serialized
    assert any(event.event_type == "model_call_completed" for event in harness.audit.events)


def test_repeated_failure_without_relevant_change_stalls(loop_fixture) -> None:
    repeated = ordinary_patch_json("1")
    harness = loop_fixture(
        responses=[repeated, repeated, finish_json()],
        reports=[failed_report(), failed_report()],
    )

    result = harness.loop.run(harness.task_id)

    assert result.status is TaskStatus.STALLED
    assert result.iterations == 2
    assert len(harness.llm.calls) == 2


def test_missing_verifier_blocks_after_persisting_the_model_round(loop_fixture) -> None:
    harness = loop_fixture(
        responses=[quality_json()],
        reports=[FileNotFoundError("pytest missing")],
    )

    result = harness.loop.run(harness.task_id)

    assert result.status is TaskStatus.BLOCKED
    assert result.iterations == 1


def test_deadline_after_response_wins_before_verifier_and_keeps_round_accounting(
    loop_fixture,
) -> None:
    clock = FixedClock(NOW)

    class DeadlineAdvancingLLM(ScriptedLLM):
        def complete(self, messages: tuple[Message, ...]) -> str:
            response = super().complete(messages)
            clock.value = NOW + timedelta(seconds=1)
            return response

    harness = loop_fixture(
        llm=DeadlineAdvancingLLM([finish_json()]),
        reports=[successful_report()],
        deadline=NOW + timedelta(seconds=1),
        clock=clock,
    )

    result = harness.loop.run(harness.task_id)

    assert result.status is TaskStatus.BUDGET_EXHAUSTED
    assert result.iterations == 1
    assert harness.pipeline.calls == []


def test_provider_internal_retries_remain_one_persisted_model_round(loop_fixture) -> None:
    attempts: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        attempts.append(request)
        if len(attempts) < 3:
            raise httpx.ConnectError("temporary failure", request=request)
        content = quality_json() if len(attempts) == 3 else finish_json()
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": content}}]},
        )

    client = OpenAICompatibleLLM(
        "https://provider.invalid/v1/chat/completions",
        "test-model",
        lambda: "test-key",
        retries=2,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    harness = loop_fixture(
        llm=client,
        reports=[successful_report(), successful_report()],
    )

    result = harness.loop.run(harness.task_id)

    assert result.status is TaskStatus.SUCCEEDED
    assert result.iterations == 2
    assert len(attempts) == 4


def test_deletion_changes_relevant_digest_and_avoids_false_stall(loop_fixture) -> None:
    changed = ToolResult(
        effect_kind="apply_patch",
        code_changed=True,
        changed_paths=("src/calc.py",),
        before_digests={"src/calc.py": "a" * 64},
        after_digests={"src/calc.py": "b" * 64},
        normalized_metadata={"code": "ok"},
    )
    deleted = ToolResult(
        effect_kind="apply_patch",
        code_changed=True,
        changed_paths=("src/calc.py",),
        before_digests={"src/calc.py": "b" * 64},
        after_digests={},
        normalized_metadata={"code": "ok"},
    )
    harness = loop_fixture(
        responses=[ordinary_patch_json("1"), ordinary_patch_json("2"), finish_json()],
        reports=[failed_report(), successful_report(), successful_report()],
        dispatch_results=[changed, deleted],
    )

    result = harness.loop.run(harness.task_id)

    assert result.status is TaskStatus.SUCCEEDED
    assert result.iterations == 3
