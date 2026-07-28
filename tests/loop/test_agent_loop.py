from __future__ import annotations

from datetime import timedelta

import httpx
from conftest import (
    NOW,
    FixedClock,
    action_json,
    failed_report,
    finish_json,
    ordinary_patch_json,
    successful_report,
)

from pyquality.domain.models import TaskStatus, ToolResult
from pyquality.llm import Message, OpenAICompatibleLLM, ScriptedLLM


def test_failed_patch_feedback_changes_next_action(loop_fixture) -> None:
    bad_patch = ordinary_patch_json("1")
    corrected_patch = ordinary_patch_json("2")
    harness = loop_fixture(
        responses=[bad_patch, corrected_patch, finish_json()],
        reports=[failed_report(), failed_report(), successful_report()],
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
        responses=[finish_json(), finish_json()],
        reports=[failed_report(), successful_report()],
    )

    result = harness.loop.run(harness.task_id)

    assert result.status is TaskStatus.SUCCEEDED
    assert result.iterations == 2
    assert "assertion" in harness.llm.calls[1][-1].content


def test_terminal_resume_is_idempotent_and_never_calls_model(loop_fixture) -> None:
    harness = loop_fixture(responses=[finish_json()], reports=[successful_report()])
    first = harness.loop.run(harness.task_id)
    calls = len(harness.llm.calls)

    second = harness.loop.resume(harness.task_id)

    assert second == first
    assert len(harness.llm.calls) == calls


def test_resume_recovers_persisted_passing_verifier_transition_without_model_call(
    loop_fixture,
) -> None:
    harness = loop_fixture(responses=[])
    assert harness.repository.set_status(
        harness.task_id, TaskStatus.CREATED, TaskStatus.RUNNING
    ) is True
    assert harness.repository.acquire_project_lease(
        harness.task_id, owner_token="seed-owner"
    ) is True
    harness.repository.append_iteration(
        harness.task_id,
        sequence=1,
        context_digest="a" * 64,
        quality_outcome="passed",
    )
    harness.repository.release_project_lease(
        harness.task_id, owner_token="seed-owner"
    )

    result = harness.loop.resume(harness.task_id)

    assert result.status is TaskStatus.SUCCEEDED
    assert result.iterations == 1
    assert harness.llm.calls == []


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
        responses=[finish_json()],
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
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": finish_json()}}]},
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
        reports=[successful_report()],
    )

    result = harness.loop.run(harness.task_id)

    assert result.status is TaskStatus.SUCCEEDED
    assert result.iterations == 1
    assert len(attempts) == 3


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
        reports=[failed_report(), failed_report(), successful_report()],
        dispatch_results=[changed, deleted],
    )

    result = harness.loop.run(harness.task_id)

    assert result.status is TaskStatus.SUCCEEDED
    assert result.iterations == 3
