from __future__ import annotations

from datetime import UTC, datetime

import pytest

from pyquality.context import ContextBuilder, ContextInput, SourceExcerpt
from pyquality.domain.models import Finding
from pyquality.feedback import FeedbackComposer
from pyquality.memory import MemoryContext
from pyquality.storage.sqlite import DecisionRecord, FindingRecord, IterationRecord


def _iteration(sequence: int) -> IterationRecord:
    return IterationRecord(
        id=f"iteration-{sequence}",
        task_id="task-1",
        sequence=sequence,
        context_digest="a" * 64,
        action_json='{"kind":"read_file","arguments":{"path":"src/money.py"}}',
        policy_outcome=None,
        tool_result_digest=None,
        fingerprint=None,
        relevant_digest=None,
        created_at=datetime(2026, 7, 28, tzinfo=UTC),
    )


def context_fixture() -> ContextInput:
    finding = Finding(
        source="pytest",
        category="assertion",
        severity="error",
        path="src/money.py",
        line=8,
        summary="decimal rounding is incorrect",
        evidence="assert Decimal('1.005') == Decimal('1.01')",
        group_key="assert:money",
    )
    packet = FeedbackComposer().compose((finding,), total_bytes=1_000, per_item_bytes=500)
    memory = MemoryContext(
        iterations=tuple(_iteration(sequence) for sequence in range(1, 6)),
        findings=(
            FindingRecord(
                id="finding-1",
                iteration_id="iteration-5",
                finding=finding,
                created_at=datetime(2026, 7, 28, tzinfo=UTC),
                resolved_at=None,
            ),
        ),
        decisions=(
            DecisionRecord(
                id="decision-1",
                project_id="project-1",
                scope_type="path",
                scope_value="src/money.py",
                content="Use Decimal quantize for currency.",
                source="operator",
                created_at=datetime(2026, 7, 28, tzinfo=UTC),
                updated_at=datetime(2026, 7, 28, tzinfo=UTC),
            ),
            DecisionRecord(
                id="decision-2",
                project_id="project-1",
                scope_type="path",
                scope_value="README.md",
                content="README-only decision",
                source="operator",
                created_at=datetime(2026, 7, 28, tzinfo=UTC),
                updated_at=datetime(2026, 7, 28, tzinfo=UTC),
            ),
        ),
    )
    return ContextInput(
        task="fix decimal rounding",
        memory=memory,
        feedback=packet,
        sources=(SourceExcerpt(path="src/money.py", content="def money():\n    return 'x'\n"),),
    )


def test_context_contains_task_two_iterations_feedback_and_relevant_excerpt() -> None:
    messages = ContextBuilder(source_bytes=1_000, total_bytes=4_000).build(context_fixture())
    joined = "\n".join(message.content for message in messages)

    assert "fix decimal rounding" in joined
    assert "iteration 3" not in joined
    assert "iteration 4" in joined and "iteration 5" in joined
    assert "src/money.py" in joined
    assert "README-only decision" not in joined
    assert "decimal rounding is incorrect" in joined


def test_context_truncates_utf8_source_with_visible_marker() -> None:
    fixture = context_fixture().model_copy(
        update={"sources": (SourceExcerpt(path="src/money.py", content="😀" * 10),)}
    )

    messages = ContextBuilder(source_bytes=10, total_bytes=1_000).build(fixture)

    assert "[source truncated]" in "\n".join(message.content for message in messages)
    assert all(len(message.content.encode("utf-8")) <= 1_000 for message in messages)


@pytest.mark.parametrize("total_bytes", (1, 10))
def test_context_replaces_an_impossible_schema_with_a_visible_marker(total_bytes: int) -> None:
    messages = ContextBuilder(source_bytes=10, total_bytes=total_bytes).build(context_fixture())

    assert [(message.role, message.content) for message in messages] == [("system", "~")]
    assert sum(len(message.content.encode("utf-8")) for message in messages) <= total_bytes


def test_context_marks_aggregate_multibyte_truncation_within_the_total_budget() -> None:
    fixture = context_fixture().model_copy(update={"task": "修" * 200})

    messages = ContextBuilder(source_bytes=1_000, total_bytes=300).build(fixture)
    combined_bytes = sum(len(message.content.encode("utf-8")) for message in messages)

    assert messages[0].content.endswith("Arbitrary shell commands are not an allowed action.")
    assert messages[-1].content.endswith("[context truncated]")
    assert combined_bytes <= 300


def test_context_uses_only_the_marker_when_that_exactly_fills_remaining_budget() -> None:
    messages = ContextBuilder(source_bytes=1_000, total_bytes=253).build(context_fixture())

    assert messages[-1].content == "[context truncated]"
    assert sum(len(message.content.encode("utf-8")) for message in messages) == 253
