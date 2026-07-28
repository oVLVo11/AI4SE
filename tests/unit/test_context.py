from __future__ import annotations

from datetime import UTC, datetime

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
