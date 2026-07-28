from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from pyquality.domain.models import Finding
from pyquality.memory import MemorySelector
from pyquality.storage.sqlite import FindingRecord, SQLiteTaskRepository


def _finding(severity: str, summary: str, path: str) -> Finding:
    return Finding(
        source="pytest",
        category="assertion",
        severity=severity,
        path=path,
        line=4,
        summary=summary,
        evidence="assert 2 + 2 == 5",
        group_key=f"assert:{path}",
    )


@pytest.fixture
def snapshot(tmp_path: Path):
    repo = SQLiteTaskRepository(tmp_path / "state.sqlite")
    task = repo.create_task("C:/work/demo", "fix math", round_limit=8)
    for sequence in range(1, 5):
        repo.append_iteration(
            task.id,
            sequence=sequence,
            context_digest=str(sequence) * 64,
            findings=(
                _finding("warning", "unresolved warning", "src/math.py"),
                _finding("error", "unresolved error", "src/math.py"),
            ),
        )
    repo.add_decision(
        task.project_id,
        scope_type="path",
        scope_value="src/math.py",
        content="Use Decimal in src/math.py",
        source="operator",
    )
    repo.add_decision(
        task.project_id,
        scope_type="path",
        scope_value="README.md",
        content="unrelated README wording",
        source="operator",
    )
    return repo.resume_snapshot(task.id)


def test_memory_selects_two_recent_iterations_and_matching_decisions(snapshot) -> None:
    """Including stale rounds or unrelated decisions would distract the next model response."""
    context = MemorySelector().select(snapshot, {"src/math.py"}, max_iterations=2)

    assert [item.sequence for item in context.iterations] == [3, 4]
    assert [decision.content for decision in context.decisions] == ["Use Decimal in src/math.py"]
    assert "unrelated README wording" not in context.model_dump_json()


def test_memory_places_errors_before_warnings(snapshot) -> None:
    """Sending warnings ahead of errors would hide the highest-priority unresolved feedback."""
    context = MemorySelector().select(snapshot, {"src/math.py"})

    assert [record.finding.severity for record in context.findings] == [
        "error",
        "error",
        "error",
        "error",
        "warning",
        "warning",
        "warning",
        "warning",
    ]


def test_memory_excludes_resolved_findings_and_orders_ties_by_creation_and_id(snapshot) -> None:
    """Resolved feedback or arbitrary tie order would make prompt context non-deterministic."""
    created_at = datetime(2026, 7, 28, tzinfo=UTC)
    original = snapshot.findings[0]
    later_id = FindingRecord(
        id="z-finding",
        iteration_id=original.iteration_id,
        finding=_finding("error", "later id", "src/math.py"),
        created_at=created_at,
        resolved_at=None,
    )
    resolved = FindingRecord(
        id="resolved-finding",
        iteration_id=original.iteration_id,
        finding=_finding("error", "resolved", "src/math.py"),
        created_at=created_at,
        resolved_at=created_at,
    )
    earlier_id = FindingRecord(
        id="a-finding",
        iteration_id=original.iteration_id,
        finding=_finding("error", "earlier id", "src/math.py"),
        created_at=created_at,
        resolved_at=None,
    )
    amended = snapshot.model_copy(update={"findings": (later_id, resolved, earlier_id)})

    context = MemorySelector().select(amended, {"src/math.py"})

    assert [record.id for record in context.findings] == ["a-finding", "z-finding"]
