"""Bounded, deterministic memory for the next model response."""

from __future__ import annotations

from pydantic import ConfigDict

from pyquality.domain.models import PublicModel
from pyquality.storage.sqlite import (
    DecisionRecord,
    FindingRecord,
    IterationRecord,
    RecoverySnapshot,
)


class MemoryContext(PublicModel):
    """Typed recovery context that intentionally excludes unbounded tool output."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    iterations: tuple[IterationRecord, ...]
    findings: tuple[FindingRecord, ...]
    decisions: tuple[DecisionRecord, ...]


class MemorySelector:
    """Chooses only recent work and decisions relevant to the current repository paths."""

    def select(
        self,
        snapshot: RecoverySnapshot,
        current_paths: set[str],
        max_iterations: int = 2,
    ) -> MemoryContext:
        recent = _recent_iterations(snapshot.iterations, max_iterations)
        findings = tuple(
            sorted(
                (finding for finding in snapshot.findings if finding.resolved_at is None),
                key=lambda finding: (
                    0 if finding.finding.severity == "error" else 1,
                    finding.created_at,
                    finding.id,
                ),
            )
        )
        validators = {finding.finding.source for finding in findings}
        decisions = tuple(
            decision
            for decision in sorted(snapshot.decisions, key=lambda item: (item.created_at, item.id))
            if _matches_scope(decision, current_paths, validators)
        )
        return MemoryContext(iterations=recent, findings=findings, decisions=decisions)


def _recent_iterations(
    iterations: tuple[IterationRecord, ...], max_iterations: int
) -> tuple[IterationRecord, ...]:
    if max_iterations <= 0:
        return ()
    ordered = sorted(iterations, key=lambda item: (item.sequence, item.created_at, item.id))
    return tuple(ordered[-max_iterations:])


def _matches_scope(
    decision: DecisionRecord, current_paths: set[str], validators: set[str]
) -> bool:
    if decision.scope_type == "path":
        prefix = decision.scope_value.rstrip("/")
        return any(path == prefix or path.startswith(f"{prefix}/") for path in current_paths)
    return decision.scope_type == "validator" and decision.scope_value in validators
