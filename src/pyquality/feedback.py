"""Deterministic, bounded quality feedback and stopping decisions."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Sequence
from datetime import datetime
from pathlib import PurePosixPath
from typing import Any

from pydantic import Field

from .domain.models import Finding, PublicModel, QualityReport, TaskStatus

_PRIORITY = {
    "infrastructure": 0,
    "timeout": 0,
    "missing_tool_dependency": 0,
    "syntax": 1,
    "import_collection": 1,
    "assertion": 2,
    "runtime": 2,
    "ruff": 3,
}
_ABSOLUTE_TEMP = re.compile(
    r"(?i)(?:[a-z]:)?[/\\](?:[^\s:/\\]+[/\\])*(?:temp|tmp)[/\\][^\s:]+"
)
_TIMING = re.compile(r"(?i)\b\d+(?:\.\d+)?\s*(?:ms|s|sec|secs|seconds)\b")


class FeedbackFinding(PublicModel):
    """One grouped root cause selected for model feedback."""

    category: str = Field(min_length=1)
    path: str | None = None
    line: int | None = Field(default=None, ge=1)
    summary: str = Field(min_length=1)
    evidence: str = Field(min_length=1)
    group_key: str = Field(min_length=1)
    occurrences: int = Field(ge=1)


class FeedbackPacket(PublicModel):
    """Rendered feedback plus explicit accounting metadata."""

    findings: tuple[FeedbackFinding, ...]
    omitted_count: int = Field(ge=0)
    truncated: bool
    byte_budget: int = Field(ge=1)
    text: str = Field(min_length=1)


class ProgressEntry(PublicModel):
    """The narrow quality-history value consumed by :class:`ProgressTracker`."""

    fingerprint: str | None = None
    relevant_digest: str | None = None
    report: QualityReport | None = None
    blocked: bool = False
    failed: bool = False
    all_digest: str | None = None


class FeedbackComposer:
    """Group root causes and render the highest-priority evidence within a byte cap."""

    def compose(
        self,
        findings: Iterable[Finding],
        total_bytes: int,
        per_item_bytes: int,
    ) -> FeedbackPacket:
        if total_bytes < 1 or per_item_bytes < 1:
            raise ValueError("feedback byte budgets must be positive")

        grouped: dict[str, list[Finding]] = {}
        for finding in findings:
            grouped.setdefault(finding.group_key, []).append(finding)
        ordered = sorted(
            grouped.values(),
            key=lambda group: _finding_key(min(group, key=_finding_key)),
        )

        candidates: list[FeedbackFinding] = []
        item_truncated = False
        for group in ordered:
            representative = min(group, key=_finding_key)
            compact_evidence = _truncate_utf8(representative.evidence, per_item_bytes)
            item_truncated = item_truncated or compact_evidence != representative.evidence
            candidates.append(
                FeedbackFinding(
                    category=representative.category,
                    path=_normalized_relative_path(representative.path),
                    line=representative.line,
                    summary=representative.summary,
                    evidence=compact_evidence,
                    group_key=representative.group_key,
                    occurrences=len(group),
                )
            )

        selected: list[FeedbackFinding] = []
        for candidate in candidates:
            proposed = (*selected, candidate)
            omitted = len(candidates) - len(proposed)
            if len(_render(proposed, omitted, total_bytes).encode("utf-8")) <= total_bytes:
                selected.append(candidate)
            else:
                break

        omitted_count = len(candidates) - len(selected)
        raw_text = _render(tuple(selected), omitted_count, total_bytes)
        text = (
            "~"
            if not selected and len(raw_text.encode("utf-8")) > total_bytes
            else _truncate_utf8(raw_text, total_bytes)
        )
        truncated = omitted_count > 0 or item_truncated
        return FeedbackPacket(
            findings=tuple(selected),
            omitted_count=omitted_count,
            truncated=truncated,
            byte_budget=total_bytes,
            text=text,
        )


def failure_fingerprint(findings: Iterable[Any]) -> str:
    """Hash stable normalized failure identity, excluding evidence and volatile values."""
    tuples = sorted(
        (
            str(finding.category),
            _fingerprint_text(getattr(finding, "path", None)),
            getattr(finding, "line", None),
            _fingerprint_text(getattr(finding, "group_key", "")),
        )
        for finding in findings
    )
    canonical = json.dumps(tuples, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class ProgressTracker:
    """Apply terminal-state rules in their specified precedence."""

    def decide(
        self,
        history: Sequence[ProgressEntry],
        round_limit: int,
        deadline: datetime | None,
        now: datetime,
    ) -> TaskStatus | None:
        if round_limit < 1:
            raise ValueError("round_limit must be positive")
        if deadline is not None and (deadline.tzinfo is None) != (now.tzinfo is None):
            raise ValueError("deadline and now must have matching timezone awareness")

        current = history[-1] if history else None
        if current is not None and current.report is not None and current.report.succeeded:
            return TaskStatus.SUCCEEDED
        if current is not None and current.blocked:
            return TaskStatus.BLOCKED
        if len(history) >= 2 and _same_relevant_failure(history[-2], history[-1]):
            return TaskStatus.STALLED
        if len(history) >= round_limit or deadline is not None and now >= deadline:
            return TaskStatus.BUDGET_EXHAUSTED
        if current is not None and current.failed:
            return TaskStatus.FAILED
        return None


def _same_relevant_failure(previous: ProgressEntry, current: ProgressEntry) -> bool:
    return (
        current.fingerprint is not None
        and current.fingerprint == previous.fingerprint
        and current.relevant_digest == previous.relevant_digest
    )


def _finding_key(finding: Finding) -> tuple[int, str, int, str, str]:
    return (
        _PRIORITY[finding.category],
        _normalized_relative_path(finding.path) or "",
        finding.line or 0,
        finding.summary.casefold(),
        finding.group_key,
    )


def _normalized_relative_path(path: str | None) -> str | None:
    if path is None:
        return None
    normalized = path.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return PurePosixPath(normalized).as_posix()


def _render(findings: Sequence[FeedbackFinding], omitted: int, budget: int) -> str:
    header = f"budget={budget};omitted={omitted}"
    lines = [
        "|".join(
            (
                finding.category,
                f"{finding.path or '-'}:{finding.line or 0}",
                str(finding.occurrences),
                finding.summary,
                finding.evidence,
            )
        )
        for finding in findings
    ]
    return "\n".join((header, *lines))


def _truncate_utf8(value: str, limit: int) -> str:
    encoded = value.encode("utf-8")
    if len(encoded) <= limit:
        return value or "~"
    truncated = encoded[:limit].decode("utf-8", errors="ignore").rstrip()
    return truncated or "~"


def _fingerprint_text(value: object) -> str:
    text = "" if value is None else str(value).replace("\\", "/")
    text = _ABSOLUTE_TEMP.sub("<temp>", text)
    text = _TIMING.sub("<time>", text)
    return text.casefold()
