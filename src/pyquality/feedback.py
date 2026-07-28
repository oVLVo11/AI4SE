"""Deterministic, bounded quality feedback and stopping decisions."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Sequence
from datetime import datetime
from pathlib import PurePosixPath
from typing import Any, Literal

from pydantic import Field, model_validator

from .domain.models import (
    MAX_CONFIG_PATTERN_BYTES,
    MAX_FINDING_EVIDENCE_BYTES,
    MAX_FINDING_SUMMARY_BYTES,
    MAX_GROUP_KEY_BYTES,
    Finding,
    PublicModel,
    QualityReport,
    TaskStatus,
)

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
_DRIVE_TEMP_PATH = re.compile(
    r"(?i)[a-z]:/(?:[^\s:/]+/)*(?:temp|tmp)/[^\s:]+"
)
_TIMING = re.compile(r"(?i)\b\d+(?:\.\d+)?\s*(?:ms|s|sec|secs|seconds)\b")


class FeedbackFinding(PublicModel):
    """One grouped root cause selected for model feedback."""

    category: Literal[
        "syntax",
        "import_collection",
        "assertion",
        "runtime",
        "ruff",
        "timeout",
        "missing_tool_dependency",
        "infrastructure",
    ]
    path: str | None = None
    line: int | None = Field(default=None, ge=1)
    summary: str = Field(min_length=1)
    evidence: str = Field(min_length=1)
    group_key: str = Field(min_length=1)
    occurrences: int = Field(ge=1)

    @model_validator(mode="after")
    def validate_finding(self) -> FeedbackFinding:
        if self.path is None and self.line is not None:
            raise ValueError("line requires path")
        if self.path is not None:
            normalized = PurePosixPath(self.path)
            if (
                not self.path
                or "\\" in self.path
                or normalized.is_absolute()
                or ".." in normalized.parts
            ):
                raise ValueError("path must be repository-relative POSIX text")
            _require_bytes(self.path, MAX_CONFIG_PATTERN_BYTES, "path")
        _require_bytes(self.summary, MAX_FINDING_SUMMARY_BYTES, "summary")
        _require_bytes(self.evidence, MAX_FINDING_EVIDENCE_BYTES, "evidence")
        _require_bytes(self.group_key, MAX_GROUP_KEY_BYTES, "group_key")
        return self


class FeedbackPacket(PublicModel):
    """Rendered feedback plus explicit accounting metadata."""

    findings: tuple[FeedbackFinding, ...]
    omitted_count: int = Field(ge=0)
    truncated: bool
    byte_budget: int = Field(ge=1)
    text: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_packet(self) -> FeedbackPacket:
        if len(self.text.encode("utf-8")) > self.byte_budget:
            raise ValueError("text exceeds byte budget")
        if self.omitted_count and not self.truncated:
            raise ValueError("omitted findings require truncated=true")
        return self


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
        render_truncated = len(raw_text.encode("utf-8")) > total_bytes
        text = (
            "~"
            if not selected and render_truncated
            else _truncate_utf8(raw_text, total_bytes)
        )
        truncated = omitted_count > 0 or item_truncated or render_truncated
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


def _finding_key(
    finding: Finding,
) -> tuple[int, str, int, str, str, str, str, str, str]:
    return (
        _PRIORITY[finding.category],
        _normalized_relative_path(finding.path) or "",
        finding.line or 0,
        finding.summary.casefold(),
        finding.group_key,
        finding.summary,
        finding.evidence,
        finding.category,
        finding.source,
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
    text = _DRIVE_TEMP_PATH.sub("<temp>", text)
    text = _TIMING.sub("<time>", text)
    return text


def _require_bytes(value: str, limit: int, field: str) -> None:
    if len(value.encode("utf-8")) > limit:
        raise ValueError(f"{field} exceeds {limit} UTF-8 bytes")
