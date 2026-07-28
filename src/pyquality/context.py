"""Deterministic, byte-bounded context construction for one model response."""

from __future__ import annotations

import json
from pathlib import PurePosixPath

from pydantic import Field, model_validator

from pyquality.domain.models import PublicModel
from pyquality.feedback import FeedbackPacket
from pyquality.llm import Message
from pyquality.memory import MemoryContext

_TRUNCATION_MARKER = "[source truncated]"
_CONTEXT_TRUNCATION_MARKER = "[context truncated]"
_TINY_TRUNCATION_MARKER = "~"
_ACTION_SCHEMA = """# Allowed action schema
Return exactly one JSON object with `kind`, `arguments`, and `rationale`.
Allowed kinds: read_file, search_text, list_files, apply_patch, run_quality, finish.
Arbitrary shell commands are not an allowed action."""


class SourceExcerpt(PublicModel):
    """A caller-selected repository-relative source excerpt."""

    path: str = Field(min_length=1)
    content: str

    @model_validator(mode="after")
    def validate_path(self) -> SourceExcerpt:
        parsed = PurePosixPath(self.path)
        if "\\" in self.path or parsed.is_absolute() or ".." in parsed.parts:
            raise ValueError("path must be repository-relative POSIX text")
        return self


class ContextInput(PublicModel):
    """The bounded typed inputs eligible for the next model prompt."""

    task: str = Field(min_length=1)
    memory: MemoryContext
    feedback: FeedbackPacket | None = None
    sources: tuple[SourceExcerpt, ...] = ()


class ContextBuilder:
    """Render stable prompt sections without admitting terminal output or settings."""

    def __init__(self, source_bytes: int = 8 * 1024, total_bytes: int = 32 * 1024) -> None:
        if source_bytes < 1 or total_bytes < 1:
            raise ValueError("context byte budgets must be positive")
        self.source_bytes = source_bytes
        self.total_bytes = total_bytes

    def build(self, context: ContextInput) -> tuple[Message, ...]:
        """Build the schema and current-state messages for exactly one model call."""
        schema_bytes = len(_ACTION_SCHEMA.encode("utf-8"))
        if schema_bytes + 1 > self.total_bytes:
            marker = _visible_marker(_CONTEXT_TRUNCATION_MARKER, self.total_bytes)
            return (Message(role="system", content=marker),)

        system = Message(role="system", content=_ACTION_SCHEMA)
        remaining = self.total_bytes - schema_bytes
        user = _truncate_utf8_with_marker(
            self._render_user(context), remaining, _CONTEXT_TRUNCATION_MARKER
        )
        return (system, Message(role="user", content=user))

    def _render_user(self, context: ContextInput) -> str:
        source_paths = {source.path for source in context.sources}
        decisions = tuple(
            decision
            for decision in context.memory.decisions
            if _decision_matches(decision.scope_type, decision.scope_value, source_paths, context)
        )
        recent = sorted(context.memory.iterations, key=lambda item: (item.sequence, item.id))[-2:]
        sections = [
            "# Task\n" + context.task,
            "# Decisions\n" + _render_decisions(decisions),
            "# Recent actions\n" + _render_actions(recent),
            "# Relevant source\n" + _render_sources(context.sources, self.source_bytes),
            "# Structured feedback\n" + (context.feedback.text if context.feedback else "none"),
        ]
        return "\n\n".join(sections)


def _decision_matches(
    scope_type: str, scope_value: str, source_paths: set[str], context: ContextInput
) -> bool:
    if scope_type == "path":
        prefix = scope_value.rstrip("/")
        return any(path == prefix or path.startswith(f"{prefix}/") for path in source_paths)
    if scope_type == "validator":
        return any(record.finding.source == scope_value for record in context.memory.findings)
    return False


def _render_decisions(decisions: tuple[object, ...]) -> str:
    if not decisions:
        return "none"
    return "\n".join(f"- {decision.content}" for decision in decisions)


def _render_actions(iterations: list[object]) -> str:
    if not iterations:
        return "none"
    lines: list[str] = []
    for iteration in iterations:
        kind = _action_kind(iteration.action_json)
        lines.append(f"- iteration {iteration.sequence}: {kind}")
    return "\n".join(lines)


def _action_kind(action_json: str | None) -> str:
    if action_json is None:
        return "no action recorded"
    try:
        decoded = json.loads(action_json)
        kind = decoded.get("kind") if isinstance(decoded, dict) else None
    except json.JSONDecodeError:
        kind = None
    return kind if isinstance(kind, str) else "unavailable action"


def _render_sources(sources: tuple[SourceExcerpt, ...], source_bytes: int) -> str:
    if not sources:
        return "none"
    return "\n\n".join(_render_source(source, source_bytes) for source in sources)


def _render_source(source: SourceExcerpt, source_bytes: int) -> str:
    content = _truncate_utf8(source.content, source_bytes)
    if content == source.content:
        return f"## {source.path}\n{content}"
    return f"## {source.path}\n{content}\n{_TRUNCATION_MARKER}"


def _truncate_utf8(value: str, limit: int) -> str:
    encoded = value.encode("utf-8")
    if len(encoded) <= limit:
        return value
    truncated = encoded[:limit]
    while truncated:
        try:
            return truncated.decode("utf-8")
        except UnicodeDecodeError:
            truncated = truncated[:-1]
    return _TINY_TRUNCATION_MARKER


def _visible_marker(marker: str, limit: int) -> str:
    return marker if len(marker.encode("utf-8")) <= limit else _TINY_TRUNCATION_MARKER


def _truncate_utf8_with_marker(value: str, limit: int, marker: str) -> str:
    if len(value.encode("utf-8")) <= limit:
        return value
    visible_marker = _visible_marker(marker, limit)
    if visible_marker == _TINY_TRUNCATION_MARKER:
        return visible_marker
    marker_bytes = len(visible_marker.encode("utf-8"))
    prefix_limit = limit - marker_bytes - 1
    if prefix_limit < 1:
        return visible_marker
    prefix = _truncate_utf8(value, prefix_limit)
    return f"{prefix}\n{visible_marker}" if prefix else visible_marker
