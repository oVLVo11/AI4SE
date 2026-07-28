"""Validated public contracts shared by every pyquality component."""

from __future__ import annotations

import json
import re
from datetime import datetime
from enum import StrEnum
from pathlib import PurePosixPath
from typing import ClassVar, Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator

MAX_RATIONALE_BYTES = 4_096
MAX_FINDING_SUMMARY_BYTES = 1_024
MAX_FINDING_EVIDENCE_BYTES = 4_096
MAX_GROUP_KEY_BYTES = 512
MAX_ACTION_ARGUMENTS_BYTES = 65_536
MAX_TOOL_OUTPUT_BYTES = 65_536
MAX_TOOL_METADATA_BYTES = 16_384
MAX_CONFIG_PATTERN_BYTES = 1_024


def _bounded(value: str, limit: int, field: str) -> None:
    if len(value.encode("utf-8")) > limit:
        raise ValueError(f"{field} exceeds {limit} UTF-8 bytes")


def _relative_path(value: str) -> None:
    path = PurePosixPath(value)
    if not value or "\\" in value or path.is_absolute() or ".." in path.parts:
        raise ValueError("path must be repository-relative POSIX text")


class PublicModel(BaseModel):
    """Reject undeclared data at every public model boundary."""

    model_config = ConfigDict(extra="forbid")


class TaskStatus(StrEnum):
    CREATED = "created"
    RUNNING = "running"
    WAITING_APPROVAL = "waiting_approval"
    SUCCEEDED = "succeeded"
    STALLED = "stalled"
    BUDGET_EXHAUSTED = "budget_exhausted"
    BLOCKED = "blocked"
    FAILED = "failed"


class ReadFileArguments(PublicModel):
    path: str = Field(min_length=1)


class SearchTextArguments(PublicModel):
    pattern: str = Field(min_length=1, max_length=2_000)
    path: str | None = None


class ListFilesArguments(PublicModel):
    path: str | None = None


class ApplyPatchArguments(PublicModel):
    patch: str = Field(min_length=1)


class RunQualityArguments(PublicModel):
    pass


class FinishArguments(PublicModel):
    pass


class Action(PublicModel):
    """A normalized action with a closed, kind-specific argument shape."""

    kind: Literal["read_file", "search_text", "list_files", "apply_patch", "run_quality", "finish"]
    arguments: dict[str, JsonValue] = Field(default_factory=dict)
    rationale: str = Field(min_length=1)
    model_config = ConfigDict(
        extra="forbid", json_schema_extra={"discriminator": {"propertyName": "kind"}}
    )

    _argument_models: ClassVar[dict[str, type[PublicModel]]] = {
        "read_file": ReadFileArguments,
        "search_text": SearchTextArguments,
        "list_files": ListFilesArguments,
        "apply_patch": ApplyPatchArguments,
        "run_quality": RunQualityArguments,
        "finish": FinishArguments,
    }

    @model_validator(mode="after")
    def validate_arguments(self) -> Action:
        model = self._argument_models[self.kind]
        self.arguments = model.model_validate(self.arguments).model_dump(exclude_none=True)
        _bounded(self.rationale, MAX_RATIONALE_BYTES, "rationale")
        _bounded(json.dumps(self.arguments, ensure_ascii=False, separators=(",", ":")), MAX_ACTION_ARGUMENTS_BYTES, "arguments")
        return self


class Finding(PublicModel):
    source: Literal["pytest", "ruff", "harness"]
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
    severity: Literal["error", "warning"]
    path: str | None = None
    line: int | None = Field(default=None, ge=1)
    summary: str = Field(min_length=1)
    evidence: str = Field(min_length=1)
    group_key: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_location(self) -> Finding:
        if self.path is None and self.line is not None:
            raise ValueError("line requires path")
        if self.path is not None:
            _relative_path(self.path)
        _bounded(self.summary, MAX_FINDING_SUMMARY_BYTES, "summary")
        _bounded(self.evidence, MAX_FINDING_EVIDENCE_BYTES, "evidence")
        _bounded(self.group_key, MAX_GROUP_KEY_BYTES, "group_key")
        return self


class CheckStatus(StrEnum):
    NOT_RUN = "not_run"
    PASSED = "passed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"


class QualityReport(PublicModel):
    targeted_pytest_status: CheckStatus
    full_pytest_status: CheckStatus
    ruff_status: CheckStatus
    findings: tuple[Finding, ...] = ()
    commands: tuple[tuple[str, ...], ...] = ()
    timed_out: tuple[str, ...] = ()
    changed_paths: tuple[str, ...] = ()

    @property
    def succeeded(self) -> bool:
        return self.full_pytest_status is CheckStatus.PASSED and self.ruff_status is CheckStatus.PASSED


class TaskResult(PublicModel):
    task_id: str = Field(min_length=1)
    status: TaskStatus
    iterations: int = Field(ge=0)
    verification_summary: str = Field(min_length=1)
    changed_paths: tuple[str, ...] = ()
    audit_location: str | None = None

    @model_validator(mode="after")
    def validate_status(self) -> TaskResult:
        if self.status in {TaskStatus.CREATED, TaskStatus.RUNNING}:
            raise ValueError("task result status must be terminal or waiting approval")
        return self


class PolicyOutcome(StrEnum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"


class PolicyDecision(PublicModel):
    outcome: PolicyOutcome
    matched_rule: str | None = None
    impact_summary: str = Field(min_length=1)
    action_digest: str = Field(min_length=64, max_length=64)

    @model_validator(mode="after")
    def normalize_digest(self) -> PolicyDecision:
        if re.fullmatch(r"[0-9a-fA-F]{64}", self.action_digest) is None:
            raise ValueError("action_digest must be SHA-256 hex")
        self.action_digest = self.action_digest.lower()
        return self


class ToolResult(PublicModel):
    effect_kind: str = Field(min_length=1)
    code_changed: bool
    changed_paths: tuple[str, ...] = ()
    before_digests: dict[str, str] = Field(default_factory=dict)
    after_digests: dict[str, str] = Field(default_factory=dict)
    truncated: bool = False
    normalized_metadata: dict[str, JsonValue] = Field(default_factory=dict)
    evidence: str | None = None

    @model_validator(mode="after")
    def validate_digests(self) -> ToolResult:
        for path in self.changed_paths:
            _relative_path(path)
        for path in (*self.before_digests, *self.after_digests):
            _relative_path(path)
        changed_paths = set(self.changed_paths)
        if set(self.before_digests) - changed_paths or set(self.after_digests) - changed_paths:
            raise ValueError("content digests must belong to changed paths")
        if self.evidence is not None:
            _bounded(self.evidence, MAX_TOOL_OUTPUT_BYTES, "evidence")
        _bounded(json.dumps(self.normalized_metadata, ensure_ascii=False, separators=(",", ":")), MAX_TOOL_METADATA_BYTES, "normalized_metadata")
        return self


class ApprovalDecision(StrEnum):
    APPROVE = "approve"
    REJECT = "reject"


class AuditEvent(PublicModel):
    event_type: str = Field(min_length=1)
    metadata: dict[str, JsonValue] = Field(default_factory=dict)
    task_id: str | None = None
    iteration_id: str | None = None
    component: str | None = None
    created_at: datetime | None = None
