"""Validated public contracts shared by every pyquality component."""

from __future__ import annotations

import json
import re
from datetime import datetime
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    RootModel,
    TypeAdapter,
    ValidationInfo,
    model_validator,
)

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


def _limit(info: ValidationInfo, name: str, default: int) -> int:
    settings = (info.context or {}).get("settings")
    return getattr(settings, name, default)


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


class ActionEnvelope(PublicModel):
    rationale: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_envelope(self, info: ValidationInfo) -> ActionEnvelope:
        _bounded(self.rationale, _limit(info, "max_rationale_bytes", MAX_RATIONALE_BYTES), "rationale")
        arguments = self.arguments.model_dump(exclude_none=True)
        _bounded(json.dumps(arguments, ensure_ascii=False, separators=(",", ":")), _limit(info, "max_action_arguments_bytes", MAX_ACTION_ARGUMENTS_BYTES), "arguments")
        return self


class ReadFileAction(ActionEnvelope):
    kind: Literal["read_file"]
    arguments: ReadFileArguments


class SearchTextAction(ActionEnvelope):
    kind: Literal["search_text"]
    arguments: SearchTextArguments


class ListFilesAction(ActionEnvelope):
    kind: Literal["list_files"]
    arguments: ListFilesArguments


class ApplyPatchAction(ActionEnvelope):
    kind: Literal["apply_patch"]
    arguments: ApplyPatchArguments


class RunQualityAction(ActionEnvelope):
    kind: Literal["run_quality"]
    arguments: RunQualityArguments


class FinishAction(ActionEnvelope):
    kind: Literal["finish"]
    arguments: FinishArguments


ActionVariant = Annotated[
    ReadFileAction | SearchTextAction | ListFilesAction | ApplyPatchAction | RunQualityAction | FinishAction,
    Field(discriminator="kind"),
]


class Action(RootModel[ActionVariant]):
    """Discriminated action envelope with the original consumer-facing accessors."""

    def __init__(self, root: ActionVariant | None = None, **data: JsonValue) -> None:
        if root is not None and data:
            raise ValueError("provide either root or action fields")
        super().__init__(root=root if root is not None else data)

    @classmethod
    def model_validate(
        cls, obj: object, *, context: dict[str, object] | None = None, **_: object
    ) -> Action:
        return cls(root=TypeAdapter(ActionVariant).validate_python(obj, context=context))

    @property
    def kind(self) -> str:
        return self.root.kind

    @property
    def arguments(self) -> dict[str, JsonValue]:
        return self.root.arguments.model_dump(exclude_none=True)

    @property
    def rationale(self) -> str:
        return self.root.rationale


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
    def validate_location(self, info: ValidationInfo) -> Finding:
        if self.path is None and self.line is not None:
            raise ValueError("line requires path")
        if self.path is not None:
            _relative_path(self.path)
            _bounded(self.path, _limit(info, "max_config_pattern_bytes", MAX_CONFIG_PATTERN_BYTES), "path")
        _bounded(self.summary, _limit(info, "max_finding_summary_bytes", MAX_FINDING_SUMMARY_BYTES), "summary")
        _bounded(self.evidence, _limit(info, "max_finding_evidence_bytes", MAX_FINDING_EVIDENCE_BYTES), "evidence")
        _bounded(self.group_key, _limit(info, "max_group_key_bytes", MAX_GROUP_KEY_BYTES), "group_key")
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
    repository_snapshot_digest: str = Field(min_length=64, max_length=64)

    @model_validator(mode="after")
    def normalize_digest(self) -> PolicyDecision:
        for field in ("action_digest", "repository_snapshot_digest"):
            value = getattr(self, field)
            if re.fullmatch(r"[0-9a-fA-F]{64}", value) is None:
                raise ValueError(f"{field} must be SHA-256 hex")
            setattr(self, field, value.lower())
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
    def validate_digests(self, info: ValidationInfo) -> ToolResult:
        for path in self.changed_paths:
            _relative_path(path)
            _bounded(path, _limit(info, "max_config_pattern_bytes", MAX_CONFIG_PATTERN_BYTES), "path")
        for path in (*self.before_digests, *self.after_digests):
            _relative_path(path)
            _bounded(path, _limit(info, "max_config_pattern_bytes", MAX_CONFIG_PATTERN_BYTES), "path")
        changed_paths = set(self.changed_paths)
        if set(self.before_digests) - changed_paths or set(self.after_digests) - changed_paths:
            raise ValueError("content digests must belong to changed paths")
        if self.evidence is not None:
            _bounded(self.evidence, _limit(info, "max_tool_output_bytes", MAX_TOOL_OUTPUT_BYTES), "evidence")
        _bounded(json.dumps(self.normalized_metadata, ensure_ascii=False, separators=(",", ":")), _limit(info, "max_tool_metadata_bytes", MAX_TOOL_METADATA_BYTES), "normalized_metadata")
        return self

    @property
    def code(self) -> str:
        """Stable dispatcher status without widening the persisted result schema."""
        value = self.normalized_metadata.get("code", "ok")
        return value if isinstance(value, str) else "invalid_result_code"

    @property
    def ok(self) -> bool:
        """Whether the effect completed successfully."""
        return self.code == "ok"

    @property
    def output(self) -> str:
        """Bounded human/model-readable output emitted by a non-mutating tool."""
        return self.evidence or ""


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
