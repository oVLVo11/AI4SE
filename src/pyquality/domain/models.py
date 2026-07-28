"""Validated public contracts shared by every pyquality component."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from pathlib import PurePosixPath
from typing import ClassVar, Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator


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
    rationale: str = Field(min_length=1, max_length=2_000)

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
            path = PurePosixPath(self.path)
            if "\\" in self.path or path.is_absolute() or ".." in path.parts:
                raise ValueError("path must be repository-relative POSIX text")
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
        changed_paths = set(self.changed_paths)
        if set(self.before_digests) - changed_paths or set(self.after_digests) - changed_paths:
            raise ValueError("content digests must belong to changed paths")
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
