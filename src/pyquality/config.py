"""Secure, bounded configuration loading for one repository run."""

from __future__ import annotations

import re
import tomllib
from collections.abc import Mapping
from pathlib import Path, PurePosixPath

from pydantic import ConfigDict, Field, ValidationError, model_validator

from .domain.models import (
    MAX_ACTION_ARGUMENTS_BYTES,
    MAX_CONFIG_PATTERN_BYTES,
    MAX_FINDING_EVIDENCE_BYTES,
    MAX_FINDING_SUMMARY_BYTES,
    MAX_GROUP_KEY_BYTES,
    MAX_RATIONALE_BYTES,
    MAX_TOOL_METADATA_BYTES,
    MAX_TOOL_OUTPUT_BYTES,
    PublicModel,
)


class ConfigError(ValueError):
    """Raised when configuration fails preflight validation."""


_LIMIT_FIELDS = frozenset(
    {
        "round_limit",
        "global_concurrency",
        "subprocess_timeout_s",
        "provider_timeout_s",
        "provider_retries",
        "total_feedback_bytes",
        "per_finding_evidence_bytes",
        "tool_output_bytes",
        "read_search_result_bytes",
        "source_excerpt_bytes",
        "feedback_total_bytes",
        "max_rationale_bytes", "max_finding_summary_bytes", "max_finding_evidence_bytes",
        "max_group_key_bytes", "max_action_arguments_bytes", "max_tool_output_bytes",
        "max_tool_metadata_bytes", "max_config_pattern_bytes", "max_config_patterns",
    }
)
_REPOSITORY_FIELDS = _LIMIT_FIELDS | {"exclusions"}
_SHELL_TOKENS = frozenset(";&|`$><\n\r")
_RUFF_CODES = re.compile(r"^[A-Z0-9]+(?:,[A-Z0-9]+)*$")


class Settings(PublicModel):
    """Runtime settings with secure ceilings and closed configuration keys."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    round_limit: int = Field(default=8, ge=1, le=8)
    global_concurrency: int = Field(default=2, ge=1, le=4)
    subprocess_timeout_s: int = Field(default=60, ge=1, le=60)
    provider_timeout_s: int = Field(default=30, ge=1, le=30)
    provider_retries: int = Field(default=2, ge=0, le=2)
    feedback_total_bytes: int = Field(default=32_768, ge=1, le=32_768)
    max_rationale_bytes: int = Field(default=MAX_RATIONALE_BYTES, ge=1, le=MAX_RATIONALE_BYTES)
    max_finding_summary_bytes: int = Field(default=MAX_FINDING_SUMMARY_BYTES, ge=1, le=MAX_FINDING_SUMMARY_BYTES)
    max_finding_evidence_bytes: int = Field(default=MAX_FINDING_EVIDENCE_BYTES, ge=1, le=MAX_FINDING_EVIDENCE_BYTES)
    max_group_key_bytes: int = Field(default=MAX_GROUP_KEY_BYTES, ge=1, le=MAX_GROUP_KEY_BYTES)
    max_action_arguments_bytes: int = Field(default=MAX_ACTION_ARGUMENTS_BYTES, ge=1, le=MAX_ACTION_ARGUMENTS_BYTES)
    max_tool_output_bytes: int = Field(default=MAX_TOOL_OUTPUT_BYTES, ge=1, le=MAX_TOOL_OUTPUT_BYTES)
    max_tool_metadata_bytes: int = Field(default=MAX_TOOL_METADATA_BYTES, ge=1, le=MAX_TOOL_METADATA_BYTES)
    max_config_pattern_bytes: int = Field(default=MAX_CONFIG_PATTERN_BYTES, ge=1, le=MAX_CONFIG_PATTERN_BYTES)
    max_config_patterns: int = Field(default=128, ge=1, le=128)
    read_search_result_bytes: int = Field(default=64 * 1024, ge=1, le=64 * 1024)
    source_excerpt_bytes: int = Field(default=8 * 1024, ge=1, le=8 * 1024)
    pytest_args: tuple[str, ...] = ("-q",)
    ruff_args: tuple[str, ...] = ("--output-format", "text")
    exclusions: tuple[str, ...] = ()
    denied_actions: tuple[str, ...] = ("shell",)
    redaction_patterns: tuple[str, ...] = ("authorization", "api_key", "token", "secret")

    @model_validator(mode="after")
    def validate_secure_values(self) -> Settings:
        _validate_pytest_args(self.pytest_args)
        _validate_ruff_args(self.ruff_args)
        for path in self.exclusions:
            _validate_relative_path(path)
        if not self.denied_actions or not self.redaction_patterns:
            raise ValueError("denied actions and redaction patterns must not be empty")
        if len(self.redaction_patterns) > self.max_config_patterns:
            raise ValueError("too many redaction patterns")
        for pattern in self.redaction_patterns:
            if len(pattern.encode("utf-8")) > self.max_config_pattern_bytes:
                raise ValueError("redaction pattern exceeds byte limit")
        return self


def load_settings(repo_root: Path, user_file: Path | None) -> Settings:
    """Merge defaults, an explicitly supplied user file, then restrictions from pyquality.toml."""
    root = _validate_root(repo_root)
    merged = Settings().model_dump(mode="json")
    if user_file is not None:
        merged.update(_read_config(user_file))
    user_settings = _build_settings(merged)

    repository_file = root / "pyquality.toml"
    if not repository_file.exists():
        return user_settings

    repository = _read_config(repository_file)
    unexpected = set(repository) - _REPOSITORY_FIELDS
    if unexpected:
        raise ConfigError(f"repository config cannot change '{min(unexpected)}'")

    narrowed = user_settings.model_dump(mode="json")
    for field in _LIMIT_FIELDS & set(repository):
        requested = repository[field]
        current = narrowed[field]
        if not isinstance(requested, int) or isinstance(requested, bool):
            raise ConfigError(f"wrong type for '{field}'")
        if requested > current:
            raise ConfigError(f"repository config cannot widen '{field}'")
        narrowed[field] = requested
    if "exclusions" in repository:
        exclusions = repository["exclusions"]
        if not isinstance(exclusions, list) or not all(isinstance(item, str) for item in exclusions):
            raise ConfigError("wrong type for 'exclusions'")
        narrowed["exclusions"] = list(dict.fromkeys((*user_settings.exclusions, *exclusions)))
    return _build_settings(narrowed)


def _validate_root(repo_root: Path) -> Path:
    try:
        root = repo_root.resolve(strict=True)
    except OSError as error:
        raise ConfigError("repository root is unreadable") from error
    if not root.is_dir():
        raise ConfigError("repository root must be a directory")
    return root


def _read_config(path: Path) -> dict[str, object]:
    try:
        with path.open("rb") as stream:
            raw = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ConfigError(f"cannot read configuration: {path}") from error
    config: object = raw
    if "tool" in raw:
        tool = raw["tool"]
        if not isinstance(tool, Mapping) or "pyquality" not in tool:
            raise ConfigError("unknown field: tool")
        config = tool["pyquality"]
    if not isinstance(config, Mapping) or not all(isinstance(key, str) for key in config):
        raise ConfigError("configuration must be a table")
    normalized = dict(config)
    _ensure_known_fields(normalized)
    return normalized


def _ensure_known_fields(config: Mapping[str, object]) -> None:
    unknown = set(config) - set(Settings.model_fields)
    if unknown:
        raise ConfigError(f"unknown field: {min(unknown)}")


def _build_settings(config: Mapping[str, object]) -> Settings:
    _ensure_known_fields(config)
    for name, field in Settings.model_fields.items():
        if name in config and not _matches_type(config[name], field.annotation):
            raise ConfigError(f"wrong type for '{name}'")
    try:
        return Settings.model_validate(config)
    except ValidationError as error:
        raise ConfigError(f"invalid configuration: {error.errors()[0]['msg']}") from error


def _matches_type(value: object, annotation: object) -> bool:
    if annotation is int:
        return isinstance(value, int) and not isinstance(value, bool)
    if annotation == tuple[str, ...]:
        return isinstance(value, list) and all(isinstance(item, str) for item in value)
    return True


def _validate_pytest_args(arguments: tuple[str, ...]) -> None:
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument in {"-q", "-v", "-x"}:
            index += 1
        elif argument == "-k":
            if index + 1 >= len(arguments) or not _safe_expression(arguments[index + 1]):
                raise ValueError("pytest -k requires a safe expression")
            index += 2
        else:
            _validate_relative_path(argument)
            index += 1


def _validate_ruff_args(arguments: tuple[str, ...]) -> None:
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument in {"--select", "--ignore"}:
            if index + 1 >= len(arguments) or not _RUFF_CODES.fullmatch(arguments[index + 1]):
                raise ValueError(f"{argument} requires comma-separated Ruff codes")
            index += 2
        elif argument == "--output-format":
            if index + 1 >= len(arguments) or arguments[index + 1] != "text":
                raise ValueError("Ruff output format must be text")
            index += 2
        else:
            _validate_relative_path(argument)
            index += 1


def _safe_expression(value: str) -> bool:
    return bool(value.strip()) and not any(token in value for token in _SHELL_TOKENS)


def _validate_relative_path(value: str) -> None:
    if not value or any(token in value for token in _SHELL_TOKENS) or "\\" in value:
        raise ValueError("path must be repository-relative POSIX text")
    path = PurePosixPath(value)
    if value.startswith("-") or path.is_absolute() or ".." in path.parts:
        raise ValueError("path must be repository-relative POSIX text")
