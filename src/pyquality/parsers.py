"""Normalize bounded pytest and Ruff output into public findings."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from pathlib import PurePosixPath
from typing import TYPE_CHECKING

from pyquality.domain.models import Finding

if TYPE_CHECKING:
    from pyquality.config import Settings

_EVIDENCE_LIMIT = 2_048
_SUMMARY_LIMIT = 512
_FILE_LINE = re.compile(r'File "(?P<path>[^"]+\.py)", line (?P<line>\d+)')
_PATH_LINE = re.compile(r"(?P<path>[^\s:'\"]+\.py):(?P<line>\d+)")
_EXCEPTION = re.compile(r"^E\s+(?P<message>.+)$", re.MULTILINE)


def parse_pytest(
    output: str,
    exit_code: int | None,
    *,
    timed_out: bool = False,
    settings: Settings | None = None,
) -> tuple[Finding, ...]:
    """Turn a pytest process outcome into one compact, actionable finding."""
    if timed_out:
        return (_harness_finding("timeout", output, settings),)
    if exit_code == 0:
        return ()
    if _missing_tool(output, "pytest"):
        return (_harness_finding("missing_tool_dependency", output, settings),)

    category = _pytest_category(output)
    path, line = _location(output)
    summary = _pytest_summary(output, category)
    return (
        _finding(
            settings,
            source="pytest",
            category=category,
            severity="error",
            path=path,
            line=line,
            summary=_compact(summary, _limit(settings, "max_finding_summary_bytes", _SUMMARY_LIMIT)),
            evidence=_compact(output, _limit(settings, "max_finding_evidence_bytes", _EVIDENCE_LIMIT)),
            group_key=_group_key("pytest", category, path, line, settings),
        ),
    )


def parse_ruff(
    output: str,
    exit_code: int | None,
    *,
    timed_out: bool = False,
    settings: Settings | None = None,
) -> tuple[Finding, ...]:
    """Turn Ruff's JSON protocol into deterministic, bounded findings."""
    if timed_out:
        return (_harness_finding("timeout", output, settings),)
    if exit_code == 0:
        return ()
    if _missing_tool(output, "ruff"):
        return (_harness_finding("missing_tool_dependency", output, settings),)
    try:
        records = json.loads(output)
    except json.JSONDecodeError:
        return (_infrastructure_finding("ruff", output, settings),)
    if not isinstance(records, list):
        return (_infrastructure_finding("ruff", output, settings),)

    findings: list[Finding] = []
    for record in records:
        if not isinstance(record, Mapping):
            continue
        code = record.get("code")
        message = record.get("message")
        filename = record.get("filename")
        location = record.get("location")
        if not isinstance(code, str) or not isinstance(message, str) or not isinstance(filename, str):
            continue
        path = _normalize_path(filename)
        if path is None:
            continue
        line = location.get("row") if isinstance(location, Mapping) else None
        if not isinstance(line, int) or isinstance(line, bool) or line < 1:
            line = None
        summary = _compact(
            f"{code}: {message}", _limit(settings, "max_finding_summary_bytes", _SUMMARY_LIMIT)
        )
        findings.append(
            _finding(
                settings,
                source="ruff",
                category="ruff",
                severity="warning",
                path=path,
                line=line,
                summary=summary,
                evidence=_compact(
                    f"{path}:{line or 0}: {summary}",
                    _limit(settings, "max_finding_evidence_bytes", _EVIDENCE_LIMIT),
                ),
                group_key=_group_key("ruff", code, path, line, settings),
            )
        )
    if not findings:
        return (_infrastructure_finding("ruff", output, settings),)
    return tuple(
        sorted(
            findings,
            key=lambda finding: (
                finding.path or "",
                finding.line or 0,
                finding.summary,
                finding.group_key,
            ),
        )
    )


def _pytest_category(output: str) -> str:
    if "SyntaxError" in output:
        return "syntax"
    if "ERROR collecting" in output or "ImportError" in output or "ModuleNotFoundError" in output:
        return "import_collection"
    if "AssertionError" in output or "FAILED " in output and "assert" in output:
        return "assertion"
    if "ERROR at" in output or _EXCEPTION.search(output):
        return "runtime"
    return "infrastructure"


def _pytest_summary(output: str, category: str) -> str:
    exception = _EXCEPTION.search(output)
    if exception is not None:
        return _compact(exception.group("message"), _SUMMARY_LIMIT)
    return {
        "syntax": "pytest reported a syntax error",
        "import_collection": "pytest could not collect a test module",
        "assertion": "pytest assertion failed",
        "runtime": "pytest reported a runtime error",
        "infrastructure": "pytest exited with unrecognized failure output",
    }[category]


def _location(output: str) -> tuple[str | None, int | None]:
    for pattern in (_FILE_LINE, _PATH_LINE):
        match = pattern.search(output)
        if match is None:
            continue
        path = _normalize_path(match.group("path"))
        if path is not None:
            line = int(match.group("line"))
            return path, line if line >= 1 else None
    return None, None


def _normalize_path(value: str) -> str | None:
    path = value.strip().replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    if not path or re.match(r"^[A-Za-z]:/", path):
        return None
    candidate = PurePosixPath(path)
    if candidate.is_absolute() or ".." in candidate.parts:
        return None
    return candidate.as_posix()


def _missing_tool(output: str, tool: str) -> bool:
    return bool(
        re.search(rf"No module named ['\"]?{re.escape(tool)}['\"]?", output)
        or re.search(rf"(?:command|executable) not found.*\b{re.escape(tool)}\b", output, re.IGNORECASE)
    )


def _harness_finding(category: str, output: str, settings: Settings | None) -> Finding:
    return _finding(
        settings,
        source="harness",
        category=category,
        severity="error",
        summary={
            "timeout": "quality command timed out",
            "missing_tool_dependency": "quality tool dependency is unavailable",
        }[category],
        evidence=_compact(output, _limit(settings, "max_finding_evidence_bytes", _EVIDENCE_LIMIT)),
        group_key=_compact(
            f"harness:{category}", _limit(settings, "max_group_key_bytes", _SUMMARY_LIMIT)
        ),
    )


def _infrastructure_finding(
    source: str, output: str, settings: Settings | None
) -> Finding:
    return _finding(
        settings,
        source="harness" if source == "ruff" else "pytest",
        category="infrastructure",
        severity="error",
        summary=f"{source} exited with unrecognized failure output",
        evidence=_compact(output, _limit(settings, "max_finding_evidence_bytes", _EVIDENCE_LIMIT)),
        group_key=_compact(
            f"{source}:infrastructure", _limit(settings, "max_group_key_bytes", _SUMMARY_LIMIT)
        ),
    )


def _group_key(
    source: str,
    category: str,
    path: str | None,
    line: int | None,
    settings: Settings | None,
) -> str:
    location = f"{path or '-'}:{line or 0}"
    return _compact(
        f"{source}:{category}:{location}",
        _limit(settings, "max_group_key_bytes", _SUMMARY_LIMIT),
    )


def _finding(settings: Settings | None, **data: object) -> Finding:
    return Finding.model_validate(data, context={"settings": settings} if settings else None)


def _limit(settings: Settings | None, name: str, default: int) -> int:
    return getattr(settings, name, default)


def _compact(value: str, limit: int = _EVIDENCE_LIMIT) -> str:
    normalized = value.strip() or "no process output"
    encoded = normalized.encode("utf-8")
    if len(encoded) <= limit:
        return normalized
    return encoded[:limit].decode("utf-8", errors="ignore").rstrip()
