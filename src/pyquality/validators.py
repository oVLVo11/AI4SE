"""Run bounded quality commands and assemble their normalized report."""

from __future__ import annotations

import hashlib
import sys
import time
from pathlib import Path, PurePosixPath

from pyquality.config import Settings
from pyquality.domain.models import CheckStatus, Finding, PublicModel, QualityReport
from pyquality.parsers import parse_pytest, parse_ruff
from pyquality.tools import ProcessResult, ProcessRunner


class RawValidationResult(PublicModel):
    """Auditable bounded result from one quality command."""

    argv: tuple[str, ...]
    exit_code: int | None
    duration_s: float
    output: str
    output_digest: str
    timed_out: bool
    truncated: bool


class PytestValidator:
    """Execute either eligible changed tests or the complete pytest suite."""

    def __init__(self, runner: ProcessRunner, settings: Settings, cwd: Path | None = None) -> None:
        self._runner = runner
        self._settings = settings
        self._cwd = cwd or Path.cwd()

    def run(self, changed_paths: set[Path]) -> RawValidationResult:
        targets = _changed_test_paths(changed_paths)
        return self._execute(
            [sys.executable, "-m", "pytest", *self._settings.pytest_args, *targets]
        )

    def _execute(self, argv: list[str]) -> RawValidationResult:
        return _run(self._runner, self._settings, self._cwd, argv)


class RuffValidator:
    """Execute Ruff using its stable JSON output protocol."""

    def __init__(self, runner: ProcessRunner, settings: Settings, cwd: Path | None = None) -> None:
        self._runner = runner
        self._settings = settings
        self._cwd = cwd or Path.cwd()

    def run(self) -> RawValidationResult:
        configured = _without_ruff_output_format(self._settings.ruff_args)
        return _run(
            self._runner,
            self._settings,
            self._cwd,
            [
                sys.executable,
                "-m",
                "ruff",
                "check",
                *configured,
                "--output-format",
                "json",
                ".",
            ],
        )


class QualityPipeline:
    """Run targeted pytest preflight, full pytest, then Ruff in a fixed order."""

    def __init__(self, runner: ProcessRunner, settings: Settings, cwd: Path | None = None) -> None:
        self._settings = settings
        self._pytest = PytestValidator(runner, settings, cwd)
        self._ruff = RuffValidator(runner, settings, cwd)

    def run(self, changed_paths: set[Path]) -> QualityReport:
        normalized_paths = _normalized_changed_paths(changed_paths)
        target_paths = {Path(path) for path in _changed_test_paths(changed_paths)}
        targeted = self._pytest.run(target_paths) if target_paths else None
        targeted_findings = (
            _pytest_findings(targeted, self._settings) if targeted is not None else ()
        )

        full: RawValidationResult | None = None
        full_findings: tuple[Finding, ...] = ()
        if targeted is None or not _preflight_blocked(targeted, targeted_findings):
            full = self._pytest.run(set())
            full_findings = _pytest_findings(full, self._settings)

        ruff = self._ruff.run()
        ruff_findings = parse_ruff(
            ruff.output, ruff.exit_code, timed_out=ruff.timed_out, settings=self._settings
        )
        results = tuple(result for result in (targeted, full, ruff) if result is not None)
        timed_out = tuple(
            name
            for name, result in (("targeted_pytest", targeted), ("full_pytest", full), ("ruff", ruff))
            if result is not None and result.timed_out
        )
        return QualityReport(
            targeted_pytest_status=_status(targeted),
            full_pytest_status=_status(full),
            ruff_status=_status(ruff),
            findings=(*targeted_findings, *full_findings, *ruff_findings),
            commands=tuple(result.argv for result in results),
            timed_out=timed_out,
            changed_paths=normalized_paths,
        )


def _run(
    runner: ProcessRunner, settings: Settings, cwd: Path, argv: list[str]
) -> RawValidationResult:
    started = time.monotonic()
    process = runner.run(
        argv,
        cwd=cwd,
        timeout_s=settings.subprocess_timeout_s,
        output_limit=settings.max_tool_output_bytes,
    )
    return _raw_result(argv, process, time.monotonic() - started)


def _raw_result(argv: list[str], process: ProcessResult, duration_s: float) -> RawValidationResult:
    return RawValidationResult(
        argv=tuple(argv),
        exit_code=process.returncode,
        duration_s=duration_s,
        output=process.output,
        output_digest=hashlib.sha256(process.output.encode("utf-8")).hexdigest(),
        timed_out=process.timed_out,
        truncated=process.truncated,
    )


def _changed_test_paths(changed_paths: set[Path]) -> tuple[str, ...]:
    return tuple(
        path
        for path in _normalized_changed_paths(changed_paths)
        if _is_direct_test_path(path)
    )


def _normalized_changed_paths(changed_paths: set[Path]) -> tuple[str, ...]:
    normalized: set[str] = set()
    for changed_path in changed_paths:
        value = changed_path.as_posix().replace("\\", "/")
        while value.startswith("./"):
            value = value[2:]
        candidate = PurePosixPath(value)
        if (
            value
            and not candidate.is_absolute()
            and ".." not in candidate.parts
            and not _is_windows_drive_path(value)
        ):
            normalized.add(candidate.as_posix())
    return tuple(sorted(normalized))


def _is_direct_test_path(path: str) -> bool:
    candidate = PurePosixPath(path)
    if len(candidate.parts) == 1:
        return candidate.match("test_*.py")
    return len(candidate.parts) == 2 and candidate.parts[0] == "tests" and candidate.match("tests/test_*.py")


def _pytest_findings(result: RawValidationResult, settings: Settings) -> tuple[Finding, ...]:
    return parse_pytest(
        result.output, result.exit_code, timed_out=result.timed_out, settings=settings
    )


def _preflight_blocked(
    result: RawValidationResult, findings: tuple[Finding, ...]
) -> bool:
    return result.timed_out or result.exit_code is None or any(
        finding.category == "missing_tool_dependency" for finding in findings
    )


def _without_ruff_output_format(arguments: tuple[str, ...]) -> tuple[str, ...]:
    kept: list[str] = []
    index = 0
    while index < len(arguments):
        if arguments[index] == "--output-format":
            index += 2
        else:
            kept.append(arguments[index])
            index += 1
    return tuple(kept)


def _is_windows_drive_path(value: str) -> bool:
    return len(value) >= 3 and value[0].isalpha() and value[1:3] == ":/"


def _status(result: RawValidationResult | None) -> CheckStatus:
    if result is None:
        return CheckStatus.NOT_RUN
    if result.timed_out:
        return CheckStatus.TIMED_OUT
    return CheckStatus.PASSED if result.exit_code == 0 else CheckStatus.FAILED
