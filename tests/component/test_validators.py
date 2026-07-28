from __future__ import annotations

import hashlib
import sys
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from pyquality.config import Settings
from pyquality.domain.models import CheckStatus
from pyquality.tools import ProcessResult
from pyquality.validators import PytestValidator, QualityPipeline


@dataclass(frozen=True)
class Call:
    argv: list[str]
    cwd: Path
    timeout_s: int
    output_limit: int


@dataclass
class RecordingRunner:
    results: list[ProcessResult]
    calls: list[Call] = field(default_factory=list)

    def run(self, argv: list[str], cwd: Path, timeout_s: int, output_limit: int) -> ProcessResult:
        self.calls.append(Call(argv, cwd, timeout_s, output_limit))
        return self.results.pop(0)


@pytest.fixture
def settings() -> Settings:
    return Settings(subprocess_timeout_s=7, max_tool_output_bytes=321)


@pytest.fixture
def passing_result() -> ProcessResult:
    return ProcessResult(0, "", "", "", False, False)


def test_changed_test_file_runs_target_then_full_then_ruff(
    settings: Settings, passing_result: ProcessResult
) -> None:
    """Skipping the changed-test preflight would delay feedback on the edited test itself."""
    runner = RecordingRunner([passing_result, passing_result, passing_result])
    pipeline = QualityPipeline(runner, settings)

    report = pipeline.run({Path("tests/test_math.py")})

    assert [call.argv for call in runner.calls] == [
        [sys.executable, "-m", "pytest", "tests/test_math.py"],
        [sys.executable, "-m", "pytest"],
        [sys.executable, "-m", "ruff", "check", "--output-format", "json", "."],
    ]
    assert report.succeeded is True


def test_non_test_change_runs_only_full_pytest_then_ruff(
    settings: Settings, passing_result: ProcessResult
) -> None:
    """Treating ordinary source as a test target would pass an invalid pytest argument."""
    runner = RecordingRunner([passing_result, passing_result])

    report = QualityPipeline(runner, settings).run({Path("src/service.py")})

    assert [call.argv for call in runner.calls] == [
        [sys.executable, "-m", "pytest"],
        [sys.executable, "-m", "ruff", "check", "--output-format", "json", "."],
    ]
    assert report.targeted_pytest_status is CheckStatus.NOT_RUN


def test_timed_out_target_skips_full_but_still_runs_ruff(settings: Settings) -> None:
    """Continuing a blocked pytest preflight could waste the remaining validation budget."""
    timed_out = ProcessResult(None, "", "", "partial", True, False)
    ruff_passed = ProcessResult(0, "", "", "", False, False)
    runner = RecordingRunner([timed_out, ruff_passed])

    report = QualityPipeline(runner, settings).run({Path("test_math.py")})

    assert [call.argv for call in runner.calls] == [
        [sys.executable, "-m", "pytest", "test_math.py"],
        [sys.executable, "-m", "ruff", "check", "--output-format", "json", "."],
    ]
    assert report.full_pytest_status is CheckStatus.NOT_RUN
    assert report.ruff_status is CheckStatus.PASSED
    assert report.findings[0].category == "timeout"


def test_raw_result_records_duration_and_digest(settings: Settings) -> None:
    """Omitting raw-result provenance would make a reported validation outcome unauditable."""
    output = "1 passed\n"
    runner = RecordingRunner([ProcessResult(0, output, "", output, False, False)])

    result = PytestValidator(runner, settings).run(set())

    assert result.duration_s >= 0
    assert result.output_digest == hashlib.sha256(output.encode("utf-8")).hexdigest()
