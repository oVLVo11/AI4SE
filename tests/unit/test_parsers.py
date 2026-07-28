from __future__ import annotations

from pathlib import Path

import pytest

from pyquality.config import Settings
from pyquality.parsers import parse_pytest, parse_ruff


@pytest.fixture
def load_fixture() -> object:
    root = Path(__file__).parents[1] / "fixtures" / "validator_outputs"
    return lambda name: (root / name).read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("fixture", "category"),
    [
        ("pytest_assertion.txt", "assertion"),
        ("pytest_import.txt", "import_collection"),
        ("pytest_syntax.txt", "syntax"),
        ("pytest_runtime.txt", "runtime"),
    ],
)
def test_pytest_categories(load_fixture: object, fixture: str, category: str) -> None:
    """Removing a pytest category branch would mis-prioritize a distinct repair class."""
    findings = parse_pytest(load_fixture(fixture), exit_code=1)  # type: ignore[operator]

    assert findings[0].category == category


def test_pytest_normalizes_windows_test_location(load_fixture: object) -> None:
    """Keeping backslashes would violate the portable Finding path contract."""
    finding = parse_pytest(load_fixture("pytest_windows_assertion.txt"), exit_code=1)[0]  # type: ignore[operator]

    assert finding.path == "tests/test_math.py"


def test_pytest_unknown_nonzero_output_is_infrastructure(load_fixture: object) -> None:
    """Dropping unfamiliar subprocess failures would hide an unrecoverable quality failure."""
    findings = parse_pytest(load_fixture("pytest_infrastructure.txt"), exit_code=1)  # type: ignore[operator]

    assert findings[0].category == "infrastructure"


def test_pytest_missing_dependency_and_timeout_are_explicit(load_fixture: object) -> None:
    """Collapsing tool absence or timeout into test failure would suggest an invalid source repair."""
    missing = parse_pytest(load_fixture("pytest_missing.txt"), exit_code=1)  # type: ignore[operator]
    timeout = parse_pytest(load_fixture("pytest_timeout.txt"), exit_code=None, timed_out=True)  # type: ignore[operator]

    assert (missing[0].category, timeout[0].category) == ("missing_tool_dependency", "timeout")


def test_ruff_json_maps_location(load_fixture: object) -> None:
    """Ignoring Ruff's JSON location would prevent source-specific lint repair."""
    finding = parse_ruff(load_fixture("ruff.json"), exit_code=1)[0]  # type: ignore[operator]

    assert (finding.category, finding.path, finding.line) == ("ruff", "src/a.py", 3)


def test_ruff_parser_sorts_and_bounds_its_findings() -> None:
    """Unsorted or oversized Ruff evidence would destabilize and exhaust feedback context."""
    output = "[" + ",".join(
        [
            '{"code":"E501","message":"' + "x" * 5_000 + '","filename":"z.py","location":{"row":2}}',
            '{"code":"F401","message":"unused","filename":"a.py","location":{"row":1}}',
        ]
    ) + "]"

    findings = parse_ruff(output, exit_code=1)

    assert [(finding.path, finding.line) for finding in findings] == [("a.py", 1), ("z.py", 2)]
    assert len(findings[1].evidence.encode("utf-8")) <= 2_048


def test_pytest_rejects_invalid_line_without_raising() -> None:
    """Passing line zero into Finding would turn malformed tool output into a harness crash."""
    findings = parse_pytest("tests/test_x.py:0: AssertionError", exit_code=1)

    assert (findings[0].path, findings[0].line) == ("tests/test_x.py", None)


@pytest.mark.parametrize(
    "output",
    [
        '[{"code":"F401","message":"unused","filename":"a.py","location":{"row":true}}]',
        '[{"code":"F401","message":"unused","filename":"a.py","location":{"row":0}}]',
    ],
)
def test_ruff_invalid_rows_do_not_become_finding_lines(output: str) -> None:
    """Boolean or out-of-range JSON rows must not masquerade as valid source locations."""
    assert parse_ruff(output, exit_code=1)[0].line is None


def test_parser_applies_effective_settings_limits_to_finding_fields() -> None:
    """Using parser constants would violate stricter effective per-run evidence limits."""
    settings = Settings(
        max_finding_summary_bytes=24,
        max_finding_evidence_bytes=32,
        max_group_key_bytes=24,
    )

    finding = parse_ruff(
        '[{"code":"F401","message":"a very long unused import message",'
        '"filename":"a.py","location":{"row":1}}]',
        exit_code=1,
        settings=settings,
    )[0]

    assert len(finding.summary.encode("utf-8")) <= 24
    assert len(finding.evidence.encode("utf-8")) <= 32
    assert len(finding.group_key.encode("utf-8")) <= 24


def test_ruff_order_includes_code_for_otherwise_identical_findings() -> None:
    """Input ordering must not affect normalized output when Ruff codes differ."""
    output = (
        '[{"code":"Z999","message":"same","filename":"a.py","location":{"row":1}},'
        '{"code":"A001","message":"same","filename":"a.py","location":{"row":1}}]'
    )

    findings = parse_ruff(output, exit_code=1)

    assert [finding.group_key for finding in findings] == [
        "ruff:A001:a.py:1",
        "ruff:Z999:a.py:1",
    ]
