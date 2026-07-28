from __future__ import annotations

from pathlib import Path

import pytest

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
