from __future__ import annotations

from pyquality.config import Settings
from pyquality.domain.models import Finding
from pyquality.feedback import FeedbackComposer, FeedbackFinding, FeedbackPacket


def finding(
    category: str,
    group_key: str,
    *,
    path: str | None = "tests/test_math.py",
    line: int | None = 4,
    summary: str = "summary",
    evidence: str = "evidence",
) -> Finding:
    return Finding(
        source="ruff" if category == "ruff" else "pytest",
        category=category,
        severity="warning" if category == "ruff" else "error",
        path=path,
        line=line,
        summary=summary,
        evidence=evidence,
        group_key=group_key,
    )


def test_feedback_orders_root_causes_and_reports_truncation() -> None:
    findings = (
        finding("ruff", "ruff", path="z.py", evidence="x" * 70),
        finding("assertion", "assert", path="b.py", evidence="x" * 70),
        finding("syntax", "syntax", path="a.py", evidence="x" * 70),
    )

    packet = FeedbackComposer().compose(findings, total_bytes=300, per_item_bytes=120)

    assert [item.category for item in packet.findings[:2]] == ["syntax", "assertion"]
    assert packet.omitted_count > 0
    assert packet.truncated is True
    assert packet.byte_budget == 300
    assert 0 < len(packet.text.encode("utf-8")) <= 300


def test_duplicate_root_causes_are_grouped() -> None:
    duplicates = tuple(finding("import_collection", "same", line=line) for line in (1, 2, 3))

    packet = FeedbackComposer().compose(duplicates, 2_000, 500)

    assert len(packet.findings) == 1
    assert packet.findings[0].occurrences == 3


def test_ties_sort_by_normalized_path_line_and_summary() -> None:
    findings = (
        finding("runtime", "c", path="b.py", line=1, summary="a"),
        finding("runtime", "b", path="a.py", line=2, summary="a"),
        finding("runtime", "a", path="a.py", line=1, summary="z"),
    )

    packet = FeedbackComposer().compose(findings, 4_000, 1_000)

    assert [(item.path, item.line) for item in packet.findings] == [
        ("a.py", 1),
        ("a.py", 2),
        ("b.py", 1),
    ]


def test_utf8_truncation_is_safe_nonempty_and_bounded_at_minimum_budget() -> None:
    item = finding("assertion", "emoji", summary="🚀", evidence="🚀" * 20)

    packet = FeedbackComposer().compose((item,), total_bytes=1, per_item_bytes=1)

    assert packet.text == "~"
    assert len(packet.text.encode("utf-8")) == 1
    assert packet.truncated is True
    assert packet.omitted_count == 1


def test_invalid_budgets_are_rejected() -> None:
    import pytest

    with pytest.raises(ValueError, match="positive"):
        FeedbackComposer().compose((), 0, 1)
    with pytest.raises(ValueError, match="positive"):
        FeedbackComposer().compose((), 1, 0)


def test_group_representative_is_deterministic_when_normalized_keys_tie() -> None:
    upper = finding("assertion", "same", summary="Alpha", evidence="z evidence")
    lower = finding("assertion", "same", summary="alpha", evidence="a evidence")

    forward = FeedbackComposer().compose((upper, lower), 2_000, 500)
    reversed_packet = FeedbackComposer().compose((lower, upper), 2_000, 500)

    assert forward == reversed_packet
    assert forward.findings[0].summary == "Alpha"


def test_group_representative_breaks_equal_priority_category_ties() -> None:
    infrastructure = finding("infrastructure", "same", summary="same", evidence="same")
    timeout = finding("timeout", "same", summary="same", evidence="same")

    forward = FeedbackComposer().compose((timeout, infrastructure), 2_000, 500)
    reverse = FeedbackComposer().compose((infrastructure, timeout), 2_000, 500)

    assert forward == reverse


def test_empty_packet_at_one_byte_reports_that_rendering_was_truncated() -> None:
    packet = FeedbackComposer().compose((), 1, 1)

    assert packet.text == "~"
    assert packet.omitted_count == 0
    assert packet.truncated is True


def test_feedback_public_models_reject_invalid_category_location_and_budget() -> None:
    import pytest
    from pydantic import ValidationError

    base = {
        "category": "assertion",
        "summary": "summary",
        "evidence": "evidence",
        "group_key": "group",
        "occurrences": 1,
    }
    with pytest.raises(ValidationError):
        FeedbackFinding(**(base | {"category": "unknown"}))
    with pytest.raises(ValidationError):
        FeedbackFinding(**base, path=None, line=1)
    with pytest.raises(ValidationError):
        FeedbackFinding(**base, path="../escape.py")
    with pytest.raises(ValidationError):
        FeedbackFinding(**base, path="C:/repo/file.py")
    with pytest.raises(ValidationError):
        FeedbackFinding(**base, path="a" * 1_025)

    valid = FeedbackFinding(**base)
    with pytest.raises(ValidationError, match="byte budget"):
        FeedbackPacket(
            findings=(valid,), omitted_count=0, truncated=False, byte_budget=1, text="🚀"
        )
    with pytest.raises(ValidationError, match="truncated"):
        FeedbackPacket(
            findings=(), omitted_count=1, truncated=False, byte_budget=100, text="omitted"
        )


def test_feedback_finding_honors_effective_settings_byte_limits() -> None:
    import pytest
    from pydantic import ValidationError

    settings = Settings(
        max_finding_summary_bytes=4,
        max_finding_evidence_bytes=4,
        max_group_key_bytes=4,
        max_config_pattern_bytes=16,
    )
    base = {
        "category": "assertion",
        "path": "a.py",
        "line": 1,
        "summary": "four",
        "evidence": "four",
        "group_key": "four",
        "occurrences": 1,
    }
    assert FeedbackFinding.model_validate(base, context={"settings": settings}).summary == "four"

    for field, value in (
        ("summary", "🚀x"),
        ("evidence", "🚀x"),
        ("group_key", "🚀x"),
        ("path", "a" * 17),
    ):
        with pytest.raises(ValidationError, match=field):
            FeedbackFinding.model_validate(
                base | {field: value}, context={"settings": settings}
            )
