from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from pyquality.domain.models import CheckStatus, Finding, QualityReport, TaskStatus
from pyquality.feedback import (
    ProgressEntry,
    ProgressTracker,
    failure_fingerprint,
)

NOW = datetime(2026, 7, 28, tzinfo=UTC)


def report(*, success: bool = False) -> QualityReport:
    status = CheckStatus.PASSED if success else CheckStatus.FAILED
    return QualityReport(
        targeted_pytest_status=CheckStatus.NOT_RUN,
        full_pytest_status=status,
        ruff_status=status,
    )


def entry(
    fingerprint: str,
    relevant_digest: str = "same",
    *,
    success: bool = False,
    blocked: bool = False,
    failed: bool = False,
) -> ProgressEntry:
    return ProgressEntry(
        fingerprint=fingerprint,
        relevant_digest=relevant_digest,
        report=report(success=success),
        blocked=blocked,
        failed=failed,
    )


def test_fingerprint_ignores_temp_paths_timings_evidence_and_input_order() -> None:
    one = SimpleNamespace(
        category="assertion", path="C:/Temp/a.py", line=2,
        group_key="C:/Temp/a.py failed in 0.21s", evidence="first timing 0.21s",
    )
    two = SimpleNamespace(
        category="assertion", path="D:/tmp/b.py", line=2,
        group_key="D:/tmp/b.py failed in 1.90s", evidence="second timing 1.90s",
    )
    stable = SimpleNamespace(
        category="ruff", path="src/z.py", line=3, group_key="ruff:E501", evidence="x",
    )

    assert failure_fingerprint((one, stable)) == failure_fingerprint((stable, two))


def test_fingerprint_is_sha256_and_changes_for_normalized_tuple() -> None:
    finding = Finding(
        source="pytest", category="assertion", severity="error", path="tests/a.py",
        line=1, summary="bad", evidence="timing 0.1s", group_key="assert:a",
    )
    changed = finding.model_copy(update={"line": 2})

    digest = failure_fingerprint((finding,))

    assert len(digest) == 64
    assert digest != failure_fingerprint((changed,))


def test_fingerprint_preserves_relative_path_case_and_repository_tmp_components() -> None:
    def item(path: str):
        return SimpleNamespace(
            category="assertion", path=path, line=1, group_key="assertion", evidence="x"
        )

    assert failure_fingerprint((item("src/A.py"),)) != failure_fingerprint((item("src/a.py"),))
    assert failure_fingerprint((item("src/tmp/a.py"),)) != failure_fingerprint(
        (item("src/tmp/b.py"),)
    )


def test_fingerprint_only_collapses_drive_qualified_volatile_temp_paths() -> None:
    def item(path: str, group_key: str):
        return SimpleNamespace(
            category="assertion", path=path, line=1, group_key=group_key, evidence="x"
        )

    windows = item("C:/Temp/a.py", "failed C:/Temp/a.py in 0.21s")
    other_windows = item("D:/tmp/b.py", "failed D:/tmp/b.py in 1.90s")
    relative = item("Temp/a.py", "failed Temp/a.py in 0.21s")

    assert failure_fingerprint((windows,)) == failure_fingerprint((other_windows,))
    assert failure_fingerprint((windows,)) != failure_fingerprint((relative,))


def test_fingerprint_collapses_only_explicit_platform_temp_roots() -> None:
    def item(path: str):
        return SimpleNamespace(
            category="assertion", path=path, line=1, group_key=f"failed {path}", evidence="x"
        )

    assert failure_fingerprint((item("/tmp/a.py"),)) == failure_fingerprint(
        (item("/tmp/b.py"),)
    )
    assert failure_fingerprint((item("C:/Temp/a.py"),)) == failure_fingerprint(
        (item("D:/tmp/b.py"),)
    )
    assert failure_fingerprint((item("C:/repo/tmp/a.py"),)) != failure_fingerprint(
        (item("D:/other/tmp/b.py"),)
    )
    assert failure_fingerprint((item("src/tmp/A.py"),)) != failure_fingerprint(
        (item("src/tmp/a.py"),)
    )


def test_fingerprint_structurally_normalizes_only_repository_relative_paths() -> None:
    def item(path: str):
        return SimpleNamespace(
            category="assertion", path=path, line=1, group_key="stable", evidence="x"
        )

    assert failure_fingerprint((item("./src/a.py"),)) == failure_fingerprint(
        (item("src/a.py"),)
    )
    assert failure_fingerprint((item("src//tmp/a.py"),)) != failure_fingerprint(
        (item("src//tmp/b.py"),)
    )
    assert failure_fingerprint((item("src//A.py"),)) != failure_fingerprint(
        (item("src/a.py"),)
    )
    assert failure_fingerprint((item("/tmp/a.py"),)) == failure_fingerprint(
        (item("/tmp/b.py"),)
    )

    embedded_a = SimpleNamespace(
        category="assertion", path="src//tmp/a.py", line=1,
        group_key="failed src//tmp/a.py", evidence="x",
    )
    embedded_b = SimpleNamespace(
        category="assertion", path="src//tmp/b.py", line=1,
        group_key="failed src//tmp/b.py", evidence="x",
    )
    assert failure_fingerprint((embedded_a,)) != failure_fingerprint((embedded_b,))


def test_success_has_highest_precedence() -> None:
    history = [entry("abc", success=True, blocked=True, failed=True)]
    assert ProgressTracker().decide(history, 1, NOW - timedelta(seconds=1), NOW) is TaskStatus.SUCCEEDED


def test_blocked_precedes_stall_and_budget() -> None:
    history = [entry("abc", blocked=True), entry("abc", blocked=True)]
    assert ProgressTracker().decide(history, 2, NOW - timedelta(seconds=1), NOW) is TaskStatus.BLOCKED


def test_same_failure_twice_without_relevant_change_stalls() -> None:
    history = [entry("abc", "one"), entry("abc", "one")]
    assert ProgressTracker().decide(history, 8, NOW + timedelta(seconds=1), NOW) is TaskStatus.STALLED


def test_unrelated_change_does_not_count_as_progress() -> None:
    history = [
        entry("abc", "one").model_copy(update={"all_digest": "x"}),
        entry("abc", "one").model_copy(update={"all_digest": "y"}),
    ]
    assert ProgressTracker().decide(history, 8, NOW + timedelta(seconds=1), NOW) is TaskStatus.STALLED


def test_relevant_change_prevents_stall() -> None:
    history = [entry("abc", "one"), entry("abc", "two")]
    assert ProgressTracker().decide(history, 8, NOW + timedelta(seconds=1), NOW) is None


def test_round_or_deadline_exhaustion_is_budget_exhausted() -> None:
    tracker = ProgressTracker()
    assert tracker.decide([entry("a"), entry("b")], 2, NOW + timedelta(seconds=1), NOW) is TaskStatus.BUDGET_EXHAUSTED
    assert tracker.decide([entry("a")], 8, NOW, NOW) is TaskStatus.BUDGET_EXHAUSTED


def test_internal_failure_follows_budget_precedence_and_empty_history_continues() -> None:
    tracker = ProgressTracker()
    assert tracker.decide([entry("a", failed=True)], 8, NOW + timedelta(seconds=1), NOW) is TaskStatus.FAILED
    assert tracker.decide([entry("a", failed=True)], 1, NOW + timedelta(seconds=1), NOW) is TaskStatus.BUDGET_EXHAUSTED
    assert tracker.decide([], 8, None, NOW) is None


def test_rejects_invalid_round_limit_and_mismatched_timezone_awareness() -> None:
    import pytest

    with pytest.raises(ValueError, match="round_limit"):
        ProgressTracker().decide([], 0, None, NOW)
    with pytest.raises(ValueError, match="timezone"):
        ProgressTracker().decide([], 8, NOW.replace(tzinfo=None), NOW)
