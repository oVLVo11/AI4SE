from __future__ import annotations

import pytest

from pyquality.domain.models import (
    Action,
    AuditEvent,
    CheckStatus,
    Finding,
    PolicyDecision,
    PolicyOutcome,
    QualityReport,
    TaskResult,
    TaskStatus,
    ToolResult,
)


def test_action_rejects_unknown_kind() -> None:
    """Changing the allowed action kinds to admit arbitrary shell execution is a bug."""
    with pytest.raises(ValueError):
        Action.model_validate({"kind": "shell", "command": "whoami"})


def test_finding_has_stable_required_shape() -> None:
    """Removing a normalized finding field would break quality-feedback consumers."""
    item = Finding(
        source="pytest",
        category="assertion",
        severity="error",
        path="tests/test_math.py",
        line=8,
        summary="1 != 2",
        evidence="E assert 1 == 2",
        group_key="assert:test_math:8",
    )

    assert item.category == "assertion"
    assert TaskStatus.SUCCEEDED.value == "succeeded"


def test_action_rejects_arguments_for_a_different_tool() -> None:
    """Allowing apply-patch data on a read action would bypass the typed action boundary."""
    with pytest.raises(ValueError):
        Action.model_validate(
            {
                "kind": "read_file",
                "arguments": {"patch": "*** Begin Patch"},
                "rationale": "Inspect the target file.",
            }
        )


def test_finding_rejects_a_line_without_a_repository_path() -> None:
    """A location with no path cannot be resolved by a quality-feedback consumer."""
    with pytest.raises(ValueError):
        Finding(
            source="ruff",
            category="ruff",
            severity="error",
            line=4,
            summary="Unused import.",
            evidence="F401",
            group_key="ruff:f401",
        )


def test_quality_success_requires_full_pytest_and_ruff_to_pass() -> None:
    """Treating a targeted test pass as full success would permit an unsafe finish."""
    report = QualityReport(
        targeted_pytest_status=CheckStatus.PASSED,
        full_pytest_status=CheckStatus.FAILED,
        ruff_status=CheckStatus.PASSED,
    )

    assert report.succeeded is False


def test_task_result_rejects_a_non_result_running_status() -> None:
    """Returning a running task as a result would violate resume's terminal contract."""
    with pytest.raises(ValueError):
        TaskResult(
            task_id="task-1",
            status=TaskStatus.RUNNING,
            iterations=1,
            verification_summary="Still working.",
        )


def test_policy_decision_has_a_closed_outcome() -> None:
    """An unknown policy outcome would let callers skip required approval handling."""
    with pytest.raises(ValueError):
        PolicyDecision(
            outcome="defer",
            matched_rule=None,
            impact_summary="Needs a decision.",
            action_digest="a" * 64,
        )

    assert PolicyOutcome.REQUIRE_APPROVAL.value == "require_approval"


def test_tool_result_rejects_digests_for_unchanged_paths() -> None:
    """A digest for an unrelated file would corrupt progress-stall detection."""
    with pytest.raises(ValueError):
        ToolResult(
            effect_kind="apply_patch",
            code_changed=True,
            changed_paths=("src/math.py",),
            after_digests={"src/other.py": "b" * 64},
        )


def test_audit_event_rejects_undeclared_metadata_fields() -> None:
    """Undeclared audit fields could accidentally carry unredacted prompt data."""
    with pytest.raises(ValueError):
        AuditEvent(event_type="model", metadata={}, prompt="secret source")
