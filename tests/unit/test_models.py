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
            repository_snapshot_digest="b" * 64,
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


def test_action_schema_exposes_kind_as_a_discriminator() -> None:
    """A generic arguments dictionary would let generated clients send invalid action shapes."""
    schema = Action.model_json_schema()

    assert schema.get("discriminator", {}).get("propertyName") == "kind"


def test_action_normalizes_a_kind_specific_argument_model() -> None:
    """Losing the typed argument model would admit unknown keys for a valid action kind."""
    action = Action.model_validate(
        {
            "kind": "read_file",
            "arguments": {"path": "src/pyquality/config.py"},
            "rationale": "Inspect the configuration loader.",
        }
    )

    assert action.arguments == {"path": "src/pyquality/config.py"}


def test_action_rejects_a_rationale_over_the_utf8_byte_limit() -> None:
    """Counting characters instead of UTF-8 bytes would exceed the configured prompt boundary."""
    with pytest.raises(ValueError):
        Action(
            kind="finish",
            arguments={},
            rationale="é" * 2_049,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("summary", "é" * 513),
        ("evidence", "é" * 2_049),
        ("group_key", "é" * 257),
    ],
)
def test_finding_rejects_fields_over_their_utf8_byte_limits(field: str, value: str) -> None:
    """Oversized finding text would exceed the configured feedback storage budget."""
    finding = {
        "source": "pytest",
        "category": "assertion",
        "severity": "error",
        "path": "tests/test_math.py",
        "line": 8,
        "summary": "failure",
        "evidence": "assert 1 == 2",
        "group_key": "assert:math:8",
    }
    finding[field] = value

    with pytest.raises(ValueError):
        Finding.model_validate(finding)


def test_action_rejects_arguments_over_the_utf8_byte_limit() -> None:
    """An oversized patch payload would exceed the action argument budget before dispatch."""
    with pytest.raises(ValueError):
        Action(
            kind="apply_patch",
            arguments={"patch": "x" * 65_525},
            rationale="Apply the requested patch.",
        )


def test_tool_result_rejects_output_and_metadata_over_their_byte_limits() -> None:
    """Unbounded tool output or metadata would bypass persisted-result size limits."""
    with pytest.raises(ValueError):
        ToolResult(
            effect_kind="read_file",
            code_changed=False,
            evidence="x" * 65_537,
        )

    with pytest.raises(ValueError):
        ToolResult(
            effect_kind="read_file",
            code_changed=False,
            normalized_metadata={"key": "x" * 16_376},
        )


@pytest.mark.parametrize("path", ["", "/src/math.py", "../src/math.py", "src\\math.py"])
def test_tool_result_rejects_non_normalized_changed_paths(path: str) -> None:
    """A non-relative changed path could make digest-based progress tracking escape the repository."""
    with pytest.raises(ValueError):
        ToolResult(effect_kind="apply_patch", code_changed=True, changed_paths=(path,))


def test_tool_result_rejects_non_normalized_digest_keys() -> None:
    """A digest key outside changed-path normalization would corrupt change attribution."""
    with pytest.raises(ValueError):
        ToolResult(
            effect_kind="apply_patch",
            code_changed=True,
            changed_paths=("src/math.py",),
            after_digests={"../outside.py": "a" * 64},
        )


def test_finding_rejects_an_empty_path() -> None:
    """An empty path cannot identify a repository file for a finding location."""
    with pytest.raises(ValueError):
        Finding(
            source="pytest",
            category="assertion",
            severity="error",
            path="",
            summary="failure",
            evidence="assert 1 == 2",
            group_key="assert:math",
        )


def test_policy_digest_normalizes_uppercase_hex_and_rejects_non_hex() -> None:
    """A malformed or inconsistently cased digest would break policy and approval comparisons."""
    decision = PolicyDecision(
        outcome="allow",
        impact_summary="Read-only inspection.",
        action_digest="A" * 64,
        repository_snapshot_digest="B" * 64,
    )

    assert decision.action_digest == "a" * 64
    assert decision.repository_snapshot_digest == "b" * 64
    with pytest.raises(ValueError):
        PolicyDecision(
            outcome="allow",
            impact_summary="Read-only inspection.",
            action_digest="g" * 64,
            repository_snapshot_digest="b" * 64,
        )


def test_policy_decision_requires_a_canonical_repository_snapshot_digest() -> None:
    """Omitting or corrupting the saved snapshot would make approval drift uncheckable."""
    with pytest.raises(ValueError):
        PolicyDecision(
            outcome="allow",
            impact_summary="Read-only inspection.",
            action_digest="a" * 64,
        )
    decision = PolicyDecision(
        outcome="allow",
        impact_summary="Read-only inspection.",
        action_digest="a" * 64,
        repository_snapshot_digest="B" * 64,
    )

    assert decision.repository_snapshot_digest == "b" * 64


def test_action_schema_contains_real_union_mapping() -> None:
    """A marker-only discriminator would still leave generated clients without variant schemas."""
    schema = Action.model_json_schema()

    assert len(schema.get("oneOf", [])) == 6
    assert set(schema["discriminator"]["mapping"]) == {
        "read_file", "search_text", "list_files", "apply_patch", "run_quality", "finish"
    }


@pytest.mark.parametrize(
    "payload",
    [
        {"kind": "read_file", "arguments": {"path": "src/a.py"}, "rationale": "Read it."},
        {"kind": "search_text", "arguments": {"pattern": "TODO"}, "rationale": "Search it."},
        {"kind": "list_files", "arguments": {}, "rationale": "List it."},
        {"kind": "apply_patch", "arguments": {"patch": "*** Begin Patch"}, "rationale": "Patch it."},
        {"kind": "run_quality", "arguments": {}, "rationale": "Verify it."},
        {"kind": "finish", "arguments": {}, "rationale": "Finish it."},
    ],
)
def test_action_union_validates_every_kind(payload: dict[str, object]) -> None:
    """Removing a union variant would make its legal action unavailable to dispatch."""
    assert Action.model_validate(payload).kind == payload["kind"]


def test_action_union_rejects_cross_kind_arguments_at_envelope_validation() -> None:
    """A patch argument on a read-file envelope must not validate as a generic action."""
    with pytest.raises(ValueError):
        Action.model_validate(
            {"kind": "read_file", "arguments": {"patch": "*** Begin Patch"}, "rationale": "Read it."}
        )


def test_action_constructor_properties_and_dump_remain_compatible() -> None:
    """Changing the union representation must not break existing action consumers."""
    action = Action(kind="read_file", arguments={"path": "src/a.py"}, rationale="Read it.")

    assert (action.kind, action.arguments, action.rationale) == (
        "read_file", {"path": "src/a.py"}, "Read it."
    )
    assert action.model_dump() == {
        "kind": "read_file", "arguments": {"path": "src/a.py"}, "rationale": "Read it."
    }


def test_model_context_enforces_lowered_settings_caps(tmp_path) -> None:
    """Ignoring supplied settings would let repository-lowered input limits be bypassed."""
    from pyquality.config import load_settings

    (tmp_path / "pyquality.toml").write_text(
        "max_rationale_bytes = 4\nmax_config_pattern_bytes = 16\n", encoding="utf-8"
    )
    settings = load_settings(tmp_path, None)

    assert Action(kind="finish", arguments={}, rationale="hello").rationale == "hello"
    with pytest.raises(ValueError):
        Action.model_validate(
            {"kind": "finish", "arguments": {}, "rationale": "hello"}, context={"settings": settings}
        )
    with pytest.raises(ValueError):
        Finding.model_validate(
            {"source": "pytest", "category": "assertion", "severity": "error", "path": "tests/very-long.py", "summary": "x", "evidence": "x", "group_key": "x"},
            context={"settings": settings},
        )
