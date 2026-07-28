from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from pyquality.domain.models import Action, PolicyOutcome
from pyquality.policy import PolicyEngine


def _patch_for(path: str, *, deleted: bool = False) -> str:
    new_header = "/dev/null" if deleted else f"b/{path}"
    return (
        f"--- a/{path}\n+++ {new_header}\n@@ -1,2 +1,1 @@\n context\n-old\n"
        if deleted
        else f"--- a/{path}\n+++ {new_header}\n@@ -1,2 +1,2 @@\n context\n-old\n+new\n"
    )


def _patch_for_files(count: int) -> str:
    chunks: list[str] = []
    for index in range(count):
        path = f"src/file_{index}.py"
        chunks.extend((f"--- a/{path}", f"+++ b/{path}", "@@ -1,2 +1,2 @@", " context", "-old", "+new"))
    return "\n".join(chunks) + "\n"


def _symlink_or_skip(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError as error:
        if getattr(error, "winerror", None) == 1314:
            pytest.skip(f"symlinks are unavailable in this test environment: {error}")
        raise


def _valid_patch(path: str = "src/module.py") -> str:
    return f"--- a/{path}\n+++ b/{path}\n@@ -1,2 +1,2 @@\n context\n-old\n+new\n"


@pytest.mark.parametrize("path", ["../outside.txt", ".env", "id_rsa", ".git/config"])
def test_denies_escape_and_sensitive_reads(tmp_path: Path, path: str) -> None:
    """Removing boundary or secret rules would expose files outside safe inspection."""
    action = Action(kind="read_file", arguments={"path": path}, rationale="Inspect it.")

    decision = PolicyEngine(tmp_path).evaluate(action)

    assert decision.outcome is PolicyOutcome.DENY


def test_denies_a_read_through_an_existing_symlink_that_escapes_root(
    tmp_path: Path, tmp_path_factory: pytest.TempPathFactory
) -> None:
    """Resolving only lexical paths would let an in-repository link disclose outside data."""
    outside = tmp_path_factory.mktemp("outside")
    _symlink_or_skip(tmp_path / "link", outside)
    action = Action(kind="read_file", arguments={"path": "link/secret"}, rationale="Inspect it.")

    decision = PolicyEngine(tmp_path).evaluate(action)

    assert decision.outcome is PolicyOutcome.DENY


def test_denies_a_new_patch_path_beneath_a_symlinked_parent_that_escapes_root(
    tmp_path: Path, tmp_path_factory: pytest.TempPathFactory
) -> None:
    """Checking only existing patch files would let new files escape through a linked parent."""
    outside = tmp_path_factory.mktemp("outside")
    _symlink_or_skip(tmp_path / "generated", outside)
    action = Action(
        kind="apply_patch",
        arguments={"patch": _patch_for("generated/new.py")},
        rationale="Add the generated module.",
    )

    decision = PolicyEngine(tmp_path).evaluate(action)

    assert decision.outcome is PolicyOutcome.DENY


def test_broad_patch_requires_approval(tmp_path: Path) -> None:
    """Reducing the file-count gate would apply a broad change without human review."""
    action = Action(
        kind="apply_patch",
        arguments={"patch": _patch_for_files(11)},
        rationale="Repair the related modules.",
    )

    decision = PolicyEngine(tmp_path).evaluate(action)

    assert decision.outcome is PolicyOutcome.REQUIRE_APPROVAL
    assert decision.matched_rule == "broad_patch"


def test_patch_over_three_hundred_changed_lines_requires_approval(tmp_path: Path) -> None:
    """Ignoring the total-line gate would allow a high-impact patch automatically."""
    patch = (
        "--- a/src/large.py\n+++ b/src/large.py\n@@ -1,302 +1,302 @@\n context\n"
        + "\n".join("-old" for _ in range(301))
        + "\n"
        + "\n".join("+new" for _ in range(301))
        + "\n"
    )
    action = Action(kind="apply_patch", arguments={"patch": patch}, rationale="Repair it.")

    decision = PolicyEngine(tmp_path).evaluate(action)

    assert decision.outcome is PolicyOutcome.REQUIRE_APPROVAL
    assert decision.matched_rule == "broad_patch"


@pytest.mark.parametrize(
    "path", ["pyproject.toml", ".github/workflows/check.yml", ".GITHUB/WORKFLOWS/check.yml", ".CircleCI/config.yml"]
)
def test_dependency_and_ci_patch_requires_approval(tmp_path: Path, path: str) -> None:
    """Dropping protected-path classification would alter dependencies or CI unattended."""
    action = Action(
        kind="apply_patch", arguments={"patch": _patch_for(path)}, rationale="Update it."
    )

    decision = PolicyEngine(tmp_path).evaluate(action)

    assert decision.outcome is PolicyOutcome.REQUIRE_APPROVAL
    assert decision.matched_rule == "protected_patch_path"


@pytest.mark.parametrize(
    "patch",
    [
        "*** Update File: src/module.py\n@@\n+new\n",
        "--- a/src/module.py\n+++ b/src/module.py\n",
        "--- a/src/module.py\n+++ b/src/module.py\n@@ -1,2 +1,1 @@\n context\n-old\n+new\n",
        '--- "a/src/module.py"\n+++ "b/src/module.py"\n@@ -1,2 +1,2 @@\n context\n-old\n+new\n',
        "--- a/src/has space.py\n+++ b/src/has space.py\n@@ -1,2 +1,2 @@\n context\n-old\n+new\n",
    ],
)
def test_denies_malformed_or_contextless_patch_before_approval(tmp_path: Path, patch: str) -> None:
    """Permissive patch scanning would let malformed targets bypass governance classification."""
    action = Action(kind="apply_patch", arguments={"patch": patch}, rationale="Apply the repair.")

    decision = PolicyEngine(tmp_path).evaluate(action)

    assert decision.outcome is PolicyOutcome.DENY
    assert decision.matched_rule == "malformed_patch"


def test_allows_a_valid_contextual_unified_patch(tmp_path: Path) -> None:
    """Rejecting valid contextual unified diffs would block ordinary repository repairs."""
    action = Action(kind="apply_patch", arguments={"patch": _valid_patch()}, rationale="Apply it.")

    decision = PolicyEngine(tmp_path).evaluate(action)

    assert decision.outcome is PolicyOutcome.ALLOW


def test_symlink_helper_reraises_errors_other_than_missing_windows_privilege(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Skipping arbitrary symlink failures would conceal broken test environments."""
    def raise_access_denied(self: Path, target: Path, target_is_directory: bool = False) -> None:
        del self, target, target_is_directory
        raise OSError("access denied")

    monkeypatch.setattr(Path, "symlink_to", raise_access_denied)

    with pytest.raises(BaseException) as raised:
        _symlink_or_skip(tmp_path / "link", tmp_path / "target")

    assert isinstance(raised.value, OSError)
    assert "access denied" in str(raised.value)


def test_repository_file_deletion_requires_approval(tmp_path: Path) -> None:
    """Treating file removal as an ordinary patch would make destructive changes automatic."""
    action = Action(
        kind="apply_patch",
        arguments={"patch": _patch_for("src/obsolete.py", deleted=True)},
        rationale="Remove the obsolete module.",
    )

    decision = PolicyEngine(tmp_path).evaluate(action)

    assert decision.outcome is PolicyOutcome.REQUIRE_APPROVAL
    assert decision.matched_rule == "file_deletion"


def test_denial_outranks_a_patch_approval_rule(tmp_path: Path) -> None:
    """Applying approval before denial would permit a sensitive file change after consent."""
    action = Action(
        kind="apply_patch",
        arguments={"patch": _patch_for(".github/workflows/secret.pem")},
        rationale="Update it.",
    )

    decision = PolicyEngine(tmp_path).evaluate(action)

    assert decision.outcome is PolicyOutcome.DENY


def test_policy_digest_is_canonical_utf8_sorted_compact_action_json(tmp_path: Path) -> None:
    """Changing serialization would break action-bound approval comparisons across processes."""
    action = Action(
        kind="search_text",
        arguments={"path": "src", "pattern": "é"},
        rationale="Find the marker.",
    )
    expected = hashlib.sha256(
        json.dumps(
            {
                "arguments": {"path": "src", "pattern": "é"},
                "kind": "search_text",
                "rationale": "Find the marker.",
            },
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()

    decision = PolicyEngine(tmp_path).evaluate(action)

    assert decision.action_digest == expected


def test_revalidation_rechecks_the_supplied_action_after_a_symlink_changes(tmp_path: Path) -> None:
    """Reusing the old allow decision would race a later symlink escape before dispatch."""
    safe = tmp_path / "safe"
    safe.mkdir()
    action = Action(kind="read_file", arguments={"path": "safe/target.txt"}, rationale="Inspect it.")
    policy = PolicyEngine(tmp_path)
    original = policy.evaluate(action)
    outside = tmp_path.parent / "outside"
    outside.mkdir(exist_ok=True)
    safe.rmdir()
    _symlink_or_skip(safe, outside)

    current_snapshot = policy.evaluate(action).repository_snapshot_digest
    refreshed = policy.revalidate(original, action, current_snapshot)

    assert original.outcome is PolicyOutcome.ALLOW
    assert refreshed.outcome is PolicyOutcome.DENY
    assert refreshed.action_digest == original.action_digest


def test_revalidation_denies_a_different_action_with_the_saved_snapshot(tmp_path: Path) -> None:
    """Trusting a decision for a different action would allow approval replay."""
    policy = PolicyEngine(tmp_path)
    original_action = Action(kind="finish", arguments={}, rationale="Finish verification.")
    changed_action = Action(kind="run_quality", arguments={}, rationale="Run verification.")
    decision = policy.evaluate(original_action)

    refreshed = policy.revalidate(decision, changed_action, decision.repository_snapshot_digest)

    assert refreshed.outcome is PolicyOutcome.DENY
    assert refreshed.matched_rule == "action_digest_mismatch"


def test_revalidation_denies_a_changed_repository_snapshot(tmp_path: Path) -> None:
    """Ignoring the supplied current snapshot would dispatch an approval after repository drift."""
    action = Action(kind="finish", arguments={}, rationale="Finish verification.")
    policy = PolicyEngine(tmp_path)
    decision = policy.evaluate(action)

    refreshed = policy.revalidate(decision, action, "0" * 64)

    assert refreshed.outcome is PolicyOutcome.DENY
    assert refreshed.matched_rule == "repository_snapshot_drift"


def test_revalidation_denies_a_policy_change_before_dispatch(tmp_path: Path) -> None:
    """A changed filesystem policy result must not reuse the earlier allow decision."""
    target = tmp_path / "module.py"
    target.write_text("value = 1\n", encoding="utf-8")
    action = Action(kind="read_file", arguments={"path": "module.py"}, rationale="Inspect it.")
    policy = PolicyEngine(tmp_path)
    decision = policy.evaluate(action)
    target.write_text("value = 2\n", encoding="utf-8")
    current_snapshot = policy.evaluate(action).repository_snapshot_digest

    refreshed = policy.revalidate(decision, action, current_snapshot)

    assert refreshed.outcome is PolicyOutcome.DENY
    assert refreshed.matched_rule == "repository_snapshot_drift"
