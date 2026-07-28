from __future__ import annotations

import hashlib
from collections.abc import Callable
from pathlib import Path

import pytest

from pyquality.config import Settings
from pyquality.domain.models import Action, PolicyOutcome
from pyquality.policy import PolicyEngine, parse_validated_patch
from pyquality.tools import SubprocessRunner, ToolDispatcher


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    (tmp_path / "a.py").write_text("context\nold\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("context\nold\n", encoding="utf-8")
    return tmp_path


def _action(patch: str) -> Action:
    return Action(kind="apply_patch", arguments={"patch": patch}, rationale="Apply repair.")


def _dispatcher(repo: Path, pre_commit_hook: Callable[[], None] | None = None) -> ToolDispatcher:
    return ToolDispatcher(repo, PolicyEngine(repo), SubprocessRunner(), Settings(), pre_commit_hook)


def _dispatch(repo: Path, action: Action):
    decision = PolicyEngine(repo).evaluate(action)
    assert decision.outcome is PolicyOutcome.ALLOW
    return _dispatcher(repo).dispatch(action, decision, decision.repository_snapshot_digest)


def test_patch_rejects_missing_context(repo: Path) -> None:
    """Applying a syntactically valid but stale hunk would overwrite unrelated source text."""
    action = _action("--- a/a.py\n+++ b/a.py\n@@ -1,2 +1,2 @@\n context\n-nope\n+fixed\n")

    result = _dispatch(repo, action)

    assert result.ok is False
    assert result.code == "patch_context_mismatch"


def test_patch_is_atomic_across_multiple_files(repo: Path) -> None:
    """Writing an early matching hunk before a later mismatch would leave a partial patch applied."""
    before = (repo / "a.py").read_bytes()
    patch = (
        "--- a/a.py\n+++ b/a.py\n@@ -1,2 +1,2 @@\n context\n-old\n+new\n"
        "--- a/b.py\n+++ b/b.py\n@@ -1,2 +1,2 @@\n context\n-missing\n+new\n"
    )
    action = _action(patch)

    result = _dispatch(repo, action)

    assert result.ok is False
    assert result.code == "patch_context_mismatch"
    assert (repo / "a.py").read_bytes() == before


def test_patch_applies_the_policy_parser_result_and_records_content_digests(repo: Path) -> None:
    """Divergent policy and dispatcher parsers could authorize a different patch than the one applied."""
    patch = "--- a/a.py\n+++ b/a.py\n@@ -1,2 +1,2 @@\n context\n-old\n+new\n"
    action = _action(patch)
    parsed = parse_validated_patch(patch)
    before = (repo / "a.py").read_bytes()

    result = _dispatch(repo, action)

    assert parsed is not None
    assert (repo / "a.py").read_text(encoding="utf-8") == "context\nnew\n"
    assert result.changed_paths == ("a.py",)
    assert result.before_digests == {"a.py": hashlib.sha256(before).hexdigest()}
    assert result.after_digests == {"a.py": hashlib.sha256((repo / "a.py").read_bytes()).hexdigest()}
    assert result.ok is True


def test_parser_rejects_duplicate_file_sections_before_any_target_write(repo: Path) -> None:
    """Accepting a duplicate file section could apply a later hunk to a changed intermediate snapshot."""
    before = (repo / "a.py").read_bytes()
    patch = (
        "--- a/a.py\n+++ b/a.py\n@@ -1,2 +1,2 @@\n context\n-old\n+new\n"
        "--- a/a.py\n+++ b/a.py\n@@ -1,2 +1,2 @@\n context\n-old\n+other\n"
    )
    action = _action(patch)
    decision = PolicyEngine(repo).evaluate(action)

    result = _dispatcher(repo).dispatch(action, decision, decision.repository_snapshot_digest)

    assert parse_validated_patch(patch) is None
    assert (result.ok, result.code) == (False, "policy_denied")
    assert (repo / "a.py").read_bytes() == before


def test_patch_rejects_no_newline_marker_and_target_without_final_newline(repo: Path) -> None:
    """A grammar that guesses EOF state can silently alter final-line semantics."""
    marker_patch = "--- a/a.py\n+++ b/a.py\n@@ -1,2 +1,2 @@\n context\n-old\n+new\n\\ No newline at end of file\n"
    assert parse_validated_patch(marker_patch) is None
    (repo / "a.py").write_bytes(b"context\nold")
    patch = "--- a/a.py\n+++ b/a.py\n@@ -1,2 +1,2 @@\n context\n-old\n+new\n"
    action = _action(patch)

    result = _dispatch(repo, action)

    assert (result.ok, result.code) == (False, "patch_target_missing_final_newline")
    assert (repo / "a.py").read_bytes() == b"context\nold"


@pytest.mark.parametrize("ending", [b"\n", b"\r\n"])
def test_patch_preserves_the_existing_line_ending_style(repo: Path, ending: bytes) -> None:
    """Normalizing CRLF patches to LF would create unrelated whole-file changes."""
    before = b"context" + ending + b"old" + ending
    (repo / "a.py").write_bytes(before)
    patch = "--- a/a.py\n+++ b/a.py\n@@ -1,2 +1,2 @@\n context\n-old\n+new\n"

    result = _dispatch(repo, _action(patch))

    assert result.ok is True
    assert (repo / "a.py").read_bytes() == b"context" + ending + b"new" + ending


def test_patch_aborts_when_target_changes_after_preparation(repo: Path) -> None:
    """Replacing a file after a stale snapshot check would overwrite a concurrent edit."""
    patch = "--- a/a.py\n+++ b/a.py\n@@ -1,2 +1,2 @@\n context\n-old\n+new\n"
    action = _action(patch)
    decision = PolicyEngine(repo).evaluate(action)

    def replace_target() -> None:
        (repo / "a.py").write_text("concurrent\n", encoding="utf-8")

    result = _dispatcher(repo, replace_target).dispatch(action, decision, decision.repository_snapshot_digest)

    assert (result.ok, result.code) == (False, "patch_target_changed")
    assert (repo / "a.py").read_text(encoding="utf-8") == "concurrent\n"


def test_patch_aborts_when_target_parent_becomes_an_outside_symlink(
    repo: Path, tmp_path_factory: pytest.TempPathFactory
) -> None:
    """Rechecking only file contents would permit a late parent symlink swap outside the repository."""
    nested = repo / "nested"
    nested.mkdir()
    target = nested / "a.py"
    target.write_text("context\nold\n", encoding="utf-8")
    outside = tmp_path_factory.mktemp("outside")
    outside_target = outside / "a.py"
    outside_target.write_text("outside\n", encoding="utf-8")
    patch = "--- a/nested/a.py\n+++ b/nested/a.py\n@@ -1,2 +1,2 @@\n context\n-old\n+new\n"
    action = _action(patch)
    decision = PolicyEngine(repo).evaluate(action)

    def swap_parent() -> None:
        target.unlink()
        nested.rmdir()
        try:
            nested.symlink_to(outside, target_is_directory=True)
        except OSError as error:
            if getattr(error, "winerror", None) == 1314:
                pytest.skip(f"symlinks are unavailable in this test environment: {error}")
            raise

    result = _dispatcher(repo, swap_parent).dispatch(action, decision, decision.repository_snapshot_digest)

    assert (result.ok, result.code) == (False, "patch_target_changed")
    assert outside_target.read_text(encoding="utf-8") == "outside\n"
