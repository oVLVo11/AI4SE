from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from pyquality.config import Settings
from pyquality.domain.models import Action, PolicyDecision, PolicyOutcome
from pyquality.policy import PolicyEngine, parse_validated_patch
from pyquality.tools import CommitObserver, SubprocessRunner, ToolDispatcher


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    (tmp_path / "a.py").write_text("context\nold\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("context\nold\n", encoding="utf-8")
    return tmp_path


def _action(patch: str) -> Action:
    return Action(kind="apply_patch", arguments={"patch": patch}, rationale="Apply repair.")


def _dispatcher(repo: Path, observer: CommitObserver | None = None, policy: object | None = None) -> ToolDispatcher:
    return ToolDispatcher(repo, policy or PolicyEngine(repo), SubprocessRunner(), Settings(), observer)


def _dispatch(repo: Path, action: Action):
    decision = PolicyEngine(repo).evaluate(action)
    assert decision.outcome is PolicyOutcome.ALLOW
    return _dispatcher(repo).dispatch(action, decision, decision.repository_snapshot_digest)


class _AllowPolicy:
    """Approval-aware policy stand-in: task 8 will supply an equivalent boundary."""

    def revalidate(
        self, decision: PolicyDecision, action: Action, current_snapshot_digest: str
    ) -> PolicyDecision:
        del action, current_snapshot_digest
        return decision.model_copy(update={"outcome": PolicyOutcome.ALLOW})


class _ConcurrentObserver:
    def __init__(self, *, after_capture=None, before_install=None) -> None:
        self._after_capture = after_capture
        self._before_install = before_install

    def after_capture(self, path: Path) -> None:
        if self._after_capture is not None:
            self._after_capture(path)

    def before_install_or_delete(self, path: Path, operation: str) -> None:
        if self._before_install is not None:
            self._before_install(path, operation)


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


def test_modify_never_overwrites_a_target_created_after_atomic_capture(repo: Path) -> None:
    """Replacing a target after capture without exclusive install would overwrite a concurrent edit."""
    patch = "--- a/a.py\n+++ b/a.py\n@@ -1,2 +1,2 @@\n context\n-old\n+new\n"
    action = _action(patch)
    decision = PolicyEngine(repo).evaluate(action)

    observer = _ConcurrentObserver(
        after_capture=lambda path: path.write_text("concurrent\n", encoding="utf-8")
    )

    result = _dispatcher(repo, observer).dispatch(action, decision, decision.repository_snapshot_digest)

    assert (result.ok, result.code) == (False, "patch_target_changed")
    assert (repo / "a.py").read_text(encoding="utf-8") == "concurrent\n"


def test_create_never_overwrites_a_target_created_before_exclusive_install(repo: Path) -> None:
    """A create implemented with replace would overwrite a file created in the commit window."""
    patch = "--- /dev/null\n+++ b/new.py\n@@ -0,0 +1 @@\n+created\n"
    action = _action(patch)
    decision = PolicyEngine(repo).evaluate(action)
    observer = _ConcurrentObserver(
        before_install=lambda path, operation: path.write_text("concurrent\n", encoding="utf-8")
        if operation == "create"
        else None
    )

    result = _dispatcher(repo, observer).dispatch(action, decision, decision.repository_snapshot_digest)

    assert (result.ok, result.code) == (False, "patch_target_changed")
    assert (repo / "new.py").read_text(encoding="utf-8") == "concurrent\n"


def test_delete_never_deletes_a_target_created_after_atomic_capture(repo: Path) -> None:
    """Deleting the target name after capture would remove a concurrent replacement object."""
    patch = "--- a/a.py\n+++ /dev/null\n@@ -1,2 +0,0 @@\n-context\n-old\n"
    action = _action(patch)
    decision = PolicyEngine(repo).evaluate(action)
    observer = _ConcurrentObserver(
        after_capture=lambda path: path.write_text("concurrent\n", encoding="utf-8")
    )

    result = _dispatcher(repo, observer, _AllowPolicy()).dispatch(
        action, decision, decision.repository_snapshot_digest
    )

    assert (result.ok, result.code) == (False, "patch_target_changed")
    assert (repo / "a.py").read_text(encoding="utf-8") == "concurrent\n"


def test_normal_create_modify_and_delete_leave_no_commit_artifacts(repo: Path) -> None:
    """Capture backups or temps that survive a successful patch would corrupt later repository scans."""
    modify = _action("--- a/a.py\n+++ b/a.py\n@@ -1,2 +1,2 @@\n context\n-old\n+new\n")
    modify_decision = PolicyEngine(repo).evaluate(modify)
    modified = _dispatcher(repo).dispatch(modify, modify_decision, modify_decision.repository_snapshot_digest)
    created = _action("--- /dev/null\n+++ b/new.py\n@@ -0,0 +1 @@\n+created\n")
    create_decision = PolicyEngine(repo).evaluate(created)
    made = _dispatcher(repo).dispatch(created, create_decision, create_decision.repository_snapshot_digest)
    delete = _action("--- a/new.py\n+++ /dev/null\n@@ -1 +0,0 @@\n-created\n")
    delete_decision = PolicyEngine(repo).evaluate(delete)
    removed = _dispatcher(repo, policy=_AllowPolicy()).dispatch(
        delete, delete_decision, delete_decision.repository_snapshot_digest
    )

    assert (modified.ok, made.ok, removed.ok) == (True, True, True)
    assert (repo / "a.py").read_text(encoding="utf-8") == "context\nnew\n"
    assert not (repo / "new.py").exists()
    assert not list(repo.glob(".pyquality-*"))


def test_multi_file_failure_rolls_back_an_earlier_install(repo: Path) -> None:
    """Leaving an earlier file patched after a later exclusive-install conflict violates all-or-safe semantics."""
    patch = (
        "--- a/a.py\n+++ b/a.py\n@@ -1,2 +1,2 @@\n context\n-old\n+new\n"
        "--- a/b.py\n+++ b/b.py\n@@ -1,2 +1,2 @@\n context\n-old\n+new\n"
    )
    action = _action(patch)
    decision = PolicyEngine(repo).evaluate(action)
    observer = _ConcurrentObserver(
        after_capture=lambda path: path.write_text("concurrent\n", encoding="utf-8")
        if path.name == "b.py"
        else None
    )

    result = _dispatcher(repo, observer).dispatch(action, decision, decision.repository_snapshot_digest)

    assert (result.ok, result.code) == (False, "patch_target_changed")
    assert (repo / "a.py").read_text(encoding="utf-8") == "context\nold\n"
    assert (repo / "b.py").read_text(encoding="utf-8") == "concurrent\n"


def test_incomplete_rollback_reports_affected_paths_without_overwriting_concurrency(repo: Path) -> None:
    """A failed rollback must preserve concurrent content and report that recovery remains incomplete."""
    patch = (
        "--- a/a.py\n+++ b/a.py\n@@ -1,2 +1,2 @@\n context\n-old\n+new\n"
        "--- a/b.py\n+++ b/b.py\n@@ -1,2 +1,2 @@\n context\n-old\n+new\n"
    )
    action = _action(patch)
    decision = PolicyEngine(repo).evaluate(action)

    def before_install(path: Path, operation: str) -> None:
        if path.name == "b.py" and operation == "modify":
            (repo / "a.py").write_text("concurrent-a\n", encoding="utf-8")
            path.write_text("concurrent-b\n", encoding="utf-8")

    result = _dispatcher(repo, _ConcurrentObserver(before_install=before_install)).dispatch(
        action, decision, decision.repository_snapshot_digest
    )

    assert (result.ok, result.code) == (False, "patch_rollback_incomplete")
    assert result.normalized_metadata["affected_paths"] == ["a.py"]
    assert (repo / "a.py").read_text(encoding="utf-8") == "concurrent-a\n"
    assert (repo / "b.py").read_text(encoding="utf-8") == "concurrent-b\n"


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

    def swap_target_for_outside_link(path: Path) -> None:
        try:
            path.symlink_to(outside_target)
        except OSError as error:
            if getattr(error, "winerror", None) == 1314:
                pytest.skip(f"symlinks are unavailable in this test environment: {error}")
            raise

    result = _dispatcher(repo, _ConcurrentObserver(after_capture=swap_target_for_outside_link)).dispatch(
        action, decision, decision.repository_snapshot_digest
    )

    assert (result.ok, result.code) == (False, "patch_target_changed")
    assert outside_target.read_text(encoding="utf-8") == "outside\n"
