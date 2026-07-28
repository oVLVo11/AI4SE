from __future__ import annotations

import hashlib
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


def _dispatcher(repo: Path) -> ToolDispatcher:
    return ToolDispatcher(repo, PolicyEngine(repo), SubprocessRunner(), Settings())


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
