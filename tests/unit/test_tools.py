from __future__ import annotations

import sys
from pathlib import Path

import pytest

from pyquality.config import Settings
from pyquality.domain.models import Action, PolicyOutcome
from pyquality.policy import PolicyEngine
from pyquality.tools import SubprocessRunner, ToolDispatcher


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("private\n", encoding="utf-8")
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "lib.py").write_text("ignored\n", encoding="utf-8")
    return tmp_path


def _dispatcher(repo: Path, *, output_limit: int = 64) -> tuple[ToolDispatcher, Settings]:
    policy = PolicyEngine(repo)
    settings = Settings(read_search_result_bytes=output_limit)
    return ToolDispatcher(repo, policy, SubprocessRunner(), settings), settings


def _allowed_decision(repo: Path, action: Action):
    decision = PolicyEngine(repo).evaluate(action)
    assert decision.outcome is PolicyOutcome.ALLOW
    return decision


def test_read_is_bounded_and_marks_truncation(repo: Path) -> None:
    """Removing the byte cap would let one source file exhaust persisted tool output."""
    (repo / "large.py").write_text("茅\n" * 100, encoding="utf-8")
    action = Action(kind="read_file", arguments={"path": "large.py"}, rationale="Read the file.")

    dispatcher, settings = _dispatcher(repo)
    decision = _allowed_decision(repo, action)
    result = dispatcher.dispatch(action, decision, decision.repository_snapshot_digest)

    assert result.truncated is True
    assert len(result.output.encode("utf-8")) <= settings.read_search_result_bytes
    assert result.ok is True


def test_list_ignores_git_and_venv_and_is_sorted(repo: Path) -> None:
    """Dropping exclusions or ordering would disclose control files or destabilize model context."""
    (repo / "z.py").write_text("z\n", encoding="utf-8")
    (repo / "a.py").write_text("a\n", encoding="utf-8")
    action = Action(kind="list_files", arguments={}, rationale="List files.")

    dispatcher, _ = _dispatcher(repo)
    decision = _allowed_decision(repo, action)
    result = dispatcher.dispatch(action, decision, decision.repository_snapshot_digest)

    assert result.output.splitlines() == ["a.py", "z.py"]
    assert ".git/config" not in result.output
    assert ".venv/lib.py" not in result.output


def test_search_returns_bounded_matches_without_a_shell(repo: Path) -> None:
    """Replacing regex search with an unbounded command would leak unbounded repository output."""
    (repo / "a.py").write_text("TODO first\nTODO second\n", encoding="utf-8")
    action = Action(
        kind="search_text", arguments={"pattern": "TODO", "path": "a.py"}, rationale="Find TODOs."
    )

    dispatcher, _ = _dispatcher(repo)
    decision = _allowed_decision(repo, action)
    result = dispatcher.dispatch(action, decision, decision.repository_snapshot_digest)

    assert result.output == "a.py:1:TODO first\na.py:2:TODO second"
    assert result.ok is True


def test_dispatch_rejects_a_stale_allow_decision_before_reading(repo: Path) -> None:
    """Skipping decision revalidation would execute an action after repository drift."""
    (repo / "safe.py").write_text("first\n", encoding="utf-8")
    action = Action(kind="read_file", arguments={"path": "safe.py"}, rationale="Read the file.")
    dispatcher, _ = _dispatcher(repo)
    decision = _allowed_decision(repo, action)
    (repo / "safe.py").write_text("changed\n", encoding="utf-8")

    result = dispatcher.dispatch(action, decision, PolicyEngine(repo).evaluate(action).repository_snapshot_digest)

    assert (result.ok, result.code, result.output) == (False, "policy_denied", "")


def test_dispatch_rejects_a_different_action_with_an_allow_decision(repo: Path) -> None:
    """Not binding the decision digest to its action would authorize a substituted tool effect."""
    (repo / "one.py").write_text("one\n", encoding="utf-8")
    (repo / "two.py").write_text("two\n", encoding="utf-8")
    allowed = Action(kind="read_file", arguments={"path": "one.py"}, rationale="Read one.")
    substituted = Action(kind="read_file", arguments={"path": "two.py"}, rationale="Read two.")
    dispatcher, _ = _dispatcher(repo)
    decision = _allowed_decision(repo, allowed)

    result = dispatcher.dispatch(substituted, decision, decision.repository_snapshot_digest)

    assert (result.ok, result.code, result.output) == (False, "policy_denied", "")


def test_dispatch_leaves_an_approval_required_patch_unmodified(repo: Path) -> None:
    """Executing a REQUIRE_APPROVAL decision would bypass the human authorization gate."""
    (repo / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
    patch = "--- a/pyproject.toml\n+++ b/pyproject.toml\n@@ -1 +1,2 @@\n [project]\n+name = 'x'\n"
    action = Action(kind="apply_patch", arguments={"patch": patch}, rationale="Change dependency config.")
    dispatcher, _ = _dispatcher(repo)
    decision = PolicyEngine(repo).evaluate(action)

    result = dispatcher.dispatch(action, decision, decision.repository_snapshot_digest)

    assert decision.outcome is PolicyOutcome.REQUIRE_APPROVAL
    assert (result.ok, result.code) == (False, "policy_denied")
    assert (repo / "pyproject.toml").read_text(encoding="utf-8") == "[project]\n"


def test_process_runner_reports_timeout_and_combined_output_cap(repo: Path) -> None:
    """Missing timeout or shared byte cap would let a quality subprocess consume unbounded resources."""
    runner = SubprocessRunner()
    argv = [sys.executable, "-c", "import sys,time; print('x' * 100); print('y' * 100, file=sys.stderr); time.sleep(1)"]

    result = runner.run(argv, repo, timeout_s=1, output_limit=32)

    assert result.timed_out is True
    assert len(result.output.encode("utf-8")) <= 32
    assert result.truncated is True
