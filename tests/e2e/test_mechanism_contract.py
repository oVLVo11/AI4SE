from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import httpx
import pytest

from pyquality.demo import run_demo
from pyquality.domain.models import TaskStatus


def test_demo_is_offline_credential_free_and_repository_confined(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Using ambient network, keyring, or sibling files would make the demo unsafe."""
    sibling = tmp_path / "secret.txt"
    sibling.write_text("do-not-read\n", encoding="utf-8")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setattr(
        httpx.Client,
        "post",
        lambda *args, **kwargs: pytest.fail("network called"),
    )
    monkeypatch.setattr(
        "keyring.get_keyring",
        lambda: pytest.fail("keyring called"),
    )
    monkeypatch.delenv("PYQUALITY_API_KEY", raising=False)

    report = run_demo(workspace)

    assert report.final_status is TaskStatus.SUCCEEDED
    assert sibling.read_text(encoding="utf-8") == "do-not-read\n"
    assert report.denied_action.dispatch_count == 0


def test_two_demo_runs_have_identical_normalized_mechanism_evidence(tmp_path: Path) -> None:
    """Letting timestamps or temporary paths into evidence would make the demo unstable."""
    first = run_demo(tmp_path / "one")
    second = run_demo(tmp_path / "two")

    assert first.normalized_events == second.normalized_events
    assert first.action_order == second.action_order
    assert first.denied_action == second.denied_action
    assert first.first_fingerprint == second.first_fingerprint
    assert first.second_fingerprint == second.second_fingerprint
    assert first.final_status == second.final_status
    assert str(tmp_path) not in first.model_dump_json()


def test_installed_cli_demo_emits_schema_stable_json(tmp_path: Path) -> None:
    """A prose or path-bearing CLI response would break machine consumption."""
    environment = dict(os.environ)
    environment["PYTHONUTF8"] = "1"
    completed = subprocess.run(
        [sys.executable, "-m", "pyquality.cli", "demo", "--json"],
        cwd=tmp_path,
        env=environment,
        text=True,
        capture_output=True,
        timeout=60,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout)
    assert payload["schema_version"] == 1
    assert payload["final_status"] == "succeeded"
    assert payload["denied_action"] == {"attempted": True, "dispatch_count": 0}
    assert str(tmp_path) not in completed.stdout
