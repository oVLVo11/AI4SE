"""Executable command-line composition checks."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from pyquality.cli import _default_app_factory, main
from pyquality.demo import DemoReport, DeniedActionEvidence
from pyquality.domain.models import TaskStatus


def _capture_server(monkeypatch: pytest.MonkeyPatch) -> list[object]:
    applications: list[object] = []
    monkeypatch.setattr(
        "pyquality.cli.uvicorn.run",
        lambda application, **_kwargs: applications.append(application),
    )
    return applications


def _assert_public_app_accepts_the_bundled_scenario(application: object) -> None:
    client = TestClient(application)
    page = client.get("/tasks/new")
    csrf_token = page.text.split('name="csrf_token" value="', 1)[1].split('"', 1)[0]
    response = client.post(
        "/tasks",
        data={"scenario": "broken_calculator", "csrf_token": csrf_token},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert client.get("/settings").status_code == 404


def _succeeded_demo_report() -> DemoReport:
    return DemoReport(
        denied_action=DeniedActionEvidence(attempted=True, dispatch_count=0),
        action_order=("read_file", "apply_patch", "apply_patch", "finish"),
        first_failure_category="assertion",
        model_saw_first_failure=True,
        first_patch_digest="1" * 64,
        second_patch_digest="2" * 64,
        first_fingerprint="3" * 64,
        second_fingerprint="4" * 64,
        normalized_events=(),
        final_status=TaskStatus.SUCCEEDED,
    )


def test_default_public_app_executes_the_bundled_runner(
    monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = 0

    def runner() -> DemoReport:
        nonlocal calls
        calls += 1
        return _succeeded_demo_report()

    monkeypatch.setattr("pyquality.cli._run_public_demo", runner, raising=False)
    application = _default_app_factory(Path("."), "public_mock")

    _assert_public_app_accepts_the_bundled_scenario(application)

    assert calls == 1


def test_serve_public_mock_flag_uses_offline_public_composition(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    applications = _capture_server(monkeypatch)
    monkeypatch.setattr(
        "pyquality.application.build_service",
        lambda *_args, **_kwargs: pytest.fail("local composition reached"),
    )

    assert main(["serve", "--repo", str(tmp_path), "--public-mock"]) == 0

    assert len(applications) == 1
    _assert_public_app_accepts_the_bundled_scenario(applications[0])


def test_serve_public_mock_environment_uses_offline_public_composition(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    applications = _capture_server(monkeypatch)
    monkeypatch.setenv("PYQUALITY_MODE", "public_mock")
    monkeypatch.setattr(
        "pyquality.application.build_service",
        lambda *_args, **_kwargs: pytest.fail("local composition reached"),
    )

    assert main(["serve", "--repo", str(tmp_path)]) == 0

    assert len(applications) == 1
    _assert_public_app_accepts_the_bundled_scenario(applications[0])


def test_serve_without_public_selector_retains_local_composition(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    applications = _capture_server(monkeypatch)

    assert (
        main(
            ["serve", "--repo", str(tmp_path)],
            app_factory=lambda mode: {"mode": mode},
        )
        == 0
    )

    assert applications == [{"mode": "local"}]


def test_serve_rejects_invalid_public_mode_environment_without_echoing_it(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    invalid_mode = "credential-value-must-not-appear"
    monkeypatch.setenv("PYQUALITY_MODE", invalid_mode)

    with pytest.raises(SystemExit) as error:
        main(["serve"], app_factory=lambda _mode: pytest.fail("app started"))

    assert error.value.code == 2
    captured = capsys.readouterr()
    assert "invalid PYQUALITY_MODE" in captured.err
    assert invalid_mode not in captured.err
