"""Executable command-line composition checks."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from pyquality.cli import main


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
