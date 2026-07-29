from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from pyquality.cli import _default_app_factory
from pyquality.domain.models import TaskStatus
from pyquality.service import TaskView
from pyquality.web.app import PublicDemoService, create_app

pytestmark = pytest.mark.filterwarnings(
    "ignore:Using `httpx` with `starlette.testclient` is deprecated:DeprecationWarning"
)


class PublicService:
    def __init__(self) -> None:
        self.calls: list[tuple[Path | str, str]] = []

    def create_task(self, repo_path: Path | str, request: str) -> TaskView:
        self.calls.append((repo_path, request))
        return TaskView(
            id="demo-task",
            status=TaskStatus.CREATED,
            round_limit=8,
            remaining_rounds=8,
        )

    def start_task(self, task_id: str) -> None:
        pass

    def get_task(self, task_id: str) -> TaskView:
        return TaskView(
            id=task_id,
            status=TaskStatus.CREATED,
            round_limit=8,
            remaining_rounds=8,
        )


def csrf(client: TestClient) -> str:
    text = client.get("/tasks/new").text
    return re.search(r'name="csrf_token" value="([^"]+)"', text).group(1)  # type: ignore[union-attr]


def test_public_mock_rejects_paths_provider_changes_and_credentials() -> None:
    service = PublicDemoService({"broken_calculator": "demo-task"})
    client = TestClient(create_app(service, mode="public_mock"))
    token = csrf(client)

    arbitrary = client.post(
        "/tasks",
        data={"repo_path": "C:/secret", "request": "fix", "csrf_token": token},
    )
    assert arbitrary.status_code == 403
    assert client.get("/settings").status_code == 404
    assert client.post(
        "/provider", data={"provider": "openai", "csrf_token": token}
    ).status_code == 404


def test_public_mock_rejects_service_with_repository_or_credential_capability() -> None:
    with pytest.raises(TypeError, match="public demo"):
        create_app(PublicService(), mode="public_mock")


def test_real_public_demo_capability_accepts_only_registered_offline_scenario() -> None:
    service = PublicDemoService({"broken_calculator": "demo-task"})
    client = TestClient(create_app(service, mode="public_mock"))

    response = client.post(
        "/tasks",
        data={"scenario": "broken_calculator", "csrf_token": csrf(client)},
        follow_redirects=False,
    )

    assert response.status_code == 303


def test_default_public_app_cannot_build_real_provider_or_credentials(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        "pyquality.application.build_service",
        lambda *args, **kwargs: pytest.fail("real harness composition reached"),
    )

    app = _default_app_factory(tmp_path, "public_mock")
    client = TestClient(app)
    response = client.post(
        "/tasks",
        data={"scenario": "broken_calculator", "csrf_token": csrf(client)},
        follow_redirects=False,
    )

    assert response.status_code == 303


def test_public_mock_accepts_only_bundled_scenario() -> None:
    service = PublicDemoService({"broken_calculator": "demo-task"})
    client = TestClient(create_app(service, mode="public_mock"))
    response = client.post(
        "/tasks",
        data={"scenario": "broken_calculator", "csrf_token": csrf(client)},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert service.get_task("demo-task").id == "demo-task"


def test_public_mock_rejects_unknown_scenario() -> None:
    client = TestClient(
        create_app(PublicDemoService({"broken_calculator": "demo-task"}), mode="public_mock")
    )
    response = client.post(
        "/tasks", data={"scenario": "other", "csrf_token": csrf(client)}
    )
    assert response.status_code == 403
