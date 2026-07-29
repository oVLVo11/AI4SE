from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from pyquality.cli import main
from pyquality.domain.models import TaskStatus
from pyquality.security import CredentialStatus
from pyquality.service import PreflightError, TaskView
from pyquality.web.app import create_app

pytestmark = pytest.mark.filterwarnings(
    "ignore:Using `httpx` with `starlette.testclient` is deprecated:DeprecationWarning"
)


class WebService:
    def __init__(self, repo: Path) -> None:
        self.repo = repo
        self.created: list[tuple[Path, str]] = []
        self.approved: list[str] = []
        self.rejected: list[str] = []
        self.view = TaskView(
            id="task-1",
            request="fix <script>alert(1)</script>",
            status=TaskStatus.WAITING_APPROVAL,
            round_limit=8,
            remaining_rounds=5,
            verification_summary="Waiting for approval",
            pending_approval_id="approval-1",
        )

    def create_task(self, repo_path: Path | str, request: str) -> TaskView:
        self.created.append((Path(repo_path), request))
        return self.view

    def start_task(self, task_id: str) -> None:
        assert task_id == "task-1"

    def get_task(self, task_id: str) -> TaskView:
        if task_id == "missing":
            raise PreflightError("task does not exist")
        return self.view

    def approve(self, approval_id: str) -> None:
        self.approved.append(approval_id)

    def reject(self, approval_id: str) -> None:
        self.rejected.append(approval_id)


def _csrf(client: TestClient) -> str:
    page = client.get("/tasks/new")
    match = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
    assert match
    return match.group(1)


@pytest.fixture
def service(tmp_path: Path) -> WebService:
    repo = tmp_path / "repo"
    repo.mkdir()
    return WebService(repo)


@pytest.fixture
def client(service: WebService) -> TestClient:
    return TestClient(create_app(service, mode="local"))


def test_session_cookie_is_http_only_strict_and_mutation_requires_csrf(
    client: TestClient, service: WebService
) -> None:
    page = client.get("/tasks/new")
    cookie = page.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie

    response = client.post(
        "/tasks", data={"repo_path": str(service.repo), "request": "fix"}
    )
    assert response.status_code == 403


def test_local_timeline_approval_and_escaped_content(
    client: TestClient, service: WebService
) -> None:
    created = client.post(
        "/tasks",
        data={"repo_path": str(service.repo), "request": "fix", "csrf_token": _csrf(client)},
        follow_redirects=False,
    )
    assert created.status_code == 303
    page = client.get(created.headers["location"])
    assert "Remaining rounds: 5" in page.text
    assert "Waiting for approval" in page.text
    assert "<script>alert(1)</script>" not in page.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page.text

    decided = client.post(
        "/approvals/approval-1/approve",
        data={"csrf_token": _csrf(client)},
        follow_redirects=False,
    )
    assert decided.status_code == 303
    assert service.approved == ["approval-1"]


def test_settings_never_renders_credential_value(client: TestClient) -> None:
    page = client.get("/settings")
    assert page.status_code == 200
    assert "sk-secret" not in page.text
    assert "Credential values are never displayed" in page.text


def test_route_maps_sanitized_service_error(client: TestClient) -> None:
    page = client.get("/tasks/missing")
    assert page.status_code == 404
    assert "task does not exist" in page.text


class CliCredentials:
    def __init__(self) -> None:
        self.value: str | None = None

    def set(self, account: str, value: str) -> None:
        self.value = value

    def status(self, account: str) -> CredentialStatus:
        return CredentialStatus(present=self.value is not None, source="keyring")

    def clear(self, account: str) -> None:
        self.value = None


def test_cli_credential_uses_getpass_and_status_never_prints_value(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    credentials = CliCredentials()
    monkeypatch.setattr("pyquality.cli.getpass.getpass", lambda prompt: "sk-secret")
    assert main(["credential", "set"], credentials=credentials) == 0
    assert credentials.value == "sk-secret"
    assert main(["credential", "status"], credentials=credentials) == 0
    output = capsys.readouterr().out
    assert "present" in output
    assert "sk-secret" not in output


def test_cli_credential_builds_secure_default_service(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    credentials = CliCredentials()
    monkeypatch.setattr("pyquality.cli._default_credentials", lambda: credentials)
    monkeypatch.setattr("pyquality.cli.getpass.getpass", lambda prompt: "sk-secret")

    assert main(["credential", "set"]) == 0
    assert credentials.value == "sk-secret"


def test_cli_serve_defaults_to_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    called: dict[str, object] = {}
    monkeypatch.setattr(
        "pyquality.cli.uvicorn.run",
        lambda app, **kwargs: called.update(app=app, **kwargs),
    )
    assert main(["serve"], app_factory=lambda mode: object()) == 0
    assert called["host"] == "127.0.0.1"
