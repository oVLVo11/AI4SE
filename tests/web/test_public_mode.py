from __future__ import annotations

import re
from pathlib import Path
from threading import Event, Lock, Thread

import pytest
from fastapi.testclient import TestClient

import pyquality.web.app as web_app
from pyquality.cli import _default_app_factory
from pyquality.demo import DemoReport, DeniedActionEvidence
from pyquality.domain.models import TaskStatus
from pyquality.service import PreflightError, TaskView
from pyquality.web.app import (
    PublicDemoService,
    _SessionCodec,
    create_app,
)

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


def succeeded_demo_report() -> DemoReport:
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


def public_demo_service() -> PublicDemoService:
    return PublicDemoService({"broken_calculator": "public-demo"}, succeeded_demo_report)


def test_public_scenario_executes_runner_and_returns_terminal_evidence() -> None:
    calls = 0

    def runner() -> DemoReport:
        nonlocal calls
        calls += 1
        return succeeded_demo_report()

    service = PublicDemoService({"broken_calculator": "public-demo"}, runner)

    task = service.run_scenario("broken_calculator")

    assert calls == 1
    assert task.status is TaskStatus.SUCCEEDED
    assert task.remaining_rounds == 0
    assert service.get_evidence(task.id) == web_app.PublicDemoEvidence(
        denied_action=True,
        denied_dispatch_count=0,
        first_failure_category="assertion",
        model_saw_first_failure=True,
        action_order=("read_file", "apply_patch", "apply_patch", "finish"),
    )


def test_public_scenario_failure_is_sanitized_and_retains_no_success() -> None:
    calls = 0

    def runner() -> DemoReport:
        nonlocal calls
        calls += 1
        if calls == 1:
            return succeeded_demo_report()
        raise RuntimeError("secret C:/users/private/source.py prompt body")

    service = PublicDemoService({"broken_calculator": "public-demo"}, runner)
    service.run_scenario("broken_calculator")

    with pytest.raises(PreflightError, match=r"^public demo execution failed$"):
        service.run_scenario("broken_calculator")

    assert service.get_evidence("public-demo") is None
    with pytest.raises(PreflightError, match=r"^task does not exist$"):
        service.get_task("public-demo")


def test_public_scenario_replaces_prior_result_without_history_accumulation() -> None:
    reports = iter(
        (
            succeeded_demo_report(),
            succeeded_demo_report().model_copy(
                update={
                    "denied_action": DeniedActionEvidence(
                        attempted=False, dispatch_count=0
                    ),
                }
            ),
        )
    )
    calls = 0

    def runner() -> DemoReport:
        nonlocal calls
        calls += 1
        return next(reports)

    service = PublicDemoService({"broken_calculator": "public-demo"}, runner)

    first = service.run_scenario("broken_calculator")
    first_evidence = service.get_evidence(first.id)
    second = service.run_scenario("broken_calculator")

    assert calls == 2
    assert first.id == second.id == "public-demo"
    assert first_evidence == web_app.PublicDemoEvidence(
        denied_action=True,
        denied_dispatch_count=0,
        first_failure_category="assertion",
        model_saw_first_failure=True,
        action_order=("read_file", "apply_patch", "apply_patch", "finish"),
    )
    assert service.get_evidence(second.id) == web_app.PublicDemoEvidence(
        denied_action=False,
        denied_dispatch_count=0,
        first_failure_category="assertion",
        model_saw_first_failure=True,
        action_order=("read_file", "apply_patch", "apply_patch", "finish"),
    )


def test_public_scenario_rejects_oversized_secret_bearing_evidence() -> None:
    secret = "secret C:/users/private/source.py prompt body"
    report = succeeded_demo_report().model_copy(
        update={
            "first_failure_category": secret,
            "action_order": ("finish",) * 1_000,
        }
    )
    service = PublicDemoService({"broken_calculator": "public-demo"}, lambda: report)

    with pytest.raises(PreflightError, match=r"^public demo execution failed$") as error:
        service.run_scenario("broken_calculator")

    assert secret not in str(error.value)
    assert service.get_evidence("public-demo") is None


def test_public_scenario_propagates_keyboard_interrupt_without_state() -> None:
    def runner() -> DemoReport:
        raise KeyboardInterrupt

    service = PublicDemoService({"broken_calculator": "public-demo"}, runner)

    with pytest.raises(KeyboardInterrupt):
        service.run_scenario("broken_calculator")

    assert service.get_evidence("public-demo") is None


def test_public_scenario_serializes_delayed_success_before_newer_success() -> None:
    first_started = Event()
    release_first = Event()
    runner_lock = Lock()
    invocations: list[str] = []
    completions: list[str] = []

    def runner() -> DemoReport:
        with runner_lock:
            invocation = len(invocations)
            invocations.append("first" if invocation == 0 else "second")
        if invocation == 0:
            first_started.set()
            assert release_first.wait(timeout=2)
            return succeeded_demo_report()
        return succeeded_demo_report().model_copy(
            update={"denied_action": DeniedActionEvidence(attempted=False, dispatch_count=0)}
        )

    service = PublicDemoService({"broken_calculator": "public-demo"}, runner)

    def run(label: str) -> None:
        service.run_scenario("broken_calculator")
        completions.append(label)

    first = Thread(target=run, args=("first",))
    second = Thread(target=run, args=("second",))
    first.start()
    assert first_started.wait(timeout=2)
    second.start()
    release_first.set()
    first.join(timeout=2)
    second.join(timeout=2)

    assert not first.is_alive()
    assert not second.is_alive()
    assert invocations == ["first", "second"]
    assert completions == ["first", "second"]
    assert service.get_evidence("public-demo").denied_action is False  # type: ignore[union-attr]


def test_public_scenario_serializes_delayed_failure_before_newer_success() -> None:
    first_started = Event()
    release_first = Event()
    runner_lock = Lock()
    invocations: list[str] = []
    completions: list[str] = []
    failures: list[BaseException] = []

    def runner() -> DemoReport:
        with runner_lock:
            invocation = len(invocations)
            invocations.append("first" if invocation == 0 else "second")
        if invocation == 0:
            first_started.set()
            assert release_first.wait(timeout=2)
            raise RuntimeError("secret failure")
        return succeeded_demo_report().model_copy(
            update={"denied_action": DeniedActionEvidence(attempted=False, dispatch_count=0)}
        )

    service = PublicDemoService({"broken_calculator": "public-demo"}, runner)

    def run(label: str) -> None:
        try:
            service.run_scenario("broken_calculator")
        except BaseException as error:  # noqa: BLE001 - capture the thread result for assertion.
            failures.append(error)
        else:
            completions.append(label)

    first = Thread(target=run, args=("first",))
    second = Thread(target=run, args=("second",))
    first.start()
    assert first_started.wait(timeout=2)
    second.start()
    release_first.set()
    first.join(timeout=2)
    second.join(timeout=2)

    assert not first.is_alive()
    assert not second.is_alive()
    assert invocations == ["first", "second"]
    assert completions == ["second"]
    assert len(failures) == 1
    assert service.get_evidence("public-demo").denied_action is False  # type: ignore[union-attr]


def csrf(client: TestClient) -> str:
    text = client.get("/tasks/new").text
    return re.search(r'name="csrf_token" value="([^"]+)"', text).group(1)  # type: ignore[union-attr]


def _retained_session_entries(app: object) -> int:
    retained = 0
    for middleware in app.user_middleware:  # type: ignore[attr-defined]
        dispatch = middleware.kwargs.get("dispatch")
        for cell in getattr(dispatch, "__closure__", ()) or ():
            try:
                value = cell.cell_contents
            except ValueError:
                continue
            if isinstance(value, dict):
                retained += len(value)
    return retained


def test_public_unknown_cookie_and_404_flood_retains_no_server_sessions() -> None:
    app = create_app(public_demo_service(), mode="public_mock")
    client = TestClient(app)

    for sequence in range(256):
        client.cookies.clear()
        headers = (
            {"cookie": f"pyquality_session=attacker-{sequence}"}
            if sequence % 2
            else {}
        )
        response = client.get(f"/missing-{sequence}", headers=headers)
        assert response.status_code == 404

    assert _retained_session_entries(app) == 0


def test_public_session_rejects_cookie_tampering_and_attacker_fixation() -> None:
    app = create_app(public_demo_service(), mode="public_mock")
    client = TestClient(app)
    page = client.get("/tasks/new")
    token = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)  # type: ignore[union-attr]
    cookie = client.cookies.get("pyquality_session")
    assert cookie is not None
    tampered = f"{cookie[:-1]}{'A' if cookie[-1] != 'A' else 'B'}"

    client.cookies.clear()
    rejected = client.post(
        "/tasks",
        data={"scenario": "broken_calculator", "csrf_token": token},
        headers={"cookie": f"pyquality_session={tampered}"},
    )
    assert rejected.status_code == 403

    client.cookies.clear()
    fixed = client.get(
        "/tasks/new", headers={"cookie": "pyquality_session=attacker-fixed"}
    )
    replacement = fixed.cookies.get("pyquality_session")
    fixed_token = re.search(
        r'name="csrf_token" value="([^"]+)"', fixed.text
    ).group(1)  # type: ignore[union-attr]
    assert replacement not in {None, "attacker-fixed"}
    assert fixed_token != "attacker-fixed"


def test_shared_session_secret_allows_multi_worker_cookie_verification() -> None:
    shared_secret = b"s" * 32
    first_app = create_app(
        public_demo_service(),
        mode="public_mock",
        session_secret=shared_secret,
    )
    second_app = create_app(
        public_demo_service(),
        mode="public_mock",
        session_secret=shared_secret,
    )
    first_worker = TestClient(first_app)
    page = first_worker.get("/tasks/new")
    token = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)  # type: ignore[union-attr]
    cookie = first_worker.cookies.get("pyquality_session")
    assert cookie is not None

    second_worker = TestClient(second_app)
    accepted = second_worker.post(
        "/tasks",
        data={"scenario": "broken_calculator", "csrf_token": token},
        headers={"cookie": f"pyquality_session={cookie}"},
        follow_redirects=False,
    )

    assert accepted.status_code == 303


def test_session_codec_rejects_non_ascii_cookie_without_raising() -> None:
    codec = _SessionCodec(b"s" * 32)

    assert codec.verify(f"é.{'0' * 64}") is None


def test_public_mock_rejects_paths_provider_changes_and_credentials() -> None:
    service = public_demo_service()
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
    service = public_demo_service()
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
    service = public_demo_service()
    client = TestClient(create_app(service, mode="public_mock"))
    response = client.post(
        "/tasks",
        data={"scenario": "broken_calculator", "csrf_token": csrf(client)},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert service.get_task("public-demo").id == "public-demo"


def test_public_mock_rejects_unknown_scenario() -> None:
    client = TestClient(
        create_app(public_demo_service(), mode="public_mock")
    )
    response = client.post(
        "/tasks", data={"scenario": "other", "csrf_token": csrf(client)}
    )
    assert response.status_code == 403
