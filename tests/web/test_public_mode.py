from __future__ import annotations

import asyncio
import re
import time
from html import escape
from pathlib import Path
from threading import Event
from urllib.parse import quote_plus

import httpx
import pytest
from fastapi.testclient import TestClient

import pyquality.web.app as web_app
from pyquality.cli import _default_app_factory
from pyquality.demo import DemoReport, DeniedActionEvidence, MechanismEvent
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

    service = PublicDemoService(
        {"broken_calculator": "public-demo"}, runner, cooldown_s=0
    )

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

    service = PublicDemoService(
        {"broken_calculator": "public-demo"}, runner, cooldown_s=0
    )
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
                update={"first_patch_digest": "5" * 64}
            ),
        )
    )
    calls = 0

    def runner() -> DemoReport:
        nonlocal calls
        calls += 1
        return next(reports)

    service = PublicDemoService(
        {"broken_calculator": "public-demo"}, runner, cooldown_s=0
    )

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
        denied_action=True,
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


@pytest.mark.parametrize(
    "updates",
    (
        {"denied_action": DeniedActionEvidence(attempted=False, dispatch_count=0)},
        {"denied_action": DeniedActionEvidence(attempted=True, dispatch_count=1)},
        {"first_failure_category": "syntax"},
        {"model_saw_first_failure": False},
        {"action_order": ("read_file", "apply_patch", "finish")},
        {"final_status": TaskStatus.FAILED},
    ),
)
def test_public_scenario_rejects_every_incomplete_success_claim(
    updates: dict[str, object],
) -> None:
    report = succeeded_demo_report().model_copy(update=updates)
    service = PublicDemoService(
        {"broken_calculator": "public-demo"}, lambda: report
    )

    with pytest.raises(PreflightError, match=r"^public demo execution failed$"):
        service.run_scenario("broken_calculator")

    assert service.get_evidence("public-demo") is None


@pytest.mark.parametrize(
    "updates",
    (
        {"denied_action": DeniedActionEvidence(attempted=False, dispatch_count=0)},
        {"denied_action": DeniedActionEvidence(attempted=True, dispatch_count=1)},
        {"first_failure_category": "syntax"},
        {"model_saw_first_failure": False},
        {"action_order": ("read_file", "apply_patch", "finish")},
        {"final_status": TaskStatus.FAILED},
    ),
)
def test_public_route_never_renders_an_incomplete_success_claim(
    updates: dict[str, object],
) -> None:
    report = succeeded_demo_report().model_copy(update=updates)
    client = TestClient(
        create_app(
            PublicDemoService({"broken_calculator": "public-demo"}, lambda: report),
            mode="public_mock",
        )
    )

    response = client.post(
        "/tasks",
        data={"scenario": "broken_calculator", "csrf_token": csrf(client)},
        follow_redirects=False,
    )

    assert response.status_code == 400
    assert "public demo execution failed" in response.text
    assert "Status: succeeded" not in response.text


def test_public_invariant_failure_clears_a_prior_success() -> None:
    reports = iter(
        (
            succeeded_demo_report(),
            succeeded_demo_report().model_copy(
                update={"model_saw_first_failure": False}
            ),
        )
    )
    service = PublicDemoService(
        {"broken_calculator": "public-demo"}, lambda: next(reports), cooldown_s=0
    )
    service.run_scenario("broken_calculator")

    with pytest.raises(PreflightError, match=r"^public demo execution failed$"):
        service.run_scenario("broken_calculator")

    assert service.get_evidence("public-demo") is None


def test_public_scenario_propagates_keyboard_interrupt_without_state() -> None:
    def runner() -> DemoReport:
        raise KeyboardInterrupt

    service = PublicDemoService({"broken_calculator": "public-demo"}, runner)

    with pytest.raises(KeyboardInterrupt):
        service.run_scenario("broken_calculator")

    assert service.get_evidence("public-demo") is None


def test_public_http_stays_responsive_and_rejects_a_concurrent_run_fast() -> None:
    async def exercise() -> None:
        started = Event()
        release = Event()
        calls = 0

        def runner() -> DemoReport:
            nonlocal calls
            calls += 1
            started.set()
            release.wait(timeout=1)
            return succeeded_demo_report()

        app = create_app(
            PublicDemoService(
                {"broken_calculator": "public-demo"}, runner, cooldown_s=0
            ),
            mode="public_mock",
        )
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as client:
            page = await client.get("/tasks/new")
            token = re.search(
                r'name="csrf_token" value="([^"]+)"', page.text
            ).group(1)  # type: ignore[union-attr]
            form = {"scenario": "broken_calculator", "csrf_token": token}

            started_at = time.monotonic()
            first = asyncio.create_task(
                client.post("/tasks", data=form, follow_redirects=False)
            )
            assert await asyncio.to_thread(started.wait, 2)
            health = await client.get("/")
            assert time.monotonic() - started_at < 0.5

            busy_started = time.monotonic()
            busy = await client.post("/tasks", data=form, follow_redirects=False)
            assert time.monotonic() - busy_started < 0.5
            assert health.status_code == 200
            assert busy.status_code == 503
            assert calls == 1

            release.set()
            assert (await first).status_code == 303

    asyncio.run(exercise())


def test_public_http_abuse_does_not_queue_runs() -> None:
    async def exercise() -> None:
        started = Event()
        release = Event()
        calls = 0

        def runner() -> DemoReport:
            nonlocal calls
            calls += 1
            if calls == 1:
                started.set()
                release.wait(timeout=1)
            return succeeded_demo_report()

        app = create_app(
            PublicDemoService(
                {"broken_calculator": "public-demo"}, runner, cooldown_s=0
            ),
            mode="public_mock",
        )
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as client:
            page = await client.get("/tasks/new")
            token = re.search(
                r'name="csrf_token" value="([^"]+)"', page.text
            ).group(1)  # type: ignore[union-attr]
            form = {"scenario": "broken_calculator", "csrf_token": token}
            first = asyncio.create_task(
                client.post("/tasks", data=form, follow_redirects=False)
            )
            assert await asyncio.to_thread(started.wait, 2)

            responses = [
                await client.post("/tasks", data=form, follow_redirects=False)
                for _ in range(8)
            ]
            assert [response.status_code for response in responses] == [503] * 8
            assert calls == 1

            release.set()
            assert (await first).status_code == 303
            await asyncio.sleep(0)
            assert calls == 1

    asyncio.run(exercise())


def test_public_cancelled_request_keeps_admission_until_worker_exits() -> None:
    async def exercise() -> None:
        started = Event()
        release = Event()
        finished = Event()
        calls = 0

        def runner() -> DemoReport:
            nonlocal calls
            calls += 1
            if calls == 1:
                started.set()
                release.wait(timeout=2)
                finished.set()
            return succeeded_demo_report()

        app = create_app(
            PublicDemoService(
                {"broken_calculator": "public-demo"}, runner, cooldown_s=0
            ),
            mode="public_mock",
        )
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as client:
            page = await client.get("/tasks/new")
            token = re.search(
                r'name="csrf_token" value="([^"]+)"', page.text
            ).group(1)  # type: ignore[union-attr]
            form = {"scenario": "broken_calculator", "csrf_token": token}
            first = asyncio.create_task(
                client.post("/tasks", data=form, follow_redirects=False)
            )
            assert await asyncio.to_thread(started.wait, 2)

            first.cancel()
            with pytest.raises(asyncio.CancelledError):
                await first
            busy = await client.post("/tasks", data=form, follow_redirects=False)

            assert busy.status_code == 503
            assert calls == 1

            release.set()
            assert await asyncio.to_thread(finished.wait, 2)
            for _attempt in range(50):
                recovered = await client.post(
                    "/tasks", data=form, follow_redirects=False
                )
                if recovered.status_code == 303:
                    break
                assert recovered.status_code == 503
                await asyncio.sleep(0.01)
            else:
                pytest.fail("worker did not release public admission")
            assert calls == 2

    asyncio.run(exercise())


def test_public_scenario_reuses_result_during_cooldown_then_allows_rerun() -> None:
    now = [100.0]
    calls = 0

    def runner() -> DemoReport:
        nonlocal calls
        calls += 1
        return succeeded_demo_report()

    service = PublicDemoService(
        {"broken_calculator": "public-demo"},
        runner,
        cooldown_s=5,
        clock=lambda: now[0],
    )

    first = service.run_scenario("broken_calculator")
    cached = service.run_scenario("broken_calculator")
    now[0] += 5.1
    repeated = service.run_scenario("broken_calculator")

    assert first == cached == repeated
    assert calls == 2


def test_public_timeout_clears_state_and_releases_admission_after_cooldown() -> None:
    now = [100.0]
    calls = 0

    def runner() -> DemoReport:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise TimeoutError("private timeout channel")
        return succeeded_demo_report()

    service = PublicDemoService(
        {"broken_calculator": "public-demo"},
        runner,
        cooldown_s=1,
        clock=lambda: now[0],
    )
    client = TestClient(create_app(service, mode="public_mock"))
    token = csrf(client)
    form = {"scenario": "broken_calculator", "csrf_token": token}

    failed = client.post("/tasks", data=form, follow_redirects=False)
    cooling_down = client.post("/tasks", data=form, follow_redirects=False)
    now[0] += 1.1
    recovered = client.post("/tasks", data=form, follow_redirects=False)

    assert failed.status_code == 400
    assert "public demo execution failed" in failed.text
    assert cooling_down.status_code == 503
    assert recovered.status_code == 303
    assert calls == 2


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
    assert arbitrary.status_code == 400
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


def test_public_demo_page_renders_only_fixed_sanitized_evidence() -> None:
    sentinels = (
        "LEAK_PATH_C:/local/private/path.py",
        "LEAK_SOURCE_def private_source(): return 'body'",
        "LEAK_PATCH_*** Begin Patch\\n*** Update File: private.py",
        "LEAK_PROMPT_private prompt body",
        "LEAK_PROVIDER_sk-provider-key",
        'LEAK_AUDIT_{"audit": "raw-payload"}',
    )
    report = succeeded_demo_report().model_copy(
        update={
            "first_patch_digest": sentinels[0],
            "second_patch_digest": sentinels[1],
            "first_fingerprint": sentinels[2],
            "second_fingerprint": sentinels[3],
            "normalized_events": (
                MechanismEvent(
                    action=sentinels[4],
                    policy=sentinels[5],
                    quality=sentinels[0],
                    fingerprint=sentinels[1],
                    dispatched=False,
                ),
            ),
        }
    )
    client = TestClient(
        create_app(PublicDemoService({"broken_calculator": "public-demo"}, lambda: report), mode="public_mock")
    )

    submitted = client.post(
        "/tasks",
        data={"scenario": "broken_calculator", "csrf_token": csrf(client)},
        follow_redirects=False,
    )
    page = client.get(submitted.headers["location"])

    assert submitted.status_code == 303
    assert page.status_code == 200
    for label in (
        "Status: succeeded",
        "Remaining rounds: 0",
        "Guardrail: outside action denied",
        "Feedback: assertion",
        escape("Progress: read_file -> apply_patch -> apply_patch -> finish"),
    ):
        assert label in page.text
    for sentinel in (*sentinels, repr(report)):
        assert sentinel not in page.text


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


@pytest.mark.parametrize(
    "body",
    (
        "scenario=broken_calculator&scenario=broken_calculator&csrf_token={token}",
        "scenario=broken_calculator&csrf_token={token}&csrf_token={token}",
        "scenario=broken_calculator&csrf_token={token}&extra=value",
        "csrf_token={token}",
        "scenario=broken_calculator",
        "scenario=broken_calculator&csrf_token={token}&",
        "scenario=broken_calculator&csrf_token",
        "scenario=%ZZ&csrf_token={token}",
        "scenario=broken_calculator&csrf_token=%FF",
    ),
)
def test_public_mock_rejects_noncanonical_urlencoded_fields(body: str) -> None:
    calls = 0

    def runner() -> DemoReport:
        nonlocal calls
        calls += 1
        return succeeded_demo_report()

    client = TestClient(
        create_app(
            PublicDemoService({"broken_calculator": "public-demo"}, runner),
            mode="public_mock",
        )
    )
    token = csrf(client)

    response = client.post(
        "/tasks",
        content=body.format(token=quote_plus(token)).encode("ascii"),
        headers={"content-type": "application/x-www-form-urlencoded"},
        follow_redirects=False,
    )

    assert response.status_code == 400
    assert calls == 0


@pytest.mark.parametrize(
    "content_type",
    ("", "application/json", "text/plain", "application/x-www-form-urlencoded, text/plain"),
)
def test_public_mock_rejects_non_form_content_types(content_type: str) -> None:
    calls = 0

    def runner() -> DemoReport:
        nonlocal calls
        calls += 1
        return succeeded_demo_report()

    client = TestClient(
        create_app(
            PublicDemoService({"broken_calculator": "public-demo"}, runner),
            mode="public_mock",
        )
    )
    token = csrf(client)
    headers = {"content-type": content_type} if content_type else {}

    response = client.post(
        "/tasks",
        content=f"scenario=broken_calculator&csrf_token={quote_plus(token)}",
        headers=headers,
        follow_redirects=False,
    )

    assert response.status_code == 415
    assert calls == 0


def test_public_mock_rejects_multipart_before_framework_form_parsing() -> None:
    calls = 0

    def runner() -> DemoReport:
        nonlocal calls
        calls += 1
        return succeeded_demo_report()

    client = TestClient(
        create_app(
            PublicDemoService({"broken_calculator": "public-demo"}, runner),
            mode="public_mock",
        )
    )
    token = csrf(client)

    response = client.post(
        "/tasks",
        files={
            "scenario": (None, "broken_calculator"),
            "csrf_token": (None, token),
        },
        follow_redirects=False,
    )

    assert response.status_code == 415
    assert calls == 0


def test_public_mock_rejects_declared_oversized_body() -> None:
    calls = 0

    def runner() -> DemoReport:
        nonlocal calls
        calls += 1
        return succeeded_demo_report()

    client = TestClient(
        create_app(
            PublicDemoService({"broken_calculator": "public-demo"}, runner),
            mode="public_mock",
        )
    )

    response = client.post(
        "/tasks",
        content=b"x",
        headers={
            "content-type": "application/x-www-form-urlencoded",
            "content-length": "4097",
        },
    )

    assert response.status_code == 413
    assert calls == 0


def test_public_mock_rejects_chunked_body_over_4096_bytes() -> None:
    calls = 0

    def runner() -> DemoReport:
        nonlocal calls
        calls += 1
        return succeeded_demo_report()

    app = create_app(
        PublicDemoService({"broken_calculator": "public-demo"}, runner),
        mode="public_mock",
        session_secret=b"s" * 32,
    )
    client = TestClient(app)
    client.get("/tasks/new")
    cookie = client.cookies.get("pyquality_session")
    assert cookie is not None

    async def submit_chunks() -> int:
        messages = iter(
            (
                {"type": "http.request", "body": b"x" * 2048, "more_body": True},
                {"type": "http.request", "body": b"y" * 2049, "more_body": False},
            )
        )
        sent: list[dict[str, object]] = []

        async def receive() -> dict[str, object]:
            return next(messages, {"type": "http.disconnect"})

        async def send(message: dict[str, object]) -> None:
            sent.append(message)

        await app(
            {
                "type": "http",
                "asgi": {"version": "3.0"},
                "http_version": "1.1",
                "method": "POST",
                "scheme": "http",
                "path": "/tasks",
                "raw_path": b"/tasks",
                "query_string": b"",
                "root_path": "",
                "headers": [
                    (b"host", b"testserver"),
                    (b"content-type", b"application/x-www-form-urlencoded"),
                    (b"cookie", f"pyquality_session={cookie}".encode("ascii")),
                ],
                "client": ("127.0.0.1", 12345),
                "server": ("testserver", 80),
            },
            receive,
            send,
        )
        return next(
            int(message["status"])
            for message in sent
            if message["type"] == "http.response.start"
        )

    assert asyncio.run(submit_chunks()) == 413
    assert calls == 0
