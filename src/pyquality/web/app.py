"""Server-rendered, session-protected local WebUI."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Literal, Protocol

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import ConfigDict, Field

from ..demo import DemoReport
from ..domain.models import PublicModel, TaskStatus
from ..service import PreflightError, ProjectBusyError, TaskView


class WebService(Protocol):
    def create_task(self, repo_path: Path | str, request: str) -> TaskView: ...

    def start_task(self, task_id: str) -> object: ...

    def get_task(self, task_id: str) -> TaskView: ...

    def approve(self, approval_id: str) -> None: ...

    def reject(self, approval_id: str) -> None: ...

    def resume_task(self, task_id: str) -> object: ...


_TEMPLATES = Jinja2Templates(directory=str(Path(__file__).with_name("templates")))
_BUNDLED_SCENARIO = "broken_calculator"
_PUBLIC_DEMO_TASK_ID = "public-demo"
_PUBLIC_DEMO_ACTION_ORDER = ("read_file", "apply_patch", "apply_patch", "finish")


class PublicDemoEvidence(PublicModel):
    """Small, source-free evidence from the bundled deterministic scenario."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    denied_action: bool
    denied_dispatch_count: int = Field(ge=0)
    first_failure_category: str
    model_saw_first_failure: bool
    action_order: tuple[str, ...]


class _SessionCodec:
    """Issue and verify stateless cookies carrying one authenticated CSRF token."""

    __slots__ = ("_key",)

    def __init__(self, key: bytes | None = None) -> None:
        if key is not None and (not isinstance(key, bytes) or len(key) < 32):
            raise ValueError("session secret must contain at least 32 bytes")
        self._key = key if key is not None else secrets.token_bytes(32)

    def issue(self) -> tuple[str, str]:
        token = secrets.token_urlsafe(32)
        return token, self._encode(token)

    def verify(self, cookie: object) -> str | None:
        if (
            not isinstance(cookie, str)
            or len(cookie) > 160
            or not cookie.isascii()
        ):
            return None
        token, separator, signature = cookie.partition(".")
        if (
            separator != "."
            or not token
            or len(token) > 64
            or len(signature) != hashlib.sha256().digest_size * 2
        ):
            return None
        expected = self._signature(token)
        return token if hmac.compare_digest(signature, expected) else None

    def _encode(self, token: str) -> str:
        return f"{token}.{self._signature(token)}"

    def _signature(self, token: str) -> str:
        return hmac.new(
            self._key, token.encode("ascii"), hashlib.sha256
        ).hexdigest()


class PublicDemoService:
    """Capability-restricted synchronous boundary for the offline public scenario."""

    def __init__(self, scenarios: Mapping[str, str], runner: Callable[[], DemoReport]) -> None:
        self._scenarios = dict(scenarios)
        self._runner = runner
        self._state: tuple[TaskView, PublicDemoEvidence] | None = None

    def run_scenario(self, scenario_id: str) -> TaskView:
        task_id = self._scenarios.get(scenario_id)
        if (
            scenario_id != _BUNDLED_SCENARIO
            or task_id != _PUBLIC_DEMO_TASK_ID
        ):
            raise PreflightError("public scenario is unavailable")

        try:
            report = self._runner()
            if report.final_status is not TaskStatus.SUCCEEDED:
                raise RuntimeError("public demo did not succeed")
            evidence = PublicDemoEvidence(
                denied_action=report.denied_action.attempted,
                denied_dispatch_count=report.denied_action.dispatch_count,
                first_failure_category=report.first_failure_category,
                model_saw_first_failure=report.model_saw_first_failure,
                action_order=report.action_order,
            )
            view = TaskView(
                id=_PUBLIC_DEMO_TASK_ID,
                status=TaskStatus.SUCCEEDED,
                round_limit=1,
                remaining_rounds=0,
                verification_summary=self._summary(evidence),
            )
        except BaseException:  # noqa: BLE001 - sanitize all runner failures.
            self._state = None
            raise PreflightError("public demo execution failed") from None
        self._state = (view, evidence)
        return view

    def get_task(self, task_id: str) -> TaskView:
        if self._state is None or task_id != _PUBLIC_DEMO_TASK_ID:
            raise PreflightError("task does not exist")
        return self._state[0]

    def get_evidence(self, task_id: str) -> PublicDemoEvidence | None:
        if self._state is None or task_id != _PUBLIC_DEMO_TASK_ID:
            return None
        return self._state[1]

    @staticmethod
    def _summary(evidence: PublicDemoEvidence) -> str:
        guardrail = (
            "outside action denied"
            if evidence.denied_action
            else "outside action unavailable"
        )
        feedback = (
            "assertion"
            if evidence.first_failure_category == "assertion"
            else "unavailable"
        )
        progress = (
            "read_file -> apply_patch -> apply_patch -> finish"
            if evidence.action_order == _PUBLIC_DEMO_ACTION_ORDER
            else "unavailable"
        )
        return f"Guardrail: {guardrail}; Feedback: {feedback}; Progress: {progress}"


def create_app(
    service: WebService,
    mode: Literal["local", "public_mock"] = "local",
    *,
    session_secret: bytes | None = None,
) -> FastAPI:
    """Create a local UI or a path/credential-isolated public mock UI."""
    if mode not in {"local", "public_mock"}:
        raise ValueError("unsupported WebUI mode")
    if mode == "public_mock" and type(service) is not PublicDemoService:
        raise TypeError("public demo requires a capability-restricted service")
    app = FastAPI()
    session_codec = _SessionCodec(session_secret)

    @app.middleware("http")
    async def local_session(request: Request, call_next):
        cookie = request.cookies.get("pyquality_session")
        csrf_token = session_codec.verify(cookie)
        if csrf_token is None:
            csrf_token, cookie = session_codec.issue()
        request.scope["session"] = {"csrf_token": csrf_token}
        response = await call_next(request)
        response.set_cookie(
            "pyquality_session",
            cookie,
            httponly=True,
            samesite="strict",
        )
        return response

    def context(request: Request, **values: object) -> dict[str, object]:
        token = request.session.get("csrf_token")
        if not isinstance(token, str):
            token = secrets.token_urlsafe(32)
            request.session["csrf_token"] = token
        return {"request": request, "csrf_token": token, "mode": mode, **values}

    async def require_csrf(request: Request) -> dict[str, object] | HTMLResponse:
        form = dict(await request.form())
        supplied = form.get("csrf_token")
        expected = request.session.get("csrf_token")
        if not isinstance(supplied, str) or not isinstance(expected, str) or not secrets.compare_digest(supplied, expected):
            return HTMLResponse("Forbidden", status_code=403)
        return form

    @app.get("/", response_class=HTMLResponse)
    @app.get("/tasks/new", response_class=HTMLResponse)
    async def new_task(request: Request) -> HTMLResponse:
        return _TEMPLATES.TemplateResponse(
            request=request,
            name="tasks_new.html",
            context=context(request, bundled_scenario=_BUNDLED_SCENARIO),
        )

    @app.post("/tasks")
    async def create_task_route(request: Request):
        form = await require_csrf(request)
        if isinstance(form, HTMLResponse):
            return form
        try:
            if mode == "public_mock":
                if set(form) - {"scenario", "csrf_token"} or form.get("scenario") != _BUNDLED_SCENARIO:
                    return HTMLResponse("Public demo accepts only the bundled scenario", status_code=403)
                task = service.run_scenario(_BUNDLED_SCENARIO)
            else:
                repo_path = Path(str(form.get("repo_path", "")))
                requested = str(form.get("request", ""))
                task = service.create_task(repo_path, requested)
        except (PreflightError, ProjectBusyError) as error:
            return _TEMPLATES.TemplateResponse(
                request=request,
                name="tasks_new.html",
                context=context(request, error=str(error), bundled_scenario=_BUNDLED_SCENARIO),
                status_code=400,
            )
        return RedirectResponse(f"/tasks/{task.id}", status_code=303)

    @app.get("/tasks/{task_id}", response_class=HTMLResponse)
    async def task_detail(request: Request, task_id: str) -> HTMLResponse:
        try:
            task = service.get_task(task_id)
        except PreflightError as error:
            return HTMLResponse(str(error), status_code=404)
        return _TEMPLATES.TemplateResponse(
            request=request,
            name="task_detail.html",
            context=context(request, task=task),
        )

    @app.post("/approvals/{approval_id}/{decision}")
    async def decide(request: Request, approval_id: str, decision: str):
        form = await require_csrf(request)
        if isinstance(form, HTMLResponse):
            return form
        if decision not in {"approve", "reject"}:
            return HTMLResponse("Unknown approval decision", status_code=404)
        try:
            getattr(service, decision)(approval_id)
        except (PreflightError, RuntimeError) as error:
            return HTMLResponse(str(error), status_code=409)
        return RedirectResponse("/tasks/new", status_code=303)

    if mode == "local":
        @app.post("/tasks/{task_id}/resume")
        async def resume_task(request: Request, task_id: str):
            form = await require_csrf(request)
            if isinstance(form, HTMLResponse):
                return form
            try:
                service.resume_task(task_id)
            except (PreflightError, RuntimeError) as error:
                return HTMLResponse(str(error), status_code=409)
            return RedirectResponse(f"/tasks/{task_id}", status_code=303)

        @app.get("/settings", response_class=HTMLResponse)
        async def settings(request: Request) -> HTMLResponse:
            return _TEMPLATES.TemplateResponse(
                request=request,
                name="settings.html",
                context=context(request),
            )

    return app
