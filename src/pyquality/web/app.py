"""Server-rendered, session-protected local WebUI."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import secrets
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from threading import Lock
from typing import Literal, Protocol

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import ConfigDict, Field
from starlette.requests import ClientDisconnect

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
_PUBLIC_FORM_CONTENT_TYPE = "application/x-www-form-urlencoded"
_PUBLIC_FORM_LIMIT_BYTES = 4_096
_PUBLIC_FORM_FIELDS = frozenset({"scenario", "csrf_token"})
_URLENCODED_HEX_DIGITS = frozenset(b"0123456789abcdefABCDEF")


class PublicDemoEvidence(PublicModel):
    """Small, source-free evidence from the bundled deterministic scenario."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    denied_action: bool
    denied_dispatch_count: int = Field(ge=0, le=0)
    first_failure_category: Literal["assertion"]
    model_saw_first_failure: bool
    action_order: tuple[
        Literal["read_file"],
        Literal["apply_patch"],
        Literal["apply_patch"],
        Literal["finish"],
    ]


class PublicDemoBusyError(PreflightError):
    """Raised when the bounded public execution slot is unavailable."""


class _PublicFormError(ValueError):
    def __init__(self, message: str, status_code: int) -> None:
        super().__init__(message)
        self.status_code = status_code


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

    def __init__(
        self,
        scenarios: Mapping[str, str],
        runner: Callable[[], DemoReport],
        *,
        cooldown_s: float = 2.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if cooldown_s < 0:
            raise ValueError("public demo cooldown must not be negative")
        self._scenarios = dict(scenarios)
        self._runner = runner
        self._cooldown_s = cooldown_s
        self._clock = clock
        self._state: tuple[TaskView, PublicDemoEvidence] | None = None
        self._next_run_at = 0.0
        self._state_lock = Lock()
        self._run_gate = Lock()

    def run_scenario(self, scenario_id: str) -> TaskView:
        cached = self._admit(scenario_id)
        if cached is not None:
            return cached
        try:
            return self._execute()
        finally:
            self._run_gate.release()

    async def run_scenario_async(self, scenario_id: str) -> TaskView:
        """Admit before offloading so rejected requests never enter a worker queue."""
        cached = self._admit(scenario_id)
        if cached is not None:
            return cached
        try:
            worker = asyncio.get_running_loop().run_in_executor(
                None, self._execute_and_release
            )
        except BaseException:
            self._run_gate.release()
            raise
        return await worker

    def get_task(self, task_id: str) -> TaskView:
        with self._state_lock:
            if self._state is None or task_id != _PUBLIC_DEMO_TASK_ID:
                raise PreflightError("task does not exist")
            return self._state[0]

    def get_evidence(self, task_id: str) -> PublicDemoEvidence | None:
        with self._state_lock:
            if self._state is None or task_id != _PUBLIC_DEMO_TASK_ID:
                return None
            return self._state[1]

    def _admit(self, scenario_id: str) -> TaskView | None:
        task_id = self._scenarios.get(scenario_id)
        if scenario_id != _BUNDLED_SCENARIO or task_id != _PUBLIC_DEMO_TASK_ID:
            raise PreflightError("public scenario is unavailable")
        if not self._run_gate.acquire(blocking=False):
            raise PublicDemoBusyError("public demo is busy")
        release_gate = True
        try:
            now = self._clock()
            with self._state_lock:
                if now >= self._next_run_at:
                    release_gate = False
                    return None
                if self._state is None:
                    cached = None
                else:
                    cached = self._state[0]
            if cached is None:
                raise PublicDemoBusyError("public demo is cooling down")
            return cached
        finally:
            if release_gate:
                self._run_gate.release()

    def _execute(self) -> TaskView:
        try:
            report = self._runner()
            if (
                report.final_status is not TaskStatus.SUCCEEDED
                or report.denied_action.attempted is not True
                or report.denied_action.dispatch_count != 0
                or report.first_failure_category != "assertion"
                or report.model_saw_first_failure is not True
                or report.action_order != _PUBLIC_DEMO_ACTION_ORDER
            ):
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
        except BaseException as error:
            with self._state_lock:
                self._state = None
                self._next_run_at = self._clock() + self._cooldown_s
            if isinstance(error, Exception):
                raise PreflightError("public demo execution failed") from None
            raise
        with self._state_lock:
            self._state = (view, evidence)
            self._next_run_at = self._clock() + self._cooldown_s
        return view

    def _execute_and_release(self) -> TaskView:
        try:
            return self._execute()
        finally:
            self._run_gate.release()

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

    def verify_csrf(
        request: Request, form: Mapping[str, object]
    ) -> dict[str, object] | HTMLResponse:
        supplied = form.get("csrf_token")
        expected = request.session.get("csrf_token")
        if not isinstance(supplied, str) or not isinstance(expected, str) or not secrets.compare_digest(supplied, expected):
            return HTMLResponse("Forbidden", status_code=403)
        return dict(form)

    async def require_csrf(request: Request) -> dict[str, object] | HTMLResponse:
        return verify_csrf(request, dict(await request.form()))

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
        if mode == "public_mock":
            try:
                public_form = await _parse_public_form(request)
            except _PublicFormError as error:
                return HTMLResponse(str(error), status_code=error.status_code)
            form = verify_csrf(request, public_form)
        else:
            form = await require_csrf(request)
        if isinstance(form, HTMLResponse):
            return form
        try:
            if mode == "public_mock":
                task = await service.run_scenario_async(_BUNDLED_SCENARIO)  # type: ignore[attr-defined]
            else:
                repo_path = Path(str(form.get("repo_path", "")))
                requested = str(form.get("request", ""))
                task = service.create_task(repo_path, requested)
        except PublicDemoBusyError as error:
            return HTMLResponse(
                str(error), status_code=503, headers={"Retry-After": "1"}
            )
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


async def _parse_public_form(request: Request) -> dict[str, str]:
    content_types = request.headers.getlist("content-type")
    if len(content_types) != 1 or not _is_public_form_content_type(content_types[0]):
        raise _PublicFormError("Unsupported Media Type", 415)

    content_lengths = request.headers.getlist("content-length")
    if len(content_lengths) > 1:
        raise _PublicFormError("Malformed public demo request", 400)
    if content_lengths:
        try:
            declared_length = int(content_lengths[0], 10)
        except ValueError:
            raise _PublicFormError("Malformed public demo request", 400) from None
        if declared_length < 0:
            raise _PublicFormError("Malformed public demo request", 400)
        if declared_length > _PUBLIC_FORM_LIMIT_BYTES:
            raise _PublicFormError("Public demo request is too large", 413)

    body = bytearray()
    try:
        async for chunk in request.stream():
            if len(body) + len(chunk) > _PUBLIC_FORM_LIMIT_BYTES:
                raise _PublicFormError("Public demo request is too large", 413)
            body.extend(chunk)
    except ClientDisconnect:
        raise _PublicFormError("Malformed public demo request", 400) from None

    fields = bytes(body).split(b"&")
    if len(fields) != 2:
        raise _PublicFormError("Malformed public demo request", 400)
    pairs: list[tuple[str, str]] = []
    for field in fields:
        name, separator, value = field.partition(b"=")
        if separator != b"=" or not name:
            raise _PublicFormError("Malformed public demo request", 400)
        pairs.append((_decode_public_form_component(name), _decode_public_form_component(value)))

    names = [name for name, _value in pairs]
    if len(set(names)) != 2 or set(names) != _PUBLIC_FORM_FIELDS:
        raise _PublicFormError("Malformed public demo request", 400)
    form = dict(pairs)
    if form["scenario"] != _BUNDLED_SCENARIO:
        raise _PublicFormError("Public demo accepts only the bundled scenario", 403)
    return form


def _is_public_form_content_type(value: str) -> bool:
    parts = [part.strip() for part in value.split(";")]
    if not parts or parts[0].casefold() != _PUBLIC_FORM_CONTENT_TYPE:
        return False
    parameters: dict[str, str] = {}
    for part in parts[1:]:
        name, separator, parameter_value = part.partition("=")
        normalized_name = name.strip().casefold()
        normalized_value = parameter_value.strip().strip('"').casefold()
        if (
            separator != "="
            or normalized_name in parameters
            or normalized_name != "charset"
            or normalized_value not in {"utf-8", "utf8"}
        ):
            return False
        parameters[normalized_name] = normalized_value
    return True


def _decode_public_form_component(value: bytes) -> str:
    decoded = bytearray()
    index = 0
    while index < len(value):
        current = value[index]
        if current == ord("+"):
            decoded.append(ord(" "))
            index += 1
            continue
        if current == ord("%"):
            if (
                index + 2 >= len(value)
                or value[index + 1] not in _URLENCODED_HEX_DIGITS
                or value[index + 2] not in _URLENCODED_HEX_DIGITS
            ):
                raise _PublicFormError("Malformed public demo request", 400)
            decoded.append(int(value[index + 1 : index + 3], 16))
            index += 3
            continue
        if current > 0x7F:
            raise _PublicFormError("Malformed public demo request", 400)
        decoded.append(current)
        index += 1
    try:
        text = decoded.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise _PublicFormError("Malformed public demo request", 400) from None
    if not text.isascii():
        raise _PublicFormError("Malformed public demo request", 400)
    return text
