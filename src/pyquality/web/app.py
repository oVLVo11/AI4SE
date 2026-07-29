"""Server-rendered, session-protected local WebUI."""

from __future__ import annotations

import secrets
from pathlib import Path
from typing import Literal, Protocol

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from ..service import PreflightError, ProjectBusyError, TaskView


class WebService(Protocol):
    def create_task(self, repo_path: Path | str, request: str) -> TaskView: ...

    def start_task(self, task_id: str) -> object: ...

    def get_task(self, task_id: str) -> TaskView: ...

    def approve(self, approval_id: str) -> None: ...

    def reject(self, approval_id: str) -> None: ...


_TEMPLATES = Jinja2Templates(directory=str(Path(__file__).with_name("templates")))
_BUNDLED_SCENARIO = "broken_calculator"


def create_app(
    service: WebService, mode: Literal["local", "public_mock"] = "local"
) -> FastAPI:
    """Create a local UI or a path/credential-isolated public mock UI."""
    if mode not in {"local", "public_mock"}:
        raise ValueError("unsupported WebUI mode")
    app = FastAPI()
    sessions: dict[str, dict[str, object]] = {}

    @app.middleware("http")
    async def local_session(request: Request, call_next):
        session_id = request.cookies.get("pyquality_session")
        if not isinstance(session_id, str) or session_id not in sessions:
            session_id = secrets.token_urlsafe(32)
            sessions[session_id] = {}
        request.scope["session"] = sessions[session_id]
        response = await call_next(request)
        response.set_cookie(
            "pyquality_session",
            session_id,
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
        if mode == "public_mock":
            if set(form) - {"scenario", "csrf_token"} or form.get("scenario") != _BUNDLED_SCENARIO:
                return HTMLResponse("Public demo accepts only the bundled scenario", status_code=403)
            repo_path: Path | str = _BUNDLED_SCENARIO
            requested = "Run bundled scenario"
        else:
            repo_path = Path(str(form.get("repo_path", "")))
            requested = str(form.get("request", ""))
        try:
            task = service.create_task(repo_path, requested)
            service.start_task(task.id)
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
        @app.get("/settings", response_class=HTMLResponse)
        async def settings(request: Request) -> HTMLResponse:
            return _TEMPLATES.TemplateResponse(
                request=request,
                name="settings.html",
                context=context(request),
            )

    return app
