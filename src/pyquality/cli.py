"""Command-line entry point for the harness presentation boundary."""

from __future__ import annotations

import argparse
import getpass
import json
from collections.abc import Callable, Sequence
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Protocol

import uvicorn

from .security import CredentialService, CredentialStatus


class _Credentials(Protocol):
    def set(self, account: str, secret: str) -> None: ...

    def status(self, account: str) -> CredentialStatus: ...

    def clear(self, account: str) -> None: ...


class _RunService(Protocol):
    def create_task(self, repo_path: Path | str, request: str): ...

    def start_task(self, task_id: str): ...


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pyquality")
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run")
    run.add_argument("repo", type=Path)
    run.add_argument("request")
    serve = commands.add_parser("serve")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", default=8000, type=int)
    serve.add_argument("--repo", type=Path, default=Path.cwd())
    demo = commands.add_parser("demo")
    demo.add_argument("--json", action="store_true", dest="as_json")
    credential = commands.add_parser("credential")
    credential_commands = credential.add_subparsers(
        dest="credential_command", required=True
    )
    credential_commands.add_parser("set")
    credential_commands.add_parser("status")
    credential_commands.add_parser("clear")
    return parser


def _default_credentials() -> CredentialService:
    import keyring

    return CredentialService(keyring.get_keyring(), service_name="pyquality")


def _default_run_service(repo: Path) -> _RunService:
    from .application import build_service

    return build_service(repo)


def _default_app_factory(repo: Path, mode: str) -> object:
    from .web.app import PublicDemoService, create_app

    if mode == "public_mock":
        return create_app(
            PublicDemoService({"broken_calculator": "public-demo"}),
            mode="public_mock",
        )
    from .application import build_service

    return create_app(build_service(repo), mode="local")


def main(
    argv: Sequence[str] | None = None,
    *,
    service: _RunService | None = None,
    credentials: _Credentials | None = None,
    app_factory: Callable[[str], object] | None = None,
    demo_runner: Callable[[], int] | None = None,
) -> int:
    args = _parser().parse_args(argv)
    if args.command == "credential":
        if credentials is None:
            credentials = _default_credentials()
        if args.credential_command == "set":
            credentials.set("provider", getpass.getpass("Provider credential: "))
            print("credential stored")
        elif args.credential_command == "status":
            print("present" if credentials.status("provider").present else "missing")
        else:
            credentials.clear("provider")
            print("credential cleared")
        return 0
    if args.command == "serve":
        if app_factory is None:
            app = _default_app_factory(args.repo, "local")
        else:
            app = app_factory("local")
        uvicorn.run(app, host=args.host, port=args.port)
        return 0
    if args.command == "run":
        if service is None:
            service = _default_run_service(args.repo)
        task = service.create_task(args.repo, args.request)
        result = service.start_task(task.id).result()
        print(result.model_dump_json())
        return 0 if result.status.value == "succeeded" else 1
    if demo_runner is not None:
        return demo_runner()
    from .demo import DemoError, run_demo

    try:
        with TemporaryDirectory(prefix="pyquality-demo-cli-") as directory:
            report = run_demo(Path(directory))
    except BaseException as error:  # noqa: BLE001 - sanitize the complete CLI lifecycle.
        message = (
            str(error)
            if isinstance(error, DemoError)
            else f"deterministic demo failed: {type(error).__name__}"
        )
        print(json.dumps({"error": message}, sort_keys=True))
        return 1
    print(report.model_dump_json() if args.as_json else "deterministic demo succeeded")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
