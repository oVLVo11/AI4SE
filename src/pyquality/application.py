"""Production composition root for one repository-scoped harness process."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

import keyring

from .config import load_settings
from .context import ContextBuilder
from .feedback import ProgressTracker
from .llm import ActionParser, OpenAICompatibleLLM, ScriptedLLM
from .loop import AgentLoop
from .policy import PolicyEngine
from .security import AuditLogger, CredentialService
from .service import HarnessService
from .storage.sqlite import SQLiteTaskRepository
from .tools import SubprocessRunner, ToolDispatcher
from .validators import QualityPipeline


class _SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


def build_service(
    repo_root: Path,
    *,
    state_path: Path | None = None,
    audit_path: Path | None = None,
    provider: str | None = None,
) -> HarnessService:
    """Wire concrete storage, policy, tools, validators, provider, and audit boundaries."""
    root = Path(repo_root).resolve(strict=True)
    settings = load_settings(root, None)
    runtime_dir = root / ".pyquality"
    runtime_dir.mkdir(mode=0o700, exist_ok=True)
    audit = AuditLogger(audit_path or runtime_dir / "audit.jsonl")
    repository = SQLiteTaskRepository(
        state_path or runtime_dir / "state.sqlite",
        audit_event_preparer=audit.prepare,
    )
    backend = keyring.get_keyring()
    credentials = CredentialService(backend, service_name="pyquality")
    selected_provider = provider or os.environ.get("PYQUALITY_PROVIDER", "openai")
    if selected_provider == "mock":
        llm = ScriptedLLM(())
    else:
        endpoint = os.environ.get(
            "PYQUALITY_ENDPOINT", "https://api.openai.com/v1/chat/completions"
        )
        model = os.environ.get("PYQUALITY_MODEL", "gpt-5-mini")

        def credential() -> str:
            value = backend.get_password("pyquality", "provider")
            if not isinstance(value, str) or not value:
                raise RuntimeError("provider credential is unavailable")
            return value

        llm = OpenAICompatibleLLM.from_settings(
            endpoint, model, credential, settings
        )
    policy = PolicyEngine(root)
    runner = SubprocessRunner()
    loop = AgentLoop(
        repository=repository,
        policy=policy,
        dispatcher=ToolDispatcher(root, policy, runner, settings),
        pipeline=QualityPipeline(runner, settings, root),
        parser=ActionParser(settings),
        llm=llm,
        context_builder=ContextBuilder(
            source_bytes=settings.source_excerpt_bytes,
            total_bytes=settings.feedback_total_bytes,
        ),
        progress_tracker=ProgressTracker(),
        clock=_SystemClock(),
        audit_sink=audit,
    )
    return HarnessService(
        repository=repository,
        loop=loop,
        settings=settings,
        credentials=credentials,
        provider=selected_provider,
        audit_path=audit_path or runtime_dir / "audit.jsonl",
        allowed_root=root,
    )
