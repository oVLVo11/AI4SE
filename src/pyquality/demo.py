"""Offline deterministic demonstration of the harness's real mechanisms."""

from __future__ import annotations

import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory

from pydantic import Field

from .config import Settings
from .context import ContextBuilder
from .domain.models import AuditEvent, PublicModel, TaskStatus
from .feedback import ProgressTracker
from .llm import ActionParser, ScriptedLLM
from .loop import AgentLoop
from .policy import PolicyEngine
from .service import HarnessService
from .storage.sqlite import SQLiteTaskRepository
from .tools import SubprocessRunner, ToolDispatcher
from .validators import QualityPipeline

_CALCULATOR = """def add(left: int, right: int) -> int:
    return left - right
"""
_TEST = """from calculator import add


def test_adds_two_numbers() -> None:
    assert add(2, 3) == 5
"""
_PROJECT = """[tool.pytest.ini_options]
testpaths = ["tests"]

[tool.ruff]
target-version = "py312"
"""


class DeniedActionEvidence(PublicModel):
    attempted: bool
    dispatch_count: int = Field(ge=0)


class MechanismEvent(PublicModel):
    action: str
    policy: str
    quality: str | None
    fingerprint: str | None
    dispatched: bool


class DemoReport(PublicModel):
    schema_version: int = 1
    denied_action: DeniedActionEvidence
    action_order: tuple[str, ...]
    first_failure_category: str
    model_saw_first_failure: bool
    first_patch_digest: str
    second_patch_digest: str
    first_fingerprint: str
    second_fingerprint: str
    normalized_events: tuple[MechanismEvent, ...]
    final_status: TaskStatus


class DemoError(RuntimeError):
    """Typed, path-free failure exposed by the bundled scenario."""


class _FixedClock:
    def now(self) -> datetime:
        return datetime(2026, 7, 29, tzinfo=UTC)


class _Audit:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def emit(self, event: AuditEvent) -> None:
        self.events.append(event)


class _RecordingDispatcher:
    def __init__(self, delegate: ToolDispatcher) -> None:
        self._delegate = delegate
        self.actions: list[str] = []

    def dispatch(self, action, decision, current_snapshot_digest, *, approved=False):
        self.actions.append(action.kind)
        return self._delegate.dispatch(
            action,
            decision,
            current_snapshot_digest,
            approved=approved,
        )

    def expected_after_digests(self, action):
        return self._delegate.expected_after_digests(action)

    def matches_expected_after_digests(self, expected_after_digests):
        return self._delegate.matches_expected_after_digests(expected_after_digests)


def _action(kind: str, arguments: dict[str, object], rationale: str) -> str:
    return json.dumps(
        {"arguments": arguments, "kind": kind, "rationale": rationale},
        sort_keys=True,
        separators=(",", ":"),
    )


def _patch(before: str, after: str) -> str:
    return (
        "--- a/calculator.py\n"
        "+++ b/calculator.py\n"
        "@@ -1,2 +1,2 @@\n"
        " def add(left: int, right: int) -> int:\n"
        f"-    return {before}\n"
        f"+    return {after}\n"
    )


def _write_fixture(root: Path) -> None:
    (root / "tests").mkdir(parents=True)
    (root / "calculator.py").write_text(_CALCULATOR, encoding="utf-8")
    (root / "tests" / "test_calculator.py").write_text(_TEST, encoding="utf-8")
    (root / "pyproject.toml").write_text(_PROJECT, encoding="utf-8")


def run_demo(work_dir: Path) -> DemoReport:
    """Run the fixed offline scenario and return path/timestamp-free evidence."""
    base = Path(work_dir)
    base.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix="pyquality-demo-", dir=base) as temporary:
        runtime = Path(temporary)
        repository_root = runtime / "repository"
        repository_root.mkdir()
        _write_fixture(repository_root)
        database = SQLiteTaskRepository(runtime / "state.sqlite")
        settings = Settings(round_limit=8, subprocess_timeout_s=30)
        policy = PolicyEngine(repository_root)
        dispatcher = _RecordingDispatcher(
            ToolDispatcher(repository_root, policy, SubprocessRunner(), settings)
        )
        first_patch = _patch("left - right", "left + right + 1")
        second_patch = _patch("left + right + 1", "left + right")
        responses = (
            _action("read_file", {"path": "../secret"}, "inspect outside the repository"),
            _action("apply_patch", {"patch": first_patch}, "attempt an incomplete correction"),
            _action("apply_patch", {"patch": second_patch}, "correct after assertion feedback"),
            _action("finish", {}, "finish only after green verification"),
        )
        model = ScriptedLLM(responses)
        audit = _Audit()
        loop = AgentLoop(
            repository=database,
            policy=policy,
            dispatcher=dispatcher,
            pipeline=QualityPipeline(SubprocessRunner(), settings, repository_root),
            parser=ActionParser(settings),
            llm=model,
            context_builder=ContextBuilder(
                source_bytes=settings.source_excerpt_bytes,
                total_bytes=settings.feedback_total_bytes,
            ),
            progress_tracker=ProgressTracker(),
            clock=_FixedClock(),
            audit_sink=audit,
        )
        service = HarnessService(
            repository=database,
            loop=loop,
            settings=settings,
            provider="mock",
            verifier_finder=lambda name: sys.executable if name in {"pytest", "ruff"} else None,
            allowed_root=repository_root,
        )
        try:
            task = service.create_task(repository_root, "repair calculator addition")
            result = service.start_task(task.id).result(timeout=60)
            snapshot = database.resume_snapshot(task.id)
        except Exception as error:  # noqa: BLE001 - sanitize all composed boundaries.
            raise DemoError(f"deterministic demo failed: {type(error).__name__}") from None
        finally:
            service.close()
            database.close()

        action_order = tuple(
            json.loads(item.action_json)["kind"]
            for item in snapshot.iterations
            if item.action_json is not None
        )
        events = tuple(
            MechanismEvent(
                action=json.loads(item.action_json)["kind"],
                policy=item.policy_outcome.value if item.policy_outcome is not None else "none",
                quality=item.quality_outcome,
                fingerprint=item.fingerprint,
                dispatched=json.loads(item.action_json)["kind"] in dispatcher.actions,
            )
            for item in snapshot.iterations
            if item.action_json is not None
        )
        findings = [
            record.finding
            for record in snapshot.findings
            if record.finding.category == "assertion"
        ]
        fingerprints = [
            item.fingerprint for item in snapshot.iterations if item.fingerprint is not None
        ]
        if (
            result.status is not TaskStatus.SUCCEEDED
            or action_order != ("read_file", "apply_patch", "apply_patch", "finish")
            or not findings
            or len(fingerprints) < 2
        ):
            raise DemoError("deterministic demo contract was not satisfied")
        model_saw_feedback = any(
            "assertion" in message.content.casefold()
            for message in model.calls[2]
        )
        return DemoReport(
            denied_action=DeniedActionEvidence(
                attempted=True,
                dispatch_count=sum(action == "read_file" for action in dispatcher.actions),
            ),
            action_order=action_order,
            first_failure_category=findings[0].category,
            model_saw_first_failure=model_saw_feedback,
            first_patch_digest=hashlib.sha256(first_patch.encode("utf-8")).hexdigest(),
            second_patch_digest=hashlib.sha256(second_patch.encode("utf-8")).hexdigest(),
            first_fingerprint=fingerprints[0],
            second_fingerprint=fingerprints[1],
            normalized_events=events,
            final_status=result.status,
        )
