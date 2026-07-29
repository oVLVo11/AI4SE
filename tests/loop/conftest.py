from __future__ import annotations

import hashlib
import json
from collections import Counter, deque
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import pytest

from pyquality.context import ContextBuilder
from pyquality.domain.models import (
    Action,
    AuditEvent,
    CheckStatus,
    Finding,
    PolicyDecision,
    QualityReport,
    ToolResult,
)
from pyquality.feedback import ProgressTracker
from pyquality.llm import ActionParser, LLMClient, ScriptedLLM
from pyquality.loop import AgentLoop, Policy
from pyquality.policy import PolicyEngine
from pyquality.storage.sqlite import SQLiteTaskRepository

NOW = datetime(2026, 7, 29, tzinfo=UTC)


def action_json(kind: str, arguments: dict[str, object] | None = None, rationale: str = "act") -> str:
    return json.dumps(
        {"kind": kind, "arguments": arguments or {}, "rationale": rationale},
        sort_keys=True,
        separators=(",", ":"),
    )


def ordinary_patch_json(replacement: str = "1") -> str:
    patch = (
        "--- a/src/calc.py\n"
        "+++ b/src/calc.py\n"
        "@@ -1,2 +1,2 @@\n"
        " # calc\n"
        "-return_value = 0\n"
        f"+return_value = {replacement}\n"
    )
    return action_json("apply_patch", {"patch": patch}, f"set value to {replacement}")


def dependency_patch_json() -> str:
    patch = (
        "--- a/pyproject.toml\n"
        "+++ b/pyproject.toml\n"
        "@@ -1,2 +1,2 @@\n"
        '-name = "demo"\n'
        '+name = "fixed"\n'
        ' version = "1"\n'
    )
    return action_json("apply_patch", {"patch": patch}, "update dependency metadata")


def finish_json() -> str:
    return action_json("finish", rationale="verify completion")


def quality_json() -> str:
    return action_json("run_quality", rationale="establish green completion evidence")


def failed_report(category: str = "assertion") -> QualityReport:
    finding = Finding(
        source="pytest",
        category=category,
        severity="error",
        path="tests/test_calc.py",
        line=4,
        summary="assertion still fails",
        evidence="assert 0 == 1",
        group_key="pytest:assertion:test_calc:4",
    )
    return QualityReport(
        targeted_pytest_status=CheckStatus.FAILED,
        full_pytest_status=CheckStatus.FAILED,
        ruff_status=CheckStatus.PASSED,
        findings=(finding,),
        changed_paths=("src/calc.py",),
    )


def successful_report() -> QualityReport:
    return QualityReport(
        targeted_pytest_status=CheckStatus.NOT_RUN,
        full_pytest_status=CheckStatus.PASSED,
        ruff_status=CheckStatus.PASSED,
        changed_paths=("src/calc.py",),
    )


class FixedClock:
    def __init__(self, now: datetime = NOW) -> None:
        self.value = now

    def now(self) -> datetime:
        return self.value


class RecordingAuditSink:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def emit(self, event: AuditEvent) -> None:
        self.events.append(event)


class ScriptedPipeline:
    def __init__(self, reports: Sequence[QualityReport | Exception]) -> None:
        self._reports = deque(reports)
        self.calls: list[set[Path]] = []

    def run(self, changed_paths: set[Path]) -> QualityReport:
        self.calls.append(set(changed_paths))
        if not self._reports:
            raise AssertionError("unexpected quality run")
        outcome = self._reports.popleft()
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class RecordingDispatcher:
    def __init__(self, results: Sequence[ToolResult] = ()) -> None:
        self._results = deque(results)
        self.actions: list[Action] = []
        self.approved_flags: list[bool] = []
        self.expected: dict[str, str | None] = {"pyproject.toml": "d" * 64}
        self.effect_already_matches = False
        self.on_dispatch: Callable[[], None] | None = None

    def dispatch(
        self,
        action: Action,
        decision: PolicyDecision,
        current_snapshot_digest: str,
        *,
        approved: bool = False,
    ) -> ToolResult:
        del decision, current_snapshot_digest
        self.actions.append(action)
        self.approved_flags.append(approved)
        if self.on_dispatch is not None:
            self.on_dispatch()
        if self._results:
            return self._results.popleft()
        changed = action.kind == "apply_patch"
        changed_path = (
            "src/calc.py"
            if changed and "src/calc.py" in str(action.arguments.get("patch", ""))
            else "pyproject.toml"
        )
        after_digest = hashlib.sha256(action.model_dump_json().encode()).hexdigest()
        return ToolResult(
            effect_kind=action.kind,
            code_changed=changed,
            changed_paths=(changed_path,) if changed else (),
            before_digests={changed_path: "c" * 64} if changed else {},
            after_digests={changed_path: after_digest} if changed else {},
            normalized_metadata={"code": "ok"},
        )

    def expected_after_digests(self, action: Action) -> dict[str, str | None] | None:
        return dict(self.expected) if action.kind == "apply_patch" else {}

    def matches_expected_after_digests(
        self, expected_after_digests: dict[str, str | None]
    ) -> bool:
        return self.effect_already_matches and expected_after_digests == self.expected

    def dispatch_count(self, raw_action: str) -> int:
        target = ActionParser().parse(raw_action)
        return Counter(action.model_dump_json() for action in self.actions)[target.model_dump_json()]


@dataclass
class Harness:
    loop: AgentLoop
    task_id: str
    repository: SQLiteTaskRepository
    llm: LLMClient
    dispatcher: RecordingDispatcher
    pipeline: ScriptedPipeline
    audit: RecordingAuditSink
    repo_root: Path
    db_path: Path

    def restart(
        self,
        llm: LLMClient,
        pipeline: ScriptedPipeline,
        *,
        policy: Policy | None = None,
    ) -> None:
        self.repository.close()
        self.repository = SQLiteTaskRepository(self.db_path)
        self.llm = llm
        self.pipeline = pipeline
        self.loop = AgentLoop(
            repository=self.repository,
            policy=policy or PolicyEngine(self.repo_root),
            dispatcher=self.dispatcher,
            pipeline=pipeline,
            parser=ActionParser(),
            llm=llm,
            context_builder=ContextBuilder(),
            progress_tracker=ProgressTracker(),
            clock=FixedClock(),
            audit_sink=self.audit,
        )


@pytest.fixture
def loop_fixture(tmp_path: Path) -> Callable[..., Harness]:
    def build(
        *,
        responses: Sequence[str] = (),
        reports: Sequence[QualityReport | Exception] = (),
        dispatch_results: Sequence[ToolResult] = (),
        round_limit: int = 8,
        deadline: datetime | None = None,
        clock: FixedClock | None = None,
        llm: LLMClient | None = None,
        policy_factory: Callable[[Path], Policy] | None = None,
    ) -> Harness:
        repo_root = tmp_path / f"repo-{hashlib.sha256(str(len(list(tmp_path.iterdir()))).encode()).hexdigest()[:8]}"
        (repo_root / "src").mkdir(parents=True)
        (repo_root / "src" / "calc.py").write_text(
            "# calc\nreturn_value = 0\n", encoding="utf-8"
        )
        (repo_root / "pyproject.toml").write_text(
            'name = "demo"\nversion = "1"\n', encoding="utf-8"
        )
        db_path = tmp_path / f"state-{repo_root.name}.sqlite"
        repository = SQLiteTaskRepository(db_path)
        task = repository.create_task(
            str(repo_root.resolve()),
            "repair calculation",
            round_limit=round_limit,
            deadline=deadline,
        )
        client = llm or ScriptedLLM(responses)
        dispatcher = RecordingDispatcher(dispatch_results)
        pipeline = ScriptedPipeline(reports)
        audit = RecordingAuditSink()
        policy = policy_factory(repo_root) if policy_factory is not None else PolicyEngine(repo_root)
        loop = AgentLoop(
            repository=repository,
            policy=policy,
            dispatcher=dispatcher,
            pipeline=pipeline,
            parser=ActionParser(),
            llm=client,
            context_builder=ContextBuilder(),
            progress_tracker=ProgressTracker(),
            clock=clock or FixedClock(),
            audit_sink=audit,
        )
        return Harness(
            loop,
            task.id,
            repository,
            client,
            dispatcher,
            pipeline,
            audit,
            repo_root,
            db_path,
        )

    return build
