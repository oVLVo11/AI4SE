"""Durable bounded agent-loop orchestration without a framework runner."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from contextvars import ContextVar
from datetime import datetime
from pathlib import Path
from typing import Protocol
from uuid import uuid4

from pyquality.context import ContextBuilder, ContextInput
from pyquality.domain.models import (
    Action,
    ApprovalDecision,
    AuditEvent,
    CheckStatus,
    Finding,
    PolicyDecision,
    PolicyOutcome,
    QualityReport,
    TaskResult,
    TaskStatus,
    ToolResult,
)
from pyquality.feedback import (
    FeedbackComposer,
    FeedbackPacket,
    ProgressEntry,
    ProgressTracker,
    failure_fingerprint,
)
from pyquality.llm import ActionFormatError, ActionParser, LLMClient, Message, ProviderError
from pyquality.memory import MemoryContext
from pyquality.storage.sqlite import (
    ApprovalRecord,
    RecoverySnapshot,
    SQLiteTaskRepository,
    StorageStateError,
    TransitionIntentRecord,
)

_TERMINAL = frozenset(
    {
        TaskStatus.SUCCEEDED,
        TaskStatus.STALLED,
        TaskStatus.BUDGET_EXHAUSTED,
        TaskStatus.BLOCKED,
        TaskStatus.FAILED,
    }
)
_REPAIR_MESSAGE = (
    "Schema repair required: return exactly one JSON object containing only the allowed "
    "kind, arguments, and rationale fields. Do not include prose or markdown."
)


class ApprovalStateError(RuntimeError):
    """Raised when an approval query or decision is no longer legal."""


class Clock(Protocol):
    def now(self) -> datetime: ...


class AuditSink(Protocol):
    def emit(self, event: AuditEvent) -> None: ...


class Policy(Protocol):
    def evaluate(self, action: Action) -> PolicyDecision: ...

    def revalidate(
        self, decision: PolicyDecision, action: Action, current_snapshot_digest: str
    ) -> PolicyDecision: ...


class Dispatcher(Protocol):
    def dispatch(
        self,
        action: Action,
        decision: PolicyDecision,
        current_snapshot_digest: str,
        *,
        approved: bool = False,
    ) -> ToolResult: ...

    def expected_after_digests(self, action: Action) -> dict[str, str | None] | None: ...

    def matches_expected_after_digests(
        self, expected_after_digests: dict[str, str | None]
    ) -> bool: ...


class Pipeline(Protocol):
    def run(self, changed_paths: set[Path]) -> QualityReport: ...


Approval = ApprovalRecord


class AgentLoop:
    """Own the persisted task state machine and every model/action cycle."""

    def __init__(
        self,
        *,
        repository: SQLiteTaskRepository,
        policy: Policy,
        dispatcher: Dispatcher,
        pipeline: Pipeline,
        parser: ActionParser,
        llm: LLMClient,
        context_builder: ContextBuilder,
        progress_tracker: ProgressTracker,
        clock: Clock,
        audit_sink: AuditSink,
    ) -> None:
        self._repository = repository
        self._policy = policy
        self._dispatcher = dispatcher
        self._pipeline = pipeline
        self._parser = parser
        self._llm = llm
        self._context_builder = context_builder
        self._progress_tracker = progress_tracker
        self._clock = clock
        self._audit_sink = audit_sink
        self._feedback_composer = FeedbackComposer()
        self._feedback: dict[str, FeedbackPacket] = {}
        self._changed_paths: dict[str, set[str]] = {}
        self._owner_context: ContextVar[str | None] = ContextVar(
            "pyquality_loop_owner", default=None
        )
        self._cycle_intents: ContextVar[tuple[str, ...]] = ContextVar(
            "pyquality_cycle_intents", default=()
        )

    def run(self, task_id: str) -> TaskResult:
        return self._owned_call(task_id, resume=False)

    def resume(self, task_id: str) -> TaskResult:
        return self._owned_call(task_id, resume=True)

    def _owned_call(self, task_id: str, *, resume: bool) -> TaskResult:
        owner_token = uuid4().hex
        context_token = self._owner_context.set(owner_token)
        cycle_token = self._cycle_intents.set(())
        acquired = False
        try:
            snapshot = self._repository.resume_snapshot(task_id)
            if snapshot.task.status in _TERMINAL:
                return self._saved_result(snapshot)
            if snapshot.task.status is TaskStatus.WAITING_APPROVAL:
                return self._waiting_result(snapshot)
            if snapshot.task.status is TaskStatus.CREATED:
                if resume:
                    resume = False
                if not self._repository.set_status(
                    task_id, TaskStatus.CREATED, TaskStatus.RUNNING
                ):
                    return self._owned_call(task_id, resume=True)
            acquired = self._repository.acquire_project_lease(
                task_id, owner_token=owner_token
            )
            if not acquired:
                return self._make_result(
                    task_id, TaskStatus.BLOCKED, "Repository is busy."
                )
            if resume:
                recovered = self._recover_decided_approval(task_id)
                if recovered is not None:
                    return recovered
            return self._drive(task_id)
        except (OSError, PermissionError) as error:
            return self._blocked_if_possible(task_id, error) if acquired else self._make_result(
                task_id, TaskStatus.BLOCKED, f"Execution blocked: {type(error).__name__}."
            )
        except Exception as error:  # noqa: BLE001 - injected components share no base.
            return self._failed_if_possible(task_id, error, acquired=acquired)
        finally:
            if acquired:
                try:
                    self._repository.release_project_lease(
                        task_id, owner_token=owner_token
                    )
                except Exception as release_error:  # noqa: BLE001
                    _ = release_error
            self._cycle_intents.reset(cycle_token)
            self._owner_context.reset(context_token)

    def pending_approval(self, task_id: str) -> Approval:
        approval = self._repository.pending_approval(task_id)
        if approval is None:
            raise ApprovalStateError("task has no pending approval")
        return approval

    def decide_approval(self, approval_id: str, decision: ApprovalDecision) -> None:
        try:
            approval = self._repository.decide_approval_and_resume(approval_id, decision)
            self._audit_after_commit(
                "approval_decided",
                approval.task_id,
                {"approval_id": approval.id, "decision": decision.value},
            )
        except StorageStateError as error:
            raise ApprovalStateError("approval cannot be decided") from error

    def _drive(self, task_id: str) -> TaskResult:
        while True:
            snapshot = self._repository.resume_snapshot(task_id)
            if snapshot.task.status in _TERMINAL:
                return self._saved_result(snapshot)
            stop = self._pre_call_stop(snapshot)
            if stop is not None:
                return stop

            repair_attempts = _trailing_invalid_rounds(snapshot)
            repair_messages: tuple[Message, ...] = (
                (Message(role="user", content=_REPAIR_MESSAGE),)
                if repair_attempts
                else ()
            )
            messages = self._build_messages(snapshot) + repair_messages
            context_digest = _digest_messages(messages)
            recovered = self._recover_transition(task_id, "model_call", context_digest)
            intent: TransitionIntentRecord
            if recovered is None:
                intent = self._begin_transition(
                    task_id, "model_call", context_digest, "bounded context prepared"
                )
                try:
                    raw = self._llm.complete(messages)
                except ProviderError as error:
                    return self._terminal(task_id, TaskStatus.BLOCKED, str(error))
                except RuntimeError as error:
                    return self._terminal(
                        task_id,
                        TaskStatus.FAILED,
                        f"Model client consistency failure: {type(error).__name__}.",
                    )
                try:
                    action = self._parser.parse(raw)
                except ActionFormatError:
                    action = None
                payload: dict[str, object] = (
                    {"outcome": "invalid"}
                    if action is None
                    else {
                        "outcome": "action",
                        "action": action.model_dump(mode="json"),
                    }
                )
                self._complete_transition(
                    intent,
                    _digest_text(raw),
                    "normalized model result persisted",
                    "model_call_completed",
                    payload=payload,
                )
            else:
                intent = recovered
                payload = intent.result_payload or {}
                action = _action_from_transition_payload(payload)

            self._cycle_intents.set((intent.id,))
            sequence = len(snapshot.iterations) + 1
            if action is None:
                self._repository.append_iteration(
                    task_id,
                    sequence=sequence,
                    context_digest=context_digest,
                    source_intent_ids=self._cycle_intents.get(),
                    owner_token=self._owner(),
                )
                repair_attempts = _trailing_invalid_rounds(
                    self._repository.resume_snapshot(task_id)
                )
                if repair_attempts > 2:
                    return self._terminal(
                        task_id,
                        TaskStatus.FAILED,
                        "Model response remained invalid after two schema repairs.",
                    )
                continue

            if self._deadline_reached(self._repository.resume_snapshot(task_id)):
                self._repository.append_iteration(
                    task_id,
                    sequence=sequence,
                    context_digest=context_digest,
                    action_json=_canonical(action.model_dump(mode="json")),
                    source_intent_ids=self._cycle_intents.get(),
                    owner_token=self._owner(),
                )
                return self._terminal(
                    task_id, TaskStatus.BUDGET_EXHAUSTED, "Deadline exhausted."
                )
            cycle = self._execute_action(task_id, snapshot, sequence, context_digest, action)
            if cycle is not None:
                return cycle

    def _execute_action(
        self,
        task_id: str,
        snapshot: RecoverySnapshot,
        sequence: int,
        context_digest: str,
        action: Action,
    ) -> TaskResult | None:
        action_json = _canonical(action.model_dump(mode="json"))
        decision = self._policy_decision(task_id, action_json, action)
        if decision.outcome is PolicyOutcome.DENY:
            finding = _harness_finding(
                "policy denied action", decision.impact_summary, f"policy:{decision.matched_rule}"
            )
            self._append_cycle(
                task_id,
                sequence,
                context_digest,
                action_json,
                decision,
                findings=(finding,),
            )
            self._feedback[task_id] = self._compose((finding,))
            return self._stop_after_cycle(task_id)

        if decision.outcome is PolicyOutcome.REQUIRE_APPROVAL:
            waiting = self._make_result(
                task_id,
                TaskStatus.WAITING_APPROVAL,
                "Action requires explicit approval.",
            ).model_copy(update={"iterations": sequence})
            self._repository.request_approval_round_and_wait(
                task_id,
                sequence,
                context_digest,
                action_json,
                decision.action_digest,
                decision.repository_snapshot_digest,
                policy_decision=decision,
                waiting_result=waiting,
                source_intent_ids=self._cycle_intents.get(),
                owner_token=self._owner(),
            )
            self._audit_after_commit(
                "approval_requested", task_id, {"action_digest": decision.action_digest}
            )
            return waiting

        if action.kind in {"finish", "run_quality"}:
            quality = self._quality_for_cycle(
                task_id,
                sequence,
                context_digest,
                action_json,
                decision,
                {Path(path) for path in self._changed(task_id)},
            )
            if isinstance(quality, TaskResult):
                return quality
            return self._record_quality_cycle(
                task_id,
                sequence,
                context_digest,
                action_json,
                decision,
                quality,
                finish=action.kind == "finish",
            )

        try:
            tool_result = self._dispatch(task_id, action, decision, approved=False)
        except (OSError, PermissionError) as error:
            finding = _harness_finding(
                "tool execution blocked", type(error).__name__, f"tool:blocked:{action.kind}"
            )
            self._append_cycle(
                task_id,
                sequence,
                context_digest,
                action_json,
                decision,
                findings=(finding,),
            )
            return self._terminal(task_id, TaskStatus.BLOCKED, "Tool execution is blocked.")
        if tool_result is None:
            self._append_cycle(
                task_id, sequence, context_digest, action_json, decision
            )
            return self._terminal(task_id, TaskStatus.BUDGET_EXHAUSTED, "Deadline exhausted.")
        if not tool_result.ok:
            finding = _harness_finding(
                "tool action failed", tool_result.code, f"tool:{action.kind}:{tool_result.code}"
            )
            self._append_cycle(
                task_id,
                sequence,
                context_digest,
                action_json,
                decision,
                tool_result=tool_result,
                findings=(finding,),
            )
            self._feedback[task_id] = self._compose((finding,))
            return self._stop_after_cycle(task_id)
        self._changed(task_id).update(tool_result.changed_paths)
        if action.kind == "apply_patch" and tool_result.code_changed:
            quality = self._quality_for_cycle(
                task_id,
                sequence,
                context_digest,
                action_json,
                decision,
                {Path(path) for path in tool_result.changed_paths},
                tool_result=tool_result,
            )
            if isinstance(quality, TaskResult):
                return quality
            return self._record_quality_cycle(
                task_id,
                sequence,
                context_digest,
                action_json,
                decision,
                quality,
                tool_result=tool_result,
            )
        self._append_cycle(
            task_id,
            sequence,
            context_digest,
            action_json,
            decision,
            tool_result=tool_result,
        )
        if tool_result.output:
            self._feedback[task_id] = _text_feedback(tool_result.output)
        return self._stop_after_cycle(task_id)

    def _recover_decided_approval(self, task_id: str) -> TaskResult | None:
        snapshot = self._repository.resume_snapshot(task_id)
        approval = snapshot.decided_approval
        if approval is None:
            return None
        if approval.decision is ApprovalDecision.REJECT:
            finding = _harness_finding(
                "action rejected by user",
                "The proposed action was rejected by user.",
                f"approval:rejected:{approval.action_digest}",
            )
            if approval.execution_state == "completed":
                persisted = tuple(
                    item.finding
                    for item in snapshot.findings
                    if item.iteration_id == approval.iteration_id
                    and item.finding.group_key == finding.group_key
                )
                if len(persisted) != 1:
                    return self._terminal(
                        task_id,
                        TaskStatus.FAILED,
                        "Completed rejection feedback is inconsistent.",
                    )
                self._feedback[task_id] = self._compose(persisted)
                return None
            self._feedback[task_id] = self._compose((finding,))
            self._repository.mark_rejection_consumed(
                approval.id, finding=finding, owner_token=self._owner()
            )
            self._audit_after_commit(
                "approval_rejection_consumed", task_id, {"approval_id": approval.id}
            )
            return None
        if approval.decision is not ApprovalDecision.APPROVE:
            return self._terminal(task_id, TaskStatus.FAILED, "Approval recovery is inconsistent.")
        try:
            action = self._parser.parse(approval.action_json)
        except ActionFormatError:
            return self._terminal(
                task_id, TaskStatus.FAILED, "Persisted approval action is invalid."
            )
        saved = approval.policy_decision
        if saved is None:
            return self._terminal(task_id, TaskStatus.FAILED, "Saved policy decision is missing.")
        iteration = next(
            (item for item in snapshot.iterations if item.id == approval.iteration_id), None
        )
        if iteration is None:
            return self._terminal(
                task_id, TaskStatus.FAILED, "Approval iteration is missing."
            )
        if approval.execution_state == "completed":
            if iteration.quality_outcome is not None:
                return None
            if not self._dispatcher.matches_expected_after_digests(
                approval.expected_after_digests
            ):
                return self._terminal(
                    task_id,
                    TaskStatus.FAILED,
                    "Completed approval does not match its effect evidence.",
                )
            recovered = _recovered_tool_result(action, approval.expected_after_digests)
            self._changed(task_id).update(recovered.changed_paths)
            return self._verify_approved_effect(
                task_id, approval, recovered, already_completed=True
            )
        if (
            approval.execution_state == "intent_recorded"
            and iteration.quality_outcome in {"passed", "failed", "blocked"}
        ):
            self._repository.mark_execution_completed(
                approval.id,
                result_digest=iteration.tool_result_digest,
                owner_token=self._owner(),
            )
            if iteration.quality_outcome == "blocked":
                return self._terminal(
                    task_id, TaskStatus.BLOCKED, "Persisted verifier result is blocked."
                )
            if iteration.quality_outcome == "passed":
                return self._terminal(
                    task_id, TaskStatus.SUCCEEDED, "Full verification passed."
                )
            findings = tuple(
                item.finding
                for item in snapshot.findings
                if item.iteration_id == iteration.id
            )
            if not findings:
                return self._terminal(
                    task_id,
                    TaskStatus.FAILED,
                    "Persisted failed verifier result has no findings.",
                )
            self._feedback[task_id] = self._compose(findings)
            return None
        if (
            approval.execution_state == "intent_recorded"
            and iteration.quality_outcome == "not_run"
        ):
            self._repository.mark_execution_completed(
                approval.id,
                result_digest=iteration.tool_result_digest,
                owner_token=self._owner(),
            )
            if any(item.iteration_id == iteration.id for item in snapshot.findings):
                return self._terminal(
                    task_id, TaskStatus.BLOCKED, "Approved effect failed before verification."
                )
            return None
        if (
            approval.execution_state == "intent_recorded"
            and bool(approval.expected_after_digests)
            and (
            self._dispatcher.matches_expected_after_digests(
                approval.expected_after_digests
            )
            )
        ):
            recovered = _recovered_tool_result(action, approval.expected_after_digests)
            self._changed(task_id).update(recovered.changed_paths)
            return self._verify_approved_effect(
                task_id, approval, recovered, already_completed=False
            )
        current = self._policy.evaluate(action)
        if current.repository_snapshot_digest != approval.repository_snapshot_digest:
            return self._terminal(
                task_id, TaskStatus.BLOCKED, "Repository snapshot drifted after approval."
            )
        refreshed = self._policy.revalidate(saved, action, current.repository_snapshot_digest)
        if refreshed.outcome is PolicyOutcome.DENY:
            return self._terminal(task_id, TaskStatus.BLOCKED, refreshed.impact_summary)
        if refreshed.outcome is PolicyOutcome.REQUIRE_APPROVAL and (
            refreshed.matched_rule != saved.matched_rule
            or refreshed.impact_summary != saved.impact_summary
        ):
            waiting = self._make_result(
                task_id, TaskStatus.WAITING_APPROVAL, "Policy changed; new approval required."
            )
            self._repository.replace_approval_and_wait(
                approval.id,
                refreshed,
                waiting_result=waiting,
                owner_token=self._owner(),
            )
            return waiting

        if approval.execution_state == "intent_recorded":
            current = self._policy.evaluate(action)
            if current.repository_snapshot_digest != approval.repository_snapshot_digest:
                return self._terminal(
                    task_id, TaskStatus.BLOCKED, "Dispatch intent recovery found repository drift."
                )
        else:
            if self._deadline_reached(snapshot):
                return self._terminal(task_id, TaskStatus.BUDGET_EXHAUSTED, "Deadline exhausted.")
            expected = self._dispatcher.expected_after_digests(action)
            if expected is None:
                return self._terminal(
                    task_id, TaskStatus.BLOCKED, "Approved effect could not be prepared safely."
                )
            self._repository.mark_execution_intent(
                approval.id,
                expected_after_digests=expected,
                owner_token=self._owner(),
            )

        result = self._dispatch(task_id, action, saved, approved=True)
        if result is None:
            return self._terminal(task_id, TaskStatus.BUDGET_EXHAUSTED, "Deadline exhausted.")
        if not result.ok:
            finding = _harness_finding(
                "approved effect failed",
                f"Approved effect failed: {result.code}",
                f"approval:effect-failed:{result.code}",
            )
            self._persist_approved_tool_only(
                task_id, approval, result, findings=(finding,)
            )
            self._repository.mark_execution_completed(
                approval.id,
                result_digest=_digest_model(result),
                owner_token=self._owner(),
            )
            return self._terminal(task_id, TaskStatus.BLOCKED, f"Approved effect failed: {result.code}")
        self._changed(task_id).update(result.changed_paths)
        if result.code_changed:
            return self._verify_approved_effect(
                task_id, approval, result, already_completed=False
            )
        self._persist_approved_tool_only(task_id, approval, result)
        self._repository.mark_execution_completed(
            approval.id,
            result_digest=_digest_model(result),
            owner_token=self._owner(),
        )
        if result.output:
            self._feedback[task_id] = _text_feedback(result.output)
        return None

    def _verify_approved_effect(
        self,
        task_id: str,
        approval: ApprovalRecord,
        tool_result: ToolResult,
        *,
        already_completed: bool,
    ) -> TaskResult | None:
        try:
            report = self._run_quality(
                task_id, {Path(path) for path in tool_result.changed_paths}
            )
        except _DeadlineReached:
            self._persist_approved_tool_only(task_id, approval, tool_result)
            if not already_completed:
                self._repository.mark_execution_completed(
                    approval.id,
                    result_digest=_digest_model(tool_result),
                    owner_token=self._owner(),
                )
            return self._terminal(
                task_id, TaskStatus.BUDGET_EXHAUSTED, "Deadline exhausted."
            )
        except _BlockedTransition as error:
            finding = _harness_finding(
                "verifier unavailable", str(error), "verifier:unavailable"
            )
            report = QualityReport(
                targeted_pytest_status=CheckStatus.NOT_RUN,
                full_pytest_status=CheckStatus.FAILED,
                ruff_status=CheckStatus.FAILED,
                findings=(finding,),
                changed_paths=tool_result.changed_paths,
            )
        self._persist_approved_outcome(task_id, approval, tool_result, report)
        if not already_completed:
            self._repository.mark_execution_completed(
                approval.id,
                result_digest=_digest_model(tool_result),
                owner_token=self._owner(),
            )
        snapshot = self._repository.resume_snapshot(task_id)
        status = self._progress_tracker.decide(
            self._progress_history(task_id),
            snapshot.task.round_limit,
            snapshot.task.deadline,
            self._clock.now(),
        )
        if status is not None:
            return self._terminal(task_id, status, _summary(status))
        self._feedback[task_id] = self._compose(report.findings)
        return None

    def _persist_approved_outcome(
        self,
        task_id: str,
        approval: ApprovalRecord,
        tool_result: ToolResult,
        report: QualityReport,
    ) -> None:
        snapshot = self._repository.resume_snapshot(task_id)
        previous = next(
            (
                item.relevant_digest
                for item in reversed(snapshot.iterations)
                if item.id != approval.iteration_id and item.relevant_digest is not None
            ),
            None,
        )
        fingerprint = failure_fingerprint(report.findings) if report.findings else None
        self._repository.complete_iteration_outcome(
            task_id,
            approval.iteration_id,
            tool_result_digest=_digest_model(tool_result),
            fingerprint=fingerprint,
            relevant_digest=_relevant_digest(tool_result, report, previous),
            quality_outcome=_quality_outcome(report) or "failed",
            findings=report.findings,
            source_intent_ids=self._cycle_intents.get(),
            owner_token=self._owner(),
        )

    def _persist_approved_tool_only(
        self,
        task_id: str,
        approval: ApprovalRecord,
        tool_result: ToolResult,
        *,
        findings: tuple[Finding, ...] = (),
    ) -> None:
        snapshot = self._repository.resume_snapshot(task_id)
        previous = next(
            (
                item.relevant_digest
                for item in reversed(snapshot.iterations)
                if item.id != approval.iteration_id and item.relevant_digest is not None
            ),
            None,
        )
        fingerprint = failure_fingerprint(findings) if findings else None
        self._repository.complete_iteration_outcome(
            task_id,
            approval.iteration_id,
            tool_result_digest=_digest_model(tool_result),
            fingerprint=fingerprint,
            relevant_digest=previous,
            quality_outcome="not_run",
            findings=findings,
            source_intent_ids=self._cycle_intents.get(),
            owner_token=self._owner(),
        )

    def _quality_for_cycle(
        self,
        task_id: str,
        sequence: int,
        context_digest: str,
        action_json: str,
        decision: PolicyDecision,
        changed_paths: set[Path],
        *,
        tool_result: ToolResult | None = None,
    ) -> QualityReport | TaskResult:
        try:
            return self._run_quality(task_id, changed_paths)
        except _DeadlineReached:
            self._append_cycle(
                task_id,
                sequence,
                context_digest,
                action_json,
                decision,
                tool_result=tool_result,
            )
            return self._terminal(
                task_id, TaskStatus.BUDGET_EXHAUSTED, "Deadline exhausted."
            )
        except _BlockedTransition as error:
            finding = _harness_finding(
                "verifier unavailable", str(error), "verifier:unavailable"
            )
            self._append_cycle(
                task_id,
                sequence,
                context_digest,
                action_json,
                decision,
                tool_result=tool_result,
                findings=(finding,),
            )
            return self._terminal(task_id, TaskStatus.BLOCKED, "Verifier is unavailable.")

    def _record_quality_cycle(
        self,
        task_id: str,
        sequence: int,
        context_digest: str,
        action_json: str,
        decision: PolicyDecision,
        report: QualityReport,
        *,
        tool_result: ToolResult | None = None,
        finish: bool = False,
    ) -> TaskResult | None:
        previous = self._last_relevant_digest(task_id)
        relevant = _relevant_digest(tool_result, report, previous)
        fingerprint = failure_fingerprint(report.findings) if report.findings else None
        self._append_cycle(
            task_id,
            sequence,
            context_digest,
            action_json,
            decision,
            tool_result=tool_result,
            report=report,
            fingerprint=fingerprint,
            relevant_digest=relevant,
        )
        blocked = any(
            finding.category in {"missing_tool_dependency", "infrastructure"}
            for finding in report.findings
        )
        history = self._progress_history(task_id)
        history[-1] = history[-1].model_copy(update={"report": report, "blocked": blocked})
        snapshot = self._repository.resume_snapshot(task_id)
        stop = self._progress_tracker.decide(
            history, snapshot.task.round_limit, snapshot.task.deadline, self._clock.now()
        )
        if stop is not None:
            summary = "Full verification passed." if stop is TaskStatus.SUCCEEDED else _summary(stop)
            return self._terminal(task_id, stop, summary)
        if report.findings:
            self._feedback[task_id] = self._compose(report.findings)
        elif finish:
            self._feedback[task_id] = _text_feedback("Verification did not pass.")
        return None

    def _policy_decision(
        self, task_id: str, action_json: str, action: Action
    ) -> PolicyDecision:
        evidence = _digest_text(action_json)
        recovered = self._recover_transition(task_id, "policy", evidence)
        if recovered is not None:
            self._remember_intent(recovered.id)
            return _policy_from_transition(recovered)
        intent = self._begin_transition(
            task_id, "policy", evidence, "normalized action ready"
        )
        decision = self._policy.evaluate(action)
        self._complete_transition(
            intent,
            _digest_model(decision),
            f"policy outcome {decision.outcome.value}",
            "policy_completed",
            payload={"policy_decision": decision.model_dump(mode="json")},
        )
        self._remember_intent(intent.id)
        return decision

    def _run_quality(self, task_id: str, changed_paths: set[Path]) -> QualityReport:
        snapshot = self._repository.resume_snapshot(task_id)
        if self._deadline_reached(snapshot):
            raise _DeadlineReached
        evidence = _digest_text(_canonical(sorted(path.as_posix() for path in changed_paths)))
        recovered = self._recover_transition(task_id, "verifier", evidence)
        if recovered is not None:
            self._remember_intent(recovered.id)
            return _quality_from_transition(recovered)
        intent = self._begin_transition(
            task_id, "verifier", evidence, "quality inputs persisted"
        )
        try:
            report = self._pipeline.run(changed_paths)
        except (FileNotFoundError, PermissionError, OSError) as error:
            raise _BlockedTransition(str(error)) from error
        self._complete_transition(
            intent,
            _digest_model(report),
            "quality report persisted",
            "verifier_completed",
            payload={"quality_report": report.model_dump(mode="json")},
        )
        self._remember_intent(intent.id)
        return report

    def _dispatch(
        self, task_id: str, action: Action, decision: PolicyDecision, *, approved: bool
    ) -> ToolResult | None:
        snapshot = self._repository.resume_snapshot(task_id)
        if self._deadline_reached(snapshot):
            return None
        recovered = self._recover_transition(
            task_id, "dispatch", decision.action_digest
        )
        if recovered is not None:
            self._remember_intent(recovered.id)
            return _tool_from_transition(recovered)
        intent = self._begin_transition(
            task_id, "dispatch", decision.action_digest, "dispatch authorized"
        )
        result = self._dispatcher.dispatch(
            action,
            decision,
            decision.repository_snapshot_digest,
            approved=approved,
        )
        self._complete_transition(
            intent,
            _digest_model(result),
            "tool result persisted",
            "dispatch_completed",
            payload={"tool_result": result.model_dump(mode="json")},
        )
        self._remember_intent(intent.id)
        return result

    def _append_cycle(
        self,
        task_id: str,
        sequence: int,
        context_digest: str,
        action_json: str,
        decision: PolicyDecision,
        *,
        tool_result: ToolResult | None = None,
        report: QualityReport | None = None,
        findings: tuple[Finding, ...] = (),
        fingerprint: str | None = None,
        relevant_digest: str | None = None,
    ):
        persisted_findings = report.findings if report is not None else findings
        if fingerprint is None and persisted_findings:
            fingerprint = failure_fingerprint(persisted_findings)
        return self._repository.append_iteration(
            task_id,
            sequence=sequence,
            context_digest=context_digest,
            action_json=action_json,
            policy_outcome=decision.outcome,
            tool_result_digest=_digest_model(tool_result) if tool_result is not None else None,
            fingerprint=fingerprint,
            relevant_digest=relevant_digest,
            quality_outcome=_quality_outcome(report),
            findings=persisted_findings,
            source_intent_ids=self._cycle_intents.get(),
            owner_token=self._owner(),
        )

    def _stop_after_cycle(self, task_id: str) -> TaskResult | None:
        snapshot = self._repository.resume_snapshot(task_id)
        status = self._progress_tracker.decide(
            self._progress_history(task_id),
            snapshot.task.round_limit,
            snapshot.task.deadline,
            self._clock.now(),
        )
        return self._terminal(task_id, status, _summary(status)) if status is not None else None

    def _pre_call_stop(self, snapshot: RecoverySnapshot) -> TaskResult | None:
        status = self._progress_tracker.decide(
            self._progress_history(snapshot.task.id),
            snapshot.task.round_limit,
            snapshot.task.deadline,
            self._clock.now(),
        )
        if status is None:
            return None
        return self._terminal(snapshot.task.id, status, _summary(status))

    def _progress_history(self, task_id: str) -> list[ProgressEntry]:
        snapshot = self._repository.resume_snapshot(task_id)
        return [
            ProgressEntry(
                fingerprint=iteration.fingerprint,
                relevant_digest=iteration.relevant_digest,
                report=_recovered_report(iteration.quality_outcome),
                blocked=iteration.quality_outcome == "blocked",
            )
            for iteration in snapshot.iterations
        ]

    def _last_relevant_digest(self, task_id: str) -> str | None:
        history = self._progress_history(task_id)
        return history[-1].relevant_digest if history else None

    def _build_messages(self, snapshot: RecoverySnapshot) -> tuple[Message, ...]:
        memory = MemoryContext(
            iterations=snapshot.iterations,
            findings=tuple(finding for finding in snapshot.findings if finding.resolved_at is None),
            decisions=snapshot.decisions,
        )
        feedback = self._feedback.get(snapshot.task.id)
        if feedback is None:
            latest = snapshot.iterations[-1].id if snapshot.iterations else None
            findings = tuple(
                record.finding for record in snapshot.findings if record.iteration_id == latest
            )
            if findings:
                feedback = self._compose(findings)
            elif snapshot.iterations:
                tool_digest = snapshot.iterations[-1].tool_result_digest
                recovered_tool = next(
                    (
                        intent
                        for intent in reversed(snapshot.transition_intents)
                        if intent.kind == "dispatch"
                        and intent.result_digest == tool_digest
                        and intent.result_payload is not None
                    ),
                    None,
                )
                if recovered_tool is not None:
                    output = _tool_from_transition(recovered_tool).output
                    if output:
                        feedback = _text_feedback(output)
        return self._context_builder.build(
            ContextInput(task=snapshot.task.request, memory=memory, feedback=feedback)
        )

    def _compose(self, findings: Sequence[Finding]) -> FeedbackPacket:
        return self._feedback_composer.compose(
            findings, total_bytes=32 * 1_024, per_item_bytes=4 * 1_024
        )

    def _begin_transition(
        self, task_id: str, kind: str, evidence_digest: str, summary: str
    ) -> TransitionIntentRecord:
        intent = self._repository.record_transition_intent(
            task_id,
            kind=kind,
            evidence_digest=evidence_digest,
            summary=summary,
            owner_token=self._owner(),
        )
        self._audit(f"{kind}_started", task_id, {"intent_id": intent.id, "digest": evidence_digest})
        return intent

    def _recover_transition(
        self, task_id: str, kind: str, evidence_digest: str
    ) -> TransitionIntentRecord | None:
        snapshot = self._repository.resume_snapshot(task_id)
        return next(
            (
                intent
                for intent in snapshot.transition_intents
                if intent.kind == kind
                and intent.evidence_digest == evidence_digest
                and intent.state == "completed"
                and intent.consumed_at is None
            ),
            None,
        )

    def _remember_intent(self, intent_id: str) -> None:
        current = self._cycle_intents.get()
        if intent_id not in current:
            self._cycle_intents.set((*current, intent_id))

    def _complete_transition(
        self,
        intent: TransitionIntentRecord,
        result_digest: str,
        summary: str,
        event_type: str,
        *,
        payload: dict[str, object] | None = None,
    ) -> None:
        self._repository.complete_transition_intent(
            intent.id,
            result_digest=result_digest,
            summary=summary,
            result_payload=payload,
            owner_token=self._owner(),
        )
        self._audit(event_type, intent.task_id, {"intent_id": intent.id, "digest": result_digest})

    def _audit(self, event_type: str, task_id: str, metadata: dict[str, str]) -> None:
        self._audit_sink.emit(
            AuditEvent(
                event_type=event_type,
                task_id=task_id,
                component="agent_loop",
                created_at=self._clock.now(),
                metadata=metadata,
            )
        )

    def _audit_after_commit(
        self, event_type: str, task_id: str, metadata: dict[str, str]
    ) -> None:
        try:
            self._audit(event_type, task_id, metadata)
        except Exception as audit_error:  # noqa: BLE001
            _ = audit_error

    def _terminal(self, task_id: str, status: TaskStatus, summary: str) -> TaskResult:
        result = self._make_result(task_id, status, summary)
        if not self._repository.set_status(
            task_id,
            TaskStatus.RUNNING,
            status,
            result,
            owner_token=self._owner(),
        ):
            snapshot = self._repository.resume_snapshot(task_id)
            if snapshot.task.status in _TERMINAL:
                return self._saved_result(snapshot)
            raise StorageStateError("terminal compare-and-set failed")
        try:
            self._audit("task_terminal", task_id, {"status": status.value})
        except Exception as audit_error:  # noqa: BLE001
            _ = audit_error
        return result

    def _make_result(self, task_id: str, status: TaskStatus, summary: str) -> TaskResult:
        snapshot = self._repository.resume_snapshot(task_id)
        return TaskResult(
            task_id=task_id,
            status=status,
            iterations=len(snapshot.iterations),
            verification_summary=summary,
            changed_paths=tuple(sorted(self._changed(task_id))),
        )

    def _waiting_result(self, snapshot: RecoverySnapshot) -> TaskResult:
        return snapshot.task.result or TaskResult(
            task_id=snapshot.task.id,
            status=TaskStatus.WAITING_APPROVAL,
            iterations=len(snapshot.iterations),
            verification_summary="Action requires explicit approval.",
        )

    @staticmethod
    def _saved_result(snapshot: RecoverySnapshot) -> TaskResult:
        if snapshot.task.result is None:
            raise StorageStateError("terminal task has no saved result")
        return snapshot.task.result

    def _changed(self, task_id: str) -> set[str]:
        if task_id not in self._changed_paths:
            recovered: set[str] = set()
            snapshot = self._repository.resume_snapshot(task_id)
            for intent in snapshot.transition_intents:
                if intent.kind != "dispatch" or intent.result_payload is None:
                    continue
                try:
                    recovered.update(_tool_from_transition(intent).changed_paths)
                except (StorageStateError, ValueError):
                    continue
            self._changed_paths[task_id] = recovered
        return self._changed_paths[task_id]

    def _owner(self) -> str:
        owner_token = self._owner_context.get()
        if owner_token is None:
            raise StorageStateError("agent loop has no active lease owner")
        return owner_token

    def _deadline_reached(self, snapshot: RecoverySnapshot) -> bool:
        return snapshot.task.deadline is not None and self._clock.now() >= snapshot.task.deadline

    def _blocked_if_possible(self, task_id: str, error: Exception) -> TaskResult:
        try:
            snapshot = self._repository.resume_snapshot(task_id)
            if snapshot.task.status in _TERMINAL:
                return self._saved_result(snapshot)
            if snapshot.task.status is TaskStatus.WAITING_APPROVAL:
                return self._waiting_result(snapshot)
            return self._terminal(task_id, TaskStatus.BLOCKED, f"Execution blocked: {type(error).__name__}.")
        except (OSError, PermissionError, StorageStateError):
            raise error

    def _failed_if_possible(
        self, task_id: str, error: Exception, *, acquired: bool
    ) -> TaskResult:
        if not acquired:
            return self._repository.fail_inconsistent_task(
                task_id,
                f"Internal consistency failure: {type(error).__name__}.",
            )
        try:
            snapshot = self._repository.resume_snapshot(task_id)
            if snapshot.task.status in _TERMINAL:
                return self._saved_result(snapshot)
            if snapshot.task.status is TaskStatus.WAITING_APPROVAL:
                return self._waiting_result(snapshot)
            return self._terminal(
                task_id,
                TaskStatus.FAILED,
                f"Internal consistency failure: {type(error).__name__}.",
            )
        except Exception as recovery_error:
            raise error from recovery_error


class _DeadlineReached(RuntimeError):
    pass


class _BlockedTransition(RuntimeError):
    pass


def _canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _digest_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _digest_model(value: object) -> str:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    return _digest_text(_canonical(value))


def _digest_messages(messages: tuple[Message, ...]) -> str:
    return _digest_text(_canonical([message.model_dump(mode="json") for message in messages]))


def _harness_finding(summary: str, evidence: str, group_key: str) -> Finding:
    return Finding(
        source="harness",
        category="infrastructure",
        severity="error",
        summary=summary,
        evidence=evidence,
        group_key=group_key,
    )


def _text_feedback(text: str) -> FeedbackPacket:
    bounded = text.encode("utf-8")[: 32 * 1_024].decode("utf-8", errors="ignore") or "~"
    return FeedbackPacket(
        findings=(), omitted_count=0, truncated=bounded != text, byte_budget=32 * 1_024, text=bounded
    )


def _relevant_digest(
    tool_result: ToolResult | None, report: QualityReport, previous: str | None
) -> str | None:
    if tool_result is None:
        return previous
    relevant = {
        path: tool_result.after_digests.get(path)
        for path in tool_result.changed_paths
        if path in report.changed_paths
    }
    return _digest_text(_canonical(relevant)) if relevant else previous


def _quality_outcome(report: QualityReport | None) -> str | None:
    if report is None:
        return None
    if report.succeeded:
        return "passed"
    if any(
        finding.category in {"missing_tool_dependency", "infrastructure"}
        for finding in report.findings
    ):
        return "blocked"
    return "failed"


def _recovered_report(outcome: str | None) -> QualityReport | None:
    if outcome is None or outcome == "not_run":
        return None
    status = CheckStatus.PASSED if outcome == "passed" else CheckStatus.FAILED
    return QualityReport(
        targeted_pytest_status=CheckStatus.NOT_RUN,
        full_pytest_status=status,
        ruff_status=status,
    )


def _recovered_tool_result(
    action: Action, expected_after_digests: dict[str, str | None]
) -> ToolResult:
    return ToolResult(
        effect_kind=action.kind,
        code_changed=action.kind == "apply_patch" and bool(expected_after_digests),
        changed_paths=tuple(sorted(expected_after_digests)),
        after_digests={
            path: digest
            for path, digest in expected_after_digests.items()
            if digest is not None
        },
        normalized_metadata={"code": "ok", "recovered": True},
    )


def _action_from_transition_payload(payload: dict[str, object]) -> Action | None:
    outcome = payload.get("outcome")
    if outcome == "invalid":
        return None
    if outcome != "action" or "action" not in payload:
        raise StorageStateError("persisted model transition payload is invalid")
    return Action.model_validate(payload["action"])


def _tool_from_transition(intent: TransitionIntentRecord) -> ToolResult:
    payload = intent.result_payload or {}
    if "tool_result" not in payload:
        raise StorageStateError("persisted dispatch transition payload is invalid")
    return ToolResult.model_validate(payload["tool_result"])


def _quality_from_transition(intent: TransitionIntentRecord) -> QualityReport:
    payload = intent.result_payload or {}
    if "quality_report" not in payload:
        raise StorageStateError("persisted verifier transition payload is invalid")
    return QualityReport.model_validate(payload["quality_report"])


def _policy_from_transition(intent: TransitionIntentRecord) -> PolicyDecision:
    payload = intent.result_payload or {}
    if "policy_decision" not in payload:
        raise StorageStateError("persisted policy transition payload is invalid")
    return PolicyDecision.model_validate(payload["policy_decision"])


def _trailing_invalid_rounds(snapshot: RecoverySnapshot) -> int:
    count = 0
    for iteration in reversed(snapshot.iterations):
        if iteration.action_json is not None:
            break
        count += 1
    return count


def _summary(status: TaskStatus) -> str:
    return {
        TaskStatus.SUCCEEDED: "Full verification passed.",
        TaskStatus.STALLED: "Repeated failure without relevant repository progress.",
        TaskStatus.BUDGET_EXHAUSTED: "Model round or wall-clock budget exhausted.",
        TaskStatus.BLOCKED: "Execution is blocked by the environment or policy.",
        TaskStatus.FAILED: "Agent loop failed due to inconsistent state.",
    }[status]
