"""Application service boundary for local harness clients."""

from __future__ import annotations

import json
import shutil
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from threading import BoundedSemaphore, Lock
from typing import Protocol
from uuid import uuid4

from pydantic import ConfigDict, Field

from .config import Settings, load_settings
from .domain.models import ApprovalDecision, AuditEvent, PublicModel, TaskResult, TaskStatus
from .security import CredentialError, CredentialStatus, redact, sanitize_audit_metadata
from .storage.sqlite import SQLiteTaskRepository, StorageStateError, TaskRecord


class ProjectBusyError(RuntimeError):
    """Raised when one repository already has non-terminal work."""


class PreflightError(RuntimeError):
    """Raised when work cannot safely be accepted."""


class _Loop(Protocol):
    def run(self, task_id: str) -> TaskResult: ...

    def resume(self, task_id: str) -> TaskResult: ...

    def run_leased(
        self, task_id: str, owner_token: str, *, resume: bool
    ) -> TaskResult: ...

    def decide_approval(self, approval_id: str, decision: ApprovalDecision) -> str: ...

    def decide_approval_leased(
        self,
        approval_id: str,
        decision: ApprovalDecision,
        *,
        owner_token: str,
    ) -> str: ...


class _Credentials(Protocol):
    def status(self, account: str) -> CredentialStatus: ...


class TaskView(PublicModel):
    """Credential-free, source-free task state safe for UI serialization."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    status: TaskStatus
    round_limit: int = Field(ge=1)
    remaining_rounds: int = Field(ge=0)
    verification_summary: str | None = None
    changed_paths: tuple[str, ...] = ()
    pending_approval_id: str | None = None


_TERMINAL = frozenset(
    {
        TaskStatus.SUCCEEDED,
        TaskStatus.STALLED,
        TaskStatus.BUDGET_EXHAUSTED,
        TaskStatus.BLOCKED,
        TaskStatus.FAILED,
    }
)


class HarnessService:
    """Owns process-bounded submission and exposes sanitized harness operations."""

    def __init__(
        self,
        *,
        repository: SQLiteTaskRepository,
        loop: _Loop,
        settings: Settings,
        credentials: _Credentials | None = None,
        provider: str = "mock",
        verifier_finder: Callable[[str], str | None] = shutil.which,
        audit_path: Path | None = None,
        audit_secrets: set[str] | None = None,
        allowed_root: Path | None = None,
    ) -> None:
        self._repository = repository
        self._loop = loop
        self._settings = settings
        self._credentials = credentials
        self._provider = provider
        self._verifier_finder = verifier_finder
        self._audit_path = audit_path
        self._audit_secrets = set(audit_secrets or ())
        self._allowed_root = allowed_root
        self._executor = ThreadPoolExecutor(
            max_workers=settings.global_concurrency,
            thread_name_prefix="pyquality",
        )
        self._lock = Lock()
        self._capacity = BoundedSemaphore(settings.global_concurrency)
        self._active_repositories: dict[str, str] = {}
        self._task_repositories: dict[str, str] = {}
        self._futures: dict[str, Future[TaskResult]] = {}
        self._pending_owners: dict[str, str] = {}

    @property
    def settings(self) -> Settings:
        return self._settings

    def create_task(self, repo_path: Path | str, request: str) -> TaskView:
        root = self._preflight(Path(repo_path), request)
        canonical = str(root)
        if not self._capacity.acquire(blocking=False):
            raise PreflightError("global execution capacity is exhausted")
        record: TaskRecord | None = None
        placeholder: Future[TaskResult] = Future()
        with self._lock:
            if canonical in self._active_repositories:
                self._capacity.release()
                raise ProjectBusyError("repository already has active work")
            try:
                record = self._repository.create_task(
                    canonical, request, self._settings.round_limit
                )
            except Exception:
                self._capacity.release()
                raise
            self._active_repositories[canonical] = record.id
            self._task_repositories[record.id] = canonical
            self._futures[record.id] = placeholder
        self._prepare_submission(
            record.id,
            placeholder,
            resume=False,
            rollback_new_task=True,
        )
        return self.get_task(record.id)

    def start_task(self, task_id: str, *, resume: bool = False) -> Future[TaskResult]:
        with self._lock:
            existing = self._futures.get(task_id)
            if existing is not None:
                return existing
        snapshot = self._snapshot(task_id)
        if snapshot.task.status in _TERMINAL or snapshot.task.status is TaskStatus.WAITING_APPROVAL:
            completed: Future[TaskResult] = Future()
            if snapshot.task.result is None:
                raise PreflightError("saved task result is unavailable")
            completed.set_result(snapshot.task.result)
            with self._lock:
                return self._futures.setdefault(task_id, completed)
        if not self._capacity.acquire(blocking=False):
            raise PreflightError("global execution capacity is exhausted")
        placeholder: Future[TaskResult] = Future()
        with self._lock:
            existing = self._futures.get(task_id)
            if existing is not None:
                self._capacity.release()
                return existing
            self._futures[task_id] = placeholder
            canonical = self._repository.task_project_path(task_id)
            self._task_repositories[task_id] = canonical
            self._active_repositories[canonical] = task_id
            owner_token = self._pending_owners.get(task_id)
        self._prepare_submission(
            task_id,
            placeholder,
            resume=resume or snapshot.task.status is TaskStatus.RUNNING,
            rollback_new_task=False,
            owner_token=owner_token,
        )
        return placeholder

    def get_task(self, task_id: str) -> TaskView:
        snapshot = self._snapshot(task_id)
        return self._view(snapshot.task, snapshot=snapshot)

    def approve(self, approval_id: str) -> Future[TaskResult]:
        return self._decide_and_resume(approval_id, ApprovalDecision.APPROVE)

    def reject(self, approval_id: str) -> Future[TaskResult]:
        return self._decide_and_resume(approval_id, ApprovalDecision.REJECT)

    def cancel_task(self, task_id: str) -> None:
        with self._lock:
            future = self._futures.get(task_id)
            if future is not None:
                raise PreflightError("running task cannot be cancelled")
            canonical = self._task_repositories.pop(task_id, None)
            if canonical is not None and self._active_repositories.get(canonical) == task_id:
                self._active_repositories.pop(canonical, None)
        snapshot = self._snapshot(task_id)
        if snapshot.task.status is not TaskStatus.CREATED:
            raise PreflightError("running task cannot be cancelled")
        self._repository.discard_unstarted_task(task_id)

    def export_audit(self) -> tuple[AuditEvent, ...]:
        if self._audit_path is None:
            return ()
        try:
            lines = self._audit_path.read_text(encoding="utf-8").splitlines()
            return tuple(self._decode_audit(line) for line in lines if line.strip())
        except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError):
            raise PreflightError("audit export is unavailable") from None

    def close(self) -> None:
        self._executor.shutdown(wait=True, cancel_futures=False)

    def _preflight(self, repo_path: Path, request: str) -> Path:
        if not isinstance(request, str) or not request.strip():
            raise PreflightError("request must be non-empty text")
        try:
            root = repo_path.resolve(strict=True)
        except OSError:
            raise PreflightError("repository is unavailable") from None
        if not root.is_dir():
            raise PreflightError("repository must be a directory")
        if self._allowed_root is not None and root != self._allowed_root:
            raise PreflightError("repository is outside this service scope")
        try:
            load_settings(root, None)
        except (OSError, ValueError):
            raise PreflightError("repository configuration is invalid") from None
        missing = [name for name in ("pytest", "ruff") if self._verifier_finder(name) is None]
        if missing:
            raise PreflightError(f"required verifier is unavailable: {missing[0]}")
        if self._provider != "mock":
            if self._credentials is None:
                raise PreflightError("provider credential service is unavailable")
            try:
                status = self._credentials.status("provider")
            except CredentialError:
                raise PreflightError("provider credential status is unavailable") from None
            if not status.present:
                raise PreflightError("provider credential is not configured")
        return root

    def _snapshot(self, task_id: str):
        try:
            return self._repository.resume_snapshot(task_id)
        except StorageStateError:
            raise PreflightError("task does not exist") from None

    def _require_known_task(self, task_id: str) -> None:
        self._snapshot(task_id)

    def _decide_and_resume(
        self, approval_id: str, decision: ApprovalDecision
    ) -> Future[TaskResult]:
        if not self._capacity.acquire(blocking=False):
            raise PreflightError("global execution capacity is exhausted")
        owner_token = uuid4().hex
        try:
            task_id = self._loop.decide_approval_leased(
                approval_id, decision, owner_token=owner_token
            )
        except Exception:
            self._capacity.release()
            raise
        placeholder: Future[TaskResult] = Future()
        with self._lock:
            self._futures[task_id] = placeholder
            self._pending_owners[task_id] = owner_token
        self._dispatch_preleased(
            task_id,
            owner_token,
            placeholder,
            resume=True,
            rollback_new_task=False,
        )
        return placeholder

    def _prepare_submission(
        self,
        task_id: str,
        placeholder: Future[TaskResult],
        *,
        resume: bool,
        rollback_new_task: bool,
        owner_token: str | None = None,
    ) -> None:
        owner_token = owner_token or uuid4().hex
        lease_acquired = False
        try:
            snapshot = self._snapshot(task_id)
            if snapshot.task.status is TaskStatus.CREATED:
                if not self._repository.set_status(
                    task_id, TaskStatus.CREATED, TaskStatus.RUNNING
                ):
                    raise PreflightError("task state changed before submission")
            elif snapshot.task.status is not TaskStatus.RUNNING:
                raise PreflightError("task is not ready for execution")
            lease_acquired = self._repository.owns_project_lease(
                task_id, owner_token=owner_token
            ) or self._repository.acquire_project_lease(
                task_id, owner_token=owner_token
            )
            if not lease_acquired:
                raise ProjectBusyError("repository is busy")
        except Exception:
            if lease_acquired:
                self._repository.release_project_lease(
                    task_id, owner_token=owner_token
                )
            if rollback_new_task:
                self._repository.discard_unstarted_task(task_id)
            self._remove_submission(task_id)
            self._capacity.release()
            raise
        with self._lock:
            self._pending_owners[task_id] = owner_token
        self._dispatch_preleased(
            task_id,
            owner_token,
            placeholder,
            resume=resume,
            rollback_new_task=rollback_new_task,
        )

    def _dispatch_preleased(
        self,
        task_id: str,
        owner_token: str,
        placeholder: Future[TaskResult],
        *,
        resume: bool,
        rollback_new_task: bool,
    ) -> None:
        try:
            worker = self._executor.submit(
                self._loop.run_leased,
                task_id,
                owner_token,
                resume=resume,
            )
        except Exception:
            if rollback_new_task:
                self._repository.release_project_lease(
                    task_id, owner_token=owner_token
                )
                self._repository.discard_unstarted_task(task_id)
                self._remove_submission(task_id)
            else:
                with self._lock:
                    self._futures.pop(task_id, None)
            self._capacity.release()
            raise
        worker.add_done_callback(
            lambda completed: self._complete_submission(
                task_id, owner_token, placeholder, completed
            )
        )

    def _complete_submission(
        self,
        task_id: str,
        owner_token: str,
        placeholder: Future[TaskResult],
        worker: Future[TaskResult],
    ) -> None:
        result: TaskResult | None = None
        try:
            result = worker.result()
            placeholder.set_result(result)
        except Exception as error:  # noqa: BLE001 - preserve injected loop failure.
            placeholder.set_exception(error)
        finally:
            if self._repository.owns_project_lease(
                task_id, owner_token=owner_token
            ):
                self._repository.release_project_lease(
                    task_id, owner_token=owner_token
                )
            with self._lock:
                self._pending_owners.pop(task_id, None)
                if result is None or result.status in _TERMINAL:
                    canonical = self._task_repositories.pop(task_id, None)
                    if canonical is not None and self._active_repositories.get(canonical) == task_id:
                        self._active_repositories.pop(canonical, None)
            self._capacity.release()

    def _remove_submission(self, task_id: str) -> None:
        with self._lock:
            self._futures.pop(task_id, None)
            self._pending_owners.pop(task_id, None)
            canonical = self._task_repositories.pop(task_id, None)
            if canonical is not None and self._active_repositories.get(canonical) == task_id:
                self._active_repositories.pop(canonical, None)

    def _view(self, task: TaskRecord, *, snapshot: object | None = None) -> TaskView:
        iterations = getattr(snapshot, "iterations", ())
        pending = getattr(snapshot, "pending_approval", None)
        result = task.result
        return TaskView(
            id=task.id,
            status=task.status,
            round_limit=task.round_limit,
            remaining_rounds=max(0, task.round_limit - len(iterations)),
            verification_summary=result.verification_summary if result else None,
            changed_paths=result.changed_paths if result else (),
            pending_approval_id=pending.id if pending else None,
        )

    def _decode_audit(self, line: str) -> AuditEvent:
        payload = redact(
            json.loads(line),
            self._audit_secrets,
            set(self._settings.redaction_patterns),
        )
        if not isinstance(payload, dict) or set(payload) != {
            "task_id", "iteration", "component", "event_type", "duration", "outcome", "metadata"
        }:
            raise ValueError("invalid audit record")
        metadata = payload["metadata"]
        if not isinstance(metadata, dict):
            raise TypeError("invalid audit metadata")
        candidates = dict(metadata)
        candidates["outcome"] = payload["outcome"]
        candidates["duration"] = payload["duration"]
        safe_metadata, duration, outcome = sanitize_audit_metadata(
            candidates, self._audit_secrets
        )
        if outcome is not None:
            safe_metadata["outcome"] = outcome
        if duration is not None:
            safe_metadata["duration"] = duration
        return AuditEvent(
            task_id=payload["task_id"],
            iteration_id=payload["iteration"],
            component=payload["component"],
            event_type=payload["event_type"],
            metadata=safe_metadata,
        )
