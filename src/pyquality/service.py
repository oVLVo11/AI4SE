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

    @property
    def settings(self) -> Settings:
        return self._settings

    def create_task(self, repo_path: Path | str, request: str) -> TaskView:
        root = self._preflight(Path(repo_path), request)
        canonical = str(root)
        with self._lock:
            if canonical in self._active_repositories:
                raise ProjectBusyError("repository already has active work")
            record = self._repository.create_task(canonical, request, self._settings.round_limit)
            self._active_repositories[canonical] = record.id
            self._task_repositories[record.id] = canonical
        return self._view(record)

    def start_task(self, task_id: str, *, resume: bool = False) -> Future[TaskResult]:
        with self._lock:
            existing = self._futures.get(task_id)
            if existing is not None and not existing.done():
                return existing
            self._require_known_task(task_id)
            if not self._capacity.acquire(blocking=False):
                self._fail_acceptance(task_id, "Global execution capacity is exhausted.")
                raise PreflightError("global execution capacity is exhausted")
        return self._submit_with_lease(task_id, resume=resume, capacity_held=True)

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
            if future is not None and not future.done():
                raise PreflightError("running task cannot be cancelled")
            canonical = self._task_repositories.pop(task_id, None)
            if canonical is not None and self._active_repositories.get(canonical) == task_id:
                self._active_repositories.pop(canonical, None)
        self._repository.fail_inconsistent_task(task_id, "Task cancelled before execution.")

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
        try:
            task_id = self._loop.decide_approval(approval_id, decision)
        except Exception:
            self._capacity.release()
            raise
        return self._submit_with_lease(task_id, resume=True, capacity_held=True)

    def _submit_with_lease(
        self, task_id: str, *, resume: bool, capacity_held: bool
    ) -> Future[TaskResult]:
        owner_token = uuid4().hex
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
            lease_acquired = self._repository.acquire_project_lease(
                task_id, owner_token=owner_token
            )
            if not lease_acquired:
                raise ProjectBusyError("repository is busy")
            future = self._executor.submit(
                self._loop.run_leased,
                task_id,
                owner_token,
                resume=resume,
            )
            with self._lock:
                self._futures[task_id] = future
            future.add_done_callback(lambda completed: self._after_run(task_id, completed))
            return future
        except Exception:
            if lease_acquired:
                self._repository.release_project_lease(
                    task_id, owner_token=owner_token
                )
            self._fail_acceptance(task_id, "Task submission failed.")
            if capacity_held:
                self._capacity.release()
            raise

    def _fail_acceptance(self, task_id: str, summary: str) -> None:
        self._repository.fail_inconsistent_task(task_id, summary)
        canonical = self._task_repositories.pop(task_id, None)
        if canonical is not None and self._active_repositories.get(canonical) == task_id:
            self._active_repositories.pop(canonical, None)

    def _after_run(self, task_id: str, future: Future[TaskResult]) -> None:
        try:
            try:
                result = future.result()
            except Exception:  # noqa: BLE001 - executor preserves injected loop failures.
                result = None
            if result is None or result.status in _TERMINAL:
                with self._lock:
                    canonical = self._task_repositories.pop(task_id, None)
                    if canonical is not None and self._active_repositories.get(canonical) == task_id:
                        self._active_repositories.pop(canonical, None)
        finally:
            self._capacity.release()

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
