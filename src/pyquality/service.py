"""Application service boundary for local harness clients."""

from __future__ import annotations

import json
import shutil
from collections.abc import Callable
from collections.abc import Set as AbstractSet
from concurrent.futures import Future, InvalidStateError, ThreadPoolExecutor
from pathlib import Path
from threading import BoundedSemaphore, Lock
from typing import Protocol
from uuid import uuid4

from pydantic import ConfigDict, Field

from .config import Settings, load_settings
from .domain.models import ApprovalDecision, AuditEvent, PublicModel, TaskResult, TaskStatus
from .security import CredentialError, CredentialStatus, redact, sanitize_audit_metadata
from .storage.sqlite import (
    ProjectReservationError,
    SQLiteTaskRepository,
    StorageStateError,
    TaskCreationConflictError,
    TaskRecord,
)


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
    resume_available: bool = False


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
        audit_secrets: AbstractSet[str] | None = None,
        allowed_root: Path | None = None,
    ) -> None:
        self._repository = repository
        self._loop = loop
        self._settings = settings
        self._credentials = credentials
        self._provider = provider
        self._verifier_finder = verifier_finder
        self._audit_path = audit_path
        self._audit_secrets = (
            audit_secrets if audit_secrets is not None else frozenset()
        )
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
        task_id = uuid4().hex
        creation_nonce = uuid4().hex
        if not self._capacity.acquire(blocking=False):
            raise PreflightError("global execution capacity is exhausted")
        record: TaskRecord | None = None
        placeholder: Future[TaskResult] = Future()
        reservation_conflict = False
        creation_conflict = False
        try:
            self._reconcile_stale_repository_mapping(canonical)
            with self._lock:
                if canonical in self._active_repositories:
                    raise ProjectBusyError(
                        "repository is busy: it already has active work"
                    )
                record = self._repository.create_task_with_project_reservation(
                    canonical,
                    request,
                    self._settings.round_limit,
                    task_id=task_id,
                    creation_nonce=creation_nonce,
                )
                self._active_repositories[canonical] = record.id
                self._task_repositories[record.id] = canonical
                self._futures[record.id] = placeholder
        except ProjectReservationError:
            self._compensate_setup_failure(
                None,
                None,
                None,
                rollback_new_task=False,
            )
            reservation_conflict = True
        except TaskCreationConflictError:
            self._compensate_setup_failure(
                None,
                None,
                None,
                rollback_new_task=False,
            )
            creation_conflict = True
        except Exception:
            self._compensate_setup_failure(
                task_id,
                None,
                placeholder,
                rollback_new_task=True,
                creation_nonce=creation_nonce,
            )
            raise
        if reservation_conflict:
            raise ProjectBusyError(
                "repository is busy: it already has active work"
            )
        if creation_conflict:
            raise PreflightError("task creation is unavailable")
        assert record is not None
        self._prepare_submission(
            record.id,
            placeholder,
            resume=False,
            rollback_new_task=True,
            creation_nonce=creation_nonce,
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
            return completed
        if not self._capacity.acquire(blocking=False):
            raise PreflightError("global execution capacity is exhausted")
        placeholder: Future[TaskResult] = Future()
        with self._lock:
            existing = self._futures.get(task_id)
            if existing is not None:
                self._capacity.release()
                return existing
            self._futures[task_id] = placeholder
        state_changed = False
        try:
            canonical = self._repository.task_project_path(task_id)
            with self._lock:
                if self._futures.get(task_id) is not placeholder:
                    raise PreflightError("task state changed before submission")
                self._task_repositories[task_id] = canonical
                self._active_repositories[canonical] = task_id
                owner_token = self._pending_owners.get(task_id)
        except StorageStateError:
            self._compensate_setup_failure(
                task_id,
                None,
                placeholder,
                rollback_new_task=False,
            )
            state_changed = True
        except Exception:
            self._compensate_setup_failure(
                task_id,
                None,
                placeholder,
                rollback_new_task=False,
            )
            raise
        if state_changed:
            raise PreflightError("task state changed before submission")
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

    def resume_task(self, task_id: str) -> Future[TaskResult]:
        """Attempt recovery for durable RUNNING work through the lease protocol."""
        snapshot = self._snapshot(task_id)
        if snapshot.task.status is not TaskStatus.RUNNING:
            raise PreflightError("task is not awaiting dispatch recovery")
        with self._lock:
            if task_id in self._futures:
                raise PreflightError("task is not awaiting dispatch recovery")
        return self.start_task(task_id, resume=True)

    def cancel_task(self, task_id: str) -> None:
        storage_failed = False
        try:
            cancelled = self._repository.cancel_created_task(task_id)
        except StorageStateError:
            storage_failed = True
            cancelled = False
        if storage_failed:
            raise PreflightError("task cancellation is unavailable")
        if not cancelled:
            raise PreflightError("running task cannot be cancelled")
        with self._lock:
            self._futures.pop(task_id, None)
            self._pending_owners.pop(task_id, None)
            canonical = self._task_repositories.pop(task_id, None)
            if canonical is not None and self._active_repositories.get(canonical) == task_id:
                self._active_repositories.pop(canonical, None)

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

    def _reconcile_stale_repository_mapping(self, canonical: str) -> None:
        with self._lock:
            mapped_task = self._active_repositories.get(canonical)
        if mapped_task is None:
            return
        try:
            durable_status = self._repository.resume_snapshot(mapped_task).task.status
        except StorageStateError:
            stale = True
        except Exception:  # noqa: BLE001 - an unreadable mapping stays busy.
            return
        else:
            stale = durable_status in _TERMINAL
        if not stale:
            return
        with self._lock:
            if self._active_repositories.get(canonical) != mapped_task:
                return
            self._active_repositories.pop(canonical, None)
            if self._task_repositories.get(mapped_task) == canonical:
                self._task_repositories.pop(mapped_task, None)

    def _snapshot(self, task_id: str):
        try:
            snapshot = self._repository.resume_snapshot(task_id)
        except StorageStateError:
            pass
        else:
            return snapshot
        raise PreflightError("task does not exist")

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
        creation_nonce: str | None = None,
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
            self._compensate_setup_failure(
                task_id,
                owner_token,
                placeholder,
                rollback_new_task=rollback_new_task,
                creation_nonce=creation_nonce,
            )
            raise
        with self._lock:
            self._pending_owners[task_id] = owner_token
        self._dispatch_preleased(
            task_id,
            owner_token,
            placeholder,
            resume=resume,
            rollback_new_task=rollback_new_task,
            creation_nonce=creation_nonce,
        )

    def _dispatch_preleased(
        self,
        task_id: str,
        owner_token: str,
        placeholder: Future[TaskResult],
        *,
        resume: bool,
        rollback_new_task: bool,
        creation_nonce: str | None = None,
    ) -> None:
        try:
            worker = self._executor.submit(
                self._loop.run_leased,
                task_id,
                owner_token,
                resume=resume,
            )
        except Exception:
            self._compensate_setup_failure(
                task_id,
                owner_token,
                placeholder,
                rollback_new_task=rollback_new_task,
                creation_nonce=creation_nonce,
            )
            raise
        worker.add_done_callback(
            lambda completed: self._complete_submission(
                task_id, owner_token, placeholder, completed
            )
        )

    def _compensate_setup_failure(
        self,
        task_id: str | None,
        owner_token: str | None,
        placeholder: Future[TaskResult] | None,
        *,
        rollback_new_task: bool,
        creation_nonce: str | None = None,
    ) -> None:
        """Best-effort one setup rollback while preserving the caller's error."""
        try:
            self._reconcile_setup_failure(
                task_id,
                owner_token,
                placeholder,
                rollback_new_task=rollback_new_task,
                creation_nonce=creation_nonce,
            )
        except BaseException as cleanup_error:  # noqa: BLE001 - keep primary.
            _ = cleanup_error
        finally:
            try:
                self._capacity.release()
            except BaseException as cleanup_error:  # noqa: BLE001 - keep primary.
                _ = cleanup_error

    def _reconcile_setup_failure(
        self,
        task_id: str | None,
        owner_token: str | None,
        placeholder: Future[TaskResult] | None,
        *,
        rollback_new_task: bool,
        creation_nonce: str | None = None,
    ) -> None:
        deleted = False
        durable_status: TaskStatus | None = None
        durable_known = False
        if rollback_new_task and task_id is not None and owner_token is not None:
            try:
                deleted = self._repository.rollback_running_task(
                    task_id, owner_token=owner_token
                )
            except BaseException as cleanup_error:  # noqa: BLE001 - keep primary.
                _ = cleanup_error
        if (
            rollback_new_task
            and task_id is not None
            and creation_nonce is not None
            and not deleted
        ):
            try:
                deleted = self._repository.rollback_created_task(
                    task_id, creation_nonce=creation_nonce
                )
            except BaseException as cleanup_error:  # noqa: BLE001 - keep primary.
                _ = cleanup_error
        if (
            rollback_new_task
            and task_id is not None
            and owner_token is not None
        ):
            try:
                self._repository.release_project_lease(
                    task_id, owner_token=owner_token
                )
            except BaseException as cleanup_error:  # noqa: BLE001 - keep primary.
                _ = cleanup_error
        if task_id is not None and not deleted:
            exists: bool | None = None
            try:
                exists = self._repository.task_exists(task_id)
            except BaseException as inspection_error:  # noqa: BLE001 - fail closed.
                _ = inspection_error
            if exists is False:
                deleted = True
                durable_known = True
            else:
                try:
                    durable_status = self._repository.resume_snapshot(
                        task_id
                    ).task.status
                    durable_known = True
                except StorageStateError:
                    deleted = True
                    durable_known = True
                except BaseException as inspection_error:  # noqa: BLE001 - fail closed.
                    _ = inspection_error
        elif deleted:
            durable_known = True
        try:
            if task_id is not None and placeholder is not None:
                with self._lock:
                    if self._futures.get(task_id) is placeholder:
                        self._futures.pop(task_id, None)
        except BaseException as cleanup_error:  # noqa: BLE001 - keep reconciling.
            _ = cleanup_error
        terminal_or_deleted = deleted or (
            durable_known and durable_status in _TERMINAL
        )
        if task_id is not None and terminal_or_deleted:
            try:
                with self._lock:
                    self._pending_owners.pop(task_id, None)
            except BaseException as cleanup_error:  # noqa: BLE001 - keep reconciling.
                _ = cleanup_error
            canonical: str | None = None
            try:
                with self._lock:
                    canonical = self._task_repositories.pop(task_id, None)
            except BaseException as cleanup_error:  # noqa: BLE001 - keep reconciling.
                _ = cleanup_error
            if canonical is not None:
                try:
                    with self._lock:
                        if self._active_repositories.get(canonical) == task_id:
                            self._active_repositories.pop(canonical, None)
                except BaseException as cleanup_error:  # noqa: BLE001 - use identity sweep.
                    _ = cleanup_error
            try:
                with self._lock:
                    for active_path, active_task in tuple(
                        self._active_repositories.items()
                    ):
                        if active_task == task_id:
                            self._active_repositories.pop(active_path, None)
            except BaseException as cleanup_error:  # noqa: BLE001 - keep primary.
                _ = cleanup_error
        elif task_id is not None and durable_known:
            if durable_status is TaskStatus.RUNNING and owner_token is not None:
                owns_lease: bool | None = None
                try:
                    owns_lease = self._repository.owns_project_lease(
                        task_id, owner_token=owner_token
                    )
                except BaseException as cleanup_error:  # noqa: BLE001 - retain fail-closed.
                    _ = cleanup_error
                try:
                    with self._lock:
                        if owns_lease is False:
                            if self._pending_owners.get(task_id) == owner_token:
                                self._pending_owners.pop(task_id, None)
                        else:
                            self._pending_owners[task_id] = owner_token
                except BaseException as cleanup_error:  # noqa: BLE001 - keep primary.
                    _ = cleanup_error
            else:
                try:
                    with self._lock:
                        self._pending_owners.pop(task_id, None)
                except BaseException as cleanup_error:  # noqa: BLE001 - keep primary.
                    _ = cleanup_error
            if durable_status in {
                TaskStatus.CREATED,
                TaskStatus.RUNNING,
                TaskStatus.WAITING_APPROVAL,
            }:
                canonical = None
                try:
                    canonical = self._repository.task_project_path(task_id)
                except BaseException as cleanup_error:  # noqa: BLE001 - keep recoverable maps.
                    _ = cleanup_error
                if canonical is not None:
                    try:
                        with self._lock:
                            active_task = self._active_repositories.get(canonical)
                            if active_task in {None, task_id}:
                                self._task_repositories[task_id] = canonical
                                self._active_repositories[canonical] = task_id
                    except BaseException as cleanup_error:  # noqa: BLE001 - keep primary.
                        _ = cleanup_error
        elif task_id is not None and owner_token is not None:
            try:
                with self._lock:
                    self._pending_owners[task_id] = owner_token
            except BaseException as cleanup_error:  # noqa: BLE001 - fail closed.
                _ = cleanup_error

    def _complete_submission(
        self,
        task_id: str,
        owner_token: str,
        placeholder: Future[TaskResult],
        worker: Future[TaskResult],
    ) -> None:
        result: TaskResult | None = None
        error: BaseException | None = None
        try:
            result = worker.result()
        except BaseException as caught:  # noqa: BLE001 - preserve injected loop failure.
            error = caught
        cleanup_error: BaseException | None = None
        try:
            if self._repository.owns_project_lease(task_id, owner_token=owner_token):
                self._repository.release_project_lease(task_id, owner_token=owner_token)
        except BaseException as caught:  # noqa: BLE001 - publish cleanup failure.
            cleanup_error = caught
        durable_status: TaskStatus | None = None
        try:
            durable_status = self._repository.resume_snapshot(task_id).task.status
        except BaseException as caught:  # noqa: BLE001 - retain ownership fail-closed.
            cleanup_error = cleanup_error or caught
        try:
            with self._lock:
                if durable_status is not TaskStatus.RUNNING:
                    self._pending_owners.pop(task_id, None)
                if durable_status in _TERMINAL:
                    canonical = self._task_repositories.pop(task_id, None)
                    if (
                        canonical is not None
                        and self._active_repositories.get(canonical) == task_id
                    ):
                        self._active_repositories.pop(canonical, None)
        except BaseException as caught:  # noqa: BLE001 - continue mandatory cleanup.
            cleanup_error = cleanup_error or caught
        try:
            self._capacity.release()
        except BaseException as caught:  # noqa: BLE001 - publish cleanup failure.
            cleanup_error = cleanup_error or caught
        published_error = error or cleanup_error
        try:
            if published_error is None:
                assert result is not None
                placeholder.set_result(result)
            else:
                placeholder.set_exception(published_error)
        except InvalidStateError:
            pass
        finally:
            with self._lock:
                if self._futures.get(task_id) is placeholder:
                    self._futures.pop(task_id)

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
        with self._lock:
            resume_available = (
                task.status is TaskStatus.RUNNING
                and task.id not in self._futures
            )
        return TaskView(
            id=task.id,
            status=task.status,
            round_limit=task.round_limit,
            remaining_rounds=max(0, task.round_limit - len(iterations)),
            verification_summary=result.verification_summary if result else None,
            changed_paths=result.changed_paths if result else (),
            pending_approval_id=pending.id if pending else None,
            resume_available=resume_available,
        )

    def _decode_audit(self, line: str) -> AuditEvent:
        audit_secrets = set(self._audit_secrets)
        payload = redact(
            json.loads(line),
            audit_secrets,
            set(self._settings.redaction_patterns),
        )
        if not isinstance(payload, dict) or set(payload) != {
            "event_id", "task_id", "iteration", "component", "event_type", "duration",
            "outcome", "metadata"
        }:
            raise ValueError("invalid audit record")
        metadata = payload["metadata"]
        if not isinstance(metadata, dict):
            raise TypeError("invalid audit metadata")
        candidates = dict(metadata)
        candidates["outcome"] = payload["outcome"]
        candidates["duration"] = payload["duration"]
        safe_metadata, duration, outcome = sanitize_audit_metadata(
            candidates, audit_secrets
        )
        if outcome is not None:
            safe_metadata["outcome"] = outcome
        if duration is not None:
            safe_metadata["duration"] = duration
        return AuditEvent(
            event_id=payload["event_id"],
            task_id=payload["task_id"],
            iteration_id=payload["iteration"],
            component=payload["component"],
            event_type=payload["event_type"],
            metadata=safe_metadata,
        )
