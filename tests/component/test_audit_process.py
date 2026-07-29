from __future__ import annotations

import json
import multiprocessing
import os
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import Field

from pyquality.domain.models import AuditEvent as _AuditEvent
from pyquality.security import AuditLogger, AuditWriteError


class AuditEvent(_AuditEvent):
    """Supply distinct valid IDs for audit-process fixtures."""

    event_id: str = Field(default_factory=lambda: uuid4().hex + uuid4().hex)


def _hold_shared_windows_handle(path: str, ready: object, release: object) -> None:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL

    handle = create_file(path, 0x80000000, 0x00000007, None, 3, 0x00000080, None)
    invalid_handle = ctypes.c_void_p(-1).value
    value = int(handle) if handle is not None else None
    if value in {None, invalid_handle}:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        ready.set()  # type: ignore[attr-defined]
        if not release.wait(15):  # type: ignore[attr-defined]
            raise RuntimeError("timed out waiting to release external audit handle")
    finally:
        assert close_handle(handle)


def _emit_capacity_contender(
    path: str,
    index_root: str,
    event_id: str,
    ready: object,
    release: object,
    results: object,
) -> None:
    from pyquality import security

    security._MAX_AUDIT_RECEIPTS = 1
    ready.set()  # type: ignore[attr-defined]
    if not release.wait(15):  # type: ignore[attr-defined]
        raise RuntimeError("timed out waiting to race audit recovery")
    outcome = "accepted"
    try:
        AuditLogger(Path(path), index_root=Path(index_root)).emit(
            AuditEvent(event_id=event_id, event_type="transition")
        )
    except security.AuditRecoveryRequired:
        outcome = "rejected"
    except AuditWriteError:
        outcome = "write-error"
    results.put(outcome)  # type: ignore[attr-defined]


@pytest.mark.skipif(os.name != "nt", reason="Windows cross-process share-mode enforcement unavailable")
def test_windows_external_handle_blocks_exclusive_existing_audit_open(tmp_path: Path) -> None:
    """Catches shared existing-file opens that bypass exclusive audit ownership."""
    path = tmp_path / "audit.jsonl"
    logger = AuditLogger(path)
    logger.emit(AuditEvent(event_type="transition", metadata={"intent_id": "seed"}))
    before = path.read_bytes()
    context = multiprocessing.get_context("spawn")
    ready = context.Event()
    release = context.Event()
    holder = context.Process(
        target=_hold_shared_windows_handle,
        args=(str(path), ready, release),
    )
    holder.start()
    try:
        assert ready.wait(10)
        with pytest.raises(AuditWriteError) as raised:
            logger.emit(
                AuditEvent(event_type="transition", metadata={"intent_id": "blocked"})
            )
        assert raised.value.__cause__ is None
        assert raised.value.__context__ is None
        assert path.read_bytes() == before
    finally:
        release.set()
        holder.join(15)
    assert holder.exitcode == 0

    logger.emit(AuditEvent(event_type="transition", metadata={"intent_id": "released"}))

    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert [record["metadata"]["intent_id"] for record in records] == ["seed", "released"]


def test_pending_recovery_and_two_process_append_share_last_capacity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Recovery and racing writers must clear one orphan then admit only one new ID."""
    from pyquality import security

    monkeypatch.setattr(security, "_MAX_AUDIT_RECEIPTS", 1)
    path = tmp_path / "audit.jsonl"
    index_base = tmp_path / "index"
    pending_id = "1" * 64
    contender_ids = ["2" * 64, "3" * 64]
    descriptor = security._open_audit(path)
    try:
        index_root = security._audit_index_root(path, descriptor, index_base)
        security._ensure_secure_audit_index_root(index_base, index_root)
    finally:
        os.close(descriptor)
    checkpoint_descriptor = security._open_audit(
        index_root / "checkpoint",
        append=False,
    )
    try:
        security._store_audit_checkpoint(
            checkpoint_descriptor,
            None,
            indexed_size=0,
            committed_receipt_count=0,
            pending_event_id=pending_id,
            pending_start_offset=0,
        )
    finally:
        os.close(checkpoint_descriptor)
    orphan_descriptor = security._open_audit(
        security._audit_receipt_path(index_root, pending_id),
        append=False,
    )
    os.close(orphan_descriptor)

    context = multiprocessing.get_context("spawn")
    ready = [context.Event(), context.Event()]
    release = context.Event()
    results = context.Queue()
    processes = [
        context.Process(
            target=_emit_capacity_contender,
            args=(
                str(path),
                str(index_base),
                event_id,
                ready[index],
                release,
                results,
            ),
        )
        for index, event_id in enumerate(contender_ids)
    ]
    try:
        for process in processes:
            process.start()
        assert all(signal.wait(15) for signal in ready)
        release.set()
        for process in processes:
            process.join(20)
            assert process.exitcode == 0
    finally:
        release.set()
        for process in processes:
            if process.is_alive():
                process.terminate()
            process.join(5)

    assert sorted(results.get(timeout=10) for _ in processes) == [
        "accepted",
        "rejected",
    ]
    receipt_paths = [
        security._audit_receipt_path(index_root, event_id)
        for event_id in [pending_id, *contender_ids]
    ]
    assert sum(receipt_path.exists() for receipt_path in receipt_paths) == 1
    records = [json.loads(line) for line in path.read_bytes().splitlines()]
    assert len(records) == 1
    assert records[0]["event_id"] in contender_ids
