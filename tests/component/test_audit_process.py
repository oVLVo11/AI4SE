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
