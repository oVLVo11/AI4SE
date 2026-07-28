"""Cross-process advisory locks backing durable project leases."""

from __future__ import annotations

import errno
import hashlib
import os
from pathlib import Path
from typing import BinaryIO


class LocalProjectLock:
    """Own one non-blocking, process-scoped lock on a hashed project key."""

    def __init__(self, handle: BinaryIO) -> None:
        self._handle = handle

    @classmethod
    def try_acquire(
        cls, lock_root: Path, project_id: str
    ) -> LocalProjectLock | None:
        lock_root.mkdir(parents=True, exist_ok=True)
        resolved_root = lock_root.resolve()
        digest = hashlib.sha256(project_id.encode("utf-8")).hexdigest()
        lock_path = resolved_root / f"{digest}.lock"
        if lock_path.parent != resolved_root or len(lock_path.stem) != 64:
            raise ValueError("invalid local project lock path")

        open_path = _windows_extended_path(lock_path) if os.name == "nt" else lock_path
        handle = open_path.open("a+b")
        try:
            handle.seek(0, os.SEEK_END)
            if handle.tell() == 0:
                handle.write(b"\0")
                handle.flush()
            handle.seek(0)
            if not _try_lock(handle):
                handle.close()
                return None
        except Exception:
            handle.close()
            raise
        return cls(handle)

    def release(self) -> None:
        if self._handle.closed:
            return
        try:
            self._handle.seek(0)
            _unlock(self._handle)
        finally:
            self._handle.close()


def _windows_extended_path(path: Path) -> Path:
    text = str(path)
    if text.startswith("\\\\?\\"):
        return path
    if text.startswith("\\\\"):
        return Path("\\\\?\\UNC\\" + text[2:])
    return Path("\\\\?\\" + text)


if os.name == "nt":
    import msvcrt

    def _try_lock(handle: BinaryIO) -> bool:
        try:
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError as error:
            if error.errno in {errno.EACCES, errno.EAGAIN, errno.EDEADLK}:
                return False
            raise
        return True

    def _unlock(handle: BinaryIO) -> None:
        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)

else:
    import fcntl

    def _try_lock(handle: BinaryIO) -> bool:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            if error.errno in {errno.EACCES, errno.EAGAIN}:
                return False
            raise
        return True

    def _unlock(handle: BinaryIO) -> None:
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
