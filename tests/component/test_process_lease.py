from __future__ import annotations

import errno
import os
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier, Event

import pytest

from pyquality.domain.models import TaskStatus
from pyquality.storage.sqlite import SQLiteTaskRepository


def _lease_holder(db_path: Path, task_id: str) -> subprocess.Popen[str]:
    script = (
        "import time\n"
        "from pathlib import Path\n"
        "from pyquality.storage.sqlite import SQLiteTaskRepository\n"
        f"repo = SQLiteTaskRepository(Path({str(db_path)!r}))\n"
        f"ok = repo.acquire_project_lease({task_id!r}, owner_token='child-owner')\n"
        "print('ACQUIRED' if ok else 'FAILED', flush=True)\n"
        "time.sleep(300)\n"
    )
    return subprocess.Popen(
        [sys.executable, "-c", script],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def test_live_child_excludes_parent_and_process_death_allows_safe_takeover(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "state.sqlite"
    setup = SQLiteTaskRepository(db_path)
    task = setup.create_task("C:/work/demo", "fix sum", round_limit=8)
    assert setup.set_status(task.id, TaskStatus.CREATED, TaskStatus.RUNNING) is True
    setup.close()
    child = _lease_holder(db_path, task.id)
    try:
        assert child.stdout is not None
        assert child.stdout.readline().strip() == "ACQUIRED"
        contender = SQLiteTaskRepository(db_path)
        assert contender.acquire_project_lease(
            task.id, owner_token="parent-owner"
        ) is False
        contender.close()

        child.terminate()
        child.wait(timeout=5)

        reopened = SQLiteTaskRepository(db_path)
        assert reopened.acquire_project_lease(
            task.id, owner_token="parent-owner"
        ) is True
        reopened.release_project_lease(
            task.id, owner_token="parent-owner"
        )
        reopened.close()
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)


def test_lock_files_are_hashed_and_adjacent_to_database_not_repository(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "app-data" / "state.sqlite"
    db_path.parent.mkdir()
    repository_root = tmp_path / "target-repository"
    repository_root.mkdir()
    repo = SQLiteTaskRepository(db_path)
    task = repo.create_task(str(repository_root.resolve()), "fix sum", round_limit=8)
    assert repo.set_status(task.id, TaskStatus.CREATED, TaskStatus.RUNNING) is True

    assert repo.acquire_project_lease(task.id, owner_token="owner") is True

    lock_files = tuple((db_path.parent / ".state.sqlite.lease-locks").glob("*.lock"))
    assert len(lock_files) == 1
    assert len(lock_files[0].stem) == 64
    assert repository_root not in lock_files[0].parents
    repo.release_project_lease(task.id, owner_token="owner")
    repo.close()


def test_repository_close_releases_kernel_lock_for_safe_takeover(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "state.sqlite"
    first = SQLiteTaskRepository(db_path)
    task = first.create_task("C:/work/demo", "fix sum", round_limit=8)
    assert first.set_status(task.id, TaskStatus.CREATED, TaskStatus.RUNNING) is True
    assert first.acquire_project_lease(task.id, owner_token="first-owner") is True

    second = SQLiteTaskRepository(db_path)
    assert second.acquire_project_lease(task.id, owner_token="second-owner") is False

    first.close()
    assert second.acquire_project_lease(task.id, owner_token="second-owner") is True
    second.release_project_lease(task.id, owner_token="second-owner")
    second.close()


def test_relative_absolute_and_dot_database_paths_share_one_live_lock(
    tmp_path: Path, monkeypatch,
) -> None:
    nested = tmp_path / "nested"
    nested.mkdir()
    monkeypatch.chdir(tmp_path)
    lexical_path = Path("nested") / ".." / "state.sqlite"
    first = SQLiteTaskRepository(lexical_path)
    task = first.create_task("C:/work/demo", "fix sum", round_limit=8)
    assert first.set_status(task.id, TaskStatus.CREATED, TaskStatus.RUNNING) is True
    assert first.acquire_project_lease(task.id, owner_token="first-owner") is True

    absolute = SQLiteTaskRepository((tmp_path / "state.sqlite").absolute())
    assert absolute.acquire_project_lease(
        task.id, owner_token="second-owner"
    ) is False
    case_alias = None
    if os.name == "nt":
        case_alias = SQLiteTaskRepository(
            Path(str(tmp_path / "state.sqlite").swapcase())
        )
        assert case_alias.acquire_project_lease(
            task.id, owner_token="case-owner"
        ) is False
    first.close()
    absolute.close()
    if case_alias is not None:
        case_alias.close()


@pytest.mark.skipif(os.name != "nt", reason="Windows lock identity semantics")
def test_nonexistent_mixed_case_database_aliases_share_one_lock_identity(
    tmp_path: Path, monkeypatch,
) -> None:
    """Case-sensitive lock identities would let first-open aliases bypass fencing."""
    owner_path = tmp_path / "State.SQLite"
    contender_path = tmp_path / "sTATE.sQLITE"
    real_connect = sqlite3.connect
    both_paths_resolved = Barrier(2)
    owner_constructed = Event()
    owner_acquired = Event()
    release_owner = Event()
    missing_before_connect: list[bool] = []
    task_ids: list[str] = []

    def gated_connect(database, *args, **kwargs):
        missing_before_connect.append(not Path(database).exists())
        both_paths_resolved.wait(timeout=5)
        if Path(database).name == contender_path.name:
            assert owner_constructed.wait(timeout=5)
        return real_connect(database, *args, **kwargs)

    monkeypatch.setattr(sqlite3, "connect", gated_connect)

    def own_lease() -> tuple[str, bool]:
        repository = None
        try:
            repository = SQLiteTaskRepository(owner_path)
            owner_constructed.set()
            task = repository.create_task("C:/work/demo", "fix sum", round_limit=8)
            assert repository.set_status(
                task.id, TaskStatus.CREATED, TaskStatus.RUNNING
            ) is True
            task_ids.append(task.id)
            lease_result = repository.acquire_project_lease(
                task.id, owner_token="owner"
            )
            owner_acquired.set()
            assert release_owner.wait(timeout=10)
            return str(repository._lock_root), lease_result
        finally:
            owner_constructed.set()
            owner_acquired.set()
            if repository is not None:
                repository.close()

    def contend_for_lease() -> tuple[str, bool]:
        repository = None
        try:
            repository = SQLiteTaskRepository(contender_path)
            assert owner_acquired.wait(timeout=10)
            lease_result = repository.acquire_project_lease(
                task_ids[0], owner_token="contender"
            )
            return str(repository._lock_root), lease_result
        finally:
            if repository is not None:
                repository.close()

    with ThreadPoolExecutor(max_workers=2) as executor:
        owner_future = executor.submit(own_lease)
        contender_future = executor.submit(contend_for_lease)
        try:
            contender_lock_root, contender_result = contender_future.result(timeout=15)
        finally:
            release_owner.set()
        owner_lock_root, owner_result = owner_future.result(timeout=15)

    assert missing_before_connect == [True, True]
    assert owner_lock_root == contender_lock_root
    assert owner_result is True
    assert contender_result is False


def test_database_file_alias_cannot_steal_a_live_lease(tmp_path: Path) -> None:
    db_path = tmp_path / "state.sqlite"
    first = SQLiteTaskRepository(db_path)
    task = first.create_task("C:/work/demo", "fix sum", round_limit=8)
    assert first.set_status(task.id, TaskStatus.CREATED, TaskStatus.RUNNING) is True
    assert first.acquire_project_lease(task.id, owner_token="first-owner") is True
    alias_path = tmp_path / "state-alias.sqlite"
    try:
        alias_path.symlink_to(db_path)
    except OSError as error:
        if error.errno in {errno.EPERM, errno.EACCES, errno.ENOSYS} or getattr(
            error, "winerror", None
        ) == 1314:
            pytest.skip(f"database symlink unavailable: {error.__class__.__name__}")
        raise

    alias = SQLiteTaskRepository(alias_path)
    assert alias.acquire_project_lease(task.id, owner_token="alias-owner") is False
    first.close()
    alias.close()
