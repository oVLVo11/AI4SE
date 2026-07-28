from __future__ import annotations

import subprocess
import sys
from pathlib import Path

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
