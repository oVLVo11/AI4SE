"""Bounded repository effects reached only through a revalidated policy decision."""

from __future__ import annotations

import hashlib
import os
import signal
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Protocol

from pyquality.config import Settings
from pyquality.domain.models import Action, PolicyDecision, PolicyOutcome, ToolResult
from pyquality.policy import (
    PatchFile,
    PolicyEngine,
    ValidatedPatch,
    is_sensitive_relative_path,
    parse_validated_patch,
)

_DEFAULT_EXCLUDED_DIRECTORIES = frozenset(
    {".git", ".venv", "__pycache__", ".pytest_cache", ".ruff_cache"}
)
_MAX_SEARCH_MATCHES = 1_000


@dataclass(frozen=True)
class ProcessResult:
    """Bounded process outcome; ``output`` contains both stdout and stderr."""

    returncode: int | None
    stdout: str
    stderr: str
    output: str
    timed_out: bool
    truncated: bool


class ProcessRunner(Protocol):
    """Injectable subprocess boundary for quality validation."""

    def run(self, argv: list[str], cwd: Path, timeout_s: int, output_limit: int) -> ProcessResult: ...


class CommitObserver(Protocol):
    """Optional production coordination boundary around an atomic patch commit."""

    def after_capture(self, path: Path) -> None: ...

    def before_install_or_delete(self, path: Path, operation: str) -> None: ...

    def after_pins_acquired(self, parents: tuple[Path, ...]) -> None: ...

    def before_cleanup(self, path: Path, backup: Path) -> None: ...


class _NoopCommitObserver:
    def after_capture(self, path: Path) -> None:
        del path

    def before_install_or_delete(self, path: Path, operation: str) -> None:
        del path, operation

    def after_pins_acquired(self, parents: tuple[Path, ...]) -> None:
        del parents

    def before_cleanup(self, path: Path, backup: Path) -> None:
        del path, backup


@dataclass
class PinnedDirectory:
    """A retained parent directory identity for one patch commit transaction."""

    path: Path
    identity: tuple[int, int]
    fd: int | None = None
    handle: int | None = None

    @classmethod
    def acquire(cls, path: Path) -> PinnedDirectory | None:
        try:
            canonical = path.resolve(strict=True)
            identity = _identity(canonical.lstat())
            if os.name != "nt":
                flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                fd = os.open(canonical, flags)
                if _identity(os.fstat(fd)) != identity:
                    os.close(fd)
                    return None
                return cls(canonical, identity, fd=fd)
            import ctypes
            from ctypes import wintypes

            create_file = ctypes.windll.kernel32.CreateFileW
            create_file.argtypes = [
                wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
                wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
            ]
            create_file.restype = wintypes.HANDLE
            handle = create_file(
                str(canonical), 0x0001, 0x00000001 | 0x00000002, None, 3,
                0x02000000 | 0x00200000, None,
            )
            if handle == wintypes.HANDLE(-1).value:
                return None
            return cls(canonical, identity, handle=int(handle))
        except OSError:
            return None

    def verify(self) -> bool:
        if self.fd is not None:
            return _identity(os.fstat(self.fd)) == self.identity
        return self.handle is not None

    def close(self) -> None:
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        if self.handle is not None:
            import ctypes

            ctypes.windll.kernel32.CloseHandle(self.handle)
            self.handle = None


class SubprocessRunner:
    """Run a fixed argv without a shell and keep all captured output byte-bounded."""

    def run(self, argv: list[str], cwd: Path, timeout_s: int, output_limit: int) -> ProcessResult:
        if not argv or not all(isinstance(argument, str) and argument for argument in argv):
            raise ValueError("argv must contain non-empty strings")
        if timeout_s < 1 or output_limit < 1:
            raise ValueError("timeout_s and output_limit must be positive")
        fixed_cwd = Path(cwd).resolve(strict=True)
        if not fixed_cwd.is_dir():
            raise ValueError("cwd must be a directory")

        process = subprocess.Popen(
            argv,
            cwd=fixed_cwd,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=os.name != "nt",
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
        )
        captured: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray(), "output": bytearray()}
        lock = threading.Lock()
        truncated = False

        def drain(name: str, stream: BinaryIO) -> None:
            nonlocal truncated
            try:
                while block := stream.read(8_192):
                    with lock:
                        remaining = output_limit - len(captured["output"])
                        if remaining <= 0:
                            truncated = True
                            continue
                        kept = block[:remaining]
                        captured[name].extend(kept)
                        captured["output"].extend(kept)
                        if len(kept) != len(block):
                            truncated = True
            except (OSError, ValueError):
                return

        assert process.stdout is not None and process.stderr is not None
        readers = [
            threading.Thread(target=drain, args=("stdout", process.stdout), daemon=True),
            threading.Thread(target=drain, args=("stderr", process.stderr), daemon=True),
        ]
        for reader in readers:
            reader.start()
        timed_out = False
        try:
            process.wait(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            timed_out = True
            _terminate_process_tree(process)
            for stream in (process.stdout, process.stderr):
                threading.Thread(target=_close_pipe, args=(stream,), daemon=True).start()
            try:
                process.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                process.kill()
        finally:
            join_deadline = time.monotonic() + 0.25
            for reader in readers:
                reader.join(timeout=max(0, join_deadline - time.monotonic()))

        return ProcessResult(
            returncode=process.returncode,
            stdout=_decode_bounded(captured["stdout"]),
            stderr=_decode_bounded(captured["stderr"]),
            output=_decode_bounded(captured["output"]),
            timed_out=timed_out,
            truncated=truncated,
        )


class ToolDispatcher:
    """The single effect boundary for policy-approved repository actions."""

    def __init__(
        self,
        repo_root: Path,
        policy: PolicyEngine,
        process_runner: ProcessRunner,
        settings: Settings,
        commit_observer: CommitObserver | None = None,
    ) -> None:
        self._root = Path(repo_root).resolve(strict=True)
        if not self._root.is_dir():
            raise ValueError("repo_root must be a directory")
        self._policy = policy
        self._process_runner = process_runner
        self._settings = settings
        self._commit_observer = commit_observer or _NoopCommitObserver()

    def dispatch(
        self, action: Action, decision: PolicyDecision, current_snapshot_digest: str
    ) -> ToolResult:
        """Revalidate *decision* immediately before performing the requested effect."""
        refreshed = self._policy.revalidate(decision, action, current_snapshot_digest)
        if refreshed.outcome is not PolicyOutcome.ALLOW:
            return _result(action.kind, "policy_denied")
        if action.kind == "read_file":
            return self._read_file(str(action.arguments["path"]))
        if action.kind == "list_files":
            return self._list_files(action.arguments.get("path"))
        if action.kind == "search_text":
            return self._search_text(str(action.arguments["pattern"]), action.arguments.get("path"))
        if action.kind == "apply_patch":
            return self._apply_patch(str(action.arguments["patch"]))
        return _result(action.kind, "unsupported_action")

    def _read_file(self, raw_path: str) -> ToolResult:
        target = self._existing_file(raw_path)
        if target is None:
            return _result("read_file", "file_not_found")
        try:
            source = target.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            return _result("read_file", "utf8_decode_error")
        except OSError:
            return _result("read_file", "read_error")
        output, truncated = _truncate_text(source, self.output_limit)
        return _result("read_file", "ok", output=output, truncated=truncated)

    def _list_files(self, raw_path: object) -> ToolResult:
        target = self._directory(raw_path)
        if target is None:
            return _result("list_files", "directory_not_found")
        paths: list[str] = []
        excluded = _DEFAULT_EXCLUDED_DIRECTORIES | set(self._settings.exclusions)
        try:
            for directory, names, files in target.walk():
                names[:] = sorted(name for name in names if name not in excluded)
                for filename in sorted(files):
                    candidate = directory / filename
                    if candidate.is_symlink() or not candidate.is_file():
                        continue
                    relative = candidate.relative_to(self._root).as_posix()
                    if is_sensitive_relative_path(PurePosixPath(relative)):
                        continue
                    paths.append(relative)
        except OSError:
            return _result("list_files", "read_error")
        output, truncated = _truncate_text("\n".join(sorted(paths)), self.output_limit)
        return _result("list_files", "ok", output=output, truncated=truncated)

    def _search_text(self, pattern: str, raw_path: object) -> ToolResult:
        target = self._search_target(raw_path)
        if target is None:
            return _result("search_text", "path_not_found")
        candidates = [target] if target.is_file() else self._walk_files(target)
        matches: list[str] = []
        try:
            for candidate in candidates:
                try:
                    source = candidate.read_text(encoding="utf-8")
                except UnicodeDecodeError:
                    return _result("search_text", "utf8_decode_error")
                for line_number, line in enumerate(source.splitlines(), start=1):
                    if pattern in line:
                        matches.append(f"{candidate.relative_to(self._root).as_posix()}:{line_number}:{line}")
                        if len(matches) >= _MAX_SEARCH_MATCHES:
                            output, _ = _truncate_text("\n".join(matches), self.output_limit)
                            return _result("search_text", "ok", output=output, truncated=True)
        except OSError:
            return _result("search_text", "read_error")
        output, truncated = _truncate_text("\n".join(matches), self.output_limit)
        return _result("search_text", "ok", output=output, truncated=truncated)

    def _apply_patch(self, source: str) -> ToolResult:
        patch = parse_validated_patch(source)
        if patch is None:
            return _result("apply_patch", "malformed_patch")
        pins = self._acquire_parent_pins(patch)
        if pins is None:
            return _result("apply_patch", "patch_parent_unpinned")
        try:
            prepared, error = self._prepare_patch(patch)
            if error is not None:
                return _result("apply_patch", error)
            assert prepared is not None
            self._commit_observer.after_pins_acquired(tuple(pin.path for pin in pins))
            if not all(pin.verify() for pin in pins):
                return _result("apply_patch", "patch_parent_unpinned")
            records: list[_CommitRecord] = []
            try:
                for item in prepared:
                    records.append(_CommitRecord(item, _write_patch_temp(item)))
            except OSError:
                _cleanup_temps(records)
                return _result("apply_patch", "patch_write_error")

            committed: list[_CommitRecord] = []
            for record in records:
                code = self._commit_record(record)
                if code is None:
                    committed.append(record)
                    continue
                rollback_paths = _rollback([*committed, record])
                _cleanup_temps(records)
                if rollback_paths:
                    return _result("apply_patch", "patch_rollback_incomplete", affected_paths=rollback_paths)
                return _result("apply_patch", code)

            cleanup_paths = _cleanup_backups(records, self._commit_observer)
            _cleanup_temps(records)
            if cleanup_paths:
                return _result("apply_patch", "patch_cleanup_incomplete", affected_paths=cleanup_paths)
        finally:
            for pin in reversed(pins):
                pin.close()

        changed = tuple(item.patch.path for item in prepared)
        before = {item.patch.path: _digest(item.old_content) for item in prepared if item.old_content is not None}
        after = {item.patch.path: _digest(item.new_content) for item in prepared if item.new_content is not None}
        return ToolResult(
            effect_kind="apply_patch",
            code_changed=bool(prepared),
            changed_paths=changed,
            before_digests=before,
            after_digests=after,
            normalized_metadata={"code": "ok"},
        )

    def _acquire_parent_pins(self, patch: ValidatedPatch) -> list[PinnedDirectory] | None:
        parents: set[Path] = set()
        for file_patch in patch.files:
            target = self._patch_target(file_patch.path)
            if target is None:
                return None
            parents.add(target.parent.resolve(strict=True))
        pins: list[PinnedDirectory] = []
        for parent in sorted(parents, key=lambda path: str(path).casefold()):
            pin = PinnedDirectory.acquire(parent)
            if pin is None:
                for acquired in reversed(pins):
                    acquired.close()
                return None
            pins.append(pin)
        return pins

    def _commit_record(self, record: _CommitRecord) -> str | None:
        item = record.item
        operation = "delete" if item.new_content is None else "modify" if item.old_content is not None else "create"
        if item.old_content is not None:
            code = _capture_target(record)
            if code is not None:
                return code
            self._commit_observer.after_capture(item.target)
        self._commit_observer.before_install_or_delete(item.target, operation)

        if operation == "delete":
            if _path_exists(item.target):
                assert record.backup is not None
                record.backup.unlink()
                record.backup = None
                return "patch_target_changed"
            return None
        if _path_exists(item.target) or record.temporary is None:
            return "patch_target_changed"
        if not _install_exclusive(record.temporary, item.target):
            return "patch_target_changed"
        record.temporary = None
        record.installed_identity = _identity(item.target.lstat())
        record.installed_digest = _digest(item.target.read_bytes())
        return None

    @property
    def output_limit(self) -> int:
        return min(self._settings.read_search_result_bytes, self._settings.max_tool_output_bytes)

    def _prepare_patch(self, patch: ValidatedPatch) -> tuple[list[_PreparedPatch] | None, str | None]:
        prepared: list[_PreparedPatch] = []
        for file_patch in patch.files:
            target = self._patch_target(file_patch.path)
            if target is None:
                return None, "patch_path_error"
            exists = target.exists()
            if exists and (target.is_symlink() or not target.is_file()):
                return None, "patch_path_error"
            try:
                old_content = target.read_bytes() if exists else None
            except OSError:
                return None, "patch_read_error"
            if file_patch.old_path is not None and old_content is None:
                return None, "patch_context_mismatch"
            if file_patch.old_path is None and old_content is not None:
                return None, "patch_context_mismatch"
            if old_content is not None:
                if not old_content.endswith(b"\n"):
                    return None, "patch_target_missing_final_newline"
                try:
                    current = old_content.decode("utf-8")
                except UnicodeDecodeError:
                    return None, "patch_utf8_decode_error"
            else:
                current = ""
            updated = _apply_file_hunks(current, file_patch)
            if updated is None:
                return None, "patch_context_mismatch"
            new_content = None if file_patch.new_path is None else updated.encode("utf-8")
            state = _capture_target_state(target, old_content, self._root)
            if state is None:
                return None, "patch_target_changed"
            prepared.append(_PreparedPatch(file_patch, target, old_content, new_content, state))
        return prepared, None

    def _existing_file(self, raw_path: str) -> Path | None:
        target = self._safe_target(raw_path)
        if target is None or target.is_symlink() or not target.is_file():
            return None
        return target

    def _directory(self, raw_path: object) -> Path | None:
        target = self._root if raw_path is None else self._safe_target(str(raw_path))
        if target is None or target.is_symlink() or not target.is_dir():
            return None
        return target

    def _search_target(self, raw_path: object) -> Path | None:
        target = self._root if raw_path is None else self._safe_target(str(raw_path))
        if target is None or target.is_symlink() or not (target.is_file() or target.is_dir()):
            return None
        return target

    def _walk_files(self, target: Path) -> list[Path]:
        excluded = _DEFAULT_EXCLUDED_DIRECTORIES | set(self._settings.exclusions)
        results: list[Path] = []
        for directory, names, files in target.walk():
            names[:] = sorted(name for name in names if name not in excluded)
            results.extend(
                candidate
                for name in sorted(files)
                if not (candidate := directory / name).is_symlink()
                and is_sensitive_relative_path(PurePosixPath(candidate.relative_to(self._root).as_posix()))
                is False
            )
        return results

    def _safe_target(self, raw_path: str) -> Path | None:
        try:
            relative = PurePosixPath(raw_path)
            if not raw_path or "\\" in raw_path or relative.is_absolute() or ".." in relative.parts:
                return None
            target = self._root.joinpath(*relative.parts)
            resolved = target.resolve(strict=True)
        except OSError:
            return None
        return resolved if resolved.is_relative_to(self._root) else None

    def _patch_target(self, raw_path: str) -> Path | None:
        relative = PurePosixPath(raw_path)
        target = self._root.joinpath(*relative.parts)
        try:
            parent = target.parent.resolve(strict=True)
        except OSError:
            return None
        if not parent.is_relative_to(self._root):
            return None
        return target


@dataclass(frozen=True)
class _PreparedPatch:
    patch: PatchFile
    target: Path
    old_content: bytes | None
    new_content: bytes | None
    target_state: _TargetState


@dataclass
class _CommitRecord:
    item: _PreparedPatch
    temporary: Path | None
    backup: Path | None = None
    installed_identity: tuple[int, int] | None = None
    installed_digest: str | None = None


@dataclass(frozen=True)
class _TargetState:
    canonical_parent: Path
    parent_identity: tuple[int, int]
    target_identity: tuple[int, int] | None
    target_digest: str | None


def _apply_file_hunks(current: str, patch: PatchFile) -> str | None:
    lines = current.splitlines(keepends=True)
    offset = 0
    newline = "\r\n" if "\r\n" in current else "\n"
    for hunk in patch.hunks:
        start = hunk.old_start + offset if hunk.old_count == 0 else hunk.old_start - 1 + offset
        if start < 0 or start > len(lines):
            return None
        expected = [line.text for line in hunk.lines if line.prefix in {" ", "-"}]
        if [_line_text(line) for line in lines[start : start + hunk.old_count]] != expected:
            return None
        replacement = [
            line.text + newline
            for line in hunk.lines
            if line.prefix in {" ", "+"}
        ]
        lines[start : start + hunk.old_count] = replacement
        offset += hunk.new_count - hunk.old_count
    return "".join(lines)


def _line_text(line: str) -> str:
    return line.removesuffix("\n").removesuffix("\r")


def _result(
    effect_kind: str,
    code: str,
    *,
    output: str = "",
    truncated: bool = False,
    affected_paths: list[str] | None = None,
) -> ToolResult:
    metadata: dict[str, object] = {"code": code}
    if affected_paths:
        metadata["affected_paths"] = affected_paths
    return ToolResult(
        effect_kind=effect_kind,
        code_changed=False,
        truncated=truncated,
        normalized_metadata=metadata,
        evidence=output or None,
    )


def _truncate_text(value: str, limit: int) -> tuple[str, bool]:
    encoded = value.encode("utf-8")
    if len(encoded) <= limit:
        return value, False
    return encoded[:limit].decode("utf-8", errors="ignore"), True


def _decode_bounded(value: bytes | bytearray) -> str:
    return bytes(value).decode("utf-8", errors="ignore")


def _digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _capture_target_state(target: Path, content: bytes | None, root: Path) -> _TargetState | None:
    try:
        parent = target.parent.resolve(strict=True)
        if not parent.is_relative_to(root):
            return None
        parent_stat = parent.lstat()
        if content is None:
            if target.exists() or target.is_symlink():
                return None
            return _TargetState(parent, _identity(parent_stat), None, None)
        target_stat = target.lstat()
    except OSError:
        return None
    return _TargetState(parent, _identity(parent_stat), _identity(target_stat), _digest(content))


def _target_state_matches(item: _PreparedPatch) -> bool:
    try:
        parent = item.target.parent.resolve(strict=True)
        if parent != item.target_state.canonical_parent or _identity(parent.lstat()) != item.target_state.parent_identity:
            return False
        if item.target_state.target_identity is None:
            return not item.target.exists() and not item.target.is_symlink()
        return (
            _identity(item.target.lstat()) == item.target_state.target_identity
            and _digest(item.target.read_bytes()) == item.target_state.target_digest
        )
    except OSError:
        return False


def _write_patch_temp(item: _PreparedPatch) -> Path | None:
    if item.new_content is None:
        return None
    descriptor, temporary_name = tempfile.mkstemp(dir=item.target.parent, prefix=".pyquality-")
    temporary = Path(temporary_name)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(item.new_content)
    return temporary


def _capture_target(record: _CommitRecord) -> str | None:
    item = record.item
    if not _target_state_matches(item):
        return "patch_target_changed"
    descriptor, backup_name = tempfile.mkstemp(dir=item.target.parent, prefix=".pyquality-backup-")
    os.close(descriptor)
    backup = Path(backup_name)
    try:
        os.replace(item.target, backup)
    except OSError:
        backup.unlink(missing_ok=True)
        return "patch_target_changed"
    record.backup = backup
    if _backup_matches(record):
        return None
    if not _restore_exclusive(backup, item.target):
        record.backup = backup
    else:
        record.backup = None
    return "patch_target_changed"


def _backup_matches(record: _CommitRecord) -> bool:
    assert record.backup is not None
    expected = record.item.target_state
    try:
        return (
            _identity(record.backup.lstat()) == expected.target_identity
            and _digest(record.backup.read_bytes()) == expected.target_digest
        )
    except OSError:
        return False


def _install_exclusive(temporary: Path, target: Path) -> bool:
    try:
        os.link(temporary, target)
    except FileExistsError:
        return False
    except OSError:
        return False
    temporary.unlink()
    return True


def _restore_exclusive(backup: Path, target: Path) -> bool:
    if _path_exists(target):
        return False
    return _install_exclusive(backup, target)


def _rollback(records: list[_CommitRecord]) -> list[str]:
    incomplete: list[str] = []
    for record in reversed(records):
        item = record.item
        if record.installed_identity is not None:
            if not _file_matches(item.target, record.installed_identity, record.installed_digest):
                incomplete.append(item.patch.path)
                continue
            try:
                item.target.unlink()
            except OSError:
                incomplete.append(item.patch.path)
                continue
        if record.backup is not None:
            if not _restore_exclusive(record.backup, item.target):
                incomplete.append(item.patch.path)
                incomplete.append(record.backup.name)
                continue
            record.backup = None
    return sorted(set(incomplete))


def _cleanup_backups(records: list[_CommitRecord], observer: CommitObserver) -> list[str]:
    incomplete: list[str] = []
    for record in records:
        if record.backup is None:
            continue
        try:
            observer.before_cleanup(record.item.target, record.backup)
            record.backup.unlink()
            record.backup = None
        except OSError:
            incomplete.append(record.backup.name)
    return incomplete


def _cleanup_temps(records: list[_CommitRecord]) -> None:
    for record in records:
        if record.temporary is not None:
            record.temporary.unlink(missing_ok=True)
            record.temporary = None


def _file_matches(target: Path, identity: tuple[int, int], digest: str | None) -> bool:
    try:
        return _identity(target.lstat()) == identity and _digest(target.read_bytes()) == digest
    except OSError:
        return False


def _path_exists(path: Path) -> bool:
    return path.exists() or path.is_symlink()


def _identity(details: os.stat_result) -> tuple[int, int]:
    return details.st_dev, details.st_ino


def _terminate_process_tree(process: subprocess.Popen[bytes]) -> None:
    if os.name == "nt":
        try:
            taskkill = subprocess.Popen(
                ["taskkill.exe", "/PID", str(process.pid), "/T", "/F"],
                shell=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                taskkill.wait(timeout=0.25)
            except subprocess.TimeoutExpired:
                taskkill.kill()
        except OSError:
            pass
        finally:
            try:
                process.kill()
            except ProcessLookupError:
                pass
        return
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def _close_pipe(stream: BinaryIO | None) -> None:
    if stream is not None:
        try:
            stream.close()
        except OSError:
            return
