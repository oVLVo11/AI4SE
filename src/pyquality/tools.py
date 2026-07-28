"""Bounded repository effects reached only through a revalidated policy decision."""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Protocol

from pyquality.config import Settings
from pyquality.domain.models import Action, PolicyDecision, PolicyOutcome, ToolResult
from pyquality.policy import PatchFile, PolicyEngine, ValidatedPatch, parse_validated_patch

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
        )
        captured: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray(), "output": bytearray()}
        lock = threading.Lock()
        truncated = False

        def drain(name: str, stream: object) -> None:
            nonlocal truncated
            assert hasattr(stream, "read")
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
            process.kill()
            process.wait()
        finally:
            for reader in readers:
                reader.join()

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
        self, repo_root: Path, policy: PolicyEngine, process_runner: ProcessRunner, settings: Settings
    ) -> None:
        self._root = Path(repo_root).resolve(strict=True)
        if not self._root.is_dir():
            raise ValueError("repo_root must be a directory")
        self._policy = policy
        self._process_runner = process_runner
        self._settings = settings

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
                    paths.append(relative)
        except OSError:
            return _result("list_files", "read_error")
        output, truncated = _truncate_text("\n".join(sorted(paths)), self.output_limit)
        return _result("list_files", "ok", output=output, truncated=truncated)

    def _search_text(self, pattern: str, raw_path: object) -> ToolResult:
        try:
            matcher = re.compile(pattern)
        except re.error:
            return _result("search_text", "invalid_regex")
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
                    if matcher.search(line):
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
        prepared, error = self._prepare_patch(patch)
        if error is not None:
            return _result("apply_patch", error)
        assert prepared is not None
        temporary_paths: list[Path] = []
        try:
            for item in prepared:
                if item.new_content is None:
                    continue
                descriptor, temporary_name = tempfile.mkstemp(dir=item.target.parent, prefix=".pyquality-")
                temporary = Path(temporary_name)
                temporary_paths.append(temporary)
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(item.new_content)
            for item, temporary in zip(
                (item for item in prepared if item.new_content is not None), temporary_paths, strict=True
            ):
                os.replace(temporary, item.target)
            for item in prepared:
                if item.new_content is None and item.target.exists():
                    item.target.unlink()
        except OSError:
            return _result("apply_patch", "patch_write_error")
        finally:
            for temporary in temporary_paths:
                if temporary.exists():
                    temporary.unlink(missing_ok=True)

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
            prepared.append(_PreparedPatch(file_patch, target, old_content, new_content))
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
            results.extend(directory / name for name in sorted(files) if not (directory / name).is_symlink())
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
            line.text + ("" if line.no_newline else newline)
            for line in hunk.lines
            if line.prefix in {" ", "+"}
        ]
        lines[start : start + hunk.old_count] = replacement
        offset += hunk.new_count - hunk.old_count
    return "".join(lines)


def _line_text(line: str) -> str:
    return line.removesuffix("\n").removesuffix("\r")


def _result(effect_kind: str, code: str, *, output: str = "", truncated: bool = False) -> ToolResult:
    return ToolResult(
        effect_kind=effect_kind,
        code_changed=False,
        truncated=truncated,
        normalized_metadata={"code": code},
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
