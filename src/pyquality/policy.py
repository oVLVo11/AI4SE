"""Deterministic repository-confinement and governance decisions."""

from __future__ import annotations

import hashlib
import json
import re
import stat
from dataclasses import dataclass, replace
from fnmatch import fnmatchcase
from pathlib import Path, PurePosixPath

from pyquality.domain.models import Action, PolicyDecision, PolicyOutcome

_ALLOWED_ACTION_KINDS = frozenset(
    {"read_file", "search_text", "list_files", "apply_patch", "run_quality", "finish"}
)
_DEFAULT_SENSITIVE_PATTERNS = (
    ".env",
    ".env.*",
    ".git",
    ".aws",
    ".gnupg",
    ".kube",
    ".ssh",
    "credentials",
    "credential",
    "secrets",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa",
    "*.key",
    "*.pem",
    "*.p12",
    "*.pfx",
)
_DEPENDENCY_PATHS = {
    "pyproject.toml",
    "requirements.txt",
    "requirements-dev.txt",
    "setup.cfg",
    "setup.py",
    "tox.ini",
    "pdm.lock",
    "poetry.lock",
    "pipfile",
    "pipfile.lock",
}
_CI_FILENAMES = {".gitlab-ci.yml", "azure-pipelines.yml", "jenkinsfile"}
_HUNK_HEADER = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@$")
_UNAVAILABLE_SNAPSHOT_DIGEST = hashlib.sha256(b"repository snapshot unavailable").hexdigest()


@dataclass(frozen=True)
class PatchLine:
    """One validated unified-diff body line, without its trailing newline."""

    prefix: str
    text: str
    no_newline: bool = False


@dataclass(frozen=True)
class PatchHunk:
    """A contextual hunk that both policy and dispatch consume."""

    old_start: int
    old_count: int
    new_start: int
    new_count: int
    lines: tuple[PatchLine, ...]


@dataclass(frozen=True)
class PatchFile:
    """A validated file section from a unified patch."""

    old_path: str | None
    new_path: str | None
    hunks: tuple[PatchHunk, ...]

    @property
    def path(self) -> str:
        return self.old_path or self.new_path or ""


@dataclass(frozen=True)
class ValidatedPatch:
    """Reusable, grammar-validated unified diff shared by policy and tools."""

    files: tuple[PatchFile, ...]
    paths: tuple[str, ...]
    changed_lines: int
    deletes_file: bool


class PolicyEngine:
    """Classify typed actions without performing filesystem effects."""

    def __init__(
        self, repo_root: Path, sensitive_patterns: tuple[str, ...] = _DEFAULT_SENSITIVE_PATTERNS
    ) -> None:
        self._repo_root_path = Path(repo_root)
        self._canonical_root()
        self._sensitive_patterns = tuple(pattern.casefold() for pattern in sensitive_patterns)

    def evaluate(self, action: Action) -> PolicyDecision:
        """Return the safe, approval-gated, or denied classification for *action*."""
        digest = _action_digest(action)
        root = self._canonical_root_or_none()
        if root is None:
            return _decision(
                PolicyOutcome.DENY,
                "repository_root_changed",
                "Repository root is unavailable.",
                digest,
                _UNAVAILABLE_SNAPSHOT_DIGEST,
            )
        snapshot_digest = _repository_snapshot_digest(root)
        if snapshot_digest is None:
            return _decision(
                PolicyOutcome.DENY,
                "repository_snapshot_unavailable",
                "Repository snapshot is unavailable.",
                digest,
                _UNAVAILABLE_SNAPSHOT_DIGEST,
            )
        if action.kind not in _ALLOWED_ACTION_KINDS:
            return _decision(
                PolicyOutcome.DENY,
                "unknown_action",
                "Action kind is not permitted.",
                digest,
                snapshot_digest,
            )
        paths, impact, error = self._action_paths(action)
        if error is not None:
            rule = "malformed_patch" if error == "malformed_patch" else "invalid_action"
            summary = "Patch is not a valid contextual unified diff." if rule == "malformed_patch" else error
            return _decision(PolicyOutcome.DENY, rule, summary, digest, snapshot_digest)

        for path in paths:
            denial = self._path_denial(path, root)
            if denial is not None:
                return _decision(
                    PolicyOutcome.DENY, denial, f"Path is not permitted: {path}", digest, snapshot_digest
                )

        if action.kind != "apply_patch":
            return _decision(
                PolicyOutcome.ALLOW,
                None,
                "Repository-confined non-mutating action.",
                digest,
                snapshot_digest,
            )

        assert impact is not None
        if impact.deletes_file:
            return _decision(
                PolicyOutcome.REQUIRE_APPROVAL,
                "file_deletion",
                "Patch deletes a repository file.",
                digest,
                snapshot_digest,
            )
        if _has_protected_path(impact.paths):
            return _decision(
                PolicyOutcome.REQUIRE_APPROVAL,
                "protected_patch_path",
                "Patch changes dependency declarations or CI configuration.",
                digest,
                snapshot_digest,
            )
        if len(impact.paths) > 10 or impact.changed_lines > 300:
            return _decision(
                PolicyOutcome.REQUIRE_APPROVAL,
                "broad_patch",
                f"Patch affects {len(impact.paths)} files and {impact.changed_lines} changed lines.",
                digest,
                snapshot_digest,
            )
        return _decision(
            PolicyOutcome.ALLOW,
            None,
            f"Patch affects {len(impact.paths)} files and {impact.changed_lines} changed lines.",
            digest,
            snapshot_digest,
        )

    def revalidate(
        self, decision: PolicyDecision, action: Action, current_snapshot_digest: str
    ) -> PolicyDecision:
        """Re-evaluate a decision-bound action and current repository snapshot before dispatch."""
        action_digest = _action_digest(action)
        if action_digest != decision.action_digest:
            return _decision(
                PolicyOutcome.DENY,
                "action_digest_mismatch",
                "Action does not match the saved decision.",
                action_digest,
                current_snapshot_digest,
            )
        if current_snapshot_digest != decision.repository_snapshot_digest:
            return _decision(
                PolicyOutcome.DENY,
                "repository_snapshot_drift",
                "Repository snapshot drifted since the decision.",
                action_digest,
                current_snapshot_digest,
            )
        refreshed = self.evaluate(action)
        if refreshed.repository_snapshot_digest != current_snapshot_digest:
            return _decision(
                PolicyOutcome.DENY,
                "repository_snapshot_drift",
                "Repository snapshot drifted since the decision.",
                action_digest,
                refreshed.repository_snapshot_digest,
            )
        return refreshed

    def _canonical_root(self) -> Path:
        root = self._repo_root_path.resolve(strict=True)
        if not root.is_dir():
            raise ValueError("repo_root must resolve to a directory")
        return root

    def _canonical_root_or_none(self) -> Path | None:
        try:
            return self._canonical_root()
        except (OSError, ValueError):
            return None

    def _action_paths(self, action: Action) -> tuple[tuple[str, ...], ValidatedPatch | None, str | None]:
        arguments = action.arguments
        if action.kind in {"read_file", "search_text", "list_files"}:
            path = arguments.get("path")
            if path is None:
                return (), None, None
            if not isinstance(path, str):
                return (), None, "Action path must be text."
            return (path,), None, None
        if action.kind != "apply_patch":
            return (), None, None
        patch = arguments.get("patch")
        if not isinstance(patch, str):
            return (), None, "Patch must be text."
        impact = parse_validated_patch(patch)
        if impact is None:
            return (), None, "malformed_patch"
        return impact.paths, impact, None

    def _path_denial(self, raw_path: str, root: Path) -> str | None:
        path = _normalized_relative_path(raw_path)
        if path is None:
            return "path_escape"
        if _is_sensitive(path, self._sensitive_patterns):
            return "sensitive_path"
        target = _resolve_target(root, path)
        if target is None or not target.is_relative_to(root):
            return "path_escape"
        return None


def _action_digest(action: Action) -> str:
    payload = {"kind": action.kind, "arguments": action.arguments, "rationale": action.rationale}
    normalized = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _decision(
    outcome: PolicyOutcome,
    matched_rule: str | None,
    impact_summary: str,
    action_digest: str,
    repository_snapshot_digest: str,
) -> PolicyDecision:
    return PolicyDecision(
        outcome=outcome,
        matched_rule=matched_rule,
        impact_summary=impact_summary,
        action_digest=action_digest,
        repository_snapshot_digest=repository_snapshot_digest,
    )


def _repository_snapshot_digest(root: Path) -> str | None:
    entries: list[tuple[str, str, str]] = []
    try:
        for path in root.rglob("*"):
            relative = path.relative_to(root).as_posix()
            details = path.lstat()
            if stat.S_ISLNK(details.st_mode):
                entries.append((relative, "link", path.readlink().as_posix()))
            elif stat.S_ISDIR(details.st_mode):
                entries.append((relative, "directory", ""))
            elif stat.S_ISREG(details.st_mode):
                entries.append((relative, "file", _file_digest(path)))
            else:
                entries.append((relative, "other", str(details.st_mode)))
    except OSError:
        return None
    normalized = json.dumps(sorted(entries), ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for block in iter(lambda: file.read(64 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _normalized_relative_path(value: str) -> PurePosixPath | None:
    path = PurePosixPath(value)
    if not value or "\\" in value or path.is_absolute() or ".." in path.parts:
        return None
    if any(part in {"", "."} for part in path.parts):
        return None
    return path


def _resolve_target(root: Path, relative_path: PurePosixPath) -> Path | None:
    candidate = root.joinpath(*relative_path.parts)
    remaining: list[str] = []
    parent = candidate
    try:
        while not parent.exists() and not parent.is_symlink():
            remaining.append(parent.name)
            parent = parent.parent
        resolved_parent = parent.resolve(strict=True)
    except OSError:
        return None
    return resolved_parent.joinpath(*reversed(remaining))


def _is_sensitive(path: PurePosixPath, patterns: tuple[str, ...]) -> bool:
    return any(
        fnmatchcase(segment.casefold(), pattern)
        for segment in path.parts
        for pattern in patterns
    )


def parse_validated_patch(patch: str) -> ValidatedPatch | None:
    """Return the complete contextual diff grammar used for policy and application.

    This validates only patch syntax and confinement-safe header paths. Filesystem
    context is deliberately checked by ``ToolDispatcher`` immediately after policy
    revalidation, so policy cannot authorize a different parse than dispatch uses.
    """
    paths: set[str] = set()
    changed_lines = 0
    deletes_file = False
    files: list[PatchFile] = []
    lines = patch.splitlines()
    index = 0
    while index < len(lines):
        old_path = _header_path(lines[index], "--- a/")
        if old_path is None and lines[index] != "--- /dev/null":
            return None
        index += 1
        if index == len(lines):
            return None
        new_path = _header_path(lines[index], "+++ b/")
        if new_path is None and lines[index] != "+++ /dev/null":
            return None
        index += 1
        if old_path is None and new_path is None:
            return None
        if old_path is not None and new_path is not None and old_path != new_path:
            return None
        path = old_path or new_path
        assert path is not None
        paths.add(path)
        deletes_file = deletes_file or new_path is None
        found_hunk = False
        hunks: list[PatchHunk] = []
        requires_context = old_path is not None and new_path is not None
        while index < len(lines) and not lines[index].startswith("--- "):
            hunk_match = _HUNK_HEADER.match(lines[index])
            if hunk_match is None:
                return None
            found_hunk = True
            old_count = int(hunk_match.group(2) or "1")
            new_count = int(hunk_match.group(4) or "1")
            old_start = int(hunk_match.group(1))
            new_start = int(hunk_match.group(3))
            index += 1
            old_seen = 0
            new_seen = 0
            has_context = False
            body: list[PatchLine] = []
            while index < len(lines) and not lines[index].startswith(("@@ ", "--- ")):
                line = lines[index]
                if line == r"\ No newline at end of file":
                    if not body:
                        return None
                    body[-1] = replace(body[-1], no_newline=True)
                    index += 1
                    continue
                if not line.startswith((" ", "+", "-")):
                    return None
                if line.startswith(" "):
                    old_seen += 1
                    new_seen += 1
                    has_context = True
                elif line.startswith("+"):
                    new_seen += 1
                    changed_lines += 1
                else:
                    old_seen += 1
                    changed_lines += 1
                body.append(PatchLine(line[0], line[1:]))
                index += 1
            if old_seen != old_count or new_seen != new_count:
                return None
            if requires_context and not has_context:
                return None
            hunks.append(PatchHunk(old_start, old_count, new_start, new_count, tuple(body)))
        if not found_hunk:
            return None
        files.append(PatchFile(old_path, new_path, tuple(hunks)))
    return ValidatedPatch(tuple(files), tuple(sorted(paths)), changed_lines, deletes_file)


def _header_path(line: str, prefix: str) -> str | None:
    if not line.startswith(prefix):
        return None
    path = line.removeprefix(prefix)
    if not path or any(character.isspace() for character in path) or '"' in path:
        return None
    try:
        path.encode("utf-8")
    except UnicodeEncodeError:
        return None
    if "\\" in path or ".." in path.split("/") or "" in path.split("/") or "." in path.split("/"):
        return None
    if _normalized_relative_path(path) is None:
        return None
    return path


def _has_protected_path(paths: tuple[str, ...]) -> bool:
    for raw_path in paths:
        path = PurePosixPath(raw_path)
        normalized = str(path).casefold()
        if normalized in _DEPENDENCY_PATHS or path.name.casefold() in _CI_FILENAMES:
            return True
        parts = tuple(part.casefold() for part in path.parts)
        if parts[:2] == (".github", "workflows") or parts[:1] == (".circleci",):
            return True
    return False
