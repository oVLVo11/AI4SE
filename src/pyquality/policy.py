"""Deterministic repository-confinement and governance decisions."""

from __future__ import annotations

import hashlib
import json
import re
import stat
from dataclasses import dataclass
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
_CUSTOM_PATCH_FILE = re.compile(r"^\*\*\* (Add|Delete|Update) File: (.+)$")
_GIT_DIFF_FILE = re.compile(r"^diff --git a/(.+) b/(.+)$")
_UNAVAILABLE_SNAPSHOT_DIGEST = hashlib.sha256(b"repository snapshot unavailable").hexdigest()


@dataclass(frozen=True)
class _PatchImpact:
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
            return _decision(PolicyOutcome.DENY, "invalid_action", error, digest, snapshot_digest)

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

    def _action_paths(self, action: Action) -> tuple[tuple[str, ...], _PatchImpact | None, str | None]:
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
        impact = _parse_patch(patch)
        if not impact.paths:
            return (), None, "Patch does not identify any repository files."
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


def _parse_patch(patch: str) -> _PatchImpact:
    paths: set[str] = set()
    changed_lines = 0
    deletes_file = False
    pending_old_path: str | None = None
    for line in patch.splitlines():
        custom_match = _CUSTOM_PATCH_FILE.match(line)
        if custom_match is not None:
            operation, path = custom_match.groups()
            paths.add(path)
            deletes_file = deletes_file or operation == "Delete"
            continue
        git_match = _GIT_DIFF_FILE.match(line)
        if git_match is not None:
            paths.update(git_match.groups())
            continue
        if line.startswith("--- "):
            pending_old_path = _patch_header_path(line[4:])
            if pending_old_path is not None:
                paths.add(pending_old_path)
            continue
        if line.startswith("+++ "):
            new_path = _patch_header_path(line[4:])
            if new_path is None and pending_old_path is not None:
                deletes_file = True
            elif new_path is not None:
                paths.add(new_path)
            continue
        if line.startswith(("+", "-")):
            changed_lines += 1
    return _PatchImpact(tuple(sorted(paths)), changed_lines, deletes_file)


def _patch_header_path(value: str) -> str | None:
    path = value.split("\t", 1)[0].strip()
    if path == "/dev/null":
        return None
    if path.startswith(("a/", "b/")):
        return path[2:]
    return path


def _has_protected_path(paths: tuple[str, ...]) -> bool:
    for raw_path in paths:
        path = PurePosixPath(raw_path)
        normalized = str(path).casefold()
        if normalized in _DEPENDENCY_PATHS or path.name.casefold() in _CI_FILENAMES:
            return True
        if path.parts[:2] == (".github", "workflows") or path.parts[:1] == (".circleci",):
            return True
    return False
