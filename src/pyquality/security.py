"""Credential isolation, bounded redaction, and hardened local JSONL audit output."""

from __future__ import annotations

import json
import math
import os
import re
import stat
import tempfile
from collections.abc import Callable, Iterable, Iterator, Mapping
from collections.abc import Set as AbstractSet
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Literal
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit, urlunsplit

from pydantic import Field

from .domain.models import AuditEvent, PublicModel

_REDACTED = "[REDACTED]"
_REDACTED_BYTES = "[REDACTED_BYTES]"
_UNSUPPORTED = "[UNSUPPORTED_OBJECT]"
_CYCLE = "[CYCLE]"
_TRUNCATED = "[TRUNCATED]"
_MAX_DEPTH = 16
_MAX_WORK = 512
_MAX_ITEMS = 128
_MAX_TEXT_BYTES = 4_096
_MAX_REDACTION_BYTES = 8_192
_MAX_RECORD_BYTES = 16_384
_SENSITIVE_KEY_PARTS = frozenset(
    {"authorization", "api_key", "apikey", "token", "secret", "password", "credential"}
)
_BEARER = re.compile(r"(?i)(bearer\s+)([^\s,;]+)")
_APPROVED_ALIASES = {
    "intent_id": "intent_id", "intentId": "intent_id", "intent-id": "intent_id",
    "approval_id": "approval_id", "approvalId": "approval_id", "approval-id": "approval_id",
    "action_digest": "action_digest", "actionDigest": "action_digest", "action-digest": "action_digest",
    "digest": "digest", "status": "status", "decision": "decision", "duration": "duration",
    "outcome": "outcome", "error_code": "error_code", "errorCode": "error_code",
}


class CredentialError(RuntimeError):
    """Base class for deliberately detail-free credential failures."""


class CredentialBackendError(CredentialError):
    pass


class CredentialNotFoundError(CredentialError):
    pass


class CredentialProviderError(CredentialError):
    pass


class AuditWriteError(RuntimeError):
    pass


class CredentialWarning(PublicModel):
    code: Literal["environment_plaintext"]
    message: str = Field(min_length=1, max_length=256)


class CredentialStatus(PublicModel):
    present: bool
    source: Literal["keyring", "environment"]
    warning: CredentialWarning | None = None


@dataclass(frozen=True, repr=False)
class CredentialUse[T]:
    value: T
    warning: CredentialWarning | None = None

    def __repr__(self) -> str:
        return f"CredentialUse(warning={self.warning!r})"


class CredentialService:
    def __init__(self, backend: object, *, service_name: str) -> None:
        if not isinstance(service_name, str) or not service_name:
            raise ValueError("service_name must be non-empty text")
        self._backend = backend
        self._service_name = service_name

    def set(self, account: str, secret: str) -> None:
        self._valid_account(account)
        if not isinstance(secret, str) or not secret:
            raise ValueError("credential must be non-empty text")
        backend = self._usable_backend()
        failed = False
        try:
            backend.set_password(self._service_name, account, secret)  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001
            failed = True
        if failed:
            raise CredentialBackendError("credential backend write failed")

    def status(self, account: str, *, source: Literal["keyring", "environment"] = "keyring") -> CredentialStatus:
        self._valid_account(account)
        self._valid_source(source)
        if source == "environment":
            return CredentialStatus(present=bool(os.environ.get("PYQUALITY_API_KEY")), source="environment", warning=_environment_warning())
        backend = self._usable_backend()
        failed = False
        present = False
        try:
            present = backend.get_password(self._service_name, account) is not None  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001
            failed = True
        if failed:
            raise CredentialBackendError("credential backend status check failed")
        return CredentialStatus(present=present, source="keyring")

    def get[T](self, account: str, provider: Callable[[str], T], *, source: Literal["keyring", "environment"] = "keyring") -> CredentialUse[object]:
        self._valid_account(account)
        self._valid_source(source)
        if not callable(provider):
            raise TypeError("provider must be callable")
        warning: CredentialWarning | None = None
        failed = False
        if source == "environment":
            secret = os.environ.get("PYQUALITY_API_KEY")
            warning = _environment_warning()
        else:
            secret = None
            backend = self._usable_backend()
            try:
                secret = backend.get_password(self._service_name, account)  # type: ignore[attr-defined]
            except Exception:  # noqa: BLE001
                failed = True
        if failed:
            raise CredentialBackendError("credential backend read failed")
        if not isinstance(secret, str) or not secret:
            raise CredentialNotFoundError("credential is not available from the selected source")
        provider_failed = False
        value: object = None
        try:
            value = provider(secret)
        except Exception:  # noqa: BLE001
            provider_failed = True
        if provider_failed:
            raise CredentialProviderError("credential provider operation failed")
        try:
            safe_value = _safe_provider_value(value, (secret,), set(), 0)
        except ValueError:
            safe_value = None
            provider_failed = True
        if provider_failed:
            raise CredentialProviderError("credential provider returned an unsafe result")
        return CredentialUse(value=safe_value, warning=warning)

    def clear(self, account: str) -> None:
        self._valid_account(account)
        backend = self._usable_backend()
        failed = False
        try:
            backend.delete_password(self._service_name, account)  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001
            failed = True
        if failed:
            raise CredentialBackendError("credential backend delete failed")

    def _usable_backend(self) -> object:
        try:
            methods = (self._backend.get_password, self._backend.set_password, self._backend.delete_password)  # type: ignore[attr-defined]
            priority = getattr(self._backend, "priority", None)
            valid = all(callable(item) for item in methods) and (
                priority is None or (isinstance(priority, (int, float)) and not isinstance(priority, bool) and priority > 0)
            )
        except Exception:  # noqa: BLE001
            valid = False
        if not valid:
            raise CredentialBackendError("credential backend is unavailable")
        return self._backend

    @staticmethod
    def _valid_account(account: str) -> None:
        if not isinstance(account, str) or not account:
            raise ValueError("account must be non-empty text")

    @staticmethod
    def _valid_source(source: str) -> None:
        if source not in {"keyring", "environment"}:
            raise ValueError("credential source must be keyring or environment")


def _environment_warning() -> CredentialWarning:
    return CredentialWarning(code="environment_plaintext", message="Environment credentials are plaintext and visible to processes with access to this process environment.")


def _safe_provider_value(value: object, secrets: tuple[str, ...], active: set[int], depth: int) -> object:
    """Copy only JSON-like provider results, rejecting unknown objects and secret-bearing keys/values."""
    if depth > _MAX_DEPTH:
        raise ValueError
    if value is None:
        return value
    if type(value) in {bool, int}:
        if _canonical_scalar(value) in secrets:
            raise ValueError
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError
        if _canonical_scalar(value) in secrets:
            raise ValueError
        return value
    if type(value) is str:
        if any(secret in value for secret in secrets):
            raise ValueError
        return _valid_utf8(value)
    if type(value) in {bytes, bytearray}:
        if any(secret.encode("utf-8") in bytes(value) for secret in secrets):
            raise ValueError
        return bytes(value)
    if type(value) not in {dict, list, tuple}:
        raise ValueError
    identity = id(value)
    if identity in active:
        raise ValueError
    active.add(identity)
    try:
        if type(value) is dict:
            result: dict[str, object] = {}
            for key, item in value.items():
                if type(key) is not str or any(secret in key for secret in secrets):
                    raise ValueError
                result[_valid_utf8(key)] = _safe_provider_value(item, secrets, active, depth + 1)
            return result
        items = [_safe_provider_value(item, secrets, active, depth + 1) for item in value]
        return tuple(items) if type(value) is tuple else items
    finally:
        active.discard(identity)


def _canonical_scalar(value: bool | float) -> str:
    return str(value).casefold()


@dataclass
class _Budget:
    work: int = _MAX_WORK
    items: int = _MAX_ITEMS
    bytes: int = _MAX_REDACTION_BYTES

    def node(self) -> bool:
        self.work -= 1
        return self.work >= 0

    def item(self) -> bool:
        self.items -= 1
        return self.items >= 0

    def text_limit(self, limit: int) -> int:
        return max(0, min(limit, self.bytes))

    def used_text(self, value: str) -> None:
        self.bytes -= len(value.encode("utf-8"))


def redact(value: object, secrets: set[str], sensitive_keys: set[str]) -> object:
    normalized_secrets = tuple(sorted((_valid_utf8(item) for item in secrets if isinstance(item, str) and item), key=len, reverse=True))
    keys = frozenset(_valid_utf8(item).casefold() for item in sensitive_keys if isinstance(item, str) and item) | _SENSITIVE_KEY_PARTS
    result = _redact(value, normalized_secrets, keys, set(), 0, _Budget())
    try:
        if len(_stable_json(result).encode("utf-8")) > _MAX_REDACTION_BYTES:
            return _TRUNCATED
    except Exception:  # noqa: BLE001
        return _TRUNCATED
    return result


def _redact(value: object, secrets: tuple[str, ...], keys: frozenset[str], active: set[int], depth: int, budget: _Budget) -> object:
    if depth > _MAX_DEPTH or not budget.node():
        return _TRUNCATED
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else _UNSUPPORTED
    if isinstance(value, str):
        return _redact_text(value, secrets, keys, budget)
    if isinstance(value, bytes | bytearray | memoryview):
        return _REDACTED_BYTES
    if isinstance(value, BaseException):
        return _REDACTED
    identity = id(value)
    if identity in active:
        return _CYCLE
    if isinstance(value, Mapping):
        active.add(identity)
        try:
            output: dict[str, object] = {}
            for key, item in value.items():
                if not budget.item():
                    _insert(output, _TRUNCATED, _TRUNCATED)
                    break
                clean_key = _unique_key(output, _clean_key(key, secrets, budget))
                output[clean_key] = _REDACTED if _is_sensitive_key(clean_key, keys) else _redact(item, secrets, keys, active, depth + 1, budget)
            return output
        except Exception:  # noqa: BLE001
            return _UNSUPPORTED
        finally:
            active.discard(identity)
    if isinstance(value, AbstractSet):
        try:
            if len(value) > max(0, budget.items):
                return [_TRUNCATED]
            items = [_redact(item, secrets, keys, active, depth + 1, budget) for item in value]
            return sorted(items, key=_stable_json)
        except Exception:  # noqa: BLE001
            return _UNSUPPORTED
    if isinstance(value, Iterable):
        active.add(identity)
        try:
            output = []
            iterator = iter(value)
            while budget.item():
                try:
                    item = next(iterator)
                except StopIteration:
                    return output
                output.append(_redact(item, secrets, keys, active, depth + 1, budget))
            return output + [_TRUNCATED]
        except Exception:  # noqa: BLE001
            return _UNSUPPORTED
        finally:
            active.discard(identity)
    return _UNSUPPORTED


def _insert(mapping: dict[str, object], key: str, value: object) -> None:
    mapping[_unique_key(mapping, key)] = value


def _unique_key(mapping: Mapping[str, object], key: str) -> str:
    if key not in mapping:
        return key
    index = 2
    while f"{key}#{index}" in mapping:
        index += 1
    return f"{key}#{index}"


def _clean_key(key: object, secrets: tuple[str, ...], budget: _Budget) -> str:
    return _redact_text(key, secrets, frozenset(), budget) if isinstance(key, str) else "[NON_STRING_KEY]"


def _redact_text(value: str, secrets: tuple[str, ...], keys: frozenset[str], budget: _Budget) -> str:
    clean = _valid_utf8(value)
    for secret in secrets:
        clean = clean.replace(secret, _REDACTED)
    clean = _BEARER.sub(r"\1" + _REDACTED, clean)
    try:
        parsed = urlsplit(clean)
        if parsed.scheme and parsed.netloc:
            decoded_path = unquote(parsed.path)
            for secret in secrets:
                decoded_path = decoded_path.replace(secret, _REDACTED)
            query = []
            for key, item in parse_qsl(parsed.query, keep_blank_values=True):
                for secret in secrets:
                    item = item.replace(secret, _REDACTED)
                query.append((key, _REDACTED if _is_sensitive_key(key, keys) else item))
            clean = urlunsplit((parsed.scheme, parsed.netloc, quote(decoded_path, safe="/%[]"), urlencode(query), parsed.fragment))
    except Exception:  # noqa: BLE001
        clean = _truncate_text(clean, budget.text_limit(_MAX_TEXT_BYTES))
        budget.used_text(clean)
        return clean or _TRUNCATED
    clean = _truncate_text(clean, budget.text_limit(_MAX_TEXT_BYTES))
    budget.used_text(clean)
    return clean or _TRUNCATED


def _is_sensitive_key(key: str, keys: frozenset[str]) -> bool:
    folded = key.casefold().replace("-", "_")
    return folded in keys or any(part in folded for part in keys)


def _valid_utf8(value: str) -> str:
    return value.encode("utf-8", errors="replace").decode("utf-8")


def _truncate_text(value: str, limit: int) -> str:
    if limit <= 0:
        return _TRUNCATED
    encoded = value.encode("utf-8")
    if len(encoded) <= limit:
        return value
    suffix = _TRUNCATED.encode("utf-8")
    if limit <= len(suffix):
        return suffix[:limit].decode("utf-8", errors="ignore") or _TRUNCATED
    return encoded[: limit - len(suffix)].decode("utf-8", errors="ignore") + _TRUNCATED


def _stable_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


class AuditLogger:
    def __init__(self, path: Path, *, secrets: set[str] | None = None) -> None:
        self._path = Path(path).absolute()
        self._secrets = set(secrets or ())

    def emit(self, event: AuditEvent) -> None:
        failed = False
        try:
            encoded = self._encode(event)
            self._append(encoded)
        except Exception:  # noqa: BLE001
            failed = True
        if failed:
            raise AuditWriteError("audit record could not be written")

    def _encode(self, event: AuditEvent) -> bytes:
        record = self._record(event)
        encoded = _stable_json(record).encode("utf-8")
        if len(encoded) > _MAX_RECORD_BYTES:
            record["metadata"] = {"truncated": _TRUNCATED}
            encoded = _stable_json(record).encode("utf-8")
        if len(encoded) > _MAX_RECORD_BYTES:
            raise ValueError("audit record exceeds bound")
        return encoded + b"\n"

    def _record(self, event: AuditEvent) -> dict[str, object]:
        metadata, duration, outcome = _approved_metadata(event.metadata, self._secrets)
        return {
            "task_id": _audit_scalar(event.task_id, self._secrets, 1_024),
            "iteration": _audit_scalar(event.iteration_id, self._secrets, 1_024),
            "component": _audit_scalar(event.component, self._secrets, 1_024),
            "event_type": _audit_scalar(event.event_type, self._secrets, 1_024),
            "duration": duration,
            "outcome": outcome,
            "metadata": metadata,
        }

    def _append(self, encoded: bytes) -> None:
        self._prepare_path()
        descriptor = _open_audit(self._path)
        try:
            with _identity_lock(self._path, descriptor):
                self._prepare_path()
                _recover_tail(descriptor)
                _write_all(descriptor, encoded)
                os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _prepare_path(self) -> None:
        _reject_links(self._path, include_final=True)
        self._path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        _reject_links(self._path, include_final=True)


def _approved_metadata(metadata: Mapping[str, object], secrets: set[str]) -> tuple[dict[str, object], float | int | None, str | None]:
    output: dict[str, object] = {}
    duration: float | int | None = None
    outcome: str | None = None
    for key, value in metadata.items():
        canonical = _APPROVED_ALIASES.get(key) if isinstance(key, str) else None
        if canonical is None:
            continue
        if canonical == "duration":
            if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value):
                duration = value
            continue
        if canonical == "outcome":
            if isinstance(value, str):
                outcome = _audit_scalar(value, secrets, 256)
            continue
        if isinstance(value, str):
            output[canonical] = _audit_scalar(value, secrets, 4_096)
    return dict(sorted(output.items())), duration, outcome


def _audit_scalar(value: object, secrets: set[str], limit: int) -> object:
    clean = redact(value, secrets, set())
    return _truncate_text(clean, limit) if isinstance(clean, str) else clean


def _is_link(path: Path) -> bool:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _reject_links(path: Path, *, include_final: bool) -> None:
    absolute = path.absolute()
    parts = absolute.parts
    current = Path(parts[0])
    stop = len(parts) if include_final else len(parts) - 1
    for part in parts[1:stop]:
        current /= part
        if _is_link(current):
            raise OSError("audit path contains a link")


def _open_audit(path: Path) -> int:
    _reject_links(path, include_final=True)
    flags = os.O_APPEND | os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if os.name == "nt":
        descriptor = os.open(path, flags, 0o600)
    else:
        parent_descriptor = _open_parent_no_follow(path.parent)
        try:
            descriptor = os.open(path.name, flags, 0o600, dir_fd=parent_descriptor)
        finally:
            os.close(parent_descriptor)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise OSError("audit target is not a regular file")
        try:
            os.fchmod(descriptor, 0o600)
        except (AttributeError, OSError):
            pass
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _open_parent_no_follow(parent: Path) -> int:
    """Traverse existing POSIX parents by descriptor; Windows keeps reparse-point validation."""
    if os.name == "nt":
        raise OSError("Windows parent traversal uses reparse-safe validation")
    absolute = parent.absolute()
    root = Path(absolute.anchor)
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in absolute.relative_to(root).parts:
            next_descriptor = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        os.fchmod(descriptor, 0o700)
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


@contextmanager
def _identity_lock(path: Path, descriptor: int) -> Iterator[None]:
    identity = os.fstat(descriptor)
    lock_root = _lock_root()
    lock_path = lock_root / f"{identity.st_dev}-{identity.st_ino}.lock"
    _reject_links(lock_path, include_final=True)
    handle = lock_path.open("a+b")
    try:
        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            handle.write(b"\0")
            handle.flush()
        handle.seek(0)
        _lock(handle)
        yield
    finally:
        try:
            _unlock(handle)
        finally:
            handle.close()


def _lock_root() -> Path:
    root = Path(tempfile.gettempdir()).absolute() / "pyquality-audit-locks"
    if _is_link(root):
        raise OSError("audit lock root is a link")
    root.mkdir(mode=0o700, exist_ok=True)
    if _is_link(root) or not root.is_dir():
        raise OSError("audit lock root is unsafe")
    try:
        os.chmod(root, 0o700)
    except OSError:
        pass
    return root


def _write_all(descriptor: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        written = os.write(descriptor, data[offset:])
        if written <= 0:
            raise OSError("short audit write")
        offset += written


def _recover_tail(descriptor: int) -> None:
    size = os.lseek(descriptor, 0, os.SEEK_END)
    if size == 0:
        return
    position = size
    tail = b""
    while position:
        take = min(4096, position)
        position -= take
        os.lseek(descriptor, position, os.SEEK_SET)
        chunk = os.read(descriptor, take)
        tail = chunk + tail
        index = tail.rfind(b"\n")
        if index >= 0:
            if position + len(tail) != size or not tail.endswith(b"\n"):
                os.ftruncate(descriptor, position + index + 1)
            return
    os.ftruncate(descriptor, 0)


if os.name == "nt":
    import msvcrt

    def _lock(handle: BinaryIO) -> None:
        msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)

    def _unlock(handle: BinaryIO) -> None:
        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)

else:
    import fcntl

    def _lock(handle: BinaryIO) -> None:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)

    def _unlock(handle: BinaryIO) -> None:
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
