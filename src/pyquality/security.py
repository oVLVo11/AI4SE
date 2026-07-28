"""Credential isolation, recursive redaction, and durable local audit output."""

from __future__ import annotations

import json
import math
import os
import re
import threading
from collections.abc import Callable, Mapping, Sequence
from collections.abc import Set as AbstractSet
from dataclasses import dataclass
from pathlib import Path
from typing import Literal
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from pydantic import Field

from .domain.models import AuditEvent, PublicModel

_REDACTED = "[REDACTED]"
_REDACTED_BYTES = "[REDACTED_BYTES]"
_UNSUPPORTED = "[UNSUPPORTED_OBJECT]"
_CYCLE = "[CYCLE]"
_TRUNCATED = "[TRUNCATED]"
_MAX_DEPTH = 16
_MAX_ITEMS = 100
_MAX_TEXT_BYTES = 4_096
_MAX_RECORD_BYTES = 16_384
_SENSITIVE_KEY_PARTS = frozenset(
    {"authorization", "api_key", "apikey", "token", "secret", "password", "credential"}
)
_BODY_KEY_PARTS = frozenset({"prompt", "response", "source", "body", "model_input", "model_output"})
_BEARER = re.compile(r"(?i)(bearer\s+)([^\s,;]+)")


class CredentialError(RuntimeError):
    """Base class for credential operations that deliberately hides backend details."""


class CredentialBackendError(CredentialError):
    """The selected keyring cannot safely perform the requested operation."""


class CredentialNotFoundError(CredentialError):
    """No credential is available from the explicitly selected source."""


class CredentialProviderError(CredentialError):
    """The provider callable failed after receiving an isolated credential."""


class AuditWriteError(RuntimeError):
    """An audit record could not be safely appended."""


class CredentialWarning(PublicModel):
    """A safe, serializable warning returned for environment credential use."""

    code: Literal["environment_plaintext"]
    message: str = Field(min_length=1, max_length=256)


class CredentialStatus(PublicModel):
    """Presence-only credential state; it intentionally has no value field."""

    present: bool
    source: Literal["keyring", "environment"]
    warning: CredentialWarning | None = None


@dataclass(frozen=True, repr=False)
class CredentialUse[T]:
    """Provider output plus any source warning, with a value-safe representation."""

    value: T
    warning: CredentialWarning | None = None

    def __repr__(self) -> str:
        return f"CredentialUse(warning={self.warning!r})"


class CredentialService:
    """A no-list/no-echo credential boundary over an injected keyring-compatible backend."""

    def __init__(self, backend: object, *, service_name: str) -> None:
        if not isinstance(service_name, str) or not service_name:
            raise ValueError("service_name must be non-empty text")
        self._backend = backend
        self._service_name = service_name

    def set(self, account: str, secret: str) -> None:
        """Create or replace a keyring secret without returning it."""
        self._validate_account_and_secret(account, secret)
        backend = self._usable_backend()
        try:
            backend.set_password(self._service_name, account, secret)
        except Exception:  # noqa: BLE001 - backend details can include the secret.
            raise CredentialBackendError("credential backend write failed") from None

    def status(self, account: str, *, source: Literal["keyring", "environment"] = "keyring") -> CredentialStatus:
        """Return only presence and source information for an explicitly selected source."""
        self._validate_account(account)
        if source == "environment":
            return CredentialStatus(
                present=bool(os.environ.get("PYQUALITY_API_KEY")),
                source="environment",
                warning=_environment_warning(),
            )
        self._validate_source(source)
        backend = self._usable_backend()
        try:
            present = backend.get_password(self._service_name, account) is not None
        except Exception:  # noqa: BLE001 - backend messages are not safe to expose.
            raise CredentialBackendError("credential backend status check failed") from None
        return CredentialStatus(present=present, source="keyring")

    def get[T](
        self,
        account: str,
        provider: Callable[[str], T],
        *,
        source: Literal["keyring", "environment"] = "keyring",
    ) -> CredentialUse[T]:
        """Pass a secret to the provider callable, never back to this method's caller."""
        self._validate_account(account)
        if not callable(provider):
            raise TypeError("provider must be callable")
        self._validate_source(source)
        warning: CredentialWarning | None = None
        if source == "environment":
            secret = os.environ.get("PYQUALITY_API_KEY")
            warning = _environment_warning()
        else:
            backend = self._usable_backend()
            try:
                secret = backend.get_password(self._service_name, account)
            except Exception:  # noqa: BLE001 - backend messages are not safe to expose.
                raise CredentialBackendError("credential backend read failed") from None
        if not isinstance(secret, str) or not secret:
            raise CredentialNotFoundError("credential is not available from the selected source")
        try:
            value = provider(secret)
        except Exception:  # noqa: BLE001 - providers can accidentally include credentials in errors.
            raise CredentialProviderError("credential provider operation failed") from None
        if _contains_secret(value, secret, set(), 0):
            raise CredentialProviderError("credential provider returned a credential")
        return CredentialUse(value=value, warning=warning)

    def clear(self, account: str) -> None:
        """Delete one named keyring credential without exposing stored data."""
        self._validate_account(account)
        backend = self._usable_backend()
        try:
            backend.delete_password(self._service_name, account)
        except Exception:  # noqa: BLE001 - backend messages are not safe to expose.
            raise CredentialBackendError("credential backend delete failed") from None

    def _usable_backend(self) -> object:
        backend = self._backend
        try:
            methods = (backend.get_password, backend.set_password, backend.delete_password)  # type: ignore[attr-defined]
            priority = getattr(backend, "priority", None)
            usable = all(callable(method) for method in methods) and (
                priority is None or (isinstance(priority, (int, float)) and not isinstance(priority, bool) and priority > 0)
            )
        except Exception:  # noqa: BLE001 - a hostile backend must not disclose its details.
            usable = False
        if not usable:
            raise CredentialBackendError("credential backend is unavailable")
        return backend

    @staticmethod
    def _validate_account(account: str) -> None:
        if not isinstance(account, str) or not account:
            raise ValueError("account must be non-empty text")

    @classmethod
    def _validate_account_and_secret(cls, account: str, secret: str) -> None:
        cls._validate_account(account)
        if not isinstance(secret, str) or not secret:
            raise ValueError("credential must be non-empty text")

    @staticmethod
    def _validate_source(source: str) -> None:
        if source not in {"keyring", "environment"}:
            raise ValueError("credential source must be keyring or environment")


def _environment_warning() -> CredentialWarning:
    return CredentialWarning(
        code="environment_plaintext",
        message="Environment credentials are plaintext and visible to processes with access to this process environment.",
    )


def _contains_secret(value: object, secret: str, active: set[int], depth: int) -> bool:
    """Inspect only built-in container data without invoking arbitrary object methods."""
    if depth > _MAX_DEPTH:
        return False
    if isinstance(value, str):
        return secret in value
    if isinstance(value, bytes | bytearray | memoryview):
        return secret.encode("utf-8") in bytes(value)
    if not isinstance(value, Mapping | Sequence | AbstractSet) or isinstance(value, str):
        return False
    identity = id(value)
    if identity in active:
        return False
    active.add(identity)
    try:
        values = value.values() if isinstance(value, Mapping) else value
        return any(_contains_secret(item, secret, active, depth + 1) for item in values)
    except Exception:  # noqa: BLE001 - do not let a provider-controlled object leak through errors.
        return True
    finally:
        active.discard(identity)


def redact(value: object, secrets: set[str], sensitive_keys: set[str]) -> object:
    """Return a bounded JSON-safe copy with secrets and unsafe values replaced."""
    normalized_secrets = tuple(
        sorted((secret for secret in secrets if isinstance(secret, str) and secret), key=len, reverse=True)
    )
    normalized_keys = frozenset(
        key.casefold() for key in sensitive_keys if isinstance(key, str) and key
    ) | _SENSITIVE_KEY_PARTS
    return _redact(value, normalized_secrets, normalized_keys, set(), 0)


def _redact(
    value: object,
    secrets: tuple[str, ...],
    sensitive_keys: frozenset[str],
    active: set[int],
    depth: int,
) -> object:
    if depth > _MAX_DEPTH:
        return _TRUNCATED
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else _UNSUPPORTED
    if isinstance(value, str):
        return _redact_text(value, secrets, sensitive_keys)
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
            for index, (key, item) in enumerate(value.items()):
                if index >= _MAX_ITEMS:
                    output["[TRUNCATED]"] = _TRUNCATED
                    break
                clean_key = _clean_key(key)
                output[clean_key] = (
                    _REDACTED
                    if _is_sensitive_key(clean_key, sensitive_keys)
                    else _redact(item, secrets, sensitive_keys, active, depth + 1)
                )
            return output
        except Exception:  # noqa: BLE001 - mapping implementations can be hostile.
            return _UNSUPPORTED
        finally:
            active.discard(identity)
    if isinstance(value, Sequence | AbstractSet):
        active.add(identity)
        try:
            items = list(value)
            output = [_redact(item, secrets, sensitive_keys, active, depth + 1) for item in items[:_MAX_ITEMS]]
            if len(items) > _MAX_ITEMS:
                output.append(_TRUNCATED)
            if isinstance(value, AbstractSet):
                output.sort(key=_stable_json)
            return output
        except Exception:  # noqa: BLE001 - never call arbitrary object representations.
            return _UNSUPPORTED
        finally:
            active.discard(identity)
    return _UNSUPPORTED


def _clean_key(key: object) -> str:
    return _truncate_text(key, _MAX_TEXT_BYTES) if isinstance(key, str) else "[NON_STRING_KEY]"


def _redact_text(value: str, secrets: tuple[str, ...], sensitive_keys: frozenset[str]) -> str:
    clean = value
    for secret in secrets:
        clean = clean.replace(secret, _REDACTED)
    clean = _BEARER.sub(r"\1" + _REDACTED, clean)
    try:
        parsed = urlsplit(clean)
        if parsed.scheme and parsed.netloc and parsed.query:
            query = parse_qsl(parsed.query, keep_blank_values=True)
            clean_query = [
                (key, _REDACTED if _is_sensitive_key(key, sensitive_keys) else item)
                for key, item in query
            ]
            clean = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(clean_query), parsed.fragment))
    except Exception:  # noqa: BLE001 - malformed text is preserved after direct secret replacement.
        return _truncate_text(clean, _MAX_TEXT_BYTES)
    return _truncate_text(clean, _MAX_TEXT_BYTES)


def _is_sensitive_key(key: str, sensitive_keys: frozenset[str]) -> bool:
    folded = key.casefold().replace("-", "_")
    return folded in sensitive_keys or any(part in folded for part in sensitive_keys)


def _truncate_text(value: str, limit: int) -> str:
    encoded = value.encode("utf-8", errors="replace")
    if len(encoded) <= limit:
        return value
    suffix = _TRUNCATED.encode("utf-8")
    return encoded[: limit - len(suffix)].decode("utf-8", errors="ignore") + _TRUNCATED


def _stable_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


_LOCK_GUARD = threading.Lock()
_PATH_LOCKS: dict[Path, threading.Lock] = {}


class AuditLogger:
    """Append-only local JSONL sink that redacts and bounds every persisted record."""

    def __init__(self, path: Path, *, secrets: set[str] | None = None) -> None:
        self._path = Path(path)
        self._secrets = set(secrets or ())
        with _LOCK_GUARD:
            self._lock = _PATH_LOCKS.setdefault(self._path.absolute(), threading.Lock())

    def emit(self, event: AuditEvent) -> None:
        """Redact, serialize, and append exactly one complete JSON object line."""
        try:
            record = self._record(event)
            encoded = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            if len(encoded.encode("utf-8")) > _MAX_RECORD_BYTES:
                record["metadata"] = {"truncated": _TRUNCATED}
                encoded = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            with self._lock:
                self._prepare_path()
                descriptor = os.open(self._path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
                try:
                    try:
                        os.chmod(self._path, 0o600)
                    except OSError:
                        pass
                    with os.fdopen(descriptor, "a", encoding="utf-8", newline="\n") as stream:
                        descriptor = -1
                        stream.write(encoded + "\n")
                        stream.flush()
                finally:
                    if descriptor != -1:
                        os.close(descriptor)
        except AuditWriteError:
            raise
        except Exception:  # noqa: BLE001 - events and OS errors can contain sensitive details.
            raise AuditWriteError("audit record could not be written") from None

    def _record(self, event: AuditEvent) -> dict[str, object]:
        metadata = _audit_metadata(event.metadata, self._secrets)
        duration = metadata.pop("duration", None)
        outcome = metadata.pop("outcome", None)
        return {
            "task_id": _bounded_audit_scalar(event.task_id, self._secrets),
            "iteration": _bounded_audit_scalar(event.iteration_id, self._secrets),
            "component": _bounded_audit_scalar(event.component, self._secrets),
            "event_type": _bounded_audit_scalar(event.event_type, self._secrets),
            "duration": duration,
            "outcome": outcome,
            "metadata": metadata,
        }

    def _prepare_path(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(self._path.parent, 0o700)
        except OSError:
            pass


def _audit_metadata(metadata: Mapping[str, object], secrets: set[str]) -> dict[str, object]:
    output: dict[str, object] = {}
    for key, value in metadata.items():
        clean_key = _clean_key(key)
        if _is_body_key(clean_key) or _is_sensitive_key(clean_key, _SENSITIVE_KEY_PARTS):
            continue
        output[clean_key] = _audit_value(value, secrets, set(), 0)
    return output


def _audit_value(value: object, secrets: set[str], active: set[int], depth: int) -> object:
    """Recursively discard body-bearing metadata while retaining approved structural context."""
    if depth > _MAX_DEPTH:
        return _TRUNCATED
    if value is None or isinstance(value, (str, bytes, bytearray, memoryview, bool, int, float, BaseException)):
        return redact(value, secrets, set())
    if isinstance(value, Mapping):
        identity = id(value)
        if identity in active:
            return _CYCLE
        active.add(identity)
        try:
            output: dict[str, object] = {}
            for index, (key, item) in enumerate(value.items()):
                if index >= _MAX_ITEMS:
                    output["[TRUNCATED]"] = _TRUNCATED
                    break
                clean_key = _clean_key(key)
                if _is_body_key(clean_key) or _is_sensitive_key(clean_key, _SENSITIVE_KEY_PARTS):
                    continue
                output[clean_key] = _audit_value(item, secrets, active, depth + 1)
            return output
        except Exception:  # noqa: BLE001 - metadata must never call arbitrary representations.
            return _UNSUPPORTED
        finally:
            active.discard(identity)
    if isinstance(value, Sequence | AbstractSet):
        identity = id(value)
        if identity in active:
            return _CYCLE
        active.add(identity)
        try:
            output = [_audit_value(item, secrets, active, depth + 1) for item in list(value)[:_MAX_ITEMS]]
            return output + ([_TRUNCATED] if len(value) > _MAX_ITEMS else [])
        except Exception:  # noqa: BLE001 - metadata must stay JSON-safe under hostile values.
            return _UNSUPPORTED
        finally:
            active.discard(identity)
    return redact(value, secrets, set())


def _is_body_key(key: str) -> bool:
    folded = key.casefold().replace("-", "_")
    return any(part in folded for part in _BODY_KEY_PARTS)


def _bounded_audit_scalar(value: object, secrets: set[str]) -> object:
    clean = redact(value, secrets, set())
    return _truncate_text(clean, 1_024) if isinstance(clean, str) else clean
