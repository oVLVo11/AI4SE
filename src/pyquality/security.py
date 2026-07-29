"""Credential isolation, bounded redaction, and hardened local JSONL audit output."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import struct
import time
from collections.abc import Callable, Iterable, Iterator, Mapping
from collections.abc import Set as AbstractSet
from contextlib import contextmanager
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from threading import RLock
from typing import Literal, NamedTuple
from urllib.parse import quote, urlsplit, urlunsplit

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
_MAX_TAIL_RECOVERY_BYTES = 64 * 1_024
_MAX_INDEX_REBUILD_BYTES = 256 * 1_024
_MAX_RECEIPT_BYTES = 512
_MAX_AUDIT_RECEIPTS = 16_384
_CHECKPOINT_MAGIC = b"PQAIDX1\0"
_CHECKPOINT_SLOT = struct.Struct(">8sQQQ32s")
_CHECKPOINT_V2_MAGIC = b"PQAIDX2\0"
_CHECKPOINT_V2_REGION_OFFSET = _CHECKPOINT_SLOT.size * 2
_CHECKPOINT_V2_SLOT = struct.Struct(">8sQQQQ32s32s24x")
_R4_MIGRATION_MAGIC = b"PQAMIG2\0"
_R4_MIGRATION_TARGET_FORMAT = 2
_R4_SOURCE_LOCATOR_BYTES = 4_096
_R4_MIGRATION_SLOT = struct.Struct(">8sQ64sQQQQBH4096s32s109x")
_RECEIPT_MAGIC = b"PQARCP2\0"
_RECEIPT_SLOT_OFFSET = 256
_RECEIPT_SLOT = struct.Struct(">8sQQI32s32s32s")
_DEFAULT_STATE_HOME = (
    Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    if os.name == "nt"
    else Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
)
_DEFAULT_AUDIT_INDEX_BASE = Path(
    os.environ.get(
        "PYQUALITY_AUDIT_INDEX_ROOT",
        _DEFAULT_STATE_HOME / "pyquality" / "audit-index",
    )
)
_SENSITIVE_KEY_PARTS = frozenset(
    {"authorization", "api_key", "apikey", "token", "secret", "password", "credential"}
)
_BEARER = re.compile(r"(?i)(bearer\s+)([^\s,;]+)")
_SCALAR_NUMBER = re.compile(
    r"[+-]?(?:(?:\d+(?:\.\d*)?)|(?:\.\d+))(?:[eE][+-]?\d+)?\Z",
    re.ASCII,
)
_MAX_SCALAR_TEXT = 4_096
_MAX_SCALAR_DIGITS = 4_096
_MAX_SCALAR_ADJUSTED_EXPONENT = 4_096
_MAX_PROVIDER_INTEGER_BITS = 512
_MAX_PROVIDER_TEXT_BYTES = 4_096
_MAX_DURATION_SECONDS = 86_400
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


class AuditRecoveryRequired(AuditWriteError):
    """The bounded online protocol requires explicit rotation or offline repair."""


class _AuditCheckpoint(NamedTuple):
    generation: int
    indexed_size: int
    committed_receipt_count: int
    pending_event_id: str | None
    pending_start_offset: int | None


class _R4MigrationState(NamedTuple):
    generation: int
    source_identity: str
    target_format: int
    next_cursor: int
    receipt_count: int
    indexed_size: int
    completed: bool
    source_root: str


class _R4Receipt(NamedTuple):
    path: Path
    event_id: str
    offset: int
    length: int
    digest: str


class CredentialWarning(PublicModel):
    code: Literal["environment_plaintext"]
    message: str = Field(min_length=1, max_length=256)


class CredentialStatus(PublicModel):
    present: bool
    source: Literal["keyring", "environment"]
    warning: CredentialWarning | None = None


class KnownSecretRegistry(AbstractSet[str]):
    """Process-local secrets known to every live redaction boundary."""

    def __init__(self, secrets: Iterable[str] = ()) -> None:
        self._lock = RLock()
        self._values: set[str] = set()
        for secret in secrets:
            self.register(secret)

    def register(self, secret: str) -> None:
        if not isinstance(secret, str) or not secret:
            raise ValueError("known secret must be non-empty text")
        with self._lock:
            self._values.add(secret)

    def snapshot(self) -> set[str]:
        with self._lock:
            return set(self._values)

    def __contains__(self, value: object) -> bool:
        with self._lock:
            return value in self._values

    def __iter__(self) -> Iterator[str]:
        return iter(tuple(sorted(self.snapshot())))

    def __len__(self) -> int:
        with self._lock:
            return len(self._values)

    def __repr__(self) -> str:
        return f"KnownSecretRegistry(count={len(self)})"


@dataclass(frozen=True, repr=False)
class CredentialUse[T]:
    value: T
    warning: CredentialWarning | None = None

    def __repr__(self) -> str:
        return f"CredentialUse(warning={self.warning!r})"


class CredentialService:
    def __init__(
        self,
        backend: object,
        *,
        service_name: str,
        secret_registry: KnownSecretRegistry | None = None,
    ) -> None:
        if not isinstance(service_name, str) or not service_name:
            raise ValueError("service_name must be non-empty text")
        self._backend = backend
        self._service_name = service_name
        self._secret_registry = secret_registry

    def set(self, account: str, secret: str) -> None:
        self._valid_account(account)
        if not isinstance(secret, str) or not secret:
            raise ValueError("credential must be non-empty text")
        if _SCALAR_NUMBER.fullmatch(secret) is not None and _canonical_decimal_text(secret) is None:
            raise ValueError("numeric credential is outside the supported domain")
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
        if self._secret_registry is not None:
            self._secret_registry.register(secret)
        provider_failed = False
        value: object = None
        try:
            value = provider(secret)
        except Exception:  # noqa: BLE001
            provider_failed = True
        if provider_failed:
            raise CredentialProviderError("credential provider operation failed")
        try:
            safe_value = _safe_provider_value(value, frozenset({_canonical_text(secret)}), (secret,), set(), 0)
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


type _CanonicalDecimal = tuple[Literal["number"], int, tuple[int, ...], int]
type _CanonicalScalar = (
    _CanonicalDecimal | tuple[Literal["bool"], bool] | tuple[Literal["text"], str]
)


def _safe_provider_value(value: object, secret_forms: frozenset[_CanonicalScalar], secrets: tuple[str, ...], active: set[int], depth: int) -> object:
    """Copy only JSON-like provider results, rejecting unknown objects and secret-bearing keys/values."""
    if depth > _MAX_DEPTH:
        raise ValueError
    if value is None:
        return value
    if type(value) in {bool, int}:
        if _canonical_scalar(value) in secret_forms:
            raise ValueError
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError
        if _canonical_scalar(value) in secret_forms:
            raise ValueError
        return value
    if type(value) is str:
        text = _bounded_provider_text(value)
        if any(secret in text for secret in secrets) or _canonical_text(text) in secret_forms:
            raise ValueError
        return text
    if type(value) in {bytes, bytearray}:
        encoded = bytes(value)
        if len(encoded) > _MAX_PROVIDER_TEXT_BYTES:
            raise ValueError
        if any(secret.encode("utf-8") in encoded for secret in secrets):
            raise ValueError
        return encoded
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
                if type(key) is not str:
                    raise ValueError
                clean_key = _bounded_provider_text(key)
                if (
                    any(secret in clean_key for secret in secrets)
                    or _canonical_text(clean_key) in secret_forms
                ):
                    raise ValueError
                result[clean_key] = _safe_provider_value(
                    item, secret_forms, secrets, active, depth + 1
                )
            return result
        items = [_safe_provider_value(item, secret_forms, secrets, active, depth + 1) for item in value]
        return tuple(items) if type(value) is tuple else items
    finally:
        active.discard(identity)


def _canonical_scalar(value: object) -> _CanonicalScalar:
    if type(value) is bool:
        return ("bool", value)
    if type(value) is int and value.bit_length() > _MAX_PROVIDER_INTEGER_BITS:
        raise ValueError
    if type(value) is float and not math.isfinite(value):
        raise ValueError
    canonical = _canonical_decimal_text(str(value))
    if canonical is None:
        raise ValueError
    return canonical


def _canonical_text(value: str) -> _CanonicalScalar:
    text = _valid_utf8(value)
    lowered = text.casefold()
    if lowered in {"true", "false"}:
        return ("bool", lowered == "true")
    canonical = _canonical_decimal_text(text)
    if canonical is not None:
        return canonical
    return ("text", text)


def _canonical_decimal_text(text: str) -> _CanonicalDecimal | None:
    if len(text.encode("utf-8", errors="replace")) > _MAX_SCALAR_TEXT:
        return None
    if _SCALAR_NUMBER.fullmatch(text) is None:
        return None
    if sum(character.isdigit() for character in text) > _MAX_SCALAR_DIGITS:
        return None
    try:
        decimal = Decimal(text)
    except InvalidOperation:
        return None
    if not decimal.is_finite():
        return None
    parts = decimal.as_tuple()
    digits = list(parts.digits)
    if not any(digits):
        return ("number", 0, (0,), 0)
    while digits and digits[0] == 0:
        digits.pop(0)
    exponent = parts.exponent
    while digits and digits[-1] == 0:
        digits.pop()
        exponent += 1
    adjusted = exponent + len(digits) - 1
    if (
        abs(adjusted) > _MAX_SCALAR_ADJUSTED_EXPONENT
        or _plain_decimal_size(parts.sign, digits, exponent) > _MAX_SCALAR_TEXT
    ):
        return None
    return ("number", parts.sign, tuple(digits), exponent)


def _plain_decimal_size(sign: int, digits: list[int], exponent: int) -> int:
    if exponent >= 0:
        return sign + len(digits) + exponent
    point = len(digits) + exponent
    if point > 0:
        return sign + len(digits) + 1
    return sign + 2 - exponent


def _bounded_provider_text(value: str) -> str:
    encoded = value.encode("utf-8", errors="replace")
    if len(encoded) > _MAX_PROVIDER_TEXT_BYTES:
        raise ValueError
    return encoded.decode("utf-8")


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
        if _json_size(result) > _MAX_REDACTION_BYTES:
            candidate = [result[0], _TRUNCATED] if isinstance(result, list) and result else _TRUNCATED
            return candidate if _json_size(candidate) <= _MAX_REDACTION_BYTES else _TRUNCATED
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
                if budget.bytes <= 0:
                    return output + [_TRUNCATED]
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
    try:
        parsed = urlsplit(clean)
        if parsed.scheme and parsed.netloc:
            clean = urlunsplit(
                (
                    _redact_plain_text(parsed.scheme, secrets),
                    _redact_url_component(parsed.netloc, secrets),
                    _redact_url_component(parsed.path, secrets),
                    _redact_url_query(parsed.query, secrets, keys),
                    _redact_url_component(parsed.fragment, secrets),
                )
            )
        else:
            clean = _redact_plain_text(clean, secrets)
    except Exception:  # noqa: BLE001
        clean = _redact_plain_text(clean, secrets)
        clean = _truncate_text(clean, budget.text_limit(_MAX_TEXT_BYTES))
        budget.used_text(clean)
        return clean or _TRUNCATED
    clean = _truncate_text(clean, budget.text_limit(_MAX_TEXT_BYTES))
    budget.used_text(clean)
    return clean or _TRUNCATED


@dataclass(frozen=True)
class _UrlUnit:
    decoded: str
    raw: str


def _redact_plain_text(value: str, secrets: tuple[str, ...]) -> str:
    clean = value
    for secret in secrets:
        clean = clean.replace(secret, _REDACTED)
    return _BEARER.sub(r"\1" + _REDACTED, clean)


def _redact_url_query(raw_query: str, secrets: tuple[str, ...], keys: frozenset[str]) -> str:
    fields: list[str] = []
    for field in raw_query.split("&"):
        raw_key, separator, raw_value = field.partition("=")
        decoded_key = _decoded_url_component(raw_key, plus_as_space=True)
        clean_key = _redact_url_component(raw_key, secrets, plus_as_space=True)
        if not separator:
            fields.append(clean_key)
            continue
        clean_value = (
            _encoded_url_marker()
            if _is_sensitive_key(decoded_key, keys)
            else _redact_url_component(raw_value, secrets, plus_as_space=True)
        )
        fields.append(f"{clean_key}={clean_value}")
    return "&".join(fields)


def _redact_url_component(
    raw: str, secrets: tuple[str, ...], *, plus_as_space: bool = False
) -> str:
    units = _url_units(raw, plus_as_space=plus_as_space)
    decoded = "".join(unit.decoded for unit in units)
    spans = _secret_spans(decoded, secrets)
    spans.extend(match.span(2) for match in _BEARER.finditer(decoded))
    spans = _merged_spans(spans)
    if not spans:
        return raw
    output: list[str] = []
    position = 0
    redacting = False
    for unit in units:
        end = position + len(unit.decoded)
        overlaps = any(start < end and stop > position for start, stop in spans)
        if overlaps:
            if not redacting:
                output.append(_encoded_url_marker())
            redacting = True
        else:
            output.append(unit.raw)
            redacting = False
        position = end
    return "".join(output)


def _decoded_url_component(raw: str, *, plus_as_space: bool) -> str:
    return "".join(unit.decoded for unit in _url_units(raw, plus_as_space=plus_as_space))


def _url_units(raw: str, *, plus_as_space: bool) -> list[_UrlUnit]:
    units: list[_UrlUnit] = []
    index = 0
    while index < len(raw):
        if raw[index] == "%" and index + 2 < len(raw) and _is_hex_pair(raw[index + 1:index + 3]):
            start = index
            encoded = bytearray()
            while index + 2 < len(raw) and raw[index] == "%" and _is_hex_pair(raw[index + 1:index + 3]):
                encoded.append(int(raw[index + 1:index + 3], 16))
                index += 3
            units.append(_UrlUnit(encoded.decode("utf-8", errors="replace"), raw[start:index]))
            continue
        character = raw[index]
        units.append(_UrlUnit(" " if plus_as_space and character == "+" else character, character))
        index += 1
    return units


def _is_hex_pair(value: str) -> bool:
    return len(value) == 2 and all(character in "0123456789abcdefABCDEF" for character in value)


def _secret_spans(value: str, secrets: tuple[str, ...]) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    for secret in secrets:
        start = 0
        while (found := value.find(secret, start)) >= 0:
            spans.append((found, found + len(secret)))
            start = found + len(secret)
    return spans


def _merged_spans(spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[tuple[int, int]] = []
    for start, stop in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(stop, merged[-1][1]))
        else:
            merged.append((start, stop))
    return merged


def _encoded_url_marker() -> str:
    return quote(_REDACTED, safe="")


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


def _json_size(value: object) -> int:
    return len(_stable_json(value).encode("utf-8"))


class AuditLogger:
    def __init__(
        self,
        path: Path,
        *,
        secrets: set[str] | None = None,
        secret_registry: KnownSecretRegistry | None = None,
        index_root: Path | None = None,
    ) -> None:
        failed = False
        audit_path: Path | None = None
        audit_index_base: Path | None = None
        try:
            audit_path = Path(path)
            audit_index_base = (
                _DEFAULT_AUDIT_INDEX_BASE
                if index_root is None
                else Path(index_root)
            )
        except OSError:
            failed = True
        if failed or audit_path is None or audit_index_base is None:
            raise AuditWriteError("audit path is invalid")
        self._path = audit_path
        self._index_base = audit_index_base
        self._secrets = (
            secret_registry if secret_registry is not None else KnownSecretRegistry()
        )
        for secret in secrets or ():
            self._secrets.register(secret)

    def emit(self, event: AuditEvent) -> None:
        failed = False
        recovery_required = False
        try:
            encoded = self._encode(event)
            self._append(encoded, event.event_id)
        except AuditRecoveryRequired:
            recovery_required = True
        except Exception:  # noqa: BLE001
            failed = True
        if recovery_required:
            raise AuditRecoveryRequired(
                "audit stream requires explicit rotation or offline index rebuild"
            )
        if failed:
            raise AuditWriteError("audit record could not be written")

    def prepare(self, event: AuditEvent) -> AuditEvent:
        """Return the exact bounded, allowlisted event safe for durable queuing."""
        return sanitize_audit_event(event, self._secrets.snapshot())

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
        secrets = self._secrets.snapshot()
        metadata, duration, outcome = _approved_metadata(event.metadata, secrets)
        return {
            "event_id": event.event_id,
            "task_id": _audit_scalar(event.task_id, secrets, 1_024),
            "iteration": _audit_scalar(event.iteration_id, secrets, 1_024),
            "component": _audit_scalar(event.component, secrets, 1_024),
            "event_type": _audit_scalar(event.event_type, secrets, 1_024),
            "duration": duration,
            "outcome": outcome,
            "metadata": metadata,
        }

    def _append(self, encoded: bytes, event_id: str) -> None:
        descriptor = _open_audit(self._path)
        try:
            with _audit_file_lock(descriptor):
                _recover_tail(descriptor)
                index_root = _audit_index_root(
                    self._path,
                    descriptor,
                    self._index_base,
                )
                _ensure_secure_audit_index_root(self._index_base, index_root)
                _migrate_released_r4_audit_index(
                    self._path,
                    descriptor,
                    index_root,
                )
                checkpoint_path = index_root / "checkpoint"
                checkpoint_descriptor = _open_audit(checkpoint_path, append=False)
                try:
                    checkpoint = _reconcile_audit_index(
                        descriptor,
                        checkpoint_descriptor,
                        index_root,
                    )
                    receipt_path = _audit_receipt_path(index_root, event_id)
                    receipt_descriptor = _open_existing_audit(
                        receipt_path,
                        append=False,
                    )
                    try:
                        if receipt_descriptor is not None:
                            receipt = _load_audit_receipt(receipt_descriptor)
                            if receipt is not None:
                                _verify_audit_receipt(
                                    descriptor,
                                    receipt,
                                    event_id,
                                )
                                return
                        if (
                            checkpoint.committed_receipt_count
                            >= _MAX_AUDIT_RECEIPTS
                        ):
                            raise AuditRecoveryRequired
                        offset = os.lseek(descriptor, 0, os.SEEK_END)
                        checkpoint = _store_audit_checkpoint(
                            checkpoint_descriptor,
                            checkpoint,
                            offset,
                            checkpoint.committed_receipt_count,
                            pending_event_id=event_id,
                            pending_start_offset=offset,
                        )
                        if receipt_descriptor is None:
                            receipt_descriptor = _open_audit(
                                receipt_path,
                                append=False,
                            )
                        receipt = _load_audit_receipt(
                            receipt_descriptor,
                            allow_torn=True,
                        )
                        if receipt is not None:
                            raise AuditRecoveryRequired
                        _write_audit_record(descriptor, encoded)
                        _commit_audit_receipt(
                            receipt_descriptor,
                            event_id,
                            offset,
                            encoded,
                        )
                        _store_audit_checkpoint(
                            checkpoint_descriptor,
                            checkpoint,
                            offset + len(encoded),
                            checkpoint.committed_receipt_count + 1,
                        )
                    finally:
                        if receipt_descriptor is not None:
                            os.close(receipt_descriptor)
                finally:
                    os.close(checkpoint_descriptor)
        finally:
            os.close(descriptor)


def _approved_metadata(metadata: Mapping[str, object], secrets: set[str]) -> tuple[dict[str, object], float | int | None, str | None]:
    output: dict[str, object] = {}
    duration: float | int | None = None
    outcome: str | None = None
    for key, value in metadata.items():
        canonical = _APPROVED_ALIASES.get(key) if isinstance(key, str) else None
        if canonical is None:
            continue
        if canonical == "duration":
            if (type(value) is int and 0 <= value <= _MAX_DURATION_SECONDS) or (
                type(value) is float and math.isfinite(value) and 0 <= value <= _MAX_DURATION_SECONDS
            ):
                duration = value
            continue
        if canonical == "outcome":
            if isinstance(value, str):
                outcome = _audit_scalar(value, secrets, 256)
            continue
        if isinstance(value, str):
            output[canonical] = _audit_scalar(value, secrets, 4_096)
    return dict(sorted(output.items())), duration, outcome


def sanitize_audit_metadata(
    metadata: Mapping[str, object], secrets: set[str]
) -> tuple[dict[str, object], float | int | None, str | None]:
    """Apply the centralized audit allowlist and recursive scalar redaction."""
    return _approved_metadata(metadata, secrets)


def sanitize_audit_event(event: AuditEvent, secrets: set[str]) -> AuditEvent:
    """Apply the audit envelope boundary before either queuing or delivery."""
    metadata, duration, outcome = _approved_metadata(event.metadata, secrets)
    if duration is not None:
        metadata["duration"] = duration
    if outcome is not None:
        metadata["outcome"] = outcome
    return event.model_copy(
        update={
            "task_id": _audit_scalar(event.task_id, secrets, 1_024),
            "iteration_id": _audit_scalar(event.iteration_id, secrets, 1_024),
            "component": _audit_scalar(event.component, secrets, 1_024),
            "event_type": _audit_scalar(event.event_type, secrets, 1_024),
            "metadata": metadata,
        }
    )


def _audit_scalar(value: object, secrets: set[str], limit: int) -> object:
    clean = redact(value, secrets, set())
    if isinstance(clean, str) and _is_absolute_path_text(clean):
        clean = _REDACTED
    return _truncate_text(clean, limit) if isinstance(clean, str) else clean


def _is_absolute_path_text(value: str) -> bool:
    return (
        value.startswith(("/", "\\"))
        or re.match(r"^[A-Za-z]:[\\/]", value) is not None
    )


def _open_audit(
    path: Path,
    *,
    append: bool = True,
    create: bool = True,
) -> int:
    absolute = path.absolute()
    if os.name == "nt":
        return _open_windows_audit(absolute, append=append, create=create)
    return _open_posix_audit(absolute, append=append, create=create)


def _open_existing_audit(path: Path, *, append: bool = True) -> int | None:
    try:
        return _open_audit(path, append=append, create=False)
    except OSError as error:
        if error.errno not in {2, 3}:
            raise
    return None


def _remove_open_audit(path: Path, descriptor: int) -> None:
    if os.name == "nt":
        _remove_windows_open_audit(descriptor)
        return
    _remove_posix_open_audit(path.absolute(), descriptor)


def _open_posix_audit(
    path: Path,
    *,
    append: bool = True,
    create: bool = True,
) -> int:
    no_follow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if no_follow is None or directory is None:
        raise OSError("descriptor-relative no-follow opens are unavailable")
    root = Path(path.anchor)
    parts = path.relative_to(root).parts
    if not parts or parts[-1] in {"", ".", ".."}:
        raise OSError("audit path has no file component")
    directory_flags = os.O_RDONLY | directory | no_follow | getattr(os, "O_CLOEXEC", 0)
    parent_descriptor = os.open(root, directory_flags)
    try:
        for index, part in enumerate(parts[:-1]):
            if part in {"", ".", ".."} or "/" in part or "\\" in part:
                raise OSError("audit path contains an invalid component")
            if create:
                next_descriptor, created = _open_or_create_posix_directory(
                    parent_descriptor, part, directory_flags
                )
            else:
                next_descriptor = os.open(part, directory_flags, dir_fd=parent_descriptor)
                created = False
            os.close(parent_descriptor)
            parent_descriptor = next_descriptor
            if created:
                os.fchmod(parent_descriptor, 0o700)

        flags = os.O_RDWR | no_follow | getattr(os, "O_CLOEXEC", 0)
        if create:
            flags |= os.O_CREAT
        if append:
            flags |= os.O_APPEND
        descriptor = os.open(parts[-1], flags, 0o600, dir_fd=parent_descriptor)
    finally:
        os.close(parent_descriptor)
    try:
        information = os.fstat(descriptor)
        if not stat.S_ISREG(information.st_mode):
            raise OSError("audit target is not a regular file")
        if information.st_uid != os.geteuid():
            raise OSError("audit target has an unsafe owner")
        os.fchmod(descriptor, 0o600)
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _open_or_create_posix_directory(
    parent_descriptor: int, name: str, flags: int
) -> tuple[int, bool]:
    try:
        return os.open(name, flags, dir_fd=parent_descriptor), False
    except FileNotFoundError:
        try:
            os.mkdir(name, 0o700, dir_fd=parent_descriptor)
            created = True
        except FileExistsError:
            created = False
        return os.open(name, flags, dir_fd=parent_descriptor), created


@contextmanager
def _audit_file_lock(descriptor: int) -> Iterator[None]:
    _lock_descriptor(descriptor)
    try:
        yield
    finally:
        _unlock_descriptor(descriptor)


def _write_all(descriptor: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        written = os.write(descriptor, data[offset:])
        if written <= 0:
            raise OSError("short audit write")
        offset += written


def _write_audit_record(descriptor: int, encoded: bytes) -> None:
    """Append and durably publish JSONL before committing its receipt."""
    _write_all(descriptor, encoded)
    os.fsync(descriptor)


def _recover_tail(descriptor: int) -> None:
    size = os.lseek(descriptor, 0, os.SEEK_END)
    if size == 0:
        return
    os.lseek(descriptor, size - 1, os.SEEK_SET)
    if os.read(descriptor, 1) == b"\n":
        return
    position = size
    remaining = min(size, _MAX_TAIL_RECOVERY_BYTES)
    while position and remaining:
        take = min(4096, position, remaining)
        position -= take
        remaining -= take
        os.lseek(descriptor, position, os.SEEK_SET)
        chunk = os.read(descriptor, take)
        index = chunk.rfind(b"\n")
        if index >= 0:
            os.ftruncate(descriptor, position + index + 1)
            os.fsync(descriptor)
            return
    if position == 0:
        os.ftruncate(descriptor, 0)
        os.fsync(descriptor)
        return
    raise AuditRecoveryRequired


def _audit_index_root(
    path: Path,
    descriptor: int,
    index_base: Path | None = None,
) -> Path:
    del path
    identity = _audit_stream_identity(descriptor)
    base = _DEFAULT_AUDIT_INDEX_BASE if index_base is None else index_base
    return base.absolute() / identity


def _ensure_secure_audit_index_root(base: Path, index_root: Path) -> None:
    """Create and validate the shared base and identity leaf without following links."""
    absolute_base = base.absolute()
    absolute_index = index_root.absolute()
    try:
        absolute_index.relative_to(absolute_base)
    except ValueError as error:
        raise OSError("audit index identity escaped its configured root") from error
    _ensure_audit_index_namespace(absolute_base)
    _ensure_secure_audit_directory(absolute_index)


def _audit_receipt_path(index_root: Path, event_id: str) -> Path:
    return index_root / "receipts" / event_id[:2] / event_id


def _read_at(descriptor: int, offset: int, length: int) -> bytes:
    os.lseek(descriptor, offset, os.SEEK_SET)
    output = bytearray()
    while len(output) < length:
        chunk = os.read(descriptor, length - len(output))
        if not chunk:
            break
        output.extend(chunk)
    return bytes(output)


def _checkpoint_digest(
    generation: int, indexed_size: int, receipt_count: int
) -> bytes:
    return hashlib.sha256(
        struct.pack(">QQQ", generation, indexed_size, receipt_count)
    ).digest()


def _checkpoint_v2_digest(
    generation: int,
    indexed_size: int,
    committed_receipt_count: int,
    pending_start_offset: int,
    pending_event_id: bytes,
) -> bytes:
    return hashlib.sha256(
        struct.pack(
            ">QQQQ32s",
            generation,
            indexed_size,
            committed_receipt_count,
            pending_start_offset,
            pending_event_id,
        )
    ).digest()


def _load_audit_checkpoint(
    descriptor: int,
    *,
    audit_size: int | None = None,
) -> _AuditCheckpoint | None:
    candidates: list[_AuditCheckpoint] = []
    future_format = False
    for slot in range(2):
        encoded = _read_at(
            descriptor,
            slot * _CHECKPOINT_SLOT.size,
            _CHECKPOINT_SLOT.size,
        )
        if len(encoded) != _CHECKPOINT_SLOT.size:
            continue
        magic, generation, indexed_size, receipt_count, digest = (
            _CHECKPOINT_SLOT.unpack(encoded)
        )
        if magic.startswith(b"PQAIDX") and magic not in {
            _CHECKPOINT_MAGIC,
            _CHECKPOINT_V2_MAGIC,
        }:
            future_format = True
        if (
            magic == _CHECKPOINT_MAGIC
            and receipt_count <= _MAX_AUDIT_RECEIPTS
            and digest
            == _checkpoint_digest(generation, indexed_size, receipt_count)
        ):
            candidates.append(
                _AuditCheckpoint(
                    generation,
                    indexed_size,
                    receipt_count,
                    None,
                    None,
                )
            )
    for slot in range(2):
        encoded = _read_at(
            descriptor,
            _CHECKPOINT_V2_REGION_OFFSET + slot * _CHECKPOINT_V2_SLOT.size,
            _CHECKPOINT_V2_SLOT.size,
        )
        if len(encoded) != _CHECKPOINT_V2_SLOT.size:
            continue
        (
            magic,
            generation,
            indexed_size,
            committed_receipt_count,
            stored_pending_start,
            pending_event_id_bytes,
            digest,
        ) = _CHECKPOINT_V2_SLOT.unpack(encoded)
        if magic.startswith(b"PQAIDX") and magic not in {
            _CHECKPOINT_MAGIC,
            _CHECKPOINT_V2_MAGIC,
        }:
            future_format = True
        pending_event_id = (
            None
            if pending_event_id_bytes == bytes(32)
            else pending_event_id_bytes.hex()
        )
        pending_start_offset = (
            None if pending_event_id is None else stored_pending_start
        )
        if (
            magic == _CHECKPOINT_V2_MAGIC
            and generation > 0
            and committed_receipt_count
            + (1 if pending_event_id is not None else 0)
            <= _MAX_AUDIT_RECEIPTS
            and (pending_event_id is not None or stored_pending_start == 0)
            and (
                pending_start_offset is None
                or pending_start_offset == indexed_size
            )
            and digest
            == _checkpoint_v2_digest(
                generation,
                indexed_size,
                committed_receipt_count,
                stored_pending_start,
                pending_event_id_bytes,
            )
        ):
            candidates.append(
                _AuditCheckpoint(
                    generation,
                    indexed_size,
                    committed_receipt_count,
                    pending_event_id,
                    pending_start_offset,
                )
            )
    if future_format:
        raise AuditRecoveryRequired
    if not candidates:
        if os.lseek(descriptor, 0, os.SEEK_END):
            raise AuditRecoveryRequired
        return None
    checkpoint = max(candidates, key=lambda item: item.generation)
    if (
        audit_size is not None
        and (
            checkpoint.indexed_size > audit_size
            or (
                checkpoint.pending_start_offset is not None
                and checkpoint.pending_start_offset > audit_size
            )
        )
    ):
        raise AuditRecoveryRequired
    return checkpoint


def _store_audit_checkpoint(
    descriptor: int,
    previous: _AuditCheckpoint | None,
    indexed_size: int,
    committed_receipt_count: int,
    *,
    pending_event_id: str | None = None,
    pending_start_offset: int | None = None,
) -> _AuditCheckpoint:
    if (
        indexed_size < 0
        or committed_receipt_count < 0
        or committed_receipt_count
        + (1 if pending_event_id is not None else 0)
        > _MAX_AUDIT_RECEIPTS
        or (
            pending_event_id is not None
            and (
                re.fullmatch(r"[0-9a-f]{64}", pending_event_id) is None
                or pending_start_offset != indexed_size
            )
        )
        or (pending_event_id is None and pending_start_offset is not None)
    ):
        raise AuditRecoveryRequired
    generation = 1 if previous is None else previous.generation + 1
    payload = _encode_audit_checkpoint_v2(
        generation,
        indexed_size,
        committed_receipt_count,
        pending_event_id=pending_event_id,
        pending_start_offset=pending_start_offset,
    )
    os.lseek(
        descriptor,
        _CHECKPOINT_V2_REGION_OFFSET
        + (generation % 2) * _CHECKPOINT_V2_SLOT.size,
        os.SEEK_SET,
    )
    _write_all(descriptor, payload)
    os.fsync(descriptor)
    return _AuditCheckpoint(
        generation,
        indexed_size,
        committed_receipt_count,
        pending_event_id,
        pending_start_offset,
    )


def _encode_audit_checkpoint_v2(
    generation: int,
    indexed_size: int,
    committed_receipt_count: int,
    *,
    pending_event_id: str | None = None,
    pending_start_offset: int | None = None,
) -> bytes:
    pending_event_id_bytes = (
        bytes(32) if pending_event_id is None else bytes.fromhex(pending_event_id)
    )
    stored_pending_start = 0 if pending_start_offset is None else pending_start_offset
    payload = _CHECKPOINT_V2_SLOT.pack(
        _CHECKPOINT_V2_MAGIC,
        generation,
        indexed_size,
        committed_receipt_count,
        stored_pending_start,
        pending_event_id_bytes,
        _checkpoint_v2_digest(
            generation,
            indexed_size,
            committed_receipt_count,
            stored_pending_start,
            pending_event_id_bytes,
        ),
    )
    return payload


def _receipt_checksum(
    generation: int,
    offset: int,
    length: int,
    event_id: bytes,
    digest: bytes,
) -> bytes:
    return hashlib.sha256(
        struct.pack(">QQI", generation, offset, length) + event_id + digest
    ).digest()


def _valid_legacy_receipt(encoded: bytes) -> dict[str, object] | None:
    line, separator, tail = encoded.partition(b"\n")
    if not separator or any(tail):
        return None
    try:
        receipt = json.loads(line)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if (
        not isinstance(receipt, dict)
        or receipt.get("version") != 1
        or re.fullmatch(r"[0-9a-f]{64}", receipt.get("event_id", "")) is None
        or type(receipt.get("offset")) is not int
        or receipt["offset"] < 0
        or type(receipt.get("length")) is not int
        or not 1 <= receipt["length"] <= _MAX_RECORD_BYTES + 1
        or re.fullmatch(r"[0-9a-f]{64}", receipt.get("digest", "")) is None
    ):
        return None
    return receipt


def _load_audit_receipt(
    descriptor: int,
    *,
    allow_torn: bool = False,
) -> dict[str, object] | None:
    size = os.lseek(descriptor, 0, os.SEEK_END)
    if size == 0:
        return None
    if size > _MAX_RECEIPT_BYTES:
        raise OSError("audit receipt exceeds bound")
    candidates: list[dict[str, object]] = []
    for slot in range(2):
        encoded = _read_at(
            descriptor,
            _RECEIPT_SLOT_OFFSET + slot * _RECEIPT_SLOT.size,
            _RECEIPT_SLOT.size,
        )
        if len(encoded) != _RECEIPT_SLOT.size:
            continue
        magic, generation, offset, length, event_id, digest, checksum = (
            _RECEIPT_SLOT.unpack(encoded)
        )
        if (
            magic == _RECEIPT_MAGIC
            and generation > 0
            and 1 <= length <= _MAX_RECORD_BYTES + 1
            and checksum
            == _receipt_checksum(generation, offset, length, event_id, digest)
        ):
            candidates.append(
                {
                    "version": 2,
                    "generation": generation,
                    "event_id": event_id.hex(),
                    "offset": offset,
                    "length": length,
                    "digest": digest.hex(),
                }
            )
    if candidates:
        return max(candidates, key=lambda receipt: int(receipt["generation"]))
    legacy_region = _read_at(
        descriptor,
        0,
        min(size, _RECEIPT_SLOT_OFFSET),
    )
    legacy = _valid_legacy_receipt(legacy_region)
    if legacy is not None:
        return legacy
    if allow_torn:
        return None
    raise OSError("audit receipt is malformed")


def _commit_audit_receipt(
    descriptor: int,
    event_id: str,
    offset: int,
    encoded: bytes,
) -> None:
    """Durably index only a JSONL record that was already fsynced."""
    previous = _load_audit_receipt(descriptor, allow_torn=True)
    previous_generation = (
        previous.get("generation", 0) if previous is not None else 0
    )
    assert isinstance(previous_generation, int)
    generation = previous_generation + 1
    event_id_bytes = bytes.fromhex(event_id)
    digest = hashlib.sha256(encoded).digest()
    payload = _RECEIPT_SLOT.pack(
        _RECEIPT_MAGIC,
        generation,
        offset,
        len(encoded),
        event_id_bytes,
        digest,
        _receipt_checksum(
            generation,
            offset,
            len(encoded),
            event_id_bytes,
            digest,
        ),
    )
    slot = (generation - 1) % 2
    os.lseek(
        descriptor,
        _RECEIPT_SLOT_OFFSET + slot * _RECEIPT_SLOT.size,
        os.SEEK_SET,
    )
    _write_all(descriptor, payload)
    os.fsync(descriptor)


def _verify_audit_receipt(
    audit_descriptor: int,
    receipt: Mapping[str, object],
    event_id: str,
) -> None:
    if receipt["event_id"] != event_id:
        raise OSError("audit receipt identity mismatch")
    offset = receipt["offset"]
    length = receipt["length"]
    assert isinstance(offset, int) and isinstance(length, int)
    encoded = _read_at(audit_descriptor, offset, length)
    if (
        len(encoded) != length
        or hashlib.sha256(encoded).hexdigest() != receipt["digest"]
    ):
        raise OSError("audit receipt does not match visible log")


def _event_id_from_record(encoded: bytes) -> str | None:
    if len(encoded) > _MAX_RECORD_BYTES + 1 or not encoded.endswith(b"\n"):
        return None
    try:
        payload = json.loads(encoded)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    event_id = payload.get("event_id") if isinstance(payload, dict) else None
    return event_id if isinstance(event_id, str) and re.fullmatch(r"[0-9a-f]{64}", event_id) else None


def _remove_pending_audit_receipt(index_root: Path, event_id: str) -> None:
    receipt_path = _audit_receipt_path(index_root, event_id)
    receipt_descriptor = _open_existing_audit(receipt_path, append=False)
    if receipt_descriptor is None:
        return
    try:
        if os.lseek(receipt_descriptor, 0, os.SEEK_END) > _MAX_RECEIPT_BYTES:
            raise AuditRecoveryRequired
        _remove_open_audit(receipt_path, receipt_descriptor)
    finally:
        os.close(receipt_descriptor)


def _recover_pending_audit_reservation(
    audit_descriptor: int,
    checkpoint_descriptor: int,
    index_root: Path,
    checkpoint: _AuditCheckpoint,
    audit_size: int,
) -> _AuditCheckpoint:
    event_id = checkpoint.pending_event_id
    start_offset = checkpoint.pending_start_offset
    if event_id is None or start_offset is None:
        return checkpoint
    remaining = audit_size - start_offset
    if remaining < 0:
        raise AuditRecoveryRequired
    if remaining == 0:
        _remove_pending_audit_receipt(index_root, event_id)
        return _store_audit_checkpoint(
            checkpoint_descriptor,
            checkpoint,
            start_offset,
            checkpoint.committed_receipt_count,
        )
    probe = _read_at(
        audit_descriptor,
        start_offset,
        min(remaining, _MAX_RECORD_BYTES + 2),
    )
    newline = probe.find(b"\n")
    if newline < 0:
        if remaining <= min(_MAX_RECORD_BYTES + 1, _MAX_TAIL_RECOVERY_BYTES):
            os.ftruncate(audit_descriptor, start_offset)
            os.fsync(audit_descriptor)
            _remove_pending_audit_receipt(index_root, event_id)
            return _store_audit_checkpoint(
                checkpoint_descriptor,
                checkpoint,
                start_offset,
                checkpoint.committed_receipt_count,
            )
        raise AuditRecoveryRequired
    record_length = newline + 1
    if record_length > _MAX_RECORD_BYTES + 1:
        raise AuditRecoveryRequired
    encoded = probe[:record_length]
    if _event_id_from_record(encoded) != event_id:
        raise AuditRecoveryRequired
    receipt_path = _audit_receipt_path(index_root, event_id)
    receipt_descriptor = _open_existing_audit(receipt_path, append=False)
    if receipt_descriptor is None:
        receipt_descriptor = _open_audit(receipt_path, append=False)
    try:
        receipt = _load_audit_receipt(receipt_descriptor, allow_torn=True)
        if receipt is None:
            _commit_audit_receipt(
                receipt_descriptor,
                event_id,
                start_offset,
                encoded,
            )
        else:
            _verify_audit_receipt(audit_descriptor, receipt, event_id)
            if receipt["offset"] != start_offset:
                raise AuditRecoveryRequired
    finally:
        os.close(receipt_descriptor)
    return _store_audit_checkpoint(
        checkpoint_descriptor,
        checkpoint,
        start_offset + record_length,
        checkpoint.committed_receipt_count + 1,
    )


def _reconcile_audit_index(
    audit_descriptor: int,
    checkpoint_descriptor: int,
    index_root: Path,
) -> _AuditCheckpoint:
    """Index a complete bounded suffix or fail without guessing about older IDs."""
    audit_size = os.lseek(audit_descriptor, 0, os.SEEK_END)
    checkpoint = _load_audit_checkpoint(
        checkpoint_descriptor,
        audit_size=audit_size,
    )
    if checkpoint is not None and checkpoint.pending_event_id is not None:
        checkpoint = _recover_pending_audit_reservation(
            audit_descriptor,
            checkpoint_descriptor,
            index_root,
            checkpoint,
            audit_size,
        )
        audit_size = os.lseek(audit_descriptor, 0, os.SEEK_END)
    indexed_size = 0 if checkpoint is None else checkpoint.indexed_size
    receipt_count = (
        0 if checkpoint is None else checkpoint.committed_receipt_count
    )
    if indexed_size > audit_size:
        raise AuditRecoveryRequired
    unindexed = audit_size - indexed_size
    if unindexed > _MAX_INDEX_REBUILD_BYTES:
        raise AuditRecoveryRequired
    suffix = _read_at(audit_descriptor, indexed_size, unindexed)
    if len(suffix) != unindexed or (suffix and not suffix.endswith(b"\n")):
        raise OSError("audit index suffix is incomplete")
    offset = indexed_size
    for encoded in suffix.splitlines(keepends=True):
        event_id = _event_id_from_record(encoded)
        if event_id is not None:
            if receipt_count >= _MAX_AUDIT_RECEIPTS:
                raise AuditRecoveryRequired
            checkpoint = _store_audit_checkpoint(
                checkpoint_descriptor,
                checkpoint,
                offset,
                receipt_count,
                pending_event_id=event_id,
                pending_start_offset=offset,
            )
            receipt_path = _audit_receipt_path(index_root, event_id)
            receipt_descriptor = _open_existing_audit(
                receipt_path,
                append=False,
            )
            if receipt_descriptor is None:
                receipt_descriptor = _open_audit(receipt_path, append=False)
            try:
                existing = _load_audit_receipt(
                    receipt_descriptor,
                    allow_torn=True,
                )
                if existing is not None:
                    _verify_audit_receipt(audit_descriptor, existing, event_id)
                    if existing["offset"] != offset:
                        raise OSError("audit log already contains a duplicate event id")
                else:
                    _commit_audit_receipt(
                        receipt_descriptor,
                        event_id,
                        offset,
                        encoded,
                    )
            finally:
                os.close(receipt_descriptor)
            receipt_count += 1
            checkpoint = _store_audit_checkpoint(
                checkpoint_descriptor,
                checkpoint,
                offset + len(encoded),
                receipt_count,
            )
        offset += len(encoded)
    if checkpoint is None or checkpoint.indexed_size != audit_size:
        checkpoint = _store_audit_checkpoint(
            checkpoint_descriptor,
            checkpoint,
            audit_size,
            receipt_count,
        )
    assert checkpoint is not None
    return checkpoint


def _audit_migration_fault(stage: str) -> None:
    """Test seam for migration durability boundaries."""
    del stage


def _r4_migration_digest(
    generation: int,
    source_identity: bytes,
    target_format: int,
    next_cursor: int,
    receipt_count: int,
    indexed_size: int,
    completed: bool,
    locator_length: int,
    source_locator: bytes,
) -> bytes:
    return hashlib.sha256(
        struct.pack(
            ">Q64sQQQQBH4096s",
            generation,
            source_identity,
            target_format,
            next_cursor,
            receipt_count,
            indexed_size,
            completed,
            locator_length,
            source_locator,
        )
    ).digest()


def _encode_r4_migration_state(
    generation: int,
    *,
    source_identity: str,
    next_cursor: int,
    receipt_count: int,
    indexed_size: int,
    completed: bool,
    source_root: Path,
) -> bytes:
    try:
        identity = source_identity.encode("ascii")
        locator = str(source_root.absolute()).encode("utf-8")
    except UnicodeEncodeError as error:
        raise AuditRecoveryRequired from error
    if (
        re.fullmatch(r"[0-9a-f]+-[0-9a-f]+", source_identity) is None
        or not 1 <= len(identity) <= 64
        or not 1 <= len(locator) <= _R4_SOURCE_LOCATOR_BYTES
        or next_cursor > receipt_count
        or receipt_count > _MAX_AUDIT_RECEIPTS
        or indexed_size < 0
        or (completed and next_cursor != receipt_count)
    ):
        raise AuditRecoveryRequired
    encoded_identity = identity.ljust(64, b"\0")
    encoded_locator = locator.ljust(_R4_SOURCE_LOCATOR_BYTES, b"\0")
    return _R4_MIGRATION_SLOT.pack(
        _R4_MIGRATION_MAGIC,
        generation,
        encoded_identity,
        _R4_MIGRATION_TARGET_FORMAT,
        next_cursor,
        receipt_count,
        indexed_size,
        completed,
        len(locator),
        encoded_locator,
        _r4_migration_digest(
            generation,
            encoded_identity,
            _R4_MIGRATION_TARGET_FORMAT,
            next_cursor,
            receipt_count,
            indexed_size,
            completed,
            len(locator),
            encoded_locator,
        ),
    )


def _load_r4_migration_state(
    descriptor: int,
    *,
    source_identity: str,
    audit_size: int,
) -> _R4MigrationState:
    size = os.lseek(descriptor, 0, os.SEEK_END)
    if size == 0 or size > _R4_MIGRATION_SLOT.size * 2:
        raise AuditRecoveryRequired
    candidates: list[_R4MigrationState] = []
    future_format = False
    for slot in range(2):
        encoded = _read_at(
            descriptor,
            slot * _R4_MIGRATION_SLOT.size,
            _R4_MIGRATION_SLOT.size,
        )
        if len(encoded) != _R4_MIGRATION_SLOT.size:
            continue
        (
            magic,
            generation,
            encoded_identity,
            target_format,
            next_cursor,
            receipt_count,
            indexed_size,
            completed,
            locator_length,
            encoded_locator,
            digest,
        ) = _R4_MIGRATION_SLOT.unpack(encoded)
        if magic.startswith(b"PQAMIG") and magic != _R4_MIGRATION_MAGIC:
            future_format = True
        identity_bytes = encoded_identity.rstrip(b"\0")
        try:
            decoded_identity = identity_bytes.decode("ascii")
            source_root = encoded_locator[:locator_length].decode("utf-8")
        except (UnicodeDecodeError, ValueError):
            continue
        locator_padding = encoded_locator[locator_length:]
        source_path = Path(source_root)
        if (
            magic == _R4_MIGRATION_MAGIC
            and generation > 0
            and encoded_identity == identity_bytes.ljust(64, b"\0")
            and decoded_identity == source_identity
            and re.fullmatch(r"[0-9a-f]+-[0-9a-f]+", decoded_identity)
            is not None
            and target_format == _R4_MIGRATION_TARGET_FORMAT
            and next_cursor <= receipt_count <= _MAX_AUDIT_RECEIPTS
            and indexed_size <= audit_size
            and completed in {0, 1}
            and (not completed or next_cursor == receipt_count)
            and 1 <= locator_length <= _R4_SOURCE_LOCATOR_BYTES
            and not any(locator_padding)
            and source_path.is_absolute()
            and digest
            == _r4_migration_digest(
                generation,
                encoded_identity,
                target_format,
                next_cursor,
                receipt_count,
                indexed_size,
                bool(completed),
                locator_length,
                encoded_locator,
            )
        ):
            _validate_r4_audit_index_identity(source_path, decoded_identity)
            candidates.append(
                _R4MigrationState(
                    generation,
                    decoded_identity,
                    target_format,
                    next_cursor,
                    receipt_count,
                    indexed_size,
                    bool(completed),
                    source_root,
                )
            )
    if future_format or not candidates:
        raise AuditRecoveryRequired
    return max(candidates, key=lambda state: state.generation)


def _store_r4_migration_state(
    descriptor: int,
    previous: _R4MigrationState | None,
    *,
    source_identity: str,
    next_cursor: int,
    receipt_count: int,
    indexed_size: int,
    completed: bool,
    source_root: Path,
) -> _R4MigrationState:
    generation = 1 if previous is None else previous.generation + 1
    payload = _encode_r4_migration_state(
        generation,
        source_identity=source_identity,
        next_cursor=next_cursor,
        receipt_count=receipt_count,
        indexed_size=indexed_size,
        completed=completed,
        source_root=source_root,
    )
    os.lseek(
        descriptor,
        ((generation - 1) % 2) * _R4_MIGRATION_SLOT.size,
        os.SEEK_SET,
    )
    _write_all(descriptor, payload)
    os.fsync(descriptor)
    return _R4MigrationState(
        generation,
        source_identity,
        _R4_MIGRATION_TARGET_FORMAT,
        next_cursor,
        receipt_count,
        indexed_size,
        completed,
        str(source_root.absolute()),
    )


def _validate_r4_audit_index_identity(
    candidate_root: Path,
    expected_identity: str,
) -> None:
    prefix = ".pyquality-audit-index-"
    encoded_identity = candidate_root.name[len(prefix) :] if candidate_root.name.startswith(prefix) else ""
    if (
        re.fullmatch(r"[0-9a-f]+-[0-9a-f]+", expected_identity) is None
        or encoded_identity != expected_identity
    ):
        raise AuditRecoveryRequired


def _r4_candidate_exists(candidate_root: Path) -> bool:
    try:
        os.lstat(candidate_root)
    except FileNotFoundError:
        return False
    except OSError:
        raise AuditRecoveryRequired from None
    return True


def _validate_secure_r4_directory(path: Path) -> None:
    try:
        _validate_existing_r4_audit_directory(path.absolute())
    except OSError:
        raise AuditRecoveryRequired from None


def _open_secure_r4_file(path: Path) -> int:
    try:
        if os.name == "nt":
            return _open_audit(path, append=False, create=False)
        return _open_posix_r4_audit(path.absolute())
    except OSError:
        raise AuditRecoveryRequired from None


def _bounded_r4_directory_entries(
    path: Path,
    *,
    limit: int,
) -> list[tuple[str, bool, bool]]:
    entries: list[tuple[str, bool, bool]] = []
    try:
        with os.scandir(path) as iterator:
            for entry in iterator:
                if len(entries) >= limit:
                    raise AuditRecoveryRequired
                entries.append(
                    (
                        entry.name,
                        entry.is_dir(follow_symlinks=False),
                        entry.is_file(follow_symlinks=False),
                    )
                )
    except AuditRecoveryRequired:
        raise
    except OSError:
        raise AuditRecoveryRequired from None
    return entries


def _enumerate_r4_receipts(
    source_root: Path,
    expected_count: int,
) -> tuple[_R4Receipt, ...]:
    receipts_root = source_root / "receipts"
    if expected_count == 0 and not _r4_candidate_exists(receipts_root):
        return ()
    _validate_secure_r4_directory(receipts_root)
    shard_entries = _bounded_r4_directory_entries(receipts_root, limit=257)
    receipt_paths: list[Path] = []
    for shard, is_directory, is_file in sorted(shard_entries):
        if (
            not is_directory
            or is_file
            or re.fullmatch(r"[0-9a-f]{2}", shard) is None
        ):
            raise AuditRecoveryRequired
        shard_root = receipts_root / shard
        _validate_secure_r4_directory(shard_root)
        remaining_limit = _MAX_AUDIT_RECEIPTS - len(receipt_paths) + 1
        file_entries = _bounded_r4_directory_entries(
            shard_root,
            limit=remaining_limit,
        )
        for name, child_is_directory, child_is_file in sorted(file_entries):
            if (
                child_is_directory
                or not child_is_file
                or re.fullmatch(r"[0-9a-f]{64}", name) is None
                or not name.startswith(shard)
            ):
                raise AuditRecoveryRequired
            receipt_paths.append(shard_root / name)
            if len(receipt_paths) > _MAX_AUDIT_RECEIPTS:
                raise AuditRecoveryRequired
    if len(receipt_paths) != expected_count:
        raise AuditRecoveryRequired
    return tuple(
        _load_r4_receipt_metadata(path)
        for path in sorted(receipt_paths, key=lambda item: (item.parent.name, item.name))
    )


def _load_r4_receipt_metadata(path: Path) -> _R4Receipt:
    descriptor = _open_secure_r4_file(path)
    try:
        try:
            receipt = _load_audit_receipt(descriptor)
        except OSError:
            raise AuditRecoveryRequired from None
    finally:
        os.close(descriptor)
    if receipt is None or receipt.get("version") != 1:
        raise AuditRecoveryRequired
    event_id = receipt.get("event_id")
    offset = receipt.get("offset")
    length = receipt.get("length")
    digest = receipt.get("digest")
    if (
        event_id != path.name
        or not isinstance(event_id, str)
        or type(offset) is not int
        or type(length) is not int
        or not isinstance(digest, str)
    ):
        raise AuditRecoveryRequired
    return _R4Receipt(path, event_id, offset, length, digest)


def _read_verified_r4_record(
    audit_descriptor: int,
    receipt: _R4Receipt,
    *,
    indexed_size: int,
) -> bytes:
    if receipt.offset + receipt.length > indexed_size:
        raise AuditRecoveryRequired
    encoded = _read_at(audit_descriptor, receipt.offset, receipt.length)
    if (
        len(encoded) != receipt.length
        or hashlib.sha256(encoded).hexdigest() != receipt.digest
        or _event_id_from_record(encoded) != receipt.event_id
    ):
        raise AuditRecoveryRequired
    return encoded


def _load_released_r4_index(
    source_root: Path,
    audit_descriptor: int,
    audit_size: int,
) -> tuple[_AuditCheckpoint, tuple[_R4Receipt, ...]]:
    _validate_secure_r4_directory(source_root)
    checkpoint_descriptor = _open_secure_r4_file(source_root / "checkpoint")
    try:
        if not 0 < os.lseek(checkpoint_descriptor, 0, os.SEEK_END) <= _CHECKPOINT_SLOT.size * 2:
            raise AuditRecoveryRequired
        try:
            checkpoint = _load_audit_checkpoint(
                checkpoint_descriptor,
                audit_size=audit_size,
            )
        except OSError:
            raise AuditRecoveryRequired from None
    finally:
        os.close(checkpoint_descriptor)
    if checkpoint is None or checkpoint.pending_event_id is not None:
        raise AuditRecoveryRequired
    receipts = _enumerate_r4_receipts(
        source_root,
        checkpoint.committed_receipt_count,
    )
    for receipt in receipts:
        _read_verified_r4_record(
            audit_descriptor,
            receipt,
            indexed_size=checkpoint.indexed_size,
        )
    return checkpoint, receipts


def _open_existing_migration_target(path: Path) -> int | None:
    try:
        return _open_existing_audit(path, append=False)
    except OSError:
        raise AuditRecoveryRequired from None


def _load_existing_target_checkpoint(
    index_root: Path,
    audit_size: int,
) -> tuple[_AuditCheckpoint | None, bool]:
    descriptor = _open_existing_migration_target(index_root / "checkpoint")
    if descriptor is None:
        return None, False
    try:
        try:
            checkpoint = _load_audit_checkpoint(
                descriptor,
                audit_size=audit_size,
            )
        except OSError:
            raise AuditRecoveryRequired from None
        is_v2 = checkpoint is not None and _audit_checkpoint_is_v2(
            descriptor,
            checkpoint,
        )
        return checkpoint, is_v2
    finally:
        os.close(descriptor)


def _audit_checkpoint_is_v2(
    descriptor: int,
    expected: _AuditCheckpoint,
) -> bool:
    pending_event_id = expected.pending_event_id
    pending_bytes = (
        bytes(32) if pending_event_id is None else bytes.fromhex(pending_event_id)
    )
    pending_start = (
        0 if expected.pending_start_offset is None else expected.pending_start_offset
    )
    for slot in range(2):
        encoded = _read_at(
            descriptor,
            _CHECKPOINT_V2_REGION_OFFSET + slot * _CHECKPOINT_V2_SLOT.size,
            _CHECKPOINT_V2_SLOT.size,
        )
        if len(encoded) != _CHECKPOINT_V2_SLOT.size:
            continue
        (
            magic,
            generation,
            indexed_size,
            receipt_count,
            stored_pending_start,
            stored_pending_event_id,
            digest,
        ) = _CHECKPOINT_V2_SLOT.unpack(encoded)
        if (
            magic == _CHECKPOINT_V2_MAGIC
            and generation == expected.generation
            and indexed_size == expected.indexed_size
            and receipt_count == expected.committed_receipt_count
            and stored_pending_start == pending_start
            and stored_pending_event_id == pending_bytes
            and digest
            == _checkpoint_v2_digest(
                generation,
                indexed_size,
                receipt_count,
                stored_pending_start,
                stored_pending_event_id,
            )
        ):
            return True
    return False


def _assert_target_uncommitted(index_root: Path, audit_size: int) -> None:
    checkpoint, _ = _load_existing_target_checkpoint(index_root, audit_size)
    if checkpoint is not None and (
        checkpoint.indexed_size
        or checkpoint.committed_receipt_count
        or checkpoint.pending_event_id is not None
    ):
        raise AuditRecoveryRequired


def _assert_target_receipts_absent(receipts: tuple[_R4Receipt, ...], index_root: Path) -> None:
    for receipt in receipts:
        descriptor = _open_existing_migration_target(
            _audit_receipt_path(index_root, receipt.event_id)
        )
        if descriptor is not None:
            os.close(descriptor)
            raise AuditRecoveryRequired


def _assert_target_receipt_namespace_empty(index_root: Path) -> None:
    receipts_root = index_root / "receipts"
    if not _r4_candidate_exists(receipts_root):
        return
    try:
        _validate_existing_secure_audit_directory(receipts_root.absolute())
        with os.scandir(receipts_root) as entries:
            if next(entries, None) is not None:
                raise AuditRecoveryRequired
    except AuditRecoveryRequired:
        raise
    except OSError:
        raise AuditRecoveryRequired from None


def _exact_torn_prefix(descriptor: int, offset: int, payload: bytes) -> bool:
    size = os.lseek(descriptor, 0, os.SEEK_END)
    return bool(
        offset < size < offset + len(payload)
        and _read_at(descriptor, 0, offset) == bytes(offset)
        and _read_at(descriptor, offset, size - offset) == payload[: size - offset]
    )


def _verify_migrated_target_receipts(
    audit_descriptor: int,
    receipts: tuple[_R4Receipt, ...],
    index_root: Path,
) -> None:
    for source in receipts:
        descriptor = _open_existing_migration_target(
            _audit_receipt_path(index_root, source.event_id)
        )
        if descriptor is None:
            raise AuditRecoveryRequired
        try:
            receipt = _load_audit_receipt(descriptor)
            if (
                receipt is None
                or receipt.get("version") != 2
                or receipt.get("offset") != source.offset
                or receipt.get("length") != source.length
                or receipt.get("digest") != source.digest
            ):
                raise AuditRecoveryRequired
            _verify_audit_receipt(audit_descriptor, receipt, source.event_id)
        except OSError:
            raise AuditRecoveryRequired from None
        finally:
            os.close(descriptor)


def _target_checkpoint_matches_migration(
    checkpoint: _AuditCheckpoint | None,
    is_v2: bool,
    state: _R4MigrationState,
) -> bool:
    return bool(
        checkpoint is not None
        and is_v2
        and checkpoint.indexed_size == state.indexed_size
        and checkpoint.committed_receipt_count == state.receipt_count
        and checkpoint.pending_event_id is None
    )


def _verify_target_migration_checkpoint(
    index_root: Path,
    state: _R4MigrationState,
    audit_size: int,
) -> None:
    checkpoint, is_v2 = _load_existing_target_checkpoint(index_root, audit_size)
    if not (
        checkpoint is not None
        and is_v2
        and checkpoint.indexed_size >= state.indexed_size
        and checkpoint.committed_receipt_count >= state.receipt_count
    ):
        raise AuditRecoveryRequired


def _copy_r4_receipt(
    audit_descriptor: int,
    receipt: _R4Receipt,
    *,
    indexed_size: int,
    index_root: Path,
) -> None:
    current = _load_r4_receipt_metadata(receipt.path)
    if current != receipt:
        raise AuditRecoveryRequired
    encoded = _read_verified_r4_record(
        audit_descriptor,
        current,
        indexed_size=indexed_size,
    )
    target_path = _audit_receipt_path(index_root, receipt.event_id)
    target_descriptor = _open_existing_migration_target(target_path)
    if target_descriptor is None:
        target_descriptor = _open_audit(target_path, append=False)
    try:
        try:
            existing = _load_audit_receipt(
                target_descriptor,
                allow_torn=True,
            )
        except OSError:
            raise AuditRecoveryRequired from None
        if existing is None:
            _commit_audit_receipt(
                target_descriptor,
                receipt.event_id,
                receipt.offset,
                encoded,
            )
        elif (
            existing.get("version") != 2
            or existing.get("offset") != receipt.offset
            or existing.get("length") != receipt.length
            or existing.get("digest") != receipt.digest
        ):
            raise AuditRecoveryRequired
        else:
            try:
                _verify_audit_receipt(
                    audit_descriptor,
                    existing,
                    receipt.event_id,
                )
            except OSError:
                raise AuditRecoveryRequired from None
    finally:
        os.close(target_descriptor)
    _sync_audit_directory_chain(index_root, target_path.parent)


def _publish_r4_migration_checkpoint(
    index_root: Path,
    state: _R4MigrationState,
    audit_size: int,
    audit_descriptor: int,
    receipts: tuple[_R4Receipt, ...],
) -> None:
    checkpoint_path = index_root / "checkpoint"
    descriptor = _open_existing_migration_target(checkpoint_path)
    if descriptor is None:
        descriptor = _open_audit(checkpoint_path, append=False)
    try:
        torn = False
        try:
            checkpoint = _load_audit_checkpoint(
                descriptor,
                audit_size=audit_size,
            )
        except AuditRecoveryRequired:
            expected = _encode_audit_checkpoint_v2(
                1, state.indexed_size, state.receipt_count
            )
            offset = _CHECKPOINT_V2_REGION_OFFSET + _CHECKPOINT_V2_SLOT.size
            if not _exact_torn_prefix(descriptor, offset, expected):
                raise
            _verify_migrated_target_receipts(audit_descriptor, receipts, index_root)
            torn = True
            checkpoint = None
        except OSError:
            raise AuditRecoveryRequired from None
        if torn:
            _remove_open_audit(checkpoint_path, descriptor)
            os.close(descriptor)
            descriptor = _open_audit(checkpoint_path, append=False)
        is_v2 = checkpoint is not None and _audit_checkpoint_is_v2(
            descriptor,
            checkpoint,
        )
        if not _target_checkpoint_matches_migration(
            checkpoint,
            is_v2,
            state,
        ):
            if checkpoint is not None and (
                checkpoint.indexed_size
                or checkpoint.committed_receipt_count
                or checkpoint.pending_event_id is not None
            ):
                raise AuditRecoveryRequired
            _store_audit_checkpoint(
                descriptor,
                checkpoint,
                state.indexed_size,
                state.receipt_count,
            )
    finally:
        os.close(descriptor)
    _sync_audit_directory_chain(index_root, index_root)


def _sync_audit_directory_chain(index_root: Path, leaf: Path) -> None:
    if os.name == "nt":
        return
    absolute_root = index_root.absolute()
    absolute_leaf = leaf.absolute()
    try:
        absolute_leaf.relative_to(absolute_root)
    except ValueError as error:
        raise OSError("audit durability path escaped its identity root") from error
    current = absolute_leaf
    while True:
        _sync_posix_audit_directory(current)
        if current == absolute_root:
            return
        current = current.parent


def _prepare_r4_migration(
    marker_descriptor: int | None,
    state: _R4MigrationState | None,
    source_checkpoint: _AuditCheckpoint,
    receipts: tuple[_R4Receipt, ...],
    *,
    source_identity: str,
    source_root: Path,
    index_root: Path,
    marker_path: Path,
    audit_size: int,
) -> tuple[int, _R4MigrationState]:
    if state is not None:
        if (
            state.receipt_count
            != source_checkpoint.committed_receipt_count
            or state.indexed_size != source_checkpoint.indexed_size
            or Path(state.source_root) != source_root.absolute()
            or marker_descriptor is None
        ):
            raise AuditRecoveryRequired
        _sync_audit_directory_chain(index_root, index_root)
        return marker_descriptor, state
    _assert_target_uncommitted(index_root, audit_size)
    _assert_target_receipts_absent(receipts, index_root)
    _audit_migration_fault("before_marker")
    descriptor = _open_audit(marker_path, append=False)
    try:
        if os.lseek(descriptor, 0, os.SEEK_END):
            raise AuditRecoveryRequired
        initial = _store_r4_migration_state(
            descriptor,
            None,
            source_identity=source_identity,
            next_cursor=0,
            receipt_count=source_checkpoint.committed_receipt_count,
            indexed_size=source_checkpoint.indexed_size,
            completed=False,
            source_root=source_root,
        )
        _sync_audit_directory_chain(index_root, index_root)
        return descriptor, initial
    except Exception:
        os.close(descriptor)
        raise


def _migrate_released_r4_audit_index(
    audit_path: Path,
    audit_descriptor: int,
    index_root: Path,
) -> None:
    source_identity = _audit_stream_identity(audit_descriptor)
    audit_size = os.lseek(audit_descriptor, 0, os.SEEK_END)
    marker_path = index_root / "migration"
    marker_descriptor = _open_existing_migration_target(marker_path)
    state: _R4MigrationState | None = None
    torn_marker = False
    try:
        if marker_descriptor is not None:
            try:
                state = _load_r4_migration_state(
                    marker_descriptor,
                    source_identity=source_identity,
                    audit_size=audit_size,
                )
            except AuditRecoveryRequired:
                torn_marker = True
            except OSError:
                raise AuditRecoveryRequired from None
            if state is not None and state.completed:
                _verify_target_migration_checkpoint(
                    index_root,
                    state,
                    audit_size,
                )
                return

        source_root = (
            Path(state.source_root)
            if state is not None
            else audit_path.absolute().parent
            / f".pyquality-audit-index-{source_identity}"
        )
        _validate_r4_audit_index_identity(source_root, source_identity)
        if not _r4_candidate_exists(source_root):
            if state is not None:
                raise AuditRecoveryRequired
            return
        source_checkpoint, receipts = _load_released_r4_index(
            source_root,
            audit_descriptor,
            audit_size,
        )
        if torn_marker:
            _assert_target_uncommitted(index_root, audit_size)
            _assert_target_receipt_namespace_empty(index_root)
            expected = _encode_r4_migration_state(
                1,
                source_identity=source_identity,
                next_cursor=0,
                receipt_count=source_checkpoint.committed_receipt_count,
                indexed_size=source_checkpoint.indexed_size,
                completed=False,
                source_root=source_root,
            )
            if marker_descriptor is None or not _exact_torn_prefix(
                marker_descriptor, 0, expected
            ):
                raise AuditRecoveryRequired
            _remove_open_audit(marker_path, marker_descriptor)
            os.close(marker_descriptor)
            marker_descriptor = None
        marker_descriptor, state = _prepare_r4_migration(
            marker_descriptor,
            state,
            source_checkpoint,
            receipts,
            source_identity=source_identity,
            source_root=source_root,
            index_root=index_root,
            marker_path=marker_path,
            audit_size=audit_size,
        )
        for cursor in range(state.next_cursor, state.receipt_count):
            _audit_migration_fault("before_receipt_copy")
            _copy_r4_receipt(
                audit_descriptor,
                receipts[cursor],
                indexed_size=state.indexed_size,
                index_root=index_root,
            )
            _audit_migration_fault("after_receipt_fsync")
            state = _store_r4_migration_state(
                marker_descriptor,
                state,
                source_identity=source_identity,
                next_cursor=cursor + 1,
                receipt_count=state.receipt_count,
                indexed_size=state.indexed_size,
                completed=False,
                source_root=source_root,
            )
        _publish_r4_migration_checkpoint(
            index_root, state, audit_size, audit_descriptor, receipts
        )
        _audit_migration_fault("before_completed_marker")
        _store_r4_migration_state(
            marker_descriptor,
            state,
            source_identity=source_identity,
            next_cursor=state.receipt_count,
            receipt_count=state.receipt_count,
            indexed_size=state.indexed_size,
            completed=True,
            source_root=source_root,
        )
    finally:
        if marker_descriptor is not None:
            os.close(marker_descriptor)


if os.name == "nt":
    import ctypes
    import msvcrt
    from ctypes import wintypes

    _INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
    _FILE_ATTRIBUTE_DIRECTORY = 0x00000010
    _FILE_ATTRIBUTE_NORMAL = 0x00000080
    _FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
    _FILE_SHARE_READ = 0x00000001
    _FILE_SHARE_WRITE = 0x00000002
    _FILE_SHARE_DELETE = 0x00000004
    _FILE_SHARE_ALL = _FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE
    _FILE_OPEN = 1
    _FILE_CREATE = 2
    _FILE_OPEN_IF = 3
    _FILE_OPENED = 1
    _FILE_CREATED = 2
    _FILE_DIRECTORY_FILE = 0x00000001
    _FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020
    _FILE_NON_DIRECTORY_FILE = 0x00000040
    _FILE_OPEN_REPARSE_POINT = 0x00200000
    _FILE_READ_ATTRIBUTES = 0x00000080
    _FILE_WRITE_ATTRIBUTES = 0x00000100
    _DELETE = 0x00010000
    _READ_CONTROL = 0x00020000
    _SYNCHRONIZE = 0x00100000
    _GENERIC_READ = 0x80000000
    _GENERIC_WRITE = 0x40000000
    _FILE_ALL_ACCESS = 0x001F01FF
    _OBJ_CASE_INSENSITIVE = 0x00000040
    _OPEN_EXISTING = 3
    _FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    _FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    _LOCKFILE_EXCLUSIVE_LOCK = 0x00000002
    _DUPLICATE_SAME_ACCESS = 0x00000002
    _TOKEN_QUERY = 0x00000008
    _TOKEN_OWNER = 4
    _ERROR_INSUFFICIENT_BUFFER = 122
    _SE_FILE_OBJECT = 1
    _OWNER_SECURITY_INFORMATION = 0x00000001
    _DACL_SECURITY_INFORMATION = 0x00000004
    _SE_DACL_PROTECTED = 0x1000
    _SET_ACCESS = 2
    _TRUSTEE_IS_SID = 0
    _TRUSTEE_IS_USER = 1
    _ACL_SIZE_INFORMATION_CLASS = 2
    _ACCESS_ALLOWED_ACE_TYPE = 0
    _SHARING_VIOLATION = 32
    _EXCLUSIVE_OPEN_TIMEOUT_SECONDS = 2.0
    _EXCLUSIVE_OPEN_RETRY_SECONDS = 0.01

    class _UnicodeString(ctypes.Structure):
        _fields_ = [
            ("Length", wintypes.USHORT),
            ("MaximumLength", wintypes.USHORT),
            ("Buffer", wintypes.LPWSTR),
        ]

    class _ObjectAttributes(ctypes.Structure):
        _fields_ = [
            ("Length", wintypes.ULONG),
            ("RootDirectory", wintypes.HANDLE),
            ("ObjectName", ctypes.POINTER(_UnicodeString)),
            ("Attributes", wintypes.ULONG),
            ("SecurityDescriptor", wintypes.LPVOID),
            ("SecurityQualityOfService", wintypes.LPVOID),
        ]

    class _IoStatusBlock(ctypes.Structure):
        _fields_ = [("Status", ctypes.c_void_p), ("Information", ctypes.c_size_t)]

    class _ByHandleFileInformation(ctypes.Structure):
        _fields_ = [
            ("dwFileAttributes", wintypes.DWORD),
            ("ftCreationTime", wintypes.FILETIME),
            ("ftLastAccessTime", wintypes.FILETIME),
            ("ftLastWriteTime", wintypes.FILETIME),
            ("dwVolumeSerialNumber", wintypes.DWORD),
            ("nFileSizeHigh", wintypes.DWORD),
            ("nFileSizeLow", wintypes.DWORD),
            ("nNumberOfLinks", wintypes.DWORD),
            ("nFileIndexHigh", wintypes.DWORD),
            ("nFileIndexLow", wintypes.DWORD),
        ]

    class _Overlapped(ctypes.Structure):
        _fields_ = [
            ("Internal", ctypes.c_size_t),
            ("InternalHigh", ctypes.c_size_t),
            ("Offset", wintypes.DWORD),
            ("OffsetHigh", wintypes.DWORD),
            ("hEvent", wintypes.HANDLE),
        ]

    class _FileDispositionInfo(ctypes.Structure):
        _fields_ = [("DeleteFile", wintypes.BOOL)]

    class _Trustee(ctypes.Structure):
        _fields_ = [
            ("pMultipleTrustee", wintypes.LPVOID),
            ("MultipleTrusteeOperation", wintypes.DWORD),
            ("TrusteeForm", wintypes.DWORD),
            ("TrusteeType", wintypes.DWORD),
            ("ptstrName", wintypes.LPWSTR),
        ]

    class _ExplicitAccess(ctypes.Structure):
        _fields_ = [
            ("grfAccessPermissions", wintypes.DWORD),
            ("grfAccessMode", wintypes.DWORD),
            ("grfInheritance", wintypes.DWORD),
            ("Trustee", _Trustee),
        ]

    class _TokenOwner(ctypes.Structure):
        _fields_ = [("Owner", wintypes.LPVOID)]

    class _SecurityDescriptor(ctypes.Structure):
        _fields_ = [
            ("Revision", ctypes.c_ubyte),
            ("Sbz1", ctypes.c_ubyte),
            ("Control", wintypes.WORD),
            ("Owner", wintypes.LPVOID),
            ("Group", wintypes.LPVOID),
            ("Sacl", wintypes.LPVOID),
            ("Dacl", wintypes.LPVOID),
        ]

    class _AclSizeInformation(ctypes.Structure):
        _fields_ = [
            ("AceCount", wintypes.DWORD),
            ("AclBytesInUse", wintypes.DWORD),
            ("AclBytesFree", wintypes.DWORD),
        ]

    class _AccessAllowedAce(ctypes.Structure):
        _fields_ = [
            ("AceType", ctypes.c_ubyte),
            ("AceFlags", ctypes.c_ubyte),
            ("AceSize", wintypes.WORD),
            ("Mask", wintypes.DWORD),
            ("SidStart", wintypes.DWORD),
        ]

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    _ntdll = ctypes.WinDLL("ntdll")
    _create_file = _kernel32.CreateFileW
    _create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    _create_file.restype = wintypes.HANDLE
    _close_handle = _kernel32.CloseHandle
    _close_handle.argtypes = [wintypes.HANDLE]
    _close_handle.restype = wintypes.BOOL
    _get_file_information = _kernel32.GetFileInformationByHandle
    _get_file_information.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_ByHandleFileInformation),
    ]
    _get_file_information.restype = wintypes.BOOL
    _duplicate_handle = _kernel32.DuplicateHandle
    _duplicate_handle.argtypes = [
        wintypes.HANDLE,
        wintypes.HANDLE,
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.DWORD,
        wintypes.BOOL,
        wintypes.DWORD,
    ]
    _duplicate_handle.restype = wintypes.BOOL
    _get_current_process = _kernel32.GetCurrentProcess
    _get_current_process.restype = wintypes.HANDLE
    _local_free = _kernel32.LocalFree
    _local_free.argtypes = [wintypes.LPVOID]
    _local_free.restype = wintypes.LPVOID
    _lock_file_ex = _kernel32.LockFileEx
    _lock_file_ex.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(_Overlapped),
    ]
    _lock_file_ex.restype = wintypes.BOOL
    _unlock_file_ex = _kernel32.UnlockFileEx
    _unlock_file_ex.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(_Overlapped),
    ]
    _unlock_file_ex.restype = wintypes.BOOL
    _set_file_information_by_handle = _kernel32.SetFileInformationByHandle
    _set_file_information_by_handle.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    _set_file_information_by_handle.restype = wintypes.BOOL
    _nt_create_file = _ntdll.NtCreateFile
    _nt_create_file.argtypes = [
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.DWORD,
        ctypes.POINTER(_ObjectAttributes),
        ctypes.POINTER(_IoStatusBlock),
        wintypes.LPVOID,
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.LPVOID,
        wintypes.ULONG,
    ]
    _nt_create_file.restype = wintypes.LONG
    _rtl_nt_status_to_dos_error = _ntdll.RtlNtStatusToDosError
    _rtl_nt_status_to_dos_error.argtypes = [wintypes.LONG]
    _rtl_nt_status_to_dos_error.restype = wintypes.ULONG
    _open_process_token = _advapi32.OpenProcessToken
    _open_process_token.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    _open_process_token.restype = wintypes.BOOL
    _get_token_information = _advapi32.GetTokenInformation
    _get_token_information.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    _get_token_information.restype = wintypes.BOOL
    _get_security_info = _advapi32.GetSecurityInfo
    _get_security_info.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
    ]
    _get_security_info.restype = wintypes.DWORD
    _set_entries_in_acl = _advapi32.SetEntriesInAclW
    _set_entries_in_acl.argtypes = [
        wintypes.ULONG,
        ctypes.POINTER(_ExplicitAccess),
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.LPVOID),
    ]
    _set_entries_in_acl.restype = wintypes.DWORD
    _initialize_security_descriptor = _advapi32.InitializeSecurityDescriptor
    _initialize_security_descriptor.argtypes = [wintypes.LPVOID, wintypes.DWORD]
    _initialize_security_descriptor.restype = wintypes.BOOL
    _set_security_descriptor_owner = _advapi32.SetSecurityDescriptorOwner
    _set_security_descriptor_owner.argtypes = [
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.BOOL,
    ]
    _set_security_descriptor_owner.restype = wintypes.BOOL
    _set_security_descriptor_dacl = _advapi32.SetSecurityDescriptorDacl
    _set_security_descriptor_dacl.argtypes = [
        wintypes.LPVOID,
        wintypes.BOOL,
        wintypes.LPVOID,
        wintypes.BOOL,
    ]
    _set_security_descriptor_dacl.restype = wintypes.BOOL
    _set_security_descriptor_control = _advapi32.SetSecurityDescriptorControl
    _set_security_descriptor_control.argtypes = [
        wintypes.LPVOID,
        wintypes.WORD,
        wintypes.WORD,
    ]
    _set_security_descriptor_control.restype = wintypes.BOOL
    _get_security_descriptor_control = _advapi32.GetSecurityDescriptorControl
    _get_security_descriptor_control.argtypes = [
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.WORD),
        ctypes.POINTER(wintypes.DWORD),
    ]
    _get_security_descriptor_control.restype = wintypes.BOOL
    _get_acl_information = _advapi32.GetAclInformation
    _get_acl_information.argtypes = [
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.c_int,
    ]
    _get_acl_information.restype = wintypes.BOOL
    _get_ace = _advapi32.GetAce
    _get_ace.argtypes = [
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
    ]
    _get_ace.restype = wintypes.BOOL
    _equal_sid = _advapi32.EqualSid
    _equal_sid.argtypes = [wintypes.LPVOID, wintypes.LPVOID]
    _equal_sid.restype = wintypes.BOOL
    _is_valid_sid = _advapi32.IsValidSid
    _is_valid_sid.argtypes = [wintypes.LPVOID]
    _is_valid_sid.restype = wintypes.BOOL

    def _open_windows_audit(
        path: Path,
        *,
        append: bool = True,
        create: bool = True,
    ) -> int:
        root_handle: int | None = None
        parent_handle: int | None = None
        final_handle: int | None = None
        descriptor: int | None = None
        try:
            root = Path(path.anchor)
            parts = path.relative_to(root).parts
            if not parts or parts[-1] in {"", ".", ".."}:
                raise OSError("audit path has no file component")
            root_handle = _open_windows_root(str(root))
            _validate_windows_handle(root_handle, directory=True)
            parent_handle = root_handle
            root_handle = None
            for part in parts[:-1]:
                _validate_windows_component(part)
                if create:
                    next_handle, created = _open_or_create_windows_directory(
                        parent_handle, part
                    )
                else:
                    next_handle = _nt_open_relative(
                        parent_handle,
                        part,
                        desired_access=_FILE_READ_ATTRIBUTES,
                        disposition=_FILE_OPEN,
                        attributes=_FILE_ATTRIBUTE_DIRECTORY,
                        options=_FILE_DIRECTORY_FILE | _FILE_OPEN_REPARSE_POINT,
                    )
                    created = False
                try:
                    _validate_windows_handle(next_handle, directory=True)
                    if created:
                        _fchmod_windows_handle(next_handle, 0o700)
                except Exception:
                    _close_windows_handle(next_handle)
                    raise
                _close_windows_handle(parent_handle)
                parent_handle = next_handle
            _validate_windows_component(parts[-1])
            with _windows_audit_security() as (security_descriptor, owner_sid):
                final_handle, open_result = _open_exclusive_windows_audit_file(
                    parent_handle,
                    parts[-1],
                    security_descriptor,
                    create=create,
                )
                allowed_results = (
                    {_FILE_CREATED, _FILE_OPENED} if create else {_FILE_OPENED}
                )
                if open_result not in allowed_results:
                    raise OSError("native audit file returned an unexpected open result")
                _validate_windows_handle(final_handle, directory=False)
                _verify_windows_owner_only_dacl(final_handle, owner_sid)
            descriptor_flags = os.O_RDWR | getattr(os, "O_BINARY", 0)
            if append:
                descriptor_flags |= os.O_APPEND
            descriptor = msvcrt.open_osfhandle(final_handle, descriptor_flags)
            final_handle = None
            os.fchmod(descriptor, 0o600)
            return descriptor
        except Exception:
            if descriptor is not None:
                os.close(descriptor)
            raise
        finally:
            if final_handle is not None:
                _close_windows_handle(final_handle)
            if parent_handle is not None:
                _close_windows_handle(parent_handle)
            if root_handle is not None:
                _close_windows_handle(root_handle)

    def _open_exclusive_windows_audit_file(
        parent: int,
        name: str,
        security_descriptor: wintypes.LPVOID,
        *,
        create: bool,
    ) -> tuple[int, int]:
        deadline = time.monotonic() + _EXCLUSIVE_OPEN_TIMEOUT_SECONDS
        while True:
            try:
                return _nt_open_relative_result(
                    parent,
                    name,
                    desired_access=(
                        _GENERIC_READ
                        | _GENERIC_WRITE
                        | _DELETE
                        | _SYNCHRONIZE
                        | _READ_CONTROL
                    ),
                    disposition=_FILE_OPEN_IF if create else _FILE_OPEN,
                    attributes=_FILE_ATTRIBUTE_NORMAL,
                    options=(
                        _FILE_NON_DIRECTORY_FILE
                        | _FILE_OPEN_REPARSE_POINT
                        | _FILE_SYNCHRONOUS_IO_NONALERT
                    ),
                    share_access=0,
                    security_descriptor=security_descriptor,
                )
            except OSError as error:
                if error.errno != _SHARING_VIOLATION or time.monotonic() >= deadline:
                    raise
                time.sleep(_EXCLUSIVE_OPEN_RETRY_SECONDS)

    def _open_windows_root(root: str) -> int:
        handle = _create_file(
            root,
            _FILE_READ_ATTRIBUTES,
            _FILE_SHARE_ALL,
            None,
            _OPEN_EXISTING,
            _FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
        value = int(handle) if handle is not None else None
        if value in {None, _INVALID_HANDLE_VALUE}:
            raise ctypes.WinError(ctypes.get_last_error())
        return value

    def _open_or_create_windows_directory(parent: int, name: str) -> tuple[int, bool]:
        access = _FILE_READ_ATTRIBUTES
        options = _FILE_DIRECTORY_FILE | _FILE_OPEN_REPARSE_POINT
        try:
            return (
                _nt_open_relative(
                    parent,
                    name,
                    desired_access=access,
                    disposition=_FILE_OPEN,
                    attributes=_FILE_ATTRIBUTE_DIRECTORY,
                    options=options,
                ),
                False,
            )
        except OSError as error:
            if error.errno not in {2, 3}:
                raise
        try:
            return (
                _nt_open_relative(
                    parent,
                    name,
                    desired_access=access | _FILE_WRITE_ATTRIBUTES,
                    disposition=_FILE_CREATE,
                    attributes=_FILE_ATTRIBUTE_DIRECTORY,
                    options=options,
                ),
                True,
            )
        except OSError as error:
            if error.errno not in {80, 183}:
                raise
        return (
            _nt_open_relative(
                parent,
                name,
                desired_access=access,
                disposition=_FILE_OPEN,
                attributes=_FILE_ATTRIBUTE_DIRECTORY,
                options=options,
            ),
            False,
        )

    def _ensure_audit_index_namespace(path: Path) -> None:
        _ensure_secure_audit_directory(path)

    def _ensure_secure_audit_directory(path: Path) -> None:
        """Create or validate the final directory with the exact owner-only DACL."""
        root_handle: int | None = None
        parent_handle: int | None = None
        final_handle: int | None = None
        try:
            root = Path(path.anchor)
            parts = path.relative_to(root).parts
            if not parts:
                raise OSError("audit index root has no secure component")
            root_handle = _open_windows_root(str(root))
            _validate_windows_handle(root_handle, directory=True)
            parent_handle = root_handle
            root_handle = None
            for part in parts[:-1]:
                _validate_windows_component(part)
                next_handle, _ = _open_or_create_windows_directory(
                    parent_handle,
                    part,
                )
                try:
                    _validate_windows_handle(next_handle, directory=True)
                except Exception:
                    _close_windows_handle(next_handle)
                    raise
                _close_windows_handle(parent_handle)
                parent_handle = next_handle
            _validate_windows_component(parts[-1])
            with _windows_audit_security() as (security_descriptor, owner_sid):
                try:
                    final_handle = _nt_open_relative(
                        parent_handle,
                        parts[-1],
                        desired_access=_FILE_READ_ATTRIBUTES | _READ_CONTROL,
                        disposition=_FILE_OPEN,
                        attributes=_FILE_ATTRIBUTE_DIRECTORY,
                        options=_FILE_DIRECTORY_FILE | _FILE_OPEN_REPARSE_POINT,
                    )
                except OSError as error:
                    if error.errno not in {2, 3}:
                        raise
                    try:
                        final_handle, information = _nt_open_relative_result(
                            parent_handle,
                            parts[-1],
                            desired_access=_FILE_READ_ATTRIBUTES | _READ_CONTROL,
                            disposition=_FILE_CREATE,
                            attributes=_FILE_ATTRIBUTE_DIRECTORY,
                            options=_FILE_DIRECTORY_FILE | _FILE_OPEN_REPARSE_POINT,
                            security_descriptor=security_descriptor,
                        )
                    except OSError as create_error:
                        if create_error.errno not in {80, 183}:
                            raise
                        final_handle = _nt_open_relative(
                            parent_handle,
                            parts[-1],
                            desired_access=_FILE_READ_ATTRIBUTES | _READ_CONTROL,
                            disposition=_FILE_OPEN,
                            attributes=_FILE_ATTRIBUTE_DIRECTORY,
                            options=_FILE_DIRECTORY_FILE | _FILE_OPEN_REPARSE_POINT,
                        )
                    else:
                        if information != _FILE_CREATED:
                            raise OSError(
                                "audit index directory was not created exclusively"
                            )
                _validate_windows_handle(final_handle, directory=True)
                _verify_windows_owner_only_dacl(final_handle, owner_sid)
        finally:
            if final_handle is not None:
                _close_windows_handle(final_handle)
            if parent_handle is not None:
                _close_windows_handle(parent_handle)
            if root_handle is not None:
                _close_windows_handle(root_handle)

    def _validate_existing_secure_audit_directory(path: Path) -> None:
        """Validate an existing directory without following any reparse point."""
        root = Path(path.anchor)
        parts = path.relative_to(root).parts
        if not parts:
            raise OSError("audit directory has no secure component")
        descriptor = _open_windows_root(str(root))
        try:
            _validate_windows_handle(descriptor, directory=True)
            with _windows_audit_security() as (_, owner_sid):
                for index, part in enumerate(parts):
                    _validate_windows_component(part)
                    final = index == len(parts) - 1
                    next_descriptor = _nt_open_relative(
                        descriptor,
                        part,
                        desired_access=(
                            _FILE_READ_ATTRIBUTES
                            | (_READ_CONTROL if final else 0)
                        ),
                        disposition=_FILE_OPEN,
                        attributes=_FILE_ATTRIBUTE_DIRECTORY,
                        options=(
                            _FILE_DIRECTORY_FILE | _FILE_OPEN_REPARSE_POINT
                        ),
                    )
                    try:
                        _validate_windows_handle(
                            next_descriptor,
                            directory=True,
                        )
                        if final:
                            _verify_windows_owner_only_dacl(
                                next_descriptor,
                                owner_sid,
                            )
                    except Exception:
                        _close_windows_handle(next_descriptor)
                        raise
                    _close_windows_handle(descriptor)
                    descriptor = next_descriptor
        finally:
            _close_windows_handle(descriptor)

    def _validate_existing_r4_audit_directory(path: Path) -> None:
        """Accept only current directories or the released R4 inherited ACL shape."""
        root = Path(path.anchor)
        parts = path.relative_to(root).parts
        if not parts:
            raise OSError("audit directory has no secure component")
        descriptor = _open_windows_root(str(root))
        try:
            _validate_windows_handle(descriptor, directory=True)
            with _windows_audit_security() as (_, owner_sid):
                for index, part in enumerate(parts):
                    _validate_windows_component(part)
                    final = index == len(parts) - 1
                    next_descriptor = _nt_open_relative(
                        descriptor,
                        part,
                        desired_access=_FILE_READ_ATTRIBUTES | (_READ_CONTROL if final else 0),
                        disposition=_FILE_OPEN,
                        attributes=_FILE_ATTRIBUTE_DIRECTORY,
                        options=_FILE_DIRECTORY_FILE | _FILE_OPEN_REPARSE_POINT,
                    )
                    try:
                        _validate_windows_handle(next_descriptor, directory=True)
                        if final:
                            try:
                                _verify_windows_owner_only_dacl(next_descriptor, owner_sid)
                            except OSError:
                                _verify_windows_released_r4_dacl(next_descriptor, owner_sid)
                    except Exception:
                        _close_windows_handle(next_descriptor)
                        raise
                    _close_windows_handle(descriptor)
                    descriptor = next_descriptor
        finally:
            _close_windows_handle(descriptor)

    def _nt_open_relative(
        parent: int,
        name: str,
        *,
        desired_access: int,
        disposition: int,
        attributes: int,
        options: int,
        share_access: int = _FILE_SHARE_ALL,
    ) -> int:
        handle, _ = _nt_open_relative_result(
            parent,
            name,
            desired_access=desired_access,
            disposition=disposition,
            attributes=attributes,
            options=options,
            share_access=share_access,
        )
        return handle

    def _nt_open_relative_result(
        parent: int,
        name: str,
        *,
        desired_access: int,
        disposition: int,
        attributes: int,
        options: int,
        share_access: int = _FILE_SHARE_ALL,
        security_descriptor: object | None = None,
    ) -> tuple[int, int]:
        buffer = ctypes.create_unicode_buffer(name)
        name_length = len(name.encode("utf-16-le"))
        unicode_name = _UnicodeString(
            Length=name_length,
            MaximumLength=name_length + 2,
            Buffer=ctypes.cast(buffer, wintypes.LPWSTR),
        )
        object_attributes = _ObjectAttributes(
            Length=ctypes.sizeof(_ObjectAttributes),
            RootDirectory=wintypes.HANDLE(parent),
            ObjectName=ctypes.pointer(unicode_name),
            Attributes=_OBJ_CASE_INSENSITIVE,
            SecurityDescriptor=security_descriptor,
            SecurityQualityOfService=None,
        )
        io_status = _IoStatusBlock()
        handle = wintypes.HANDLE()
        status = _nt_create_file(
            ctypes.byref(handle),
            desired_access,
            ctypes.byref(object_attributes),
            ctypes.byref(io_status),
            None,
            attributes,
            share_access,
            disposition,
            options,
            None,
            0,
        )
        if status < 0:
            error = int(_rtl_nt_status_to_dos_error(status))
            raise OSError(error, "native audit component open failed")
        if handle.value in {None, _INVALID_HANDLE_VALUE}:
            raise OSError("native audit component returned an invalid handle")
        return int(handle.value), int(io_status.Information)

    def _validate_windows_component(name: str) -> None:
        encoded_length = len(name.encode("utf-16-le"))
        if (
            not name
            or name in {".", ".."}
            or encoded_length > 510
            or any(character in name for character in ("/", "\\", ":", "\0"))
        ):
            raise OSError("audit path contains an invalid component")

    def _audit_stream_identity(descriptor: int) -> str:
        information = _ByHandleFileInformation()
        handle = msvcrt.get_osfhandle(descriptor)
        if not _get_file_information(
            wintypes.HANDLE(handle), ctypes.byref(information)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        file_index = (information.nFileIndexHigh << 32) | information.nFileIndexLow
        return f"{information.dwVolumeSerialNumber:08x}-{file_index:016x}"

    def _validate_windows_handle(handle: int, *, directory: bool) -> None:
        information = _ByHandleFileInformation()
        if not _get_file_information(wintypes.HANDLE(handle), ctypes.byref(information)):
            raise ctypes.WinError(ctypes.get_last_error())
        if information.dwFileAttributes & _FILE_ATTRIBUTE_REPARSE_POINT:
            raise OSError("audit path contains a reparse point")
        is_directory = bool(information.dwFileAttributes & _FILE_ATTRIBUTE_DIRECTORY)
        if is_directory != directory:
            raise OSError("audit path component has the wrong type")

    @contextmanager
    def _windows_audit_security() -> Iterator[tuple[wintypes.LPVOID, wintypes.LPVOID]]:
        token = wintypes.HANDLE()
        token_value = 0
        acl = wintypes.LPVOID()
        if not _open_process_token(_get_current_process(), _TOKEN_QUERY, ctypes.byref(token)):
            raise ctypes.WinError(ctypes.get_last_error())
        token_value = int(token.value)
        try:
            required = wintypes.DWORD()
            ctypes.set_last_error(0)
            if _get_token_information(token, _TOKEN_OWNER, None, 0, ctypes.byref(required)):
                raise OSError("token owner query returned an invalid size result")
            error = ctypes.get_last_error()
            if error != _ERROR_INSUFFICIENT_BUFFER or not required.value:
                raise ctypes.WinError(error)
            token_buffer = ctypes.create_string_buffer(required.value)
            if not _get_token_information(
                token,
                _TOKEN_OWNER,
                token_buffer,
                required.value,
                ctypes.byref(required),
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            token_owner = ctypes.cast(
                token_buffer, ctypes.POINTER(_TokenOwner)
            ).contents
            owner_sid = wintypes.LPVOID(token_owner.Owner)
            if not owner_sid.value or not _is_valid_sid(owner_sid):
                raise OSError("process token owner has an invalid security identifier")
            trustee = _Trustee(
                pMultipleTrustee=None,
                MultipleTrusteeOperation=0,
                TrusteeForm=_TRUSTEE_IS_SID,
                TrusteeType=_TRUSTEE_IS_USER,
                ptstrName=ctypes.cast(owner_sid, wintypes.LPWSTR),
            )
            explicit_access = _ExplicitAccess(
                grfAccessPermissions=_FILE_ALL_ACCESS,
                grfAccessMode=_SET_ACCESS,
                grfInheritance=0,
                Trustee=trustee,
            )
            result = _set_entries_in_acl(
                1, ctypes.byref(explicit_access), None, ctypes.byref(acl)
            )
            if result:
                raise OSError(result, "owner-only audit ACL construction failed")
            security_descriptor = _SecurityDescriptor()
            descriptor_pointer = ctypes.cast(
                ctypes.byref(security_descriptor), wintypes.LPVOID
            )
            if not _initialize_security_descriptor(descriptor_pointer, 1):
                raise ctypes.WinError(ctypes.get_last_error())
            if not _set_security_descriptor_owner(
                descriptor_pointer, owner_sid, False
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            if not _set_security_descriptor_dacl(
                descriptor_pointer, True, acl, False
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            if not _set_security_descriptor_control(
                descriptor_pointer, _SE_DACL_PROTECTED, _SE_DACL_PROTECTED
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            yield descriptor_pointer, owner_sid
        finally:
            if acl.value:
                _local_free(acl)
            if token_value:
                _close_windows_handle(token_value)

    def _verify_windows_owner_only_dacl(handle: int, owner_sid: wintypes.LPVOID) -> None:
        owner = wintypes.LPVOID()
        dacl = wintypes.LPVOID()
        security_descriptor = wintypes.LPVOID()
        result = _get_security_info(
            wintypes.HANDLE(handle),
            _SE_FILE_OBJECT,
            _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION,
            ctypes.byref(owner),
            None,
            ctypes.byref(dacl),
            None,
            ctypes.byref(security_descriptor),
        )
        if result:
            raise OSError(result, "audit ACL verification query failed")
        try:
            if (
                not owner.value
                or not _is_valid_sid(owner)
                or not _equal_sid(owner, owner_sid)
                or not dacl.value
            ):
                raise OSError("audit target owner or ACL is unsafe")
            control = wintypes.WORD()
            revision = wintypes.DWORD()
            if not _get_security_descriptor_control(
                security_descriptor, ctypes.byref(control), ctypes.byref(revision)
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            if not control.value & _SE_DACL_PROTECTED:
                raise OSError("audit target ACL is not protected")
            information = _AclSizeInformation()
            if not _get_acl_information(
                dacl,
                ctypes.byref(information),
                ctypes.sizeof(information),
                _ACL_SIZE_INFORMATION_CLASS,
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            if information.AceCount != 1:
                raise OSError("audit target ACL is not owner-only")
            ace_pointer = wintypes.LPVOID()
            if not _get_ace(dacl, 0, ctypes.byref(ace_pointer)) or not ace_pointer.value:
                raise ctypes.WinError(ctypes.get_last_error())
            ace = ctypes.cast(ace_pointer, ctypes.POINTER(_AccessAllowedAce)).contents
            ace_sid = wintypes.LPVOID(
                ace_pointer.value + _AccessAllowedAce.SidStart.offset
            )
            if (
                ace.AceType != _ACCESS_ALLOWED_ACE_TYPE
                or ace.AceFlags != 0
                or ace.Mask != _FILE_ALL_ACCESS
                or not _is_valid_sid(ace_sid)
                or not _equal_sid(ace_sid, owner_sid)
            ):
                raise OSError("audit target ACL contains an unsafe access entry")
        finally:
            if security_descriptor.value:
                _local_free(security_descriptor)

    def _verify_windows_released_r4_dacl(handle: int, owner_sid: wintypes.LPVOID) -> None:
        owner = wintypes.LPVOID()
        dacl = wintypes.LPVOID()
        security_descriptor = wintypes.LPVOID()
        result = _get_security_info(
            wintypes.HANDLE(handle),
            _SE_FILE_OBJECT,
            _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION,
            ctypes.byref(owner),
            None,
            ctypes.byref(dacl),
            None,
            ctypes.byref(security_descriptor),
        )
        if result:
            raise OSError(result, "released R4 ACL verification query failed")
        try:
            if (
                not owner.value
                or not _is_valid_sid(owner)
                or not _equal_sid(owner, owner_sid)
                or not dacl.value
            ):
                raise OSError("released R4 directory owner or ACL is unsafe")
            control = wintypes.WORD()
            revision = wintypes.DWORD()
            if not _get_security_descriptor_control(
                security_descriptor, ctypes.byref(control), ctypes.byref(revision)
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            if control.value & _SE_DACL_PROTECTED:
                raise OSError("released R4 ACL is not inherited")
            information = _AclSizeInformation()
            if not _get_acl_information(
                dacl,
                ctypes.byref(information),
                ctypes.sizeof(information),
                _ACL_SIZE_INFORMATION_CLASS,
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            if not information.AceCount:
                raise OSError("released R4 ACL is empty")
            for index in range(information.AceCount):
                ace_pointer = wintypes.LPVOID()
                if not _get_ace(dacl, index, ctypes.byref(ace_pointer)) or not ace_pointer.value:
                    raise ctypes.WinError(ctypes.get_last_error())
                ace = ctypes.cast(
                    ace_pointer, ctypes.POINTER(_AccessAllowedAce)
                ).contents
                if ace.AceType != _ACCESS_ALLOWED_ACE_TYPE or not ace.AceFlags & 0x10:
                    raise OSError("released R4 ACL contains an explicit or unsafe entry")
        finally:
            if security_descriptor.value:
                _local_free(security_descriptor)

    def _fchmod_windows_handle(handle: int, mode: int) -> None:
        duplicate = wintypes.HANDLE()
        process = _get_current_process()
        if not _duplicate_handle(
            process,
            wintypes.HANDLE(handle),
            process,
            ctypes.byref(duplicate),
            0,
            False,
            _DUPLICATE_SAME_ACCESS,
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        duplicate_value = int(duplicate.value)
        descriptor: int | None = None
        try:
            descriptor = msvcrt.open_osfhandle(
                duplicate_value, os.O_RDONLY | getattr(os, "O_BINARY", 0)
            )
            duplicate_value = 0
            os.fchmod(descriptor, mode)
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if duplicate_value:
                _close_windows_handle(duplicate_value)

    def _close_windows_handle(handle: int) -> None:
        _close_handle(wintypes.HANDLE(handle))

    def _remove_windows_open_audit(descriptor: int) -> None:
        information = _FileDispositionInfo(DeleteFile=True)
        handle = wintypes.HANDLE(msvcrt.get_osfhandle(descriptor))
        if not _set_file_information_by_handle(
            handle,
            4,
            ctypes.byref(information),
            ctypes.sizeof(information),
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        os.fsync(descriptor)

    def _lock_descriptor(descriptor: int) -> None:
        overlapped = _Overlapped()
        handle = wintypes.HANDLE(msvcrt.get_osfhandle(descriptor))
        if not _lock_file_ex(
            handle,
            _LOCKFILE_EXCLUSIVE_LOCK,
            0,
            1,
            0,
            ctypes.byref(overlapped),
        ):
            raise ctypes.WinError(ctypes.get_last_error())

    def _unlock_descriptor(descriptor: int) -> None:
        overlapped = _Overlapped()
        handle = wintypes.HANDLE(msvcrt.get_osfhandle(descriptor))
        if not _unlock_file_ex(handle, 0, 1, 0, ctypes.byref(overlapped)):
            raise ctypes.WinError(ctypes.get_last_error())

else:
    import fcntl

    def _audit_stream_identity(descriptor: int) -> str:
        information = os.fstat(descriptor)
        return f"{information.st_dev:x}-{information.st_ino:x}"

    def _remove_posix_open_audit(path: Path, descriptor: int) -> None:
        no_follow = getattr(os, "O_NOFOLLOW", None)
        directory = getattr(os, "O_DIRECTORY", None)
        if no_follow is None or directory is None:
            raise OSError("descriptor-relative no-follow removal is unavailable")
        root = Path(path.anchor)
        parts = path.relative_to(root).parts
        if not parts or parts[-1] in {"", ".", ".."}:
            raise OSError("audit removal path has no file component")
        flags = os.O_RDONLY | directory | no_follow | getattr(os, "O_CLOEXEC", 0)
        parent_descriptor = os.open(root, flags)
        try:
            for part in parts[:-1]:
                if part in {"", ".", ".."} or "/" in part or "\\" in part:
                    raise OSError("audit removal path contains an invalid component")
                next_descriptor = os.open(
                    part,
                    flags,
                    dir_fd=parent_descriptor,
                )
                os.close(parent_descriptor)
                parent_descriptor = next_descriptor
            expected = os.fstat(descriptor)
            visible = os.stat(
                parts[-1],
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            if (
                not stat.S_ISREG(visible.st_mode)
                or visible.st_uid != os.geteuid()
                or (visible.st_dev, visible.st_ino)
                != (expected.st_dev, expected.st_ino)
            ):
                raise OSError("audit removal target identity changed")
            os.unlink(parts[-1], dir_fd=parent_descriptor)
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)

    def _open_existing_posix_audit_directory(path: Path) -> int:
        no_follow = getattr(os, "O_NOFOLLOW", None)
        directory = getattr(os, "O_DIRECTORY", None)
        if no_follow is None or directory is None:
            raise OSError("descriptor-relative no-follow opens are unavailable")
        root = Path(path.anchor)
        parts = path.relative_to(root).parts
        flags = (
            os.O_RDONLY
            | directory
            | no_follow
            | getattr(os, "O_CLOEXEC", 0)
        )
        descriptor = os.open(root, flags)
        try:
            for part in parts:
                if part in {"", ".", ".."} or "/" in part or "\\" in part:
                    raise OSError("audit directory has an invalid component")
                next_descriptor = os.open(
                    part,
                    flags,
                    dir_fd=descriptor,
                )
                os.close(descriptor)
                descriptor = next_descriptor
            return descriptor
        except Exception:
            os.close(descriptor)
            raise

    def _open_posix_r4_audit(path: Path) -> int:
        """Open released evidence read-only without repairing its permissions."""
        no_follow = getattr(os, "O_NOFOLLOW", None)
        if no_follow is None or path.name in {"", ".", ".."}:
            raise OSError("legacy audit path has no file component")
        parent_descriptor = _open_existing_posix_audit_directory(path.parent)
        try:
            descriptor = os.open(
                path.name,
                os.O_RDONLY | no_follow | getattr(os, "O_CLOEXEC", 0),
                dir_fd=parent_descriptor,
            )
        finally:
            os.close(parent_descriptor)
        try:
            information = os.fstat(descriptor)
            if (
                not stat.S_ISREG(information.st_mode)
                or information.st_uid != os.geteuid()
                or information.st_mode & 0o077
            ):
                raise OSError("legacy audit evidence is not owner-only")
            return descriptor
        except Exception:
            os.close(descriptor)
            raise

    def _open_windows_audit(
        path: Path,
        *,
        append: bool = True,
        create: bool = True,
    ) -> int:
        del path, append, create
        raise OSError("Windows native audit opens are unavailable")

    def _ensure_secure_audit_directory(path: Path) -> None:
        no_follow = getattr(os, "O_NOFOLLOW", None)
        directory = getattr(os, "O_DIRECTORY", None)
        if no_follow is None or directory is None:
            raise OSError("descriptor-relative no-follow opens are unavailable")
        root = Path(path.anchor)
        parts = path.relative_to(root).parts
        if not parts:
            raise OSError("audit index root has no secure component")
        flags = os.O_RDONLY | directory | no_follow | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(root, flags)
        try:
            for part in parts:
                if part in {"", ".", ".."} or "/" in part or "\\" in part:
                    raise OSError("audit index path contains an invalid component")
                next_descriptor, created = _open_or_create_posix_directory(
                    descriptor,
                    part,
                    flags,
                )
                os.close(descriptor)
                descriptor = next_descriptor
                if created:
                    os.fchmod(descriptor, 0o700)
            information = os.fstat(descriptor)
            if information.st_uid != os.geteuid() or information.st_mode & 0o077:
                raise OSError("audit index root is not owner-only")
        finally:
            os.close(descriptor)

    def _validate_existing_secure_audit_directory(path: Path) -> None:
        descriptor = _open_existing_posix_audit_directory(path)
        try:
            information = os.fstat(descriptor)
            if information.st_uid != os.geteuid() or information.st_mode & 0o077:
                raise OSError("audit directory is not owner-only")
        finally:
            os.close(descriptor)

    _validate_existing_r4_audit_directory = _validate_existing_secure_audit_directory

    def _sync_posix_audit_directory(path: Path) -> None:
        descriptor = _open_existing_posix_audit_directory(path)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _ensure_audit_index_namespace(path: Path) -> None:
        _ensure_secure_audit_directory(path)

    def _lock_descriptor(descriptor: int) -> None:
        fcntl.flock(descriptor, fcntl.LOCK_EX)

    def _unlock_descriptor(descriptor: int) -> None:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
