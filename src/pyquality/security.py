"""Credential isolation, bounded redaction, and hardened local JSONL audit output."""

from __future__ import annotations

import json
import math
import os
import re
import stat
import time
from collections.abc import Callable, Iterable, Iterator, Mapping
from collections.abc import Set as AbstractSet
from contextlib import contextmanager
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Literal
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
    def __init__(self, path: Path, *, secrets: set[str] | None = None) -> None:
        failed = False
        audit_path: Path | None = None
        try:
            audit_path = Path(path)
        except OSError:
            failed = True
        if failed or audit_path is None:
            raise AuditWriteError("audit path is invalid")
        self._path = audit_path
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
        descriptor = _open_audit(self._path)
        try:
            with _audit_file_lock(descriptor):
                _recover_tail(descriptor)
                _write_all(descriptor, encoded)
                os.fsync(descriptor)
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


def _audit_scalar(value: object, secrets: set[str], limit: int) -> object:
    clean = redact(value, secrets, set())
    return _truncate_text(clean, limit) if isinstance(clean, str) else clean


def _open_audit(path: Path) -> int:
    absolute = path.absolute()
    if os.name == "nt":
        return _open_windows_audit(absolute)
    return _open_posix_audit(absolute)


def _open_posix_audit(path: Path) -> int:
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
            next_descriptor, created = _open_or_create_posix_directory(
                parent_descriptor, part, directory_flags
            )
            os.close(parent_descriptor)
            parent_descriptor = next_descriptor
            if created:
                os.fchmod(parent_descriptor, 0o700)

        flags = os.O_APPEND | os.O_CREAT | os.O_RDWR | no_follow | getattr(os, "O_CLOEXEC", 0)
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

    def _open_windows_audit(path: Path) -> int:
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
                next_handle, created = _open_or_create_windows_directory(parent_handle, part)
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
                )
                if open_result not in {_FILE_CREATED, _FILE_OPENED}:
                    raise OSError("native audit file returned an unexpected open result")
                _validate_windows_handle(final_handle, directory=False)
                _verify_windows_owner_only_dacl(final_handle, owner_sid)
            descriptor = msvcrt.open_osfhandle(
                final_handle, os.O_APPEND | os.O_RDWR | getattr(os, "O_BINARY", 0)
            )
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
        parent: int, name: str, security_descriptor: wintypes.LPVOID
    ) -> tuple[int, int]:
        deadline = time.monotonic() + _EXCLUSIVE_OPEN_TIMEOUT_SECONDS
        while True:
            try:
                return _nt_open_relative_result(
                    parent,
                    name,
                    desired_access=(
                        _GENERIC_READ | _GENERIC_WRITE | _SYNCHRONIZE | _READ_CONTROL
                    ),
                    disposition=_FILE_OPEN_IF,
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

    def _open_windows_audit(path: Path) -> int:
        del path
        raise OSError("Windows native audit opens are unavailable")

    def _lock_descriptor(descriptor: int) -> None:
        fcntl.flock(descriptor, fcntl.LOCK_EX)

    def _unlock_descriptor(descriptor: int) -> None:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
