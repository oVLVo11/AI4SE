from __future__ import annotations

import hashlib
import json
import multiprocessing
import os
import shutil
import struct
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import unquote
from uuid import uuid4

import pytest
from pydantic import Field

from pyquality.domain.models import AuditEvent as _AuditEvent
from pyquality.security import AuditLogger, AuditWriteError, redact


class AuditEvent(_AuditEvent):
    """Test fixture that supplies a fresh valid ID unless a replay ID is explicit."""

    event_id: str = Field(default_factory=lambda: uuid4().hex + uuid4().hex)


@pytest.fixture
def r4_tmp_path(tmp_path: Path) -> Path:
    """Remove owner-only R4 roots while the creating Windows token is still live."""
    yield tmp_path
    if os.name == "nt":
        from pyquality import security

        for directory, _, filenames in os.walk(tmp_path, topdown=False):
            for filename in filenames:
                target = Path(directory) / filename
                descriptor: int | None = None
                try:
                    descriptor = security._open_audit(
                        target,
                        append=False,
                        create=False,
                    )
                except OSError:
                    target.unlink(missing_ok=True)
                else:
                    try:
                        security._remove_open_audit(target, descriptor)
                    finally:
                        os.close(descriptor)
    shutil.rmtree(tmp_path)


def _set_process_environment(root: str) -> None:
    for name in ("HOME", "LOCALAPPDATA", "TEMP", "TMP", "USERPROFILE"):
        os.environ[name] = root


def _prepare_existing_audit(path: Path, content: bytes = b"") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        from pyquality import security

        descriptor = security._open_windows_audit(path)
        os.close(descriptor)
        if content:
            path.write_bytes(content)
        return
    path.write_bytes(content)


def test_prepare_existing_audit_creates_a_missing_posix_parent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """POSIX migration fixtures must be able to seed nested legacy audit paths."""
    path = tmp_path / "nested" / "audit.jsonl"
    monkeypatch.setattr(os, "name", "posix")

    _prepare_existing_audit(path, b"legacy\n")

    assert path.read_bytes() == b"legacy\n"


def _emit_in_process(path: str, start: int, count: int, environment_root: str) -> None:
    _set_process_environment(environment_root)
    logger = AuditLogger(Path(path))
    for index in range(start, start + count):
        logger.emit(AuditEvent(event_type="transition", metadata={"intent_id": f"intent-{index}"}))


def _emit_aliases(first: str, second: str, start: int, environment_root: str) -> None:
    _set_process_environment(environment_root)
    for index in range(start, start + 30):
        AuditLogger(Path(first if index % 2 else second)).emit(
            AuditEvent(event_type="transition", metadata={"intent_id": f"alias-{index}"})
        )


def _emit_while_write_is_held(
    path: str,
    environment_root: str,
    ready: object,
    release: object,
) -> None:
    _set_process_environment(environment_root)
    from pyquality import security

    real_write_all = security._write_all

    def held_write(descriptor: int, data: bytes) -> None:
        ready.set()  # type: ignore[attr-defined]
        if not release.wait(15):  # type: ignore[attr-defined]
            raise RuntimeError("timed out waiting to release audit write")
        real_write_all(descriptor, data)

    security._write_all = held_write
    security.AuditLogger(Path(path)).emit(
        AuditEvent(event_type="transition", metadata={"intent_id": "held"})
    )


def _emit_with_signals(path: str, environment_root: str, started: object, finished: object) -> None:
    _set_process_environment(environment_root)
    started.set()  # type: ignore[attr-defined]
    try:
        AuditLogger(Path(path)).emit(
            AuditEvent(event_type="transition", metadata={"intent_id": "contender"})
        )
    finally:
        finished.set()  # type: ignore[attr-defined]


def _replay_alias_once(
    path: str,
    event_id: str,
    environment_root: str,
    index_root: str | None = None,
) -> None:
    _set_process_environment(environment_root)
    options = {} if index_root is None else {"index_root": Path(index_root)}
    AuditLogger(Path(path), **options).emit(
        AuditEvent(event_id=event_id, event_type="transition")
    )


def _write_secure_test_file(path: Path, payloads: list[tuple[int, bytes]]) -> None:
    from pyquality import security

    descriptor = security._open_audit(path, append=False)
    try:
        for offset, payload in payloads:
            os.lseek(descriptor, offset, os.SEEK_SET)
            security._write_all(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _build_released_r4_audit_index(
    path: Path,
    index_base: Path,
    *,
    event_count: int,
) -> tuple[list[AuditEvent], list[bytes], Path, Path]:
    """Materialize the released 90b9c45 checkpoint and JSON receipt layout."""
    from pyquality import security

    logger = AuditLogger(path, index_root=index_base)
    events = [
        AuditEvent(
            event_id=f"{index + 1_000:064x}",
            event_type="transition",
            metadata={"status": "x" * 4_096},
        )
        for index in range(event_count)
    ]
    records = [logger._encode(event) for event in events]
    _prepare_existing_audit(path, b"".join(records))
    audit_descriptor = security._open_audit(path)
    try:
        identity = security._audit_stream_identity(audit_descriptor)
        new_root = security._audit_index_root(path, audit_descriptor, index_base)
    finally:
        os.close(audit_descriptor)
    legacy_root = path.absolute().parent / f".pyquality-audit-index-{identity}"
    offsets: list[int] = []
    position = 0
    for record in records:
        offsets.append(position)
        position += len(record)
    newest_generation = max(2, event_count)
    prior_count = max(0, event_count - 1)
    prior_size = offsets[-1] if records else 0
    checkpoint_payloads = []
    for generation, indexed_size, receipt_count in (
        (newest_generation - 1, prior_size, prior_count),
        (newest_generation, position, event_count),
    ):
        payload = security._CHECKPOINT_SLOT.pack(
            security._CHECKPOINT_MAGIC,
            generation,
            indexed_size,
            receipt_count,
            security._checkpoint_digest(generation, indexed_size, receipt_count),
        )
        checkpoint_payloads.append(
            ((generation % 2) * security._CHECKPOINT_SLOT.size, payload)
        )
    _write_secure_test_file(legacy_root / "checkpoint", checkpoint_payloads)
    for event, record, offset in zip(events, records, offsets, strict=True):
        receipt = (
            json.dumps(
                {
                    "digest": hashlib.sha256(record).hexdigest(),
                    "event_id": event.event_id,
                    "length": len(record),
                    "offset": offset,
                    "version": 1,
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
        _write_secure_test_file(
            legacy_root / "receipts" / event.event_id[:2] / event.event_id,
            [(0, receipt)],
        )
    return events, records, legacy_root, new_root


def test_redacts_nested_headers_urls_and_exception_text(tmp_path: Path) -> None:
    """Catches a recursive branch that preserves a credential in nested request data."""
    del tmp_path
    value = {
        "headers": {"Authorization": "Bearer sk-secret"},
        "url": "https://x.test/?api_key=sk-secret",
        "error": RuntimeError("failed with sk-secret"),
    }

    clean = redact(value, secrets={"sk-secret"}, sensitive_keys={"authorization", "api_key"})

    assert "sk-secret" not in json.dumps(clean)


def test_redacts_percent_encoded_registered_secret_in_url_query_and_path() -> None:
    """Catches a registered secret that only appears after percent-decoding URL components."""
    clean = redact(
        "https://x.test/sk%2Dsecret?note=sk%2Dsecret&other=%2Fsafe%2Fpath",
        secrets={"sk-secret"},
        sensitive_keys=set(),
    )
    assert "secret" not in clean
    assert "%2Fsafe%2Fpath" in clean


def test_redacts_decoded_url_keys_and_preserves_percent_literals_and_unicode() -> None:
    """Catches decoded query-key leakage or double-decoding literal percent and Unicode components."""
    clean = redact(
        "https://x.test/%E9%9B%AA%25?sk%2Dsecret=value&note=%2525%E9%9B%AA",
        secrets={"sk-secret"},
        sensitive_keys=set(),
    )
    assert "secret" not in clean
    assert "%2525" in clean
    assert "%E9%9B%AA" in clean


def test_url_redaction_preserves_raw_encoded_structure_while_redacting_decoded_secrets() -> None:
    """Catches whole-component decode/re-encode that changes encoded URL data into structure."""
    clean = redact(
        "https://x.test/keep%2Fdata/%5Bencoded%5D/%25/secret%2Fvalue"
        "?note=keep%2Fdata&bracket=%5Bencoded%5D&percent=%25"
        "&api%2Fkey=safe&plain=secret%2Fvalue",
        secrets={"secret/value", "api/key"},
        sensitive_keys=set(),
    )

    assert isinstance(clean, str)
    assert "secret/value" not in unquote(clean)
    assert "api/key" not in unquote(clean)
    assert "/keep%2Fdata/%5Bencoded%5D/%25/" in clean
    assert "note=keep%2Fdata" in clean
    assert "bracket=%5Bencoded%5D" in clean
    assert "percent=%25" in clean


def test_redact_handles_cycles_bytes_and_dangerous_objects_without_mutating_input() -> None:
    """Catches unsafe repr calls, non-JSON bytes, recursive traversal, or in-place redaction."""

    class Dangerous:
        def __repr__(self) -> str:
            raise AssertionError("repr must not be invoked")

        def __str__(self) -> str:
            raise AssertionError("str must not be invoked")

    original: dict[str, object] = {"payload": b"\xffsk-secret", "object": Dangerous()}
    original["self"] = original

    clean = redact(original, secrets={"sk-secret"}, sensitive_keys=set())

    assert original["payload"] == b"\xffsk-secret"
    assert clean["payload"] == "[REDACTED_BYTES]"
    assert clean["object"] == "[UNSUPPORTED_OBJECT]"
    assert clean["self"] == "[CYCLE]"
    assert "sk-secret" not in json.dumps(clean)


def test_redact_sanitizes_registered_secret_mapping_keys_and_resolves_collisions() -> None:
    """Catches key leaks and order-dependent overwrites after key redaction/truncation."""
    clean = redact(
        {"sk-secret": "first", "[REDACTED]": "second"},
        secrets={"sk-secret"},
        sensitive_keys=set(),
    )

    assert "sk-secret" not in json.dumps(clean)
    assert list(clean.values()) == ["first", "second"]
    assert len(clean) == 2


def test_redact_limits_lazy_generator_work_and_aggregate_output() -> None:
    """Catches eager list materialization and unbounded aggregate traversal."""

    pulls = 0

    def guarded_generator():
        nonlocal pulls
        for index in range(10_000):
            pulls += 1
            if index == 130:
                raise AssertionError("redaction consumed an unbounded generator")
            yield {"value": "x" * 2_000, "index": index}

    clean = redact(guarded_generator(), secrets=set(), sensitive_keys=set())

    assert isinstance(clean, list)
    assert len(json.dumps(clean).encode("utf-8")) <= 8_192
    assert clean[-1] == "[TRUNCATED]"
    assert pulls == 5


def test_redact_fallback_rechecks_a_huge_one_element_nested_result() -> None:
    """Catches returning an oversized first element from the aggregate-size fallback."""
    value = [
        {
            f"key-{index:03d}-" + ("k" * 64): "x" * 4_096
            for index in range(128)
        }
    ]

    clean = redact(value, secrets=set(), sensitive_keys=set())

    encoded = json.dumps(clean, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    assert len(encoded) <= 8_192


def test_audit_logger_rejects_configurable_sidecar_lock_authority(tmp_path: Path) -> None:
    """Catches allowing callers to select a lock namespace that can diverge across processes."""
    from pyquality import security

    with pytest.raises(TypeError):
        security.AuditLogger(tmp_path / "audit.jsonl", lock_root=tmp_path / "locks")


def test_audit_logger_constructor_performs_no_external_io(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Catches creating lock roots or audit parents before the first emit."""
    from pyquality import security

    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "app-data"))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "home"))
    real_mkdir = Path.mkdir
    created: list[Path] = []

    def recording_mkdir(path: Path, *args: object, **kwargs: object) -> None:
        created.append(path)
        real_mkdir(path, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", recording_mkdir)

    security.AuditLogger(tmp_path / "missing" / "audit.jsonl")

    assert created == []


def test_audit_logger_constructor_sanitizes_path_conversion_errors() -> None:
    """Catches exposing an OSError (and its sensitive text) from constructor path coercion."""
    from pyquality import security

    class ExplodingPath(os.PathLike[str]):
        def __fspath__(self) -> str:
            raise OSError("path contained sk-secret")

    with pytest.raises(AuditWriteError) as raised:
        security.AuditLogger(ExplodingPath())  # type: ignore[arg-type]

    assert "sk-secret" not in str(raised.value)
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None


def test_audit_path_creation_uses_only_descriptor_or_handle_relative_operations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Catches path-based check-then-create/open operations for audit components."""
    target = tmp_path / "new" / "nested" / "audit.jsonl"
    logger = AuditLogger(target)

    def forbidden(*_: object, **__: object) -> None:
        raise AssertionError("path-based filesystem operation used")

    with monkeypatch.context() as patcher:
        patcher.setattr(Path, "lstat", forbidden)
        patcher.setattr(Path, "mkdir", forbidden)
        patcher.setattr(Path, "open", forbidden)
        patcher.setattr(os, "chmod", forbidden)
        logger.emit(AuditEvent(event_type="transition", metadata={"intent_id": "safe-open"}))

    assert json.loads(target.read_text(encoding="utf-8"))["metadata"] == {
        "intent_id": "safe-open"
    }


def test_posix_audit_never_chmods_an_existing_shared_parent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catches changing the permissions of a pre-existing shared audit parent."""
    from types import SimpleNamespace

    from pyquality import security

    descriptors = iter((10, 11, 12))
    chmod_calls: list[tuple[int, int]] = []

    def fake_open(
        name: object,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        del name, flags, mode, dir_fd
        return next(descriptors)

    monkeypatch.setattr(security.os, "O_NOFOLLOW", 0x100, raising=False)
    monkeypatch.setattr(security.os, "O_DIRECTORY", 0x200, raising=False)
    monkeypatch.setattr(security.os, "open", fake_open)
    monkeypatch.setattr(security.os, "close", lambda _: None)
    monkeypatch.setattr(security.os, "fchmod", lambda fd, mode: chmod_calls.append((fd, mode)))
    monkeypatch.setattr(
        security.os,
        "fstat",
        lambda _: SimpleNamespace(st_mode=0o100600, st_uid=4242),
    )
    monkeypatch.setattr(security.os, "geteuid", lambda: 4242, raising=False)

    descriptor = security._open_posix_audit(Path("/shared/audit.jsonl"))

    assert descriptor == 12
    assert chmod_calls == [(12, 0o600)]


def test_posix_audit_chmods_only_directories_created_by_the_current_open(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catches failing to secure a newly created component while preserving existing parents."""
    from types import SimpleNamespace

    from pyquality import security

    next_descriptor = iter((20, 21, 22, 23))
    created: set[tuple[int, str]] = set()
    chmod_calls: list[tuple[int, int]] = []

    def fake_open(
        name: object,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        del flags, mode
        text = os.fspath(name)
        if text == "new" and (dir_fd, text) not in created:
            raise FileNotFoundError
        return next(next_descriptor)

    def fake_mkdir(name: str, mode: int, *, dir_fd: int) -> None:
        assert mode == 0o700
        created.add((dir_fd, name))

    monkeypatch.setattr(security.os, "O_NOFOLLOW", 0x100, raising=False)
    monkeypatch.setattr(security.os, "O_DIRECTORY", 0x200, raising=False)
    monkeypatch.setattr(security.os, "open", fake_open)
    monkeypatch.setattr(security.os, "mkdir", fake_mkdir)
    monkeypatch.setattr(security.os, "close", lambda _: None)
    monkeypatch.setattr(security.os, "fchmod", lambda fd, mode: chmod_calls.append((fd, mode)))
    monkeypatch.setattr(
        security.os,
        "fstat",
        lambda _: SimpleNamespace(st_mode=0o100600, st_uid=4242),
    )
    monkeypatch.setattr(security.os, "geteuid", lambda: 4242, raising=False)

    descriptor = security._open_posix_audit(Path("/shared/new/audit.jsonl"))

    assert descriptor == 23
    assert chmod_calls == [(22, 0o700), (23, 0o600)]


def test_posix_audit_refuses_a_final_file_owned_by_another_user(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catches appending to an attacker-owned regular file through an otherwise safe descriptor."""
    from types import SimpleNamespace

    from pyquality import security

    descriptors = iter((30, 31, 32))
    closed: list[int] = []

    def fake_open(*_: object, **__: object) -> int:
        return next(descriptors)

    monkeypatch.setattr(security.os, "O_NOFOLLOW", 0x100, raising=False)
    monkeypatch.setattr(security.os, "O_DIRECTORY", 0x200, raising=False)
    monkeypatch.setattr(security.os, "open", fake_open)
    monkeypatch.setattr(security.os, "close", closed.append)
    monkeypatch.setattr(security.os, "fchmod", lambda *_: None)
    monkeypatch.setattr(
        security.os,
        "fstat",
        lambda _: SimpleNamespace(st_mode=0o100600, st_uid=9999),
    )
    monkeypatch.setattr(security.os, "geteuid", lambda: 4242, raising=False)

    with pytest.raises(OSError, match="owner"):
        security._open_posix_audit(Path("/shared/audit.jsonl"))

    assert 32 in closed


def test_audit_log_omits_source_and_prompt_by_default(tmp_path: Path) -> None:
    """Catches accepting prompt/source-bearing metadata into a persisted audit record."""
    logger = AuditLogger(tmp_path / "audit.jsonl", secrets={"sk-secret"})

    logger.emit(AuditEvent(event_type="model", metadata={"prompt": "source body", "key": "sk-secret"}))

    text = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    assert "source body" not in text and "sk-secret" not in text


def test_audit_logger_replay_of_same_event_id_is_observable_once(
    tmp_path: Path,
) -> None:
    """A repository mark failure must not duplicate an already-appended JSONL event."""
    path = tmp_path / "audit.jsonl"
    event = AuditEvent(
        event_id="a" * 64,
        event_type="task_terminal",
        task_id="task-1",
        component="agent_loop",
        metadata={"status": "succeeded", "prompt": "source body"},
    )

    AuditLogger(path, secrets={"source body"}).emit(event)
    AuditLogger(path, secrets={"source body"}).emit(event)

    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert len(records) == 1
    assert records[0]["event_id"] == event.event_id
    assert "source body" not in json.dumps(records[0])


def test_audit_replay_of_old_event_uses_bounded_historical_log_io(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Exactly-once replay must not rescan all prior JSONL records under the lock."""
    from pyquality import security

    path = tmp_path / "audit.jsonl"
    logger = AuditLogger(path)
    events = [
        AuditEvent(
            event_id=f"{index:064x}",
            event_type="transition",
            metadata={"intent_id": f"intent-{index}-" + ("x" * 4_000)},
        )
        for index in range(96)
    ]
    for event in events:
        logger.emit(event)
    before = path.read_bytes()
    real_read = security.os.read
    bytes_read = 0

    def bounded_read(descriptor: int, count: int) -> bytes:
        nonlocal bytes_read
        chunk = real_read(descriptor, count)
        bytes_read += len(chunk)
        return chunk

    monkeypatch.setattr(security.os, "read", bounded_read)

    logger.emit(events[48])

    assert path.read_bytes() == before
    assert bytes_read <= 64 * 1_024


def test_huge_unterminated_audit_tail_fails_with_bounded_recovery_io(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Tail repair must not read or retain an attacker-sized malformed suffix."""
    from pyquality import security

    path = tmp_path / "audit.jsonl"
    malformed = b"x" * (1024 * 1024)
    _prepare_existing_audit(path, malformed)
    real_read = security.os.read
    bytes_read = 0

    def bounded_read(descriptor: int, count: int) -> bytes:
        nonlocal bytes_read
        chunk = real_read(descriptor, count)
        bytes_read += len(chunk)
        return chunk

    monkeypatch.setattr(security.os, "read", bounded_read)

    with pytest.raises(AuditWriteError) as raised:
        AuditLogger(path).emit(
            AuditEvent(event_id="d" * 64, event_type="transition")
        )

    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    assert bytes_read <= 128 * 1_024
    assert path.read_bytes() == malformed


def test_append_before_receipt_crash_replays_without_duplicate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A crash after JSONL fsync must rebuild its receipt from only the new suffix."""
    from pyquality import security

    path = tmp_path / "audit.jsonl"
    logger = AuditLogger(path)
    event = AuditEvent(
        event_id="e" * 64,
        event_type="task_terminal",
        metadata={"status": "succeeded"},
    )
    commit_receipt = security._commit_audit_receipt

    def fail_receipt(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise OSError("receipt fsync failed")

    monkeypatch.setattr(security, "_commit_audit_receipt", fail_receipt)
    with pytest.raises(AuditWriteError):
        logger.emit(event)
    assert len(path.read_bytes().splitlines()) == 1

    monkeypatch.setattr(security, "_commit_audit_receipt", commit_receipt)
    logger.emit(event)

    records = [json.loads(line) for line in path.read_bytes().splitlines()]
    assert [record["event_id"] for record in records] == [event.event_id]


def _prepare_receipt_directory_durability_logger(
    tmp_path: Path,
) -> tuple[AuditLogger, Path, Path]:
    """Create the audit index before recording receipt-publication calls."""
    from pyquality import security

    path = tmp_path / "audit.jsonl"
    index_base = tmp_path / "index"
    logger = AuditLogger(path, index_root=index_base)
    descriptor = security._open_audit(path)
    try:
        index_root = security._audit_index_root(path, descriptor, index_base)
        security._ensure_secure_audit_index_root(index_base, index_root)
    finally:
        os.close(descriptor)
    return logger, path, index_root


def test_receipt_directory_durability_normal_append_orders_receipt_before_checkpoint_clear(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing receipt-directory fsync would clear the reservation too early."""
    from pyquality import security

    logger, _, index_root = _prepare_receipt_directory_durability_logger(tmp_path)
    event = AuditEvent(event_id="d" * 64, event_type="transition")
    receipt_path = security._audit_receipt_path(index_root, event.event_id)
    calls: list[str] = []
    sync_calls: list[tuple[Path, Path]] = []
    receipt_descriptor: int | None = None
    real_open = security._open_audit
    real_fsync = security.os.fsync
    real_store = security._store_audit_checkpoint

    def record_open(
        target: Path,
        *,
        append: bool = True,
        create: bool = True,
    ) -> int:
        nonlocal receipt_descriptor
        descriptor = real_open(target, append=append, create=create)
        if Path(target) == receipt_path:
            receipt_descriptor = descriptor
        return descriptor

    def record_fsync(descriptor: int) -> None:
        real_fsync(descriptor)
        if descriptor == receipt_descriptor:
            calls.append("receipt-file-fsync")

    def record_sync(root: Path, leaf: Path) -> None:
        sync_calls.append((root, leaf))
        calls.append("receipt-directory-fsync")

    def record_store(*args: object, **kwargs: object):
        previous = args[1] if len(args) > 1 else kwargs.get("previous")
        if (
            previous is not None
            and previous.pending_event_id == event.event_id
            and kwargs.get("pending_event_id") is None
        ):
            calls.append("clear-pending-checkpoint")
        return real_store(*args, **kwargs)

    monkeypatch.setattr(security, "_open_audit", record_open)
    monkeypatch.setattr(security.os, "fsync", record_fsync)
    monkeypatch.setattr(security, "_sync_audit_directory_chain", record_sync)
    monkeypatch.setattr(security, "_store_audit_checkpoint", record_store)

    logger.emit(event)

    assert calls.index("receipt-file-fsync") < calls.index("receipt-directory-fsync")
    assert calls.index("receipt-directory-fsync") < calls.index("clear-pending-checkpoint")
    assert sync_calls == [(index_root, receipt_path.parent)]


def test_receipt_directory_durability_normal_append_sync_failure_retains_pending_checkpoint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A parent-directory failure must retain the exact durable reservation."""
    from pyquality import security

    logger, path, index_root = _prepare_receipt_directory_durability_logger(tmp_path)
    event = AuditEvent(event_id="e" * 64, event_type="transition")

    def fail_directory_sync(root: Path, leaf: Path) -> None:
        del root, leaf
        raise OSError("simulated directory sync failure")

    monkeypatch.setattr(security, "_sync_audit_directory_chain", fail_directory_sync)

    with pytest.raises(AuditWriteError):
        logger.emit(event)

    checkpoint_descriptor = security._open_audit(
        index_root / "checkpoint",
        append=False,
    )
    try:
        checkpoint = security._load_audit_checkpoint(
            checkpoint_descriptor,
            audit_size=path.stat().st_size,
        )
    finally:
        os.close(checkpoint_descriptor)
    assert checkpoint is not None
    assert checkpoint.pending_event_id == event.event_id
    assert checkpoint.committed_receipt_count == 0


def test_receipt_directory_durability_normal_append_recovers_after_post_sync_checkpoint_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failure after publication but before clearance must reconcile exactly once."""
    from pyquality import security

    logger, path, index_root = _prepare_receipt_directory_durability_logger(tmp_path)
    event = AuditEvent(event_id="f" * 64, event_type="transition")
    directory_synced = False
    faulted = False
    real_store = security._store_audit_checkpoint

    def record_sync(root: Path, leaf: Path) -> None:
        nonlocal directory_synced
        assert (root, leaf) == (
            index_root,
            security._audit_receipt_path(index_root, event.event_id).parent,
        )
        directory_synced = True

    def fail_once_after_directory_sync(*args: object, **kwargs: object):
        nonlocal faulted
        previous = args[1] if len(args) > 1 else kwargs.get("previous")
        if (
            not faulted
            and directory_synced
            and previous is not None
            and previous.pending_event_id == event.event_id
            and kwargs.get("pending_event_id") is None
        ):
            faulted = True
            raise OSError("simulated checkpoint-clear failure")
        return real_store(*args, **kwargs)

    monkeypatch.setattr(security, "_sync_audit_directory_chain", record_sync)
    monkeypatch.setattr(
        security,
        "_store_audit_checkpoint",
        fail_once_after_directory_sync,
    )

    with pytest.raises(AuditWriteError):
        logger.emit(event)
    assert directory_synced and faulted

    logger.emit(event)

    checkpoint_descriptor = security._open_audit(
        index_root / "checkpoint",
        append=False,
    )
    try:
        checkpoint = security._load_audit_checkpoint(
            checkpoint_descriptor,
            audit_size=path.stat().st_size,
        )
    finally:
        os.close(checkpoint_descriptor)
    assert checkpoint is not None
    assert checkpoint.pending_event_id is None
    assert checkpoint.committed_receipt_count == 1
    assert len(path.read_bytes().splitlines()) == 1
    assert security._audit_receipt_path(index_root, event.event_id).exists()


def test_receipt_directory_durability_normal_append_retry_resyncs_before_clearing_pending(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A visible receipt after failed publication must be synced again before it is counted."""
    from pyquality import security

    logger, path, index_root = _prepare_receipt_directory_durability_logger(tmp_path)
    event = AuditEvent(event_id="2" * 64, event_type="transition")
    receipt_parent = security._audit_receipt_path(index_root, event.event_id).parent
    sync_calls: list[tuple[Path, Path]] = []
    calls: list[str] = []
    real_store = security._store_audit_checkpoint

    def fail_then_record_sync(root: Path, leaf: Path) -> None:
        sync_calls.append((root, leaf))
        if len(sync_calls) == 1:
            raise OSError("simulated directory sync failure")
        calls.append("retry-receipt-directory-fsync")

    def record_store(*args: object, **kwargs: object):
        previous = args[1] if len(args) > 1 else kwargs.get("previous")
        if (
            previous is not None
            and previous.pending_event_id == event.event_id
            and kwargs.get("pending_event_id") is None
        ):
            calls.append("clear-pending-checkpoint")
        return real_store(*args, **kwargs)

    monkeypatch.setattr(security, "_sync_audit_directory_chain", fail_then_record_sync)
    monkeypatch.setattr(security, "_store_audit_checkpoint", record_store)

    with pytest.raises(AuditWriteError):
        logger.emit(event)
    checkpoint_descriptor = security._open_audit(index_root / "checkpoint", append=False)
    try:
        failed_checkpoint = security._load_audit_checkpoint(
            checkpoint_descriptor,
            audit_size=path.stat().st_size,
        )
    finally:
        os.close(checkpoint_descriptor)
    assert failed_checkpoint is not None
    assert failed_checkpoint.pending_event_id == event.event_id
    logger.emit(event)

    assert sync_calls == [(index_root, receipt_parent), (index_root, receipt_parent)]
    assert calls.index("retry-receipt-directory-fsync") < calls.index(
        "clear-pending-checkpoint"
    )
    checkpoint_descriptor = security._open_audit(index_root / "checkpoint", append=False)
    try:
        checkpoint = security._load_audit_checkpoint(
            checkpoint_descriptor,
            audit_size=path.stat().st_size,
        )
    finally:
        os.close(checkpoint_descriptor)
    assert checkpoint is not None
    assert checkpoint.pending_event_id is None
    assert checkpoint.committed_receipt_count == 1


def test_receipt_directory_durability_pending_retry_refsyncs_before_clearing_pending(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A valid cached receipt after fsync failure must be fsynced again before count advance."""
    from pyquality import security

    logger, path, index_root = _prepare_receipt_directory_durability_logger(tmp_path)
    event = AuditEvent(event_id="3" * 64, event_type="transition")
    receipt_path = security._audit_receipt_path(index_root, event.event_id)
    receipt_descriptors: set[int] = set()
    calls: list[str] = []
    fsync_faulted = False
    real_open = security._open_audit
    real_close = security.os.close
    real_fsync = security.os.fsync
    real_store = security._store_audit_checkpoint

    def record_open(
        target: Path,
        *,
        append: bool = True,
        create: bool = True,
    ) -> int:
        descriptor = real_open(target, append=append, create=create)
        if Path(target) == receipt_path:
            receipt_descriptors.add(descriptor)
        return descriptor

    def record_close(descriptor: int) -> None:
        receipt_descriptors.discard(descriptor)
        real_close(descriptor)

    def fail_then_record_receipt_fsync(descriptor: int) -> None:
        nonlocal fsync_faulted
        if descriptor in receipt_descriptors:
            if not fsync_faulted:
                fsync_faulted = True
                raise OSError("simulated receipt file fsync failure")
            calls.append("retry-receipt-file-fsync")
        real_fsync(descriptor)

    def record_sync(root: Path, leaf: Path) -> None:
        assert (root, leaf) == (index_root, receipt_path.parent)
        calls.append("retry-receipt-directory-fsync")

    def record_store(*args: object, **kwargs: object):
        previous = args[1] if len(args) > 1 else kwargs.get("previous")
        if (
            previous is not None
            and previous.pending_event_id == event.event_id
            and kwargs.get("pending_event_id") is None
        ):
            calls.append("clear-pending-checkpoint")
        return real_store(*args, **kwargs)

    monkeypatch.setattr(security, "_open_audit", record_open)
    monkeypatch.setattr(security.os, "close", record_close)
    monkeypatch.setattr(security.os, "fsync", fail_then_record_receipt_fsync)
    monkeypatch.setattr(security, "_sync_audit_directory_chain", record_sync)
    monkeypatch.setattr(security, "_store_audit_checkpoint", record_store)

    with pytest.raises(AuditWriteError):
        logger.emit(event)
    assert fsync_faulted
    logger.emit(event)

    assert calls.index("retry-receipt-file-fsync") < calls.index(
        "retry-receipt-directory-fsync"
    )
    assert calls.index("retry-receipt-directory-fsync") < calls.index(
        "clear-pending-checkpoint"
    )
    checkpoint_descriptor = security._open_audit(index_root / "checkpoint", append=False)
    try:
        checkpoint = security._load_audit_checkpoint(
            checkpoint_descriptor,
            audit_size=path.stat().st_size,
        )
    finally:
        os.close(checkpoint_descriptor)
    assert checkpoint is not None
    assert checkpoint.pending_event_id is None
    assert checkpoint.committed_receipt_count == 1


def test_receipt_directory_durability_reconciliation_orders_new_receipt_before_checkpoint_clear(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Suffix reconciliation must publish its new receipt before clearing pending work."""
    from pyquality import security

    path = tmp_path / "audit.jsonl"
    index_base = tmp_path / "index"
    logger = AuditLogger(path, index_root=index_base)
    event = AuditEvent(event_id="a" * 64, event_type="transition")
    _prepare_existing_audit(path, logger._encode(event))
    descriptor = security._open_audit(path)
    try:
        os.fsync(descriptor)
        index_root = security._audit_index_root(path, descriptor, index_base)
        security._ensure_secure_audit_index_root(index_base, index_root)
    finally:
        os.close(descriptor)
    receipt_path = security._audit_receipt_path(index_root, event.event_id)
    calls: list[str] = []
    sync_calls: list[tuple[Path, Path]] = []
    receipt_descriptor: int | None = None
    real_open = security._open_audit
    real_fsync = security.os.fsync
    real_store = security._store_audit_checkpoint

    def record_open(
        target: Path,
        *,
        append: bool = True,
        create: bool = True,
    ) -> int:
        nonlocal receipt_descriptor
        opened = real_open(target, append=append, create=create)
        if Path(target) == receipt_path:
            receipt_descriptor = opened
        return opened

    def record_fsync(opened: int) -> None:
        real_fsync(opened)
        if opened == receipt_descriptor:
            calls.append("receipt-file-fsync")

    def record_sync(root: Path, leaf: Path) -> None:
        sync_calls.append((root, leaf))
        calls.append("receipt-directory-fsync")

    def record_store(*args: object, **kwargs: object):
        previous = args[1] if len(args) > 1 else kwargs.get("previous")
        if (
            previous is not None
            and previous.pending_event_id == event.event_id
            and kwargs.get("pending_event_id") is None
        ):
            calls.append("clear-pending-checkpoint")
        return real_store(*args, **kwargs)

    monkeypatch.setattr(security, "_open_audit", record_open)
    monkeypatch.setattr(security.os, "fsync", record_fsync)
    monkeypatch.setattr(security, "_sync_audit_directory_chain", record_sync)
    monkeypatch.setattr(security, "_store_audit_checkpoint", record_store)

    logger.emit(event)

    assert calls.index("receipt-file-fsync") < calls.index("receipt-directory-fsync")
    assert calls.index("receipt-directory-fsync") < calls.index("clear-pending-checkpoint")
    assert sync_calls == [(index_root, receipt_path.parent)]


def test_receipt_directory_durability_reconciliation_sync_failure_retains_pending_checkpoint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A reconciliation directory failure must not count its pending suffix event."""
    from pyquality import security

    path = tmp_path / "audit.jsonl"
    index_base = tmp_path / "index"
    logger = AuditLogger(path, index_root=index_base)
    event = AuditEvent(event_id="b" * 64, event_type="transition")
    _prepare_existing_audit(path, logger._encode(event))
    descriptor = security._open_audit(path)
    try:
        os.fsync(descriptor)
        index_root = security._audit_index_root(path, descriptor, index_base)
        security._ensure_secure_audit_index_root(index_base, index_root)
    finally:
        os.close(descriptor)

    def fail_directory_sync(root: Path, leaf: Path) -> None:
        del root, leaf
        raise OSError("simulated directory sync failure")

    monkeypatch.setattr(security, "_sync_audit_directory_chain", fail_directory_sync)

    with pytest.raises(AuditWriteError):
        logger.emit(event)

    checkpoint_descriptor = security._open_audit(
        index_root / "checkpoint",
        append=False,
    )
    try:
        checkpoint = security._load_audit_checkpoint(
            checkpoint_descriptor,
            audit_size=path.stat().st_size,
        )
    finally:
        os.close(checkpoint_descriptor)
    assert checkpoint is not None
    assert checkpoint.pending_event_id == event.event_id
    assert checkpoint.committed_receipt_count == 0


def test_receipt_directory_durability_reconciliation_retry_resyncs_before_clearing_pending(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed suffix receipt publication must retry its exact parent before count advance."""
    from pyquality import security

    path = tmp_path / "audit.jsonl"
    index_base = tmp_path / "index"
    logger = AuditLogger(path, index_root=index_base)
    event = AuditEvent(event_id="1" * 64, event_type="transition")
    _prepare_existing_audit(path, logger._encode(event))
    descriptor = security._open_audit(path)
    try:
        os.fsync(descriptor)
        index_root = security._audit_index_root(path, descriptor, index_base)
        security._ensure_secure_audit_index_root(index_base, index_root)
    finally:
        os.close(descriptor)
    receipt_parent = security._audit_receipt_path(index_root, event.event_id).parent
    sync_calls: list[tuple[Path, Path]] = []
    calls: list[str] = []
    real_store = security._store_audit_checkpoint

    def fail_then_record_sync(root: Path, leaf: Path) -> None:
        sync_calls.append((root, leaf))
        if len(sync_calls) == 1:
            raise OSError("simulated directory sync failure")
        calls.append("retry-receipt-directory-fsync")

    def record_store(*args: object, **kwargs: object):
        previous = args[1] if len(args) > 1 else kwargs.get("previous")
        if (
            previous is not None
            and previous.pending_event_id == event.event_id
            and kwargs.get("pending_event_id") is None
        ):
            calls.append("clear-pending-checkpoint")
        return real_store(*args, **kwargs)

    monkeypatch.setattr(security, "_sync_audit_directory_chain", fail_then_record_sync)
    monkeypatch.setattr(security, "_store_audit_checkpoint", record_store)

    with pytest.raises(AuditWriteError):
        logger.emit(event)
    logger.emit(event)

    assert sync_calls == [(index_root, receipt_parent), (index_root, receipt_parent)]
    assert calls.index("retry-receipt-directory-fsync") < calls.index(
        "clear-pending-checkpoint"
    )
    checkpoint_descriptor = security._open_audit(index_root / "checkpoint", append=False)
    try:
        checkpoint = security._load_audit_checkpoint(
            checkpoint_descriptor,
            audit_size=path.stat().st_size,
        )
    finally:
        os.close(checkpoint_descriptor)
    assert checkpoint is not None
    assert checkpoint.pending_event_id is None
    assert checkpoint.committed_receipt_count == 1


def test_receipt_directory_durability_existing_receipt_skips_publication_sync(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Replaying an already verified receipt must not publish a directory entry again."""
    from pyquality import security

    logger, _, _ = _prepare_receipt_directory_durability_logger(tmp_path)
    event = AuditEvent(event_id="c" * 64, event_type="transition")
    logger.emit(event)
    sync_calls: list[tuple[Path, Path]] = []

    def record_sync(root: Path, leaf: Path) -> None:
        sync_calls.append((root, leaf))

    monkeypatch.setattr(security, "_sync_audit_directory_chain", record_sync)

    logger.emit(event)

    assert sync_calls == []


@pytest.mark.parametrize("written_bytes", [0, 1, 47])
def test_torn_receipt_update_retains_prior_valid_slot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    written_bytes: int,
) -> None:
    """A failed zero/partial/nonempty replacement must not destroy the durable receipt."""
    from pyquality import security

    path = tmp_path / "audit.jsonl"
    event = AuditEvent(event_id="6" * 64, event_type="transition")
    logger = AuditLogger(path)
    logger.emit(event)
    encoded = path.read_bytes()
    audit_descriptor = security._open_audit(path)
    try:
        index_root = security._audit_index_root(path, audit_descriptor)
    finally:
        os.close(audit_descriptor)
    receipt_descriptor = security._open_audit(
        security._audit_receipt_path(index_root, event.event_id),
        append=False,
    )
    real_write_all = security._write_all

    def torn_write(descriptor: int, payload: bytes) -> None:
        if written_bytes:
            os.write(descriptor, payload[:written_bytes])
        raise OSError("simulated torn receipt write")

    monkeypatch.setattr(security, "_write_all", torn_write)
    try:
        with pytest.raises(OSError, match="torn receipt"):
            security._commit_audit_receipt(
                receipt_descriptor,
                event.event_id,
                0,
                encoded,
                created=False,
                index_root=index_root,
                receipt_parent=security._audit_receipt_path(
                    index_root,
                    event.event_id,
                ).parent,
            )
    finally:
        os.close(receipt_descriptor)
        monkeypatch.setattr(security, "_write_all", real_write_all)

    logger.emit(event)

    records = [json.loads(line) for line in path.read_bytes().splitlines()]
    assert [record["event_id"] for record in records] == [event.event_id]


def test_failed_log_append_cannot_commit_index_before_visible_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A pre-append failure must leave no receipt capable of suppressing the retry."""
    from pyquality import security

    path = tmp_path / "audit.jsonl"
    logger = AuditLogger(path)
    event = AuditEvent(event_id="f" * 64, event_type="transition")
    write_record = security._write_audit_record

    def fail_record(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise OSError("audit append failed")

    monkeypatch.setattr(security, "_write_audit_record", fail_record)
    with pytest.raises(AuditWriteError):
        logger.emit(event)
    assert path.read_bytes() == b""

    monkeypatch.setattr(security, "_write_audit_record", write_record)
    logger.emit(event)

    assert json.loads(path.read_text(encoding="utf-8"))["event_id"] == event.event_id


def test_audit_receipt_index_has_explicit_rotation_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Per-event receipts must have a durable count ceiling, not unbounded disk growth."""
    from pyquality import security

    monkeypatch.setattr(security, "_MAX_AUDIT_RECEIPTS", 2)
    path = tmp_path / "audit.jsonl"
    logger = AuditLogger(path)
    events = [
        AuditEvent(event_id=str(index) * 64, event_type="transition")
        for index in range(1, 4)
    ]
    logger.emit(events[0])
    logger.emit(events[1])
    logger.emit(events[0])

    with pytest.raises(security.AuditRecoveryRequired):
        logger.emit(events[2])

    records = [json.loads(line) for line in path.read_bytes().splitlines()]
    assert [record["event_id"] for record in records] == [
        events[0].event_id,
        events[1].event_id,
    ]


def test_receipt_capacity_rejection_creates_no_rejected_id_sidecar(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Capacity must be reserved before opening a distinct receipt with create semantics."""
    from pyquality import security

    monkeypatch.setattr(security, "_MAX_AUDIT_RECEIPTS", 1)
    path = tmp_path / "audit.jsonl"
    accepted = AuditEvent(event_id="1" * 64, event_type="transition")
    rejected = AuditEvent(event_id="2" * 64, event_type="transition")
    logger = AuditLogger(path)
    logger.emit(accepted)
    descriptor = security._open_audit(path)
    try:
        index_root = security._audit_index_root(path, descriptor)
    finally:
        os.close(descriptor)

    with pytest.raises(security.AuditRecoveryRequired):
        logger.emit(rejected)

    assert not security._audit_receipt_path(index_root, rejected.event_id).exists()
    assert [
        item.name
        for item in (index_root / "receipts").rglob("*")
        if item.is_file()
    ] == [accepted.event_id]


def test_concurrent_receipt_capacity_allows_one_id_without_orphan_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The audit-stream lock must serialize capacity reservation and receipt creation."""
    from pyquality import security

    monkeypatch.setattr(security, "_MAX_AUDIT_RECEIPTS", 1)
    path = tmp_path / "audit.jsonl"
    events = [
        AuditEvent(event_id=character * 64, event_type="transition")
        for character in ("3", "4")
    ]

    def emit(event: AuditEvent) -> str:
        try:
            AuditLogger(path).emit(event)
        except security.AuditRecoveryRequired:
            return "rejected"
        return "accepted"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(emit, events))

    assert sorted(outcomes) == ["accepted", "rejected"]
    descriptor = security._open_audit(path)
    try:
        index_root = security._audit_index_root(path, descriptor)
    finally:
        os.close(descriptor)
    receipt_files = [
        item
        for item in (index_root / "receipts").rglob("*")
        if item.is_file()
    ]
    assert len(receipt_files) == 1
    assert len(path.read_bytes().splitlines()) == 1


def test_corrupt_latest_checkpoint_recovers_from_prior_slot_without_rescan(
    tmp_path: Path,
) -> None:
    """A torn newest checkpoint must retain the prior durable recovery frontier."""
    from pyquality import security

    path = tmp_path / "audit.jsonl"
    logger = AuditLogger(path)
    first = AuditEvent(event_id="7" * 64, event_type="transition")
    second = AuditEvent(event_id="8" * 64, event_type="transition")
    logger.emit(first)
    descriptor = security._open_audit(path)
    try:
        index_root = security._audit_index_root(path, descriptor)
    finally:
        os.close(descriptor)
    checkpoint_path = index_root / "checkpoint"
    checkpoint_descriptor = security._open_audit(checkpoint_path, append=False)
    try:
        checkpoint = security._load_audit_checkpoint(checkpoint_descriptor)
    finally:
        os.close(checkpoint_descriptor)
    assert checkpoint is not None
    newest_slot = checkpoint[0] % 2
    encoded = bytearray(checkpoint_path.read_bytes())
    encoded[newest_slot * security._CHECKPOINT_SLOT.size] ^= 0xFF
    checkpoint_path.write_bytes(encoded)

    logger.emit(second)
    logger.emit(first)

    records = [json.loads(line) for line in path.read_bytes().splitlines()]
    assert [record["event_id"] for record in records] == [
        first.event_id,
        second.event_id,
    ]


def test_legacy_r5_checkpoint_decodes_without_pending_reservation(
    tmp_path: Path,
) -> None:
    """A released R5 checkpoint must upgrade without inventing pending work."""
    from pyquality import security

    checkpoint_path = tmp_path / "checkpoint"
    generation = 7
    indexed_size = 4_096
    receipt_count = 3
    payload = security._CHECKPOINT_SLOT.pack(
        security._CHECKPOINT_MAGIC,
        generation,
        indexed_size,
        receipt_count,
        security._checkpoint_digest(generation, indexed_size, receipt_count),
    )
    descriptor = security._open_audit(checkpoint_path, append=False)
    try:
        security._write_all(descriptor, payload)
        os.fsync(descriptor)
        checkpoint = security._load_audit_checkpoint(descriptor)
    finally:
        os.close(descriptor)

    assert checkpoint is not None
    assert checkpoint.generation == generation
    assert checkpoint.indexed_size == indexed_size
    assert checkpoint.committed_receipt_count == receipt_count
    assert checkpoint.pending_event_id is None
    assert checkpoint.pending_start_offset is None


def test_pending_checkpoint_generation_round_trips(tmp_path: Path) -> None:
    """A missing pending field write would allow receipt creation without durable capacity."""
    from pyquality import security

    checkpoint_path = tmp_path / "checkpoint"
    descriptor = security._open_audit(checkpoint_path, append=False)
    try:
        stored = security._store_audit_checkpoint(
            descriptor,
            None,
            indexed_size=512,
            committed_receipt_count=4,
            pending_event_id="a" * 64,
            pending_start_offset=512,
        )
        loaded = security._load_audit_checkpoint(descriptor, audit_size=640)
    finally:
        os.close(descriptor)

    assert loaded == stored
    assert loaded is not None
    assert loaded.pending_event_id == "a" * 64
    assert loaded.pending_start_offset == 512


@pytest.mark.parametrize("kind", ["corrupt", "future"])
def test_checkpoint_decoder_rejects_unrecoverable_or_future_format(
    tmp_path: Path,
    kind: str,
) -> None:
    """An unreadable sole checkpoint must fail typed instead of triggering a history scan."""
    from pyquality import security

    generation = 1
    indexed_size = 0
    receipt_count = 0
    digest = security._checkpoint_digest(generation, indexed_size, receipt_count)
    if kind == "corrupt":
        digest = b"x" * len(digest)
    magic = security._CHECKPOINT_MAGIC if kind == "corrupt" else b"PQAIDX9\0"
    checkpoint_path = tmp_path / "checkpoint"
    payload = security._CHECKPOINT_SLOT.pack(
        magic,
        generation,
        indexed_size,
        receipt_count,
        digest,
    )
    descriptor = security._open_audit(checkpoint_path, append=False)
    try:
        security._write_all(descriptor, payload)
        os.fsync(descriptor)
        with pytest.raises(security.AuditRecoveryRequired):
            security._load_audit_checkpoint(descriptor)
    finally:
        os.close(descriptor)


def test_torn_new_pending_checkpoint_retains_older_valid_generation(
    tmp_path: Path,
) -> None:
    """A torn inactive-slot update must not destroy the last durable reservation."""
    from pyquality import security

    checkpoint_path = tmp_path / "checkpoint"
    descriptor = security._open_audit(checkpoint_path, append=False)
    try:
        older = security._store_audit_checkpoint(
            descriptor,
            None,
            indexed_size=0,
            committed_receipt_count=0,
            pending_event_id="b" * 64,
            pending_start_offset=0,
        )
        newest = security._store_audit_checkpoint(
            descriptor,
            older,
            indexed_size=0,
            committed_receipt_count=0,
            pending_event_id="c" * 64,
            pending_start_offset=0,
        )
        newest_offset = (
            security._CHECKPOINT_V2_REGION_OFFSET
            + (newest.generation % 2) * security._CHECKPOINT_V2_SLOT.size
        )
        os.lseek(descriptor, newest_offset, os.SEEK_SET)
        first_byte = os.read(descriptor, 1)
        os.lseek(descriptor, newest_offset, os.SEEK_SET)
        os.write(descriptor, bytes([first_byte[0] ^ 0xFF]))
        os.fsync(descriptor)
        loaded = security._load_audit_checkpoint(descriptor, audit_size=0)
    finally:
        os.close(descriptor)

    assert loaded == older


def test_repeated_preappend_failures_keep_only_one_pending_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Distinct failed appends must not accumulate uncounted receipt sidecars."""
    from pyquality import security

    monkeypatch.setattr(security, "_MAX_AUDIT_RECEIPTS", 1)
    path = tmp_path / "audit.jsonl"
    index_base = tmp_path / "index"
    events = [
        AuditEvent(event_id=character * 64, event_type="transition")
        for character in ("1", "2", "3", "4")
    ]

    def fail_before_append(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise OSError("simulated pre-append failure")

    monkeypatch.setattr(security, "_write_audit_record", fail_before_append)
    logger = AuditLogger(path, index_root=index_base)
    for event in events:
        with pytest.raises(AuditWriteError):
            logger.emit(event)

    descriptor = security._open_audit(path)
    try:
        index_root = security._audit_index_root(path, descriptor, index_base)
        audit_size = os.lseek(descriptor, 0, os.SEEK_END)
    finally:
        os.close(descriptor)
    receipt_paths = [
        security._audit_receipt_path(index_root, event.event_id) for event in events
    ]
    checkpoint_descriptor = security._open_audit(
        index_root / "checkpoint",
        append=False,
    )
    try:
        checkpoint = security._load_audit_checkpoint(
            checkpoint_descriptor,
            audit_size=audit_size,
        )
    finally:
        os.close(checkpoint_descriptor)

    assert path.read_bytes() == b""
    assert sum(receipt_path.exists() for receipt_path in receipt_paths) == 1
    assert checkpoint is not None
    assert checkpoint.committed_receipt_count == 0
    assert checkpoint.pending_event_id == events[-1].event_id


@pytest.mark.parametrize(
    ("stage", "record_was_appended"),
    [
        ("pending_checkpoint_fsynced", False),
        ("receipt_created", False),
        ("before_append", False),
        ("append_fsynced", True),
        ("receipt_committed", True),
        ("before_final_checkpoint", True),
    ],
)
def test_pending_reservation_recovers_each_crash_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
    record_was_appended: bool,
) -> None:
    """Restart must clear an unused reservation or complete an appended one exactly once."""
    from pyquality import security

    monkeypatch.setattr(security, "_MAX_AUDIT_RECEIPTS", 1)
    path = tmp_path / "audit.jsonl"
    index_base = tmp_path / "index"
    first = AuditEvent(event_id="a" * 64, event_type="transition")
    second = AuditEvent(event_id="b" * 64, event_type="transition")
    faulted = False
    real_open = security._open_audit
    real_store = security._store_audit_checkpoint
    real_write = security._write_audit_record
    real_commit = security._commit_audit_receipt

    def fail_once() -> None:
        nonlocal faulted
        if not faulted:
            faulted = True
            raise OSError(f"simulated crash at {stage}")

    def faulting_open(
        target: Path,
        *,
        append: bool = True,
        create: bool = True,
    ) -> int:
        descriptor = real_open(target, append=append, create=create)
        if stage == "receipt_created" and Path(target).name == first.event_id:
            os.close(descriptor)
            fail_once()
        return descriptor

    def faulting_store(*args: object, **kwargs: object):
        previous = args[1] if len(args) > 1 else kwargs.get("previous")
        pending_event_id = kwargs.get("pending_event_id")
        if (
            stage == "before_final_checkpoint"
            and previous is not None
            and previous.pending_event_id == first.event_id
            and pending_event_id is None
        ):
            fail_once()
        stored = real_store(*args, **kwargs)
        if (
            stage == "pending_checkpoint_fsynced"
            and stored.pending_event_id == first.event_id
        ):
            fail_once()
        return stored

    def faulting_write(descriptor: int, encoded: bytes) -> None:
        if stage == "before_append":
            fail_once()
        real_write(descriptor, encoded)
        if stage == "append_fsynced":
            fail_once()

    def faulting_commit(
        descriptor: int,
        event_id: str,
        offset: int,
        encoded: bytes,
        *,
        created: bool,
        index_root: Path,
        receipt_parent: Path,
    ) -> None:
        real_commit(
            descriptor,
            event_id,
            offset,
            encoded,
            created=created,
            index_root=index_root,
            receipt_parent=receipt_parent,
        )
        if stage == "receipt_committed" and event_id == first.event_id:
            fail_once()

    with monkeypatch.context() as fault:
        fault.setattr(security, "_open_audit", faulting_open)
        fault.setattr(security, "_store_audit_checkpoint", faulting_store)
        fault.setattr(security, "_write_audit_record", faulting_write)
        fault.setattr(security, "_commit_audit_receipt", faulting_commit)
        with pytest.raises(AuditWriteError):
            AuditLogger(path, index_root=index_base).emit(first)
    assert faulted

    recovered = AuditLogger(path, index_root=index_base)
    if record_was_appended:
        with pytest.raises(security.AuditRecoveryRequired):
            recovered.emit(second)
        recovered.emit(first)
        expected_ids = [first.event_id]
    else:
        recovered.emit(second)
        expected_ids = [second.event_id]

    records = [json.loads(line) for line in path.read_bytes().splitlines()]
    assert [record["event_id"] for record in records] == expected_ids
    descriptor = security._open_audit(path)
    try:
        index_root = security._audit_index_root(path, descriptor, index_base)
    finally:
        os.close(descriptor)
    assert not security._audit_receipt_path(index_root, first.event_id).exists() or record_was_appended
    assert sum(
        security._audit_receipt_path(index_root, event.event_id).exists()
        for event in (first, second)
    ) == 1


@pytest.mark.parametrize("pending_bytes", ["different_event", "oversized_record"])
def test_pending_recovery_rejects_unauthenticated_complete_bytes_without_create(
    tmp_path: Path,
    pending_bytes: str,
) -> None:
    """Pending recovery must not bless mismatched or over-bound bytes as its event."""
    from pyquality import security

    path = tmp_path / "audit.jsonl"
    index_base = tmp_path / "index"
    pending = AuditEvent(event_id="c" * 64, event_type="transition")
    probe = AuditEvent(event_id="d" * 64, event_type="transition")
    logger = AuditLogger(path, index_root=index_base)
    descriptor = security._open_audit(path)
    try:
        index_root = security._audit_index_root(path, descriptor, index_base)
        security._ensure_secure_audit_index_root(index_base, index_root)
        checkpoint_descriptor = security._open_audit(
            index_root / "checkpoint",
            append=False,
        )
        try:
            security._store_audit_checkpoint(
                checkpoint_descriptor,
                None,
                indexed_size=0,
                committed_receipt_count=0,
                pending_event_id=pending.event_id,
                pending_start_offset=0,
            )
        finally:
            os.close(checkpoint_descriptor)
        if pending_bytes == "different_event":
            encoded = logger._encode(
                AuditEvent(event_id="e" * 64, event_type="transition")
            )
        else:
            encoded = b"x" * (security._MAX_RECORD_BYTES + 1) + b"\n"
        security._write_audit_record(descriptor, encoded)
    finally:
        os.close(descriptor)

    with pytest.raises(security.AuditRecoveryRequired) as raised:
        logger.emit(probe)

    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    assert not security._audit_receipt_path(index_root, pending.event_id).exists()
    assert not security._audit_receipt_path(index_root, probe.event_id).exists()


@pytest.mark.parametrize(
    "stage",
    ["reservation_checkpoint", "receipt_commit", "completion_checkpoint"],
)
def test_suffix_reconciliation_resumes_each_reserved_record_stage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
) -> None:
    """A reconciliation crash must resume its one pending suffix record idempotently."""
    from pyquality import security

    path = tmp_path / "audit.jsonl"
    index_base = tmp_path / "index"
    logger = AuditLogger(path, index_root=index_base)
    seeds = [
        AuditEvent(event_id=character * 64, event_type="transition")
        for character in ("5", "6")
    ]
    initial = b"".join(logger._encode(event) for event in seeds)
    _prepare_existing_audit(path, initial)
    first = seeds[0]
    faulted = False
    real_store = security._store_audit_checkpoint
    real_commit = security._commit_audit_receipt

    def fail_once() -> None:
        nonlocal faulted
        if not faulted:
            faulted = True
            raise OSError(f"simulated reconciliation crash at {stage}")

    def faulting_store(*args: object, **kwargs: object):
        previous = args[1] if len(args) > 1 else kwargs.get("previous")
        pending_event_id = kwargs.get("pending_event_id")
        if (
            stage == "completion_checkpoint"
            and previous is not None
            and previous.pending_event_id == first.event_id
            and pending_event_id is None
        ):
            fail_once()
        stored = real_store(*args, **kwargs)
        if (
            stage == "reservation_checkpoint"
            and stored.pending_event_id == first.event_id
        ):
            fail_once()
        return stored

    def faulting_commit(
        descriptor: int,
        event_id: str,
        offset: int,
        encoded: bytes,
        *,
        created: bool,
        index_root: Path,
        receipt_parent: Path,
    ) -> None:
        real_commit(
            descriptor,
            event_id,
            offset,
            encoded,
            created=created,
            index_root=index_root,
            receipt_parent=receipt_parent,
        )
        if stage == "receipt_commit" and event_id == first.event_id:
            fail_once()

    with monkeypatch.context() as fault:
        fault.setattr(security, "_store_audit_checkpoint", faulting_store)
        fault.setattr(security, "_commit_audit_receipt", faulting_commit)
        with pytest.raises(AuditWriteError):
            logger.emit(AuditEvent(event_id="7" * 64, event_type="transition"))
    assert faulted

    logger.emit(first)

    records = [json.loads(line) for line in path.read_bytes().splitlines()]
    assert [record["event_id"] for record in records] == [
        event.event_id for event in seeds
    ]
    descriptor = security._open_audit(path)
    try:
        index_root = security._audit_index_root(path, descriptor, index_base)
        audit_size = os.lseek(descriptor, 0, os.SEEK_END)
    finally:
        os.close(descriptor)
    checkpoint_descriptor = security._open_audit(
        index_root / "checkpoint",
        append=False,
    )
    try:
        checkpoint = security._load_audit_checkpoint(
            checkpoint_descriptor,
            audit_size=audit_size,
        )
    finally:
        os.close(checkpoint_descriptor)
    assert checkpoint is not None
    assert checkpoint.pending_event_id is None
    assert checkpoint.committed_receipt_count == len(seeds)


def test_audit_id_scan_ignores_nested_id_in_oversized_legacy_record(
    tmp_path: Path,
) -> None:
    """A bounded scan must not mistake an over-limit nested key for a top-level ID."""
    path = tmp_path / "audit.jsonl"
    event_id = "b" * 64
    _prepare_existing_audit(
        path,
        b'{"metadata":{"padding":"'
        + (b"x" * 20_000)
        + b'","event_id":"'
        + event_id.encode("ascii")
        + b'"}}\n',
    )
    event = AuditEvent(
        event_id=event_id,
        event_type="task_terminal",
        task_id="task-1",
        component="agent_loop",
        metadata={"status": "succeeded"},
    )

    AuditLogger(path).emit(event)

    records = path.read_bytes().splitlines()
    assert len(records) == 2
    assert json.loads(records[-1])["event_id"] == event_id


def test_audit_id_scan_detects_top_level_id_across_read_boundary(tmp_path: Path) -> None:
    """Chunking must retain exact-once behavior when the bounded ID spans two reads."""
    path = tmp_path / "audit.jsonl"
    event = AuditEvent(
        event_id="c" * 64,
        event_type="task_terminal",
        task_id="task-1",
        component="agent_loop",
        metadata={"status": "succeeded"},
    )
    logger = AuditLogger(path)
    encoded = logger._encode(event)
    initial = (b"x" * 65_529) + b"\n" + encoded
    _prepare_existing_audit(path, initial)

    logger.emit(event)

    assert path.read_bytes() == initial


def test_audit_log_accepts_only_allowlisted_metadata_and_normalizes_aliases(tmp_path: Path) -> None:
    """Catches body-bearing aliases bypassing a denylist instead of an approved metadata schema."""
    logger = AuditLogger(tmp_path / "audit.jsonl")
    logger.emit(
        AuditEvent(
            event_type="transition",
            metadata={
                "intentId": "intent-1",
                "actionDigest": "a" * 64,
                "payload": "source body",
                "messages": [{"content": "source body"}],
                "completion": "source body",
                "conversation": "source body",
            },
        )
    )

    record = json.loads((tmp_path / "audit.jsonl").read_text(encoding="utf-8"))
    assert record["metadata"] == {"action_digest": "a" * 64, "intent_id": "intent-1"}


def test_audit_allowlisted_fields_drop_nested_and_wrong_scalar_types(tmp_path: Path) -> None:
    """Catches recursive body persistence under an otherwise approved metadata key."""
    logger = AuditLogger(tmp_path / "audit.jsonl")
    logger.emit(
        AuditEvent(
            event_type="transition",
            metadata={"intent_id": {"prompt": "body"}, "digest": ["body"], "status": True, "duration": True},
        )
    )
    record = json.loads((tmp_path / "audit.jsonl").read_text(encoding="utf-8"))
    assert record["metadata"] == {}
    assert record["duration"] is None


@pytest.mark.parametrize("value", [True, 10**1000, float("nan"), float("inf"), -1, 86_401])
def test_audit_drops_invalid_duration_without_dropping_event(tmp_path: Path, value: object) -> None:
    """Catches unbounded, non-finite, boolean, or semantically invalid durations entering audit JSON."""
    path = tmp_path / "audit.jsonl"
    AuditLogger(path).emit(AuditEvent(event_type="transition", metadata={"duration": value, "intent_id": "ok"}))
    record = json.loads(path.read_text(encoding="utf-8"))
    assert record["duration"] is None
    assert record["metadata"] == {"intent_id": "ok"}


@pytest.mark.parametrize("value", [0, 86_400, 1.5])
def test_audit_accepts_bounded_finite_duration(tmp_path: Path, value: float) -> None:
    """Catches rejecting the documented finite duration boundary values."""
    path = tmp_path / "audit.jsonl"
    AuditLogger(path).emit(AuditEvent(event_type="transition", metadata={"duration": value}))
    assert json.loads(path.read_text(encoding="utf-8"))["duration"] == value


def test_audit_record_cap_applies_after_duration_and_outcome_fallback(tmp_path: Path) -> None:
    """Catches a fallback that omits metadata but persists unbounded envelope outcome fields."""
    logger = AuditLogger(tmp_path / "audit.jsonl")
    logger.emit(
        AuditEvent(
            event_type="model",
            metadata={
                "duration": 1.5,
                "outcome": "ok",
                "intent_id": "x" * 10_000,
                "approval_id": "x" * 10_000,
                "action_digest": "x" * 10_000,
                "digest": "x" * 10_000,
                "status": "x" * 10_000,
                "decision": "x" * 10_000,
            },
        )
    )

    record = json.loads((tmp_path / "audit.jsonl").read_text(encoding="utf-8"))
    assert len((tmp_path / "audit.jsonl").read_bytes().rstrip(b"\n")) <= 16_384
    assert record["metadata"] == {"truncated": "[TRUNCATED]"}
    assert (record["duration"], record["outcome"]) == (1.5, "ok")


def test_audit_retries_short_os_write_until_the_jsonl_record_is_complete(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Catches a partial kernel write that would otherwise leave a truncated JSONL record."""
    from pyquality import security

    real_write = security.os.write

    def short_write(descriptor: int, data: bytes) -> int:
        return real_write(descriptor, data[: max(1, len(data) // 3)])

    monkeypatch.setattr(security.os, "write", short_write)
    path = tmp_path / "audit.jsonl"
    AuditLogger(path).emit(AuditEvent(event_type="model", metadata={"intent_id": "ok"}))
    assert json.loads(path.read_text(encoding="utf-8"))["metadata"] == {"intent_id": "ok"}


def test_audit_multi_process_hardlink_aliases_share_one_complete_record_stream(tmp_path: Path) -> None:
    """Catches lexical sidecar locks that do not converge when two names share one audit inode."""
    left = tmp_path / "left"
    right = tmp_path / "right"
    left.mkdir()
    right.mkdir()
    path = left / "audit.jsonl"
    _prepare_existing_audit(path)
    alias = right / "audit-alias.jsonl"
    try:
        os.link(path, alias)
    except OSError as error:
        pytest.skip(f"hardlink creation unavailable: {error.__class__.__name__}")
    context = multiprocessing.get_context("spawn")
    processes = [
        context.Process(
            target=_emit_aliases,
            args=(str(path), str(alias), index * 30, str(tmp_path / f"environment-{index}")),
        )
        for index in range(2)
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(20)
        assert process.exitcode == 0
    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert {record["metadata"]["intent_id"] for record in records} == {f"alias-{index}" for index in range(60)}


def test_default_index_replays_large_stream_through_cross_process_hardlink_alias(
    tmp_path: Path,
) -> None:
    """Default sidecar identity must not depend on the audit file's lexical parent."""
    from pyquality import security

    left = tmp_path / "left"
    right = tmp_path / "right"
    left.mkdir()
    right.mkdir()
    path = left / "audit.jsonl"
    logger = AuditLogger(path)
    events = [
        AuditEvent(
            event_id=f"{index:064x}",
            event_type="transition",
            metadata={"status": "x" * 4_096},
        )
        for index in range(72)
    ]
    for event in events:
        logger.emit(event)
    assert path.stat().st_size > security._MAX_INDEX_REBUILD_BYTES
    before = path.read_bytes()
    alias = right / "audit-alias.jsonl"
    try:
        os.link(path, alias)
    except OSError as error:
        pytest.skip(f"hardlink creation unavailable: {error.__class__.__name__}")

    context = multiprocessing.get_context("spawn")
    process = context.Process(
        target=_replay_alias_once,
        args=(
            str(alias),
            events[-1].event_id,
            str(tmp_path / "different-environment"),
        ),
    )
    process.start()
    process.join(20)

    assert process.exitcode == 0
    assert path.read_bytes() == before


def test_configured_index_root_is_shared_by_hardlink_alias_processes(
    tmp_path: Path,
) -> None:
    """A configured secure global root must key receipts by the opened stream identity."""
    left = tmp_path / "configured-left"
    right = tmp_path / "configured-right"
    left.mkdir()
    right.mkdir()
    path = left / "audit.jsonl"
    index_root = tmp_path / "shared-index"
    logger = AuditLogger(path, index_root=index_root)
    events = [
        AuditEvent(
            event_id=f"{index + 100:064x}",
            event_type="transition",
            metadata={"status": "y" * 4_096},
        )
        for index in range(72)
    ]
    for event in events:
        logger.emit(event)
    before = path.read_bytes()
    alias = right / "audit-alias.jsonl"
    try:
        os.link(path, alias)
    except OSError as error:
        pytest.skip(f"hardlink creation unavailable: {error.__class__.__name__}")

    context = multiprocessing.get_context("spawn")
    process = context.Process(
        target=_replay_alias_once,
        args=(
            str(alias),
            events[-1].event_id,
            str(tmp_path / "configured-environment"),
            str(index_root),
        ),
    )
    process.start()
    process.join(20)

    assert process.exitcode == 0
    assert path.read_bytes() == before


def test_released_r4_large_index_migrates_without_historical_log_scan(
    r4_tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Upgrade must replay an old R4 ID beyond the bounded suffix without rescanning JSONL."""
    from pyquality import security

    tmp_path = r4_tmp_path
    path = tmp_path / "legacy" / "audit.jsonl"
    index_base = tmp_path / "new-index"
    events, _, legacy_root, new_root = _build_released_r4_audit_index(
        path,
        index_base,
        event_count=66,
    )
    before = path.read_bytes()
    assert len(before) > security._MAX_INDEX_REBUILD_BYTES
    audit_stat = path.stat()
    read_requests: list[tuple[int, int]] = []
    real_read_at = security._read_at

    def bounded_read_at(descriptor: int, offset: int, length: int) -> bytes:
        information = os.fstat(descriptor)
        if (information.st_dev, information.st_ino) == (
            audit_stat.st_dev,
            audit_stat.st_ino,
        ):
            read_requests.append((offset, length))
        return real_read_at(descriptor, offset, length)

    monkeypatch.setattr(security, "_read_at", bounded_read_at)

    AuditLogger(path, index_root=index_base).emit(events[0])

    assert path.read_bytes() == before
    assert read_requests
    assert max(length for _, length in read_requests) <= security._MAX_RECORD_BYTES + 1
    assert all(length != len(before) for _, length in read_requests)
    assert (new_root / "migration").is_file()
    assert security._audit_receipt_path(new_root, events[0].event_id).is_file()
    assert legacy_root.is_dir()


@pytest.mark.parametrize(
    "defect",
    [
        "permissive",
        "foreign_owner",
        "corrupt_checkpoint",
        "over_cap",
        "receipt_mismatch",
    ],
)
def test_invalid_released_r4_index_fails_closed_without_copying(
    r4_tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    defect: str,
) -> None:
    """Invalid R4 evidence must not be ignored in favor of a silent small-log rebuild."""
    from pyquality import security

    tmp_path = r4_tmp_path
    path = tmp_path / defect / "audit.jsonl"
    index_base = tmp_path / f"new-{defect}"
    events, _, legacy_root, new_root = _build_released_r4_audit_index(
        path,
        index_base,
        event_count=2,
    )
    checkpoint_path = legacy_root / "checkpoint"
    first_receipt = security._audit_receipt_path(legacy_root, events[0].event_id)
    if defect == "permissive":
        if os.name == "nt":
            _windows_set_test_dacl(
                checkpoint_path,
                "D:(A;;FA;;;WD)",
                protected=False,
            )
        else:
            os.chmod(checkpoint_path, 0o644)
    elif defect == "foreign_owner":
        real_validate = security._validate_existing_r4_audit_directory

        def reject_foreign_owner(candidate: Path) -> None:
            if candidate == legacy_root.absolute():
                raise OSError("simulated foreign owner")
            real_validate(candidate)

        monkeypatch.setattr(
            security,
            "_validate_existing_r4_audit_directory",
            reject_foreign_owner,
        )
    elif defect == "corrupt_checkpoint":
        encoded = bytearray(checkpoint_path.read_bytes())
        encoded[0] ^= 0xFF
        encoded[security._CHECKPOINT_SLOT.size] ^= 0xFF
        _write_secure_test_file(checkpoint_path, [(0, bytes(encoded))])
    elif defect == "over_cap":
        monkeypatch.setattr(security, "_MAX_AUDIT_RECEIPTS", 1)
    else:
        receipt_descriptor = security._open_audit(
            first_receipt,
            append=False,
            create=False,
        )
        try:
            receipt = json.loads(
                security._read_at(
                    receipt_descriptor,
                    0,
                    security._MAX_RECEIPT_BYTES,
                )
            )
        finally:
            os.close(receipt_descriptor)
        receipt["digest"] = "0" * 64
        payload = (
            json.dumps(
                receipt,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
        _write_secure_test_file(first_receipt, [(0, payload)])

    with pytest.raises(security.AuditRecoveryRequired) as raised:
        AuditLogger(path, index_root=index_base).emit(events[0])

    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    assert str(legacy_root) not in str(raised.value)
    assert not (new_root / "migration").exists()
    assert not security._audit_receipt_path(new_root, events[0].event_id).exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows inherited DACL regression")
@pytest.mark.parametrize(
    "sddl",
    [
        "D:(A;OICIID;FA;;;WD)",
        "D:(A;OICIID;0x1301bf;;;BU)",
        "D:(A;OICIID;0x1301bf;;;AU)",
    ],
)
def test_released_r4_directory_rejects_untrusted_inherited_writers(
    r4_tmp_path: Path,
    sddl: str,
) -> None:
    """Inherited broad principals must not gain mutation authority over R4 evidence."""
    from pyquality import security

    path = r4_tmp_path / "unsafe-directory" / "audit.jsonl"
    index_base = r4_tmp_path / "unsafe-directory-index"
    events, _, legacy_root, new_root = _build_released_r4_audit_index(
        path, index_base, event_count=2
    )
    parent_sddl = "D:P(A;OICI;FA;;;OW)" + sddl.removeprefix("D:").replace(
        "OICIID", "OICI"
    )
    _windows_set_test_dacl(
        legacy_root.parent,
        parent_sddl,
        protected=True,
        directory=True,
    )
    _windows_set_test_dacl(
        legacy_root,
        sddl,
        protected=False,
        directory=True,
    )

    with pytest.raises(security.AuditRecoveryRequired):
        AuditLogger(path, index_root=index_base).emit(events[0])

    assert not (new_root / "migration").exists()


def test_r4_candidate_rejects_a_wrong_encoded_stream_identity(
    r4_tmp_path: Path,
) -> None:
    """A legacy directory name for another inode must never become migration authority."""
    from pyquality import security

    tmp_path = r4_tmp_path
    expected_identity = "1a-2b"
    wrong_root = tmp_path / ".pyquality-audit-index-3c-4d"

    with pytest.raises(security.AuditRecoveryRequired):
        security._validate_r4_audit_index_identity(
            wrong_root,
            expected_identity,
        )


def test_released_r4_directory_link_is_not_followed(r4_tmp_path: Path) -> None:
    """Migration must not follow a linked R4 namespace component to attacker data."""
    from pyquality import security

    tmp_path = r4_tmp_path
    path = tmp_path / "linked-legacy" / "audit.jsonl"
    index_base = tmp_path / "linked-new"
    events, _, legacy_root, new_root = _build_released_r4_audit_index(
        path,
        index_base,
        event_count=2,
    )
    outside = tmp_path / "outside-legacy"
    legacy_root.rename(outside)
    try:
        legacy_root.symlink_to(outside, target_is_directory=True)
    except OSError as error:
        outside.rename(legacy_root)
        pytest.skip(f"directory link creation unavailable: {error.__class__.__name__}")

    with pytest.raises(security.AuditRecoveryRequired):
        AuditLogger(path, index_root=index_base).emit(events[0])

    assert not (new_root / "migration").exists()
    assert outside.is_dir()


def test_released_r4_conflicts_with_existing_committed_r5_data(
    r4_tmp_path: Path,
) -> None:
    """A partially populated R5 root must not silently merge a released R4 namespace."""
    from pyquality import security

    tmp_path = r4_tmp_path
    path = tmp_path / "conflict" / "audit.jsonl"
    index_base = tmp_path / "conflict-new"
    events, records, legacy_root, new_root = _build_released_r4_audit_index(
        path,
        index_base,
        event_count=2,
    )
    security._ensure_secure_audit_index_root(index_base, new_root)
    receipt_descriptor = security._open_audit(
        security._audit_receipt_path(new_root, events[0].event_id),
        append=False,
    )
    try:
        security._commit_audit_receipt(
            receipt_descriptor,
            events[0].event_id,
            0,
            records[0],
            created=True,
            index_root=new_root,
            receipt_parent=security._audit_receipt_path(
                new_root,
                events[0].event_id,
            ).parent,
        )
    finally:
        os.close(receipt_descriptor)
    checkpoint_descriptor = security._open_audit(
        new_root / "checkpoint",
        append=False,
    )
    try:
        security._store_audit_checkpoint(
            checkpoint_descriptor,
            None,
            indexed_size=len(records[0]),
            committed_receipt_count=1,
        )
    finally:
        os.close(checkpoint_descriptor)

    with pytest.raises(security.AuditRecoveryRequired) as raised:
        AuditLogger(path, index_root=index_base).emit(events[1])

    assert str(legacy_root) not in str(raised.value)
    assert not security._audit_receipt_path(new_root, events[1].event_id).exists()
    assert not (new_root / "migration").exists()


@pytest.mark.parametrize(
    "stage",
    [
        "before_marker",
        "before_receipt_copy",
        "after_receipt_fsync",
        "before_completed_marker",
    ],
)
def test_r4_migration_interruption_resumes_and_hardlink_alias_converges(
    r4_tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
) -> None:
    """Every migration crash point must resume idempotently before alias replay."""
    from pyquality import security

    tmp_path = r4_tmp_path
    left = tmp_path / f"left-{stage}"
    right = tmp_path / f"right-{stage}"
    left.mkdir()
    right.mkdir()
    path = left / "audit.jsonl"
    alias = right / "audit-alias.jsonl"
    index_base = tmp_path / f"new-{stage}"
    events, _, _, new_root = _build_released_r4_audit_index(
        path,
        index_base,
        event_count=4,
    )
    before = path.read_bytes()
    try:
        os.link(path, alias)
    except OSError as error:
        pytest.skip(f"hardlink creation unavailable: {error.__class__.__name__}")
    faulted = False

    def migration_fault(current_stage: str) -> None:
        nonlocal faulted
        if current_stage == stage and not faulted:
            faulted = True
            raise OSError(f"simulated migration crash at {stage}")

    with monkeypatch.context() as fault:
        fault.setattr(
            security,
            "_audit_migration_fault",
            migration_fault,
            raising=False,
        )
        with pytest.raises(AuditWriteError):
            AuditLogger(path, index_root=index_base).emit(events[0])
    assert faulted
    assert path.read_bytes() == before

    AuditLogger(path, index_root=index_base).emit(events[0])
    context = multiprocessing.get_context("spawn")
    process = context.Process(
        target=_replay_alias_once,
        args=(
            str(alias),
            events[-1].event_id,
            str(tmp_path / f"environment-{stage}"),
            str(index_base),
        ),
    )
    process.start()
    process.join(20)

    assert process.exitcode == 0
    assert path.read_bytes() == before
    assert (new_root / "migration").is_file()


def test_receipt_directory_durability_r4_retry_resyncs_before_cursor_advance(
    r4_tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A visible migration target after sync failure must not advance its cursor unsynced."""
    from pyquality import security

    path = r4_tmp_path / "migration-retry" / "audit.jsonl"
    index_base = r4_tmp_path / "migration-retry-index"
    events, _, _, index_root = _build_released_r4_audit_index(
        path,
        index_base,
        event_count=1,
    )
    event = events[0]
    receipt_parent = security._audit_receipt_path(index_root, event.event_id).parent
    sync_calls: list[tuple[Path, Path]] = []

    def fail_then_record_receipt_sync(root: Path, leaf: Path) -> None:
        if (root, leaf) != (index_root, receipt_parent):
            return
        sync_calls.append((root, leaf))
        if len(sync_calls) == 1:
            raise OSError("simulated migration receipt directory sync failure")

    def load_marker_state():
        audit_descriptor = security._open_audit(path, create=False)
        try:
            identity = security._audit_stream_identity(audit_descriptor)
            audit_size = os.lseek(audit_descriptor, 0, os.SEEK_END)
        finally:
            os.close(audit_descriptor)
        marker_descriptor = security._open_audit(
            index_root / "migration",
            append=False,
            create=False,
        )
        try:
            return security._load_r4_migration_state(
                marker_descriptor,
                source_identity=identity,
                audit_size=audit_size,
            )
        finally:
            os.close(marker_descriptor)

    monkeypatch.setattr(
        security,
        "_sync_audit_directory_chain",
        fail_then_record_receipt_sync,
    )

    with pytest.raises(AuditWriteError):
        AuditLogger(path, index_root=index_base).emit(event)
    assert load_marker_state().next_cursor == 0

    AuditLogger(path, index_root=index_base).emit(event)

    assert sync_calls == [(index_root, receipt_parent), (index_root, receipt_parent)]
    state = load_marker_state()
    assert state.next_cursor == 1
    assert state.completed is True


def test_receipt_directory_durability_r4_retry_refsyncs_before_cursor_advance(
    r4_tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A cached R4 target after fsync failure must be fsynced before cursor advance."""
    from pyquality import security

    path = r4_tmp_path / "migration-refsync" / "audit.jsonl"
    index_base = r4_tmp_path / "migration-refsync-index"
    events, _, _, index_root = _build_released_r4_audit_index(
        path,
        index_base,
        event_count=1,
    )
    event = events[0]
    receipt_path = security._audit_receipt_path(index_root, event.event_id)
    receipt_descriptors: set[int] = set()
    calls: list[str] = []
    fsync_faulted = False
    real_open = security._open_audit
    real_close = security.os.close
    real_fsync = security.os.fsync
    real_store_state = security._store_r4_migration_state

    def record_open(
        target: Path,
        *,
        append: bool = True,
        create: bool = True,
    ) -> int:
        descriptor = real_open(target, append=append, create=create)
        if Path(target) == receipt_path:
            receipt_descriptors.add(descriptor)
        return descriptor

    def record_close(descriptor: int) -> None:
        receipt_descriptors.discard(descriptor)
        real_close(descriptor)

    def fail_then_record_receipt_fsync(descriptor: int) -> None:
        nonlocal fsync_faulted
        if descriptor in receipt_descriptors:
            if not fsync_faulted:
                fsync_faulted = True
                raise OSError("simulated migration receipt file fsync failure")
            calls.append("retry-receipt-file-fsync")
        real_fsync(descriptor)

    def record_sync(root: Path, leaf: Path) -> None:
        if (root, leaf) == (index_root, receipt_path.parent):
            calls.append("retry-receipt-directory-fsync")

    def record_state(*args: object, **kwargs: object):
        if kwargs.get("next_cursor") == 1:
            calls.append("advance-r4-cursor")
        return real_store_state(*args, **kwargs)

    monkeypatch.setattr(security, "_open_audit", record_open)
    monkeypatch.setattr(security.os, "close", record_close)
    monkeypatch.setattr(security.os, "fsync", fail_then_record_receipt_fsync)
    monkeypatch.setattr(security, "_sync_audit_directory_chain", record_sync)
    monkeypatch.setattr(security, "_store_r4_migration_state", record_state)

    with pytest.raises(AuditWriteError):
        AuditLogger(path, index_root=index_base).emit(event)
    assert fsync_faulted
    AuditLogger(path, index_root=index_base).emit(event)

    assert calls.index("retry-receipt-file-fsync") < calls.index(
        "retry-receipt-directory-fsync"
    )
    assert calls.index("retry-receipt-directory-fsync") < calls.index(
        "advance-r4-cursor"
    )


def test_completed_r4_marker_allows_live_checkpoint_to_advance(
    r4_tmp_path: Path,
) -> None:
    """A frozen migration frontier must not reject later committed R5 appends."""
    tmp_path = r4_tmp_path
    path = tmp_path / "completed" / "audit.jsonl"
    index_base = tmp_path / "completed-index"
    legacy, _, _, _ = _build_released_r4_audit_index(
        path,
        index_base,
        event_count=2,
    )
    first_live = AuditEvent(event_id="f" * 64, event_type="transition")
    second_live = AuditEvent(event_id="e" * 64, event_type="transition")
    logger = AuditLogger(path, index_root=index_base)

    logger.emit(legacy[0])
    logger.emit(first_live)
    logger.emit(second_live)
    logger.emit(first_live)

    event_ids = [json.loads(line)["event_id"] for line in path.read_bytes().splitlines()]
    assert event_ids == [event.event_id for event in legacy] + [
        first_live.event_id,
        second_live.event_id,
    ]


@pytest.mark.parametrize(
    "scenario", ["torn_upgrade", "torn_sidecar", "zero_sidecar", "mixed_future"]
)
def test_completed_pqamig1_marker_replays_and_upgrades_in_place(
    r4_tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scenario: str,
) -> None:
    """A committed marker from 63b08cf remains authoritative after the format upgrade."""
    from pyquality import security

    path = r4_tmp_path / "v1-marker" / "audit.jsonl"
    index_base = r4_tmp_path / "v1-marker-index"
    events, _, _, new_root = _build_released_r4_audit_index(
        path, index_base, event_count=3
    )
    AuditLogger(path, index_root=index_base).emit(events[0])
    marker_path = new_root / "migration"
    audit_descriptor = security._open_audit(path, create=False)
    try:
        identity = security._audit_stream_identity(audit_descriptor)
        audit_size = os.lseek(audit_descriptor, 0, os.SEEK_END)
    finally:
        os.close(audit_descriptor)
    encoded_identity = identity.encode("ascii").ljust(64, b"\0")
    generation = 2
    legacy_slot = struct.Struct(">8sQ64sQQQQB32s111x")
    legacy_digest = hashlib.sha256(
        struct.pack(
            ">Q64sQQQQB",
            generation,
            encoded_identity,
            2,
            len(events),
            len(events),
            audit_size,
            True,
        )
    ).digest()
    legacy_payload = legacy_slot.pack(
        b"PQAMIG1\0",
        generation,
        encoded_identity,
        2,
        len(events),
        len(events),
        audit_size,
        True,
        legacy_digest,
    )
    descriptor = security._open_audit(marker_path, append=False, create=False)
    try:
        os.ftruncate(descriptor, 0)
        security._write_all(descriptor, bytes(legacy_slot.size) + legacy_payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)

    if scenario == "mixed_future":
        future_payload = b"PQAMIG9\0" + legacy_payload[8:]
        _write_secure_test_file(marker_path, [(0, legacy_payload), (legacy_slot.size, future_payload)])
        with pytest.raises(security.AuditRecoveryRequired):
            AuditLogger(path, index_root=index_base).emit(events[-1])
        return

    real_write = security._write_all
    v2_writes = 0

    def tear_main_upgrade(descriptor: int, payload: bytes) -> None:
        nonlocal v2_writes
        if payload.startswith(security._R4_MIGRATION_MAGIC):
            v2_writes += 1
            target_write = 1 if scenario in {"torn_sidecar", "zero_sidecar"} else 2
            if v2_writes == target_write:
                if scenario != "zero_sidecar":
                    real_write(descriptor, payload[: len(payload) // 2])
                os.fsync(descriptor)
                raise OSError("simulated torn main-marker upgrade")
        real_write(descriptor, payload)

    with monkeypatch.context() as fault:
        fault.setattr(security, "_write_all", tear_main_upgrade)
        with pytest.raises(AuditWriteError):
            AuditLogger(path, index_root=index_base).emit(events[-1])

    AuditLogger(path, index_root=index_base).emit(events[-1])

    assert marker_path.read_bytes().startswith(security._R4_MIGRATION_MAGIC)


@pytest.mark.parametrize(
    "staging_kind", ["zero", "partial", "random", "corrupt_current", "future"]
)
def test_invalid_staging_fails_closed_with_valid_completed_v2_main(
    r4_tmp_path: Path,
    staging_kind: str,
) -> None:
    from pyquality import security

    path = r4_tmp_path / "future-staging" / "audit.jsonl"
    index_base = r4_tmp_path / "future-staging-index"
    events, _, _, new_root = _build_released_r4_audit_index(
        path, index_base, event_count=2
    )
    AuditLogger(path, index_root=index_base).emit(events[0])
    marker = (new_root / "migration").read_bytes()
    assert marker.startswith(security._R4_MIGRATION_MAGIC)
    if staging_kind == "zero":
        staging = b""
    elif staging_kind == "partial":
        staging = marker[: security._R4_MIGRATION_SLOT.size // 2]
    elif staging_kind == "random":
        staging = b"not-a-marker"
    elif staging_kind == "future":
        staging = b"PQAMIG9\0" + marker[8:]
    else:
        damaged = bytearray(marker)
        for slot in range(2):
            digest_offset = (
                slot * security._R4_MIGRATION_SLOT.size
                + security._R4_MIGRATION_SLOT.size
                - 141
            )
            if digest_offset < len(damaged):
                damaged[digest_offset] ^= 0xFF
        staging = bytes(damaged)
    _write_secure_test_file(new_root / "migration-v2", [(0, staging)])

    with pytest.raises(security.AuditRecoveryRequired):
        AuditLogger(path, index_root=index_base).emit(events[-1])


@pytest.mark.skipif(os.name != "nt", reason="Windows token ACL semantics")
@pytest.mark.parametrize("attributes", [0, 0x10])
def test_disabled_or_deny_only_token_group_is_not_acl_trusted(attributes: int) -> None:
    from pyquality import security

    assert not security._windows_group_attributes_allow_trust(attributes)


@pytest.mark.skipif(os.name != "nt", reason="Windows inherited ACL semantics")
@pytest.mark.parametrize("flags", [0, 0x1, 0x2, 0x7])
def test_parent_ace_must_propagate_to_bless_inherited_child(flags: int) -> None:
    from pyquality import security

    assert not security._windows_parent_ace_can_propagate(flags)


def test_completed_r4_marker_allows_pending_r5_recovery(
    r4_tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A post-migration pending append must recover beyond the immutable frontier."""
    from pyquality import security

    tmp_path = r4_tmp_path
    path = tmp_path / "pending-live" / "audit.jsonl"
    index_base = tmp_path / "pending-live-index"
    legacy, _, _, _ = _build_released_r4_audit_index(
        path,
        index_base,
        event_count=2,
    )
    logger = AuditLogger(path, index_root=index_base)
    logger.emit(legacy[0])
    live = AuditEvent(event_id="d" * 64, event_type="transition")
    real_commit = security._commit_audit_receipt

    def fail_before_receipt_commit(
        descriptor: int,
        event_id: str,
        offset: int,
        encoded: bytes,
        *,
        created: bool,
        index_root: Path,
        receipt_parent: Path,
    ) -> None:
        if event_id == live.event_id:
            raise OSError("simulated post-migration receipt crash")
        real_commit(
            descriptor,
            event_id,
            offset,
            encoded,
            created=created,
            index_root=index_root,
            receipt_parent=receipt_parent,
        )

    with monkeypatch.context() as fault:
        fault.setattr(security, "_commit_audit_receipt", fail_before_receipt_commit)
        with pytest.raises(AuditWriteError):
            logger.emit(live)

    AuditLogger(path, index_root=index_base).emit(live)

    event_ids = [json.loads(line)["event_id"] for line in path.read_bytes().splitlines()]
    assert event_ids.count(live.event_id) == 1


def test_incomplete_r4_migration_resumes_first_through_hardlink_alias(
    r4_tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The durable marker must reopen its source when the current alias has no R4 root."""
    from pyquality import security

    tmp_path = r4_tmp_path
    left = tmp_path / "alias-source"
    right = tmp_path / "alias-resume"
    left.mkdir()
    right.mkdir()
    path = left / "audit.jsonl"
    alias = right / "audit.jsonl"
    index_base = tmp_path / "alias-index"
    events, _, _, _ = _build_released_r4_audit_index(
        path,
        index_base,
        event_count=4,
    )
    before = path.read_bytes()
    try:
        os.link(path, alias)
    except OSError as error:
        pytest.skip(f"hardlink creation unavailable: {error.__class__.__name__}")
    faulted = False

    def fault_after_first_receipt(stage: str) -> None:
        nonlocal faulted
        if stage == "after_receipt_fsync" and not faulted:
            faulted = True
            raise OSError("simulated first-receipt crash")

    with monkeypatch.context() as fault:
        fault.setattr(security, "_audit_migration_fault", fault_after_first_receipt)
        with pytest.raises(AuditWriteError):
            AuditLogger(path, index_root=index_base).emit(events[0])
    assert faulted

    AuditLogger(alias, index_root=index_base).emit(events[-1])

    assert path.read_bytes() == before


@pytest.mark.parametrize("torn_write", ["marker", "checkpoint"])
def test_first_r4_migration_write_can_tear_twice_and_reinitialize(
    r4_tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    torn_write: str,
) -> None:
    """No valid first slot must be safely reconstructible without blessing conflicts."""
    from pyquality import security

    tmp_path = r4_tmp_path
    path = tmp_path / f"torn-{torn_write}" / "audit.jsonl"
    index_base = tmp_path / f"torn-{torn_write}-index"
    events, _, _, _ = _build_released_r4_audit_index(
        path,
        index_base,
        event_count=3,
    )
    before = path.read_bytes()
    real_write = security._write_all
    magic = (
        security._R4_MIGRATION_MAGIC
        if torn_write == "marker"
        else security._CHECKPOINT_V2_MAGIC
    )

    for _ in range(2):
        faulted = False

        def tear_first_slot(descriptor: int, data: bytes) -> None:
            nonlocal faulted
            if data.startswith(magic) and not faulted:
                real_write(descriptor, data[: len(data) // 2])
                os.fsync(descriptor)
                faulted = True
                raise OSError("simulated torn first slot")
            real_write(descriptor, data)

        with monkeypatch.context() as fault:
            fault.setattr(security, "_write_all", tear_first_slot)
            with pytest.raises(AuditWriteError):
                AuditLogger(path, index_root=index_base).emit(events[0])
        assert faulted

    AuditLogger(path, index_root=index_base).emit(events[0])

    assert path.read_bytes() == before


def test_configured_index_namespace_rejects_directory_link(
    tmp_path: Path,
) -> None:
    """The shared namespace and identity leaf must be reached without following links."""
    outside = tmp_path / "outside-index"
    outside.mkdir()
    linked_root = tmp_path / "linked-index"
    try:
        linked_root.symlink_to(outside, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"directory link creation unavailable: {error.__class__.__name__}")
    audit = tmp_path / "audit.jsonl"

    with pytest.raises(AuditWriteError):
        AuditLogger(audit, index_root=linked_root).emit(
            AuditEvent(event_id="5" * 64, event_type="transition")
        )

    assert tuple(outside.iterdir()) == ()
    assert audit.read_bytes() == b""


def test_configured_index_uses_distinct_opened_file_identities(
    tmp_path: Path,
) -> None:
    """Equal event IDs in distinct streams must not share a lexical receipt namespace."""
    index_base = tmp_path / "identity-index"
    event = AuditEvent(event_id="a" * 64, event_type="transition")
    first = tmp_path / "first" / "audit.jsonl"
    second = tmp_path / "second" / "audit.jsonl"

    AuditLogger(first, index_root=index_base).emit(event)
    AuditLogger(second, index_root=index_base).emit(event)

    assert first.read_bytes() == second.read_bytes()
    assert len([item for item in index_base.iterdir() if item.is_dir()]) == 2


def test_audit_file_lock_excludes_live_hardlink_alias_writer_with_different_environment_root(
    tmp_path: Path,
) -> None:
    """Catches sidecar locks that do not exclude a live writer through another hardlink name."""
    left = tmp_path / "left"
    right = tmp_path / "right"
    left.mkdir()
    right.mkdir()
    path = left / "audit.jsonl"
    _prepare_existing_audit(path)
    alias = right / "audit-alias.jsonl"
    try:
        os.link(path, alias)
    except OSError as error:
        pytest.skip(f"hardlink creation unavailable: {error.__class__.__name__}")

    context = multiprocessing.get_context("spawn")
    ready = context.Event()
    release = context.Event()
    contender_started = context.Event()
    contender_finished = context.Event()
    holder = context.Process(
        target=_emit_while_write_is_held,
        args=(str(path), str(tmp_path / "environment-holder"), ready, release),
    )
    contender = context.Process(
        target=_emit_with_signals,
        args=(
            str(alias),
            str(tmp_path / "environment-contender"),
            contender_started,
            contender_finished,
        ),
    )
    holder.start()
    assert ready.wait(15)
    assert path.stat().st_size == 0
    contender.start()
    assert contender_started.wait(15)
    was_excluded = not contender_finished.wait(1)
    release.set()
    holder.join(20)
    contender.join(20)

    assert was_excluded
    assert (holder.exitcode, contender.exitcode) == (0, 0)
    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert {record["metadata"]["intent_id"] for record in records} == {"held", "contender"}


def test_audit_normalizes_lone_surrogates_to_valid_utf8(tmp_path: Path) -> None:
    """Catches a Unicode encoding error from strings that contain a lone surrogate."""
    logger = AuditLogger(tmp_path / "audit.jsonl")
    logger.emit(AuditEvent.model_construct(event_type="model\ud800", metadata={"intent_id": "ok\udcff"}))

    text = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    assert "\ud800" not in text and "\udcff" not in text


@pytest.mark.parametrize("linked_component", ["final", "parent"])
def test_audit_rejects_final_and_parent_symlink_targets(
    tmp_path: Path, linked_component: str
) -> None:
    """Catches following either final-file or parent-directory links outside the audit root."""
    outside = tmp_path / "outside.txt"
    outside.write_text("outside\n", encoding="utf-8")
    outside_dir = tmp_path / "outside-dir"
    outside_dir.mkdir()
    if linked_component == "final":
        path = tmp_path / "audit.jsonl"
        link_target = outside
        is_directory = False
    else:
        parent_link = tmp_path / "audit-parent"
        path = parent_link / "audit.jsonl"
        link_target = outside_dir
        is_directory = True
    try:
        (path if linked_component == "final" else path.parent).symlink_to(
            link_target, target_is_directory=is_directory
        )
    except OSError as error:
        pytest.skip(
            f"{linked_component} symlink creation unavailable: {error.__class__.__name__}"
        )

    with pytest.raises(AuditWriteError) as raised:
        AuditLogger(path).emit(AuditEvent(event_type="model", metadata={"intent_id": "ok"}))
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    assert outside.read_text(encoding="utf-8") == "outside\n"
    assert not (outside_dir / "audit.jsonl").exists()


def _windows_current_owner_sid() -> tuple[object, object]:
    import ctypes
    from ctypes import wintypes

    class TokenOwner(ctypes.Structure):
        _fields_ = [("Owner", wintypes.LPVOID)]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    get_current_process = kernel32.GetCurrentProcess
    get_current_process.restype = wintypes.HANDLE
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL
    open_process_token = advapi32.OpenProcessToken
    open_process_token.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    open_process_token.restype = wintypes.BOOL
    get_token_information = advapi32.GetTokenInformation
    get_token_information.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    get_token_information.restype = wintypes.BOOL

    token = wintypes.HANDLE()
    assert open_process_token(get_current_process(), 0x00000008, ctypes.byref(token))
    try:
        required = wintypes.DWORD()
        ctypes.set_last_error(0)
        assert not get_token_information(token, 4, None, 0, ctypes.byref(required))
        assert ctypes.get_last_error() == 122
        token_buffer = ctypes.create_string_buffer(required.value)
        assert get_token_information(
            token, 4, token_buffer, required.value, ctypes.byref(required)
        )
        token_owner = ctypes.cast(token_buffer, ctypes.POINTER(TokenOwner)).contents
        owner_sid = wintypes.LPVOID(token_owner.Owner)
        assert owner_sid.value
        return token_buffer, owner_sid
    finally:
        assert close_handle(token)


def _windows_descriptor_is_exact_owner_only(
    security_descriptor: object, user_sid: object
) -> bool:
    import ctypes
    from ctypes import wintypes

    class AclSizeInformation(ctypes.Structure):
        _fields_ = [
            ("AceCount", wintypes.DWORD),
            ("AclBytesInUse", wintypes.DWORD),
            ("AclBytesFree", wintypes.DWORD),
        ]

    class AccessAllowedAce(ctypes.Structure):
        _fields_ = [
            ("AceType", ctypes.c_ubyte),
            ("AceFlags", ctypes.c_ubyte),
            ("AceSize", wintypes.WORD),
            ("Mask", wintypes.DWORD),
            ("SidStart", wintypes.DWORD),
        ]

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    get_security_descriptor_owner = advapi32.GetSecurityDescriptorOwner
    get_security_descriptor_owner.argtypes = [
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.BOOL),
    ]
    get_security_descriptor_owner.restype = wintypes.BOOL
    get_security_descriptor_dacl = advapi32.GetSecurityDescriptorDacl
    get_security_descriptor_dacl.argtypes = [
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.BOOL),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.BOOL),
    ]
    get_security_descriptor_dacl.restype = wintypes.BOOL
    get_security_descriptor_control = advapi32.GetSecurityDescriptorControl
    get_security_descriptor_control.argtypes = [
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.WORD),
        ctypes.POINTER(wintypes.DWORD),
    ]
    get_security_descriptor_control.restype = wintypes.BOOL
    get_acl_information = advapi32.GetAclInformation
    get_acl_information.argtypes = [
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.c_int,
    ]
    get_acl_information.restype = wintypes.BOOL
    get_ace = advapi32.GetAce
    get_ace.argtypes = [
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
    ]
    get_ace.restype = wintypes.BOOL
    equal_sid = advapi32.EqualSid
    equal_sid.argtypes = [wintypes.LPVOID, wintypes.LPVOID]
    equal_sid.restype = wintypes.BOOL

    descriptor = wintypes.LPVOID(security_descriptor)
    sid = wintypes.LPVOID(getattr(user_sid, "value", user_sid))
    owner = wintypes.LPVOID()
    owner_defaulted = wintypes.BOOL()
    dacl_present = wintypes.BOOL()
    dacl = wintypes.LPVOID()
    dacl_defaulted = wintypes.BOOL()
    if not get_security_descriptor_owner(
        descriptor, ctypes.byref(owner), ctypes.byref(owner_defaulted)
    ):
        return False
    if not get_security_descriptor_dacl(
        descriptor,
        ctypes.byref(dacl_present),
        ctypes.byref(dacl),
        ctypes.byref(dacl_defaulted),
    ):
        return False
    control = wintypes.WORD()
    revision = wintypes.DWORD()
    if not get_security_descriptor_control(
        descriptor, ctypes.byref(control), ctypes.byref(revision)
    ):
        return False
    information = AclSizeInformation()
    if not get_acl_information(
        dacl, ctypes.byref(information), ctypes.sizeof(information), 2
    ):
        return False
    ace_pointer = wintypes.LPVOID()
    if not get_ace(dacl, 0, ctypes.byref(ace_pointer)) or not ace_pointer.value:
        return False
    ace = ctypes.cast(ace_pointer, ctypes.POINTER(AccessAllowedAce)).contents
    ace_sid = wintypes.LPVOID(ace_pointer.value + AccessAllowedAce.SidStart.offset)
    return bool(
        owner.value
        and not owner_defaulted.value
        and dacl_present.value
        and dacl.value
        and not dacl_defaulted.value
        and control.value & 0x1000
        and information.AceCount == 1
        and ace.AceType == 0
        and ace.AceFlags == 0
        and ace.Mask == 0x001F01FF
        and equal_sid(owner, sid)
        and equal_sid(ace_sid, sid)
    )


def _windows_set_test_dacl(
    path: Path,
    sddl: str,
    *,
    protected: bool,
    directory: bool = False,
) -> None:
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    convert = advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.DWORD),
    ]
    convert.restype = wintypes.BOOL
    get_dacl = advapi32.GetSecurityDescriptorDacl
    get_dacl.argtypes = [
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.BOOL),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.BOOL),
    ]
    get_dacl.restype = wintypes.BOOL
    set_security_info = advapi32.SetSecurityInfo
    set_security_info.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.LPVOID,
    ]
    set_security_info.restype = wintypes.DWORD
    local_free = kernel32.LocalFree
    local_free.argtypes = [wintypes.LPVOID]
    local_free.restype = wintypes.LPVOID
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL

    security_descriptor = wintypes.LPVOID()
    assert convert(sddl, 1, ctypes.byref(security_descriptor), None)
    try:
        present = wintypes.BOOL()
        dacl = wintypes.LPVOID()
        defaulted = wintypes.BOOL()
        assert get_dacl(
            security_descriptor,
            ctypes.byref(present),
            ctypes.byref(dacl),
            ctypes.byref(defaulted),
        )
        assert present.value and dacl.value
        flags = 0x02000000 if directory else 0x00000080
        handle = create_file(
            str(path), 0x00020000 | 0x00040000, 0x00000007, None, 3, flags, None
        )
        invalid_handle = ctypes.c_void_p(-1).value
        value = int(handle) if handle is not None else None
        assert value not in {None, invalid_handle}
        try:
            assert set_security_info(
                handle,
                1,
                0x00000004
                | (0x80000000 if protected else 0x20000000),
                None,
                None,
                dacl,
                None,
            ) == 0
        finally:
            assert close_handle(handle)
    finally:
        assert not local_free(security_descriptor)


def _windows_security_sddl(path: Path) -> str:
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_named_security_info = advapi32.GetNamedSecurityInfoW
    get_named_security_info.argtypes = [
        wintypes.LPWSTR,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
    ]
    get_named_security_info.restype = wintypes.DWORD
    convert = advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW
    convert.argtypes = [
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPWSTR),
        ctypes.POINTER(wintypes.DWORD),
    ]
    convert.restype = wintypes.BOOL
    local_free = kernel32.LocalFree
    local_free.argtypes = [wintypes.LPVOID]
    local_free.restype = wintypes.LPVOID

    security_descriptor = wintypes.LPVOID()
    assert get_named_security_info(
        str(path), 1, 0x00000001 | 0x00000004, None, None, None, None,
        ctypes.byref(security_descriptor),
    ) == 0
    output = wintypes.LPWSTR()
    try:
        assert convert(
            security_descriptor,
            1,
            0x00000001 | 0x00000004,
            ctypes.byref(output),
            None,
        )
        assert output.value is not None
        return output.value
    finally:
        if output:
            assert not local_free(output)
        if security_descriptor.value:
            assert not local_free(security_descriptor)


@pytest.mark.skipif(os.name != "nt", reason="Windows process handle accounting only")
def test_windows_failed_audit_opens_close_all_native_handles(tmp_path: Path) -> None:
    """Catches leaking retained parent/final handles when a Windows native open fails."""
    import ctypes
    from ctypes import wintypes

    get_process_handle_count = ctypes.windll.kernel32.GetProcessHandleCount
    get_process_handle_count.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    get_process_handle_count.restype = wintypes.BOOL
    get_current_process = ctypes.windll.kernel32.GetCurrentProcess
    get_current_process.restype = wintypes.HANDLE

    def handle_count() -> int:
        count = wintypes.DWORD()
        assert get_process_handle_count(get_current_process(), ctypes.byref(count))
        return count.value

    directory_target = tmp_path / "audit-target"
    directory_target.mkdir()
    logger = AuditLogger(directory_target)
    before = handle_count()
    for _ in range(25):
        with pytest.raises(AuditWriteError) as raised:
            logger.emit(AuditEvent(event_type="model", metadata={"intent_id": "ok"}))
        assert raised.value.__cause__ is None
        assert raised.value.__context__ is None
    assert handle_count() <= before + 2


@pytest.mark.skipif(os.name != "nt", reason="Windows native security descriptors are unavailable")
def test_windows_audit_security_uses_process_token_owner_when_user_differs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catches using TokenUser as the descriptor owner and sole ACL trustee."""
    import ctypes
    from ctypes import wintypes

    from pyquality import security

    class SidAndAttributes(ctypes.Structure):
        _fields_ = [("Sid", wintypes.LPVOID), ("Attributes", wintypes.DWORD)]

    class TokenUser(ctypes.Structure):
        _fields_ = [("User", SidAndAttributes)]

    class TokenOwner(ctypes.Structure):
        _fields_ = [("Owner", wintypes.LPVOID)]

    owner_buffer, owner_sid = _windows_current_owner_sid()
    assert ctypes.sizeof(owner_buffer) > 0
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    create_well_known_sid = advapi32.CreateWellKnownSid
    create_well_known_sid.argtypes = [
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.DWORD),
    ]
    create_well_known_sid.restype = wintypes.BOOL
    user_buffer = ctypes.create_string_buffer(68)
    user_size = wintypes.DWORD(ctypes.sizeof(user_buffer))
    assert create_well_known_sid(1, None, user_buffer, ctypes.byref(user_size))
    user_sid = wintypes.LPVOID(ctypes.addressof(user_buffer))
    assert not security._equal_sid(owner_sid, user_sid)
    real_get_token_information = security._get_token_information

    def divergent_token_information(
        token: object,
        information_class: int,
        destination: object,
        destination_size: int,
        required_size: object,
    ) -> bool:
        if information_class == 1:
            value = TokenUser(User=SidAndAttributes(Sid=user_sid, Attributes=0))
        elif information_class == 4:
            value = TokenOwner(Owner=owner_sid)
        else:
            return bool(
                real_get_token_information(
                    token,
                    information_class,
                    destination,
                    destination_size,
                    required_size,
                )
            )
        size = ctypes.sizeof(value)
        ctypes.cast(required_size, ctypes.POINTER(wintypes.DWORD)).contents.value = size
        if not destination or destination_size < size:
            ctypes.set_last_error(122)
            return False
        ctypes.memmove(destination, ctypes.byref(value), size)
        return True

    monkeypatch.setattr(security, "_get_token_information", divergent_token_information)

    with security._windows_audit_security() as (descriptor, selected_owner_sid):
        assert security._equal_sid(selected_owner_sid, owner_sid)
        assert not security._equal_sid(selected_owner_sid, user_sid)
        assert _windows_descriptor_is_exact_owner_only(descriptor.value, owner_sid)


@pytest.mark.skipif(os.name != "nt", reason="Windows native security descriptors are unavailable")
def test_windows_final_open_supplies_atomic_owner_only_descriptor_and_native_disposition(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Catches null final descriptors, shared opens, or ignoring native create/open results."""
    import ctypes
    from ctypes import wintypes

    from pyquality import security

    token_buffer, owner_sid = _windows_current_owner_sid()
    assert ctypes.sizeof(token_buffer) > 0
    real_nt_create_file = security._nt_create_file
    real_set_entries = security._set_entries_in_acl
    real_local_free = security._local_free
    final_calls: list[tuple[int, int, int, bool]] = []
    allocated_acls: list[int] = []
    freed_allocations: list[int] = []

    def recording_nt_create_file(
        handle: object,
        desired_access: int,
        object_attributes: object,
        io_status: object,
        allocation_size: object,
        attributes: int,
        share_access: int,
        disposition: int,
        options: int,
        extended_attributes: object,
        extended_attributes_length: int,
    ) -> int:
        native_attributes = ctypes.cast(
            object_attributes, ctypes.POINTER(security._ObjectAttributes)
        ).contents
        is_final = bool(options & security._FILE_NON_DIRECTORY_FILE)
        descriptor_ok = bool(
            native_attributes.SecurityDescriptor
            and _windows_descriptor_is_exact_owner_only(
                native_attributes.SecurityDescriptor, owner_sid
            )
        )
        status = real_nt_create_file(
            handle,
            desired_access,
            object_attributes,
            io_status,
            allocation_size,
            attributes,
            share_access,
            disposition,
            options,
            extended_attributes,
            extended_attributes_length,
        )
        if is_final and status >= 0:
            information = ctypes.cast(
                io_status, ctypes.POINTER(security._IoStatusBlock)
            ).contents.Information
            final_calls.append((share_access, disposition, information, descriptor_ok))
        return status

    def recording_set_entries(
        count: int, entries: object, old_acl: object, new_acl: object
    ) -> int:
        result = real_set_entries(count, entries, old_acl, new_acl)
        if result == 0:
            pointer = ctypes.cast(new_acl, ctypes.POINTER(wintypes.LPVOID)).contents.value
            assert pointer
            allocated_acls.append(pointer)
        return result

    def recording_local_free(pointer: object) -> object:
        value = ctypes.cast(pointer, wintypes.LPVOID).value
        if value:
            freed_allocations.append(value)
        return real_local_free(pointer)

    monkeypatch.setattr(security, "_nt_create_file", recording_nt_create_file)
    monkeypatch.setattr(security, "_set_entries_in_acl", recording_set_entries)
    monkeypatch.setattr(security, "_local_free", recording_local_free)

    path = tmp_path / "audit.jsonl"
    logger = AuditLogger(path)
    logger.emit(AuditEvent(event_type="transition", metadata={"intent_id": "created"}))
    logger.emit(AuditEvent(event_type="transition", metadata={"intent_id": "opened"}))

    assert final_calls == [
        (0, security._FILE_OPEN_IF, 2, True),  # audit stream created
        (0, security._FILE_OPEN_IF, 2, True),  # checkpoint created
        (0, security._FILE_OPEN_IF, 2, True),  # first receipt created
        (0, security._FILE_OPEN_IF, 1, True),  # audit stream reopened
        (0, security._FILE_OPEN_IF, 1, True),  # checkpoint reopened
        (0, security._FILE_OPEN_IF, 2, True),  # second receipt created
    ]
    assert allocated_acls
    assert all(freed_allocations.count(pointer) >= allocated_acls.count(pointer) for pointer in allocated_acls)


@pytest.mark.skipif(os.name != "nt", reason="Windows native DACL APIs are unavailable")
def test_windows_existing_permissive_audit_fails_without_dacl_or_file_mutation(
    tmp_path: Path,
) -> None:
    """Catches retroactively hardening and appending to a permissive existing audit file."""
    path = tmp_path / "audit.jsonl"
    original = b"preexisting\n"
    path.write_bytes(original)
    _windows_set_test_dacl(path, "D:(A;;FA;;;WD)", protected=False)
    before = _windows_security_sddl(path)

    with pytest.raises(AuditWriteError) as raised:
        AuditLogger(path).emit(
            AuditEvent(event_type="transition", metadata={"intent_id": "must-fail"})
        )

    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    assert _windows_security_sddl(path) == before
    assert path.read_bytes() == original


@pytest.mark.skipif(os.name != "nt", reason="Windows native DACL APIs are unavailable")
def test_windows_valid_presecured_existing_audit_emits_without_descriptor_change(
    tmp_path: Path,
) -> None:
    """Catches rejecting an exact owner-only existing file or rewriting its descriptor."""
    path = tmp_path / "audit.jsonl"
    logger = AuditLogger(path)
    logger.emit(AuditEvent(event_type="transition", metadata={"intent_id": "seed"}))
    before = _windows_security_sddl(path)

    logger.emit(AuditEvent(event_type="transition", metadata={"intent_id": "existing"}))

    assert _windows_security_sddl(path) == before
    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert [record["metadata"]["intent_id"] for record in records] == ["seed", "existing"]


@pytest.mark.skipif(os.name != "nt", reason="Windows handle security APIs are unavailable")
def test_windows_audit_file_has_one_protected_owner_allow_ace(tmp_path: Path) -> None:
    """Catches relying on CRT mode bits instead of an owner-only protected file DACL."""
    import ctypes
    import msvcrt
    from ctypes import wintypes

    class AclSizeInformation(ctypes.Structure):
        _fields_ = [
            ("AceCount", wintypes.DWORD),
            ("AclBytesInUse", wintypes.DWORD),
            ("AclBytesFree", wintypes.DWORD),
        ]

    class AccessAllowedAce(ctypes.Structure):
        _fields_ = [
            ("AceType", ctypes.c_ubyte),
            ("AceFlags", ctypes.c_ubyte),
            ("AceSize", wintypes.WORD),
            ("Mask", wintypes.DWORD),
            ("SidStart", wintypes.DWORD),
        ]

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_security_info = advapi32.GetSecurityInfo
    get_security_info.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
    ]
    get_security_info.restype = wintypes.DWORD
    get_security_descriptor_control = advapi32.GetSecurityDescriptorControl
    get_security_descriptor_control.argtypes = [
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.WORD),
        ctypes.POINTER(wintypes.DWORD),
    ]
    get_security_descriptor_control.restype = wintypes.BOOL
    get_acl_information = advapi32.GetAclInformation
    get_acl_information.argtypes = [wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD, ctypes.c_int]
    get_acl_information.restype = wintypes.BOOL
    get_ace = advapi32.GetAce
    get_ace.argtypes = [wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.LPVOID)]
    get_ace.restype = wintypes.BOOL
    equal_sid = advapi32.EqualSid
    equal_sid.argtypes = [wintypes.LPVOID, wintypes.LPVOID]
    equal_sid.restype = wintypes.BOOL
    local_free = kernel32.LocalFree
    local_free.argtypes = [wintypes.LPVOID]
    local_free.restype = wintypes.LPVOID

    path = tmp_path / "audit.jsonl"
    AuditLogger(path).emit(AuditEvent(event_type="transition", metadata={"intent_id": "acl"}))
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
    security_descriptor = wintypes.LPVOID()
    owner = wintypes.LPVOID()
    dacl = wintypes.LPVOID()
    try:
        handle = wintypes.HANDLE(msvcrt.get_osfhandle(descriptor))
        result = get_security_info(
            handle,
            1,
            0x00000001 | 0x00000004,
            ctypes.byref(owner),
            None,
            ctypes.byref(dacl),
            None,
            ctypes.byref(security_descriptor),
        )
        assert result == 0
        control = wintypes.WORD()
        revision = wintypes.DWORD()
        assert get_security_descriptor_control(
            security_descriptor, ctypes.byref(control), ctypes.byref(revision)
        )
        assert control.value & 0x1000
        information = AclSizeInformation()
        assert get_acl_information(dacl, ctypes.byref(information), ctypes.sizeof(information), 2)
        assert information.AceCount == 1
        ace_pointer = wintypes.LPVOID()
        assert get_ace(dacl, 0, ctypes.byref(ace_pointer))
        ace = ctypes.cast(ace_pointer, ctypes.POINTER(AccessAllowedAce)).contents
        assert (ace.AceType, ace.AceFlags) == (0, 0)
        ace_sid = ctypes.c_void_p(ace_pointer.value + AccessAllowedAce.SidStart.offset)
        assert equal_sid(owner, ace_sid)
        assert ace.Mask & 0x001F01FF == 0x001F01FF
    finally:
        if security_descriptor.value:
            local_free(security_descriptor)
        os.close(descriptor)


@pytest.mark.skipif(os.name != "nt", reason="Windows delete sharing is unavailable")
@pytest.mark.parametrize("operation", ["rename", "delete"])
def test_windows_locked_audit_append_denies_live_rename_and_delete(
    tmp_path: Path, operation: str
) -> None:
    """Catches FILE_SHARE_DELETE allowing the active audit stream to change identity."""
    from pyquality import security

    path = tmp_path / "audit.jsonl"
    AuditLogger(path).emit(AuditEvent(event_type="transition", metadata={"intent_id": "seed"}))
    descriptor = security._open_windows_audit(path)
    try:
        with security._audit_file_lock(descriptor), pytest.raises(OSError):
            if operation == "rename":
                path.rename(tmp_path / "renamed.jsonl")
            else:
                path.unlink()
    finally:
        os.close(descriptor)


def test_audit_recovers_partial_tail_and_serializes_multi_process_emits(tmp_path: Path) -> None:
    """Catches inter-process interleaving and a crash tail that makes future JSONL unreadable."""
    path = tmp_path / "audit.jsonl"
    _prepare_existing_audit(path, b'{"event_type":"partial"')
    context = multiprocessing.get_context("spawn")
    processes = [
        context.Process(
            target=_emit_in_process,
            args=(str(path), index * 20, 20, str(tmp_path / f"environment-{index}")),
        )
        for index in range(3)
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(20)
        assert process.exitcode == 0

    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert len(records) == 60
    assert {record["metadata"]["intent_id"] for record in records} == {
        f"intent-{index}" for index in range(60)
    }


def test_audit_log_omits_nested_model_body_metadata(tmp_path: Path) -> None:
    """Catches nested prompt or response data surviving the audit metadata filter."""
    logger = AuditLogger(tmp_path / "audit.jsonl")
    logger.emit(
        AuditEvent(
            event_type="model",
            metadata={"request": {"prompt": "source body", "response": "model body"}},
        )
    )

    record = json.loads((tmp_path / "audit.jsonl").read_text(encoding="utf-8"))
    assert record["metadata"] == {}


def test_audit_log_keeps_approved_scalar_metadata_in_its_envelope(tmp_path: Path) -> None:
    """Catches treating ordinary scalar audit context as a character sequence."""
    logger = AuditLogger(tmp_path / "audit.jsonl")
    logger.emit(
        AuditEvent(
            event_type="transition",
            task_id="task-1",
            iteration_id="2",
            component="agent_loop",
            metadata={"intent_id": "intent-1", "duration": 1.5, "outcome": "ok"},
        )
    )

    record = json.loads((tmp_path / "audit.jsonl").read_text(encoding="utf-8"))
    assert record["metadata"] == {"intent_id": "intent-1"}
    assert (record["duration"], record["outcome"]) == (1.5, "ok")


def test_audit_records_are_jsonl_complete_deterministic_and_thread_safe(tmp_path: Path) -> None:
    """Catches interleaved concurrent writes or omitted required audit envelope fields."""
    path = tmp_path / "nested" / "audit.jsonl"
    logger = AuditLogger(path, secrets={"sk-secret"})

    def emit(index: int) -> None:
        logger.emit(
            AuditEvent(
                event_type="transition",
                task_id="task-1",
                iteration_id=str(index),
                component="agent_loop",
                metadata={"intent_id": f"intent-{index}", "prompt": "not persisted"},
            )
        )

    with ThreadPoolExecutor(max_workers=8) as workers:
        list(workers.map(emit, range(40)))

    lines = path.read_text(encoding="utf-8").splitlines()
    records = [json.loads(line) for line in lines]
    assert len(records) == 40
    assert {record["iteration"] for record in records} == {str(index) for index in range(40)}
    assert all(
        {"task_id", "iteration", "component", "event_type", "duration", "outcome", "metadata"}
        <= record.keys()
        and "prompt" not in record["metadata"]
        for record in records
    )
    if os.name != "nt":
        assert path.stat().st_mode & 0o077 == 0
        assert path.parent.stat().st_mode & 0o077 == 0


def test_audit_envelope_is_bounded_when_every_context_field_is_large(tmp_path: Path) -> None:
    """Catches a record-size fallback that truncates metadata but leaves oversized envelope fields."""
    logger = AuditLogger(tmp_path / "audit.jsonl")
    large = "x" * 10_000
    logger.emit(
        AuditEvent(
            event_type=large,
            task_id=large,
            iteration_id=large,
            component=large,
            metadata={"intent_id": large},
        )
    )

    line = (tmp_path / "audit.jsonl").read_bytes().rstrip(b"\n")
    assert len(line) <= 16_384
    assert len(json.loads(line)["metadata"]["intent_id"].encode("utf-8")) <= 4_096


def test_audit_write_failure_is_typed_and_does_not_chain_sensitive_event(tmp_path: Path) -> None:
    """Catches leaking metadata when the audit target cannot be opened for append."""
    directory = tmp_path / "audit-target"
    directory.mkdir()
    logger = AuditLogger(directory, secrets={"sk-secret"})

    with pytest.raises(AuditWriteError) as raised:
        logger.emit(AuditEvent(event_type="model", metadata={"key": "sk-secret"}))

    assert "sk-secret" not in str(raised.value)
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
