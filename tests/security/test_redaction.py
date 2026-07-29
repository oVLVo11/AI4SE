from __future__ import annotations

import json
import multiprocessing
import os
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


def _set_process_environment(root: str) -> None:
    for name in ("HOME", "LOCALAPPDATA", "TEMP", "TMP", "USERPROFILE"):
        os.environ[name] = root


def _prepare_existing_audit(path: Path, content: bytes = b"") -> None:
    if os.name == "nt":
        from pyquality import security

        descriptor = security._open_windows_audit(path)
        os.close(descriptor)
        if content:
            path.write_bytes(content)
        return
    path.write_bytes(content)


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


def _windows_set_test_dacl(path: Path, sddl: str, *, protected: bool) -> None:
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
        handle = create_file(
            str(path), 0x00020000 | 0x00040000, 0x00000007, None, 3, 0x00000080, None
        )
        invalid_handle = ctypes.c_void_p(-1).value
        value = int(handle) if handle is not None else None
        assert value not in {None, invalid_handle}
        try:
            assert set_security_info(
                handle,
                1,
                0x00000004 | (0x80000000 if protected else 0x20000000),
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

    assert final_calls == [(0, security._FILE_OPEN_IF, 2, True), (0, security._FILE_OPEN_IF, 1, True)]
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
