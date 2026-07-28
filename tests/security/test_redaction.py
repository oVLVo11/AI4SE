from __future__ import annotations

import json
import multiprocessing
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import unquote

import pytest

from pyquality.domain.models import AuditEvent
from pyquality.security import AuditLogger, AuditWriteError, redact


def _set_process_environment(root: str) -> None:
    for name in ("HOME", "LOCALAPPDATA", "TEMP", "TMP", "USERPROFILE"):
        os.environ[name] = root


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


def test_audit_log_omits_source_and_prompt_by_default(tmp_path: Path) -> None:
    """Catches accepting prompt/source-bearing metadata into a persisted audit record."""
    logger = AuditLogger(tmp_path / "audit.jsonl", secrets={"sk-secret"})

    logger.emit(AuditEvent(event_type="model", metadata={"prompt": "source body", "key": "sk-secret"}))

    text = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    assert "source body" not in text and "sk-secret" not in text


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
    path.touch()
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
    path.touch()
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


def test_audit_recovers_partial_tail_and_serializes_multi_process_emits(tmp_path: Path) -> None:
    """Catches inter-process interleaving and a crash tail that makes future JSONL unreadable."""
    path = tmp_path / "audit.jsonl"
    path.write_bytes(b'{"event_type":"partial"')
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
