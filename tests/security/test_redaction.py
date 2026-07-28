from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from pyquality.domain.models import AuditEvent
from pyquality.security import AuditLogger, AuditWriteError, redact


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


def test_audit_log_omits_source_and_prompt_by_default(tmp_path: Path) -> None:
    """Catches accepting prompt/source-bearing metadata into a persisted audit record."""
    logger = AuditLogger(tmp_path / "audit.jsonl", secrets={"sk-secret"})

    logger.emit(AuditEvent(event_type="model", metadata={"prompt": "source body", "key": "sk-secret"}))

    text = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    assert "source body" not in text and "sk-secret" not in text


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
    assert record["metadata"] == {"request": {}}


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
