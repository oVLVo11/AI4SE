from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from pyquality.application import build_service
from pyquality.domain.models import AuditEvent, TaskStatus
from pyquality.llm import Message, ProviderError
from pyquality.service import HarnessService, PreflightError


def test_production_composition_builds_offline_repository_scoped_service(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    class Backend:
        priority = 1

        def get_password(self, service: str, account: str) -> None:
            return None

        def set_password(self, service: str, account: str, value: str) -> None:
            pass

        def delete_password(self, service: str, account: str) -> None:
            pass

    repo = tmp_path / "repo"
    other = tmp_path / "other"
    repo.mkdir()
    other.mkdir()
    monkeypatch.setattr("pyquality.application.keyring.get_keyring", Backend)

    service = build_service(repo, provider="mock")

    assert isinstance(service, HarnessService)
    with pytest.raises(PreflightError, match="scope"):
        service.create_task(other, "must not cross repositories")


def test_production_provider_registers_credential_before_outbox_preparation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An empty production secret set would persist a retrieved provider key in SQLite."""
    secret = "production-keyring-secret"

    class Backend:
        priority = 1

        def __init__(self) -> None:
            self.reads = 0

        def get_password(self, service: str, account: str) -> str:
            assert (service, account) == ("pyquality", "provider")
            self.reads += 1
            return secret

        def set_password(self, service: str, account: str, value: str) -> None:
            raise AssertionError("credential write was not requested")

        def delete_password(self, service: str, account: str) -> None:
            raise AssertionError("credential deletion was not requested")

    backend = Backend()
    monkeypatch.setattr("pyquality.application.keyring.get_keyring", lambda: backend)

    def provider_response(
        client: httpx.Client, url: str, **kwargs: object
    ) -> httpx.Response:
        del client, url
        headers = kwargs["headers"]
        assert isinstance(headers, dict)
        assert headers["Authorization"] == f"Bearer {secret}"
        request = httpx.Request("POST", "https://provider.invalid")
        return httpx.Response(
            200,
            request=request,
            json={
                "choices": [
                    {
                        "message": {
                            "content": (
                                '{"kind":"finish","arguments":{},'
                                '"rationale":"done"}'
                            )
                        }
                    }
                ]
            },
        )

    monkeypatch.setattr(httpx.Client, "post", provider_response)
    repo = tmp_path / "repo"
    repo.mkdir()
    state = tmp_path / "state.sqlite"
    audit = tmp_path / "audit.jsonl"
    service = build_service(repo, state_path=state, audit_path=audit, provider="openai")
    repository = service._repository
    try:
        assert backend.reads == 0
        service._loop._llm.complete((Message(role="user", content="next action"),))
        assert backend.reads == 1

        def provider_failure(*args: object, **kwargs: object) -> httpx.Response:
            del args, kwargs
            raise httpx.TransportError(f"transport failed with {secret}")

        monkeypatch.setattr(httpx.Client, "post", provider_failure)
        with pytest.raises(ProviderError) as raised:
            service._loop._llm.complete(
                (Message(role="user", content="next action"),)
            )
        assert backend.reads == 2
        assert secret not in str(raised.value)

        task = repository.create_task(str(repo), "verify redaction", round_limit=1)
        assert repository.set_status(task.id, TaskStatus.CREATED, TaskStatus.RUNNING)
        owner = "application-secret-registry-owner"
        assert repository.acquire_project_lease(task.id, owner_token=owner)
        event = AuditEvent(
            event_id="a" * 64,
            task_id=task.id,
            component="provider",
            event_type="provider_result",
            metadata={"status": secret},
        )
        repository.append_iteration(
            task.id,
            sequence=1,
            context_digest="b" * 64,
            audit_events=(event,),
            owner_token=owner,
        )

        with repository._connection_lock:
            stored = repository._connection.execute(
                "SELECT event_json FROM audit_outbox WHERE event_id = ?",
                (event.event_id,),
            ).fetchone()[0]
        assert secret not in stored
        assert json.loads(stored)["metadata"] == {"status": "[REDACTED]"}
        assert secret not in repository.pending_audit_events()[0].event.model_dump_json()
        service._loop._audit_sink.emit(event)
        assert secret not in audit.read_text(encoding="utf-8")
        assert secret not in service.get_task(task.id).model_dump_json()
    finally:
        service.close()
        repository.close()
