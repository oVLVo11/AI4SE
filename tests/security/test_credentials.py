from __future__ import annotations

import pytest

from pyquality.security import CredentialBackendError, CredentialProviderError, CredentialService


class MemoryKeyring:
    """Complete in-memory keyring double; tests do not touch an OS credential store."""

    priority = 1

    def __init__(self) -> None:
        self._values: dict[tuple[str, str], str] = {}

    def set_password(self, service_name: str, username: str, password: str) -> None:
        self._values[(service_name, username)] = password

    def get_password(self, service_name: str, username: str) -> str | None:
        return self._values.get((service_name, username))

    def delete_password(self, service_name: str, username: str) -> None:
        self._values.pop((service_name, username), None)


@pytest.fixture
def memory_keyring() -> MemoryKeyring:
    return MemoryKeyring()


def test_credential_status_never_contains_secret(memory_keyring: MemoryKeyring) -> None:
    """Catches a status/repr change that includes a stored credential."""
    service = CredentialService(memory_keyring, service_name="pyquality")

    service.set("openai-compatible", "sk-secret")

    status = service.status("openai-compatible")
    assert status.present is True
    assert "sk-secret" not in repr(status)
    service.clear("openai-compatible")
    assert service.status("openai-compatible").present is False


def test_get_passes_secret_only_to_provider_and_returns_environment_warning(
    memory_keyring: MemoryKeyring, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Catches returning a selected environment secret or silently using environment fallback."""
    service = CredentialService(memory_keyring, service_name="pyquality")
    monkeypatch.setenv("PYQUALITY_API_KEY", "env-secret")
    received: list[str] = []

    result = service.get("openai-compatible", lambda key: received.append(key), source="environment")

    assert received == ["env-secret"]
    assert result.value is None
    assert result.warning is not None
    assert "process" in result.warning.message
    assert "env-secret" not in repr(result)
    assert service.status("openai-compatible").present is False


def test_keyring_backend_failure_is_typed_and_sanitized() -> None:
    """Catches writing through an unusable backend or leaking its secret-bearing exception text."""

    class UnusableKeyring:
        priority = 0

        def set_password(self, *_: object) -> None:
            raise AssertionError("must not be called")

        def get_password(self, *_: object) -> str | None:
            raise AssertionError("must not be called")

        def delete_password(self, *_: object) -> None:
            raise AssertionError("must not be called")

    with pytest.raises(CredentialBackendError) as raised:
        CredentialService(UnusableKeyring(), service_name="pyquality").set("provider", "sk-secret")

    assert "sk-secret" not in str(raised.value)
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None


def test_get_requires_a_provider_callable(memory_keyring: MemoryKeyring) -> None:
    """Catches a raw get API that would hand credentials back to arbitrary callers."""
    service = CredentialService(memory_keyring, service_name="pyquality")
    service.set("provider", "sk-secret")

    with pytest.raises(TypeError):
        service.get("provider", None)  # type: ignore[arg-type]


def test_get_rejects_a_provider_that_echoes_the_credential(memory_keyring: MemoryKeyring) -> None:
    """Catches a provider result path that hands the key back to the service caller."""
    service = CredentialService(memory_keyring, service_name="pyquality")
    service.set("provider", "sk-secret")

    with pytest.raises(CredentialProviderError) as raised:
        service.get("provider", lambda secret: secret)

    assert "sk-secret" not in str(raised.value)
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None


def test_provider_result_rejects_secret_in_mapping_key_and_arbitrary_object(memory_keyring: MemoryKeyring) -> None:
    """Catches a callback result that smuggles credentials through keys or object attributes."""
    service = CredentialService(memory_keyring, service_name="pyquality")
    service.set("provider", "sk-secret")

    class Result:
        key = "sk-secret"

    for result in ({"sk-secret": "echo"}, Result()):
        with pytest.raises(CredentialProviderError) as raised:
            service.get("provider", lambda _, result=result: result)
        assert raised.value.__cause__ is None
        assert raised.value.__context__ is None


@pytest.mark.parametrize(("secret", "result"), [("123", 123), ("true", True), ("1.5", 1.5), ("123", {"nested": [123]})])
def test_provider_result_rejects_canonical_scalar_secret_echoes(memory_keyring: MemoryKeyring, secret: str, result: object) -> None:
    """Catches numeric, boolean, float, and nested forms that canonically spell a credential."""
    service = CredentialService(memory_keyring, service_name="pyquality")
    service.set("provider", secret)

    with pytest.raises(CredentialProviderError) as raised:
        service.get("provider", lambda _, result=result: result)

    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None


@pytest.mark.parametrize(
    ("secret", "result"),
    [("True", True), ("+123", 123), ("01", {"nested": 1}), ("1.50", {"1.5": "value"})],
)
def test_provider_result_compares_stored_and_returned_scalars_with_one_grammar(memory_keyring: MemoryKeyring, secret: str, result: object) -> None:
    """Catches equivalent scalar spellings that evade direct textual credential comparison."""
    service = CredentialService(memory_keyring, service_name="pyquality")
    service.set("provider", secret)

    with pytest.raises(CredentialProviderError):
        service.get("provider", lambda _, result=result: result)


def test_backend_exception_does_not_preserve_secret_in_exception_chain() -> None:
    """Catches chaining a backend exception whose message contains the credential."""

    class ExplodingKeyring:
        priority = 1

        def set_password(self, _: str, __: str, password: str) -> None:
            raise RuntimeError(f"backend saw {password}")

        def get_password(self, *_: object) -> str | None:
            return None

        def delete_password(self, *_: object) -> None:
            return None

    with pytest.raises(CredentialBackendError) as raised:
        CredentialService(ExplodingKeyring(), service_name="pyquality").set("provider", "sk-secret")

    assert "sk-secret" not in str(raised.value)
    assert raised.value.__cause__ is None
