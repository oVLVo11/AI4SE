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


@pytest.mark.parametrize(
    ("secret", "result"),
    [
        ("1e3", 1000),
        ("1000", 1000.0),
        ("1000.0", "1e3"),
        ("-0", 0),
        ("+001.00", 1.0),
        ("-001e+2", -100),
        ("false", False),
    ],
)
def test_provider_result_canonicalizes_bounded_decimal_spellings(
    memory_keyring: MemoryKeyring, secret: str, result: object
) -> None:
    """Catches exponent, fixed-point, signed-zero, or leading-zero credential echoes."""
    service = CredentialService(memory_keyring, service_name="pyquality")
    service.set("provider", secret)

    with pytest.raises(CredentialProviderError):
        service.get("provider", lambda _, result=result: result)


@pytest.mark.parametrize(
    ("secret", "result"),
    [
        ("1e300", "1" + "0" * 300),
        ("1" + "0" * 300, "1e300"),
        ("1e257", "10e256"),
        ("-0001e300", "-10e299"),
        ("-0e300", "+000.000e-300"),
        ("+00012300e298", "123e300"),
    ],
)
def test_provider_result_canonicalizes_huge_textual_decimal_spellings(
    memory_keyring: MemoryKeyring, secret: str, result: str
) -> None:
    """Catches bounded numeric text falling back to spelling-sensitive text identities."""
    service = CredentialService(memory_keyring, service_name="pyquality")
    service.set("provider", secret)

    with pytest.raises(CredentialProviderError):
        service.get("provider", lambda _: result)


def test_set_rejects_numeric_credential_outside_closed_text_domain(
    memory_keyring: MemoryKeyring,
) -> None:
    """Catches storing an exponent whose equivalent integer exceeds the 4 KiB domain."""
    service = CredentialService(memory_keyring, service_name="pyquality")

    with pytest.raises(ValueError) as raised:
        service.set("provider", "1e4096")

    assert memory_keyring.get_password("pyquality", "provider") is None
    assert "1e4096" not in str(raised.value)
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None


@pytest.mark.parametrize(
    "result", ["x" * 4_097, b"x" * 4_097], ids=["str-4097-bytes", "bytes-4097"]
)
def test_provider_rejects_text_results_above_four_kib_before_return(
    memory_keyring: MemoryKeyring, result: str | bytes
) -> None:
    """Catches returning oversized callback text that happens not to contain the credential."""
    service = CredentialService(memory_keyring, service_name="pyquality")
    service.set("provider", "sk-secret")

    with pytest.raises(CredentialProviderError) as raised:
        service.get("provider", lambda _: result)

    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None


@pytest.mark.parametrize(
    ("secret", "result"),
    [
        ("1e4094", "1" + "0" * 4_094),
        ("1" + "0" * 4_094, "1" + "0" * 4_094 + "."),
        ("1" + "0" * 4_094 + ".", "1e4094"),
    ],
)
def test_largest_exponent_integer_and_fixed_spellings_share_one_identity(
    memory_keyring: MemoryKeyring, secret: str, result: str
) -> None:
    """Catches splitting the largest three-form equivalence class inside 4,096 bytes."""
    service = CredentialService(memory_keyring, service_name="pyquality")
    service.set("provider", secret)

    with pytest.raises(CredentialProviderError):
        service.get("provider", lambda _: result)


def test_nonnumeric_api_key_with_large_exponent_suffix_remains_exact_text(
    memory_keyring: MemoryKeyring,
) -> None:
    """Catches rejecting ordinary API-key text merely because its suffix resembles a number."""
    service = CredentialService(memory_keyring, service_name="pyquality")
    service.set("provider", "sk-live-1e4096")

    result = service.get("provider", lambda _: "1e4096")

    assert result.value == "1e4096"


def test_provider_rejects_numeric_like_objects_without_string_or_repr_inspection(
    memory_keyring: MemoryKeyring,
) -> None:
    """Catches expanding or inspecting an unsupported numeric-like callback result."""

    class HugeNumber:
        def __str__(self) -> str:
            raise AssertionError("str must not be invoked")

        def __repr__(self) -> str:
            raise AssertionError("repr must not be invoked")

        def __int__(self) -> int:
            raise AssertionError("int conversion must not be invoked")

    service = CredentialService(memory_keyring, service_name="pyquality")
    service.set("provider", "sk-secret")

    with pytest.raises(CredentialProviderError) as raised:
        service.get("provider", lambda _: HugeNumber())

    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None


@pytest.mark.parametrize(
    ("secret", "result"),
    [
        ("invoice-1e300", "1" + "0" * 300),
        ("1e300", "1" + "0" * 299 + "1"),
        ("1e300units", "10e299"),
        ("--0001", 1),
    ],
)
def test_provider_result_keeps_nonnumeric_and_nonequivalent_huge_text_distinct(
    memory_keyring: MemoryKeyring, secret: str, result: object
) -> None:
    """Catches huge-number normalization conflating ordinary text or nearby numeric values."""
    service = CredentialService(memory_keyring, service_name="pyquality")
    service.set("provider", secret)

    assert service.get("provider", lambda _: result).value == result


@pytest.mark.parametrize(("secret", "result"), [("1", True), ("0", False)])
def test_provider_result_does_not_conflate_boolean_and_numeric_scalars(
    memory_keyring: MemoryKeyring, secret: str, result: bool
) -> None:
    """Catches a numeric grammar that treats bool as the integers one and zero."""
    service = CredentialService(memory_keyring, service_name="pyquality")
    service.set("provider", secret)

    use = service.get("provider", lambda _: result)

    assert use.value is result


def test_provider_scalar_grammar_rejects_huge_results_without_poisoning_huge_text_secrets(
    memory_keyring: MemoryKeyring,
) -> None:
    """Catches unbounded numeric conversion and false positives from an unparseable text secret."""
    service = CredentialService(memory_keyring, service_name="pyquality")
    service.set("provider", "sk-" + "9" * 10_000)

    assert service.get("provider", lambda _: 7).value == 7
    with pytest.raises(CredentialProviderError) as raised:
        service.get("provider", lambda _: 10**10_000)
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None


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
