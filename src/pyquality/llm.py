"""Injectable, bounded model-response adapters and strict action parsing."""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from typing import Literal, Protocol

import httpx
from pydantic import Field, ValidationError

from pyquality.config import Settings
from pyquality.domain.models import Action, PublicModel


class Message(PublicModel):
    """One provider-neutral chat message."""

    role: Literal["system", "user", "assistant"]
    content: str = Field(min_length=1)


class LLMClient(Protocol):
    """The single-response model boundary consumed by the agent loop."""

    def complete(self, messages: tuple[Message, ...]) -> str:
        """Return one provider response for one agent-loop round."""


class ScriptedLLMExhaustedError(RuntimeError):
    """Raised when an offline scripted client has no next response."""


class ScriptedLLM:
    """Deterministic offline client that records every prompt supplied to it."""

    def __init__(self, responses: Sequence[str]) -> None:
        self._responses = list(responses)
        self.calls: list[tuple[Message, ...]] = []

    def complete(self, messages: tuple[Message, ...]) -> str:
        self.calls.append(messages)
        if not self._responses:
            raise ScriptedLLMExhaustedError("scripted LLM has no remaining responses")
        return self._responses.pop(0)


class ProviderError(RuntimeError):
    """A provider failure with no request headers, body, or credential material."""


class OpenAICompatibleLLM:
    """One OpenAI-compatible chat-completions request per ``complete`` call.

    Transient transport failures are retried here within this single logical model call,
    so they do not create duplicate agent-loop rounds.
    """

    def __init__(
        self,
        endpoint: str,
        model: str,
        credential: Callable[[], str],
        *,
        timeout_s: int = 30,
        retries: int = 2,
        client: httpx.Client | None = None,
    ) -> None:
        if not endpoint:
            raise ValueError("endpoint must not be empty")
        if not model:
            raise ValueError("model must not be empty")
        if not 1 <= timeout_s <= 30:
            raise ValueError("timeout_s must be between 1 and 30")
        if not 0 <= retries <= 2:
            raise ValueError("retries must be between 0 and 2")
        self.endpoint = endpoint
        self.model = model
        self.timeout_s = timeout_s
        self.retries = retries
        self._credential = credential
        self._client = client or httpx.Client()

    @classmethod
    def from_settings(
        cls,
        endpoint: str,
        model: str,
        credential: Callable[[], str],
        settings: Settings,
        *,
        client: httpx.Client | None = None,
    ) -> OpenAICompatibleLLM:
        """Construct an adapter constrained by the validated provider settings."""
        return cls(
            endpoint,
            model,
            credential,
            timeout_s=settings.provider_timeout_s,
            retries=settings.provider_retries,
            client=client,
        )

    def complete(self, messages: tuple[Message, ...]) -> str:
        payload = {
            "model": self.model,
            "messages": [message.model_dump(mode="json") for message in messages],
        }
        credential_failed = False
        try:
            # The credential is deliberately fetched directly before the provider call and
            # is neither retained on this instance nor included in exception messages.
            key = self._credential()
        except Exception:  # noqa: BLE001 - credential backends have no shared error base.
            credential_failed = True
        if credential_failed:
            raise ProviderError("provider request failed") from None

        request_failed = True
        body = None
        for attempt in range(self.retries + 1):
            try:
                response = self._client.post(
                    self.endpoint,
                    headers={"Authorization": f"Bearer {key}"},
                    json=payload,
                    timeout=self.timeout_s,
                )
                response.raise_for_status()
                body = response.json()
                request_failed = False
                break
            except httpx.TransportError:
                if attempt == self.retries:
                    break
            except (httpx.HTTPError, ValueError, TypeError, KeyError, IndexError):
                break
        if request_failed:
            raise ProviderError("provider request failed") from None

        try:
            content = body["choices"][0]["message"]["content"]
        except (TypeError, KeyError, IndexError) as error:
            raise ProviderError("provider response did not contain one message") from error
        if not isinstance(content, str) or not content:
            raise ProviderError("provider response did not contain text")
        return content


class ActionFormatError(ValueError):
    """Raised when one provider response cannot be interpreted as one typed action."""


class ActionParser:
    """Parse exactly one JSON object at the public model-action boundary."""

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings

    def parse(self, raw: str) -> Action:
        if not isinstance(raw, str):
            raise ActionFormatError("provider response must be text")
        try:
            decoded = json.loads(raw, object_pairs_hook=_unique_json_object)
        except _DuplicateJSONKeyError as error:
            raise ActionFormatError(f"duplicate JSON key: {error.key}") from error
        except json.JSONDecodeError as error:
            raise ActionFormatError("provider response must contain one JSON object") from error
        if not isinstance(decoded, dict):
            raise ActionFormatError("provider response must contain one JSON object")
        try:
            context = {"settings": self._settings} if self._settings is not None else None
            return Action.model_validate(decoded, context=context)
        except ValidationError as error:
            raise ActionFormatError("provider response is not an allowed action") from error


class _DuplicateJSONKeyError(ValueError):
    def __init__(self, key: str) -> None:
        super().__init__(key)
        self.key = key


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJSONKeyError(key)
        result[key] = value
    return result
