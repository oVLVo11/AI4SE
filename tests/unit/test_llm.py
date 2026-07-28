from __future__ import annotations

import json

import httpx
import pytest

from pyquality.llm import (
    ActionFormatError,
    ActionParser,
    Message,
    OpenAICompatibleLLM,
    ProviderError,
    ScriptedLLM,
    ScriptedLLMExhaustedError,
)


def test_scripted_llm_records_feedback_context() -> None:
    llm = ScriptedLLM(['{"kind":"finish","arguments":{},"rationale":"done"}'])

    assert "finish" in llm.complete((Message(role="user", content="failure: assertion"),))
    assert "failure: assertion" in llm.calls[0][0].content


def test_scripted_llm_raises_typed_error_when_responses_are_exhausted() -> None:
    with pytest.raises(ScriptedLLMExhaustedError):
        ScriptedLLM(()).complete((Message(role="user", content="next action"),))


def test_action_parser_rejects_shell() -> None:
    with pytest.raises(ActionFormatError):
        ActionParser().parse(
            '{"kind":"shell","arguments":{"command":"ls"},"rationale":"x"}'
        )


def test_action_parser_accepts_exactly_one_json_object() -> None:
    parser = ActionParser()

    action = parser.parse('{"kind":"finish","arguments":{},"rationale":"done"}')

    assert (action.kind, action.arguments, action.rationale) == ("finish", {}, "done")
    with pytest.raises(ActionFormatError):
        parser.parse('{"kind":"finish","arguments":{},"rationale":"done"}\n{}')


def test_openai_compatible_llm_uses_one_injected_http_response_without_network() -> None:
    received: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        received.append(request)
        return httpx.Response(
            200,
            json={
                "id": "chatcmpl-test",
                "object": "chat.completion",
                "created": 1,
                "model": "test-model",
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": '{"kind":"finish","arguments":{},"rationale":"done"}',
                        },
                        "finish_reason": "stop",
                    }
                ],
            },
        )

    key_calls: list[str] = []
    client = httpx.Client(transport=httpx.MockTransport(handler))
    llm = OpenAICompatibleLLM(
        "https://provider.invalid/v1/chat/completions",
        "test-model",
        lambda: key_calls.append("called") or "test-key",
        client=client,
    )

    response = llm.complete((Message(role="user", content="choose an action"),))

    assert response == '{"kind":"finish","arguments":{},"rationale":"done"}'
    assert key_calls == ["called"]
    assert len(received) == 1
    assert received[0].headers["authorization"] == "Bearer test-key"
    assert json.loads(received[0].content) == {
        "model": "test-model",
        "messages": [{"role": "user", "content": "choose an action"}],
    }


def test_openai_compatible_llm_hides_credential_callable_failures() -> None:
    client = httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200)))
    llm = OpenAICompatibleLLM(
        "https://provider.invalid/v1/chat/completions",
        "test-model",
        lambda: (_ for _ in ()).throw(RuntimeError("secret credential detail")),
        client=client,
    )

    with pytest.raises(ProviderError, match="provider request failed") as error:
        llm.complete((Message(role="user", content="choose an action"),))

    assert "secret credential detail" not in str(error.value)
