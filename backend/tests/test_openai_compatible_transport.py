import asyncio
from types import SimpleNamespace

from aegis.models.openai_compatible import (
    OpenAICompatibleTransport,
)


def test_transport_preserves_connection_configuration() -> None:
    transport = OpenAICompatibleTransport(
        api_key="test-key",
        base_url="https://example.invalid/v1",
        timeout_seconds=75.0,
        max_retries=2,
    )

    assert transport.api_key == "test-key"
    assert transport.base_url == (
        "https://example.invalid/v1"
    )
    assert transport.timeout_seconds == 75.0
    assert transport.max_retries == 2


def test_transport_delegates_chat_completion(
    monkeypatch,
) -> None:
    transport = OpenAICompatibleTransport(
        api_key="test-key",
        base_url="https://example.invalid/v1",
        timeout_seconds=45.0,
        max_retries=0,
    )

    captured = {}

    async def fake_create(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(
                        content='{"status":"ok"}'
                    )
                )
            ]
        )

    monkeypatch.setattr(
        transport.client.chat.completions,
        "create",
        fake_create,
    )

    response = asyncio.run(
        transport.create_chat_completion(
            model="fake/model",
            messages=[
                {
                    "role": "user",
                    "content": "Return JSON.",
                }
            ],
            temperature=0.0,
            max_tokens=128,
        )
    )

    assert captured == {
        "model": "fake/model",
        "messages": [
            {
                "role": "user",
                "content": "Return JSON.",
            }
        ],
        "temperature": 0.0,
        "max_tokens": 128,
    }
    assert (
        response.choices[0].message.content
        == '{"status":"ok"}'
    )
