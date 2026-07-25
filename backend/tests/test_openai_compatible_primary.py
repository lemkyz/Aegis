import asyncio
from types import SimpleNamespace

import pytest

from aegis.config.settings import Settings
from aegis.models.openai_compatible_primary import (
    OpenAICompatibleSecurityModelClient,
)


def settings() -> Settings:
    return Settings(
        _env_file=None,
        aegis_fingerprint_key="f" * 32,
        ai_primary_provider="openai_compatible",
        ai_primary_model="fake/primary",
        ai_primary_api_key="test-key",
        ai_primary_base_url="https://example.invalid/v1",
    )


def test_primary_client_parses_security_findings(
    monkeypatch,
) -> None:
    client = OpenAICompatibleSecurityModelClient(
        settings()
    )

    async def fake_create(**kwargs):
        return SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(
                        content=(
                            '{"findings":[{'
                            '"title":"Command injection",'
                            '"severity":"high",'
                            '"confidence":0.95,'
                            '"summary":"Unsafe shell execution.",'
                            '"evidence":["shell=True"],'
                            '"recommended_fix":"Disable shell.",'
                            '"proposed_patch":"```python\\n'
                            'safe_call()\\n```"'
                            '}]}'
                        )
                    )
                )
            ]
        )

    monkeypatch.setattr(
        client.transport,
        "create_chat_completion",
        fake_create,
    )

    findings = asyncio.run(
        client.analyze_security(
            code="run(value, shell=True)",
            language="python",
            filename="app.py",
            scanner_evidence=[],
        )
    )

    assert len(findings) == 1
    assert findings[0].title == "Command injection"
    assert findings[0].proposed_patch == "safe_call()"


def test_primary_client_rejects_invalid_json(
    monkeypatch,
) -> None:
    client = OpenAICompatibleSecurityModelClient(
        settings()
    )

    async def fake_create(**kwargs):
        return SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(
                        content="not-json"
                    )
                )
            ]
        )

    monkeypatch.setattr(
        client.transport,
        "create_chat_completion",
        fake_create,
    )

    with pytest.raises(
        RuntimeError,
        match="invalid JSON",
    ):
        asyncio.run(
            client.analyze_security(
                code="print('safe')",
                language="python",
                filename="safe.py",
                scanner_evidence=[],
            )
        )


def test_primary_client_rejects_empty_response(
    monkeypatch,
) -> None:
    client = OpenAICompatibleSecurityModelClient(
        settings()
    )

    async def fake_create(**kwargs):
        return SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(
                        content=None
                    )
                )
            ]
        )

    monkeypatch.setattr(
        client.transport,
        "create_chat_completion",
        fake_create,
    )

    with pytest.raises(
        RuntimeError,
        match="empty response",
    ):
        asyncio.run(
            client.analyze_security(
                code="print('safe')",
                language="python",
                filename="safe.py",
                scanner_evidence=[],
            )
        )
