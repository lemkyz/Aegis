import asyncio
from types import SimpleNamespace

from aegis.config.settings import Settings
from aegis.models.openai_compatible_primary import (
    OpenAICompatibleSecurityModelClient,
)
from aegis.models.openai_compatible_verifier import (
    OpenAICompatibleVerifierClient,
)
from aegis.schemas.analysis import SecurityFinding


def primary_settings() -> Settings:
    return Settings(
        _env_file=None,
        aegis_fingerprint_key="f" * 32,
        ai_primary_provider="openai_compatible",
        ai_primary_model="fake/primary",
        ai_primary_api_key="test-key",
        ai_primary_base_url="https://example.invalid/v1",
        ai_request_profile="fast",
    )


def verifier_settings() -> Settings:
    return Settings(
        _env_file=None,
        aegis_fingerprint_key="f" * 32,
        ai_primary_provider="openai_compatible",
        ai_primary_model="fake/primary",
        ai_primary_api_key="primary-key",
        ai_primary_base_url="https://primary.invalid/v1",
        ai_verifier_provider="openai_compatible",
        ai_verifier_model="fake/verifier",
        ai_verifier_api_key="verifier-key",
        ai_verifier_base_url="https://verifier.invalid/v1",
        ai_request_profile="fast",
    )


def test_primary_client_uses_profile_token_budget(
    monkeypatch,
) -> None:
    client = OpenAICompatibleSecurityModelClient(
        primary_settings()
    )
    captured = {}

    async def fake_create(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(
                        content='{"findings":[]}'
                    )
                )
            ]
        )

    monkeypatch.setattr(
        client.transport,
        "create_chat_completion",
        fake_create,
    )

    asyncio.run(
        client.analyze_security(
            code="print('safe')",
            language="python",
            filename="safe.py",
            scanner_evidence=[],
        )
    )

    assert captured["max_tokens"] == 900
    assert client.transport.timeout_seconds == 45.0
    assert client.transport.max_retries == 0


def test_verifier_client_uses_profile_token_budget(
    monkeypatch,
) -> None:
    client = OpenAICompatibleVerifierClient(
        verifier_settings()
    )
    captured = {}

    async def fake_create(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(
                        content='{"verifications":[]}'
                    )
                )
            ]
        )

    monkeypatch.setattr(
        client.transport,
        "create_chat_completion",
        fake_create,
    )

    asyncio.run(
        client.verify_findings(
            code="print('safe')",
            language="python",
            filename="safe.py",
            scanner_evidence=[],
            primary_findings=[
                SecurityFinding(
                    title="Test",
                    severity="low",
                    confidence=0.5,
                    summary="Test finding.",
                    evidence=[],
                    recommended_fix="Review.",
                )
            ],
        )
    )

    assert captured["max_tokens"] == 700
    assert client.transport.timeout_seconds == 45.0
    assert client.transport.max_retries == 0
