import asyncio
from types import SimpleNamespace

import pytest

from aegis.models.nvidia_verifier import (
    NvidiaVerifierClient,
)
from aegis.schemas.analysis import SecurityFinding


def finding() -> SecurityFinding:
    return SecurityFinding(
        title="Command injection",
        severity="high",
        confidence=0.9,
        summary="Untrusted input reaches shell execution.",
        evidence=["subprocess.run(command, shell=True)"],
        recommended_fix="Disable shell execution.",
    )


def test_parses_verifier_response(
    monkeypatch,
) -> None:
    client = NvidiaVerifierClient()

    async def fake_create(**kwargs):
        return SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(
                        content=(
                            '{"verifications":['
                            '{"finding_index":0,'
                            '"verdict":"supported",'
                            '"confidence":0.95,'
                            '"reasoning":"Code confirms it.",'
                            '"evidence":["shell=True"]}'
                            ']}'
                        )
                    )
                )
            ]
        )

    monkeypatch.setattr(
        client.client.chat.completions,
        "create",
        fake_create,
    )

    result = asyncio.run(
        client.verify_findings(
            code="subprocess.run(command, shell=True)",
            language="python",
            filename="app.py",
            scanner_evidence=[],
            primary_findings=[finding()],
        )
    )

    assert result.status == "completed"
    assert result.verifications[0].verdict == (
        "supported"
    )


def test_rejects_invalid_verifier_json(
    monkeypatch,
) -> None:
    client = NvidiaVerifierClient()

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
        client.client.chat.completions,
        "create",
        fake_create,
    )

    with pytest.raises(
        RuntimeError,
        match="invalid JSON",
    ):
        asyncio.run(
            client.verify_findings(
                code="print('safe')",
                language="python",
                filename="safe.py",
                scanner_evidence=[],
                primary_findings=[finding()],
            )
        )


def test_uses_dedicated_verifier_model_when_configured(
    monkeypatch,
) -> None:
    from aegis.config.settings import Settings
    import aegis.models.nvidia_verifier as module

    settings = Settings(
        _env_file=None,
        aegis_fingerprint_key="f" * 32,
        nvidia_api_key="test-key",
        nvidia_base_url="https://example.invalid/v1",
        nvidia_model="fake/primary",
        nvidia_verifier_model="fake/verifier",
        ai_request_timeout_seconds=45.0,
        ai_max_retries=0,
    )

    monkeypatch.setattr(
        module,
        "get_settings",
        lambda: settings,
    )

    client = module.NvidiaVerifierClient()

    assert client.model == "fake/verifier"


def test_falls_back_to_primary_model_when_verifier_unset(
    monkeypatch,
) -> None:
    from aegis.config.settings import Settings
    import aegis.models.nvidia_verifier as module

    settings = Settings(
        _env_file=None,
        aegis_fingerprint_key="f" * 32,
        nvidia_api_key="test-key",
        nvidia_base_url="https://example.invalid/v1",
        nvidia_model="fake/primary",
        nvidia_verifier_model=None,
        ai_request_timeout_seconds=45.0,
        ai_max_retries=0,
    )

    monkeypatch.setattr(
        module,
        "get_settings",
        lambda: settings,
    )

    client = module.NvidiaVerifierClient()

    assert client.model == "fake/primary"


def test_rejects_verification_with_invalid_finding_index(
    monkeypatch,
) -> None:
    client = NvidiaVerifierClient()

    async def fake_create(**kwargs):
        return SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(
                        content=(
                            '{"verifications":['
                            '{"finding_index":-1,'
                            '"verdict":"supported",'
                            '"confidence":0.99,'
                            '"reasoning":"Invalid.",'
                            '"evidence":[]}'
                            ']}'
                        )
                    )
                )
            ]
        )

    monkeypatch.setattr(
        client.client.chat.completions,
        "create",
        fake_create,
    )

    with pytest.raises(Exception):
        asyncio.run(
            client.verify_findings(
                code="print('safe')",
                language="python",
                filename="safe.py",
                scanner_evidence=[],
                primary_findings=[finding()],
            )
        )


def test_empty_model_response_is_rejected(
    monkeypatch,
) -> None:
    client = NvidiaVerifierClient()

    async def fake_create(**kwargs):
        return SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(
                        content=""
                    )
                )
            ]
        )

    monkeypatch.setattr(
        client.client.chat.completions,
        "create",
        fake_create,
    )

    with pytest.raises(
        RuntimeError,
        match="empty response",
    ):
        asyncio.run(
            client.verify_findings(
                code="print('safe')",
                language="python",
                filename="safe.py",
                scanner_evidence=[],
                primary_findings=[finding()],
            )
        )
