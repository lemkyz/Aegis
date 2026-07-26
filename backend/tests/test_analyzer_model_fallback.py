import asyncio
from types import SimpleNamespace

from aegis.orchestrator.analyzer import SecurityAnalyzer
from aegis.schemas.analysis import (
    AnalyzeCodeRequest,
    ScannerEvidence,
    SecurityFinding,
)
from aegis.schemas.model_verification import (
    FindingVerification,
    VerifierReviewResult,
)


class FailingPrimary:
    provider = "provider-a"
    model = "primary/failing"
    transport = SimpleNamespace(
        base_url="https://primary.invalid/v1"
    )

    async def analyze_security(self, **kwargs):
        raise TimeoutError("primary timeout")


class SuccessfulPrimaryFallback:
    provider = "provider-b"
    model = "primary/fallback"
    transport = SimpleNamespace(
        base_url="https://fallback.invalid/v1"
    )

    async def analyze_security(
        self,
        *,
        scanner_evidence,
        **kwargs,
    ):
        return [
            SecurityFinding(
                title="Command injection",
                severity="high",
                confidence=0.90,
                summary="Unsafe shell execution.",
                evidence=["shell=True"],
                scanner_evidence=scanner_evidence,
                cwe=["CWE-78"],
                recommended_fix="Disable shell execution.",
            )
        ]


class FailingPrimaryFallback:
    provider = "provider-b"
    model = "primary/fallback-failing"
    transport = SimpleNamespace(
        base_url="https://fallback.invalid/v1"
    )

    async def analyze_security(self, **kwargs):
        raise RuntimeError("fallback unavailable")


class SuccessfulVerifier:
    provider = "provider-c"
    model = "verifier/active"
    transport = SimpleNamespace(
        base_url="https://verifier.invalid/v1"
    )

    async def verify_findings(
        self,
        *,
        primary_findings,
        **kwargs,
    ):
        return VerifierReviewResult(
            model=self.model,
            status="completed",
            verifications=[
                FindingVerification(
                    finding_index=0,
                    verdict="supported",
                    confidence=0.94,
                    reasoning="Scanner evidence confirms it.",
                )
            ],
        )


class FailingVerifier(SuccessfulVerifier):
    model = "verifier/failing"

    async def verify_findings(self, **kwargs):
        raise TimeoutError("verifier timeout")


class SuccessfulVerifierFallback(SuccessfulVerifier):
    provider = "provider-d"
    model = "verifier/fallback"
    transport = SimpleNamespace(
        base_url="https://verifier-fallback.invalid/v1"
    )


def evidence() -> list[ScannerEvidence]:
    return [
        ScannerEvidence(
            tool="bandit",
            rule_id="bandit.python.b602",
            message="shell=True identified",
            severity="HIGH",
            file="app.py",
            line_start=4,
            line_end=4,
            code="subprocess.run(command, shell=True)",
            cwe=["CWE-78"],
        )
    ]


def request() -> AnalyzeCodeRequest:
    return AnalyzeCodeRequest(
        filename="app.py",
        language="python",
        code=(
            "import subprocess\n"
            "command = input()\n"
            "subprocess.run(command, shell=True)"
        ),
    )


def patch_scanners(
    monkeypatch,
    analyzer: SecurityAnalyzer,
) -> None:
    async def fake_collect(_request):
        return evidence()

    monkeypatch.setattr(
        analyzer,
        "_collect_scanner_evidence",
        fake_collect,
    )


def test_primary_fallback_continues_ai_analysis(
    monkeypatch,
) -> None:
    analyzer = SecurityAnalyzer(
        fingerprint_key="f" * 32,
        model_client=FailingPrimary(),
        primary_fallback_client=SuccessfulPrimaryFallback(),
        verifier_client=SuccessfulVerifier(),
    )
    patch_scanners(monkeypatch, analyzer)

    result = asyncio.run(
        analyzer.deep_analyze(request())
    )

    assert result.analysis_status == "completed"
    assert result.result_source == "ai"
    assert result.model == "primary/fallback"
    assert result.model_consensus is not None
    assert (
        result.model_consensus.primary_provider
        == "provider-b"
    )
    assert (
        result.model_consensus.primary_model
        == "primary/fallback"
    )


def test_failed_primary_and_fallback_use_scanner_result(
    monkeypatch,
) -> None:
    analyzer = SecurityAnalyzer(
        fingerprint_key="f" * 32,
        model_client=FailingPrimary(),
        primary_fallback_client=FailingPrimaryFallback(),
        verifier_client=SuccessfulVerifier(),
    )
    patch_scanners(monkeypatch, analyzer)

    result = asyncio.run(
        analyzer.deep_analyze(request())
    )

    assert result.analysis_status == "fallback"
    assert result.result_source == "scanner_fallback"
    assert result.model_consensus is None
    assert len(result.findings) == 1
    assert "primary/failing" in result.model
    assert "primary/fallback-failing" in result.model


def test_verifier_fallback_updates_consensus_route(
    monkeypatch,
) -> None:
    analyzer = SecurityAnalyzer(
        fingerprint_key="f" * 32,
        model_client=SuccessfulPrimaryFallback(),
        verifier_client=FailingVerifier(),
        verifier_fallback_client=(
            SuccessfulVerifierFallback()
        ),
    )
    patch_scanners(monkeypatch, analyzer)

    result = asyncio.run(
        analyzer.deep_analyze(request())
    )

    assert result.analysis_status == "completed"
    assert result.model_consensus is not None
    assert (
        result.model_consensus.verifier_provider
        == "provider-d"
    )
    assert (
        result.model_consensus.verifier_model
        == "verifier/fallback"
    )
    assert result.model_consensus.status == "completed"
