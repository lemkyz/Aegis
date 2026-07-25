from aegis.models.protocol import SecurityModelClient
from aegis.orchestrator.analyzer import SecurityAnalyzer
from aegis.schemas.analysis import (
    ScannerEvidence,
    SecurityFinding,
)


class FakeSecurityModelClient:
    model = "fake/security-reviewer"

    async def analyze_security(
        self,
        *,
        code: str,
        language: str,
        filename: str,
        scanner_evidence: list[ScannerEvidence],
    ) -> list[SecurityFinding]:
        return []


def test_analyzer_accepts_injected_model_client() -> None:
    client = FakeSecurityModelClient()

    analyzer = SecurityAnalyzer(
        fingerprint_key="f" * 32,
        model_client=client,
    )

    assert analyzer.model_client is client
    assert analyzer.model_client.model == (
        "fake/security-reviewer"
    )


def test_fake_client_satisfies_model_protocol() -> None:
    client: SecurityModelClient = (
        FakeSecurityModelClient()
    )

    assert client.model == "fake/security-reviewer"


class FakeSecurityVerifierClient:
    model = "fake/security-verifier"

    async def verify_findings(
        self,
        *,
        code: str,
        language: str,
        filename: str,
        scanner_evidence: list[ScannerEvidence],
        primary_findings: list[SecurityFinding],
    ):
        from aegis.schemas.model_verification import (
            VerifierReviewResult,
        )

        return VerifierReviewResult(
            model=self.model,
            status="completed",
        )


def test_fake_verifier_satisfies_verifier_protocol() -> None:
    from aegis.models.protocol import (
        SecurityVerifierClient,
    )

    client: SecurityVerifierClient = (
        FakeSecurityVerifierClient()
    )

    assert client.model == "fake/security-verifier"


def test_analyzer_accepts_injected_verifier_and_consensus() -> None:
    from aegis.security.model_consensus import (
        ModelConsensusEvaluator,
    )

    primary = FakeSecurityModelClient()
    verifier = FakeSecurityVerifierClient()
    consensus = ModelConsensusEvaluator()

    analyzer = SecurityAnalyzer(
        fingerprint_key="f" * 32,
        model_client=primary,
        verifier_client=verifier,
        consensus_evaluator=consensus,
    )

    assert analyzer.model_client is primary
    assert analyzer.verifier_client is verifier
    assert analyzer.consensus_evaluator is consensus
