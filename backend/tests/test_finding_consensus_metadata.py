import asyncio

import pytest

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


class Primary:
    model = "fake/primary"

    async def analyze_security(
        self,
        *,
        code: str,
        language: str,
        filename: str,
        scanner_evidence: list[ScannerEvidence],
    ) -> list[SecurityFinding]:
        return [
            SecurityFinding(
                title="Command injection",
                severity="high",
                confidence=0.90,
                summary="Shell execution is unsafe.",
                evidence=["shell=True"],
                scanner_evidence=scanner_evidence,
                recommended_fix="Disable shell execution.",
            )
        ]


class Verifier:
    model = "fake/verifier"

    async def verify_findings(
        self,
        *,
        code: str,
        language: str,
        filename: str,
        scanner_evidence: list[ScannerEvidence],
        primary_findings: list[SecurityFinding],
    ) -> VerifierReviewResult:
        return VerifierReviewResult(
            model=self.model,
            status="completed",
            verifications=[
                FindingVerification(
                    finding_index=0,
                    verdict="supported",
                    confidence=0.94,
                    reasoning="The code confirms the issue.",
                )
            ],
        )


def test_consensus_metadata_is_attached_to_finding(
    monkeypatch,
) -> None:
    analyzer = SecurityAnalyzer(
        fingerprint_key="f" * 32,
        model_client=Primary(),
        verifier_client=Verifier(),
    )

    async def fake_collect(
        request: AnalyzeCodeRequest,
    ) -> list[ScannerEvidence]:
        return [
            ScannerEvidence(
                tool="bandit",
                rule_id="bandit.python.b602",
                message="shell=True identified",
                severity="HIGH",
                file=request.filename,
                line_start=1,
                line_end=1,
                code="subprocess.run(command, shell=True)",
            )
        ]

    monkeypatch.setattr(
        analyzer,
        "_collect_scanner_evidence",
        fake_collect,
    )

    result = asyncio.run(
        analyzer.deep_analyze(
            AnalyzeCodeRequest(
                filename="app.py",
                language="python",
                code=(
                    "subprocess.run(command, shell=True)"
                ),
            )
        )
    )

    finding = result.findings[0]

    assert finding.confidence == 0.90
    assert finding.consensus_verdict == "confirmed"
    assert finding.consensus_confidence == pytest.approx(
        0.92
    )
    assert finding.verifier_model == "fake/verifier"
    assert finding.verifier_confidence == 0.94


def test_finding_schema_remains_backward_compatible() -> None:
    finding = SecurityFinding(
        title="Scanner finding",
        severity="medium",
        confidence=0.85,
        summary="Scanner-only result.",
        recommended_fix="Review the code.",
    )

    assert finding.consensus_verdict is None
    assert finding.consensus_confidence is None
    assert finding.verifier_model is None
    assert finding.verifier_confidence is None


def test_finding_preserves_verifier_audit_metadata(
    monkeypatch,
) -> None:
    analyzer = SecurityAnalyzer(
        fingerprint_key="f" * 32,
        model_client=Primary(),
        verifier_client=Verifier(),
    )

    async def fake_collect(
        request: AnalyzeCodeRequest,
    ) -> list[ScannerEvidence]:
        return [
            ScannerEvidence(
                tool="bandit",
                rule_id="bandit.python.b602",
                message="shell=True identified",
                severity="HIGH",
                file=request.filename,
                line_start=1,
                line_end=1,
                code="subprocess.run(command, shell=True)",
            )
        ]

    monkeypatch.setattr(
        analyzer,
        "_collect_scanner_evidence",
        fake_collect,
    )

    result = asyncio.run(
        analyzer.deep_analyze(
            AnalyzeCodeRequest(
                filename="app.py",
                language="python",
                code=(
                    "subprocess.run(command, shell=True)"
                ),
            )
        )
    )

    finding = result.findings[0]

    assert finding.primary_model == "fake/primary"
    assert finding.verifier_model == "fake/verifier"
    assert finding.verifier_verdict == "supported"
    assert finding.verifier_confidence == 0.94
    assert finding.verifier_reasoning == (
        "The code confirms the issue."
    )
    assert finding.verifier_evidence == []
    assert finding.consensus_verdict == "confirmed"
    assert finding.consensus_reasons


def test_legacy_finding_has_empty_audit_metadata() -> None:
    finding = SecurityFinding(
        title="Legacy scanner finding",
        severity="medium",
        confidence=0.85,
        summary="Scanner-only result.",
        recommended_fix="Review the code.",
    )

    assert finding.primary_model is None
    assert finding.verifier_verdict is None
    assert finding.verifier_reasoning is None
    assert finding.verifier_evidence == []
    assert finding.consensus_reasons == []


def test_confirmed_analyzer_finding_builds_confirmed_claim(
    monkeypatch,
) -> None:
    analyzer = SecurityAnalyzer(
        fingerprint_key="f" * 32,
        model_client=Primary(),
        verifier_client=Verifier(),
    )

    async def fake_collect(
        request: AnalyzeCodeRequest,
    ) -> list[ScannerEvidence]:
        return [
            ScannerEvidence(
                tool="bandit",
                rule_id="bandit.python.b602",
                message="shell=True identified",
                severity="HIGH",
                file=request.filename,
                line_start=1,
                line_end=1,
                code="subprocess.run(command, shell=True)",
            )
        ]

    monkeypatch.setattr(
        analyzer,
        "_collect_scanner_evidence",
        fake_collect,
    )

    result = asyncio.run(
        analyzer.deep_analyze(
            AnalyzeCodeRequest(
                filename="app.py",
                language="python",
                code=(
                    "subprocess.run(command, shell=True)"
                ),
            )
        )
    )

    assert result.claims[0].state == "confirmed"
    assert result.claims[0].confidence == pytest.approx(
        0.92
    )


def test_duplicate_verifier_metadata_preserves_first_decision(
    monkeypatch,
) -> None:
    class DuplicateVerifier:
        model = "fake/verifier"

        async def verify_findings(
            self,
            *,
            code: str,
            language: str,
            filename: str,
            scanner_evidence: list[ScannerEvidence],
            primary_findings: list[SecurityFinding],
        ) -> VerifierReviewResult:
            return VerifierReviewResult(
                model=self.model,
                status="completed",
                verifications=[
                    FindingVerification(
                        finding_index=0,
                        verdict="supported",
                        confidence=0.95,
                        reasoning="First verifier decision.",
                        evidence=["first-evidence"],
                    ),
                    FindingVerification(
                        finding_index=0,
                        verdict="refuted",
                        confidence=0.99,
                        reasoning="Conflicting duplicate.",
                        evidence=["duplicate-evidence"],
                    ),
                ],
            )

    analyzer = SecurityAnalyzer(
        fingerprint_key="f" * 32,
        model_client=Primary(),
        verifier_client=DuplicateVerifier(),
    )

    async def fake_collect(
        request: AnalyzeCodeRequest,
    ) -> list[ScannerEvidence]:
        return [
            ScannerEvidence(
                tool="bandit",
                rule_id="bandit.python.b602",
                message="shell=True identified",
                severity="HIGH",
                file=request.filename,
                line_start=1,
                line_end=1,
                code="subprocess.run(command, shell=True)",
            )
        ]

    monkeypatch.setattr(
        analyzer,
        "_collect_scanner_evidence",
        fake_collect,
    )

    result = asyncio.run(
        analyzer.deep_analyze(
            AnalyzeCodeRequest(
                filename="app.py",
                language="python",
                code=(
                    "subprocess.run(command, shell=True)"
                ),
            )
        )
    )

    finding = result.findings[0]

    assert result.model_consensus is not None
    assert result.model_consensus.status == "partial"
    assert (
        result.model_consensus.decisions[0].verdict
        == "confirmed"
    )
    assert finding.verifier_verdict == "supported"
    assert finding.verifier_confidence == 0.95
    assert finding.verifier_reasoning == (
        "First verifier decision."
    )
    assert finding.verifier_evidence == [
        "first-evidence"
    ]
    assert any(
        "duplicate decisions" in error
        for error in result.model_consensus.errors
    )

