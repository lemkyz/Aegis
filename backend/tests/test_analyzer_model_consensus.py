import asyncio

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


class FakePrimaryClient:
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
                summary=(
                    "Untrusted input reaches shell execution."
                ),
                evidence=[
                    "subprocess.run(command, shell=True)"
                ],
                scanner_evidence=scanner_evidence,
                cwe=["CWE-78"],
                recommended_fix=(
                    "Disable shell execution."
                ),
            )
        ]


class SupportingVerifierClient:
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
        assert len(primary_findings) == 1

        return VerifierReviewResult(
            model=self.model,
            status="completed",
            verifications=[
                FindingVerification(
                    finding_index=0,
                    verdict="supported",
                    confidence=0.94,
                    reasoning=(
                        "The source invokes a shell with "
                        "caller-controlled data."
                    ),
                    evidence=[
                        "shell=True",
                    ],
                )
            ],
        )


class FailingVerifierClient:
    model = "fake/failing-verifier"

    async def verify_findings(
        self,
        *,
        code: str,
        language: str,
        filename: str,
        scanner_evidence: list[ScannerEvidence],
        primary_findings: list[SecurityFinding],
    ) -> VerifierReviewResult:
        raise TimeoutError("verifier timeout")


def scanner_evidence() -> list[ScannerEvidence]:
    return [
        ScannerEvidence(
            tool="bandit",
            rule_id="bandit.python.b602",
            message="shell=True identified",
            severity="HIGH",
            file="app.py",
            line_start=4,
            line_end=4,
            code=(
                "subprocess.run(command, shell=True)"
            ),
            cwe=["CWE-78"],
        )
    ]


def request() -> AnalyzeCodeRequest:
    return AnalyzeCodeRequest(
        filename="app.py",
        language="python",
        code="""
import subprocess


def run(command: str) -> None:
    subprocess.run(command, shell=True)
""".strip(),
    )


def test_deep_analysis_runs_primary_verifier_and_consensus(
    monkeypatch,
) -> None:
    analyzer = SecurityAnalyzer(
        fingerprint_key="f" * 32,
        model_client=FakePrimaryClient(),
        verifier_client=SupportingVerifierClient(),
    )

    async def fake_collect(
        _request: AnalyzeCodeRequest,
    ) -> list[ScannerEvidence]:
        return scanner_evidence()

    monkeypatch.setattr(
        analyzer,
        "_collect_scanner_evidence",
        fake_collect,
    )

    result = asyncio.run(
        analyzer.deep_analyze(request())
    )

    assert result.analysis_status == "completed"
    assert result.result_source == "ai"
    assert len(result.findings) == 1
    assert result.model_consensus is not None
    assert result.model_consensus.status == "completed"
    assert (
        result.model_consensus.primary_model
        == "fake/primary"
    )
    assert (
        result.model_consensus.verifier_model
        == "fake/verifier"
    )
    assert (
        result.model_consensus.decisions[0].verdict
        == "confirmed"
    )


def test_verifier_failure_preserves_primary_finding(
    monkeypatch,
) -> None:
    analyzer = SecurityAnalyzer(
        fingerprint_key="f" * 32,
        model_client=FakePrimaryClient(),
        verifier_client=FailingVerifierClient(),
    )

    async def fake_collect(
        _request: AnalyzeCodeRequest,
    ) -> list[ScannerEvidence]:
        return scanner_evidence()

    monkeypatch.setattr(
        analyzer,
        "_collect_scanner_evidence",
        fake_collect,
    )

    result = asyncio.run(
        analyzer.deep_analyze(request())
    )

    assert result.analysis_status == "completed"
    assert result.result_source == "ai"
    assert len(result.findings) == 1
    assert result.model_consensus is not None
    assert result.model_consensus.status == "partial"
    assert (
        result.model_consensus.decisions[0].verdict
        == "unverified"
    )
    assert result.model_consensus.errors == [
        "verifier timeout"
    ]


def test_fast_analysis_does_not_create_consensus(
    monkeypatch,
) -> None:
    analyzer = SecurityAnalyzer(
        fingerprint_key="f" * 32,
        model_client=FakePrimaryClient(),
        verifier_client=SupportingVerifierClient(),
    )

    async def fake_collect(
        _request: AnalyzeCodeRequest,
    ) -> list[ScannerEvidence]:
        return scanner_evidence()

    monkeypatch.setattr(
        analyzer,
        "_collect_scanner_evidence",
        fake_collect,
    )

    result = asyncio.run(
        analyzer.fast_analyze(request())
    )

    assert result.analysis_status == "skipped"
    assert result.result_source == "scanner"
    assert result.model_consensus is None
