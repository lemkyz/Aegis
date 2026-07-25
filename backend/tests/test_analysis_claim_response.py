from aegis.schemas.analysis import (
    AnalyzeCodeResponse,
    ScannerEvidence,
    SecurityFinding,
)
from aegis.orchestrator.analyzer import (
    SecurityAnalyzer,
)


def finding() -> SecurityFinding:
    scanner = ScannerEvidence(
        tool="Semgrep",
        rule_id=(
            "aegis.python.command-injection."
            "subprocess-shell"
        ),
        message=(
            "Untrusted input reaches shell execution."
        ),
        severity="ERROR",
        file="app.py",
        line_start=8,
        line_end=8,
        code="subprocess.run(command, shell=True)",
        cwe=["CWE-78"],
        owasp=["A03:2021"],
    )

    return SecurityFinding(
        title="Command Injection",
        severity="high",
        confidence=0.95,
        summary=(
            "Untrusted input may reach a shell command."
        ),
        evidence=[
            "The command includes attacker-controlled input.",
        ],
        scanner_evidence=[scanner],
        cwe=["CWE-78"],
        owasp=["A03:2021"],
        vulnerable_lines=[8],
        false_positive_notes=[],
        recommended_fix=(
            "Pass arguments as a list and disable shell."
        ),
        proposed_patch=None,
    )


def test_analysis_response_accepts_legacy_payload() -> None:
    response = AnalyzeCodeResponse(
        filename="safe.py",
        language="python",
        model="not-used",
        scanner="semgrep",
        analysis_status="skipped",
        result_source="scanner",
        findings=[],
    )

    assert response.findings == []
    assert response.claims == []


def test_analysis_response_preserves_findings() -> None:
    original = finding()

    response = AnalyzeCodeResponse(
        filename="app.py",
        language="python",
        model="not-used",
        scanner="semgrep",
        analysis_status="skipped",
        result_source="scanner",
        findings=[original],
        claims=[],
    )

    assert response.findings == [original]


def test_analyzer_builds_claims_from_findings() -> None:
    original = finding()

    claims = SecurityAnalyzer._build_claims(
        findings=[original],
        filename="app.py",
    )

    assert len(claims) == 1

    claim = claims[0]

    assert claim.statement == original.summary
    assert claim.category == "command-injection"
    assert claim.severity == original.severity
    assert claim.state == "supported"
    assert claim.locations[0].file == "app.py"


def test_analyzer_builds_no_claims_without_findings() -> None:
    claims = SecurityAnalyzer._build_claims(
        findings=[],
        filename="safe.py",
    )

    assert claims == []


def test_analysis_response_serializes_claims() -> None:
    original = finding()
    claims = SecurityAnalyzer._build_claims(
        findings=[original],
        filename="app.py",
    )

    response = AnalyzeCodeResponse(
        filename="app.py",
        language="python",
        model="not-used",
        scanner="semgrep",
        analysis_status="skipped",
        result_source="scanner",
        findings=[original],
        claims=claims,
    )

    payload = response.model_dump()

    assert len(payload["findings"]) == 1
    assert len(payload["claims"]) == 1
    assert payload["claims"][0]["claim_id"].startswith(
        "claim:sha256:"
    )


def test_scanner_claims_do_not_create_model_review_evidence() -> None:
    claims = SecurityAnalyzer._build_claims(
        findings=[finding()],
        filename="app.py",
        include_narrative_evidence=False,
    )

    assert len(claims) == 1
    assert {
        evidence.source.kind
        for evidence in claims[0].evidence
    } == {"scanner"}


def test_ai_claims_preserve_model_review_evidence() -> None:
    claims = SecurityAnalyzer._build_claims(
        findings=[finding()],
        filename="app.py",
        include_narrative_evidence=True,
    )

    assert {
        evidence.source.kind
        for evidence in claims[0].evidence
    } == {
        "scanner",
        "model_review",
    }


def test_ai_claim_exposes_consensus_audit_evidence() -> None:
    original = finding()

    original.primary_model = "fake/primary"
    original.verifier_model = "fake/verifier"
    original.verifier_verdict = "supported"
    original.verifier_confidence = 0.93
    original.verifier_reasoning = (
        "Unsafe shell execution is present."
    )
    original.consensus_verdict = "confirmed"
    original.consensus_confidence = 0.94
    original.consensus_reasons = [
        "Primary and verifier agree.",
    ]

    claims = SecurityAnalyzer._build_claims(
        findings=[original],
        filename="app.py",
        include_narrative_evidence=True,
    )

    assert {
        evidence.source.kind
        for evidence in claims[0].evidence
    } == {
        "scanner",
        "model_review",
        "model_verification",
        "model_consensus",
    }
