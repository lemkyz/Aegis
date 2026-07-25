import os

from fastapi.testclient import TestClient

os.environ.setdefault(
    "AEGIS_FINGERPRINT_KEY",
    "test-only-fingerprint-key-32-characters",
)

from aegis.main import analyzer, app


client = TestClient(app)


VULNERABLE_CODE = """
import subprocess

def run(user_input: str):
    subprocess.run(
        user_input,
        shell=True,
    )
""".strip()


def test_fast_analysis_returns_findings_and_claims() -> None:
    response = client.post(
        "/v1/analyze/fast",
        json={
            "code": VULNERABLE_CODE,
            "language": "python",
            "filename": "app.py",
        },
    )

    assert response.status_code == 200

    payload = response.json()

    assert "findings" in payload
    assert "claims" in payload
    assert len(payload["claims"]) == len(
        payload["findings"]
    )

    for claim in payload["claims"]:
        assert claim["claim_id"].startswith(
            "claim:sha256:"
        )
        assert claim["evidence"]


def test_safe_fast_analysis_returns_empty_claims() -> None:
    response = client.post(
        "/v1/analyze/fast",
        json={
            "code": "def add(a, b):\n    return a + b\n",
            "language": "python",
            "filename": "safe.py",
        },
    )

    assert response.status_code == 200

    payload = response.json()

    assert payload["findings"] == []
    assert payload["claims"] == []


def test_legacy_analysis_endpoint_exposes_claims(
    monkeypatch,
) -> None:
    async def deterministic_deep_analysis(
        request,
    ):
        return await analyzer.fast_analyze(
            request
        )

    monkeypatch.setattr(
        analyzer,
        "deep_analyze",
        deterministic_deep_analysis,
    )

    response = client.post(
        "/v1/analyze",
        json={
            "code": VULNERABLE_CODE,
            "language": "python",
            "filename": "app.py",
        },
    )

    assert response.status_code == 200

    payload = response.json()

    assert "findings" in payload
    assert "claims" in payload
    assert len(payload["claims"]) == len(
        payload["findings"]
    )


def test_response_keeps_existing_top_level_fields() -> None:
    response = client.post(
        "/v1/analyze/fast",
        json={
            "code": VULNERABLE_CODE,
            "language": "python",
            "filename": "app.py",
        },
    )

    assert response.status_code == 200

    payload = response.json()

    assert {
        "filename",
        "language",
        "model",
        "scanner",
        "analysis_status",
        "result_source",
        "findings",
    }.issubset(payload)


def test_deep_analysis_endpoint_exposes_multi_model_contract(
    monkeypatch,
) -> None:
    from aegis.schemas.analysis import (
        AnalyzeCodeResponse,
        ScannerEvidence,
        SecurityFinding,
    )
    from aegis.schemas.claims import (
        EvidenceItem,
        EvidenceSource,
        SecurityClaim,
    )
    from aegis.schemas.model_consensus import (
        FindingConsensusDecision,
        ModelConsensusResult,
    )

    finding = SecurityFinding(
        title="Command Injection",
        severity="high",
        confidence=0.90,
        primary_model="fake/primary",
        verifier_model="fake/verifier",
        verifier_verdict="supported",
        verifier_confidence=0.94,
        verifier_reasoning=(
            "The shell invocation confirms the unsafe flow."
        ),
        verifier_evidence=[
            "subprocess.run(user_input, shell=True)",
        ],
        consensus_verdict="confirmed",
        consensus_confidence=0.92,
        consensus_reasons=[
            "The independent verifier supports the finding.",
        ],
        summary=(
            "Untrusted input may reach shell execution."
        ),
        evidence=[
            "Caller-controlled input reaches shell=True.",
        ],
        scanner_evidence=[
            ScannerEvidence(
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
                line_start=4,
                line_end=4,
                code=(
                    "subprocess.run(user_input, shell=True)"
                ),
                cwe=["CWE-78"],
                owasp=["A03:2021"],
            )
        ],
        cwe=["CWE-78"],
        owasp=["A03:2021"],
        vulnerable_lines=[4],
        recommended_fix=(
            "Pass an argument list and disable shell execution."
        ),
    )

    claim = SecurityClaim(
        claim_id="claim:sha256:test-contract",
        statement=finding.summary,
        category="command-injection",
        severity="high",
        confidence=0.92,
        state="confirmed",
        cwe=["CWE-78"],
        owasp=["A03:2021"],
        evidence=[
            EvidenceItem(
                evidence_id="evidence:scanner",
                source=EvidenceSource(
                    kind="scanner",
                    name="Semgrep",
                    rule_id=(
                        "aegis.python.command-injection."
                        "subprocess-shell"
                    ),
                ),
                summary="Scanner evidence.",
                confidence=0.90,
            ),
            EvidenceItem(
                evidence_id="evidence:primary",
                source=EvidenceSource(
                    kind="model_review",
                    name="fake/primary",
                ),
                summary="Primary model review.",
                confidence=0.90,
            ),
            EvidenceItem(
                evidence_id="evidence:verifier",
                source=EvidenceSource(
                    kind="model_verification",
                    name="fake/verifier",
                ),
                summary="Verifier supported the finding.",
                confidence=0.94,
            ),
            EvidenceItem(
                evidence_id="evidence:consensus",
                source=EvidenceSource(
                    kind="model_consensus",
                    name="Aegis Deterministic Consensus",
                ),
                summary=(
                    "Consensus classified the finding "
                    "as confirmed."
                ),
                confidence=0.92,
            ),
        ],
        remediation=finding.recommended_fix,
    )

    consensus = ModelConsensusResult(
        primary_model="fake/primary",
        verifier_model="fake/verifier",
        status="completed",
        decisions=[
            FindingConsensusDecision(
                finding_index=0,
                verdict="confirmed",
                confidence=0.92,
                primary_confidence=0.90,
                verifier_confidence=0.94,
                reasons=[
                    (
                        "The independent verifier "
                        "supports the finding."
                    ),
                ],
            )
        ],
    )

    async def deterministic_deep_analysis(
        request,
    ) -> AnalyzeCodeResponse:
        return AnalyzeCodeResponse(
            filename=request.filename,
            language=request.language,
            model="fake/primary",
            scanner="semgrep",
            analysis_status="completed",
            result_source="ai",
            findings=[finding],
            claims=[claim],
            model_consensus=consensus,
        )

    monkeypatch.setattr(
        analyzer,
        "deep_analyze",
        deterministic_deep_analysis,
    )

    response = client.post(
        "/v1/analyze/deep",
        json={
            "code": VULNERABLE_CODE,
            "language": "python",
            "filename": "app.py",
        },
    )

    assert response.status_code == 200

    payload = response.json()

    assert payload["model"] == "fake/primary"
    assert payload["analysis_status"] == "completed"
    assert payload["result_source"] == "ai"

    finding_payload = payload["findings"][0]

    assert finding_payload["confidence"] == 0.90
    assert finding_payload["primary_model"] == "fake/primary"
    assert finding_payload["verifier_model"] == "fake/verifier"
    assert finding_payload["verifier_verdict"] == "supported"
    assert finding_payload["verifier_confidence"] == 0.94
    assert (
        finding_payload["consensus_verdict"]
        == "confirmed"
    )
    assert finding_payload["consensus_confidence"] == 0.92
    assert finding_payload["consensus_reasons"]

    consensus_payload = payload["model_consensus"]

    assert consensus_payload["status"] == "completed"
    assert (
        consensus_payload["primary_model"]
        == "fake/primary"
    )
    assert (
        consensus_payload["verifier_model"]
        == "fake/verifier"
    )
    assert (
        consensus_payload["decisions"][0]["verdict"]
        == "confirmed"
    )

    claim_payload = payload["claims"][0]

    assert claim_payload["state"] == "confirmed"
    assert claim_payload["confidence"] == 0.92
    assert {
        evidence["source"]["kind"]
        for evidence in claim_payload["evidence"]
    } == {
        "scanner",
        "model_review",
        "model_verification",
        "model_consensus",
    }


def test_fast_endpoint_has_null_model_consensus() -> None:
    response = client.post(
        "/v1/analyze/fast",
        json={
            "code": VULNERABLE_CODE,
            "language": "python",
            "filename": "app.py",
        },
    )

    assert response.status_code == 200
    assert response.json()["model_consensus"] is None
