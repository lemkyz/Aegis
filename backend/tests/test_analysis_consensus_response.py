from aegis.schemas.analysis import AnalyzeCodeResponse
from aegis.schemas.model_consensus import (
    FindingConsensusDecision,
    ModelConsensusResult,
)


def test_analysis_response_remains_backward_compatible() -> None:
    response = AnalyzeCodeResponse(
        filename="safe.py",
        language="python",
        model="not-used",
        scanner="semgrep",
        analysis_status="skipped",
        result_source="scanner",
        findings=[],
    )

    assert response.model_consensus is None
    assert response.claims == []


def test_analysis_response_exposes_model_consensus() -> None:
    consensus = ModelConsensusResult(
        primary_provider="provider-a",
        primary_model="fake/primary",
        verifier_provider="provider-b",
        verifier_model="fake/verifier",
        route_independence="independent",
        independently_verified=True,
        route_reasons=[
            "Distinct provider and model.",
        ],
        status="completed",
        decisions=[
            FindingConsensusDecision(
                finding_index=0,
                verdict="confirmed",
                confidence=0.93,
                primary_confidence=0.91,
                verifier_confidence=0.95,
                reasons=[
                    "Independent verification supported "
                    "the finding."
                ],
            )
        ],
    )

    response = AnalyzeCodeResponse(
        filename="app.py",
        language="python",
        model="fake/primary",
        scanner="semgrep+bandit",
        analysis_status="completed",
        result_source="ai",
        findings=[],
        model_consensus=consensus,
    )

    assert response.model_consensus is consensus
    assert (
        response.model_consensus.primary_provider
        == "provider-a"
    )
    assert (
        response.model_consensus.verifier_provider
        == "provider-b"
    )
    assert (
        response.model_consensus.route_independence
        == "independent"
    )
    assert (
        response.model_consensus.independently_verified
        is True
    )
    assert (
        response.model_consensus.decisions[0].verdict
        == "confirmed"
    )


def test_serialized_legacy_response_contains_null_consensus() -> None:
    response = AnalyzeCodeResponse(
        filename="safe.py",
        language="python",
        model="not-used",
        scanner="semgrep",
        analysis_status="skipped",
        result_source="scanner",
        findings=[],
    )

    payload = response.model_dump()

    assert "model_consensus" in payload
    assert payload["model_consensus"] is None
