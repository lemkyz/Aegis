from aegis.schemas.analysis import AnalyzeCodeResponse
from aegis.schemas.model_consensus import (
    ModelConsensusResult,
)


def test_analysis_response_serializes_route_metadata() -> None:
    response = AnalyzeCodeResponse(
        filename="app.py",
        language="python",
        model="model-a",
        scanner="semgrep",
        analysis_status="completed",
        result_source="ai",
        findings=[],
        model_consensus=ModelConsensusResult(
            primary_provider="nvidia",
            primary_model="model-a",
            verifier_provider="nvidia",
            verifier_model="model-b",
            route_independence=(
                "same_provider_distinct_model"
            ),
            independently_verified=True,
            route_reasons=[
                "Distinct models from the same provider.",
            ],
            status="completed",
        ),
    )

    payload = response.model_dump()
    consensus = payload["model_consensus"]

    assert consensus["primary_provider"] == "nvidia"
    assert consensus["verifier_provider"] == "nvidia"
    assert (
        consensus["route_independence"]
        == "same_provider_distinct_model"
    )
    assert consensus["independently_verified"] is True
    assert consensus["route_reasons"] == [
        "Distinct models from the same provider."
    ]
