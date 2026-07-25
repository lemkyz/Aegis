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
