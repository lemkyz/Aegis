import os

from fastapi.testclient import TestClient


os.environ.setdefault(
    "AEGIS_FINGERPRINT_KEY",
    "test-only-fingerprint-key-32-characters",
)


from aegis.main import app


client = TestClient(app)


def claim_payload(
    claim_id: str,
    *,
    severity: str,
    state: str = "confirmed",
    confidence: float = 1.0,
) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "claim_id": claim_id,
        "statement": "A security issue exists.",
        "category": "command-injection",
        "severity": severity,
        "confidence": confidence,
        "state": state,
        "cwe": ["CWE-78"],
        "owasp": ["A03:2021"],
        "locations": [],
        "evidence": [],
        "relationships": [],
        "remediation": "Apply a secure fix.",
        "proposed_patch": None,
    }


def reconciliation_payload(
    *deltas: dict[str, object],
) -> dict[str, object]:
    statuses = [
        delta["status"]
        for delta in deltas
    ]

    return {
        "reconciler": (
            "aegis-claim-reconciler-v1"
        ),
        "deltas": list(deltas),
        "summary": {
            "previous_count": sum(
                delta.get("previous_claim")
                is not None
                for delta in deltas
            ),
            "current_count": sum(
                delta.get("current_claim")
                is not None
                for delta in deltas
            ),
            "new": statuses.count("new"),
            "persistent": statuses.count(
                "persistent"
            ),
            "changed": statuses.count(
                "changed"
            ),
            "resolved": statuses.count(
                "resolved"
            ),
            "reopened": statuses.count(
                "reopened"
            ),
        },
    }


def test_policy_endpoint_blocks_critical_claim(
) -> None:
    current = claim_payload(
        "claim:critical",
        severity="critical",
    )

    response = client.post(
        "/v1/security-memory/policy",
        json={
            "profile": "balanced",
            "reconciliation": (
                reconciliation_payload(
                    {
                        "claim_id": (
                            current["claim_id"]
                        ),
                        "status": "new",
                        "previous_state": None,
                        "current_state": (
                            current["state"]
                        ),
                        "previous_claim": None,
                        "current_claim": current,
                        "reasons": [],
                    }
                )
            ),
        },
    )

    assert response.status_code == 200

    payload = response.json()

    assert payload["decision"] == "block"
    assert payload["risk_score"] == 95
    assert payload["risk_level"] == (
        "critical"
    )
    assert payload[
        "blocking_claim_ids"
    ] == ["claim:critical"]


def test_policy_endpoint_blocks_reopened_high_claim(
) -> None:
    previous = claim_payload(
        "claim:reopened",
        severity="high",
        state="verified_fixed",
    )
    current = claim_payload(
        "claim:reopened",
        severity="high",
        state="confirmed",
    )

    response = client.post(
        "/v1/security-memory/policy",
        json={
            "reconciliation": (
                reconciliation_payload(
                    {
                        "claim_id": (
                            current["claim_id"]
                        ),
                        "status": "reopened",
                        "previous_state": (
                            previous["state"]
                        ),
                        "current_state": (
                            current["state"]
                        ),
                        "previous_claim": previous,
                        "current_claim": current,
                        "reasons": [],
                    }
                )
            ),
        },
    )

    assert response.status_code == 200

    payload = response.json()

    assert payload["decision"] == "block"
    assert payload["summary"][
        "reopened"
    ] == 1
    assert payload["assessments"][0][
        "lifecycle_status"
    ] == "reopened"


def test_policy_endpoint_allows_empty_result(
) -> None:
    response = client.post(
        "/v1/security-memory/policy",
        json={
            "reconciliation": (
                reconciliation_payload()
            ),
        },
    )

    assert response.status_code == 200

    payload = response.json()

    assert payload["decision"] == "allow"
    assert payload["risk_score"] == 0
    assert payload["risk_level"] == "none"


def test_policy_endpoint_validates_profile(
) -> None:
    response = client.post(
        "/v1/security-memory/policy",
        json={
            "profile": "unknown",
            "reconciliation": (
                reconciliation_payload()
            ),
        },
    )

    assert response.status_code == 422


def test_policy_endpoint_validates_summary(
) -> None:
    response = client.post(
        "/v1/security-memory/policy",
        json={
            "reconciliation": {
                "reconciler": "test",
                "deltas": [],
                "summary": {
                    "previous_count": 0,
                    "current_count": 0,
                    "new": -1,
                    "persistent": 0,
                    "changed": 0,
                    "resolved": 0,
                    "reopened": 0,
                },
            },
        },
    )

    assert response.status_code == 422
