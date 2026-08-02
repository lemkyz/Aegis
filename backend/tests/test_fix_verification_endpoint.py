import os

from fastapi.testclient import TestClient


os.environ.setdefault(
    "AEGIS_FINGERPRINT_KEY",
    "test-only-fingerprint-key-32-characters",
)

from aegis.main import app


client = TestClient(app)


def _payload() -> dict[str, object]:
    return {
        "replay": {
            "comparator": (
                "aegis-dynamic-validation-replay-v1"
            ),
            "threat_id": "threat-command-001",
            "category": "command_injection",
            "verdict": "fixed",
            "fixed": True,
            "confidence": 0.99,
            "before_verdict": "confirmed",
            "after_verdict": "not_reproduced",
            "reasons": [],
            "denials": [],
        },
        "project_checks": [
            {
                "name": "Syntax check",
                "status": "passed",
                "details": "Syntax passed.",
            },
            {
                "name": "Tests",
                "status": "passed",
                "details": "Tests passed.",
            },
            {
                "name": "Build",
                "status": "passed",
                "details": "Build passed.",
            },
        ],
        "static_target_resolved": True,
        "static_regression_free": True,
    }


def test_fix_verification_endpoint_verifies() -> None:
    response = client.post(
        "/v1/validation/fix-verification",
        json=_payload(),
    )

    assert response.status_code == 200

    payload = response.json()

    assert payload["evaluator"] == (
        "aegis-unified-fix-verification-v1"
    )
    assert payload["verdict"] == "verified"
    assert payload["verified"] is True
    assert payload["dynamic_replay_fixed"] is True


def test_fix_verification_endpoint_reports_regression() -> None:
    payload = _payload()
    payload["static_regression_free"] = False

    response = client.post(
        "/v1/validation/fix-verification",
        json=payload,
    )

    assert response.status_code == 200

    body = response.json()

    assert body["verdict"] == (
        "regression_detected"
    )
    assert body["verified"] is False


def test_fix_verification_endpoint_validates_check_status() -> None:
    payload = _payload()
    payload["project_checks"][0][
        "status"
    ] = "unknown"

    response = client.post(
        "/v1/validation/fix-verification",
        json=payload,
    )

    assert response.status_code == 422


def test_fix_verification_endpoint_fails_closed_for_skipped_check() -> None:
    payload = _payload()
    payload["project_checks"][1][
        "status"
    ] = "skipped"

    response = client.post(
        "/v1/validation/fix-verification",
        json=payload,
    )

    assert response.status_code == 200

    body = response.json()

    assert body["verdict"] == "inconclusive"
    assert body["verified"] is False
    assert body["project_checks_passed"] is False

    assert body["passed_checks"] == [
        "Syntax check",
        "Build",
    ]
    assert body["failed_checks"] == []
    assert body["skipped_checks"] == [
        "Tests",
    ]

    assert any(
        "skipped" in reason.lower()
        or "incomplete" in reason.lower()
        for reason in body["reasons"]
    )
