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
        "authorization": {
            "authorization_confirmed": True,
            "target_type": "local_repository",
            "target": "/tmp/aegis-project",
            "allowed_test_types": [
                "command_injection",
            ],
            "dry_run": False,
            "timeout_seconds": 10,
            "memory_limit_mb": 256,
            "cpu_limit": 0.5,
            "network_policy": "disabled",
        },
        "runtime": "python",
        "entrypoint": "validation.py",
        "test_type": "command_injection",
    }


def test_validation_plan_endpoint_returns_plan() -> None:
    response = client.post(
        "/v1/validation/plan",
        json=_payload(),
    )

    assert response.status_code == 200

    payload = response.json()

    assert payload["planner"] == (
        "aegis-isolated-validation-plan-v1"
    )
    assert payload["ready"] is True
    assert payload["authorization"][
        "authorized"
    ] is True
    assert payload["image"] == "python:3.14-slim"
    assert payload["command"] == [
        "python",
        "-I",
        "-c",
        (
            "import pathlib, runpy, sys; "
                "script = pathlib.Path(sys.argv[1]); "
            "sys.path.insert(0, '/workspace'); "
                "sys.path.insert(0, str(script.parent)); "
            "runpy.run_path("
            "str(script), "
            "run_name='__main__'"
            ")"
        ),
        "/workspace/validation.py",
    ]
    assert payload["sandbox"]["network"] == "none"
    assert payload["mounts"][0]["read_only"] is True


def test_validation_plan_endpoint_rejects_escape() -> None:
    payload = _payload()
    payload["entrypoint"] = "../../etc/passwd"

    response = client.post(
        "/v1/validation/plan",
        json=payload,
    )

    assert response.status_code == 200

    body = response.json()

    assert body["ready"] is False
    assert body["command"] == []
    assert body["denials"]


def test_validation_plan_endpoint_validates_runtime() -> None:
    payload = _payload()
    payload["runtime"] = "shell"

    response = client.post(
        "/v1/validation/plan",
        json=payload,
    )

    assert response.status_code == 422
