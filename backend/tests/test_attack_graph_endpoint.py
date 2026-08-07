import os

from fastapi.testclient import TestClient


os.environ.setdefault(
    "AEGIS_FINGERPRINT_KEY",
    "test-only-fingerprint-key-32-characters",
)

from aegis.main import app
from aegis.schemas.attack_surface import (
    AttackSurfaceFile,
)
from aegis.security.attack_surface import (
    AttackSurfaceMapper,
)
from aegis.security.threat_model import (
    ThreatModeler,
)


client = TestClient(app)


def source_artifacts() -> tuple[dict, dict]:
    files = [
        AttackSurfaceFile(
            filename="app.py",
            language="python",
            code="""
import os


def execute(request):
    command = request.args.get("command")
    return os.system(command)
""".strip(),
        )
    ]

    surface = AttackSurfaceMapper().scan(files)
    threat_model = ThreatModeler().scan(files)

    return (
        surface.model_dump(mode="json"),
        threat_model.model_dump(mode="json"),
    )


def test_attack_graph_endpoint_builds_exact_graph() -> None:
    surface, threat_model = source_artifacts()

    response = client.post(
        "/v1/attack-graph/build",
        json={
            "attack_surface": surface,
            "threat_model": threat_model,
        },
    )

    assert response.status_code == 200
    payload = response.json()

    assert payload["builder"] == (
        "aegis-attack-graph-v1"
    )
    assert payload["source_artifacts"] == [
        "attack_surface_graph",
        "threat_model",
    ]
    assert payload["attack_paths"]
    assert (
        payload["summary"]["attack_paths"]
        == len(payload["attack_paths"])
    )
    assert (
        payload["summary"]["confirmed_paths"]
        >= 1
    )


def test_attack_graph_endpoint_fails_closed_on_provenance_drift() -> None:
    surface, threat_model = source_artifacts()

    surface["nodes"] = surface["nodes"][:-1]

    response = client.post(
        "/v1/attack-graph/build",
        json={
            "attack_surface": surface,
            "threat_model": threat_model,
        },
    )

    assert response.status_code == 409
    assert (
        "provenance"
        in response.json()["detail"].lower()
    )
