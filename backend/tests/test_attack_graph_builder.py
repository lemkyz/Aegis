from __future__ import annotations

import pytest

from aegis.schemas.attack_surface import (
    AttackSurfaceFile,
    AttackSurfaceScanResponse,
)
from aegis.security.attack_graph import (
    AttackGraphBuilder,
)
from aegis.security.attack_surface import (
    AttackSurfaceMapper,
)
from aegis.security.threat_model import ThreatModeler


def analyze(
    code: str,
    *,
    filename: str = "app.py",
) -> tuple[
    AttackSurfaceScanResponse,
    object,
]:
    files = [
        AttackSurfaceFile(
            filename=filename,
            language="python",
            code=code.strip(),
        )
    ]
    surface = AttackSurfaceMapper().scan(files)
    threats = ThreatModeler().scan(files)
    return surface, threats


def test_builds_proven_command_injection_attack_path() -> None:
    surface, threats = analyze(
        """
import os


def execute(request):
    command = request.args.get("command")
    return os.system(command)
"""
    )

    artifact = AttackGraphBuilder().build(
        attack_surface=surface,
        threat_model=threats,
    )

    path = next(
        item
        for item in artifact.attack_paths
        if item.exploitability == "confirmed"
    )

    assert path.risk == "critical"
    assert len(path.node_ids) == 2
    assert len(path.steps) == 1
    assert (
        path.steps[0].relationship
        == "data_flow"
    )
    assert any(
        "request.args.get" in detail
        for detail in path.steps[0].evidence
    )
    assert (
        artifact.summary.attack_paths
        == len(artifact.attack_paths)
    )
    assert artifact.summary.confirmed_paths >= 1


def test_attack_graph_is_deterministic() -> None:
    surface, threats = analyze(
        """
import requests


def fetch(request):
    raw_url = request.args.get("url")
    target = raw_url.strip()
    return requests.get(target)
"""
    )

    builder = AttackGraphBuilder()
    first = builder.build(
        attack_surface=surface,
        threat_model=threats,
    )
    second = builder.build(
        attack_surface=surface,
        threat_model=threats,
    )

    assert first == second
    assert (
        first.artifact_sha256()
        == second.artifact_sha256()
    )


def test_attack_graph_does_not_invent_path_without_graph_proof() -> None:
    surface, threats = analyze(
        """
import requests


def fetch(request):
    ignored = request.args.get("url")
    target = "https://api.example.com"
    return requests.get(target)
"""
    )

    artifact = AttackGraphBuilder().build(
        attack_surface=surface,
        threat_model=threats,
    )

    ssrf_ids = {
        threat.id
        for threat in threats.threats
        if threat.category == "ssrf"
        and not threat.data_flow
    }
    assert ssrf_ids
    assert not any(
        path.threat_id in ssrf_ids
        for path in artifact.attack_paths
    )


def test_attack_graph_rejects_surface_threat_model_drift() -> None:
    surface, threats = analyze(
        """
import os


def execute(request):
    command = request.args.get("command")
    return os.system(command)
"""
    )

    mismatched = surface.model_copy(
        deep=True,
        update={
            "nodes": surface.nodes[:-1],
        },
    )

    with pytest.raises(
        ValueError,
        match="attack surface|drift|provenance",
    ):
        AttackGraphBuilder().build(
            attack_surface=mismatched,
            threat_model=threats,
        )


def test_attack_graph_materializes_trust_boundary_crossings() -> None:
    surface, threats = analyze(
        """
import requests


def fetch(request):
    url = request.args.get("url")
    return requests.get(url)
"""
    )

    artifact = AttackGraphBuilder().build(
        attack_surface=surface,
        threat_model=threats,
    )

    assert artifact.attack_paths
    assert artifact.boundary_crossings
    assert any(
        crossing.direction
        in {"entry", "outbound"}
        for crossing
        in artifact.boundary_crossings
    )
    assert any(
        path.boundary_crossing_ids
        for path in artifact.attack_paths
    )


def test_data_sentinel_detects_explicit_credential_flow() -> None:
    surface, threats = analyze(
        """
def login(db, request):
    password = request.args.get("password")
    query = f"SELECT * FROM users WHERE password = '{password}'"
    return db.execute(query).fetchone()
"""
    )

    artifact = AttackGraphBuilder().build(
        attack_surface=surface,
        threat_model=threats,
    )

    exposures = (
        artifact.sensitive_data_exposures
    )
    assert exposures
    assert any(
        "credential" in item.data_classes
        for item in exposures
    )
    assert any(
        item.sink_kind == "database"
        for item in exposures
    )


def test_data_sentinel_does_not_label_generic_input_sensitive() -> None:
    surface, threats = analyze(
        """
import os


def execute(request):
    command = request.args.get("command")
    return os.system(command)
"""
    )

    artifact = AttackGraphBuilder().build(
        attack_surface=surface,
        threat_model=threats,
    )

    assert (
        artifact.sensitive_data_exposures
        == []
    )


def test_secret_exposure_carries_secret_data_class_when_graph_proven() -> None:
    surface, threats = analyze(
        """
import os
import requests


def send_secret(request):
    api_key = os.environ["APP_API_KEY"]
    url = request.args.get("url")
    return requests.get(
        f"{url}?api_key={api_key}"
    )
"""
    )

    artifact = AttackGraphBuilder().build(
        attack_surface=surface,
        threat_model=threats,
    )

    secret_exposures = [
        item
        for item
        in artifact.sensitive_data_exposures
        if (
            "secret" in item.data_classes
            or "credential"
            in item.data_classes
        )
    ]

    assert secret_exposures


def test_path_confidence_never_exceeds_underlying_proof() -> None:
    surface, threats = analyze(
        """
import os


def execute(request):
    command = request.args.get("command")
    return os.system(command)
"""
    )

    artifact = AttackGraphBuilder().build(
        attack_surface=surface,
        threat_model=threats,
    )

    threat_by_id = {
        threat.id: threat
        for threat in threats.threats
    }
    edge_by_pair = {
        (edge.source, edge.target): edge
        for edge in surface.edges
        if edge.relationship == "data_flow"
    }

    for path in artifact.attack_paths:
        threat = threat_by_id[
            path.threat_id
        ]
        edge = edge_by_pair[
            (
                path.source_node_id,
                path.sink_node_id,
            )
        ]
        assert path.confidence <= (
            threat.confidence
        )
        assert path.confidence <= (
            edge.confidence
        )
        if (
            threat.exploitability_confidence
            > 0
        ):
            assert path.confidence <= (
                threat
                .exploitability_confidence
            )
