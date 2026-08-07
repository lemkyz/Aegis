from __future__ import annotations

import pytest
from pydantic import ValidationError

from aegis.schemas.attack_graph import (
    AttackGraphArtifact,
    AttackGraphStep,
    AttackGraphSummary,
    AttackPath,
    SensitiveDataExposure,
    TrustBoundaryCrossing,
)


def step(
    source: str,
    target: str,
    *,
    relationship: str = "data_flow",
) -> AttackGraphStep:
    return AttackGraphStep(
        source_node_id=source,
        target_node_id=target,
        relationship=relationship,
        confidence=0.97,
        evidence=[
            f"{source} reaches {target}.",
        ],
    )


def path() -> AttackPath:
    return AttackPath(
        path_id="attack-path:sha256:" + "1" * 64,
        threat_id="threat:sql-injection",
        source_node_id="node:user-input",
        sink_node_id="node:database",
        node_ids=[
            "node:user-input",
            "node:parameter",
            "node:database",
        ],
        steps=[
            step(
                "node:user-input",
                "node:parameter",
            ),
            step(
                "node:parameter",
                "node:database",
            ),
        ],
        boundary_crossing_ids=[
            "boundary-crossing:sha256:" + "2" * 64,
        ],
        risk="critical",
        exploitability="confirmed",
        confidence=0.97,
        evidence=[
            "Attacker-controlled input reaches a database sink.",
        ],
    )


def crossing() -> TrustBoundaryCrossing:
    return TrustBoundaryCrossing(
        crossing_id=(
            "boundary-crossing:sha256:"
            + "2" * 64
        ),
        boundary_id="boundary:request",
        boundary_type="untrusted_input",
        node_id="node:user-input",
        direction="entry",
        evidence=[
            "Request data enters the application.",
        ],
    )


def exposure() -> SensitiveDataExposure:
    return SensitiveDataExposure(
        exposure_id=(
            "data-exposure:sha256:"
            + "3" * 64
        ),
        path_id=path().path_id,
        source_node_id="node:user-input",
        sink_node_id="node:database",
        data_classes=[
            "credential",
            "pii",
        ],
        sink_kind="database",
        risk="critical",
        evidence=[
            "Sensitive data can reach the sink on the proven path.",
        ],
    )


def artifact() -> AttackGraphArtifact:
    return AttackGraphArtifact(
        builder="aegis-attack-graph-v1",
        source_artifacts=[
            "attack_surface_graph",
            "threat_model",
        ],
        attack_paths=[path()],
        boundary_crossings=[crossing()],
        sensitive_data_exposures=[
            exposure()
        ],
        summary=AttackGraphSummary(
            attack_paths=1,
            boundary_crossings=1,
            sensitive_data_exposures=1,
            critical_paths=1,
            high_paths=0,
            confirmed_paths=1,
        ),
    )


def test_attack_graph_artifact_is_strict_and_frozen() -> None:
    item = artifact()

    with pytest.raises(ValidationError):
        AttackGraphArtifact.model_validate({
            **item.model_dump(mode="json"),
            "unexpected": True,
        })

    with pytest.raises(ValidationError):
        item.builder = "changed"  # type: ignore[misc]


def test_attack_path_requires_exact_step_chain() -> None:
    payload = path().model_dump(
        mode="json"
    )
    payload["steps"] = [
        step(
            "node:user-input",
            "node:database",
        ).model_dump(mode="json"),
    ]

    with pytest.raises(
        ValidationError,
        match="step chain|node_ids",
    ):
        AttackPath.model_validate(payload)


def test_attack_path_rejects_wrong_source_or_sink() -> None:
    payload = path().model_dump(mode="json")
    payload["source_node_id"] = "node:other"

    with pytest.raises(
        ValidationError,
        match="source|path",
    ):
        AttackPath.model_validate(payload)


def test_attack_graph_rejects_duplicate_path_identity() -> None:
    item = artifact()
    payload = item.model_dump(mode="json")
    payload["attack_paths"] = [
        item.attack_paths[0].model_dump(
            mode="json"
        ),
        item.attack_paths[0].model_dump(
            mode="json"
        ),
    ]
    payload["summary"]["attack_paths"] = 2
    payload["summary"]["critical_paths"] = 2
    payload["summary"]["confirmed_paths"] = 2

    with pytest.raises(
        ValidationError,
        match="duplicate.*path",
    ):
        AttackGraphArtifact.model_validate(
            payload
        )


def test_exposure_must_reference_existing_attack_path() -> None:
    item = artifact()
    payload = item.model_dump(mode="json")
    payload[
        "sensitive_data_exposures"
    ][0]["path_id"] = "attack-path:missing"

    with pytest.raises(
        ValidationError,
        match="exposure.*path",
    ):
        AttackGraphArtifact.model_validate(
            payload
        )


def test_summary_must_match_material_graph_content() -> None:
    item = artifact()
    payload = item.model_dump(mode="json")
    payload["summary"][
        "boundary_crossings"
    ] = 99

    with pytest.raises(
        ValidationError,
        match="summary",
    ):
        AttackGraphArtifact.model_validate(
            payload
        )


def test_only_declared_source_artifacts_are_accepted() -> None:
    item = artifact()
    payload = item.model_dump(mode="json")
    payload["source_artifacts"] = [
        "threat_model",
    ]

    with pytest.raises(
        ValidationError,
        match="source_artifacts",
    ):
        AttackGraphArtifact.model_validate(
            payload
        )


def test_attack_graph_digest_is_deterministic() -> None:
    first = artifact()
    second = AttackGraphArtifact.model_validate(
        first.model_dump(mode="json")
    )

    assert first.artifact_sha256() == (
        second.artifact_sha256()
    )
    assert len(first.artifact_sha256()) == 64


def test_attack_graph_digest_changes_with_material_path_state() -> None:
    first = artifact()
    payload = first.model_dump(mode="json")
    payload["attack_paths"][0][
        "risk"
    ] = "high"
    payload["summary"][
        "critical_paths"
    ] = 0
    payload["summary"][
        "high_paths"
    ] = 1
    second = AttackGraphArtifact.model_validate(
        payload
    )

    assert first.artifact_sha256() != (
        second.artifact_sha256()
    )


def test_data_sentinel_classes_are_closed_contract() -> None:
    payload = exposure().model_dump(
        mode="json"
    )
    payload["data_classes"] = [
        "totally_unknown_class",
    ]

    with pytest.raises(ValidationError):
        SensitiveDataExposure.model_validate(
            payload
        )
