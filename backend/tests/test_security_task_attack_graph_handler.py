from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from aegis.orchestrator.security_task_attack_graph_handler import (
    AttackGraphTaskHandler,
)
from aegis.orchestrator.security_task_handler import (
    SecurityTaskHandlerContext,
)
from aegis.orchestrator.security_task_handlers import (
    SecurityTaskInputError,
)
from aegis.schemas.attack_graph import (
    AttackGraphArtifact,
)
from aegis.schemas.attack_surface import (
    AttackSurfaceFile,
)
from aegis.schemas.security_task_plan import (
    SecurityTaskNode,
)
from aegis.security.attack_surface import (
    AttackSurfaceMapper,
)
from aegis.security.threat_model import ThreatModeler


CODE = """
import os


def execute(request):
    command = request.args.get("command")
    return os.system(command)
""".strip()


def run(coro):
    return asyncio.run(coro)


def task() -> SecurityTaskNode:
    return SecurityTaskNode(
        task_id="attack_graph",
        kind="attack_graph",
        state="ready",
        produces=["attack_graph"],
    )


def context(
    root: Path,
) -> SecurityTaskHandlerContext:
    return SecurityTaskHandlerContext(
        execution_id="execution:attack-graph-test",
        operation="repository_review",
        language="python",
        repository_root=str(root),
        metadata={},
    )


def inputs() -> dict[str, object]:
    files = [
        AttackSurfaceFile(
            filename="app.py",
            language="python",
            code=CODE,
        )
    ]
    surface = AttackSurfaceMapper().scan(
        files
    )
    threat_model = ThreatModeler().scan(
        files
    )
    return {
        "attack_surface_graph": (
            surface.model_dump(mode="json")
        ),
        "threat_model": (
            threat_model.model_dump(mode="json")
        ),
    }


def test_attack_graph_handler_contract() -> None:
    capability = (
        AttackGraphTaskHandler.capability
    )

    assert capability.kind == "attack_graph"
    assert capability.required_artifacts == frozenset({
        "attack_surface_graph",
        "threat_model",
    })
    assert capability.produced_artifacts == frozenset({
        "attack_graph",
    })
    assert capability.side_effect_free is True


def test_attack_graph_handler_emits_deterministic_artifact(
    tmp_path: Path,
) -> None:
    handler = AttackGraphTaskHandler()
    payload = inputs()

    first = run(
        handler.execute(
            task=task(),
            context=context(tmp_path),
            inputs=payload,
        )
    )
    second = run(
        handler.execute(
            task=task(),
            context=context(tmp_path),
            inputs=payload,
        )
    )

    first_artifact = (
        AttackGraphArtifact.model_validate(
            first.output["attack_graph"]
        )
    )
    second_artifact = (
        AttackGraphArtifact.model_validate(
            second.output["attack_graph"]
        )
    )

    assert first_artifact == second_artifact
    assert first_artifact.attack_paths
    assert (
        first.metadata[
            "attack_graph_sha256"
        ]
        == first_artifact.artifact_sha256()
    )
    assert (
        first_artifact.artifact_sha256()
        == second_artifact.artifact_sha256()
    )


def test_attack_graph_handler_rejects_provenance_drift(
    tmp_path: Path,
) -> None:
    payload = inputs()
    surface = dict(
        payload["attack_surface_graph"]
    )
    surface["nodes"] = (
        surface["nodes"][:-1]
    )
    payload[
        "attack_surface_graph"
    ] = surface

    with pytest.raises(
        SecurityTaskInputError,
        match="provenance|attack surface|drift",
    ):
        run(
            AttackGraphTaskHandler()
            .execute(
                task=task(),
                context=context(tmp_path),
                inputs=payload,
            )
        )


def test_attack_graph_handler_rejects_invalid_source_artifact(
    tmp_path: Path,
) -> None:
    payload = inputs()
    payload["threat_model"] = {
        "invalid": True,
    }

    with pytest.raises(
        SecurityTaskInputError,
        match="valid threat model|provenance",
    ):
        run(
            AttackGraphTaskHandler()
            .execute(
                task=task(),
                context=context(tmp_path),
                inputs=payload,
            )
        )
