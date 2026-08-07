from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pydantic import ValidationError

from aegis.orchestrator.security_task_handler import (
    SecurityTaskHandlerCapability,
    SecurityTaskHandlerContext,
    SecurityTaskHandlerResult,
)
from aegis.orchestrator.security_task_handlers import (
    SecurityTaskInputError,
)
from aegis.schemas.attack_surface import (
    AttackSurfaceScanResponse,
)
from aegis.schemas.security_task_plan import (
    SecurityTaskNode,
)
from aegis.schemas.threat_model import (
    ThreatModelScanResponse,
)
from aegis.security.attack_graph import (
    AttackGraphBuilder,
)


class AttackGraphTaskHandler:
    handler = (
        "aegis-attack-graph-task-handler-v1"
    )

    capability = SecurityTaskHandlerCapability(
        kind="attack_graph",
        required_artifacts=frozenset({
            "attack_surface_graph",
            "threat_model",
        }),
        produced_artifacts=frozenset({
            "attack_graph",
        }),
        supports_retry=True,
        max_attempts=2,
        side_effect_free=True,
    )

    def __init__(
        self,
        *,
        builder: AttackGraphBuilder
        | None = None,
    ) -> None:
        self._builder = (
            builder
            or AttackGraphBuilder()
        )

    async def execute(
        self,
        *,
        task: SecurityTaskNode,
        context: SecurityTaskHandlerContext,
        inputs: Mapping[str, Any],
    ) -> SecurityTaskHandlerResult:
        del task

        context.raise_if_cancelled()

        try:
            attack_surface = (
                AttackSurfaceScanResponse
                .model_validate(
                    inputs.get(
                        "attack_surface_graph"
                    )
                )
            )
        except ValidationError as exc:
            raise SecurityTaskInputError(
                "Attack graph requires a valid "
                "attack surface provenance artifact."
            ) from exc

        try:
            threat_model = (
                ThreatModelScanResponse
                .model_validate(
                    inputs.get(
                        "threat_model"
                    )
                )
            )
        except ValidationError as exc:
            raise SecurityTaskInputError(
                "Attack graph requires a valid "
                "threat model provenance artifact."
            ) from exc

        try:
            artifact = self._builder.build(
                attack_surface=attack_surface,
                threat_model=threat_model,
            )
        except ValueError as exc:
            raise SecurityTaskInputError(
                "Attack graph provenance drift "
                "or integrity failure."
            ) from exc

        context.raise_if_cancelled()

        digest = artifact.artifact_sha256()

        return SecurityTaskHandlerResult(
            output={
                "attack_graph": (
                    artifact.model_dump(
                        mode="json"
                    )
                ),
            },
            metadata={
                "handler": self.handler,
                "builder": artifact.builder,
                "attack_graph_sha256": (
                    digest
                ),
                "attack_paths": (
                    artifact.summary.attack_paths
                ),
                "boundary_crossings": (
                    artifact.summary
                    .boundary_crossings
                ),
                "sensitive_data_exposures": (
                    artifact.summary
                    .sensitive_data_exposures
                ),
            },
            reasons=[
                (
                    "Attack paths are materialized "
                    "only from graph-proven "
                    "source-to-sink data-flow edges."
                ),
                (
                    "Data Sentinel classifications "
                    "are attached only to proven "
                    "attack paths."
                ),
            ],
        )
