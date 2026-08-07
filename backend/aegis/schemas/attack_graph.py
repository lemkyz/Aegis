from __future__ import annotations

import hashlib
import json
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    model_validator,
)


AttackGraphRisk = Literal[
    "info",
    "low",
    "medium",
    "high",
    "critical",
]

AttackGraphExploitability = Literal[
    "confirmed",
    "likely",
    "possible",
    "unlikely",
    "not_exploitable",
    "unknown",
]

TrustBoundaryDirection = Literal[
    "entry",
    "exit",
    "outbound",
    "internal",
]

SensitiveDataClass = Literal[
    "public",
    "internal",
    "confidential",
    "secret",
    "credential",
    "pii",
    "financial",
    "health",
    "session",
    "token",
    "unknown",
]

SensitiveSinkKind = Literal[
    "database",
    "filesystem",
    "outbound_request",
    "process_execution",
    "secret_access",
    "response",
    "log",
    "unknown",
]


class _ImmutableAttackGraphModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
    )


class AttackGraphStep(
    _ImmutableAttackGraphModel
):
    source_node_id: str = Field(
        min_length=1,
        max_length=500,
    )
    target_node_id: str = Field(
        min_length=1,
        max_length=500,
    )
    relationship: str = Field(
        min_length=1,
        max_length=100,
    )
    confidence: float = Field(
        ge=0.0,
        le=1.0,
    )
    evidence: list[str] = Field(
        min_length=1,
        max_length=100,
    )


class TrustBoundaryCrossing(
    _ImmutableAttackGraphModel
):
    crossing_id: str = Field(
        min_length=1,
        max_length=500,
    )
    boundary_id: str = Field(
        min_length=1,
        max_length=500,
    )
    boundary_type: str = Field(
        min_length=1,
        max_length=100,
    )
    node_id: str = Field(
        min_length=1,
        max_length=500,
    )
    direction: TrustBoundaryDirection
    evidence: list[str] = Field(
        min_length=1,
        max_length=100,
    )


class AttackPath(
    _ImmutableAttackGraphModel
):
    path_id: str = Field(
        min_length=1,
        max_length=500,
    )
    threat_id: str = Field(
        min_length=1,
        max_length=500,
    )
    source_node_id: str = Field(
        min_length=1,
        max_length=500,
    )
    sink_node_id: str = Field(
        min_length=1,
        max_length=500,
    )
    node_ids: list[str] = Field(
        min_length=2,
        max_length=500,
    )
    steps: list[AttackGraphStep] = Field(
        min_length=1,
        max_length=499,
    )
    boundary_crossing_ids: list[str] = Field(
        default_factory=list,
        max_length=100,
    )
    risk: AttackGraphRisk
    exploitability: (
        AttackGraphExploitability
    )
    confidence: float = Field(
        ge=0.0,
        le=1.0,
    )
    evidence: list[str] = Field(
        min_length=1,
        max_length=200,
    )

    @model_validator(mode="after")
    def validate_chain(
        self,
    ) -> "AttackPath":
        if (
            self.node_ids[0]
            != self.source_node_id
        ):
            raise ValueError(
                "Attack path source must match "
                "the first node_ids entry."
            )

        if (
            self.node_ids[-1]
            != self.sink_node_id
        ):
            raise ValueError(
                "Attack path sink must match "
                "the final node_ids entry."
            )

        if (
            len(self.steps)
            != len(self.node_ids) - 1
        ):
            raise ValueError(
                "Attack path step chain must match "
                "node_ids."
            )

        for index, step in enumerate(
            self.steps
        ):
            if (
                step.source_node_id
                != self.node_ids[index]
                or step.target_node_id
                != self.node_ids[index + 1]
            ):
                raise ValueError(
                    "Attack path step chain must "
                    "follow node_ids exactly."
                )

        if (
            len(set(self.node_ids))
            != len(self.node_ids)
        ):
            raise ValueError(
                "Attack path cannot contain a "
                "node cycle."
            )

        if (
            len(
                set(
                    self.boundary_crossing_ids
                )
            )
            != len(
                self.boundary_crossing_ids
            )
        ):
            raise ValueError(
                "Attack path contains duplicate "
                "boundary crossing identities."
            )

        return self


class SensitiveDataExposure(
    _ImmutableAttackGraphModel
):
    exposure_id: str = Field(
        min_length=1,
        max_length=500,
    )
    path_id: str = Field(
        min_length=1,
        max_length=500,
    )
    source_node_id: str = Field(
        min_length=1,
        max_length=500,
    )
    sink_node_id: str = Field(
        min_length=1,
        max_length=500,
    )
    data_classes: list[
        SensitiveDataClass
    ] = Field(
        min_length=1,
        max_length=50,
    )
    sink_kind: SensitiveSinkKind
    risk: AttackGraphRisk
    evidence: list[str] = Field(
        min_length=1,
        max_length=200,
    )

    @model_validator(mode="after")
    def validate_classes(
        self,
    ) -> "SensitiveDataExposure":
        if (
            len(set(self.data_classes))
            != len(self.data_classes)
        ):
            raise ValueError(
                "Sensitive data exposure contains "
                "duplicate data classes."
            )
        return self


class AttackGraphSummary(
    _ImmutableAttackGraphModel
):
    attack_paths: int = Field(ge=0)
    boundary_crossings: int = Field(ge=0)
    sensitive_data_exposures: int = Field(
        ge=0
    )
    critical_paths: int = Field(ge=0)
    high_paths: int = Field(ge=0)
    confirmed_paths: int = Field(ge=0)


class AttackGraphArtifact(
    _ImmutableAttackGraphModel
):
    schema_version: Literal["1.0"] = "1.0"
    builder: str = Field(
        min_length=1,
        max_length=200,
    )
    source_artifacts: list[str] = Field(
        min_length=2,
        max_length=2,
    )
    attack_paths: list[
        AttackPath
    ] = Field(
        default_factory=list,
        max_length=10_000,
    )
    boundary_crossings: list[
        TrustBoundaryCrossing
    ] = Field(
        default_factory=list,
        max_length=10_000,
    )
    sensitive_data_exposures: list[
        SensitiveDataExposure
    ] = Field(
        default_factory=list,
        max_length=10_000,
    )
    summary: AttackGraphSummary

    @model_validator(mode="after")
    def validate_graph(
        self,
    ) -> "AttackGraphArtifact":
        if self.source_artifacts != [
            "attack_surface_graph",
            "threat_model",
        ]:
            raise ValueError(
                "Attack graph source_artifacts "
                "must be exactly attack_surface_graph "
                "and threat_model."
            )

        path_ids = [
            item.path_id
            for item in self.attack_paths
        ]
        if len(set(path_ids)) != len(
            path_ids
        ):
            raise ValueError(
                "Attack graph contains duplicate "
                "attack path identities."
            )

        crossing_ids = [
            item.crossing_id
            for item in self.boundary_crossings
        ]
        if (
            len(set(crossing_ids))
            != len(crossing_ids)
        ):
            raise ValueError(
                "Attack graph contains duplicate "
                "trust-boundary crossing identities."
            )

        exposure_ids = [
            item.exposure_id
            for item
            in self.sensitive_data_exposures
        ]
        if (
            len(set(exposure_ids))
            != len(exposure_ids)
        ):
            raise ValueError(
                "Attack graph contains duplicate "
                "sensitive-data exposure identities."
            )

        known_paths = set(path_ids)
        known_crossings = set(crossing_ids)

        for item in self.attack_paths:
            unknown_crossings = (
                set(
                    item.boundary_crossing_ids
                )
                - known_crossings
            )
            if unknown_crossings:
                raise ValueError(
                    "Attack path references an "
                    "unknown trust-boundary crossing."
                )

        for item in (
            self.sensitive_data_exposures
        ):
            if item.path_id not in known_paths:
                raise ValueError(
                    "Sensitive data exposure "
                    "references an unknown attack path."
                )

            path = next(
                candidate
                for candidate in self.attack_paths
                if candidate.path_id
                == item.path_id
            )
            if (
                item.source_node_id
                != path.source_node_id
                or item.sink_node_id
                != path.sink_node_id
            ):
                raise ValueError(
                    "Sensitive data exposure endpoints "
                    "must match its attack path."
                )

        expected_summary = {
            "attack_paths": len(
                self.attack_paths
            ),
            "boundary_crossings": len(
                self.boundary_crossings
            ),
            "sensitive_data_exposures": len(
                self.sensitive_data_exposures
            ),
            "critical_paths": sum(
                item.risk == "critical"
                for item in self.attack_paths
            ),
            "high_paths": sum(
                item.risk == "high"
                for item in self.attack_paths
            ),
            "confirmed_paths": sum(
                item.exploitability
                == "confirmed"
                for item in self.attack_paths
            ),
        }

        if self.summary.model_dump() != (
            expected_summary
        ):
            raise ValueError(
                "Attack graph summary does not match "
                "material graph content."
            )

        return self

    def artifact_sha256(self) -> str:
        canonical = json.dumps(
            self.model_dump(mode="json"),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")

        return hashlib.sha256(
            canonical
        ).hexdigest()
