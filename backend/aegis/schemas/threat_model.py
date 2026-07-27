from typing import Literal

from pydantic import BaseModel, Field

from aegis.schemas.attack_surface import (
    AttackSurfaceEdge,
    AttackSurfaceFile,
    AttackSurfaceNode,
)
from aegis.schemas.dependencies import (
    DependencyScanStatus,
)


ThreatCategory = Literal[
    "command_injection",
    "sql_injection",
    "path_traversal",
    "ssrf",
    "secret_exposure",
    "authentication_bypass",
    "unsafe_data_flow",
    "vulnerable_dependency",
]

ThreatSeverity = Literal[
    "info",
    "low",
    "medium",
    "high",
    "critical",
]


Exploitability = Literal[
    "confirmed",
    "likely",
    "possible",
    "unlikely",
    "not_exploitable",
    "unknown",
]


class ThreatModelScanRequest(BaseModel):
    files: list[AttackSurfaceFile] = Field(
        min_length=1,
        max_length=300,
    )


class ThreatAsset(BaseModel):
    id: str
    name: str
    kind: str

    file: str
    line: int

    description: str
    source_node_ids: list[str] = Field(
        default_factory=list,
    )


class TrustBoundary(BaseModel):
    id: str
    label: str

    file: str
    line: int

    boundary_type: str
    evidence: str
    source_node_ids: list[str] = Field(
        default_factory=list,
    )


class ThreatFinding(BaseModel):
    id: str
    title: str
    category: ThreatCategory
    severity: ThreatSeverity

    confidence: float = Field(
        ge=0.0,
        le=1.0,
    )

    file: str
    line: int

    entry_point: str | None = None
    affected_asset: str
    trust_boundary: str | None = None

    description: str
    attack_path: list[str] = Field(
        default_factory=list,
    )
    mitigations: list[str] = Field(
        default_factory=list,
    )
    evidence: list[str] = Field(
        default_factory=list,
    )
    source_node_ids: list[str] = Field(
        default_factory=list,
    )
    data_flow: list[str] = Field(
        default_factory=list,
    )

    exploitability: Exploitability = "unknown"
    exploitability_confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
    )
    exploitability_reasons: list[str] = Field(
        default_factory=list,
    )
    prerequisites: list[str] = Field(
        default_factory=list,
    )
    blocking_controls: list[str] = Field(
        default_factory=list,
    )


class ThreatModelSummary(BaseModel):
    files_scanned: int

    assets_found: int
    trust_boundaries_found: int
    threats_found: int

    critical: int
    high: int
    medium: int
    low: int
    info: int


class ThreatModelEvidenceSummary(BaseModel):
    source_artifacts: list[str] = Field(
        default_factory=list,
    )
    secret_findings: int = Field(ge=0)
    dependency_vulnerabilities: int = Field(
        ge=0,
    )
    dependency_scan_status: DependencyScanStatus
    dependency_coverage_complete: bool
    attack_surface_nodes: int = Field(ge=0)
    attack_surface_edges: int = Field(ge=0)


class ThreatModelScanResponse(BaseModel):
    modeler: str

    attack_surface_nodes: list[AttackSurfaceNode]
    attack_surface_edges: list[AttackSurfaceEdge]

    assets: list[ThreatAsset]
    trust_boundaries: list[TrustBoundary]
    threats: list[ThreatFinding]

    summary: ThreatModelSummary
    evidence_summary: (
        ThreatModelEvidenceSummary | None
    ) = None
