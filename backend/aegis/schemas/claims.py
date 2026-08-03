from typing import Literal

from pydantic import BaseModel, Field, model_validator


ClaimState = Literal[
    "suspected",
    "supported",
    "confirmed",
    "mitigated",
    "verified_fixed",
    "false_positive",
    "accepted_risk",
    "inconclusive",
]

EvidenceKind = Literal[
    "scanner",
    "semantic_analysis",
    "data_flow",
    "runtime_execution",
    "dynamic_probe",
    "test_result",
    "patch_diff",
    "user_decision",
    "model_review",
    "model_verification",
    "model_consensus",
]

EvidenceRelationshipKind = Literal[
    "supports",
    "contradicts",
    "corroborates",
    "derived_from",
    "verifies",
    "mitigates",
]


class CodeLocation(BaseModel):
    file: str = Field(min_length=1, max_length=1_000)
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    symbol: str | None = Field(default=None, max_length=500)

    @model_validator(mode="after")
    def validate_line_range(self) -> "CodeLocation":
        if self.line_end < self.line_start:
            raise ValueError(
                "line_end must be greater than or equal to line_start"
            )

        return self


class EvidenceSource(BaseModel):
    kind: EvidenceKind
    name: str = Field(min_length=1, max_length=300)
    rule_id: str | None = Field(default=None, max_length=500)
    version: str | None = Field(default=None, max_length=100)


class EvidenceItem(BaseModel):
    evidence_id: str = Field(min_length=1, max_length=300)
    source: EvidenceSource
    summary: str = Field(min_length=1, max_length=5_000)
    confidence: float = Field(ge=0.0, le=1.0)

    locations: list[CodeLocation] = Field(default_factory=list)
    details: list[str] = Field(default_factory=list)

    observed_at: str | None = Field(default=None, max_length=100)


class EvidenceRelationship(BaseModel):
    relationship_id: str = Field(min_length=1, max_length=300)
    source_evidence_id: str = Field(min_length=1, max_length=300)
    target_evidence_id: str = Field(min_length=1, max_length=300)
    kind: EvidenceRelationshipKind
    reason: str | None = Field(default=None, max_length=2_000)


class SecurityClaim(BaseModel):
    schema_version: str = "1.0"

    claim_id: str = Field(min_length=1, max_length=300)
    statement: str = Field(min_length=1, max_length=5_000)

    category: str = Field(min_length=1, max_length=300)
    severity: Literal[
        "info",
        "low",
        "medium",
        "high",
        "critical",
    ]
    confidence: float = Field(ge=0.0, le=1.0)
    state: ClaimState

    cwe: list[str] = Field(default_factory=list)
    owasp: list[str] = Field(default_factory=list)

    locations: list[CodeLocation] = Field(default_factory=list)
    evidence: list[EvidenceItem] = Field(default_factory=list)
    relationships: list[EvidenceRelationship] = Field(default_factory=list)

    remediation: str | None = Field(default=None, max_length=10_000)
    proposed_patch: str | None = None

    @model_validator(mode="after")
    def validate_evidence_graph(self) -> "SecurityClaim":
        relationship_ids: set[str] = set()
        relationship_keys: set[tuple[str, str, str]] = set()
        epistemic_kinds = {
            "supports",
            "corroborates",
            "contradicts",
            "verifies",
        }
        epistemic_relationships: dict[tuple[str, str], str] = {}

        for relationship in self.relationships:
            if relationship.relationship_id in relationship_ids:
                raise ValueError(
                    "Evidence graph contains a duplicate "
                    "relationship_id."
                )
            relationship_ids.add(
                relationship.relationship_id
            )

            if (
                relationship.source_evidence_id
                == relationship.target_evidence_id
            ):
                raise ValueError(
                    "Evidence relationships must reference "
                    "distinct evidence."
                )

            relationship_key = (
                relationship.source_evidence_id,
                relationship.target_evidence_id,
                relationship.kind,
            )
            if relationship_key in relationship_keys:
                raise ValueError(
                    "Evidence graph contains a duplicate "
                    "evidence relationship."
                )
            relationship_keys.add(
                relationship_key
            )

            if relationship.kind in epistemic_kinds:
                epistemic_key = (
                    relationship.source_evidence_id,
                    relationship.target_evidence_id,
                )
                previous_kind = (
                    epistemic_relationships.get(
                        epistemic_key
                    )
                )
                if (
                    previous_kind is not None
                    and previous_kind != relationship.kind
                ):
                    raise ValueError(
                        "Evidence graph contains conflicting "
                        "epistemic relationships."
                    )
                epistemic_relationships[
                    epistemic_key
                ] = relationship.kind

        evidence_ids = [
            item.evidence_id
            for item in self.evidence
        ]

        if len(evidence_ids) != len(set(evidence_ids)):
            raise ValueError(
                "evidence_id values must be unique within a claim"
            )

        known_evidence_ids = set(evidence_ids)

        for relationship in self.relationships:
            if (
                relationship.source_evidence_id
                not in known_evidence_ids
            ):
                raise ValueError(
                    "relationship source_evidence_id "
                    "must reference evidence in the claim"
                )

            if (
                relationship.target_evidence_id
                not in known_evidence_ids
            ):
                raise ValueError(
                    "relationship target_evidence_id "
                    "must reference evidence in the claim"
                )

        provenance_graph: dict[str, set[str]] = {}
        for relationship in self.relationships:
            if relationship.kind != "derived_from":
                continue
            provenance_graph.setdefault(
                relationship.source_evidence_id,
                set(),
            ).add(
                relationship.target_evidence_id
            )

        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(evidence_id: str) -> None:
            if evidence_id in visited:
                return
            if evidence_id in visiting:
                raise ValueError(
                    "Evidence graph contains a "
                    "provenance cycle."
                )

            visiting.add(evidence_id)
            for parent_id in sorted(
                provenance_graph.get(
                    evidence_id,
                    set(),
                )
            ):
                visit(parent_id)
            visiting.remove(evidence_id)
            visited.add(evidence_id)

        for evidence_id in sorted(provenance_graph):
            visit(evidence_id)

        return self
