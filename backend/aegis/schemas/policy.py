from typing import Literal

from pydantic import BaseModel, Field, model_validator

from aegis.schemas.memory import (
    ClaimReconciliationResponse,
    SecurityMemoryRecordRequest,
    SecurityMemoryRecordResponse,
)


PolicyDecision = Literal[
    "allow",
    "review",
    "block",
]

PolicyRiskLevel = Literal[
    "none",
    "low",
    "medium",
    "high",
    "critical",
]

PolicyProfile = Literal[
    "permissive",
    "balanced",
    "strict",
]


class MemoryPolicyEvaluationRequest(BaseModel):
    reconciliation: ClaimReconciliationResponse
    profile: PolicyProfile = "balanced"


class PolicyClaimAssessment(BaseModel):
    claim_id: str = Field(
        min_length=1,
        max_length=300,
    )

    lifecycle_status: Literal[
        "new",
        "persistent",
        "changed",
        "resolved",
        "reopened",
    ]

    severity: Literal[
        "critical",
        "high",
        "medium",
        "low",
        "info",
    ]

    confidence: float = Field(
        ge=0.0,
        le=1.0,
    )

    risk_score: int = Field(
        ge=0,
        le=100,
    )

    risk_level: PolicyRiskLevel
    decision: PolicyDecision

    reasons: list[str] = Field(
        default_factory=list,
    )


class MemoryPolicySummary(BaseModel):
    claims_evaluated: int = Field(ge=0)
    claims_ignored: int = Field(ge=0)

    allowed: int = Field(ge=0)
    review_required: int = Field(ge=0)
    blocked: int = Field(ge=0)

    highest_risk_score: int = Field(
        ge=0,
        le=100,
    )
    highest_risk_level: PolicyRiskLevel

    new: int = Field(ge=0)
    persistent: int = Field(ge=0)
    changed: int = Field(ge=0)
    reopened: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_counts(
        self,
    ) -> "MemoryPolicySummary":
        if (
            self.allowed
            + self.review_required
            + self.blocked
            != self.claims_evaluated
        ):
            raise ValueError(
                "Policy decision counts must equal "
                "claims_evaluated"
            )

        return self


class MemoryPolicyDecisionResponse(BaseModel):
    engine: str
    policy_version: str
    profile: PolicyProfile

    decision: PolicyDecision
    risk_score: int = Field(
        ge=0,
        le=100,
    )
    risk_level: PolicyRiskLevel

    blocking_claim_ids: list[str] = Field(
        default_factory=list,
    )
    review_claim_ids: list[str] = Field(
        default_factory=list,
    )

    assessments: list[
        PolicyClaimAssessment
    ] = Field(
        default_factory=list,
    )

    summary: MemoryPolicySummary
    reasons: list[str] = Field(
        default_factory=list,
    )


class SecurityMemoryPolicyRecordRequest(
    SecurityMemoryRecordRequest
):
    profile: PolicyProfile = "balanced"


class SecurityMemoryPolicyRecordResponse(BaseModel):
    memory: SecurityMemoryRecordResponse
    policy: MemoryPolicyDecisionResponse


class SecurityPolicyTaskRequest(BaseModel):
    profile: PolicyProfile = "balanced"
    reconciliation: (
        ClaimReconciliationResponse
        | None
    ) = None
    source_artifacts: list[str] = Field(
        default_factory=list,
        max_length=50,
    )

    @model_validator(mode="after")
    def validate_sources(
        self,
    ) -> "SecurityPolicyTaskRequest":
        if len(
            self.source_artifacts
        ) != len(
            set(self.source_artifacts)
        ):
            raise ValueError(
                "source_artifacts must be unique"
            )

        if any(
            not name.strip()
            for name in self.source_artifacts
        ):
            raise ValueError(
                "source_artifacts must not contain "
                "blank names"
            )

        return self


class SecurityPolicyTaskArtifact(BaseModel):
    handler: str
    source_artifacts: list[str] = Field(
        min_length=1,
    )
    snapshot_id: str | None = Field(
        default=None,
        max_length=300,
    )
    decision: MemoryPolicyDecisionResponse
    outputs_redacted: bool
