from pydantic import BaseModel, Field, model_validator

from aegis.schemas.changes import (
    ChangeFileStatus,
    ChangeSet,
    ChangeSetCollectionRequest,
)
from aegis.schemas.policy import (
    PolicyDecision,
    PolicyProfile,
    PolicyRiskLevel,
)


class ChangePolicyEvaluationRequest(BaseModel):
    change_set: ChangeSet
    profile: PolicyProfile = "balanced"


class ChangeFilePolicyAssessment(BaseModel):
    path: str = Field(
        min_length=1,
        max_length=2_000,
    )
    old_path: str | None = Field(
        default=None,
        max_length=2_000,
    )
    status: ChangeFileStatus

    risk_score: int = Field(
        ge=0,
        le=100,
    )
    risk_level: PolicyRiskLevel
    decision: PolicyDecision

    rule_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=200,
    )
    start_line: int | None = Field(
        default=None,
        ge=1,
    )
    start_column: int | None = Field(
        default=None,
        ge=1,
    )

    reasons: list[str] = Field(
        default_factory=list,
    )


class ChangePolicySummary(BaseModel):
    files_evaluated: int = Field(ge=0)

    allowed: int = Field(ge=0)
    review_required: int = Field(ge=0)
    blocked: int = Field(ge=0)

    highest_risk_score: int = Field(
        ge=0,
        le=100,
    )
    highest_risk_level: PolicyRiskLevel

    sensitive_files: int = Field(ge=0)
    dangerous_patterns: int = Field(ge=0)
    truncated_files: int = Field(ge=0)
    binary_files: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_counts(
        self,
    ) -> "ChangePolicySummary":
        if (
            self.allowed
            + self.review_required
            + self.blocked
            != self.files_evaluated
        ):
            raise ValueError(
                "Change-policy decision counts must "
                "equal files_evaluated"
            )

        return self


class ChangePolicyDecisionResponse(BaseModel):
    engine: str
    policy_version: str
    profile: PolicyProfile

    decision: PolicyDecision
    risk_score: int = Field(
        ge=0,
        le=100,
    )
    risk_level: PolicyRiskLevel

    blocking_paths: list[str] = Field(
        default_factory=list,
    )
    review_paths: list[str] = Field(
        default_factory=list,
    )

    assessments: list[
        ChangeFilePolicyAssessment
    ] = Field(
        default_factory=list,
    )

    summary: ChangePolicySummary

    reasons: list[str] = Field(
        default_factory=list,
    )


class ChangePolicyCollectionRequest(
    ChangeSetCollectionRequest
):
    profile: PolicyProfile = "balanced"


class ChangePolicyCollectionResponse(BaseModel):
    change_set: ChangeSet
    policy: ChangePolicyDecisionResponse
