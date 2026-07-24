from datetime import date

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

    repository_policy: object | None = Field(
        default=None,
        exclude=True,
    )


class ChangePolicyFinding(BaseModel):
    rule_id: str = Field(
        min_length=1,
        max_length=200,
    )
    reason: str = Field(
        min_length=1,
        max_length=2_000,
    )
    score: int = Field(
        ge=0,
        le=100,
    )
    blocking: bool = False

    decision_override: str | None = Field(
        default=None,
        pattern=r"^(review|block)$",
    )

    waived: bool = False
    waiver_reason: str | None = Field(
        default=None,
        max_length=2_000,
    )
    waiver_expires: date | None = None
    waiver_expired: bool = False

    start_line: int | None = Field(
        default=None,
        ge=1,
    )
    start_column: int | None = Field(
        default=None,
        ge=1,
    )


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

    findings: list[ChangePolicyFinding] = Field(
        default_factory=list,
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
    profile: PolicyProfile | None = None


class RepositoryPolicyApplication(BaseModel):
    source: str | None = None
    loaded: bool = False
    profile: PolicyProfile = "balanced"
    fail_on_review: bool = False

    rule_overrides: int = Field(
        default=0,
        ge=0,
    )
    active_waivers: int = Field(
        default=0,
        ge=0,
    )
    expired_waivers: int = Field(
        default=0,
        ge=0,
    )


class ChangePolicyCollectionResponse(BaseModel):
    change_set: ChangeSet
    policy: ChangePolicyDecisionResponse
    repository_policy: RepositoryPolicyApplication = Field(
        default_factory=RepositoryPolicyApplication,
    )
