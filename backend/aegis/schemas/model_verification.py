from typing import Literal

from pydantic import BaseModel, Field

from aegis.schemas.analysis import SecurityFinding


ModelRole = Literal["primary", "verifier"]
ModelCallStatus = Literal[
    "completed",
    "failed",
    "skipped",
]
VerificationVerdict = Literal[
    "supported",
    "refuted",
    "uncertain",
]


class ModelReviewResult(BaseModel):
    role: ModelRole
    model: str
    status: ModelCallStatus
    findings: list[SecurityFinding] = Field(
        default_factory=list,
    )
    error: str | None = None


class FindingVerification(BaseModel):
    finding_index: int = Field(ge=0)
    verdict: VerificationVerdict
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str = Field(min_length=1)
    evidence: list[str] = Field(
        default_factory=list,
    )


class VerifierReviewResult(BaseModel):
    role: Literal["verifier"] = "verifier"
    model: str
    status: ModelCallStatus
    verifications: list[FindingVerification] = Field(
        default_factory=list,
    )
    additional_findings: list[SecurityFinding] = Field(
        default_factory=list,
    )
    error: str | None = None
