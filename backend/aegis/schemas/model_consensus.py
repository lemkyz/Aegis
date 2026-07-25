from typing import Literal

from pydantic import BaseModel, Field


ConsensusVerdict = Literal[
    "confirmed",
    "disputed",
    "uncertain",
    "unverified",
]


class FindingConsensusDecision(BaseModel):
    finding_index: int = Field(ge=0)
    verdict: ConsensusVerdict
    confidence: float = Field(ge=0.0, le=1.0)
    primary_confidence: float = Field(
        ge=0.0,
        le=1.0,
    )
    verifier_confidence: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
    )
    reasons: list[str] = Field(
        default_factory=list,
    )


class ModelConsensusResult(BaseModel):
    primary_model: str
    verifier_model: str | None = None
    status: Literal[
        "completed",
        "partial",
        "failed",
    ]
    decisions: list[FindingConsensusDecision] = Field(
        default_factory=list,
    )
    errors: list[str] = Field(
        default_factory=list,
    )
