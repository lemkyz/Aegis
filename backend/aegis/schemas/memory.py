from typing import Literal

from pydantic import BaseModel, Field, model_validator

from aegis.schemas.claims import SecurityClaim


ClaimDeltaStatus = Literal[
    "new",
    "persistent",
    "changed",
    "resolved",
    "reopened",
]


class ClaimReconciliationRequest(BaseModel):
    previous_claims: list[SecurityClaim] = Field(
        default_factory=list,
    )
    current_claims: list[SecurityClaim] = Field(
        default_factory=list,
    )

    @model_validator(mode="after")
    def validate_unique_claim_ids(
        self,
    ) -> "ClaimReconciliationRequest":
        self._require_unique_claim_ids(
            self.previous_claims,
            collection_name="previous_claims",
        )
        self._require_unique_claim_ids(
            self.current_claims,
            collection_name="current_claims",
        )

        return self

    @staticmethod
    def _require_unique_claim_ids(
        claims: list[SecurityClaim],
        *,
        collection_name: str,
    ) -> None:
        claim_ids = [
            claim.claim_id
            for claim in claims
        ]

        if len(claim_ids) != len(set(claim_ids)):
            raise ValueError(
                f"{collection_name} must contain "
                "unique claim_id values"
            )


class ClaimDelta(BaseModel):
    claim_id: str = Field(
        min_length=1,
        max_length=300,
    )
    status: ClaimDeltaStatus

    previous_state: str | None = Field(
        default=None,
        max_length=100,
    )
    current_state: str | None = Field(
        default=None,
        max_length=100,
    )

    previous_claim: SecurityClaim | None = None
    current_claim: SecurityClaim | None = None

    reasons: list[str] = Field(
        default_factory=list,
    )


class ClaimReconciliationSummary(BaseModel):
    previous_count: int = Field(ge=0)
    current_count: int = Field(ge=0)

    new: int = Field(ge=0)
    persistent: int = Field(ge=0)
    changed: int = Field(ge=0)
    resolved: int = Field(ge=0)
    reopened: int = Field(ge=0)

    @property
    def total_deltas(self) -> int:
        return (
            self.new
            + self.persistent
            + self.changed
            + self.resolved
            + self.reopened
        )


class ClaimReconciliationResponse(BaseModel):
    reconciler: str
    deltas: list[ClaimDelta] = Field(
        default_factory=list,
    )
    summary: ClaimReconciliationSummary


class ProjectSecuritySnapshot(BaseModel):
    schema_version: str = "1.0"

    snapshot_id: str = Field(
        min_length=1,
        max_length=300,
    )
    project_id: str = Field(
        min_length=1,
        max_length=500,
    )
    revision: str | None = Field(
        default=None,
        max_length=500,
    )
    created_at: str = Field(
        min_length=1,
        max_length=100,
    )

    claims: list[SecurityClaim] = Field(
        default_factory=list,
    )
    claim_count: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_snapshot(
        self,
    ) -> "ProjectSecuritySnapshot":
        claim_ids = [
            claim.claim_id
            for claim in self.claims
        ]

        if len(claim_ids) != len(set(claim_ids)):
            raise ValueError(
                "snapshot claims must contain unique "
                "claim_id values"
            )

        if self.claim_count != len(self.claims):
            raise ValueError(
                "claim_count must equal the number "
                "of snapshot claims"
            )

        return self


RepositoryIdentitySource = Literal[
    "git_remote",
    "local_path",
]


class RepositoryContext(BaseModel):
    schema_version: str = "1.0"

    project_id: str = Field(
        min_length=1,
        max_length=300,
    )
    repository_root: str = Field(
        min_length=1,
        max_length=2_000,
    )

    identity_source: RepositoryIdentitySource

    remote: str | None = Field(
        default=None,
        max_length=2_000,
    )
    branch: str | None = Field(
        default=None,
        max_length=500,
    )
    head_commit: str | None = Field(
        default=None,
        max_length=200,
    )

    revision: str = Field(
        min_length=1,
        max_length=300,
    )
    dirty: bool


class SecurityMemoryRecordRequest(BaseModel):
    repository_path: str = Field(
        min_length=1,
        max_length=2_000,
    )
    claims: list[SecurityClaim] = Field(
        default_factory=list,
    )

    @model_validator(mode="after")
    def validate_unique_claim_ids(
        self,
    ) -> "SecurityMemoryRecordRequest":
        claim_ids = [
            claim.claim_id
            for claim in self.claims
        ]

        if len(claim_ids) != len(set(claim_ids)):
            raise ValueError(
                "claims must contain unique claim_id values"
            )

        return self


class SecurityMemoryRecordResponse(BaseModel):
    service: str

    repository: RepositoryContext
    snapshot: ProjectSecuritySnapshot

    previous_snapshot_id: str | None = Field(
        default=None,
        max_length=300,
    )

    reconciliation: ClaimReconciliationResponse

    baseline_created: bool
    persisted_new_snapshot: bool

    project_snapshot_count: int = Field(
        ge=1,
    )


class SecurityMemoryHistoryResponse(BaseModel):
    repository: RepositoryContext
    snapshots: list[ProjectSecuritySnapshot] = Field(
        default_factory=list,
    )
    count: int = Field(ge=0)
    limit: int = Field(ge=1, le=1_000)
    offset: int = Field(ge=0)


class SecurityMemoryLatestResponse(BaseModel):
    repository: RepositoryContext
    snapshot: ProjectSecuritySnapshot


class SecurityMemorySnapshotResponse(BaseModel):
    snapshot: ProjectSecuritySnapshot


SecurityMemoryCoverage = Literal[
    "full_repository",
    "targeted_analysis",
    "fix_verification",
]


class SecurityMemoryTaskInput(BaseModel):
    analysis_status: Literal[
        "complete",
        "partial",
        "failed",
    ]
    coverage: SecurityMemoryCoverage
    claims: list[SecurityClaim] = Field(
        default_factory=list,
        max_length=10_000,
    )
    source_artifacts: list[str] = Field(
        min_length=1,
        max_length=50,
    )
    allow_empty_snapshot: bool = False

    @model_validator(mode="after")
    def validate_task_input(
        self,
    ) -> "SecurityMemoryTaskInput":
        claim_ids = [
            claim.claim_id
            for claim in self.claims
        ]

        if len(claim_ids) != len(
            set(claim_ids)
        ):
            raise ValueError(
                "security-memory claims must have "
                "unique claim IDs"
            )

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


class SecurityMemoryTaskArtifact(BaseModel):
    handler: str
    source_artifacts: list[str] = Field(
        min_length=1,
    )
    analysis_status: Literal["complete"]
    coverage: SecurityMemoryCoverage
    memory: SecurityMemoryRecordResponse
    claims_recorded: int = Field(ge=0)
    fix_verification_applied: bool
    outputs_redacted: bool
