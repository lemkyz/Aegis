from __future__ import annotations

import hashlib
import json
from pathlib import PurePosixPath
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    model_validator,
)

from aegis.schemas.change_policy import (
    ChangePolicyDecisionResponse,
)
from aegis.schemas.validation import (
    FixProjectCheck,
    ResidualRiskAssessment,
)


Sha256Digest = str
SafeEvidenceIdentifier = Annotated[
    str,
    Field(
        min_length=1,
        max_length=300,
        pattern=(
            r"^[A-Za-z0-9]"
            r"[A-Za-z0-9._:/@+-]*$"
        ),
    ),
]


class SecureFixProposal(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
    )

    claim_id: SafeEvidenceIdentifier
    target_path: str = Field(
        min_length=1,
        max_length=2_000,
    )
    expected_file_sha256: Sha256Digest = Field(
        pattern=r"^[a-f0-9]{64}$",
    )
    expected_selection_sha256: Sha256Digest = Field(
        pattern=r"^[a-f0-9]{64}$",
    )
    start_offset: int = Field(ge=0)
    end_offset: int = Field(ge=1)
    replacement: str = Field(
        min_length=1,
        max_length=250_000,
    )

    @model_validator(mode="after")
    def validate_proposal(
        self,
    ) -> "SecureFixProposal":
        if self.end_offset <= self.start_offset:
            raise ValueError(
                "end_offset must be greater than "
                "start_offset"
            )

        if (
            "\x00" in self.target_path
            or "\\" in self.target_path
            or any(
                ord(character) < 32
                for character
                in self.target_path
            )
        ):
            raise ValueError(
                "target_path must use a safe POSIX "
                "repository-relative path"
            )

        path = PurePosixPath(self.target_path)

        if (
            path.is_absolute()
            or not path.parts
            or any(
                part in {"", ".", ".."}
                for part in path.parts
            )
        ):
            raise ValueError(
                "target_path must remain inside the "
                "repository"
            )

        if "\x00" in self.replacement:
            raise ValueError(
                "replacement must remain textual"
            )

        return self

    def patch_sha256(self) -> str:
        canonical = json.dumps(
            self.model_dump(mode="json"),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")

        return hashlib.sha256(
            canonical
        ).hexdigest()


class SecureFixApproval(BaseModel):
    confirmed: bool
    approval_id: SafeEvidenceIdentifier
    approved_patch_sha256: Sha256Digest = Field(
        pattern=r"^[a-f0-9]{64}$",
    )


class SecureFixRequest(BaseModel):
    proposal: SecureFixProposal
    approval: SecureFixApproval


FixVerificationCheckKind = Literal[
    "project",
    "static_security",
    "dynamic_replay",
]


class FixVerificationCheck(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
    )

    check_id: SafeEvidenceIdentifier
    kind: FixVerificationCheckKind
    name: str = Field(
        min_length=1,
        max_length=200,
    )


class FixVerificationPlan(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
    )

    plan_id: SafeEvidenceIdentifier
    claim_id: SafeEvidenceIdentifier
    patch_sha256: Sha256Digest = Field(
        pattern=r"^[a-f0-9]{64}$",
    )
    checks: list[
        FixVerificationCheck
    ] = Field(
        min_length=1,
        max_length=20,
    )
    requires_dynamic_replay: bool = False

    @model_validator(mode="after")
    def validate_plan(
        self,
    ) -> "FixVerificationPlan":
        check_ids = [
            check.check_id
            for check in self.checks
        ]

        if len(check_ids) != len(set(check_ids)):
            raise ValueError(
                "verification check IDs must be unique"
            )

        has_dynamic_replay = any(
            check.kind == "dynamic_replay"
            for check in self.checks
        )

        if (
            self.requires_dynamic_replay
            and not has_dynamic_replay
        ):
            raise ValueError(
                "requires_dynamic_replay requires a "
                "dynamic_replay check"
            )

        if (
            has_dynamic_replay
            and not self.requires_dynamic_replay
        ):
            raise ValueError(
                "requires_dynamic_replay must be true "
                "when a dynamic_replay check is present"
            )

        return self

    def plan_sha256(self) -> str:
        canonical = json.dumps(
            self.model_dump(mode="json"),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")

        return hashlib.sha256(
            canonical
        ).hexdigest()


class FixPlan(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
    )

    plan_id: SafeEvidenceIdentifier
    proposal: SecureFixProposal
    verification_plan: FixVerificationPlan

    @model_validator(mode="after")
    def validate_plan(
        self,
    ) -> "FixPlan":
        if (
            self.proposal.claim_id
            != self.verification_plan.claim_id
        ):
            raise ValueError(
                "fix plan claim identity must match "
                "across proposal and verification plan"
            )

        if (
            self.proposal.patch_sha256()
            != self.verification_plan.patch_sha256
        ):
            raise ValueError(
                "fix plan patch digest must match "
                "the exact proposed patch"
            )

        return self

    def plan_sha256(self) -> str:
        canonical = json.dumps(
            self.model_dump(mode="json"),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")

        return hashlib.sha256(
            canonical
        ).hexdigest()


FixTransactionState = Literal[
    "pending",
    "committed",
    "rolled_back",
    "rollback_blocked",
]


class AppliedPatchArtifact(BaseModel):
    handler: str
    transaction_id: str = Field(
        min_length=1,
        max_length=300,
    )
    claim_id: SafeEvidenceIdentifier
    target_path: str = Field(
        min_length=1,
        max_length=2_000,
    )
    approval_id: SafeEvidenceIdentifier
    patch_sha256: Sha256Digest = Field(
        pattern=r"^[a-f0-9]{64}$",
    )
    before_sha256: Sha256Digest = Field(
        pattern=r"^[a-f0-9]{64}$",
    )
    after_sha256: Sha256Digest = Field(
        pattern=r"^[a-f0-9]{64}$",
    )
    changed_characters: int = Field(ge=1)
    policy: ChangePolicyDecisionResponse
    transaction_state: FixTransactionState
    outputs_redacted: bool


class RemediationLifecycleManifest(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
    )

    schema_version: Literal["1.0"] = "1.0"
    manifest_id: SafeEvidenceIdentifier
    fix_plan: FixPlan
    fix_plan_sha256: Sha256Digest = Field(
        pattern=r"^[a-f0-9]{64}$",
    )
    applied_patch: AppliedPatchArtifact

    @model_validator(mode="after")
    def validate_manifest(
        self,
    ) -> "RemediationLifecycleManifest":
        proposal = self.fix_plan.proposal

        if (
            self.fix_plan_sha256
            != self.fix_plan.plan_sha256()
        ):
            raise ValueError(
                "remediation manifest fix plan digest "
                "must match the exact fix plan"
            )

        if proposal.claim_id != (
            self.applied_patch.claim_id
        ):
            raise ValueError(
                "remediation manifest claim identity "
                "must match the applied patch"
            )

        if proposal.patch_sha256() != (
            self.applied_patch.patch_sha256
        ):
            raise ValueError(
                "remediation manifest patch digest "
                "must match the applied patch"
            )

        if proposal.target_path != (
            self.applied_patch.target_path
        ):
            raise ValueError(
                "remediation manifest target path "
                "must match the applied patch"
            )

        if proposal.expected_file_sha256 != (
            self.applied_patch.before_sha256
        ):
            raise ValueError(
                "remediation manifest before digest "
                "must match the authorized source"
            )

        if (
            self.applied_patch.transaction_state
            != "pending"
        ):
            raise ValueError(
                "remediation manifest transaction state "
                "must be pending"
            )

        return self

    def manifest_sha256(self) -> str:
        canonical = json.dumps(
            self.model_dump(mode="json"),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")

        return hashlib.sha256(
            canonical
        ).hexdigest()


class StaticFixVerificationRequest(BaseModel):
    claim_id: SafeEvidenceIdentifier
    verifier: SafeEvidenceIdentifier
    project_checks: list[
        FixProjectCheck
    ] = Field(
        min_length=1,
        max_length=20,
    )
    security_delta: (
        "StaticSecurityDeltaEvidence"
    )
    requires_dynamic_replay: bool = False


class StaticSecurityDeltaEvidence(BaseModel):
    scanner: SafeEvidenceIdentifier
    before_scan_sha256: Sha256Digest = Field(
        pattern=r"^[a-f0-9]{64}$",
    )
    after_scan_sha256: Sha256Digest = Field(
        pattern=r"^[a-f0-9]{64}$",
    )
    target_finding_ids: list[
        SafeEvidenceIdentifier
    ] = Field(
        min_length=1,
        max_length=1_000,
    )
    remaining_target_finding_ids: list[
        SafeEvidenceIdentifier
    ] = Field(
        default_factory=list,
        max_length=1_000,
    )
    introduced_finding_ids: list[
        SafeEvidenceIdentifier
    ] = Field(
        default_factory=list,
        max_length=1_000,
    )

    @model_validator(mode="after")
    def validate_delta(
        self,
    ) -> "StaticSecurityDeltaEvidence":
        target_ids = set(
            self.target_finding_ids
        )
        remaining_ids = set(
            self.remaining_target_finding_ids
        )

        if len(target_ids) != len(
            self.target_finding_ids
        ):
            raise ValueError(
                "target_finding_ids must be unique"
            )

        if not remaining_ids.issubset(
            target_ids
        ):
            raise ValueError(
                "remaining target findings must be "
                "part of the original target set"
            )

        if len(
            self.introduced_finding_ids
        ) != len(
            set(
                self.introduced_finding_ids
            )
        ):
            raise ValueError(
                "introduced_finding_ids must be "
                "unique"
            )

        return self


StaticFixVerificationVerdict = Literal[
    "awaiting_dynamic",
    "partial",
    "failed",
]


class StaticFixVerificationArtifact(BaseModel):
    handler: str
    source_artifacts: list[str] = Field(
        min_length=1,
    )
    applied_patch: AppliedPatchArtifact
    verifier: str
    project_checks: list[FixProjectCheck]
    security_delta: StaticSecurityDeltaEvidence
    static_target_resolved: bool
    static_regression_free: bool
    verdict: StaticFixVerificationVerdict
    ready_for_dynamic: bool
    transaction_state: FixTransactionState
    residual_risk: ResidualRiskAssessment
    reasons: list[str] = Field(
        default_factory=list,
    )
    outputs_redacted: bool

    @model_validator(mode="after")
    def validate_residual_risk_provenance(
        self,
    ) -> "StaticFixVerificationArtifact":
        if (
            self.residual_risk.claim_id
            != self.applied_patch.claim_id
        ):
            raise ValueError(
                "residual risk claim identity must match "
                "the applied patch"
            )

        if (
            self.residual_risk.patch_sha256
            != self.applied_patch.patch_sha256
        ):
            raise ValueError(
                "residual risk patch digest must match "
                "the applied patch"
            )

        return self


StaticFixVerificationRequest.model_rebuild()
