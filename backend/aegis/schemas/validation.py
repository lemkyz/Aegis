from typing import Literal

from pydantic import BaseModel, Field


ValidationTargetType = Literal[
    "local_repository",
    "local_service",
    "container_image",
]

ValidationTestType = Literal[
    "command_injection",
    "sql_injection",
    "path_traversal",
    "ssrf",
    "authentication_bypass",
    "unsafe_data_flow",
]

ValidationNetworkPolicy = Literal[
    "disabled",
    "loopback",
]


class ValidationAuthorizationRequest(BaseModel):
    authorization_confirmed: bool

    target_type: ValidationTargetType
    target: str = Field(
        min_length=1,
        max_length=1_000,
    )

    allowed_test_types: list[
        ValidationTestType
    ] = Field(
        min_length=1,
        max_length=20,
    )

    dry_run: bool = True

    timeout_seconds: int = Field(
        default=10,
        ge=1,
        le=60,
    )
    memory_limit_mb: int = Field(
        default=256,
        ge=64,
        le=2_048,
    )
    cpu_limit: float = Field(
        default=0.5,
        ge=0.1,
        le=2.0,
    )

    network_policy: ValidationNetworkPolicy = (
        "disabled"
    )


class ValidationScope(BaseModel):
    target_type: ValidationTargetType
    target: str
    allowed_test_types: list[
        ValidationTestType
    ]


class ValidationLimits(BaseModel):
    timeout_seconds: int
    memory_limit_mb: int
    cpu_limit: float
    network_policy: ValidationNetworkPolicy


class ValidationAuthorizationResponse(BaseModel):
    contract: str

    authorized: bool
    execution_allowed: bool
    dry_run: bool

    normalized_scope: ValidationScope
    limits: ValidationLimits

    reasons: list[str] = Field(
        default_factory=list,
    )
    denials: list[str] = Field(
        default_factory=list,
    )


ValidationRuntime = Literal[
    "python",
    "node",
]


class ValidationPlanRequest(BaseModel):
    authorization: ValidationAuthorizationRequest

    runtime: ValidationRuntime
    entrypoint: str = Field(
        min_length=1,
        max_length=500,
    )
    test_type: ValidationTestType


class ValidationSandboxPolicy(BaseModel):
    read_only_root: bool
    host_path_relabeling: bool
    image_pull_policy: Literal[
        "never",
    ]
    network: Literal[
        "none",
        "loopback",
    ]
    drop_capabilities: list[str]
    no_new_privileges: bool
    user: str
    memory_limit_mb: int
    cpu_limit: float
    timeout_seconds: int
    pids_limit: int
    writable_tmpfs: list[str]


class ValidationMount(BaseModel):
    source: str
    target: str
    read_only: bool


class ValidationExecutionPlanResponse(BaseModel):
    planner: str
    authorization: ValidationAuthorizationResponse

    authorized: bool
    execution_allowed: bool
    ready: bool

    runtime: ValidationRuntime
    image: str | None = None
    command: list[str] = Field(
        default_factory=list,
    )

    sandbox: ValidationSandboxPolicy
    mounts: list[ValidationMount] = Field(
        default_factory=list,
    )

    reasons: list[str] = Field(
        default_factory=list,
    )
    denials: list[str] = Field(
        default_factory=list,
    )


ValidationRunStatus = Literal[
    "completed",
    "failed",
    "timed_out",
    "runtime_unavailable",
    "rejected",
]


class ValidationExecutionRequest(BaseModel):
    plan: ValidationPlanRequest


class ValidationExecutionResult(BaseModel):
    runner: str
    status: ValidationRunStatus

    runtime_executable: str | None = None
    started: bool
    timed_out: bool

    exit_code: int | None = None
    duration_ms: int = Field(
        ge=0,
    )

    stdout: str = ""
    stderr: str = ""

    argv: list[str] = Field(
        default_factory=list,
    )

    reasons: list[str] = Field(
        default_factory=list,
    )
    denials: list[str] = Field(
        default_factory=list,
    )


DynamicValidationVerdict = Literal[
    "confirmed",
    "not_reproduced",
    "blocked",
    "execution_error",
    "timed_out",
]


class ValidationSuccessCriteria(BaseModel):
    expected_exit_code: int = Field(
        default=0,
        ge=0,
        le=255,
    )
    stdout_contains: str | None = Field(
        default=None,
        min_length=1,
        max_length=1_000,
    )
    stderr_contains: str | None = Field(
        default=None,
        min_length=1,
        max_length=1_000,
    )


class DynamicValidationEvidenceRequest(BaseModel):
    threat_id: str = Field(
        min_length=1,
        max_length=300,
    )
    claim_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=300,
    )
    category: ValidationTestType

    execution: ValidationExecutionResult
    success_criteria: ValidationSuccessCriteria


class DynamicValidationEvidenceResponse(BaseModel):
    evaluator: str

    threat_id: str
    claim_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=300,
    )
    category: ValidationTestType
    verdict: DynamicValidationVerdict

    dynamically_confirmed: bool
    confidence: float = Field(
        ge=0.0,
        le=1.0,
    )

    evidence: list[str] = Field(
        default_factory=list,
    )
    reasons: list[str] = Field(
        default_factory=list,
    )

    execution_status: ValidationRunStatus
    exit_code: int | None = None
    duration_ms: int = Field(
        ge=0,
    )


DynamicReplayVerdict = Literal[
    "fixed",
    "still_exploitable",
    "inconclusive",
]


class ValidationReplayCompareRequest(BaseModel):
    before: DynamicValidationEvidenceResponse
    after: DynamicValidationEvidenceResponse


class ValidationReplayCompareResponse(BaseModel):
    comparator: str

    threat_id: str
    claim_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=300,
    )
    category: ValidationTestType
    verdict: DynamicReplayVerdict

    fixed: bool
    confidence: float = Field(
        ge=0.0,
        le=1.0,
    )

    before_verdict: DynamicValidationVerdict
    after_verdict: DynamicValidationVerdict

    reasons: list[str] = Field(
        default_factory=list,
    )
    denials: list[str] = Field(
        default_factory=list,
    )


class ValidationReplayRequest(BaseModel):
    threat_id: str = Field(
        min_length=1,
        max_length=300,
    )
    claim_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=300,
    )
    category: ValidationTestType

    plan: ValidationPlanRequest
    success_criteria: ValidationSuccessCriteria

    before_execution: ValidationExecutionResult


class ValidationReplayResponse(BaseModel):
    orchestrator: str

    threat_id: str
    claim_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=300,
    )
    category: ValidationTestType

    before_execution: ValidationExecutionResult
    before_evidence: DynamicValidationEvidenceResponse

    after_execution: ValidationExecutionResult
    after_evidence: DynamicValidationEvidenceResponse

    comparison: ValidationReplayCompareResponse


class DynamicValidationTaskArtifact(BaseModel):
    handler: str
    source_artifacts: list[str] = Field(
        min_length=1,
    )
    authorization: ValidationAuthorizationResponse
    execution_plan: ValidationExecutionPlanResponse
    replay: ValidationReplayResponse
    fix_verification: (
        "UnifiedFixVerificationResponse"
    )
    transaction_state: Literal[
        "pending",
        "committed",
        "rolled_back",
        "rollback_blocked",
    ]
    outputs_redacted: bool


FixProjectCheckStatus = Literal[
    "passed",
    "failed",
    "skipped",
]

FixVerificationVerdict = Literal[
    "verified",
    "project_failed",
    "target_not_resolved",
    "regression_detected",
    "still_exploitable",
    "inconclusive",
]


class FixProjectCheck(BaseModel):
    name: str = Field(
        min_length=1,
        max_length=200,
    )
    status: FixProjectCheckStatus
    details: str = Field(
        default="",
        max_length=5_000,
    )


class UnifiedFixVerificationRequest(BaseModel):
    replay: ValidationReplayCompareResponse

    project_checks: list[
        FixProjectCheck
    ] = Field(
        min_length=1,
        max_length=20,
    )

    static_target_resolved: bool
    static_regression_free: bool


class UnifiedFixVerificationResponse(BaseModel):
    evaluator: str

    threat_id: str
    claim_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=300,
    )
    category: ValidationTestType

    verdict: FixVerificationVerdict
    verified: bool
    confidence: float = Field(
        ge=0.0,
        le=1.0,
    )

    project_checks_passed: bool
    static_target_resolved: bool
    static_regression_free: bool
    dynamic_replay_fixed: bool

    reasons: list[str] = Field(
        default_factory=list,
    )
    failed_checks: list[str] = Field(
        default_factory=list,
    )


DynamicValidationTaskArtifact.model_rebuild()
