from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator

from aegis.schemas.validation import (
    ValidationAuthorizationRequest,
)


SecurityTaskKind = Literal[
    "repository_context",
    "deterministic_scan",
    "secret_analysis",
    "dependency_scan",
    "attack_surface",
    "primary_model_review",
    "verifier_review",
    "model_consensus",
    "threat_model",
    "dynamic_validation",
    "secure_fix",
    "fix_verification",
    "security_memory",
    "policy_evaluation",
]

SecurityTaskState = Literal[
    "planned",
    "ready",
    "waiting",
    "blocked",
    "skipped",
    "running",
    "completed",
    "failed",
]

SecurityTaskGate = Literal[
    "none",
    "scanner_evidence",
    "ai_available",
    "authorization",
    "human_approval",
    "proposed_patch",
    "runtime_available",
]


class SecurityTaskDependency(BaseModel):
    task_id: str = Field(min_length=1)
    required_states: list[SecurityTaskState] = Field(
        default_factory=lambda: ["completed"],
    )


class SecurityTaskNode(BaseModel):
    task_id: str = Field(min_length=1)
    kind: SecurityTaskKind
    state: SecurityTaskState = "planned"
    required: bool = True
    dependencies: list[SecurityTaskDependency] = Field(
        default_factory=list,
    )
    gates: list[SecurityTaskGate] = Field(
        default_factory=list,
    )
    reasons: list[str] = Field(
        default_factory=list,
    )
    produces: list[str] = Field(
        default_factory=list,
    )


class SecurityTaskPlanRequest(BaseModel):
    operation: Literal[
        "fast_scan",
        "deep_analysis",
        "repository_review",
        "fix_and_verify",
    ]
    language: str = Field(default="python", max_length=50)
    has_scanner_evidence: bool = False
    has_proposed_patch: bool = False
    authorization_confirmed: bool = False
    validation_authorization: (
        ValidationAuthorizationRequest | None
    ) = None
    human_approval_confirmed: bool = False
    include_dynamic_validation: bool = False
    highest_severity: Literal[
        "none",
        "info",
        "low",
        "medium",
        "high",
        "critical",
    ] = "none"
    finding_confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
    )
    has_proven_data_flow: bool = False
    independently_verified: bool = False
    include_security_memory: bool = True
    include_policy_evaluation: bool = True


class SecurityTaskPlanResponse(BaseModel):
    planner: str
    operation: str
    status: Literal[
        "ready",
        "partial",
        "blocked",
        "invalid",
    ]
    tasks: list[SecurityTaskNode] = Field(
        default_factory=list,
    )
    entry_task_ids: list[str] = Field(
        default_factory=list,
    )
    terminal_task_ids: list[str] = Field(
        default_factory=list,
    )
    execution_order: list[str] = Field(
        default_factory=list,
    )
    reasons: list[str] = Field(
        default_factory=list,
    )
    errors: list[str] = Field(
        default_factory=list,
    )

    @model_validator(mode="after")
    def validate_task_graph(
        self,
    ) -> "SecurityTaskPlanResponse":
        task_ids = [
            task.task_id
            for task in self.tasks
        ]

        if len(task_ids) != len(set(task_ids)):
            raise ValueError(
                "Security task IDs must be unique."
            )

        known_ids = set(task_ids)

        for task in self.tasks:
            for dependency in task.dependencies:
                if dependency.task_id not in known_ids:
                    raise ValueError(
                        "Security task dependency references "
                        f"unknown task ID: {dependency.task_id}."
                    )

                if dependency.task_id == task.task_id:
                    raise ValueError(
                        "A security task cannot depend on itself."
                    )

        for task_id in [
            *self.entry_task_ids,
            *self.terminal_task_ids,
        ]:
            if task_id not in known_ids:
                raise ValueError(
                    "Plan boundary references unknown "
                    f"task ID: {task_id}."
                )

        dependency_counts = {
            task.task_id: len(task.dependencies)
            for task in self.tasks
        }

        dependents: dict[str, list[str]] = {
            task_id: []
            for task_id in task_ids
        }

        for task in self.tasks:
            for dependency in task.dependencies:
                dependents[dependency.task_id].append(
                    task.task_id
                )

        queue = [
            task_id
            for task_id in task_ids
            if dependency_counts[task_id] == 0
        ]

        calculated_order: list[str] = []

        while queue:
            task_id = queue.pop(0)
            calculated_order.append(task_id)

            for dependent_id in dependents[task_id]:
                dependency_counts[dependent_id] -= 1

                if dependency_counts[dependent_id] == 0:
                    queue.append(dependent_id)

        if len(calculated_order) != len(task_ids):
            raise ValueError(
                "Security task graph contains a "
                "dependency cycle."
            )

        if self.execution_order:
            if (
                len(self.execution_order)
                != len(set(self.execution_order))
            ):
                raise ValueError(
                    "Execution order cannot contain "
                    "duplicate task IDs."
                )

            if set(self.execution_order) != known_ids:
                raise ValueError(
                    "Execution order must contain every "
                    "security task exactly once."
                )

            positions = {
                task_id: index
                for index, task_id
                in enumerate(self.execution_order)
            }

            for task in self.tasks:
                for dependency in task.dependencies:
                    if (
                        positions[dependency.task_id]
                        >= positions[task.task_id]
                    ):
                        raise ValueError(
                            "Execution order places a task "
                            "before one of its dependencies."
                        )
        else:
            self.execution_order = calculated_order

        return self



SecurityExecutionStatus = Literal[
    "created",
    "running",
    "completed",
    "partial",
    "failed",
    "blocked",
]


SecurityTaskEventType = Literal[
    "execution_created",
    "task_started",
    "task_completed",
    "task_failed",
    "task_skipped",
    "state_resolved",
]


class SecurityTaskResult(BaseModel):
    task_id: str = Field(min_length=1)
    success: bool
    output: dict[str, Any] = Field(
        default_factory=dict,
    )
    error: str | None = Field(
        default=None,
        max_length=10_000,
    )


class SecurityTaskRuntimeRecord(BaseModel):
    task_id: str = Field(min_length=1)
    attempts: int = Field(default=0, ge=0)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    result: SecurityTaskResult | None = None


class SecurityTaskExecutionEvent(BaseModel):
    sequence: int = Field(ge=1)
    event_type: SecurityTaskEventType
    task_id: str | None = None
    previous_state: SecurityTaskState | None = None
    new_state: SecurityTaskState | None = None
    message: str = Field(min_length=1)
    occurred_at: datetime


class SecurityTaskExecution(BaseModel):
    execution_id: str = Field(min_length=1)
    status: SecurityExecutionStatus
    plan: SecurityTaskPlanResponse
    runtime: list[SecurityTaskRuntimeRecord] = Field(
        default_factory=list,
    )
    events: list[SecurityTaskExecutionEvent] = Field(
        default_factory=list,
    )
    created_at: datetime
    updated_at: datetime

    @model_validator(mode="after")
    def validate_runtime_records(
        self,
    ) -> "SecurityTaskExecution":
        task_ids = {
            task.task_id
            for task in self.plan.tasks
        }

        runtime_ids = [
            record.task_id
            for record in self.runtime
        ]

        if len(runtime_ids) != len(set(runtime_ids)):
            raise ValueError(
                "Task runtime records must have "
                "unique task IDs."
            )

        unknown = set(runtime_ids) - task_ids

        if unknown:
            raise ValueError(
                "Task runtime record references "
                "unknown task ID."
            )

        event_sequences = [
            event.sequence
            for event in self.events
        ]

        if event_sequences != list(
            range(1, len(event_sequences) + 1)
        ):
            raise ValueError(
                "Execution event sequences must be "
                "contiguous and begin at one."
            )

        for event in self.events:
            if (
                event.task_id is not None
                and event.task_id not in task_ids
            ):
                raise ValueError(
                    "Execution event references "
                    "unknown task ID."
                )

        return self



SecurityAggregationStatus = Literal[
    "completed",
    "in_progress",
    "partial",
    "failed",
    "blocked",
]


class SecurityTaskOutputSummary(BaseModel):
    task_id: str = Field(min_length=1)
    kind: SecurityTaskKind
    state: SecurityTaskState
    attempts: int = Field(ge=0)
    success: bool | None = None
    output: dict[str, Any] = Field(
        default_factory=dict,
    )
    error: str | None = None
    reasons: list[str] = Field(
        default_factory=list,
    )


class SecurityArtifactRecord(BaseModel):
    name: str = Field(min_length=1)
    producer_task_id: str = Field(min_length=1)
    value: Any


class SecurityTaskAggregation(BaseModel):
    aggregator: str
    execution_id: str
    operation: str
    status: SecurityAggregationStatus

    execution_status: SecurityExecutionStatus

    task_summaries: list[
        SecurityTaskOutputSummary
    ] = Field(
        default_factory=list,
    )

    artifacts: list[
        SecurityArtifactRecord
    ] = Field(
        default_factory=list,
    )

    ready_task_ids: list[str] = Field(
        default_factory=list,
    )
    running_task_ids: list[str] = Field(
        default_factory=list,
    )
    completed_task_ids: list[str] = Field(
        default_factory=list,
    )
    failed_task_ids: list[str] = Field(
        default_factory=list,
    )
    blocked_task_ids: list[str] = Field(
        default_factory=list,
    )
    skipped_task_ids: list[str] = Field(
        default_factory=list,
    )

    completed_terminal_task_ids: list[str] = Field(
        default_factory=list,
    )
    pending_terminal_task_ids: list[str] = Field(
        default_factory=list,
    )

    reasons: list[str] = Field(
        default_factory=list,
    )
    errors: list[str] = Field(
        default_factory=list,
    )

    audit_event_count: int = Field(ge=0)
    last_event_sequence: int | None = Field(
        default=None,
        ge=1,
    )

    @model_validator(mode="after")
    def validate_aggregation(
        self,
    ) -> "SecurityTaskAggregation":
        summary_ids = [
            summary.task_id
            for summary in self.task_summaries
        ]

        if len(summary_ids) != len(set(summary_ids)):
            raise ValueError(
                "Aggregated task summaries must use "
                "unique task IDs."
            )

        artifact_names = [
            artifact.name
            for artifact in self.artifacts
        ]

        if len(artifact_names) != len(
            set(artifact_names)
        ):
            raise ValueError(
                "Aggregated artifact names must be "
                "unique."
            )

        if self.audit_event_count == 0:
            if self.last_event_sequence is not None:
                raise ValueError(
                    "An empty audit history cannot have "
                    "a last event sequence."
                )
        elif self.last_event_sequence != (
            self.audit_event_count
        ):
            raise ValueError(
                "The final audit sequence must match "
                "the audit event count."
            )

        return self



class SecurityTaskStateResolutionRequest(BaseModel):
    plan: SecurityTaskPlanResponse

    completed_task_ids: list[str] = Field(
        default_factory=list,
    )
    failed_task_ids: list[str] = Field(
        default_factory=list,
    )
    skipped_task_ids: list[str] = Field(
        default_factory=list,
    )
    satisfied_gates: list[
        SecurityTaskGate
    ] = Field(
        default_factory=list,
    )


class SecurityTaskExecutionCreateRequest(BaseModel):
    plan: SecurityTaskPlanResponse
    satisfied_gates: list[
        SecurityTaskGate
    ] = Field(
        default_factory=list,
    )


class SecurityTaskExecutionStartRequest(BaseModel):
    execution: SecurityTaskExecution
    task_id: str = Field(min_length=1)
    satisfied_gates: list[
        SecurityTaskGate
    ] = Field(
        default_factory=list,
    )


class SecurityTaskExecutionCompleteRequest(BaseModel):
    execution: SecurityTaskExecution
    task_id: str = Field(min_length=1)
    output: dict[str, Any] = Field(
        default_factory=dict,
    )
    satisfied_gates: list[
        SecurityTaskGate
    ] = Field(
        default_factory=list,
    )


class SecurityTaskExecutionFailRequest(BaseModel):
    execution: SecurityTaskExecution
    task_id: str = Field(min_length=1)
    error: str = Field(
        min_length=1,
        max_length=10_000,
    )
    output: dict[str, Any] = Field(
        default_factory=dict,
    )
    satisfied_gates: list[
        SecurityTaskGate
    ] = Field(
        default_factory=list,
    )


class SecurityTaskExecutionSkipRequest(BaseModel):
    execution: SecurityTaskExecution
    task_id: str = Field(min_length=1)
    reason: str = Field(
        min_length=1,
        max_length=10_000,
    )
    satisfied_gates: list[
        SecurityTaskGate
    ] = Field(
        default_factory=list,
    )


class SecurityTaskAggregationRequest(BaseModel):
    execution: SecurityTaskExecution
