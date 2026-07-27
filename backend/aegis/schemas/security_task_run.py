from pathlib import PurePosixPath, PureWindowsPath
from typing import Literal

from pydantic import BaseModel, Field, model_validator

from aegis.schemas.analysis import (
    AnalyzeCodeResponse,
)
from aegis.schemas.memory import (
    SecurityMemoryTaskArtifact,
)
from aegis.schemas.policy import (
    PolicyProfile,
    SecurityPolicyTaskArtifact,
)
from aegis.schemas.security_task_plan import (
    SecurityTaskAggregation,
    SecurityTaskExecution,
)
from aegis.schemas.threat_model import (
    ThreatModelScanResponse,
)


class SecurityTaskRunRequest(BaseModel):
    operation: Literal[
        "deep_analysis",
    ] = "deep_analysis"
    repository_path: str = Field(
        min_length=1,
        max_length=2_000,
    )
    code: str = Field(
        min_length=1,
        max_length=200_000,
    )
    filename: str = Field(
        min_length=1,
        max_length=500,
    )
    language: str = Field(
        default="python",
        min_length=1,
        max_length=50,
    )
    include_threat_model: bool = True
    include_security_memory: bool = True
    include_policy_evaluation: bool = True
    policy_profile: PolicyProfile = "balanced"

    @model_validator(mode="after")
    def validate_run_request(
        self,
    ) -> "SecurityTaskRunRequest":
        repository_path = (
            self.repository_path.strip()
        )
        filename = self.filename.strip()
        language = self.language.strip().lower()

        if "\x00" in repository_path:
            raise ValueError(
                "repository_path must not contain "
                "null bytes"
            )

        normalized_filename = (
            filename.replace("\\", "/")
        )
        posix_path = PurePosixPath(
            normalized_filename
        )
        windows_path = PureWindowsPath(
            filename
        )

        if (
            not normalized_filename
            or "\x00" in normalized_filename
            or posix_path.is_absolute()
            or windows_path.is_absolute()
            or windows_path.drive
            or ".." in posix_path.parts
        ):
            raise ValueError(
                "filename must be a safe "
                "repository-relative path"
            )

        if not self.code.strip():
            raise ValueError(
                "code must not be blank"
            )

        if not language:
            raise ValueError(
                "language must not be blank"
            )

        if (
            self.include_policy_evaluation
            and not self.include_security_memory
        ):
            raise ValueError(
                "production policy evaluation "
                "requires security memory"
            )

        self.repository_path = repository_path
        self.filename = normalized_filename
        self.language = language

        return self


class SecurityTaskRunResponse(BaseModel):
    runner: str
    workflow_status: Literal[
        "completed",
        "failed",
        "blocked",
        "stopped",
        "step_limit_reached",
    ]
    execution: SecurityTaskExecution
    aggregation: SecurityTaskAggregation
    analysis: AnalyzeCodeResponse
    threat_model: (
        ThreatModelScanResponse
        | None
    ) = None
    security_memory: (
        SecurityMemoryTaskArtifact
        | None
    ) = None
    policy_decision: (
        SecurityPolicyTaskArtifact
        | None
    ) = None
    errors: list[str] = Field(
        default_factory=list,
    )
