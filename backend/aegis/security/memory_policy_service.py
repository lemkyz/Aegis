from datetime import datetime

from aegis.schemas.memory import (
    SecurityMemoryRecordRequest,
)
from aegis.schemas.policy import (
    MemoryPolicyDecisionResponse,
    MemoryPolicyEvaluationRequest,
    SecurityMemoryPolicyRecordRequest,
    SecurityMemoryPolicyRecordResponse,
)
from aegis.security.memory_policy import (
    MemoryAwarePolicyEngine,
)
from aegis.security.security_memory import (
    SecurityMemoryService,
)


class SecurityMemoryPolicyService:
    """
    Records project security memory and immediately applies
    deterministic policy to the resulting lifecycle delta.
    """

    name = "aegis-security-memory-policy-service-v1"

    def __init__(
        self,
        *,
        memory_service: SecurityMemoryService,
        policy_engine: MemoryAwarePolicyEngine,
    ) -> None:
        self.memory_service = memory_service
        self.policy_engine = policy_engine

    def record_and_evaluate(
        self,
        request: SecurityMemoryPolicyRecordRequest,
        *,
        created_at: datetime | None = None,
    ) -> SecurityMemoryPolicyRecordResponse:
        memory = self.memory_service.record(
            SecurityMemoryRecordRequest(
                repository_path=request.repository_path,
                claims=request.claims,
            ),
            created_at=created_at,
        )

        policy: MemoryPolicyDecisionResponse = (
            self.policy_engine.evaluate(
                MemoryPolicyEvaluationRequest(
                    reconciliation=(
                        memory.reconciliation
                    ),
                    profile=request.profile,
                )
            )
        )

        return SecurityMemoryPolicyRecordResponse(
            memory=memory,
            policy=policy,
        )
