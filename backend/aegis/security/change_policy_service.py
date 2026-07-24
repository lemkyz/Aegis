from aegis.schemas.change_policy import (
    ChangePolicyCollectionRequest,
    ChangePolicyCollectionResponse,
    ChangePolicyEvaluationRequest,
)
from aegis.security.change_policy import (
    ChangeAwarePolicyEngine,
)
from aegis.security.git_changes import (
    GitChangeCollector,
)


class ChangePolicyService:
    """
    Collects a deterministic Git change set and evaluates
    it with the change-aware security policy engine.
    """

    name = "aegis-change-policy-service-v1"

    def __init__(
        self,
        *,
        collector: GitChangeCollector,
        engine: ChangeAwarePolicyEngine,
    ) -> None:
        self.collector = collector
        self.engine = engine

    def collect_and_evaluate(
        self,
        request: ChangePolicyCollectionRequest,
    ) -> ChangePolicyCollectionResponse:
        change_set = self.collector.collect(
            request.repository_path,
            mode=request.mode,
            base_revision=request.base_revision,
            head_revision=request.head_revision,
        )

        policy = self.engine.evaluate(
            ChangePolicyEvaluationRequest(
                change_set=change_set,
                profile=request.profile,
            )
        )

        return ChangePolicyCollectionResponse(
            change_set=change_set,
            policy=policy,
        )
