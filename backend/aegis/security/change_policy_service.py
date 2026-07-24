from aegis.schemas.change_policy import (
    ChangePolicyCollectionRequest,
    ChangePolicyCollectionResponse,
    ChangePolicyEvaluationRequest,
    RepositoryPolicyApplication,
)
from aegis.security.change_policy import (
    ChangeAwarePolicyEngine,
)
from aegis.security.git_changes import (
    GitChangeCollector,
)
from aegis.security.repository_policy import (
    load_discovered_repository_policy,
)


class ChangePolicyService:
    """
    Collects a deterministic Git change set and evaluates
    it with repository-aware policy configuration.
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

        policy_path, repository_policy = (
            load_discovered_repository_policy(
                change_set.repository_root
            )
        )

        effective_profile = (
            request.profile
            or (
                repository_policy.profile
                if repository_policy is not None
                and repository_policy.profile
                is not None
                else "balanced"
            )
        )

        policy = self.engine.evaluate(
            ChangePolicyEvaluationRequest(
                change_set=change_set,
                profile=effective_profile,
                repository_policy=(
                    repository_policy
                ),
            )
        )

        active_waivers = 0
        expired_waivers = 0

        for assessment in policy.assessments:
            for finding in assessment.findings:
                active_waivers += int(
                    finding.waived
                )
                expired_waivers += int(
                    finding.waiver_expired
                )

        return ChangePolicyCollectionResponse(
            change_set=change_set,
            policy=policy,
            repository_policy=(
                RepositoryPolicyApplication(
                    source=(
                        str(policy_path)
                        if policy_path is not None
                        else None
                    ),
                    loaded=(
                        repository_policy is not None
                    ),
                    profile=effective_profile,
                    fail_on_review=bool(
                        repository_policy
                        is not None
                        and repository_policy
                        .fail_on_review
                    ),
                    rule_overrides=(
                        len(repository_policy.rules)
                        if repository_policy
                        is not None
                        else 0
                    ),
                    active_waivers=active_waivers,
                    expired_waivers=(
                        expired_waivers
                    ),
                )
            ),
        )
