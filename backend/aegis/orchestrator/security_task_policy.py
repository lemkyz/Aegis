from dataclasses import dataclass, field

from aegis.schemas.security_task_plan import (
    SecurityTaskPlanRequest,
)


@dataclass(frozen=True)
class SecurityTaskPolicyDecision:
    require_threat_model: bool
    recommend_dynamic_validation: bool
    elevated_risk: bool
    reasons: list[str] = field(
        default_factory=list,
    )


class SecurityTaskPlanningPolicy:
    policy = "aegis-security-task-policy-v1"

    _severity_rank = {
        "none": 0,
        "info": 1,
        "low": 2,
        "medium": 3,
        "high": 4,
        "critical": 5,
    }

    def evaluate(
        self,
        request: SecurityTaskPlanRequest,
    ) -> SecurityTaskPolicyDecision:
        severity_rank = self._severity_rank[
            request.highest_severity
        ]

        elevated_risk = (
            severity_rank >= self._severity_rank["high"]
            or request.has_proven_data_flow
            or (
                severity_rank
                >= self._severity_rank["medium"]
                and request.finding_confidence >= 0.9
            )
        )

        require_threat_model = (
            request.operation == "deep_analysis"
            and (
                request.include_threat_model
                or (
                    elevated_risk
                    and request.has_scanner_evidence
                )
            )
        )

        recommend_dynamic_validation = (
            severity_rank
            >= self._severity_rank["critical"]
            and request.has_proven_data_flow
            and request.finding_confidence >= 0.8
        )

        reasons: list[str] = []

        if severity_rank >= self._severity_rank["high"]:
            reasons.append(
                "High or critical severity evidence "
                "requires elevated planning."
            )

        if request.has_proven_data_flow:
            reasons.append(
                "A proven source-to-sink data flow "
                "increases exploitability confidence."
            )

        if (
            request.has_scanner_evidence
            and not request.independently_verified
        ):
            reasons.append(
                "The current evidence has not yet been "
                "independently model-verified."
            )

        if require_threat_model:
            if request.include_threat_model:
                reasons.append(
                    "Threat modeling was explicitly "
                    "requested for this deep analysis."
                )
            else:
                reasons.append(
                    "Threat modeling is required for "
                    "this elevated-risk deep analysis."
                )

        if recommend_dynamic_validation:
            reasons.append(
                "Controlled dynamic validation is "
                "recommended, but remains subject to "
                "explicit authorization."
            )

        if not reasons:
            reasons.append(
                "No elevated-risk planning signal "
                "was detected."
            )

        return SecurityTaskPolicyDecision(
            require_threat_model=(
                require_threat_model
            ),
            recommend_dynamic_validation=(
                recommend_dynamic_validation
            ),
            elevated_risk=elevated_risk,
            reasons=reasons,
        )
