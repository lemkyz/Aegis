from aegis.schemas.memory import ClaimDelta
from aegis.schemas.policy import (
    MemoryPolicyDecisionResponse,
    MemoryPolicyEvaluationRequest,
    MemoryPolicySummary,
    PolicyClaimAssessment,
    PolicyDecision,
    PolicyRiskLevel,
)


class MemoryAwarePolicyEngine:
    """
    Deterministic policy gate for security-memory deltas.

    The engine does not use an AI model. It converts claim
    severity, confidence, state, and lifecycle history into a
    reproducible risk score and allow/review/block decision.
    """

    engine = "aegis-memory-aware-policy-engine-v1"
    policy_version = "1.0"

    _severity_scores = {
        "critical": 90,
        "high": 70,
        "medium": 45,
        "low": 20,
        "info": 5,
    }

    _lifecycle_modifiers = {
        "new": 5,
        "persistent": 0,
        "changed": 5,
        "resolved": 0,
        "reopened": 10,
    }

    _inactive_states = {
        "verified_fixed",
        "false_positive",
        "accepted_risk",
    }

    def evaluate(
        self,
        request: MemoryPolicyEvaluationRequest,
    ) -> MemoryPolicyDecisionResponse:
        assessments: list[
            PolicyClaimAssessment
        ] = []

        ignored = 0

        for delta in request.reconciliation.deltas:
            assessment = self._assess_delta(delta)

            if assessment is None:
                ignored += 1
                continue

            assessments.append(assessment)

        assessments.sort(
            key=lambda item: (
                -item.risk_score,
                item.claim_id,
            )
        )

        blocking_claim_ids = [
            item.claim_id
            for item in assessments
            if item.decision == "block"
        ]

        review_claim_ids = [
            item.claim_id
            for item in assessments
            if item.decision == "review"
        ]

        decision = self._overall_decision(
            assessments
        )

        risk_score = max(
            (
                item.risk_score
                for item in assessments
            ),
            default=0,
        )

        risk_level = self._risk_level(
            risk_score
        )

        summary = MemoryPolicySummary(
            claims_evaluated=len(assessments),
            claims_ignored=ignored,
            allowed=sum(
                item.decision == "allow"
                for item in assessments
            ),
            review_required=sum(
                item.decision == "review"
                for item in assessments
            ),
            blocked=sum(
                item.decision == "block"
                for item in assessments
            ),
            highest_risk_score=risk_score,
            highest_risk_level=risk_level,
            new=sum(
                item.lifecycle_status == "new"
                for item in assessments
            ),
            persistent=sum(
                item.lifecycle_status
                == "persistent"
                for item in assessments
            ),
            changed=sum(
                item.lifecycle_status == "changed"
                for item in assessments
            ),
            reopened=sum(
                item.lifecycle_status == "reopened"
                for item in assessments
            ),
        )

        return MemoryPolicyDecisionResponse(
            engine=self.engine,
            policy_version=self.policy_version,
            profile=request.profile,
            decision=decision,
            risk_score=risk_score,
            risk_level=risk_level,
            blocking_claim_ids=blocking_claim_ids,
            review_claim_ids=review_claim_ids,
            assessments=assessments,
            summary=summary,
            reasons=self._overall_reasons(
                decision=decision,
                assessments=assessments,
            ),
        )

    def _assess_delta(
        self,
        delta: ClaimDelta,
    ) -> PolicyClaimAssessment | None:
        if delta.status == "resolved":
            return None

        claim = delta.current_claim

        if claim is None:
            return None

        if claim.state in self._inactive_states:
            return None

        severity = claim.severity
        confidence = claim.confidence

        base_score = self._severity_scores[
            severity
        ]

        lifecycle_modifier = (
            self._lifecycle_modifiers[
                delta.status
            ]
        )

        confidence_factor = (
            0.5
            + (0.5 * confidence)
        )

        risk_score = round(
            (
                base_score
                + lifecycle_modifier
            )
            * confidence_factor
        )

        risk_score = max(
            0,
            min(100, risk_score),
        )

        risk_level = self._risk_level(
            risk_score
        )

        decision = self._claim_decision(
            delta=delta,
            risk_score=risk_score,
        )

        reasons = [
            (
                f"Severity {severity} contributes a "
                f"base risk score of {base_score}."
            ),
            (
                f"Lifecycle status {delta.status} "
                f"contributes a modifier of "
                f"{lifecycle_modifier}."
            ),
            (
                f"Evidence confidence is "
                f"{confidence:.2f}."
            ),
        ]

        if delta.status == "reopened":
            reasons.append(
                "A previously closed claim returned and "
                "is treated as a security regression."
            )

        if decision == "block":
            reasons.append(
                "The claim meets the deterministic "
                "blocking threshold."
            )
        elif decision == "review":
            reasons.append(
                "The claim requires explicit human "
                "security review."
            )
        else:
            reasons.append(
                "The claim remains below the review "
                "threshold."
            )

        return PolicyClaimAssessment(
            claim_id=claim.claim_id,
            lifecycle_status=delta.status,
            severity=severity,
            confidence=confidence,
            risk_score=risk_score,
            risk_level=risk_level,
            decision=decision,
            reasons=reasons,
        )

    @staticmethod
    def _claim_decision(
        *,
        delta: ClaimDelta,
        risk_score: int,
    ) -> PolicyDecision:
        if (
            delta.status == "reopened"
            and risk_score >= 65
        ):
            return "block"

        if risk_score >= 80:
            return "block"

        if risk_score >= 40:
            return "review"

        return "allow"

    @staticmethod
    def _overall_decision(
        assessments: list[
            PolicyClaimAssessment
        ],
    ) -> PolicyDecision:
        if any(
            item.decision == "block"
            for item in assessments
        ):
            return "block"

        if any(
            item.decision == "review"
            for item in assessments
        ):
            return "review"

        return "allow"

    @staticmethod
    def _risk_level(
        score: int,
    ) -> PolicyRiskLevel:
        if score >= 90:
            return "critical"

        if score >= 70:
            return "high"

        if score >= 40:
            return "medium"

        if score >= 1:
            return "low"

        return "none"

    @staticmethod
    def _overall_reasons(
        *,
        decision: PolicyDecision,
        assessments: list[
            PolicyClaimAssessment
        ],
    ) -> list[str]:
        if not assessments:
            return [
                "No active security claim required a "
                "policy decision."
            ]

        if decision == "block":
            count = sum(
                item.decision == "block"
                for item in assessments
            )

            return [
                (
                    f"{count} active security claim(s) "
                    "triggered the blocking policy."
                ),
                (
                    "The change must not pass the "
                    "security gate without remediation "
                    "or an explicit future policy "
                    "override."
                ),
            ]

        if decision == "review":
            count = sum(
                item.decision == "review"
                for item in assessments
            )

            return [
                (
                    f"{count} active security claim(s) "
                    "require human review."
                )
            ]

        return [
            "All active claims remain below the "
            "configured review threshold."
        ]
