from aegis.schemas.validation import (
    UnifiedFixVerificationRequest,
    UnifiedFixVerificationResponse,
)


class UnifiedFixVerificationEvaluator:
    evaluator = "aegis-unified-fix-verification-v1"

    def evaluate(
        self,
        request: UnifiedFixVerificationRequest,
    ) -> UnifiedFixVerificationResponse:
        passed_checks = [
            check.name
            for check in request.project_checks
            if check.status == "passed"
        ]
        failed_checks = [
            check.name
            for check in request.project_checks
            if check.status == "failed"
        ]
        skipped_checks = [
            check.name
            for check in request.project_checks
            if check.status == "skipped"
        ]

        project_checks_passed = all(
            check.status == "passed"
            for check in request.project_checks
        )

        dynamic_replay_fixed = (
            request.replay.verdict == "fixed"
            and request.replay.fixed
        )

        reasons: list[str] = []

        if failed_checks:
            verdict = "project_failed"
            verified = False
            confidence = 1.0
            reasons.append(
                "One or more project verification "
                "checks failed."
            )

        elif skipped_checks:
            verdict = "inconclusive"
            verified = False
            confidence = 1.0
            reasons.append(
                "One or more configured project "
                "verification checks were skipped; "
                "verification is incomplete."
            )

        elif not request.static_target_resolved:
            verdict = "target_not_resolved"
            verified = False
            confidence = 0.99
            reasons.append(
                "The target vulnerability remains "
                "detectable after the fix."
            )

        elif not request.static_regression_free:
            verdict = "regression_detected"
            verified = False
            confidence = 0.99
            reasons.append(
                "The fix introduced one or more new "
                "security findings."
            )

        elif request.replay.verdict == (
            "still_exploitable"
        ):
            verdict = "still_exploitable"
            verified = False
            confidence = (
                request.replay.confidence
            )
            reasons.append(
                "The original dynamic validation still "
                "reproduces after the fix."
            )

        elif request.replay.verdict == (
            "inconclusive"
        ):
            verdict = "inconclusive"
            verified = False
            confidence = (
                request.replay.confidence
            )
            reasons.append(
                "Dynamic replay did not produce enough "
                "evidence to verify the fix."
            )

        elif dynamic_replay_fixed:
            verdict = "verified"
            verified = True
            confidence = min(
                request.replay.confidence,
                0.99,
            )
            reasons.extend(
                [
                    (
                        "Configured project checks "
                        "completed without failure."
                    ),
                    (
                        "The target vulnerability is no "
                        "longer present in the static scan."
                    ),
                    (
                        "No new static security "
                        "regressions were detected."
                    ),
                    (
                        "The previously confirmed dynamic "
                        "validation no longer reproduces."
                    ),
                ]
            )

        else:
            verdict = "inconclusive"
            verified = False
            confidence = 0.95
            reasons.append(
                "The supplied replay result cannot prove "
                "that the fix is effective."
            )

        return UnifiedFixVerificationResponse(
            evaluator=self.evaluator,
            threat_id=request.replay.threat_id,
            claim_id=request.replay.claim_id,
            category=request.replay.category,
            verdict=verdict,
            verified=verified,
            confidence=confidence,
            project_checks_passed=(
                project_checks_passed
            ),
            static_target_resolved=(
                request.static_target_resolved
            ),
            static_regression_free=(
                request.static_regression_free
            ),
            dynamic_replay_fixed=(
                dynamic_replay_fixed
            ),
            reasons=reasons,
            passed_checks=passed_checks,
            failed_checks=failed_checks,
            skipped_checks=skipped_checks,
        )
