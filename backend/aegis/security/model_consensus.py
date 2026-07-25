from aegis.schemas.analysis import SecurityFinding
from aegis.schemas.model_consensus import (
    FindingConsensusDecision,
    ModelConsensusResult,
)
from aegis.schemas.model_verification import (
    VerifierReviewResult,
)


class ModelConsensusEvaluator:
    name = "aegis-model-consensus-v1"

    def evaluate(
        self,
        *,
        primary_model: str,
        primary_findings: list[SecurityFinding],
        verifier_result: VerifierReviewResult,
    ) -> ModelConsensusResult:
        errors: list[str] = []

        if verifier_result.status != "completed":
            error = (
                verifier_result.error
                or "Verifier review did not complete."
            )

            return ModelConsensusResult(
                primary_model=primary_model,
                verifier_model=verifier_result.model,
                status="partial",
                decisions=[
                    FindingConsensusDecision(
                        finding_index=index,
                        verdict="unverified",
                        confidence=min(
                            finding.confidence,
                            0.70,
                        ),
                        primary_confidence=(
                            finding.confidence
                        ),
                        reasons=[
                            "The primary finding was not "
                            "independently verified.",
                            error,
                        ],
                    )
                    for index, finding
                    in enumerate(primary_findings)
                ],
                errors=[error],
            )

        verifications_by_index = {}

        for verification in verifier_result.verifications:
            index = verification.finding_index

            if index >= len(primary_findings):
                errors.append(
                    "Verifier referenced an unknown primary "
                    f"finding index: {index}."
                )
                continue

            if index in verifications_by_index:
                errors.append(
                    "Verifier returned duplicate decisions for "
                    f"primary finding index: {index}."
                )
                continue

            verifications_by_index[index] = verification

        decisions: list[FindingConsensusDecision] = []

        for index, finding in enumerate(primary_findings):
            verification = verifications_by_index.get(index)

            if verification is None:
                decisions.append(
                    FindingConsensusDecision(
                        finding_index=index,
                        verdict="unverified",
                        confidence=min(
                            finding.confidence,
                            0.70,
                        ),
                        primary_confidence=(
                            finding.confidence
                        ),
                        reasons=[
                            "No independent verifier decision "
                            "was returned for this finding."
                        ],
                    )
                )
                continue

            if verification.verdict == "supported":
                verdict = "confirmed"
                confidence = min(
                    (
                        finding.confidence
                        + verification.confidence
                    )
                    / 2,
                    0.99,
                )
                reason = (
                    "The independent verifier supports the "
                    "primary finding."
                )

            elif verification.verdict == "refuted":
                verdict = "disputed"
                confidence = verification.confidence
                reason = (
                    "The independent verifier refutes the "
                    "primary finding."
                )

            else:
                verdict = "uncertain"
                confidence = min(
                    finding.confidence,
                    verification.confidence,
                )
                reason = (
                    "The independent verifier found the "
                    "available evidence insufficient."
                )

            decisions.append(
                FindingConsensusDecision(
                    finding_index=index,
                    verdict=verdict,
                    confidence=confidence,
                    primary_confidence=finding.confidence,
                    verifier_confidence=(
                        verification.confidence
                    ),
                    reasons=[
                        reason,
                        verification.reasoning,
                    ],
                )
            )

        status = (
            "partial"
            if errors
            or any(
                decision.verdict == "unverified"
                for decision in decisions
            )
            else "completed"
        )

        return ModelConsensusResult(
            primary_model=primary_model,
            verifier_model=verifier_result.model,
            status=status,
            decisions=decisions,
            errors=errors,
        )
