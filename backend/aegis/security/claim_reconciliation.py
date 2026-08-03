from aegis.schemas.claims import SecurityClaim
from aegis.schemas.memory import (
    ClaimDelta,
    ClaimReconciliationRequest,
    ClaimReconciliationResponse,
    ClaimReconciliationSummary,
)


class ClaimReconciler:
    name = "aegis-claim-reconciler-v1"

    _closed_states = {
        "verified_fixed",
        "false_positive",
        "accepted_risk",
    }

    _active_states = {
        "suspected",
        "supported",
        "confirmed",
        "mitigated",
        "inconclusive",
    }

    def reconcile(
        self,
        request: ClaimReconciliationRequest,
    ) -> ClaimReconciliationResponse:
        previous_by_id = {
            claim.claim_id: claim
            for claim in request.previous_claims
        }
        current_by_id = {
            claim.claim_id: claim
            for claim in request.current_claims
        }

        deltas: list[ClaimDelta] = []

        all_claim_ids = sorted(
            set(previous_by_id)
            | set(current_by_id)
        )

        for claim_id in all_claim_ids:
            previous = previous_by_id.get(claim_id)
            current = current_by_id.get(claim_id)

            deltas.append(
                self._classify(
                    claim_id=claim_id,
                    previous=previous,
                    current=current,
                )
            )

        summary = ClaimReconciliationSummary(
            previous_count=len(
                request.previous_claims
            ),
            current_count=len(
                request.current_claims
            ),
            new=self._count_status(
                deltas,
                "new",
            ),
            persistent=self._count_status(
                deltas,
                "persistent",
            ),
            changed=self._count_status(
                deltas,
                "changed",
            ),
            resolved=self._count_status(
                deltas,
                "resolved",
            ),
            reopened=self._count_status(
                deltas,
                "reopened",
            ),
        )

        return ClaimReconciliationResponse(
            reconciler=self.name,
            deltas=deltas,
            summary=summary,
        )

    def _classify(
        self,
        *,
        claim_id: str,
        previous: SecurityClaim | None,
        current: SecurityClaim | None,
    ) -> ClaimDelta:
        if previous is None and current is not None:
            return ClaimDelta(
                claim_id=claim_id,
                status="new",
                current_state=current.state,
                current_claim=current,
                reasons=[
                    "The claim was not present in the "
                    "previous security-memory baseline."
                ],
            )

        if previous is not None and current is None:
            return ClaimDelta(
                claim_id=claim_id,
                status="resolved",
                previous_state=previous.state,
                previous_claim=previous,
                reasons=[
                    "The claim was present in the previous "
                    "baseline but is absent from the current "
                    "analysis."
                ],
            )

        if previous is None or current is None:
            raise RuntimeError(
                "Claim reconciliation reached an "
                "unclassifiable state."
            )

        if self._is_reopened(
            previous=previous,
            current=current,
        ):
            return ClaimDelta(
                claim_id=claim_id,
                status="reopened",
                previous_state=previous.state,
                current_state=current.state,
                previous_claim=previous,
                current_claim=current,
                reasons=[
                    "A previously closed security claim "
                    "became active again."
                ],
            )

        changed_fields = self._changed_fields(
            previous=previous,
            current=current,
        )

        if changed_fields:
            return ClaimDelta(
                claim_id=claim_id,
                status="changed",
                previous_state=previous.state,
                current_state=current.state,
                previous_claim=previous,
                current_claim=current,
                reasons=[
                    "Security-relevant claim fields changed: "
                    + ", ".join(changed_fields)
                    + "."
                ],
            )

        return ClaimDelta(
            claim_id=claim_id,
            status="persistent",
            previous_state=previous.state,
            current_state=current.state,
            previous_claim=previous,
            current_claim=current,
            reasons=[
                "The same security claim remains present "
                "without a material lifecycle change."
            ],
        )

    def _is_reopened(
        self,
        *,
        previous: SecurityClaim,
        current: SecurityClaim,
    ) -> bool:
        return (
            previous.state in self._closed_states
            and current.state in self._active_states
        )

    @staticmethod
    def _changed_fields(
        *,
        previous: SecurityClaim,
        current: SecurityClaim,
    ) -> list[str]:
        changed: list[str] = []

        if previous.state != current.state:
            changed.append("state")

        if previous.severity != current.severity:
            changed.append("severity")

        if previous.confidence != current.confidence:
            changed.append("confidence")

        if (
            ClaimReconciler._evidence_ids(previous)
            != ClaimReconciler._evidence_ids(current)
        ):
            changed.append("evidence")

        if (
            ClaimReconciler._relationship_ids(previous)
            != ClaimReconciler._relationship_ids(current)
        ):
            changed.append("relationships")

        if (
            ClaimReconciler._location_identity(previous)
            != ClaimReconciler._location_identity(current)
        ):
            changed.append("locations")

        return changed

    @staticmethod
    def _evidence_ids(
        claim: SecurityClaim,
    ) -> tuple[str, ...]:
        return tuple(
            sorted(
                evidence.evidence_id
                for evidence in claim.evidence
            )
        )

    @staticmethod
    def _relationship_ids(
        claim: SecurityClaim,
    ) -> tuple[str, ...]:
        return tuple(
            sorted(
                relationship.relationship_id
                for relationship
                in claim.relationships
            )
        )

    @staticmethod
    def _location_identity(
        claim: SecurityClaim,
    ) -> tuple[
        tuple[str, int, int, str],
        ...,
    ]:
        return tuple(
            sorted(
                (
                    location.file,
                    location.line_start,
                    location.line_end,
                    location.symbol or "",
                )
                for location in claim.locations
            )
        )

    @staticmethod
    def _count_status(
        deltas: list[ClaimDelta],
        status: str,
    ) -> int:
        return sum(
            delta.status == status
            for delta in deltas
        )
