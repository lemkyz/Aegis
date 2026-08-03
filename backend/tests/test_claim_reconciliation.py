import pytest
from pydantic import ValidationError

from aegis.schemas.claims import (
    CodeLocation,
    EvidenceItem,
    EvidenceRelationship,
    EvidenceSource,
    SecurityClaim,
)
from aegis.schemas.memory import (
    ClaimReconciliationRequest,
)
from aegis.security.claim_reconciliation import (
    ClaimReconciler,
)


def claim(
    claim_id: str,
    *,
    state: str = "supported",
    severity: str = "high",
    confidence: float = 0.9,
    line: int = 20,
    evidence_ids: list[str] | None = None,
) -> SecurityClaim:
    return SecurityClaim(
        claim_id=claim_id,
        statement=(
            "Untrusted input reaches shell execution."
        ),
        category="command-injection",
        severity=severity,
        confidence=confidence,
        state=state,
        cwe=["CWE-78"],
        locations=[
            CodeLocation(
                file="src/app.py",
                line_start=line,
                line_end=line + 4,
            )
        ],
        evidence=[
            EvidenceItem(
                evidence_id=evidence_id,
                source=EvidenceSource(
                    kind="scanner",
                    name="Semgrep",
                    rule_id=(
                        "aegis.python.command-injection."
                        "subprocess-shell"
                    ),
                ),
                summary="Command injection detected.",
                confidence=confidence,
            )
            for evidence_id in (
                evidence_ids
                if evidence_ids is not None
                else ["evidence:scanner:1"]
            )
        ],
        remediation="Disable shell execution.",
    )


def reconcile(
    *,
    previous: list[SecurityClaim],
    current: list[SecurityClaim],
):
    return ClaimReconciler().reconcile(
        ClaimReconciliationRequest(
            previous_claims=previous,
            current_claims=current,
        )
    )


def test_classifies_new_claim() -> None:
    current = claim("claim:new")

    result = reconcile(
        previous=[],
        current=[current],
    )

    assert result.deltas[0].status == "new"
    assert result.deltas[0].previous_claim is None
    assert result.deltas[0].current_claim == current

    assert result.summary.previous_count == 0
    assert result.summary.current_count == 1
    assert result.summary.new == 1


def test_classifies_persistent_claim() -> None:
    previous = claim("claim:persistent")
    current = claim("claim:persistent")

    result = reconcile(
        previous=[previous],
        current=[current],
    )

    assert result.deltas[0].status == "persistent"
    assert result.summary.persistent == 1


def test_classifies_changed_state() -> None:
    previous = claim(
        "claim:changed",
        state="supported",
    )
    current = claim(
        "claim:changed",
        state="confirmed",
    )

    result = reconcile(
        previous=[previous],
        current=[current],
    )

    delta = result.deltas[0]

    assert delta.status == "changed"
    assert delta.previous_state == "supported"
    assert delta.current_state == "confirmed"
    assert "state" in delta.reasons[0]


def test_classifies_relationship_change_as_changed() -> None:
    previous = claim(
        "claim:relationships",
        evidence_ids=[
            "evidence:scanner:1",
            "evidence:dynamic:1",
        ],
    )
    current = previous.model_copy(
        deep=True,
        update={
            "relationships": [
                EvidenceRelationship(
                    relationship_id=(
                        "relationship:verifies:1"
                    ),
                    source_evidence_id=(
                        "evidence:dynamic:1"
                    ),
                    target_evidence_id=(
                        "evidence:scanner:1"
                    ),
                    kind="corroborates",
                    reason=(
                        "Runtime evidence corroborates "
                        "the scanner result."
                    ),
                )
            ],
        },
    )

    result = reconcile(
        previous=[previous],
        current=[current],
    )

    delta = result.deltas[0]

    assert delta.status == "changed"
    assert "relationships" in delta.reasons[0]


def test_classifies_evidence_enrichment_as_changed() -> None:
    previous = claim(
        "claim:evidence",
        evidence_ids=["evidence:scanner:1"],
    )
    current = claim(
        "claim:evidence",
        evidence_ids=[
            "evidence:scanner:1",
            "evidence:dynamic:1",
        ],
    )

    result = reconcile(
        previous=[previous],
        current=[current],
    )

    assert result.deltas[0].status == "changed"
    assert "evidence" in result.deltas[0].reasons[0]


def test_classifies_absent_claim_as_resolved() -> None:
    previous = claim("claim:resolved")

    result = reconcile(
        previous=[previous],
        current=[],
    )

    delta = result.deltas[0]

    assert delta.status == "resolved"
    assert delta.previous_claim == previous
    assert delta.current_claim is None
    assert result.summary.resolved == 1


@pytest.mark.parametrize(
    "closed_state",
    [
        "verified_fixed",
        "false_positive",
        "accepted_risk",
    ],
)
def test_classifies_closed_claim_returning_as_reopened(
    closed_state: str,
) -> None:
    previous = claim(
        "claim:reopened",
        state=closed_state,
    )
    current = claim(
        "claim:reopened",
        state="supported",
    )

    result = reconcile(
        previous=[previous],
        current=[current],
    )

    delta = result.deltas[0]

    assert delta.status == "reopened"
    assert delta.previous_state == closed_state
    assert delta.current_state == "supported"
    assert result.summary.reopened == 1
    assert result.summary.new == 0


def test_active_state_progression_is_changed_not_reopened() -> None:
    previous = claim(
        "claim:progression",
        state="supported",
    )
    current = claim(
        "claim:progression",
        state="confirmed",
    )

    result = reconcile(
        previous=[previous],
        current=[current],
    )

    assert result.deltas[0].status == "changed"
    assert result.summary.reopened == 0


def test_output_order_is_deterministic() -> None:
    result = reconcile(
        previous=[
            claim("claim:z"),
            claim("claim:a"),
        ],
        current=[
            claim("claim:m"),
            claim("claim:a"),
        ],
    )

    assert [
        delta.claim_id
        for delta in result.deltas
    ] == [
        "claim:a",
        "claim:m",
        "claim:z",
    ]


def test_summary_counts_all_delta_types() -> None:
    result = reconcile(
        previous=[
            claim("claim:persistent"),
            claim(
                "claim:changed",
                state="supported",
            ),
            claim("claim:resolved"),
            claim(
                "claim:reopened",
                state="verified_fixed",
            ),
        ],
        current=[
            claim("claim:persistent"),
            claim(
                "claim:changed",
                state="confirmed",
            ),
            claim(
                "claim:reopened",
                state="supported",
            ),
            claim("claim:new"),
        ],
    )

    assert result.summary.previous_count == 4
    assert result.summary.current_count == 4

    assert result.summary.new == 1
    assert result.summary.persistent == 1
    assert result.summary.changed == 1
    assert result.summary.resolved == 1
    assert result.summary.reopened == 1
    assert result.summary.total_deltas == 5


def test_rejects_duplicate_previous_claim_ids() -> None:
    duplicate = claim("claim:duplicate")

    with pytest.raises(
        ValidationError,
        match="previous_claims",
    ):
        ClaimReconciliationRequest(
            previous_claims=[
                duplicate,
                duplicate,
            ],
            current_claims=[],
        )


def test_rejects_duplicate_current_claim_ids() -> None:
    duplicate = claim("claim:duplicate")

    with pytest.raises(
        ValidationError,
        match="current_claims",
    ):
        ClaimReconciliationRequest(
            previous_claims=[],
            current_claims=[
                duplicate,
                duplicate,
            ],
        )


def _relationship_claim(
    claim_id: str,
    *,
    relationships: list[EvidenceRelationship],
) -> SecurityClaim:
    return claim(
        claim_id,
        evidence_ids=[
            "evidence:source",
            "evidence:target",
            "evidence:alternate",
        ],
    ).model_copy(
        deep=True,
        update={
            "relationships": relationships,
        },
    )


@pytest.mark.parametrize(
    "changed_relationship",
    [
        EvidenceRelationship(
            relationship_id="relationship:stable",
            source_evidence_id="evidence:source",
            target_evidence_id="evidence:target",
            kind="supports",
            reason="Updated material reason.",
        ),
        EvidenceRelationship(
            relationship_id="relationship:stable",
            source_evidence_id="evidence:source",
            target_evidence_id="evidence:alternate",
            kind="supports",
            reason="Original material reason.",
        ),
        EvidenceRelationship(
            relationship_id="relationship:stable",
            source_evidence_id="evidence:source",
            target_evidence_id="evidence:target",
            kind="verifies",
            reason="Original material reason.",
        ),
    ],
    ids=[
        "reason",
        "endpoint",
        "kind",
    ],
)
def test_relationship_material_change_is_reconciled(
    changed_relationship: EvidenceRelationship,
) -> None:
    previous = _relationship_claim(
        "claim:relationship-material-change",
        relationships=[
            EvidenceRelationship(
                relationship_id="relationship:stable",
                source_evidence_id="evidence:source",
                target_evidence_id="evidence:target",
                kind="supports",
                reason="Original material reason.",
            )
        ],
    )
    current = _relationship_claim(
        previous.claim_id,
        relationships=[changed_relationship],
    )

    result = reconcile(
        previous=[previous],
        current=[current],
    )

    delta = result.deltas[0]

    assert delta.status == "changed"
    assert "relationships" in delta.reasons[0]


def test_relationship_order_is_ignored_during_reconciliation() -> None:
    first = EvidenceRelationship(
        relationship_id="relationship:first",
        source_evidence_id="evidence:source",
        target_evidence_id="evidence:target",
        kind="supports",
        reason="Primary epistemic relationship.",
    )
    second = EvidenceRelationship(
        relationship_id="relationship:second",
        source_evidence_id="evidence:alternate",
        target_evidence_id="evidence:source",
        kind="derived_from",
        reason="Independent provenance relationship.",
    )

    previous = _relationship_claim(
        "claim:relationship-order",
        relationships=[first, second],
    )
    current = _relationship_claim(
        previous.claim_id,
        relationships=[second, first],
    )

    result = reconcile(
        previous=[previous],
        current=[current],
    )

    assert result.deltas[0].status == "persistent"
