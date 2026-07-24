from aegis.schemas.claims import SecurityClaim
from aegis.schemas.memory import (
    ClaimDelta,
    ClaimReconciliationResponse,
    ClaimReconciliationSummary,
)
from aegis.schemas.policy import (
    MemoryPolicyEvaluationRequest,
)
from aegis.security.memory_policy import (
    MemoryAwarePolicyEngine,
)


def claim(
    claim_id: str,
    *,
    severity: str,
    confidence: float = 1.0,
    state: str = "confirmed",
) -> SecurityClaim:
    return SecurityClaim(
        claim_id=claim_id,
        statement="A security issue exists.",
        category="command-injection",
        severity=severity,
        confidence=confidence,
        state=state,
        cwe=["CWE-78"],
        owasp=["A03:2021"],
        locations=[],
        evidence=[],
        relationships=[],
        remediation="Apply a secure fix.",
    )


def reconciliation(
    *deltas: ClaimDelta,
) -> ClaimReconciliationResponse:
    statuses = [
        delta.status
        for delta in deltas
    ]

    previous_count = sum(
        delta.previous_claim is not None
        for delta in deltas
    )
    current_count = sum(
        delta.current_claim is not None
        for delta in deltas
    )

    return ClaimReconciliationResponse(
        reconciler=(
            "aegis-claim-reconciler-v1"
        ),
        deltas=list(deltas),
        summary=ClaimReconciliationSummary(
            previous_count=previous_count,
            current_count=current_count,
            new=statuses.count("new"),
            persistent=statuses.count(
                "persistent"
            ),
            changed=statuses.count("changed"),
            resolved=statuses.count(
                "resolved"
            ),
            reopened=statuses.count(
                "reopened"
            ),
        ),
    )


def evaluate(
    *deltas: ClaimDelta,
):
    return MemoryAwarePolicyEngine().evaluate(
        MemoryPolicyEvaluationRequest(
            reconciliation=reconciliation(
                *deltas
            )
        )
    )


def test_allows_empty_delta_set() -> None:
    result = evaluate()

    assert result.decision == "allow"
    assert result.risk_score == 0
    assert result.risk_level == "none"
    assert result.assessments == []
    assert result.summary.claims_evaluated == 0


def test_blocks_new_critical_claim() -> None:
    current = claim(
        "claim:critical",
        severity="critical",
    )

    result = evaluate(
        ClaimDelta(
            claim_id=current.claim_id,
            status="new",
            current_state=current.state,
            current_claim=current,
        )
    )

    assert result.decision == "block"
    assert result.risk_score == 95
    assert result.risk_level == "critical"
    assert result.blocking_claim_ids == [
        current.claim_id
    ]


def test_blocks_reopened_high_claim() -> None:
    previous = claim(
        "claim:reopened",
        severity="high",
        state="verified_fixed",
    )
    current = claim(
        "claim:reopened",
        severity="high",
        state="confirmed",
    )

    result = evaluate(
        ClaimDelta(
            claim_id=current.claim_id,
            status="reopened",
            previous_state=previous.state,
            current_state=current.state,
            previous_claim=previous,
            current_claim=current,
        )
    )

    assessment = result.assessments[0]

    assert result.decision == "block"
    assert assessment.lifecycle_status == (
        "reopened"
    )
    assert assessment.risk_score == 80
    assert any(
        "security regression" in reason
        for reason in assessment.reasons
    )


def test_requires_review_for_persistent_high_claim(
) -> None:
    previous = claim(
        "claim:persistent",
        severity="high",
    )
    current = previous.model_copy(deep=True)

    result = evaluate(
        ClaimDelta(
            claim_id=current.claim_id,
            status="persistent",
            previous_state=previous.state,
            current_state=current.state,
            previous_claim=previous,
            current_claim=current,
        )
    )

    assert result.decision == "review"
    assert result.risk_score == 70
    assert result.review_claim_ids == [
        current.claim_id
    ]


def test_requires_review_for_new_medium_claim(
) -> None:
    current = claim(
        "claim:medium",
        severity="medium",
    )

    result = evaluate(
        ClaimDelta(
            claim_id=current.claim_id,
            status="new",
            current_state=current.state,
            current_claim=current,
        )
    )

    assert result.decision == "review"
    assert result.risk_score == 50


def test_allows_low_confidence_low_claim() -> None:
    current = claim(
        "claim:low",
        severity="low",
        confidence=0.5,
    )

    result = evaluate(
        ClaimDelta(
            claim_id=current.claim_id,
            status="new",
            current_state=current.state,
            current_claim=current,
        )
    )

    assert result.decision == "allow"
    assert result.risk_score == 19


def test_ignores_resolved_claim() -> None:
    previous = claim(
        "claim:resolved",
        severity="critical",
    )

    result = evaluate(
        ClaimDelta(
            claim_id=previous.claim_id,
            status="resolved",
            previous_state=previous.state,
            previous_claim=previous,
        )
    )

    assert result.decision == "allow"
    assert result.summary.claims_ignored == 1
    assert result.summary.claims_evaluated == 0


def test_ignores_inactive_current_claim() -> None:
    current = claim(
        "claim:fixed",
        severity="critical",
        state="verified_fixed",
    )

    result = evaluate(
        ClaimDelta(
            claim_id=current.claim_id,
            status="changed",
            current_state=current.state,
            current_claim=current,
        )
    )

    assert result.decision == "allow"
    assert result.summary.claims_ignored == 1


def test_block_overrides_review_and_allow() -> None:
    low = claim(
        "claim:low",
        severity="low",
    )
    medium = claim(
        "claim:medium",
        severity="medium",
    )
    critical = claim(
        "claim:critical",
        severity="critical",
    )

    result = evaluate(
        ClaimDelta(
            claim_id=low.claim_id,
            status="persistent",
            current_state=low.state,
            current_claim=low,
        ),
        ClaimDelta(
            claim_id=medium.claim_id,
            status="new",
            current_state=medium.state,
            current_claim=medium,
        ),
        ClaimDelta(
            claim_id=critical.claim_id,
            status="new",
            current_state=critical.state,
            current_claim=critical,
        ),
    )

    assert result.decision == "block"
    assert result.summary.allowed == 1
    assert result.summary.review_required == 1
    assert result.summary.blocked == 1


def test_assessment_order_is_deterministic() -> None:
    lower = claim(
        "claim:z",
        severity="medium",
    )
    higher_b = claim(
        "claim:b",
        severity="high",
    )
    higher_a = claim(
        "claim:a",
        severity="high",
    )

    result = evaluate(
        ClaimDelta(
            claim_id=lower.claim_id,
            status="new",
            current_state=lower.state,
            current_claim=lower,
        ),
        ClaimDelta(
            claim_id=higher_b.claim_id,
            status="new",
            current_state=higher_b.state,
            current_claim=higher_b,
        ),
        ClaimDelta(
            claim_id=higher_a.claim_id,
            status="new",
            current_state=higher_a.state,
            current_claim=higher_a,
        ),
    )

    assert [
        item.claim_id
        for item in result.assessments
    ] == [
        "claim:a",
        "claim:b",
        "claim:z",
    ]


def test_same_input_produces_same_output() -> None:
    current = claim(
        "claim:deterministic",
        severity="high",
        confidence=0.87,
    )

    delta = ClaimDelta(
        claim_id=current.claim_id,
        status="changed",
        current_state=current.state,
        current_claim=current,
    )

    engine = MemoryAwarePolicyEngine()
    request = MemoryPolicyEvaluationRequest(
        reconciliation=reconciliation(delta)
    )

    first = engine.evaluate(request)
    second = engine.evaluate(request)

    assert first == second
    assert (
        first.model_dump_json()
        == second.model_dump_json()
    )
