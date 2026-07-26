import pytest

from aegis.orchestrator.security_task_planner import (
    SecurityTaskPlanner,
)
from aegis.orchestrator.security_task_state import (
    SecurityTaskStateResolver,
)
from aegis.schemas.security_task_plan import (
    SecurityTaskPlanRequest,
)


def task_by_id(result, task_id):
    return next(
        task
        for task in result.tasks
        if task.task_id == task_id
    )


def deep_plan():
    return SecurityTaskPlanner().plan(
        SecurityTaskPlanRequest(
            operation="deep_analysis",
            has_scanner_evidence=True,
        )
    )


def test_scan_becomes_ready_after_context_completes() -> None:
    result = SecurityTaskStateResolver().resolve(
        deep_plan(),
        completed_task_ids=[
            "repository_context",
        ],
    )

    assert (
        task_by_id(
            result,
            "deterministic_scan",
        ).state
        == "ready"
    )


def test_model_review_waits_for_scanner() -> None:
    result = SecurityTaskStateResolver().resolve(
        deep_plan(),
        completed_task_ids=[
            "repository_context",
        ],
        satisfied_gates=[
            "scanner_evidence",
            "ai_available",
        ],
    )

    assert (
        task_by_id(
            result,
            "primary_model_review",
        ).state
        == "waiting"
    )


def test_model_review_ready_after_scanner_and_gates() -> None:
    result = SecurityTaskStateResolver().resolve(
        deep_plan(),
        completed_task_ids=[
            "repository_context",
            "deterministic_scan",
        ],
        satisfied_gates=[
            "scanner_evidence",
            "ai_available",
        ],
    )

    assert (
        task_by_id(
            result,
            "primary_model_review",
        ).state
        == "ready"
    )


def test_failed_scanner_blocks_model_chain() -> None:
    result = SecurityTaskStateResolver().resolve(
        deep_plan(),
        completed_task_ids=[
            "repository_context",
        ],
        failed_task_ids=[
            "deterministic_scan",
        ],
        satisfied_gates=[
            "scanner_evidence",
            "ai_available",
        ],
    )

    assert (
        task_by_id(
            result,
            "primary_model_review",
        ).state
        == "blocked"
    )
    assert (
        task_by_id(
            result,
            "verifier_review",
        ).state
        == "blocked"
    )
    assert (
        task_by_id(
            result,
            "model_consensus",
        ).state
        == "blocked"
    )


def test_skipped_primary_skips_dependents() -> None:
    result = SecurityTaskStateResolver().resolve(
        deep_plan(),
        completed_task_ids=[
            "repository_context",
            "deterministic_scan",
        ],
        skipped_task_ids=[
            "primary_model_review",
        ],
        satisfied_gates=[
            "scanner_evidence",
            "ai_available",
        ],
    )

    assert (
        task_by_id(
            result,
            "verifier_review",
        ).state
        == "skipped"
    )
    assert (
        task_by_id(
            result,
            "model_consensus",
        ).state
        == "skipped"
    )


def test_missing_ai_gate_keeps_review_waiting() -> None:
    result = SecurityTaskStateResolver().resolve(
        deep_plan(),
        completed_task_ids=[
            "repository_context",
            "deterministic_scan",
        ],
        satisfied_gates=[
            "scanner_evidence",
        ],
    )

    review = task_by_id(
        result,
        "primary_model_review",
    )

    assert review.state == "waiting"
    assert any(
        "ai_available" in reason
        for reason in review.reasons
    )


def test_missing_human_approval_is_hard_block() -> None:
    plan = SecurityTaskPlanner().plan(
        SecurityTaskPlanRequest(
            operation="fix_and_verify",
            has_proposed_patch=True,
            human_approval_confirmed=True,
            include_security_memory=False,
            include_policy_evaluation=False,
        )
    )

    result = SecurityTaskStateResolver().resolve(
        plan,
        completed_task_ids=[
            "repository_context",
        ],
        satisfied_gates=[
            "proposed_patch",
        ],
    )

    fix = task_by_id(
        result,
        "secure_fix",
    )

    assert fix.state == "blocked"
    assert any(
        "human_approval" in reason
        for reason in fix.reasons
    )


def test_full_deep_chain_reaches_consensus() -> None:
    result = SecurityTaskStateResolver().resolve(
        deep_plan(),
        completed_task_ids=[
            "repository_context",
            "deterministic_scan",
            "primary_model_review",
            "verifier_review",
        ],
        satisfied_gates=[
            "scanner_evidence",
            "ai_available",
        ],
    )

    assert (
        task_by_id(
            result,
            "model_consensus",
        ).state
        == "ready"
    )


def test_rejects_unknown_runtime_task_id() -> None:
    with pytest.raises(
        ValueError,
        match="Unknown completed task",
    ):
        SecurityTaskStateResolver().resolve(
            deep_plan(),
            completed_task_ids=[
                "not_a_task",
            ],
        )
