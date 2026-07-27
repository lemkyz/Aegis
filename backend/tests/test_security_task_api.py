import os

from fastapi.testclient import TestClient


os.environ.setdefault(
    "AEGIS_FINGERPRINT_KEY",
    "test-only-fingerprint-key-32-characters",
)


from aegis.main import app


client = TestClient(app)


def plan_payload(
    **overrides: object,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "operation": "fast_scan",
        "language": "python",
        "include_security_memory": False,
        "include_policy_evaluation": False,
    }
    payload.update(overrides)
    return payload


def create_plan(
    **overrides: object,
) -> dict[str, object]:
    response = client.post(
        "/v1/security/tasks/plan",
        json=plan_payload(**overrides),
    )

    assert response.status_code == 200
    return response.json()


def create_execution(
    plan: dict[str, object],
    *,
    gates: list[str] | None = None,
) -> dict[str, object]:
    response = client.post(
        "/v1/security/tasks/execution/create",
        json={
            "plan": plan,
            "satisfied_gates": gates or [],
        },
    )

    assert response.status_code == 200
    return response.json()


def start_task(
    execution: dict[str, object],
    task_id: str,
    *,
    gates: list[str] | None = None,
):
    return client.post(
        "/v1/security/tasks/execution/start",
        json={
            "execution": execution,
            "task_id": task_id,
            "satisfied_gates": gates or [],
        },
    )


def complete_task(
    execution: dict[str, object],
    task_id: str,
    *,
    output: dict[str, object] | None = None,
    gates: list[str] | None = None,
):
    return client.post(
        "/v1/security/tasks/execution/complete",
        json={
            "execution": execution,
            "task_id": task_id,
            "output": output or {},
            "satisfied_gates": gates or [],
        },
    )


def test_plan_endpoint_returns_execution_graph() -> None:
    response = client.post(
        "/v1/security/tasks/plan",
        json=plan_payload(),
    )

    assert response.status_code == 200

    body = response.json()

    assert body["planner"] == (
        "aegis-security-task-planner-v1"
    )
    assert body["operation"] == "fast_scan"
    assert body["status"] == "ready"
    assert body["entry_task_ids"] == [
        "repository_context"
    ]
    assert body["terminal_task_ids"] == [
        "deterministic_scan"
    ]
    assert body["execution_order"] == [
        "repository_context",
        "deterministic_scan",
    ]


def test_high_risk_plan_includes_threat_model() -> None:
    response = client.post(
        "/v1/security/tasks/plan",
        json=plan_payload(
            operation="deep_analysis",
            has_scanner_evidence=True,
            highest_severity="critical",
            finding_confidence=0.95,
            has_proven_data_flow=True,
            independently_verified=True,
        ),
    )

    assert response.status_code == 200

    body = response.json()

    assert "threat_model" in body[
        "execution_order"
    ]
    assert "dynamic_validation" not in body[
        "execution_order"
    ]
    assert any(
        "explicit authorization" in reason
        for reason in body["reasons"]
    )


def test_resolve_endpoint_unlocks_scanner() -> None:
    plan = create_plan()

    response = client.post(
        "/v1/security/tasks/resolve",
        json={
            "plan": plan,
            "completed_task_ids": [
                "repository_context",
            ],
        },
    )

    assert response.status_code == 200

    tasks = {
        task["task_id"]: task
        for task in response.json()["tasks"]
    }

    assert tasks[
        "repository_context"
    ]["state"] == "completed"

    assert tasks[
        "deterministic_scan"
    ]["state"] == "ready"


def test_resolve_rejects_unknown_task_id() -> None:
    plan = create_plan()

    response = client.post(
        "/v1/security/tasks/resolve",
        json={
            "plan": plan,
            "completed_task_ids": [
                "missing_task",
            ],
        },
    )

    assert response.status_code == 409
    assert "Unknown completed task" in (
        response.json()["detail"]
    )


def test_execution_create_initializes_audit() -> None:
    plan = create_plan()
    execution = create_execution(plan)

    assert execution["status"] == "created"
    assert execution["execution_id"].startswith(
        "execution:"
    )
    assert len(execution["runtime"]) == 2
    assert execution["events"][0][
        "event_type"
    ] == "execution_created"


def test_execution_rejects_waiting_task_start() -> None:
    plan = create_plan()
    execution = create_execution(plan)

    response = start_task(
        execution,
        "deterministic_scan",
    )

    assert response.status_code == 409
    assert "cannot start" in (
        response.json()["detail"]
    )


def test_full_fast_execution_and_aggregation() -> None:
    plan = create_plan()
    execution = create_execution(plan)

    response = start_task(
        execution,
        "repository_context",
    )
    assert response.status_code == 200
    execution = response.json()

    response = complete_task(
        execution,
        "repository_context",
        output={
            "repository_context": {
                "language": "python",
                "file_count": 1,
            }
        },
    )
    assert response.status_code == 200
    execution = response.json()

    tasks = {
        task["task_id"]: task
        for task in execution["plan"]["tasks"]
    }

    assert tasks[
        "deterministic_scan"
    ]["state"] == "ready"

    response = start_task(
        execution,
        "deterministic_scan",
    )
    assert response.status_code == 200
    execution = response.json()

    response = complete_task(
        execution,
        "deterministic_scan",
        output={
            "scanner_evidence": [
                {
                    "tool": "bandit",
                    "rule_id": "B602",
                }
            ],
            "scanner_findings": [
                {
                    "title": "shell=True",
                    "severity": "high",
                }
            ],
        },
    )
    assert response.status_code == 200
    execution = response.json()

    assert execution["status"] == "completed"

    response = client.post(
        "/v1/security/tasks/aggregate",
        json={
            "execution": execution,
        },
    )

    assert response.status_code == 200

    aggregation = response.json()

    assert aggregation["status"] == "completed"
    assert aggregation[
        "completed_terminal_task_ids"
    ] == [
        "deterministic_scan"
    ]
    assert [
        artifact["name"]
        for artifact in aggregation["artifacts"]
    ] == [
        "repository_context",
        "scanner_evidence",
        "scanner_findings",
    ]


def test_failure_endpoint_blocks_dependents() -> None:
    gates = [
        "scanner_evidence",
        "ai_available",
    ]

    plan = create_plan(
        operation="deep_analysis",
        has_scanner_evidence=True,
    )
    execution = create_execution(
        plan,
        gates=gates,
    )

    response = start_task(
        execution,
        "repository_context",
        gates=gates,
    )
    assert response.status_code == 200
    execution = response.json()

    response = complete_task(
        execution,
        "repository_context",
        gates=gates,
    )
    assert response.status_code == 200
    execution = response.json()

    response = start_task(
        execution,
        "deterministic_scan",
        gates=gates,
    )
    assert response.status_code == 200
    execution = response.json()

    response = client.post(
        "/v1/security/tasks/execution/fail",
        json={
            "execution": execution,
            "task_id": "deterministic_scan",
            "error": "Scanner crashed.",
            "satisfied_gates": gates,
        },
    )

    assert response.status_code == 200

    tasks = {
        task["task_id"]: task
        for task in response.json()[
            "plan"
        ]["tasks"]
    }

    assert tasks[
        "deterministic_scan"
    ]["state"] == "failed"

    assert tasks[
        "primary_model_review"
    ]["state"] == "blocked"


def test_skip_endpoint_propagates_skip() -> None:
    gates = [
        "scanner_evidence",
        "ai_available",
    ]

    plan = create_plan(
        operation="deep_analysis",
        has_scanner_evidence=True,
        include_security_memory=False,
        include_policy_evaluation=False,
    )
    execution = create_execution(
        plan,
        gates=gates,
    )

    for task_id in (
        "repository_context",
        "deterministic_scan",
    ):
        response = start_task(
            execution,
            task_id,
            gates=gates,
        )
        assert response.status_code == 200
        execution = response.json()

        response = complete_task(
            execution,
            task_id,
            gates=gates,
        )
        assert response.status_code == 200
        execution = response.json()

    response = client.post(
        "/v1/security/tasks/execution/skip",
        json={
            "execution": execution,
            "task_id": "primary_model_review",
            "reason": "No safe model route.",
            "satisfied_gates": gates,
        },
    )

    assert response.status_code == 200

    tasks = {
        task["task_id"]: task
        for task in response.json()[
            "plan"
        ]["tasks"]
    }

    assert tasks[
        "primary_model_review"
    ]["state"] == "skipped"

    assert tasks[
        "verifier_review"
    ]["state"] == "skipped"

    assert tasks[
        "model_consensus"
    ]["state"] == "skipped"


def test_invalid_operation_is_rejected_by_schema() -> None:
    response = client.post(
        "/v1/security/tasks/plan",
        json={
            "operation": "attack_everything",
        },
    )

    assert response.status_code == 422


def test_task_api_routes_are_registered() -> None:
    routes = {
        route.path
        for route in app.routes
    }

    expected = {
        "/v1/security/tasks/plan",
        "/v1/security/tasks/resolve",
        "/v1/security/tasks/execution/create",
        "/v1/security/tasks/execution/start",
        "/v1/security/tasks/execution/complete",
        "/v1/security/tasks/execution/fail",
        "/v1/security/tasks/execution/skip",
        "/v1/security/tasks/aggregate",
        "/v1/security/tasks/run",
    }

    assert expected <= routes
