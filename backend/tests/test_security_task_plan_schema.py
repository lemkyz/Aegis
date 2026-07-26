import pytest
from pydantic import ValidationError

from aegis.schemas.security_task_plan import (
    SecurityTaskDependency,
    SecurityTaskNode,
    SecurityTaskPlanResponse,
)


def task(
    task_id: str,
    *,
    dependencies: list[
        SecurityTaskDependency
    ] | None = None,
) -> SecurityTaskNode:
    return SecurityTaskNode(
        task_id=task_id,
        kind="deterministic_scan",
        state="planned",
        dependencies=dependencies or [],
    )


def test_accepts_valid_dependency_graph() -> None:
    response = SecurityTaskPlanResponse(
        planner="aegis-security-task-planner-v1",
        operation="deep_analysis",
        status="ready",
        tasks=[
            task("context"),
            task(
                "scan",
                dependencies=[
                    SecurityTaskDependency(
                        task_id="context",
                    )
                ],
            ),
        ],
        entry_task_ids=["context"],
        terminal_task_ids=["scan"],
    )

    assert len(response.tasks) == 2
    assert (
        response.tasks[1]
        .dependencies[0]
        .task_id
        == "context"
    )


def test_rejects_duplicate_task_ids() -> None:
    with pytest.raises(
        ValidationError,
        match="must be unique",
    ):
        SecurityTaskPlanResponse(
            planner="planner",
            operation="deep_analysis",
            status="invalid",
            tasks=[
                task("scan"),
                task("scan"),
            ],
        )


def test_rejects_unknown_dependency() -> None:
    with pytest.raises(
        ValidationError,
        match="unknown task ID",
    ):
        SecurityTaskPlanResponse(
            planner="planner",
            operation="deep_analysis",
            status="invalid",
            tasks=[
                task(
                    "scan",
                    dependencies=[
                        SecurityTaskDependency(
                            task_id="missing",
                        )
                    ],
                )
            ],
        )


def test_rejects_self_dependency() -> None:
    with pytest.raises(
        ValidationError,
        match="cannot depend on itself",
    ):
        SecurityTaskPlanResponse(
            planner="planner",
            operation="deep_analysis",
            status="invalid",
            tasks=[
                task(
                    "scan",
                    dependencies=[
                        SecurityTaskDependency(
                            task_id="scan",
                        )
                    ],
                )
            ],
        )


def test_rejects_unknown_boundary_task() -> None:
    with pytest.raises(
        ValidationError,
        match="boundary references unknown",
    ):
        SecurityTaskPlanResponse(
            planner="planner",
            operation="deep_analysis",
            status="invalid",
            tasks=[task("scan")],
            entry_task_ids=["missing"],
        )



def test_calculates_topological_execution_order() -> None:
    response = SecurityTaskPlanResponse(
        planner="planner",
        operation="deep_analysis",
        status="ready",
        tasks=[
            task("context"),
            task(
                "scan",
                dependencies=[
                    SecurityTaskDependency(
                        task_id="context",
                    )
                ],
            ),
            task(
                "review",
                dependencies=[
                    SecurityTaskDependency(
                        task_id="scan",
                    )
                ],
            ),
        ],
        entry_task_ids=["context"],
        terminal_task_ids=["review"],
    )

    assert response.execution_order == [
        "context",
        "scan",
        "review",
    ]


def test_preserves_parallel_task_input_order() -> None:
    response = SecurityTaskPlanResponse(
        planner="planner",
        operation="repository_review",
        status="ready",
        tasks=[
            task("context"),
            task(
                "secrets",
                dependencies=[
                    SecurityTaskDependency(
                        task_id="context",
                    )
                ],
            ),
            task(
                "dependencies",
                dependencies=[
                    SecurityTaskDependency(
                        task_id="context",
                    )
                ],
            ),
            task(
                "attack_surface",
                dependencies=[
                    SecurityTaskDependency(
                        task_id="context",
                    )
                ],
            ),
        ],
    )

    assert response.execution_order == [
        "context",
        "secrets",
        "dependencies",
        "attack_surface",
    ]


def test_rejects_dependency_cycle() -> None:
    with pytest.raises(
        ValidationError,
        match="dependency cycle",
    ):
        SecurityTaskPlanResponse(
            planner="planner",
            operation="deep_analysis",
            status="invalid",
            tasks=[
                task(
                    "task_a",
                    dependencies=[
                        SecurityTaskDependency(
                            task_id="task_c",
                        )
                    ],
                ),
                task(
                    "task_b",
                    dependencies=[
                        SecurityTaskDependency(
                            task_id="task_a",
                        )
                    ],
                ),
                task(
                    "task_c",
                    dependencies=[
                        SecurityTaskDependency(
                            task_id="task_b",
                        )
                    ],
                ),
            ],
        )


def test_rejects_incomplete_execution_order() -> None:
    with pytest.raises(
        ValidationError,
        match="must contain every",
    ):
        SecurityTaskPlanResponse(
            planner="planner",
            operation="deep_analysis",
            status="invalid",
            tasks=[
                task("context"),
                task(
                    "scan",
                    dependencies=[
                        SecurityTaskDependency(
                            task_id="context",
                        )
                    ],
                ),
            ],
            execution_order=["context"],
        )


def test_rejects_execution_order_before_dependency() -> None:
    with pytest.raises(
        ValidationError,
        match="before one of its dependencies",
    ):
        SecurityTaskPlanResponse(
            planner="planner",
            operation="deep_analysis",
            status="invalid",
            tasks=[
                task("context"),
                task(
                    "scan",
                    dependencies=[
                        SecurityTaskDependency(
                            task_id="context",
                        )
                    ],
                ),
            ],
            execution_order=[
                "scan",
                "context",
            ],
        )
