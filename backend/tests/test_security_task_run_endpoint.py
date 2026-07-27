import os
from pathlib import Path

from fastapi.testclient import TestClient


os.environ.setdefault(
    "AEGIS_FINGERPRINT_KEY",
    "test-only-fingerprint-key-32-characters",
)
os.environ.setdefault(
    "NVIDIA_API_KEY",
    "test-only-provider-key",
)


import aegis.main as main_module
from aegis.orchestrator.security_task_aggregator import (
    SecurityTaskResultAggregator,
)
from aegis.orchestrator.security_task_execution import (
    SecurityTaskExecutionMachine,
)
from aegis.orchestrator.security_task_planner import (
    SecurityTaskPlanner,
)
from aegis.schemas.analysis import (
    AnalyzeCodeResponse,
)
from aegis.schemas.security_task_plan import (
    SecurityTaskPlanRequest,
)
from aegis.schemas.security_task_run import (
    SecurityTaskRunIntegrity,
    SecurityTaskRunResponse,
)


client = TestClient(main_module.app)


class FakeProductionRunner:
    def __init__(self) -> None:
        self.requests = []

    async def run(
        self,
        request,
        *,
        cancellation_requested=None,
    ) -> SecurityTaskRunResponse:
        assert cancellation_requested is not None
        self.requests.append(request)
        plan = SecurityTaskPlanner().plan(
            SecurityTaskPlanRequest(
                operation="deep_analysis",
                has_scanner_evidence=False,
                include_security_memory=False,
                include_policy_evaluation=False,
            )
        )
        execution = (
            SecurityTaskExecutionMachine()
            .create(plan)
        )
        aggregation = (
            SecurityTaskResultAggregator()
            .aggregate(execution)
        )

        return SecurityTaskRunResponse(
            runner="fake-production-runner",
            workflow_status="stopped",
            execution=execution,
            aggregation=aggregation,
            analysis=AnalyzeCodeResponse(
                filename=request.filename,
                language=request.language,
                model="not-used",
                scanner="fake-scanner",
                analysis_status="skipped",
                result_source="scanner",
                findings=[],
                claims=[],
            ),
            integrity=SecurityTaskRunIntegrity(
                source_sha256="0" * 64,
                repository_revision=(
                    "working-tree:test"
                ),
                plan_sha256="1" * 64,
                audit_sha256="2" * 64,
                artifact_manifest_sha256=(
                    "3" * 64
                ),
                verified=True,
            ),
        )


class FailingProductionRunner:
    async def run(
        self,
        request,
        *,
        cancellation_requested=None,
    ) -> SecurityTaskRunResponse:
        del request
        del cancellation_requested
        raise RuntimeError(
            "sensitive-provider-detail"
        )


def payload(
    root: Path,
) -> dict[str, object]:
    return {
        "repository_path": str(root),
        "code": "print('safe')\n",
        "filename": "app.py",
        "language": "PYTHON",
        "include_security_memory": False,
        "include_policy_evaluation": False,
    }


def test_run_endpoint_invokes_production_runner(
    tmp_path: Path,
    monkeypatch,
) -> None:
    fake = FakeProductionRunner()
    monkeypatch.setattr(
        main_module,
        "security_task_production_runner",
        fake,
    )

    response = client.post(
        "/v1/security/tasks/run",
        json=payload(tmp_path),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["runner"] == (
        "fake-production-runner"
    )
    assert body["workflow_status"] == (
        "stopped"
    )
    assert body["analysis"]["language"] == (
        "python"
    )
    assert len(fake.requests) == 1


def test_run_endpoint_rejects_path_traversal(
    tmp_path: Path,
) -> None:
    request = payload(tmp_path)
    request["filename"] = "../outside.py"

    response = client.post(
        "/v1/security/tasks/run",
        json=request,
    )

    assert response.status_code == 422


def test_run_endpoint_redacts_unexpected_errors(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        main_module,
        "security_task_production_runner",
        FailingProductionRunner(),
    )

    response = client.post(
        "/v1/security/tasks/run",
        json=payload(tmp_path),
    )

    assert response.status_code == 502
    assert response.json()["detail"] == (
        "Production security workflow "
        "failed safely."
    )
    assert (
        "sensitive-provider-detail"
        not in response.text
    )
