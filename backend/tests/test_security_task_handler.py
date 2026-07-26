from __future__ import annotations

import asyncio
from typing import Any, Mapping

import pytest

from aegis.orchestrator.security_task_handler import (
    DuplicateSecurityTaskArtifactError,
    DuplicateSecurityTaskHandlerError,
    MissingSecurityTaskArtifactError,
    SecurityTaskArtifact,
    SecurityTaskArtifactStore,
    SecurityTaskExecutionCancelled,
    SecurityTaskHandlerCapability,
    SecurityTaskHandlerContext,
    SecurityTaskHandlerContractError,
    SecurityTaskHandlerRegistry,
    SecurityTaskHandlerResult,
    UnknownSecurityTaskHandlerError,
)
from aegis.schemas.security_task_plan import (
    SecurityTaskNode,
)


class ContextHandler:
    capability = SecurityTaskHandlerCapability(
        kind="repository_context",
        produced_artifacts=frozenset({
            "repository_context",
        }),
    )

    async def execute(
        self,
        *,
        task: SecurityTaskNode,
        context: SecurityTaskHandlerContext,
        inputs: Mapping[str, Any],
    ) -> SecurityTaskHandlerResult:
        del task
        del inputs

        context.raise_if_cancelled()

        return SecurityTaskHandlerResult(
            output={
                "repository_context": {
                    "language": context.language,
                },
            },
        )


class ScanHandler:
    capability = SecurityTaskHandlerCapability(
        kind="deterministic_scan",
        required_artifacts=frozenset({
            "repository_context",
        }),
        produced_artifacts=frozenset({
            "scanner_evidence",
            "scanner_findings",
        }),
        supports_retry=True,
        max_attempts=2,
    )

    async def execute(
        self,
        *,
        task: SecurityTaskNode,
        context: SecurityTaskHandlerContext,
        inputs: Mapping[str, Any],
    ) -> SecurityTaskHandlerResult:
        del task

        context.raise_if_cancelled()

        return SecurityTaskHandlerResult(
            output={
                "scanner_evidence": [
                    {
                        "source": "test",
                        "language": inputs[
                            "repository_context"
                        ]["language"],
                    }
                ],
                "scanner_findings": [],
            },
        )


def context_task() -> SecurityTaskNode:
    return SecurityTaskNode(
        task_id="repository_context",
        kind="repository_context",
        state="ready",
        produces=[
            "repository_context",
        ],
    )


def scan_task() -> SecurityTaskNode:
    return SecurityTaskNode(
        task_id="deterministic_scan",
        kind="deterministic_scan",
        state="ready",
        produces=[
            "scanner_evidence",
            "scanner_findings",
        ],
    )


def context() -> SecurityTaskHandlerContext:
    return SecurityTaskHandlerContext(
        execution_id="execution:test",
        operation="fast_scan",
        language="python",
        metadata={
            "request_id": "request:test",
        },
    )


def test_registry_registers_and_resolves_handler() -> None:
    registry = SecurityTaskHandlerRegistry()
    handler = ContextHandler()

    registry.register(handler)

    assert registry.resolve(
        "repository_context"
    ) is handler

    assert registry.registered_kinds() == (
        "repository_context",
    )


def test_registry_rejects_duplicate_kind() -> None:
    registry = SecurityTaskHandlerRegistry()

    registry.register(ContextHandler())

    with pytest.raises(
        DuplicateSecurityTaskHandlerError,
        match="already registered",
    ):
        registry.register(ContextHandler())


def test_registry_rejects_unknown_kind() -> None:
    registry = SecurityTaskHandlerRegistry()

    with pytest.raises(
        UnknownSecurityTaskHandlerError,
        match="No handler",
    ):
        registry.resolve(
            "deterministic_scan"
        )


def test_frozen_registry_cannot_change() -> None:
    registry = SecurityTaskHandlerRegistry()
    registry.freeze()

    with pytest.raises(
        SecurityTaskHandlerContractError,
        match="frozen",
    ):
        registry.register(ContextHandler())


def test_capability_rejects_input_overlap() -> None:
    with pytest.raises(
        SecurityTaskHandlerContractError,
        match="both required and optional",
    ):
        SecurityTaskHandlerCapability(
            kind="deterministic_scan",
            required_artifacts=frozenset({
                "repository_context",
            }),
            optional_artifacts=frozenset({
                "repository_context",
            }),
        )


def test_non_retryable_capability_rejects_multiple_attempts() -> None:
    with pytest.raises(
        SecurityTaskHandlerContractError,
        match="max_attempts=1",
    ):
        SecurityTaskHandlerCapability(
            kind="repository_context",
            max_attempts=2,
        )


def test_context_copies_metadata() -> None:
    metadata = {
        "nested": {
            "value": 1,
        },
    }

    handler_context = SecurityTaskHandlerContext(
        execution_id="execution:test",
        operation="fast_scan",
        metadata=metadata,
    )

    metadata["nested"]["value"] = 99

    assert handler_context.metadata[
        "nested"
    ]["value"] == 1


def test_context_detects_cancellation() -> None:
    handler_context = SecurityTaskHandlerContext(
        execution_id="execution:test",
        operation="fast_scan",
        cancellation_requested=lambda: True,
    )

    with pytest.raises(
        SecurityTaskExecutionCancelled,
        match="cancelled",
    ):
        handler_context.raise_if_cancelled()


def test_artifact_store_resolves_required_inputs() -> None:
    store = SecurityTaskArtifactStore()

    store.add(
        SecurityTaskArtifact(
            name="repository_context",
            producer_task_id=(
                "repository_context"
            ),
            value={
                "language": "python",
            },
        )
    )

    inputs = store.resolve_inputs(
        ScanHandler.capability
    )

    assert inputs == {
        "repository_context": {
            "language": "python",
        },
    }


def test_missing_required_artifact_is_rejected() -> None:
    store = SecurityTaskArtifactStore()

    with pytest.raises(
        MissingSecurityTaskArtifactError,
        match="repository_context",
    ):
        store.resolve_inputs(
            ScanHandler.capability
        )


def test_duplicate_artifact_is_rejected() -> None:
    store = SecurityTaskArtifactStore()

    artifact = SecurityTaskArtifact(
        name="repository_context",
        producer_task_id="task:one",
        value={},
    )

    store.add(artifact)

    with pytest.raises(
        DuplicateSecurityTaskArtifactError,
        match="already exists",
    ):
        store.add(
            SecurityTaskArtifact(
                name="repository_context",
                producer_task_id="task:two",
                value={},
            )
        )


def test_records_declared_handler_outputs() -> None:
    store = SecurityTaskArtifactStore()

    artifacts = store.record_handler_result(
        task=context_task(),
        capability=ContextHandler.capability,
        result=SecurityTaskHandlerResult(
            output={
                "repository_context": {
                    "language": "python",
                },
            },
        ),
    )

    assert len(artifacts) == 1
    assert artifacts[0].producer_task_id == (
        "repository_context"
    )
    assert store.value(
        "repository_context"
    ) == {
        "language": "python",
    }


def test_rejects_handler_kind_mismatch() -> None:
    store = SecurityTaskArtifactStore()

    with pytest.raises(
        SecurityTaskHandlerContractError,
        match="does not match",
    ):
        store.record_handler_result(
            task=scan_task(),
            capability=ContextHandler.capability,
            result=SecurityTaskHandlerResult(
                output={
                    "repository_context": {},
                },
            ),
        )


def test_rejects_output_not_declared_by_handler() -> None:
    store = SecurityTaskArtifactStore()

    with pytest.raises(
        SecurityTaskHandlerContractError,
        match="undeclared artifact",
    ):
        store.record_handler_result(
            task=context_task(),
            capability=ContextHandler.capability,
            result=SecurityTaskHandlerResult(
                output={
                    "repository_context": {},
                    "hidden_debug_output": True,
                },
            ),
        )


def test_rejects_output_not_declared_by_plan() -> None:
    store = SecurityTaskArtifactStore()

    task = SecurityTaskNode(
        task_id="repository_context",
        kind="repository_context",
        state="ready",
        produces=[],
    )

    with pytest.raises(
        SecurityTaskHandlerContractError,
        match="not declared by the task plan",
    ):
        store.record_handler_result(
            task=task,
            capability=ContextHandler.capability,
            result=SecurityTaskHandlerResult(
                output={
                    "repository_context": {},
                },
            ),
        )


def test_rejects_missing_declared_handler_output() -> None:
    store = SecurityTaskArtifactStore()

    with pytest.raises(
        SecurityTaskHandlerContractError,
        match="did not return declared",
    ):
        store.record_handler_result(
            task=scan_task(),
            capability=ScanHandler.capability,
            result=SecurityTaskHandlerResult(
                output={
                    "scanner_evidence": [],
                },
            ),
        )


def test_result_and_store_copy_mutable_values() -> None:
    original = {
        "items": [
            "before",
        ],
    }

    result = SecurityTaskHandlerResult(
        output={
            "repository_context": original,
        },
    )

    original["items"].append("after")

    store = SecurityTaskArtifactStore()

    store.record_handler_result(
        task=context_task(),
        capability=ContextHandler.capability,
        result=result,
    )

    retrieved = store.value(
        "repository_context"
    )
    retrieved["items"].append(
        "external-mutation"
    )

    assert store.value(
        "repository_context"
    ) == {
        "items": [
            "before",
        ],
    }


def test_handler_contract_runs_with_resolved_inputs() -> None:
    async def scenario() -> None:
        context_handler = ContextHandler()
        scan_handler = ScanHandler()
        store = SecurityTaskArtifactStore()

        context_result = (
            await context_handler.execute(
                task=context_task(),
                context=context(),
                inputs={},
            )
        )

        store.record_handler_result(
            task=context_task(),
            capability=(
                context_handler.capability
            ),
            result=context_result,
        )

        inputs = store.resolve_inputs(
            scan_handler.capability
        )

        scan_result = (
            await scan_handler.execute(
                task=scan_task(),
                context=context(),
                inputs=inputs,
            )
        )

        store.record_handler_result(
            task=scan_task(),
            capability=(
                scan_handler.capability
            ),
            result=scan_result,
        )

        assert store.value(
            "scanner_evidence"
        )[0]["language"] == "python"

        assert store.value(
            "scanner_findings"
        ) == []

    asyncio.run(scenario())
