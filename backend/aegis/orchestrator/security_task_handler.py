from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import (
    Any,
    Awaitable,
    Callable,
    Mapping,
    Protocol,
    runtime_checkable,
)

from aegis.schemas.security_task_plan import (
    SecurityTaskKind,
    SecurityTaskNode,
)


class SecurityTaskHandlerError(RuntimeError):
    """Base error for handler and artifact contracts."""


class DuplicateSecurityTaskHandlerError(
    SecurityTaskHandlerError
):
    pass


class UnknownSecurityTaskHandlerError(
    SecurityTaskHandlerError
):
    pass


class SecurityTaskHandlerContractError(
    SecurityTaskHandlerError
):
    pass


class MissingSecurityTaskArtifactError(
    SecurityTaskHandlerError
):
    pass


class DuplicateSecurityTaskArtifactError(
    SecurityTaskHandlerError
):
    pass


class SecurityTaskExecutionCancelled(
    SecurityTaskHandlerError
):
    pass


@dataclass(frozen=True, slots=True)
class SecurityTaskHandlerCapability:
    """
    Immutable declaration of what one task handler
    consumes, produces, and whether retry is safe.
    """

    kind: SecurityTaskKind

    required_artifacts: frozenset[str] = field(
        default_factory=frozenset,
    )
    optional_artifacts: frozenset[str] = field(
        default_factory=frozenset,
    )
    produced_artifacts: frozenset[str] = field(
        default_factory=frozenset,
    )

    supports_retry: bool = False
    max_attempts: int = 1
    side_effect_free: bool = True

    def __post_init__(self) -> None:
        all_inputs = (
            self.required_artifacts
            | self.optional_artifacts
        )

        overlap = (
            self.required_artifacts
            & self.optional_artifacts
        )

        if overlap:
            raise SecurityTaskHandlerContractError(
                "Handler artifacts cannot be both "
                "required and optional: "
                + ", ".join(sorted(overlap))
                + "."
            )

        invalid_names = {
            name
            for name in (
                all_inputs
                | self.produced_artifacts
            )
            if not name.strip()
        }

        if invalid_names:
            raise SecurityTaskHandlerContractError(
                "Handler artifact names must not be "
                "empty."
            )

        if self.max_attempts < 1:
            raise SecurityTaskHandlerContractError(
                "Handler max_attempts must be at "
                "least one."
            )

        if (
            not self.supports_retry
            and self.max_attempts != 1
        ):
            raise SecurityTaskHandlerContractError(
                "A non-retryable handler must use "
                "max_attempts=1."
            )


@dataclass(frozen=True, slots=True)
class SecurityTaskHandlerContext:
    """
    Read-only execution metadata supplied to handlers.

    Mutable caller-owned values are copied before being
    exposed to a handler.
    """

    execution_id: str
    operation: str
    language: str = "python"
    repository_root: str | None = None
    metadata: Mapping[str, Any] = field(
        default_factory=dict,
    )
    cancellation_requested: Callable[
        [],
        bool,
    ] = field(
        default=lambda: False,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        if not self.execution_id.strip():
            raise SecurityTaskHandlerContractError(
                "Handler context requires an "
                "execution ID."
            )

        if not self.operation.strip():
            raise SecurityTaskHandlerContractError(
                "Handler context requires an "
                "operation."
            )

        copied_metadata = deepcopy(
            dict(self.metadata)
        )

        object.__setattr__(
            self,
            "metadata",
            MappingProxyType(
                copied_metadata
            ),
        )

    def raise_if_cancelled(self) -> None:
        if self.cancellation_requested():
            raise SecurityTaskExecutionCancelled(
                "Security task execution was "
                "cancelled before handler invocation."
            )


@dataclass(frozen=True, slots=True)
class SecurityTaskHandlerResult:
    """
    Uncommitted result returned by a task handler.

    The executor will later pass this output through
    the execution state machine.
    """

    output: Mapping[str, Any] = field(
        default_factory=dict,
    )
    reasons: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(
        default_factory=dict,
    )

    def __post_init__(self) -> None:
        copied_output = deepcopy(
            dict(self.output)
        )
        copied_metadata = deepcopy(
            dict(self.metadata)
        )

        object.__setattr__(
            self,
            "output",
            MappingProxyType(
                copied_output
            ),
        )
        object.__setattr__(
            self,
            "metadata",
            MappingProxyType(
                copied_metadata
            ),
        )
        object.__setattr__(
            self,
            "reasons",
            tuple(self.reasons),
        )


@runtime_checkable
class SecurityTaskHandler(Protocol):
    capability: SecurityTaskHandlerCapability

    def execute(
        self,
        *,
        task: SecurityTaskNode,
        context: SecurityTaskHandlerContext,
        inputs: Mapping[str, Any],
    ) -> Awaitable[SecurityTaskHandlerResult]:
        ...


class SecurityTaskHandlerRegistry:
    """
    Duplicate-safe mapping from task kind to handler.

    A frozen registry cannot be changed after executor
    startup.
    """

    def __init__(self) -> None:
        self._handlers: dict[
            SecurityTaskKind,
            SecurityTaskHandler,
        ] = {}
        self._frozen = False

    @property
    def frozen(self) -> bool:
        return self._frozen

    def register(
        self,
        handler: SecurityTaskHandler,
    ) -> None:
        if self._frozen:
            raise SecurityTaskHandlerContractError(
                "The security task handler registry "
                "is frozen."
            )

        if not isinstance(
            handler,
            SecurityTaskHandler,
        ):
            raise SecurityTaskHandlerContractError(
                "Registered object does not satisfy "
                "the SecurityTaskHandler protocol."
            )

        kind = handler.capability.kind

        if kind in self._handlers:
            raise DuplicateSecurityTaskHandlerError(
                "A handler is already registered for "
                f"security task kind {kind!r}."
            )

        self._handlers[kind] = handler

    def resolve(
        self,
        kind: SecurityTaskKind,
    ) -> SecurityTaskHandler:
        try:
            return self._handlers[kind]
        except KeyError as exc:
            raise UnknownSecurityTaskHandlerError(
                "No handler is registered for "
                f"security task kind {kind!r}."
            ) from exc

    def freeze(self) -> None:
        self._frozen = True

    def registered_kinds(
        self,
    ) -> tuple[SecurityTaskKind, ...]:
        return tuple(
            sorted(self._handlers)
        )

    def __len__(self) -> int:
        return len(self._handlers)


@dataclass(frozen=True, slots=True)
class SecurityTaskArtifact:
    name: str
    producer_task_id: str
    value: Any

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise SecurityTaskHandlerContractError(
                "Artifact name must not be empty."
            )

        if not self.producer_task_id.strip():
            raise SecurityTaskHandlerContractError(
                "Artifact producer task ID must not "
                "be empty."
            )

        object.__setattr__(
            self,
            "value",
            deepcopy(self.value),
        )


class SecurityTaskArtifactStore:
    """
    Execution-local artifact store with provenance.

    Artifacts are append-only. A second producer cannot
    silently replace an existing artifact.
    """

    def __init__(
        self,
        artifacts: Mapping[
            str,
            SecurityTaskArtifact,
        ] | None = None,
    ) -> None:
        self._artifacts: dict[
            str,
            SecurityTaskArtifact,
        ] = {}

        for artifact in (
            artifacts or {}
        ).values():
            self.add(artifact)

    def add(
        self,
        artifact: SecurityTaskArtifact,
    ) -> None:
        if artifact.name in self._artifacts:
            previous = self._artifacts[
                artifact.name
            ]

            raise DuplicateSecurityTaskArtifactError(
                "Artifact "
                f"{artifact.name!r} already exists "
                "and was produced by task "
                f"{previous.producer_task_id!r}."
            )

        self._artifacts[
            artifact.name
        ] = SecurityTaskArtifact(
            name=artifact.name,
            producer_task_id=(
                artifact.producer_task_id
            ),
            value=artifact.value,
        )

    def contains(
        self,
        name: str,
    ) -> bool:
        return name in self._artifacts

    def artifact(
        self,
        name: str,
    ) -> SecurityTaskArtifact:
        try:
            artifact = self._artifacts[name]
        except KeyError as exc:
            raise MissingSecurityTaskArtifactError(
                f"Required artifact {name!r} "
                "is unavailable."
            ) from exc

        return SecurityTaskArtifact(
            name=artifact.name,
            producer_task_id=(
                artifact.producer_task_id
            ),
            value=artifact.value,
        )

    def value(
        self,
        name: str,
    ) -> Any:
        return deepcopy(
            self.artifact(name).value
        )

    def resolve_inputs(
        self,
        capability: SecurityTaskHandlerCapability,
    ) -> Mapping[str, Any]:
        missing = sorted(
            name
            for name
            in capability.required_artifacts
            if name not in self._artifacts
        )

        if missing:
            raise MissingSecurityTaskArtifactError(
                "Handler for task kind "
                f"{capability.kind!r} is missing "
                "required artifact(s): "
                + ", ".join(missing)
                + "."
            )

        requested = (
            capability.required_artifacts
            | capability.optional_artifacts
        )

        inputs = {
            name: deepcopy(
                self._artifacts[name].value
            )
            for name in sorted(requested)
            if name in self._artifacts
        }

        return MappingProxyType(inputs)

    def record_handler_result(
        self,
        *,
        task: SecurityTaskNode,
        capability: SecurityTaskHandlerCapability,
        result: SecurityTaskHandlerResult,
    ) -> tuple[SecurityTaskArtifact, ...]:
        if capability.kind != task.kind:
            raise SecurityTaskHandlerContractError(
                "Handler kind "
                f"{capability.kind!r} does not match "
                f"task kind {task.kind!r}."
            )

        output_names = set(
            result.output
        )
        handler_declared = set(
            capability.produced_artifacts
        )
        task_declared = set(
            task.produces
        )

        undeclared_by_handler = (
            output_names
            - handler_declared
        )

        if undeclared_by_handler:
            raise SecurityTaskHandlerContractError(
                "Handler returned undeclared "
                "artifact(s): "
                + ", ".join(
                    sorted(
                        undeclared_by_handler
                    )
                )
                + "."
            )

        undeclared_by_task = (
            output_names
            - task_declared
        )

        if undeclared_by_task:
            raise SecurityTaskHandlerContractError(
                "Handler returned artifact(s) not "
                "declared by the task plan: "
                + ", ".join(
                    sorted(
                        undeclared_by_task
                    )
                )
                + "."
            )

        missing_declared_outputs = (
            handler_declared
            - output_names
        )

        if missing_declared_outputs:
            raise SecurityTaskHandlerContractError(
                "Handler did not return declared "
                "artifact(s): "
                + ", ".join(
                    sorted(
                        missing_declared_outputs
                    )
                )
                + "."
            )

        pending = tuple(
            SecurityTaskArtifact(
                name=name,
                producer_task_id=task.task_id,
                value=result.output[name],
            )
            for name in sorted(output_names)
        )

        duplicates = [
            artifact.name
            for artifact in pending
            if self.contains(artifact.name)
        ]

        if duplicates:
            raise DuplicateSecurityTaskArtifactError(
                "Handler result would overwrite "
                "existing artifact(s): "
                + ", ".join(
                    sorted(duplicates)
                )
                + "."
            )

        for artifact in pending:
            self.add(artifact)

        return pending

    def snapshot(
        self,
    ) -> Mapping[str, SecurityTaskArtifact]:
        return MappingProxyType({
            name: SecurityTaskArtifact(
                name=artifact.name,
                producer_task_id=(
                    artifact.producer_task_id
                ),
                value=artifact.value,
            )
            for name, artifact
            in sorted(
                self._artifacts.items()
            )
        })

    def __len__(self) -> int:
        return len(self._artifacts)
