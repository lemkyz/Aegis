from pathlib import PurePosixPath

from aegis.schemas.validation import (
    ValidationAuthorizationRequest,
    ValidationAuthorizationResponse,
    ValidationExecutionPlanResponse,
    ValidationMount,
    ValidationPlanRequest,
    ValidationSandboxPolicy,
)
from aegis.security.authorization import (
    ValidationAuthorizer,
)


class ValidationPlanBuilder:
    planner = "aegis-isolated-validation-plan-v1"

    _runtime_images = {
        "python": "python:3.14-slim",
        "node": "node:24-slim",
    }

    def __init__(
        self,
        *,
        authorizer: ValidationAuthorizer | None = None,
    ) -> None:
        self._authorizer = (
            authorizer
            if authorizer is not None
            else ValidationAuthorizer()
        )

    def build(
        self,
        request: ValidationPlanRequest,
    ) -> ValidationExecutionPlanResponse:
        authorization = self.authorize(
            request.authorization
        )

        reasons = list(authorization.reasons)
        denials = list(authorization.denials)

        entrypoint = self._normalize_entrypoint(
            request.entrypoint,
            denials=denials,
        )

        if (
            request.test_type
            not in authorization
            .normalized_scope
            .allowed_test_types
        ):
            denials.append(
                "The requested test type is outside "
                "the authorized validation scope."
            )

        if (
            authorization
            .normalized_scope
            .target_type
            != "local_repository"
        ):
            denials.append(
                "The initial sandbox planner supports "
                "local repository targets only."
            )

        network = (
            "none"
            if authorization
            .limits
            .network_policy
            == "disabled"
            else "loopback"
        )

        sandbox = ValidationSandboxPolicy(
            read_only_root=True,
            host_path_relabeling=False,
            image_pull_policy="never",
            network=network,
            drop_capabilities=["ALL"],
            no_new_privileges=True,
            user="65532:65532",
            memory_limit_mb=(
                authorization.limits.memory_limit_mb
            ),
            cpu_limit=(
                authorization.limits.cpu_limit
            ),
            timeout_seconds=(
                authorization.limits.timeout_seconds
            ),
            pids_limit=64,
            writable_tmpfs=[
                "/tmp",
            ],
        )

        ready = (
            authorization.authorized
            and authorization.execution_allowed
            and not denials
        )

        image: str | None = None
        command: list[str] = []
        mounts: list[ValidationMount] = []

        if ready:
            image = self._runtime_images[
                request.runtime
            ]
            command = self._command(
                runtime=request.runtime,
                entrypoint=entrypoint,
            )
            mounts = [
                ValidationMount(
                    source=(
                        authorization
                        .normalized_scope
                        .target
                    ),
                    target="/workspace",
                    read_only=True,
                )
            ]
            reasons.append(
                "An isolated execution plan was "
                "generated without running it."
            )
        elif authorization.dry_run:
            reasons.append(
                "Dry-run authorization prevents an "
                "executable sandbox plan."
            )

        return ValidationExecutionPlanResponse(
            planner=self.planner,
            authorization=authorization,
            authorized=authorization.authorized,
            execution_allowed=(
                authorization.execution_allowed
            ),
            ready=ready,
            runtime=request.runtime,
            image=image,
            command=command,
            sandbox=sandbox,
            mounts=mounts,
            reasons=reasons,
            denials=denials,
        )

    def authorize(
        self,
        request: ValidationAuthorizationRequest,
    ) -> ValidationAuthorizationResponse:
        return self._authorizer.authorize(
            request
        )

    @staticmethod
    def _normalize_entrypoint(
        entrypoint: str,
        *,
        denials: list[str],
    ) -> str:
        stripped = entrypoint.strip()

        if (
            "\x00" in stripped
            or "\\" in stripped
        ):
            denials.append(
                "The validation entrypoint contains "
                "invalid path characters."
            )
            return stripped.replace("\x00", "")

        path = PurePosixPath(stripped)

        if path.is_absolute():
            denials.append(
                "The validation entrypoint must be "
                "relative to the repository."
            )

        if ".." in path.parts:
            denials.append(
                "The validation entrypoint cannot "
                "escape the repository."
            )

        if stripped.startswith("-"):
            denials.append(
                "The validation entrypoint cannot begin "
                "with an option prefix."
            )

        return path.as_posix()

    @staticmethod
    def _command(
        *,
        runtime: str,
        entrypoint: str,
    ) -> list[str]:
        workspace_entrypoint = (
            f"/workspace/{entrypoint}"
        )

        if runtime == "python":
            return [
                "python",
                "-I",
                "-c",
                (
                    "import pathlib, runpy, sys; "
                    "script = pathlib.Path(sys.argv[1]); "
                    "sys.path.insert(0, '/workspace'); "
                    "sys.path.insert(0, str(script.parent)); "
                    "runpy.run_path("
                    "str(script), "
                    "run_name='__main__'"
                    ")"
                ),
                workspace_entrypoint,
            ]

        return [
            "node",
            "--disable-proto=throw",
            workspace_entrypoint,
        ]
