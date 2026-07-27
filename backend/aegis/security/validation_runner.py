import asyncio
import shutil
import time

from aegis.schemas.validation import (
    ValidationExecutionRequest,
    ValidationExecutionResult,
    ValidationExecutionPlanResponse,
)
from aegis.security.validation_plan import (
    ValidationPlanBuilder,
)


class ValidationRunner:
    runner = "aegis-safe-container-runner-v1"

    _runtime_candidates = (
        "podman",
        "docker",
    )

    _output_limit_bytes = 64 * 1024

    def __init__(
        self,
        *,
        planner: ValidationPlanBuilder | None = None,
    ) -> None:
        self._planner = (
            planner
            if planner is not None
            else ValidationPlanBuilder()
        )

    async def run(
        self,
        request: ValidationExecutionRequest,
    ) -> ValidationExecutionResult:
        plan = self._planner.build(
            request.plan
        )

        if not plan.ready:
            return ValidationExecutionResult(
                runner=self.runner,
                status="rejected",
                started=False,
                timed_out=False,
                duration_ms=0,
                reasons=list(plan.reasons),
                denials=list(plan.denials),
            )

        runtime_executable = (
            self._find_runtime_executable()
        )

        if runtime_executable is None:
            return ValidationExecutionResult(
                runner=self.runner,
                status="runtime_unavailable",
                started=False,
                timed_out=False,
                duration_ms=0,
                reasons=list(plan.reasons),
                denials=[
                    *plan.denials,
                    (
                        "Neither Podman nor Docker is "
                        "available on this system."
                    ),
                ],
            )

        argv = self._build_runtime_argv(
            runtime_executable=runtime_executable,
            plan=plan,
        )

        started_at = time.monotonic()

        try:
            process = (
                await asyncio.create_subprocess_exec(
                    *argv,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            )
        except FileNotFoundError:
            return ValidationExecutionResult(
                runner=self.runner,
                status="runtime_unavailable",
                runtime_executable=(
                    runtime_executable
                ),
                started=False,
                timed_out=False,
                duration_ms=self._duration_ms(
                    started_at
                ),
                argv=argv,
                reasons=list(plan.reasons),
                denials=[
                    *plan.denials,
                    (
                        "The selected container runtime "
                        "could not be started."
                    ),
                ],
            )

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=(
                    plan.sandbox.timeout_seconds
                ),
            )
        except TimeoutError:
            process.kill()
            stdout, stderr = (
                await process.communicate()
            )

            return ValidationExecutionResult(
                runner=self.runner,
                status="timed_out",
                runtime_executable=(
                    runtime_executable
                ),
                started=True,
                timed_out=True,
                exit_code=process.returncode,
                duration_ms=self._duration_ms(
                    started_at
                ),
                stdout=self._decode_output(stdout),
                stderr=self._decode_output(stderr),
                argv=argv,
                reasons=list(plan.reasons),
                denials=[
                    *plan.denials,
                    (
                        "Sandbox execution exceeded the "
                        "authorized timeout."
                    ),
                ],
            )

        status = (
            "completed"
            if process.returncode == 0
            else "failed"
        )

        return ValidationExecutionResult(
            runner=self.runner,
            status=status,
            runtime_executable=runtime_executable,
            started=True,
            timed_out=False,
            exit_code=process.returncode,
            duration_ms=self._duration_ms(
                started_at
            ),
            stdout=self._decode_output(stdout),
            stderr=self._decode_output(stderr),
            argv=argv,
            reasons=list(plan.reasons),
            denials=list(plan.denials),
        )

    @classmethod
    def _find_runtime_executable(
        cls,
    ) -> str | None:
        for candidate in cls._runtime_candidates:
            executable = shutil.which(candidate)

            if executable is not None:
                return executable

        return None

    @staticmethod
    def _build_runtime_argv(
        *,
        runtime_executable: str,
        plan: ValidationExecutionPlanResponse,
    ) -> list[str]:
        if (
            not plan.ready
            or plan.image is None
            or not plan.command
            or len(plan.mounts) != 1
        ):
            raise ValueError(
                "A ready isolated execution plan is required."
            )

        mount = plan.mounts[0]

        argv = [
            runtime_executable,
            "run",
            "--rm",
            "--pull",
            plan.sandbox.image_pull_policy,
            "--read-only",
            "--network",
            plan.sandbox.network,
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--security-opt",
            "label=disable",
            "--user",
            plan.sandbox.user,
            "--memory",
            f"{plan.sandbox.memory_limit_mb}m",
            "--cpus",
            str(plan.sandbox.cpu_limit),
            "--pids-limit",
            str(plan.sandbox.pids_limit),
        ]

        for tmpfs in plan.sandbox.writable_tmpfs:
            argv.extend(
                [
                    "--tmpfs",
                    (
                        f"{tmpfs}:"
                        "rw,noexec,nosuid,nodev,"
                        "size=64m"
                    ),
                ]
            )

        argv.extend(
            [
                "--volume",
                (
                    f"{mount.source}:"
                    f"{mount.target}:ro"
                ),
                "--workdir",
                "/workspace",
                plan.image,
                *plan.command,
            ]
        )

        return argv

    @classmethod
    def _decode_output(
        cls,
        output: bytes,
    ) -> str:
        truncation_marker = (
            "\n[Aegis truncated sandbox output.]"
        )
        marker_bytes = truncation_marker.encode(
            "utf-8"
        )

        if len(output) <= cls._output_limit_bytes:
            return output.decode(
                "utf-8",
                errors="replace",
            )

        content_limit = max(
            cls._output_limit_bytes
            - len(marker_bytes),
            0,
        )

        limited = output[:content_limit]

        return (
            limited.decode(
                "utf-8",
                errors="replace",
            )
            + truncation_marker
        )

    @staticmethod
    def _duration_ms(
        started_at: float,
    ) -> int:
        return max(
            int(
                (
                    time.monotonic()
                    - started_at
                )
                * 1000
            ),
            0,
        )
