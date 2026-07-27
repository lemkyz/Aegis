import asyncio

from aegis.schemas.validation import (
    ValidationAuthorizationRequest,
    ValidationExecutionRequest,
    ValidationPlanRequest,
)
from aegis.security.validation_runner import (
    ValidationRunner,
)


def _execution_request(
    *,
    dry_run: bool = False,
) -> ValidationExecutionRequest:
    return ValidationExecutionRequest(
        plan=ValidationPlanRequest(
            authorization=(
                ValidationAuthorizationRequest(
                    authorization_confirmed=True,
                    target_type="local_repository",
                    target="/tmp/aegis-project",
                    allowed_test_types=[
                        "command_injection",
                    ],
                    dry_run=dry_run,
                    timeout_seconds=10,
                    memory_limit_mb=256,
                    cpu_limit=0.5,
                    network_policy="disabled",
                )
            ),
            runtime="python",
            entrypoint="validation.py",
            test_type="command_injection",
        )
    )


def test_builds_hardened_podman_argv() -> None:
    runner = ValidationRunner()
    plan = runner._planner.build(
        _execution_request().plan
    )

    argv = runner._build_runtime_argv(
        runtime_executable="/usr/bin/podman",
        plan=plan,
    )

    assert argv[:3] == [
        "/usr/bin/podman",
        "run",
        "--rm",
    ]
    assert argv[
        argv.index("--pull") + 1
    ] == "never"
    assert "--read-only" in argv
    assert argv[
        argv.index("--network") + 1
    ] == "none"
    assert argv[
        argv.index("--cap-drop") + 1
    ] == "ALL"
    assert (
        "no-new-privileges"
        in argv
    )
    assert "label=disable" in argv
    assert argv[
        argv.index("--user") + 1
    ] == "65532:65532"
    assert argv[
        argv.index("--memory") + 1
    ] == "256m"
    assert "--volume" in argv

    volume = argv[
        argv.index("--volume") + 1
    ]

    assert volume == (
        "/tmp/aegis-project:"
        "/workspace:ro"
    )
    assert ":Z" not in volume
    assert ":z" not in volume
    assert "sh" not in argv
    assert "bash" not in argv
    assert "/bin/sh" not in argv
    assert "/bin/bash" not in argv

    assert argv[-5:] == [
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
        "/workspace/validation.py",
    ]


def test_rejects_non_ready_plan() -> None:
    result = asyncio.run(
        ValidationRunner().run(
            _execution_request(
                dry_run=True,
            )
        )
    )

    assert result.status == "rejected"
    assert result.started is False
    assert result.argv == []


def test_reports_runtime_unavailable(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        ValidationRunner,
        "_find_runtime_executable",
        classmethod(
            lambda cls: None
        ),
    )

    result = asyncio.run(
        ValidationRunner().run(
            _execution_request()
        )
    )

    assert result.status == (
        "runtime_unavailable"
    )
    assert result.started is False
    assert result.exit_code is None


def test_executes_without_shell(
    monkeypatch,
) -> None:
    captured: dict[str, object] = {}

    class FakeProcess:
        returncode = 0

        async def communicate(
            self,
        ) -> tuple[bytes, bytes]:
            return (
                b"AEGIS_SANDBOX_OK\n",
                b"",
            )

        def kill(self) -> None:
            raise AssertionError(
                "Completed process must not be killed."
            )

    async def fake_create_subprocess_exec(
        *argv: str,
        **kwargs: object,
    ) -> FakeProcess:
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return FakeProcess()

    monkeypatch.setattr(
        ValidationRunner,
        "_find_runtime_executable",
        classmethod(
            lambda cls: "/usr/bin/podman"
        ),
    )
    monkeypatch.setattr(
        asyncio,
        "create_subprocess_exec",
        fake_create_subprocess_exec,
    )

    result = asyncio.run(
        ValidationRunner().run(
            _execution_request()
        )
    )

    assert result.status == "completed"
    assert result.started is True
    assert result.exit_code == 0
    assert result.stdout == (
        "AEGIS_SANDBOX_OK\n"
    )

    argv = captured["argv"]

    assert isinstance(argv, tuple)
    assert argv[0] == "/usr/bin/podman"
    assert "shell" not in captured["kwargs"]


def test_limits_captured_output() -> None:
    oversized = b"A" * (
        ValidationRunner._output_limit_bytes + 20
    )

    decoded = ValidationRunner._decode_output(
        oversized
    )

    assert len(decoded.encode("utf-8")) <= (
        ValidationRunner._output_limit_bytes
    )
    assert len(decoded) < len(oversized)
    assert "truncated" in decoded.lower()
