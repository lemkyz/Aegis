from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import venv
from dataclasses import dataclass
from pathlib import Path
from typing import Any


BACKEND_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = BACKEND_ROOT.parent


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


def run(
    arguments: list[str],
    *,
    cwd: Path | None = None,
    environment: dict[str, str] | None = None,
    expected_codes: set[int] | None = None,
) -> CommandResult:
    result = subprocess.run(
        arguments,
        cwd=cwd,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    allowed = (
        expected_codes
        if expected_codes is not None
        else {0}
    )

    if result.returncode not in allowed:
        command = " ".join(arguments)

        raise RuntimeError(
            "\n".join(
                [
                    f"Command failed: {command}",
                    f"Exit code: {result.returncode}",
                    "--- stdout ---",
                    result.stdout,
                    "--- stderr ---",
                    result.stderr,
                ]
            )
        )

    return CommandResult(
        returncode=result.returncode,
        stdout=result.stdout,
        stderr=result.stderr,
    )


def free_tcp_port() -> int:
    with socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM,
    ) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def read_json_url(
    url: str,
    *,
    timeout: float = 2.0,
) -> dict[str, Any]:
    with urllib.request.urlopen(
        url,
        timeout=timeout,
    ) as response:
        payload = response.read().decode("utf-8")

    parsed = json.loads(payload)

    if not isinstance(parsed, dict):
        raise RuntimeError(
            f"Expected JSON object from {url}."
        )

    return parsed


def wait_for_health(
    url: str,
    *,
    timeout: float = 20.0,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None

    while time.monotonic() < deadline:
        try:
            payload = read_json_url(url)

            if payload.get("status") == "ok":
                return payload
        except (
            OSError,
            urllib.error.URLError,
            json.JSONDecodeError,
        ) as exc:
            last_error = exc

        time.sleep(0.2)

    raise RuntimeError(
        "Backend did not become healthy in time. "
        f"Last error: {last_error}"
    )


def validate_live_backend(
    python_executable: Path,
) -> None:
    port = free_tcp_port()
    base_url = f"http://127.0.0.1:{port}"

    environment = os.environ.copy()
    environment.setdefault(
        "AEGIS_FINGERPRINT_KEY",
        "aegis-release-smoke-fingerprint-key-v1",
    )

    process = subprocess.Popen(
        [
            str(python_executable),
            "-m",
            "uvicorn",
            "aegis.main:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--log-level",
            "warning",
        ],
        cwd=BACKEND_ROOT,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    try:
        health = wait_for_health(
            f"{base_url}/health"
        )

        assert health["status"] == "ok"
        assert isinstance(
            health.get("service"),
            str,
        )
        assert isinstance(
            health.get("version"),
            str,
        )

        openapi = read_json_url(
            f"{base_url}/openapi.json"
        )

        paths = openapi.get("paths")

        if not isinstance(paths, dict):
            raise RuntimeError(
                "OpenAPI paths are missing."
            )

        required_paths = {
            "/health",
            "/v1/analyze",
            "/v1/analyze/fast",
            "/v1/analyze/deep",
            "/v1/attack-surface/scan",
            "/v1/threat-model/scan",
        }

        missing = required_paths - set(paths)

        if missing:
            raise RuntimeError(
                "OpenAPI is missing required routes: "
                + ", ".join(sorted(missing))
            )

        print(
            "PASS live backend: "
            f"{len(paths)} OpenAPI routes"
        )
    finally:
        process.terminate()

        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)

        stdout, stderr = process.communicate()

        if process.returncode not in {
            0,
            -15,
        }:
            raise RuntimeError(
                "\n".join(
                    [
                        (
                            "Backend process ended "
                            "unexpectedly."
                        ),
                        f"Return code: {process.returncode}",
                        "--- stdout ---",
                        stdout,
                        "--- stderr ---",
                        stderr,
                    ]
                )
            )


def build_wheel(
    python_executable: Path,
    destination: Path,
) -> Path:
    destination.mkdir(
        parents=True,
        exist_ok=True,
    )

    run(
        [
            str(python_executable),
            "-m",
            "pip",
            "wheel",
            ".",
            "--no-deps",
            "--wheel-dir",
            str(destination),
        ],
        cwd=BACKEND_ROOT,
    )

    wheels = sorted(
        destination.glob(
            "aegis_security_backend-*.whl"
        )
    )

    if len(wheels) != 1:
        raise RuntimeError(
            "Expected exactly one backend wheel; "
            f"found {len(wheels)}."
        )

    print(
        f"PASS wheel build: {wheels[0].name}"
    )

    shutil.rmtree(
        BACKEND_ROOT / "build",
        ignore_errors=True,
    )

    return wheels[0]


def create_installed_environment(
    wheel: Path,
    environment_root: Path,
) -> tuple[Path, Path]:
    builder = venv.EnvBuilder(
        with_pip=True,
        system_site_packages=True,
        clear=True,
    )
    builder.create(environment_root)

    bin_directory = (
        environment_root
        / (
            "Scripts"
            if os.name == "nt"
            else "bin"
        )
    )

    python_executable = (
        bin_directory
        / (
            "python.exe"
            if os.name == "nt"
            else "python"
        )
    )
    aegis_executable = (
        bin_directory
        / (
            "aegis.exe"
            if os.name == "nt"
            else "aegis"
        )
    )

    run(
        [
            str(python_executable),
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--prefer-binary",
            "--force-reinstall",
            str(wheel),
        ]
    )

    if not aegis_executable.exists():
        raise RuntimeError(
            "Installed wheel did not create the "
            "aegis console command."
        )

    help_result = run(
        [
            str(aegis_executable),
            "--help",
        ]
    )

    assert "change-gate" in help_result.stdout
    assert "policy-check" in help_result.stdout

    print(
        "PASS installed CLI entry point"
    )

    return python_executable, aegis_executable


def git(
    repository: Path,
    *arguments: str,
) -> str:
    return run(
        ["git", *arguments],
        cwd=repository,
    ).stdout.strip()


def initialize_repository(
    root: Path,
) -> None:
    root.mkdir(
        parents=True,
        exist_ok=True,
    )

    git(root, "init", "-b", "main")
    git(
        root,
        "config",
        "user.email",
        "release-smoke@aegis.local",
    )
    git(
        root,
        "config",
        "user.name",
        "Aegis Release Smoke",
    )

    (root / "app.py").write_text(
        "print('safe baseline')\n",
        encoding="utf-8",
    )

    git(root, "add", "app.py")
    git(
        root,
        "commit",
        "-m",
        "Initial safe baseline",
    )


def run_policy_check(
    executable: Path,
    repository: Path,
) -> dict[str, Any]:
    result = run(
        [
            str(executable),
            "policy-check",
            "--repository",
            str(repository),
            "--format",
            "json",
        ]
    )

    payload = json.loads(result.stdout)

    if payload.get("status") != "valid":
        raise RuntimeError(
            "Policy check did not report valid."
        )

    return payload


def run_change_gate(
    executable: Path,
    repository: Path,
    output_directory: Path,
    *,
    fail_on_review: bool = False,
    expected_code: int,
) -> tuple[
    dict[str, Any],
    dict[str, Any],
]:
    evidence_path = (
        output_directory
        / "aegis-change-gate.json"
    )
    sarif_path = (
        output_directory
        / "aegis-results.sarif"
    )

    arguments = [
        str(executable),
        "change-gate",
        "--repository",
        str(repository),
        "--mode",
        "uncommitted",
        "--format",
        "json",
        "--output",
        str(evidence_path),
        "--sarif",
        str(sarif_path),
    ]

    if fail_on_review:
        arguments.append(
            "--fail-on-review"
        )

    result = run(
        arguments,
        expected_codes={expected_code},
    )

    stdout_payload = json.loads(
        result.stdout
    )
    evidence_payload = json.loads(
        evidence_path.read_text(
            encoding="utf-8",
        )
    )
    sarif_payload = json.loads(
        sarif_path.read_text(
            encoding="utf-8",
        )
    )

    if stdout_payload != evidence_payload:
        raise RuntimeError(
            "CLI JSON stdout and evidence artifact "
            "do not match."
        )

    assert sarif_payload["version"] == "2.1.0"
    assert isinstance(
        sarif_payload["runs"],
        list,
    )

    return evidence_payload, sarif_payload


def reset_worktree(
    repository: Path,
) -> None:
    run(
        [
            "git",
            "reset",
            "--hard",
            "HEAD",
        ],
        cwd=repository,
    )

    run(
        [
            "git",
            "clean",
            "-fd",
        ],
        cwd=repository,
    )


def validate_allow(
    executable: Path,
    repository: Path,
    artifacts: Path,
) -> None:
    (repository / "app.py").write_text(
        "print('safe baseline')\n"
        "print('safe change')\n",
        encoding="utf-8",
    )

    evidence, sarif = run_change_gate(
        executable,
        repository,
        artifacts / "allow",
        expected_code=0,
    )

    assert evidence["policy"]["decision"] == (
        "allow"
    )
    assert sarif["runs"][0]["results"] == []

    print("PASS CLI scenario: ALLOW")


def validate_review(
    executable: Path,
    repository: Path,
    artifacts: Path,
) -> None:
    reset_worktree(repository)

    (repository / "app.py").write_text(
        "import subprocess\n"
        "subprocess.run(command, shell=True)\n",
        encoding="utf-8",
    )

    evidence, sarif = run_change_gate(
        executable,
        repository,
        artifacts / "review",
        expected_code=0,
    )

    assert evidence["policy"]["decision"] == (
        "review"
    )

    results = sarif["runs"][0]["results"]

    assert any(
        result["ruleId"]
        == "AEGIS-SHELL-EXECUTION"
        for result in results
    )

    run_change_gate(
        executable,
        repository,
        artifacts / "review-failing",
        fail_on_review=True,
        expected_code=2,
    )

    print(
        "PASS CLI scenario: REVIEW "
        "and fail-on-review"
    )


def validate_block(
    executable: Path,
    repository: Path,
    artifacts: Path,
) -> None:
    reset_worktree(repository)

    (repository / "config.py").write_text(
        (
            'api_key = '
            '"production-secret-token-value"\n'
        ),
        encoding="utf-8",
    )

    evidence, sarif = run_change_gate(
        executable,
        repository,
        artifacts / "block",
        expected_code=2,
    )

    assert evidence["policy"]["decision"] == (
        "block"
    )

    results = sarif["runs"][0]["results"]

    secret_result = next(
        result
        for result in results
        if result["ruleId"]
        == "AEGIS-HARDCODED-CREDENTIAL"
    )

    region = secret_result["locations"][0][
        "physicalLocation"
    ]["region"]

    assert region["startLine"] == 1
    assert region["startColumn"] == 1

    print("PASS CLI scenario: BLOCK")


def validate_active_waiver(
    executable: Path,
    repository: Path,
    artifacts: Path,
) -> None:
    reset_worktree(repository)

    (repository / ".aegis.yml").write_text(
        """
version: 1
waivers:
  - rule_id: AEGIS-SHELL-EXECUTION
    path: app.py
    reason: Release smoke migration tracked in SEC-900
    expires: 2099-12-31
""".lstrip(),
        encoding="utf-8",
    )

    (repository / "app.py").write_text(
        "import subprocess\n"
        "subprocess.run(command, shell=True)\n",
        encoding="utf-8",
    )

    policy = run_policy_check(
        executable,
        repository,
    )

    assert policy["active_waiver_count"] == 1
    assert policy["expired_waiver_count"] == 0

    evidence, sarif = run_change_gate(
        executable,
        repository,
        artifacts / "active-waiver",
        expected_code=0,
    )

    assert evidence["policy"]["decision"] == (
        "allow"
    )

    finding = next(
        finding
        for assessment
        in evidence["policy"]["assessments"]
        if assessment["path"] == "app.py"
        for finding in assessment["findings"]
    )

    assert finding["waived"] is True
    assert finding["waiver_expired"] is False

    sarif_result = next(
        result
        for result
        in sarif["runs"][0]["results"]
        if result["ruleId"]
        == "AEGIS-SHELL-EXECUTION"
    )

    assert sarif_result["level"] == "note"
    assert (
        sarif_result["properties"]["waived"]
        is True
    )

    print(
        "PASS CLI scenario: active waiver "
        "preserves evidence"
    )


def validate_expired_waiver(
    executable: Path,
    repository: Path,
    artifacts: Path,
) -> None:
    reset_worktree(repository)

    (repository / ".aegis.yml").write_text(
        """
version: 1
waivers:
  - rule_id: AEGIS-SHELL-EXECUTION
    path: app.py
    reason: Expired release smoke migration SEC-800
    expires: 2020-01-01
""".lstrip(),
        encoding="utf-8",
    )

    (repository / "app.py").write_text(
        "import subprocess\n"
        "subprocess.run(command, shell=True)\n",
        encoding="utf-8",
    )

    policy = run_policy_check(
        executable,
        repository,
    )

    assert policy["active_waiver_count"] == 0
    assert policy["expired_waiver_count"] == 1

    evidence, _ = run_change_gate(
        executable,
        repository,
        artifacts / "expired-waiver",
        expected_code=0,
    )

    assert evidence["policy"]["decision"] == (
        "review"
    )

    finding = next(
        finding
        for assessment
        in evidence["policy"]["assessments"]
        if assessment["path"] == "app.py"
        for finding in assessment["findings"]
    )

    assert finding["waived"] is False
    assert finding["waiver_expired"] is True

    print(
        "PASS CLI scenario: expired waiver "
        "is ignored"
    )


def validate_invalid_policy(
    executable: Path,
    repository: Path,
) -> None:
    reset_worktree(repository)

    (repository / ".aegis.yml").write_text(
        """
version: 1
rules:
  AEGIS-HARDCODED-CREDENTIAL:
    decision: allow
""".lstrip(),
        encoding="utf-8",
    )

    result = run(
        [
            str(executable),
            "policy-check",
            "--repository",
            str(repository),
            "--format",
            "json",
        ],
        expected_codes={3},
    )

    payload = json.loads(result.stdout)

    assert payload["status"] == "invalid"
    assert "validation failed" in payload[
        "error"
    ].lower()

    gate = run(
        [
            str(executable),
            "change-gate",
            "--repository",
            str(repository),
            "--mode",
            "uncommitted",
        ],
        expected_codes={3},
    )

    assert (
        "validation failed"
        in gate.stderr.lower()
    )

    print(
        "PASS CLI scenario: invalid policy "
        "returns EXIT_ERROR"
    )


def validate_package_contents(
    wheel: Path,
    python_executable: Path,
) -> None:
    script = """
import sys
import zipfile
from pathlib import Path

wheel = Path(sys.argv[1])

forbidden_parts = {
    ".env",
    ".pytest_cache",
    "__pycache__",
}

forbidden_suffixes = {
    ".pem",
    ".key",
}

with zipfile.ZipFile(wheel) as archive:
    names = archive.namelist()

for name in names:
    path = Path(name)

    if any(
        part in forbidden_parts
        for part in path.parts
    ):
        raise RuntimeError(
            f"Forbidden wheel content: {name}"
        )

    if path.suffix.lower() in forbidden_suffixes:
        raise RuntimeError(
            f"Sensitive wheel content: {name}"
        )

print(f"PASS wheel contents: {len(names)} entries")
"""

    run(
        [
            str(python_executable),
            "-c",
            script,
            str(wheel),
        ]
    )

    print(
        "PASS package safety inspection"
    )


def execute(
    *,
    keep_artifacts: bool,
) -> Path | None:
    source_python = Path(sys.executable)

    temporary_root = Path(
        tempfile.mkdtemp(
            prefix="aegis-release-smoke-"
        )
    )

    artifacts = temporary_root / "artifacts"

    try:
        print(
            f"Smoke workspace: {temporary_root}"
        )

        validate_live_backend(
            source_python
        )

        wheel = build_wheel(
            source_python,
            artifacts / "wheel",
        )

        validate_package_contents(
            wheel,
            source_python,
        )

        _, aegis_executable = (
            create_installed_environment(
                wheel,
                temporary_root
                / "installed-environment",
            )
        )

        repository = (
            temporary_root / "repository"
        )
        initialize_repository(repository)

        default_policy = run_policy_check(
            aegis_executable,
            repository,
        )

        assert (
            default_policy["policy_found"]
            is False
        )
        assert (
            default_policy["profile"]
            == "balanced"
        )

        print(
            "PASS policy-check default"
        )

        validate_allow(
            aegis_executable,
            repository,
            artifacts,
        )
        validate_review(
            aegis_executable,
            repository,
            artifacts,
        )
        validate_block(
            aegis_executable,
            repository,
            artifacts,
        )
        validate_active_waiver(
            aegis_executable,
            repository,
            artifacts,
        )
        validate_expired_waiver(
            aegis_executable,
            repository,
            artifacts,
        )
        validate_invalid_policy(
            aegis_executable,
            repository,
        )

        print()
        print(
            "AEGIS RELEASE SMOKE: PASS"
        )

        if keep_artifacts:
            print(
                f"Artifacts retained at: {artifacts}"
            )
            return temporary_root

        return None
    finally:
        if (
            not keep_artifacts
            and temporary_root.exists()
        ):
            shutil.rmtree(
                temporary_root,
                ignore_errors=True,
            )


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Run release-grade Aegis backend and "
            "installed-CLI smoke validation."
        )
    )
    parser.add_argument(
        "--keep-artifacts",
        action="store_true",
        help=(
            "Retain the temporary workspace and "
            "generated evidence artifacts."
        ),
    )

    arguments = parser.parse_args()

    try:
        execute(
            keep_artifacts=(
                arguments.keep_artifacts
            )
        )
    except Exception as exc:
        print(
            f"AEGIS RELEASE SMOKE: FAIL: {exc}",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
