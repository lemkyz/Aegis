from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/release_smoke.py"


def script_text() -> str:
    return SCRIPT.read_text(
        encoding="utf-8",
    )


def test_release_smoke_script_exists() -> None:
    assert SCRIPT.is_file()


def test_release_smoke_covers_live_backend() -> None:
    text = script_text()

    assert "uvicorn" in text
    assert "/health" in text
    assert "/openapi.json" in text
    assert "/v1/security/tasks/run" in text
    assert "process.terminate()" in text
    assert "process.kill()" in text


def test_release_smoke_builds_and_installs_wheel(
) -> None:
    text = script_text()

    assert '"wheel"' in text
    assert "--no-deps" in text
    assert "aegis console command" in text
    assert '"--help"' in text


def test_release_smoke_covers_gate_decisions(
) -> None:
    text = script_text()

    assert "validate_allow" in text
    assert "validate_review" in text
    assert "validate_block" in text
    assert "expected_code=0" in text
    assert "expected_code=2" in text


def test_release_smoke_covers_policy_cases(
) -> None:
    text = script_text()

    assert "validate_active_waiver" in text
    assert "validate_expired_waiver" in text
    assert "validate_invalid_policy" in text
    assert "expected_codes={3}" in text


def test_release_smoke_checks_artifacts() -> None:
    text = script_text()

    assert "aegis-change-gate.json" in text
    assert "aegis-results.sarif" in text
    assert '"2.1.0"' in text
    assert "partialFingerprints" not in text


def test_release_smoke_uses_valid_fingerprint_key(
) -> None:
    text = script_text()

    marker = (
        '"aegis-release-smoke-'
        'fingerprint-key-v1"'
    )

    assert marker in text
    assert len(
        "aegis-release-smoke-fingerprint-key-v1"
    ) >= 32



def test_installed_wheel_resolves_runtime_dependencies(
) -> None:
    text = script_text()

    install_start = text.index(
        '"pip",\n            "install",'
    )
    install_end = text.index(
        "    )\n\n    if not aegis_executable.exists()",
        install_start,
    )
    install_block = text[
        install_start:install_end
    ]

    assert '"--no-deps"' not in install_block
    assert '"--prefer-binary"' in install_block


def test_wheel_build_directory_is_cleaned(
) -> None:
    text = script_text()

    assert 'BACKEND_ROOT / "build"' in text
    assert "ignore_errors=True" in text
