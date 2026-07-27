from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = (
    ROOT
    / "scripts"
    / "run-release-readiness.sh"
)


def script_text() -> str:
    return SCRIPT.read_text(
        encoding="utf-8",
    )


def test_release_readiness_script_exists(
) -> None:
    assert SCRIPT.is_file()


def test_release_readiness_runs_acceptance_gate(
) -> None:
    text = script_text()

    assert "-m acceptance" in text
    assert '-m "not acceptance"' in text


def test_release_readiness_runs_package_checks(
) -> None:
    text = script_text()

    assert "scripts/release_smoke.py" in text
    assert "npm test" in text
    assert "npm run package" in text
    assert "npm run verify:vsix" in text
    assert "git diff --check" in text


def test_release_readiness_uses_no_shell_eval(
) -> None:
    text = script_text()

    assert "eval " not in text
    assert "bash -c" not in text
