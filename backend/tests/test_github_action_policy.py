from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]


def test_action_exposes_policy_outputs() -> None:
    payload = yaml.safe_load(
        (ROOT / "action.yml").read_text(
            encoding="utf-8",
        )
    )

    assert payload["inputs"]["profile"][
        "default"
    ] == ""

    assert payload["inputs"]["policy-output"][
        "default"
    ] == "aegis-policy-check.json"

    outputs = payload["outputs"]

    assert "policy-status" in outputs
    assert "policy-profile" in outputs
    assert "active-waivers" in outputs
    assert "expired-waivers" in outputs


def test_action_passes_policy_output_to_runner(
) -> None:
    payload = yaml.safe_load(
        (ROOT / "action.yml").read_text(
            encoding="utf-8",
        )
    )

    gate_step = next(
        step
        for step in payload["runs"]["steps"]
        if step.get("id") == "gate"
    )

    environment = gate_step["env"]

    assert environment["AEGIS_POLICY_OUTPUT"] == (
        "${{ inputs.policy-output }}"
    )


def test_runner_executes_policy_preflight_first(
) -> None:
    script = (
        ROOT / "scripts/run-pr-gate.sh"
    ).read_text(
        encoding="utf-8",
    )

    policy_index = script.index(
        "aegis policy-check"
    )
    gate_index = script.index(
        "arguments=("
    )

    assert policy_index < gate_index
    assert "--format json" in script
    assert "policy_status" in script
    assert "policy_profile" in script
    assert "active_waivers" in script
    assert "expired_waivers" in script


def test_runner_does_not_force_balanced_profile(
) -> None:
    script = (
        ROOT / "scripts/run-pr-gate.sh"
    ).read_text(
        encoding="utf-8",
    )

    assert 'profile="${AEGIS_PROFILE:-}"' in script
    assert (
        'if [[ -n "$profile" ]]; then'
        in script
    )
    assert (
        'arguments+=(--profile "${profile,,}")'
        in script
    )


def test_workflow_preserves_repository_profile(
) -> None:
    workflow = (
        ROOT
        / ".github/workflows/aegis-pr-gate.yml"
    ).read_text(
        encoding="utf-8",
    )

    assert 'profile=""' in workflow
    assert "aegis-policy-check.json" in workflow
