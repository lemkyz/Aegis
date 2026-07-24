from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]


def load_yaml(path: Path):
    return yaml.safe_load(
        path.read_text(encoding="utf-8")
    )


def test_action_metadata_contract() -> None:
    action = load_yaml(ROOT / "action.yml")

    assert action["name"] == (
        "Aegis PR Security Gate"
    )
    assert action["runs"]["using"] == "composite"

    inputs = action["inputs"]

    assert inputs["base"]["required"] is True
    assert inputs["head"]["default"] == "HEAD"
    assert inputs["profile"]["default"] == (
        "balanced"
    )
    assert inputs["fail-on-review"]["default"] == (
        "false"
    )

    outputs = action["outputs"]

    assert set(outputs) == {
        "decision",
        "risk-score",
        "risk-level",
        "changed-files",
        "blocked-files",
        "review-files",
    }


def test_action_uses_current_python_setup() -> None:
    action = load_yaml(ROOT / "action.yml")
    steps = action["runs"]["steps"]

    setup_step = next(
        step
        for step in steps
        if step["name"] == "Set up Python"
    )

    assert setup_step["uses"] == (
        "actions/setup-python@v6"
    )
    assert setup_step["with"]["python-version"] == (
        "${{ inputs.python-version }}"
    )


def test_gate_step_exposes_outputs() -> None:
    action = load_yaml(ROOT / "action.yml")
    steps = action["runs"]["steps"]

    gate_step = next(
        step
        for step in steps
        if step["name"] == "Run Aegis PR gate"
    )

    assert gate_step["id"] == "gate"
    assert gate_step["shell"] == "bash"

    for output in action["outputs"].values():
        assert "steps.gate.outputs." in (
            output["value"]
        )


def test_pull_request_workflow_is_read_only() -> None:
    workflow = load_yaml(
        ROOT
        / ".github"
        / "workflows"
        / "aegis-pr-gate.yml"
    )

    assert workflow["permissions"] == {
        "contents": "read"
    }

    job = workflow["jobs"]["security-gate"]
    steps = job["steps"]

    checkout = next(
        step
        for step in steps
        if step["name"] == "Check out repository"
    )

    assert checkout["uses"] == (
        "actions/checkout@v6"
    )
    assert checkout["with"]["fetch-depth"] == 0
    assert checkout["with"][
        "persist-credentials"
    ] is False

    gate = next(
        step
        for step in steps
        if step["name"]
        == "Run Aegis security gate"
    )

    assert gate["uses"] == "./"
    assert gate["with"]["base"]
    assert gate["with"]["head"]


def test_gate_script_uses_argument_array() -> None:
    script = (
        ROOT
        / "scripts"
        / "run-pr-gate.sh"
    ).read_text(encoding="utf-8")

    assert "arguments=(" in script
    assert 'aegis "${arguments[@]}"' in script
    assert "eval " not in script
    assert "bash -c" not in script


def test_gate_script_is_executable() -> None:
    path = ROOT / "scripts" / "run-pr-gate.sh"

    assert path.stat().st_mode & 0o111
