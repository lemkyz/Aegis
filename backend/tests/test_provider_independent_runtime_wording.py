from pathlib import Path


def test_analyzer_runtime_messages_are_provider_independent() -> None:
    source = Path(
        "aegis/orchestrator/analyzer.py"
    ).read_text()

    forbidden = [
        "The NVIDIA model was not called.",
        "will be sent to the NVIDIA model.",
        "NVIDIA deep analysis starting",
    ]

    for marker in forbidden:
        assert marker not in source

    required = [
        "The configured primary model was not called.",
        "will be sent to the configured primary model.",
        "Primary model analysis starting",
    ]

    for marker in required:
        assert marker in source
