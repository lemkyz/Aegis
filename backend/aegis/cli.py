from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TextIO

from pydantic import ValidationError

from aegis.schemas.change_policy import (
    ChangePolicyCollectionRequest,
    ChangePolicyCollectionResponse,
)
from aegis.security.change_policy import (
    ChangeAwarePolicyEngine,
)
from aegis.security.change_policy_service import (
    ChangePolicyService,
)
from aegis.security.git_changes import (
    GitChangeCollector,
)


EXIT_ALLOW_OR_REVIEW = 0
EXIT_BLOCK = 2
EXIT_ERROR = 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aegis",
        description=(
            "Evidence-first security gates for "
            "software changes."
        ),
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    gate_parser = subparsers.add_parser(
        "change-gate",
        help=(
            "Collect and evaluate staged, "
            "uncommitted, or pull request "
            "Git changes."
        ),
    )

    gate_parser.add_argument(
        "--repository",
        default=".",
        help=(
            "Path inside the Git repository. "
            "Defaults to the current directory."
        ),
    )
    gate_parser.add_argument(
        "--mode",
        choices=(
            "staged",
            "uncommitted",
            "pull_request",
        ),
        default="uncommitted",
        help=(
            "Git change set to evaluate. "
            "Defaults to uncommitted."
        ),
    )
    gate_parser.add_argument(
        "--base",
        dest="base_revision",
        help=(
            "Base Git revision for pull_request "
            "mode, for example origin/main."
        ),
    )
    gate_parser.add_argument(
        "--head",
        dest="head_revision",
        default=None,
        help=(
            "Head Git revision for pull_request "
            "mode. Defaults to HEAD."
        ),
    )

    gate_parser.add_argument(
        "--profile",
        choices=(
            "permissive",
            "balanced",
            "strict",
        ),
        default="balanced",
        help="Security policy profile.",
    )
    gate_parser.add_argument(
        "--format",
        choices=(
            "text",
            "json",
        ),
        default="text",
        help="Standard-output format.",
    )
    gate_parser.add_argument(
        "--output",
        type=Path,
        help=(
            "Optional path for the complete JSON "
            "result."
        ),
    )
    gate_parser.add_argument(
        "--fail-on-review",
        action="store_true",
        help=(
            "Return the blocking exit code for "
            "REVIEW as well as BLOCK."
        ),
    )

    return parser


def create_service() -> ChangePolicyService:
    return ChangePolicyService(
        collector=GitChangeCollector(),
        engine=ChangeAwarePolicyEngine(),
    )


def render_text(
    result: ChangePolicyCollectionResponse,
) -> str:
    change_set = result.change_set
    policy = result.policy
    summary = policy.summary

    lines = [
        "Aegis Change Security Gate",
        "==========================",
        f"Decision: {policy.decision.upper()}",
        (
            "Risk: "
            f"{policy.risk_score}/100 "
            f"({policy.risk_level.upper()})"
        ),
        f"Profile: {policy.profile}",
        f"Mode: {change_set.mode}",
        f"Changed files: {change_set.file_count}",
        f"Additions: {change_set.additions}",
        f"Deletions: {change_set.deletions}",
        f"Allowed files: {summary.allowed}",
        (
            "Review-required files: "
            f"{summary.review_required}"
        ),
        f"Blocked files: {summary.blocked}",
    ]

    if policy.blocking_paths:
        lines.extend(
            [
                "",
                "Blocking paths:",
                *(
                    f"- {path}"
                    for path in policy.blocking_paths
                ),
            ]
        )

    if policy.review_paths:
        lines.extend(
            [
                "",
                "Review paths:",
                *(
                    f"- {path}"
                    for path in policy.review_paths
                ),
            ]
        )

    if policy.reasons:
        lines.extend(
            [
                "",
                "Reasons:",
                *(
                    f"- {reason}"
                    for reason in policy.reasons
                ),
            ]
        )

    return "\n".join(lines)


def render_github_summary(
    result: ChangePolicyCollectionResponse,
) -> str:
    change_set = result.change_set
    policy = result.policy
    summary = policy.summary

    lines = [
        "## Aegis Change Security Gate",
        "",
        "| Field | Result |",
        "| --- | --- |",
        (
            "| Decision | "
            f"**{policy.decision.upper()}** |"
        ),
        (
            "| Risk | "
            f"{policy.risk_score}/100 "
            f"({policy.risk_level.upper()}) |"
        ),
        f"| Profile | {policy.profile} |",
        f"| Mode | {change_set.mode} |",
        (
            "| Changed files | "
            f"{change_set.file_count} |"
        ),
        f"| Additions | {change_set.additions} |",
        f"| Deletions | {change_set.deletions} |",
        (
            "| Review required | "
            f"{summary.review_required} |"
        ),
        f"| Blocked | {summary.blocked} |",
        "",
    ]

    if policy.blocking_paths:
        lines.extend(
            [
                "### Blocking paths",
                "",
                *(
                    f"- `{escape_markdown(path)}`"
                    for path in policy.blocking_paths
                ),
                "",
            ]
        )

    if policy.review_paths:
        lines.extend(
            [
                "### Review paths",
                "",
                *(
                    f"- `{escape_markdown(path)}`"
                    for path in policy.review_paths
                ),
                "",
            ]
        )

    if policy.reasons:
        lines.extend(
            [
                "### Decision reasons",
                "",
                *(
                    f"- {escape_markdown(reason)}"
                    for reason in policy.reasons
                ),
                "",
            ]
        )

    return "\n".join(lines)


def escape_markdown(value: str) -> str:
    return (
        value
        .replace("\\", "\\\\")
        .replace("`", "\\`")
        .replace("|", "\\|")
        .replace("\r", " ")
        .replace("\n", " ")
    )


def append_github_output(
    path: Path,
    result: ChangePolicyCollectionResponse,
) -> None:
    policy = result.policy
    change_set = result.change_set

    values = {
        "decision": policy.decision,
        "risk_score": str(policy.risk_score),
        "risk_level": policy.risk_level,
        "changed_files": str(change_set.file_count),
        "blocked_files": str(
            policy.summary.blocked
        ),
        "review_files": str(
            policy.summary.review_required
        ),
    }

    with path.open(
        "a",
        encoding="utf-8",
        newline="\n",
    ) as output:
        for key, value in values.items():
            output.write(
                f"{key}={github_output_value(value)}\n"
            )


def github_output_value(value: str) -> str:
    return (
        value
        .replace("%", "%25")
        .replace("\r", "%0D")
        .replace("\n", "%0A")
    )


def write_json_result(
    path: Path,
    result: ChangePolicyCollectionResponse,
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    path.write_text(
        result.model_dump_json(
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def run_change_gate(
    arguments: argparse.Namespace,
    *,
    environment: Mapping[str, str],
    stdout: TextIO,
    stderr: TextIO,
    service: ChangePolicyService,
) -> int:
    try:
        request = ChangePolicyCollectionRequest(
            repository_path=arguments.repository,
            mode=arguments.mode,
            base_revision=arguments.base_revision,
            head_revision=arguments.head_revision,
            profile=arguments.profile,
        )

        result = service.collect_and_evaluate(
            request
        )
    except (
        OSError,
        RuntimeError,
        ValueError,
        ValidationError,
    ) as exc:
        print(
            f"Aegis change gate failed: {exc}",
            file=stderr,
        )
        return EXIT_ERROR

    if arguments.output is not None:
        try:
            write_json_result(
                arguments.output,
                result,
            )
        except OSError as exc:
            print(
                (
                    "Aegis could not write the JSON "
                    f"result: {exc}"
                ),
                file=stderr,
            )
            return EXIT_ERROR

    if arguments.format == "json":
        print(
            result.model_dump_json(indent=2),
            file=stdout,
        )
    else:
        print(
            render_text(result),
            file=stdout,
        )

    github_output = environment.get(
        "GITHUB_OUTPUT"
    )

    if github_output:
        try:
            append_github_output(
                Path(github_output),
                result,
            )
        except OSError as exc:
            print(
                (
                    "Aegis could not write GitHub "
                    f"outputs: {exc}"
                ),
                file=stderr,
            )
            return EXIT_ERROR

    github_summary = environment.get(
        "GITHUB_STEP_SUMMARY"
    )

    if github_summary:
        try:
            with Path(github_summary).open(
                "a",
                encoding="utf-8",
                newline="\n",
            ) as summary:
                summary.write(
                    render_github_summary(result)
                )
                summary.write("\n")
        except OSError as exc:
            print(
                (
                    "Aegis could not write the GitHub "
                    f"step summary: {exc}"
                ),
                file=stderr,
            )
            return EXIT_ERROR

    if result.policy.decision == "block":
        return EXIT_BLOCK

    if (
        arguments.fail_on_review
        and result.policy.decision == "review"
    ):
        return EXIT_BLOCK

    return EXIT_ALLOW_OR_REVIEW


def main(
    argv: Sequence[str] | None = None,
    *,
    environment: Mapping[str, str] | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
    service: ChangePolicyService | None = None,
) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)

    resolved_environment = (
        os.environ
        if environment is None
        else environment
    )
    resolved_stdout = (
        sys.stdout
        if stdout is None
        else stdout
    )
    resolved_stderr = (
        sys.stderr
        if stderr is None
        else stderr
    )

    if arguments.command == "change-gate":
        return run_change_gate(
            arguments,
            environment=resolved_environment,
            stdout=resolved_stdout,
            stderr=resolved_stderr,
            service=service or create_service(),
        )

    parser.error(
        f"Unknown command: {arguments.command}"
    )
    return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
