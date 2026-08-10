#!/usr/bin/env bash

set -euo pipefail

repository="${AEGIS_REPOSITORY:-.}"
base_revision="${AEGIS_BASE:-}"
head_revision="${AEGIS_HEAD:-HEAD}"
profile="${AEGIS_PROFILE:-}"
fail_on_review="${AEGIS_FAIL_ON_REVIEW:-false}"
output_path="${AEGIS_OUTPUT:-aegis-change-gate.json}"
sarif_path="${AEGIS_SARIF:-aegis-results.sarif}"
policy_output_path="${AEGIS_POLICY_OUTPUT:-aegis-policy-check.json}"

if [[ -z "$base_revision" ]]; then
  echo "Aegis PR gate requires a base revision." >&2
  exit 3
fi

set +e
aegis policy-check \
  --repository "$repository" \
  --format json \
  > "$policy_output_path"
policy_exit_code=$?
set -e

if [[ "$policy_exit_code" -ne 0 ]]; then
  echo \
    "::error title=Aegis Repository Policy::Repository policy validation failed."

  if [[ -s "$policy_output_path" ]]; then
    cat "$policy_output_path"
  fi

  exit "$policy_exit_code"
fi

python - "$policy_output_path" <<'PY'
from __future__ import annotations

import json
import os
import sys
from pathlib import Path


report_path = Path(sys.argv[1])
report = json.loads(
    report_path.read_text(
        encoding="utf-8",
    )
)

values = {
    "policy_status": report["status"],
    "policy_profile": report["profile"],
    "active_waivers": str(
        report["active_waiver_count"]
    ),
    "expired_waivers": str(
        report["expired_waiver_count"]
    ),
}

github_output = os.environ.get(
    "GITHUB_OUTPUT"
)

if github_output:
    with Path(github_output).open(
        "a",
        encoding="utf-8",
        newline="\n",
    ) as output:
        for key, value in values.items():
            output.write(
                f"{key}={value}\n"
            )

github_summary = os.environ.get(
    "GITHUB_STEP_SUMMARY"
)

if github_summary:
    policy_file = (
        report["source"]
        if report["policy_found"]
        else "Not found — balanced default"
    )

    summary = [
        "## Aegis Repository Policy",
        "",
        "| Field | Result |",
        "| --- | --- |",
        (
            "| Status | "
            f"**{report['status'].upper()}** |"
        ),
        f"| Policy file | `{policy_file}` |",
        f"| Effective profile | {report['profile']} |",
        (
            "| Rule overrides | "
            f"{report['rule_override_count']} |"
        ),
        (
            "| Active waivers | "
            f"{report['active_waiver_count']} |"
        ),
        (
            "| Expired waivers | "
            f"{report['expired_waiver_count']} |"
        ),
        "",
    ]

    with Path(github_summary).open(
        "a",
        encoding="utf-8",
        newline="\n",
    ) as output:
        output.write(
            "\n".join(summary)
        )
        output.write("\n")
PY

arguments=(
  change-gate
  --repository "$repository"
  --mode pull_request
  --base "$base_revision"
  --head "$head_revision"
  --format text
  --output "$output_path"
  --sarif "$sarif_path"
)

if [[ -n "$profile" ]]; then
  case "${profile,,}" in
    permissive|balanced|strict)
      arguments+=(--profile "${profile,,}")
      ;;
    *)
      echo \
        "profile must be permissive, balanced, strict, or empty." \
        >&2
      exit 3
      ;;
  esac
fi

case "${fail_on_review,,}" in
  true|1|yes)
    arguments+=(--fail-on-review)
    ;;
  false|0|no|"")
    ;;
  *)
    echo \
      "fail-on-review must be true or false." \
      >&2
    exit 3
    ;;
esac

set +e
aegis "${arguments[@]}"
exit_code=$?
set -e

case "$exit_code" in
  0)
    ;;
  2)
    echo \
      "::error title=Aegis Security Gate::The pull request did not satisfy the configured security policy."
    ;;
  *)
    echo \
      "::error title=Aegis Security Gate::The security gate could not be evaluated."
    ;;
esac

exit "$exit_code"
