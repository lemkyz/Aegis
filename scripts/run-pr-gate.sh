#!/usr/bin/env bash

set -euo pipefail

repository="${AEGIS_REPOSITORY:-.}"
base_revision="${AEGIS_BASE:-}"
head_revision="${AEGIS_HEAD:-HEAD}"
profile="${AEGIS_PROFILE:-balanced}"
fail_on_review="${AEGIS_FAIL_ON_REVIEW:-false}"
output_path="${AEGIS_OUTPUT:-aegis-change-gate.json}"
sarif_path="${AEGIS_SARIF:-aegis-results.sarif}"

if [[ -z "$base_revision" ]]; then
  echo "Aegis PR gate requires a base revision." >&2
  exit 3
fi

arguments=(
  change-gate
  --repository "$repository"
  --mode pull_request
  --base "$base_revision"
  --head "$head_revision"
  --profile "$profile"
  --format text
  --output "$output_path"
  --sarif "$sarif_path"
)

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
