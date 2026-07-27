#!/usr/bin/env bash

set -euo pipefail

repository_root="$(
  cd "$(dirname "${BASH_SOURCE[0]}")/.."
  pwd
)"
backend_root="$repository_root/backend"
extension_root="$repository_root/extension"
python_executable="${AEGIS_PYTHON:-$backend_root/.venv/bin/python}"

if [[ ! -x "$python_executable" ]]; then
  echo \
    "Aegis release check requires an executable Python environment." \
    >&2
  exit 3
fi

cd "$backend_root"

"$python_executable" -m pytest \
  -q \
  -m acceptance

"$python_executable" -m pytest \
  -q \
  -m "not acceptance"

"$python_executable" \
  scripts/release_smoke.py

cd "$extension_root"

npm test
npm run package
npm run verify:vsix

cd "$repository_root"

git diff --check

echo "Aegis release readiness checks passed."
