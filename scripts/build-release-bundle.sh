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
  echo "Aegis release bundling requires the backend virtual environment." >&2
  exit 3
fi

cd "$repository_root"

if [[ -n "$(git status --porcelain --untracked-files=normal)" ]]; then
  echo "Commit or remove local changes before building release artifacts." >&2
  exit 3
fi

backend_version="$(
  "$python_executable" -c \
    'import pathlib,tomllib; print(tomllib.loads(pathlib.Path("backend/pyproject.toml").read_text())["project"]["version"])'
)"
extension_version="$(
  node -p \
    'require("./extension/package.json").version'
)"

if [[ "$backend_version" != "$extension_version" ]]; then
  echo \
    "Version mismatch: backend=$backend_version extension=$extension_version" \
    >&2
  exit 3
fi

release_root="$repository_root/release"
bundle_root="$release_root/v$backend_version"

if [[ -e "$bundle_root" ]]; then
  echo "Release bundle already exists: $bundle_root" >&2
  exit 3
fi

temporary_root="$(mktemp -d)"

cleanup() {
  rm -rf -- "$temporary_root"
}

trap cleanup EXIT

"$python_executable" -m pip wheel \
  --disable-pip-version-check \
  --no-deps \
  --wheel-dir "$temporary_root" \
  "$backend_root"

(
  cd "$extension_root"
  npm run package
  npm run verify:vsix
)

cp \
  "$extension_root/aegis-security-$extension_version.vsix" \
  "$temporary_root/"

release_commit="$(git -C "$repository_root" rev-parse HEAD)"
export AEGIS_BUNDLE_ROOT="$temporary_root"
export AEGIS_RELEASE_VERSION="$backend_version"
export AEGIS_RELEASE_COMMIT="$release_commit"

"$python_executable" - <<'PY'
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path


bundle_root = Path(os.environ["AEGIS_BUNDLE_ROOT"])
version = os.environ["AEGIS_RELEASE_VERSION"]
commit = os.environ["AEGIS_RELEASE_COMMIT"]

artifacts = []

for path in sorted(bundle_root.iterdir()):
    if path.suffix not in {".vsix", ".whl"}:
        continue

    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    artifacts.append(
        {
            "name": path.name,
            "bytes": path.stat().st_size,
            "sha256": digest,
        }
    )

if len(artifacts) != 2:
    raise SystemExit(
        "Expected one wheel and one VSIX in the release bundle."
    )

manifest = {
    "schema_version": 1,
    "product": "Aegis",
    "version": version,
    "git_commit": commit,
    "artifacts": artifacts,
}

(bundle_root / "RELEASE-MANIFEST.json").write_text(
    json.dumps(manifest, indent=2) + "\n",
    encoding="utf-8",
)

checksum_lines = [
    f"{artifact['sha256']}  {artifact['name']}"
    for artifact in artifacts
]

(bundle_root / "SHA256SUMS").write_text(
    "\n".join(checksum_lines) + "\n",
    encoding="utf-8",
)
PY

mkdir -p "$release_root"
mv "$temporary_root" "$bundle_root"
trap - EXIT

echo "Aegis release bundle: $bundle_root"
echo "Commit: $release_commit"
echo
sed -n '1,200p' "$bundle_root/RELEASE-MANIFEST.json"
