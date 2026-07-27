from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BACKEND_ROOT = ROOT / "backend"
EXTENSION_ROOT = ROOT / "extension"
EXPECTED_VERSION = "0.2.0"


def test_public_versions_match() -> None:
    pyproject = tomllib.loads(
        (
            BACKEND_ROOT
            / "pyproject.toml"
        ).read_text(encoding="utf-8")
    )
    manifest = json.loads(
        (
            EXTENSION_ROOT
            / "package.json"
        ).read_text(encoding="utf-8")
    )
    lockfile = json.loads(
        (
            EXTENSION_ROOT
            / "package-lock.json"
        ).read_text(encoding="utf-8")
    )

    versions = {
        pyproject["project"]["version"],
        manifest["version"],
        lockfile["version"],
        lockfile["packages"][""]["version"],
    }

    assert versions == {EXPECTED_VERSION}


def test_runtime_version_markers_match_release(
) -> None:
    settings = (
        BACKEND_ROOT
        / "aegis"
        / "config"
        / "settings.py"
    ).read_text(encoding="utf-8")
    sarif = (
        BACKEND_ROOT
        / "aegis"
        / "security"
        / "change_sarif.py"
    ).read_text(encoding="utf-8")
    osv = (
        BACKEND_ROOT
        / "aegis"
        / "security"
        / "osv.py"
    ).read_text(encoding="utf-8")

    assert (
        f'app_version: str = "{EXPECTED_VERSION}"'
        in settings
    )
    assert (
        f'"semanticVersion": "{EXPECTED_VERSION}"'
        in sarif
    )
    assert (
        f"Aegis-Security/{EXPECTED_VERSION}"
        in osv
    )


def test_release_notes_and_changelogs_exist(
) -> None:
    versioned = [
        ROOT / "CHANGELOG.md",
        EXTENSION_ROOT / "CHANGELOG.md",
        (
            ROOT
            / "docs"
            / "releases"
            / f"v{EXPECTED_VERSION}.md"
        ),
    ]

    for path in versioned:
        assert path.is_file(), path
        text = path.read_text(encoding="utf-8")
        assert EXPECTED_VERSION in text

    assert (
        EXTENSION_ROOT
        / "SUPPORT.md"
    ).is_file()


def test_public_copy_has_no_release_placeholders(
) -> None:
    public_files = [
        ROOT / "README.md",
        ROOT / "CHANGELOG.md",
        EXTENSION_ROOT / "README.md",
        EXTENSION_ROOT / "CHANGELOG.md",
        (
            ROOT
            / "docs"
            / "releases"
            / f"v{EXPECTED_VERSION}.md"
        ),
    ]
    placeholder = re.compile(
        r"\b(?:TODO|TBD|coming soon|lorem ipsum)\b",
        re.IGNORECASE,
    )

    for path in public_files:
        text = path.read_text(encoding="utf-8")
        assert placeholder.search(text) is None, path


def test_release_bundle_script_is_safe_and_present(
) -> None:
    script = (
        ROOT
        / "scripts"
        / "build-release-bundle.sh"
    )

    assert script.is_file()
    text = script.read_text(encoding="utf-8")

    assert "mktemp -d" in text
    assert "RELEASE-MANIFEST.json" in text
    assert "SHA256SUMS" in text
    assert "git status --porcelain" in text
    assert "eval " not in text
    assert "bash -c" not in text
