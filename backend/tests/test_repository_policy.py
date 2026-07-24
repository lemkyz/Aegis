from datetime import date
from pathlib import Path

import pytest

from aegis.security.repository_policy import (
    RepositoryPolicyError,
    discover_repository_policy,
    load_discovered_repository_policy,
    load_repository_policy,
)


def write_policy(
    root: Path,
    content: str,
    *,
    name: str = ".aegis.yml",
) -> Path:
    path = root / name
    path.write_text(
        content,
        encoding="utf-8",
    )
    return path


def test_loads_repository_policy(
    tmp_path: Path,
) -> None:
    path = write_policy(
        tmp_path,
        """
version: 1
profile: strict
fail_on_review: true

rules:
  AEGIS-SHELL-EXECUTION:
    decision: block

waivers:
  - rule_id: AEGIS-SHELL-EXECUTION
    path: scripts/legacy-build.py
    reason: Legacy migration tracked in SEC-142
    expires: 2026-08-15
""".lstrip(),
    )

    policy = load_repository_policy(path)

    assert policy.version == 1
    assert policy.profile == "strict"
    assert policy.fail_on_review is True
    assert (
        policy.rules[
            "AEGIS-SHELL-EXECUTION"
        ].decision
        == "block"
    )

    waiver = policy.waivers[0]

    assert waiver.rule_id == (
        "AEGIS-SHELL-EXECUTION"
    )
    assert waiver.path == (
        "scripts/legacy-build.py"
    )
    assert waiver.expires == date(
        2026,
        8,
        15,
    )


def test_discovers_single_policy_file(
    tmp_path: Path,
) -> None:
    expected = write_policy(
        tmp_path,
        "version: 1\n",
    )

    assert discover_repository_policy(
        tmp_path
    ) == expected


def test_no_policy_is_valid(
    tmp_path: Path,
) -> None:
    path, policy = (
        load_discovered_repository_policy(
            tmp_path
        )
    )

    assert path is None
    assert policy is None


def test_rejects_both_policy_filenames(
    tmp_path: Path,
) -> None:
    write_policy(
        tmp_path,
        "version: 1\n",
        name=".aegis.yml",
    )
    write_policy(
        tmp_path,
        "version: 1\n",
        name=".aegis.yaml",
    )

    with pytest.raises(
        RepositoryPolicyError,
        match="both",
    ):
        discover_repository_policy(
            tmp_path
        )


def test_rejects_unknown_fields(
    tmp_path: Path,
) -> None:
    path = write_policy(
        tmp_path,
        """
version: 1
silent_disable_everything: true
""".lstrip(),
    )

    with pytest.raises(
        RepositoryPolicyError,
        match="validation failed",
    ):
        load_repository_policy(path)


def test_rule_override_cannot_allow(
    tmp_path: Path,
) -> None:
    path = write_policy(
        tmp_path,
        """
version: 1
rules:
  AEGIS-HARDCODED-CREDENTIAL:
    decision: allow
""".lstrip(),
    )

    with pytest.raises(
        RepositoryPolicyError,
        match="validation failed",
    ):
        load_repository_policy(path)


def test_waiver_requires_meaningful_reason(
    tmp_path: Path,
) -> None:
    path = write_policy(
        tmp_path,
        """
version: 1
waivers:
  - rule_id: AEGIS-SHELL-EXECUTION
    path: scripts/build.py
    reason: temporary
    expires: 2026-08-15
""".lstrip(),
    )

    with pytest.raises(
        RepositoryPolicyError,
        match="validation failed",
    ):
        load_repository_policy(path)


def test_rejects_repository_escape_path(
    tmp_path: Path,
) -> None:
    path = write_policy(
        tmp_path,
        """
version: 1
waivers:
  - rule_id: AEGIS-SHELL-EXECUTION
    path: ../outside.py
    reason: Migration tracked in security ticket SEC-9
    expires: 2026-08-15
""".lstrip(),
    )

    with pytest.raises(
        RepositoryPolicyError,
        match="validation failed",
    ):
        load_repository_policy(path)


def test_rejects_duplicate_waiver(
    tmp_path: Path,
) -> None:
    path = write_policy(
        tmp_path,
        """
version: 1
waivers:
  - rule_id: AEGIS-SHELL-EXECUTION
    path: scripts/build.py
    reason: Migration tracked in security ticket SEC-9
    expires: 2026-08-15
  - rule_id: AEGIS-SHELL-EXECUTION
    path: scripts/build.py
    reason: Duplicate approval from another reviewer
    expires: 2026-08-15
""".lstrip(),
    )

    with pytest.raises(
        RepositoryPolicyError,
        match="Duplicate",
    ):
        load_repository_policy(path)


def test_rejects_non_mapping_yaml(
    tmp_path: Path,
) -> None:
    path = write_policy(
        tmp_path,
        "- version\n- 1\n",
    )

    with pytest.raises(
        RepositoryPolicyError,
        match="mapping",
    ):
        load_repository_policy(path)
