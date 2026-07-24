import subprocess
from pathlib import Path

from aegis.schemas.change_policy import (
    ChangePolicyCollectionRequest,
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


def git(
    root: Path,
    *arguments: str,
) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )

    return result.stdout.strip()


def repository(tmp_path: Path) -> Path:
    root = tmp_path / "repository"
    root.mkdir()

    git(root, "init", "-b", "main")
    git(
        root,
        "config",
        "user.email",
        "aegis-tests@example.com",
    )
    git(
        root,
        "config",
        "user.name",
        "Aegis Tests",
    )

    (root / "app.py").write_text(
        "print('safe')\n",
        encoding="utf-8",
    )

    git(root, "add", "app.py")
    git(root, "commit", "-m", "Initial commit")

    return root


def service() -> ChangePolicyService:
    return ChangePolicyService(
        collector=GitChangeCollector(),
        engine=ChangeAwarePolicyEngine(),
    )


def test_collects_and_allows_safe_change(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)

    (root / "app.py").write_text(
        "print('safe')\n"
        "print('still safe')\n",
        encoding="utf-8",
    )

    result = service().collect_and_evaluate(
        ChangePolicyCollectionRequest(
            repository_path=str(root),
            mode="uncommitted",
        )
    )

    assert result.change_set.file_count == 1
    assert result.policy.decision == "allow"


def test_collects_and_blocks_hardcoded_secret(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)

    (root / "config.py").write_text(
        'api_key = "real-secret-token-value"\n',
        encoding="utf-8",
    )

    result = service().collect_and_evaluate(
        ChangePolicyCollectionRequest(
            repository_path=str(root),
            mode="uncommitted",
        )
    )

    assert result.change_set.file_count == 1
    assert result.policy.decision == "block"
    assert result.policy.blocking_paths == [
        "config.py"
    ]


def test_staged_mode_ignores_unstaged_change(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)

    (root / "staged.py").write_text(
        "print('staged')\n",
        encoding="utf-8",
    )
    git(root, "add", "staged.py")

    (root / "unstaged.py").write_text(
        'token = "real-secret-token-value"\n',
        encoding="utf-8",
    )

    result = service().collect_and_evaluate(
        ChangePolicyCollectionRequest(
            repository_path=str(root),
            mode="staged",
        )
    )

    assert [
        item.path
        for item in result.change_set.files
    ] == ["staged.py"]
    assert result.policy.decision == "allow"


def test_repository_rule_override_blocks_review(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)

    (root / ".aegis.yml").write_text(
        """
version: 1
rules:
  AEGIS-SHELL-EXECUTION:
    decision: block
""".lstrip(),
        encoding="utf-8",
    )

    (root / "app.py").write_text(
        "import subprocess\n"
        "subprocess.run(command, shell=True)\n",
        encoding="utf-8",
    )

    result = service().collect_and_evaluate(
        ChangePolicyCollectionRequest(
            repository_path=str(root),
            mode="uncommitted",
        )
    )

    assert result.policy.decision == "block"
    assert result.repository_policy.loaded is True
    assert result.repository_policy.rule_overrides == 1


def test_active_waiver_preserves_evidence_but_allows(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)

    (root / ".aegis.yml").write_text(
        """
version: 1
waivers:
  - rule_id: AEGIS-SHELL-EXECUTION
    path: app.py
    reason: Legacy migration tracked in SEC-142
    expires: 2099-08-15
""".lstrip(),
        encoding="utf-8",
    )

    (root / "app.py").write_text(
        "import subprocess\n"
        "subprocess.run(command, shell=True)\n",
        encoding="utf-8",
    )

    result = service().collect_and_evaluate(
        ChangePolicyCollectionRequest(
            repository_path=str(root),
            mode="uncommitted",
        )
    )

    assessment = next(
        item
        for item in result.policy.assessments
        if item.path == "app.py"
    )
    finding = assessment.findings[0]

    assert result.policy.decision == "allow"
    assert finding.waived is True
    assert finding.waiver_reason is not None
    assert result.repository_policy.active_waivers == 1


def test_expired_waiver_is_not_applied(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)

    (root / ".aegis.yml").write_text(
        """
version: 1
waivers:
  - rule_id: AEGIS-SHELL-EXECUTION
    path: app.py
    reason: Legacy migration tracked in SEC-142
    expires: 2020-01-01
""".lstrip(),
        encoding="utf-8",
    )

    (root / "app.py").write_text(
        "import subprocess\n"
        "subprocess.run(command, shell=True)\n",
        encoding="utf-8",
    )

    result = service().collect_and_evaluate(
        ChangePolicyCollectionRequest(
            repository_path=str(root),
            mode="uncommitted",
        )
    )

    finding = result.policy.assessments[
        0
    ].findings[0]

    assert result.policy.decision == "review"
    assert finding.waived is False
    assert finding.waiver_expired is True
    assert result.repository_policy.expired_waivers == 1


def test_repository_profile_is_used_when_cli_omits_it(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)

    (root / ".aegis.yml").write_text(
        "version: 1\nprofile: strict\n",
        encoding="utf-8",
    )

    (root / "app.py").write_text(
        "print('safe')\nprint('changed')\n",
        encoding="utf-8",
    )

    result = service().collect_and_evaluate(
        ChangePolicyCollectionRequest(
            repository_path=str(root),
            mode="uncommitted",
        )
    )

    assert result.policy.profile == "strict"
    assert result.repository_policy.profile == "strict"
