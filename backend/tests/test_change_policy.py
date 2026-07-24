from aegis.schemas.change_policy import (
    ChangePolicyEvaluationRequest,
)
from aegis.schemas.changes import (
    ChangeFile,
    ChangeSet,
)
from aegis.security.change_policy import (
    ChangeAwarePolicyEngine,
)


def change(
    *,
    path: str = "app.py",
    status: str = "modified",
    patch: str = "",
    additions: int = 0,
    deletions: int = 0,
    binary: bool = False,
    truncated: bool = False,
    old_path: str | None = None,
) -> ChangeFile:
    return ChangeFile(
        path=path,
        old_path=old_path,
        status=status,
        patch=patch,
        additions=additions,
        deletions=deletions,
        binary=binary,
        truncated=truncated,
    )


def evaluate(
    *files: ChangeFile,
):
    return ChangeAwarePolicyEngine().evaluate(
        ChangePolicyEvaluationRequest(
            change_set=ChangeSet(
                collector="test",
                repository_root="/tmp/repository",
                mode="staged",
                base_revision="base",
                head_revision="head",
                files=list(files),
                file_count=len(files),
                additions=sum(
                    item.additions
                    for item in files
                ),
                deletions=sum(
                    item.deletions
                    for item in files
                ),
            )
        )
    )


def test_empty_change_set_is_allowed() -> None:
    result = evaluate()

    assert result.decision == "allow"
    assert result.risk_score == 0
    assert result.risk_level == "none"
    assert result.summary.files_evaluated == 0


def test_normal_small_source_change_is_allowed() -> None:
    result = evaluate(
        change(
            patch=(
                "diff --git a/app.py b/app.py\n"
                "+print('safe')\n"
            ),
            additions=1,
        )
    )

    assert result.decision == "allow"
    assert result.assessments[0].risk_score == 0


def test_shell_execution_requires_review() -> None:
    result = evaluate(
        change(
            patch=(
                "diff --git a/app.py b/app.py\n"
                "+subprocess.run(command, shell=True)\n"
            ),
            additions=1,
        )
    )

    assert result.decision == "review"
    assert result.risk_score >= 40
    assert (
        "app.py"
        in result.review_paths
    )


def test_hardcoded_secret_blocks() -> None:
    result = evaluate(
        change(
            path="config.py",
            patch=(
                "diff --git a/config.py b/config.py\n"
                '+api_key = "super-secret-value"\n'
            ),
            additions=1,
        )
    )

    assert result.decision == "block"
    assert result.blocking_paths == [
        "config.py"
    ]


def test_tls_verification_disable_blocks() -> None:
    result = evaluate(
        change(
            patch=(
                "diff --git a/app.py b/app.py\n"
                "+requests.get(url, verify=False)\n"
            ),
            additions=1,
        )
    )

    assert result.decision == "block"


def test_sensitive_auth_change_is_low_risk() -> None:
    result = evaluate(
        change(
            path="src/auth/service.py",
            patch=(
                "diff --git a/src/auth/service.py "
                "b/src/auth/service.py\n"
                "+def validate_user(user):\n"
                "+    return user.is_active\n"
            ),
            additions=2,
        )
    )

    assert result.decision == "allow"
    assert result.risk_score == 25
    assert result.risk_level == "low"
    assert result.summary.sensitive_files == 1


def test_deleted_sensitive_file_requires_review() -> None:
    result = evaluate(
        change(
            path="security/permissions.py",
            status="deleted",
            deletions=20,
        )
    )

    assert result.decision == "review"
    assert result.risk_score == 60


def test_binary_change_requires_review() -> None:
    result = evaluate(
        change(
            path="artifact.bin",
            status="modified",
            binary=True,
        )
    )

    assert result.decision == "review"
    assert result.summary.binary_files == 1


def test_truncated_sensitive_change_requires_review(
) -> None:
    result = evaluate(
        change(
            path="auth/policy.py",
            patch="+safe = True\n",
            additions=1,
            truncated=True,
        )
    )

    assert result.decision == "review"
    assert result.risk_score == 55
    assert result.summary.truncated_files == 1


def test_dependency_manifest_is_low_risk() -> None:
    result = evaluate(
        change(
            path="package.json",
            additions=3,
            deletions=1,
        )
    )

    assert result.decision == "allow"
    assert result.risk_score == 20


def test_large_change_requires_review() -> None:
    result = evaluate(
        change(
            additions=1_000,
        )
    )

    assert result.decision == "review"
    assert result.risk_score == 40
    assert result.risk_level == "medium"
    assert result.review_paths == ["app.py"]


def test_strongest_decision_wins() -> None:
    result = evaluate(
        change(
            path="safe.py",
            additions=1,
        ),
        change(
            path="unsafe.py",
            patch=(
                "diff --git a/unsafe.py b/unsafe.py\n"
                '+token = "real-secret-token-value"\n'
            ),
            additions=1,
        ),
    )

    assert result.decision == "block"
    assert result.blocking_paths == [
        "unsafe.py"
    ]


def test_output_order_is_deterministic() -> None:
    first = evaluate(
        change(
            path="z.py",
            binary=True,
        ),
        change(
            path="a.py",
            binary=True,
        ),
    )
    second = evaluate(
        change(
            path="a.py",
            binary=True,
        ),
        change(
            path="z.py",
            binary=True,
        ),
    )

    assert first == second
    assert [
        item.path
        for item in first.assessments
    ] == [
        "a.py",
        "z.py",
    ]


def test_hardcoded_secret_has_rule_and_location() -> None:
    result = evaluate(
        change(
            path="config.py",
            patch=(
                "diff --git a/config.py b/config.py\n"
                "--- a/config.py\n"
                "+++ b/config.py\n"
                "@@ -1,2 +1,3 @@\n"
                " safe = True\n"
                '+api_key = "super-secret-value"\n'
                " enabled = True\n"
            ),
            additions=1,
        )
    )

    assessment = result.assessments[0]

    assert assessment.rule_id == (
        "AEGIS-HARDCODED-CREDENTIAL"
    )
    assert assessment.start_line == 2
    assert assessment.start_column == 1


def test_shell_execution_has_rule_and_location() -> None:
    result = evaluate(
        change(
            path="runner.py",
            patch=(
                "diff --git a/runner.py b/runner.py\n"
                "--- a/runner.py\n"
                "+++ b/runner.py\n"
                "@@ -8,2 +8,3 @@\n"
                " import subprocess\n"
                "+subprocess.run(command, shell=True)\n"
                " return True\n"
            ),
            additions=1,
        )
    )

    assessment = result.assessments[0]

    assert assessment.rule_id == (
        "AEGIS-SHELL-EXECUTION"
    )
    assert assessment.start_line == 9
    assert assessment.start_column == 25


def test_non_pattern_assessment_has_no_source_location(
) -> None:
    result = evaluate(
        change(
            path="artifact.bin",
            binary=True,
        )
    )

    assessment = result.assessments[0]

    assert assessment.rule_id is None
    assert assessment.start_line is None
    assert assessment.start_column is None
