from __future__ import annotations

import re
from dataclasses import dataclass

from aegis.schemas.change_policy import (
    ChangeFilePolicyAssessment,
    ChangePolicyDecisionResponse,
    ChangePolicyEvaluationRequest,
    ChangePolicySummary,
)
from aegis.schemas.changes import ChangeFile
from aegis.schemas.policy import (
    PolicyDecision,
    PolicyRiskLevel,
)


@dataclass(frozen=True)
class _PatternRule:
    rule_id: str
    expression: re.Pattern[str]
    score: int
    reason: str
    blocking: bool = False


class ChangeAwarePolicyEngine:
    """
    Deterministically evaluates Git changes without an AI
    model or executing repository code.
    """

    name = "aegis-change-aware-policy-engine-v1"
    policy_version = "1.0"

    _sensitive_path_patterns = (
        re.compile(
            r"(^|/)(auth|authentication|authorization|"
            r"permissions?|rbac|iam)(/|\.|$)",
            re.IGNORECASE,
        ),
        re.compile(
            r"(^|/)(security|crypto|encryption|signing|"
            r"certificates?)(/|\.|$)",
            re.IGNORECASE,
        ),
        re.compile(
            r"(^|/)(\.github/workflows|ci|cd|deploy|"
            r"terraform|kubernetes|helm)(/|\.|$)",
            re.IGNORECASE,
        ),
        re.compile(
            r"(^|/)(\.env|secrets?|credentials?|"
            r"private[_-]?key)(\.|/|$)",
            re.IGNORECASE,
        ),
    )

    _dependency_files = {
        "package.json",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "requirements.txt",
        "requirements-dev.txt",
        "pyproject.toml",
        "poetry.lock",
        "pipfile",
        "pipfile.lock",
        "cargo.toml",
        "cargo.lock",
        "go.mod",
        "go.sum",
        "pom.xml",
        "build.gradle",
        "composer.json",
        "composer.lock",
    }

    _pattern_rules = (
        _PatternRule(
            rule_id="AEGIS-SHELL-EXECUTION",
            expression=re.compile(
                r"\bshell\s*=\s*true\b",
                re.IGNORECASE,
            ),
            score=55,
            reason=(
                "The patch enables shell-based process "
                "execution."
            ),
        ),
        _PatternRule(
            rule_id="AEGIS-DYNAMIC-EXECUTION",
            expression=re.compile(
                r"\b(?:os\.system|os\.popen|"
                r"child_process\.exec(?:sync)?|"
                r"\beval|\bexec)\s*\(",
                re.IGNORECASE,
            ),
            score=55,
            reason=(
                "The patch introduces a dangerous dynamic "
                "execution primitive."
            ),
        ),
        _PatternRule(
            rule_id="AEGIS-TLS-VERIFICATION-DISABLED",
            expression=re.compile(
                r"\bverify\s*=\s*false\b|"
                r"\brejectUnauthorized\s*:\s*false\b|"
                r"\bNODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0",
                re.IGNORECASE,
            ),
            score=65,
            reason=(
                "The patch disables TLS certificate "
                "verification."
            ),
            blocking=True,
        ),
        _PatternRule(
            rule_id="AEGIS-WORLD-WRITABLE-PERMISSIONS",
            expression=re.compile(
                r"\bchmod\s+(?:-R\s+)?777\b|"
                r"\bos\.chmod\s*\([^,\n]+,\s*0?777\s*\)",
                re.IGNORECASE,
            ),
            score=50,
            reason=(
                "The patch introduces globally writable "
                "permissions."
            ),
        ),
        _PatternRule(
            rule_id="AEGIS-WILDCARD-CLOUD-PERMISSIONS",
            expression=re.compile(
                r"Action\s*:\s*['\"]?\*['\"]?|"
                r"Resource\s*:\s*['\"]?\*['\"]?",
                re.IGNORECASE,
            ),
            score=55,
            reason=(
                "The patch introduces wildcard cloud "
                "permissions."
            ),
        ),
        _PatternRule(
            rule_id="AEGIS-HARDCODED-CREDENTIAL",
            expression=re.compile(
                r"(?i)(password|api[_-]?key|secret|token)"
                r"\s*[:=]\s*['\"][^'\"\n]{8,}['\"]"
            ),
            score=85,
            reason=(
                "The patch appears to introduce a "
                "hard-coded credential."
            ),
            blocking=True,
        ),
    )

    def evaluate(
        self,
        request: ChangePolicyEvaluationRequest,
    ) -> ChangePolicyDecisionResponse:
        assessments = [
            self._evaluate_file(change)
            for change in request.change_set.files
        ]

        assessments.sort(
            key=lambda item: (
                -item.risk_score,
                item.path,
            )
        )

        blocking_paths = [
            item.path
            for item in assessments
            if item.decision == "block"
        ]
        review_paths = [
            item.path
            for item in assessments
            if item.decision == "review"
        ]

        highest_score = max(
            (
                item.risk_score
                for item in assessments
            ),
            default=0,
        )
        highest_level = self._risk_level(
            highest_score
        )

        if blocking_paths:
            decision: PolicyDecision = "block"
        elif review_paths:
            decision = "review"
        else:
            decision = "allow"

        reasons = self._overall_reasons(
            decision=decision,
            blocking_paths=blocking_paths,
            review_paths=review_paths,
        )

        return ChangePolicyDecisionResponse(
            engine=self.name,
            policy_version=self.policy_version,
            profile=request.profile,
            decision=decision,
            risk_score=highest_score,
            risk_level=highest_level,
            blocking_paths=blocking_paths,
            review_paths=review_paths,
            assessments=assessments,
            summary=ChangePolicySummary(
                files_evaluated=len(assessments),
                allowed=sum(
                    item.decision == "allow"
                    for item in assessments
                ),
                review_required=sum(
                    item.decision == "review"
                    for item in assessments
                ),
                blocked=sum(
                    item.decision == "block"
                    for item in assessments
                ),
                highest_risk_score=highest_score,
                highest_risk_level=highest_level,
                sensitive_files=sum(
                    self._is_sensitive_path(
                        item.path
                    )
                    for item in request.change_set.files
                ),
                dangerous_patterns=sum(
                    self._contains_dangerous_pattern(
                        item.patch
                    )
                    for item in request.change_set.files
                ),
                truncated_files=sum(
                    item.truncated
                    for item in request.change_set.files
                ),
                binary_files=sum(
                    item.binary
                    for item in request.change_set.files
                ),
            ),
            reasons=reasons,
        )

    def _evaluate_file(
        self,
        change: ChangeFile,
    ) -> ChangeFilePolicyAssessment:
        score = 0
        reasons: list[str] = []
        forced_block = False
        matched_rule_id: str | None = None
        matched_line: int | None = None
        matched_column: int | None = None

        if self._is_sensitive_path(change.path):
            score += 25
            reasons.append(
                "The file is security-sensitive."
            )

        if self._is_dependency_file(change.path):
            score += 20
            reasons.append(
                "The change modifies a dependency "
                "manifest or lockfile."
            )

        if (
            change.status == "deleted"
            and self._is_sensitive_path(change.path)
        ):
            score += 35
            reasons.append(
                "A security-sensitive file is deleted."
            )

        if (
            change.status == "renamed"
            and (
                self._is_sensitive_path(change.path)
                or (
                    change.old_path is not None
                    and self._is_sensitive_path(
                        change.old_path
                    )
                )
            )
        ):
            score += 15
            reasons.append(
                "A security-sensitive file is renamed."
            )

        if change.binary:
            score += 40
            reasons.append(
                "The binary change cannot be reviewed "
                "from textual evidence."
            )

        if change.truncated:
            score += 30
            reasons.append(
                "The patch was truncated and requires "
                "human review."
            )

        total_lines = (
            change.additions
            + change.deletions
        )

        if total_lines >= 1_000:
            score += 40
            reasons.append(
                "The file contains at least 1,000 changed "
                "lines and requires human review."
            )
        elif total_lines >= 300:
            score += 20
            reasons.append(
                "The file contains a large change."
            )
        elif total_lines >= 100:
            score += 10
            reasons.append(
                "The file contains a moderately large "
                "change."
            )

        added_lines = self._added_patch_lines(
            change.patch
        )
        added_patch_lines = (
            self._added_patch_lines_with_locations(
                change.patch
            )
        )

        for rule in self._pattern_rules:
            match = rule.expression.search(
                added_lines
            )

            if match is None:
                continue

            score += rule.score
            reasons.append(rule.reason)
            forced_block = (
                forced_block
                or rule.blocking
            )

            if matched_rule_id is None:
                matched_rule_id = rule.rule_id

                for (
                    line_number,
                    line_text,
                ) in added_patch_lines:
                    line_match = rule.expression.search(
                        line_text
                    )

                    if line_match is None:
                        continue

                    matched_line = line_number
                    matched_column = (
                        line_match.start() + 1
                    )
                    break

        score = min(score, 100)

        decision = self._decision(
            score=score,
            forced_block=forced_block,
        )

        if not reasons:
            reasons.append(
                "No elevated deterministic change risk "
                "was detected."
            )

        return ChangeFilePolicyAssessment(
            path=change.path,
            old_path=change.old_path,
            status=change.status,
            risk_score=score,
            risk_level=self._risk_level(score),
            decision=decision,
            rule_id=matched_rule_id,
            start_line=matched_line,
            start_column=matched_column,
            reasons=reasons,
        )

    @staticmethod
    def _added_patch_lines_with_locations(
        patch: str,
    ) -> list[tuple[int, str]]:
        located_lines: list[tuple[int, str]] = []
        new_line_number: int | None = None

        hunk_pattern = re.compile(
            r"^@@ -\d+(?:,\d+)? "
            r"\+(\d+)(?:,\d+)? @@"
        )

        for line in patch.splitlines():
            hunk_match = hunk_pattern.match(line)

            if hunk_match is not None:
                new_line_number = int(
                    hunk_match.group(1)
                )
                continue

            if new_line_number is None:
                continue

            if line.startswith("+++"):
                continue

            if line.startswith("+"):
                located_lines.append(
                    (
                        new_line_number,
                        line[1:],
                    )
                )
                new_line_number += 1
                continue

            if line.startswith("-"):
                continue

            if line.startswith("\\ No newline"):
                continue

            new_line_number += 1

        return located_lines


    @classmethod
    def _contains_dangerous_pattern(
        cls,
        patch: str,
    ) -> bool:
        added_lines = cls._added_patch_lines(
            patch
        )

        return any(
            rule.expression.search(added_lines)
            is not None
            for rule in cls._pattern_rules
        )

    @staticmethod
    def _added_patch_lines(
        patch: str,
    ) -> str:
        return "\n".join(
            line[1:]
            for line in patch.splitlines()
            if line.startswith("+")
            and not line.startswith("+++")
        )

    @classmethod
    def _is_sensitive_path(
        cls,
        path: str,
    ) -> bool:
        normalized = path.replace("\\", "/")

        return any(
            pattern.search(normalized)
            is not None
            for pattern in cls._sensitive_path_patterns
        )

    @classmethod
    def _is_dependency_file(
        cls,
        path: str,
    ) -> bool:
        filename = (
            path.replace("\\", "/")
            .rsplit("/", maxsplit=1)[-1]
            .lower()
        )

        return filename in cls._dependency_files

    @staticmethod
    def _decision(
        *,
        score: int,
        forced_block: bool,
    ) -> PolicyDecision:
        if forced_block or score >= 80:
            return "block"

        if score >= 40:
            return "review"

        return "allow"

    @staticmethod
    def _risk_level(
        score: int,
    ) -> PolicyRiskLevel:
        if score >= 90:
            return "critical"

        if score >= 70:
            return "high"

        if score >= 40:
            return "medium"

        if score >= 1:
            return "low"

        return "none"

    @staticmethod
    def _overall_reasons(
        *,
        decision: PolicyDecision,
        blocking_paths: list[str],
        review_paths: list[str],
    ) -> list[str]:
        if decision == "block":
            return [
                (
                    f"{len(blocking_paths)} changed "
                    "file(s) triggered a blocking "
                    "security policy."
                )
            ]

        if decision == "review":
            return [
                (
                    f"{len(review_paths)} changed "
                    "file(s) require human review."
                )
            ]

        return [
            (
                "The collected change set passed all "
                "deterministic change-policy checks."
            )
        ]
