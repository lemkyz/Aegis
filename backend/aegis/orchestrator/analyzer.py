import re

from aegis.models.factory import (
    create_primary_fallback_model_client,
    create_primary_model_client,
    create_verifier_fallback_model_client,
    create_verifier_model_client,
)
from aegis.models.protocol import (
    SecurityModelClient,
    SecurityVerifierClient,
)
from aegis.security.claim_adapter import finding_to_claim
from aegis.security.model_consensus import (
    ModelConsensusEvaluator,
)
from aegis.security.model_route_policy import (
    ModelRouteIdentity,
    ModelRoutePolicy,
)
from aegis.security.config_secrets import ConfigSecretScanner
from aegis.security.redaction import SecretRedactor
from aegis.security.secrets import SecretIntelligenceEngine
from aegis.schemas.analysis import (
    AnalyzeCodeRequest,
    AnalyzeCodeResponse,
    ScannerEvidence,
    SecurityFinding,
)
from aegis.schemas.claims import SecurityClaim
from aegis.schemas.model_verification import (
    VerifierReviewResult,
)
from aegis.security.bandit import BanditScanner
from aegis.security.eslint import EslintSecurityScanner
from aegis.security.orchestrator import SecurityScannerOrchestrator
from aegis.security.semgrep import SemgrepScanner


class SecurityAnalyzer:
    def __init__(
        self,
        *,
        fingerprint_key: str,
        model_client: SecurityModelClient | None = None,
        verifier_client: SecurityVerifierClient | None = None,
        primary_fallback_client: SecurityModelClient | None = None,
        verifier_fallback_client: SecurityVerifierClient | None = None,
        consensus_evaluator: ModelConsensusEvaluator | None = None,
        route_policy: ModelRoutePolicy | None = None,
    ) -> None:
        self.model_client = (
            model_client
            if model_client is not None
            else create_primary_model_client()
        )
        self.verifier_client = (
            verifier_client
            if verifier_client is not None
            else create_verifier_model_client()
        )
        self.primary_fallback_client = (
            primary_fallback_client
            if primary_fallback_client is not None
            else create_primary_fallback_model_client()
        )
        self.verifier_fallback_client = (
            verifier_fallback_client
            if verifier_fallback_client is not None
            else create_verifier_fallback_model_client()
        )
        self.consensus_evaluator = (
            consensus_evaluator
            if consensus_evaluator is not None
            else ModelConsensusEvaluator()
        )
        self.route_policy = (
            route_policy
            if route_policy is not None
            else ModelRoutePolicy()
        )
        self.semgrep_scanner = SemgrepScanner()
        self.bandit_scanner = BanditScanner()
        self.eslint_scanner = EslintSecurityScanner()

        self.scanner_orchestrator = (
            SecurityScannerOrchestrator(
                [
                    self.semgrep_scanner,
                    self.bandit_scanner,
                    self.eslint_scanner,
                ]
            )
        )

        self.config_scanner = ConfigSecretScanner()
        self.redactor = SecretRedactor()
        self.secret_engine = SecretIntelligenceEngine(
            fingerprint_key=fingerprint_key,
        )

    async def _collect_scanner_evidence(
        self,
        request: AnalyzeCodeRequest,
    ) -> list[ScannerEvidence]:
        orchestration = (
            await self.scanner_orchestrator.scan(
                code=request.code,
                language=request.language,
                filename=request.filename,
            )
        )

        for execution in orchestration.executions:
            if execution.status == "failed":
                print(
                    "Scanner failed without stopping "
                    f"analysis: {execution.name}: "
                    f"{execution.error}"
                )
            else:
                print(
                    f"{execution.name} completed with "
                    f"{execution.evidence_count} "
                    "evidence item(s)."
                )

        evidence = list(
            orchestration.evidence
        )

        evidence.extend(
            self.config_scanner.scan(
                code=request.code,
                language=request.language,
                filename=request.filename,
            )
        )

        unique_evidence: list[
            ScannerEvidence
        ] = []

        seen: set[
            tuple[str, int, int, str]
        ] = set()

        for item in evidence:
            identity = (
                item.rule_id,
                item.line_start,
                item.line_end,
                item.code or "",
            )

            if identity in seen:
                continue

            seen.add(identity)
            unique_evidence.append(item)

        return unique_evidence

    def _scanner_name(
        self,
        request: AnalyzeCodeRequest,
    ) -> str:
        scanners = [
            scanner.name
            for scanner
            in self.scanner_orchestrator.scanners
            if scanner.supports_language(
                request.language
            )
        ]

        if self.config_scanner.supports(
            filename=request.filename,
            language=request.language,
        ):
            scanners.append(
                self.config_scanner.name
            )

        return (
            "+".join(scanners)
            or "not-applicable"
        )

    async def fast_analyze(
        self,
        request: AnalyzeCodeRequest,
    ) -> AnalyzeCodeResponse:
        print("1. Fast Scan: security scanners starting...")

        scanner_evidence = (
            await self._collect_scanner_evidence(
                request
            )
        )

        scanner_evidence = (
            self.secret_engine.enrich_evidence_list(
                scanner_evidence
            )
        )

        print(
            f"2. Fast Scan completed. "
            f"{len(scanner_evidence)} evidence item(s) found."
        )

        redaction_session = self.redactor.create_session()

        safe_scanner_evidence = (
            redaction_session.redact_evidence_list(
                scanner_evidence
            )
        )

        findings = [
            self._scanner_evidence_to_finding(evidence)
            for evidence in safe_scanner_evidence
        ]

        findings = redaction_session.redact_findings(
            findings
        )

        return AnalyzeCodeResponse(
            filename=request.filename,
            language=request.language,
            model="not-used",
            scanner=self._scanner_name(request),
            analysis_status="skipped",
            result_source="scanner",
            findings=findings,
            claims=self._build_claims(
                findings=findings,
                filename=request.filename,
                include_narrative_evidence=False,
            ),
        )

    async def deep_analyze(
        self,
        request: AnalyzeCodeRequest,
    ) -> AnalyzeCodeResponse:
        print("1. Deep Analysis: security scanners starting...")

        scanner_evidence = (
            await self._collect_scanner_evidence(
                request
            )
        )

        scanner_evidence = (
            self.secret_engine.enrich_evidence_list(
                scanner_evidence
            )
        )

        print(
            f"2. Security scanners completed. "
            f"{len(scanner_evidence)} evidence item(s) found."
        )

        if not scanner_evidence:
            print(
                "3. No scanner evidence found. "
                "The NVIDIA model was not called."
            )

            return AnalyzeCodeResponse(
                filename=request.filename,
                language=request.language,
                model="not-used",
                scanner=self._scanner_name(request),
                analysis_status="skipped",
                result_source="scanner",
                findings=[],
                claims=[],
            )

        redaction_session = self.redactor.create_session()

        safe_scanner_evidence = (
            redaction_session.redact_evidence_list(
                scanner_evidence
            )
        )

        relevant_code = self._build_relevant_context(
            code=request.code,
            scanner_evidence=scanner_evidence,
            context_lines=20,
        )

        safe_relevant_code = (
            redaction_session.redact_text(
                relevant_code
            )
            or relevant_code
        )

        original_line_count = len(request.code.splitlines())
        relevant_line_count = len(relevant_code.splitlines())

        print(
            "3. Security context prepared: "
            f"{relevant_line_count}/{original_line_count} lines "
            "will be sent to the NVIDIA model."
        )
        print("4. NVIDIA deep analysis starting...")

        active_primary_client = self.model_client

        try:
            findings = (
                await active_primary_client.analyze_security(
                    code=safe_relevant_code,
                    language=request.language,
                    filename=request.filename,
                    scanner_evidence=safe_scanner_evidence,
                )
            )

            findings = redaction_session.redact_findings(
                findings
            )
        except Exception as primary_error:
            print(
                "5. Primary model analysis failed safely: "
                f"{primary_error}"
            )

            fallback_error: Exception | None = None

            if self.primary_fallback_client is not None:
                print(
                    "5. Explicit primary fallback route "
                    "starting..."
                )

                try:
                    active_primary_client = (
                        self.primary_fallback_client
                    )
                    findings = (
                        await active_primary_client.analyze_security(
                            code=safe_relevant_code,
                            language=request.language,
                            filename=request.filename,
                            scanner_evidence=(
                                safe_scanner_evidence
                            ),
                        )
                    )

                    findings = (
                        redaction_session.redact_findings(
                            findings
                        )
                    )

                    print(
                        "5. Explicit primary fallback route "
                        "completed."
                    )
                except Exception as exc:
                    fallback_error = exc
                    print(
                        "5. Explicit primary fallback route "
                        f"failed safely: {exc}"
                    )

            if (
                self.primary_fallback_client is None
                or fallback_error is not None
            ):
                print(
                    "5. Falling back to deterministic "
                    "scanner findings."
                )

                findings = [
                    self._scanner_evidence_to_finding(
                        evidence,
                        source_code=request.code,
                        allow_local_patch=True,
                    )
                    for evidence in safe_scanner_evidence
                ]

                findings = (
                    redaction_session.redact_findings(
                        findings
                    )
                )

                for finding in findings:
                    finding.false_positive_notes.append(
                        "AI review was unavailable or returned "
                        "an invalid response. This result is "
                        "based on deterministic scanner evidence."
                    )

                attempted_models = [
                    self.model_client.model,
                ]

                if self.primary_fallback_client is not None:
                    attempted_models.append(
                        self.primary_fallback_client.model
                    )

                return AnalyzeCodeResponse(
                    filename=request.filename,
                    language=request.language,
                    model=(
                        " -> ".join(attempted_models)
                        + " (scanner fallback)"
                    ),
                    scanner=self._scanner_name(request),
                    analysis_status="fallback",
                    result_source="scanner_fallback",
                    findings=findings,
                    claims=self._build_claims(
                        findings=findings,
                        filename=request.filename,
                        include_narrative_evidence=False,
                    ),
                )

        print(
            "5. Primary model analysis completed. "
            f"{len(findings)} finding(s) returned."
        )

        print(
            "6. Independent model verification starting..."
        )

        active_verifier_client = self.verifier_client

        try:
            verifier_result = (
                await active_verifier_client.verify_findings(
                    code=safe_relevant_code,
                    language=request.language,
                    filename=request.filename,
                    scanner_evidence=(
                        safe_scanner_evidence
                    ),
                    primary_findings=findings,
                )
            )

            print(
                "7. Independent model verification "
                "completed. "
                f"{len(verifier_result.verifications)} "
                "decision(s) returned."
            )
        except Exception as verifier_error:
            print(
                "7. Verifier model failed safely: "
                f"{verifier_error}"
            )

            fallback_error: Exception | None = None

            if self.verifier_fallback_client is not None:
                print(
                    "7. Explicit verifier fallback route "
                    "starting..."
                )

                try:
                    active_verifier_client = (
                        self.verifier_fallback_client
                    )
                    verifier_result = (
                        await active_verifier_client.verify_findings(
                            code=safe_relevant_code,
                            language=request.language,
                            filename=request.filename,
                            scanner_evidence=(
                                safe_scanner_evidence
                            ),
                            primary_findings=findings,
                        )
                    )

                    print(
                        "7. Explicit verifier fallback route "
                        "completed."
                    )
                except Exception as exc:
                    fallback_error = exc
                    print(
                        "7. Explicit verifier fallback route "
                        f"failed safely: {exc}"
                    )

            if (
                self.verifier_fallback_client is None
                or fallback_error is not None
            ):
                errors = [str(verifier_error)]

                if fallback_error is not None:
                    errors.append(str(fallback_error))

                verifier_result = VerifierReviewResult(
                    model=active_verifier_client.model,
                    status="failed",
                    error="; ".join(errors),
                )

        primary_transport = getattr(
            active_primary_client,
            "transport",
            None,
        )
        verifier_transport = getattr(
            active_verifier_client,
            "transport",
            None,
        )

        route_assessment = self.route_policy.assess(
            primary=ModelRouteIdentity(
                provider=getattr(
                    active_primary_client,
                    "provider",
                    "unknown",
                ),
                model=active_primary_client.model,
                base_url=getattr(
                    primary_transport,
                    "base_url",
                    "unknown",
                ),
            ),
            verifier=ModelRouteIdentity(
                provider=getattr(
                    active_verifier_client,
                    "provider",
                    "unknown",
                ),
                model=active_verifier_client.model,
                base_url=getattr(
                    verifier_transport,
                    "base_url",
                    "unknown",
                ),
            ),
        )

        consensus = self.consensus_evaluator.evaluate(
            primary_provider=getattr(
                active_primary_client,
                "provider",
                None,
            ),
            primary_model=active_primary_client.model,
            verifier_provider=getattr(
                active_verifier_client,
                "provider",
                None,
            ),
            primary_findings=findings,
            verifier_result=verifier_result,
            route_assessment=route_assessment,
        )

        verifications_by_index = {}

        for verification in verifier_result.verifications:
            if verification.finding_index >= len(findings):
                continue

            verifications_by_index.setdefault(
                verification.finding_index,
                verification,
            )

        for decision in consensus.decisions:
            if decision.finding_index >= len(findings):
                continue

            finding = findings[decision.finding_index]
            verification = verifications_by_index.get(
                decision.finding_index
            )

            finding.primary_model = self.model_client.model
            finding.verifier_model = consensus.verifier_model
            finding.consensus_verdict = decision.verdict
            finding.consensus_confidence = (
                decision.confidence
            )
            finding.consensus_reasons = list(
                decision.reasons
            )
            finding.verifier_confidence = (
                decision.verifier_confidence
            )

            if verification is not None:
                finding.verifier_verdict = (
                    verification.verdict
                )
                finding.verifier_reasoning = (
                    verification.reasoning
                )
                finding.verifier_evidence = list(
                    verification.evidence
                )

        print(
            "8. Deterministic model consensus completed: "
            f"{consensus.status}."
        )

        return AnalyzeCodeResponse(
            filename=request.filename,
            language=request.language,
            model=active_primary_client.model,
            scanner=self._scanner_name(request),
            analysis_status="completed",
            result_source="ai",
            findings=findings,
            claims=self._build_claims(
                findings=findings,
                filename=request.filename,
            ),
            model_consensus=consensus,
        )

    @staticmethod
    def _build_claims(
        *,
        findings: list[SecurityFinding],
        filename: str,
        include_narrative_evidence: bool = True,
    ) -> list[SecurityClaim]:
        return [
            finding_to_claim(
                finding,
                filename=filename,
                include_narrative_evidence=(
                    include_narrative_evidence
                ),
            )
            for finding in findings
        ]

    async def analyze(
        self,
        request: AnalyzeCodeRequest,
    ) -> AnalyzeCodeResponse:
        """
        Backward-compatible method used by older extension versions.
        """
        return await self.deep_analyze(request)

    @staticmethod
    def _build_relevant_context(
        *,
        code: str,
        scanner_evidence: list[ScannerEvidence],
        context_lines: int,
    ) -> str:
        source_lines = code.splitlines()

        if not source_lines:
            return code

        ranges: list[tuple[int, int]] = []

        for evidence in scanner_evidence:
            start_index = max(
                evidence.line_start - 1 - context_lines,
                0,
            )
            end_index = min(
                evidence.line_end + context_lines,
                len(source_lines),
            )

            ranges.append((start_index, end_index))

        ranges.sort()

        merged_ranges: list[tuple[int, int]] = []

        for start_index, end_index in ranges:
            if not merged_ranges:
                merged_ranges.append((start_index, end_index))
                continue

            previous_start, previous_end = merged_ranges[-1]

            if start_index <= previous_end:
                merged_ranges[-1] = (
                    previous_start,
                    max(previous_end, end_index),
                )
            else:
                merged_ranges.append((start_index, end_index))

        sections: list[str] = []

        for start_index, end_index in merged_ranges:
            start_line = start_index + 1
            end_line = end_index

            excerpt = "\n".join(
                source_lines[start_index:end_index]
            )

            sections.append(
                f"--- ORIGINAL FILE LINES "
                f"{start_line}-{end_line} ---\n"
                f"{excerpt}"
            )

        return "\n\n".join(sections)

    @staticmethod
    def _build_local_scanner_patch(
        *,
        rule_id: str,
        source_code: str,
    ) -> str | None:
        """
        Produces conservative deterministic patches for narrowly
        understood Semgrep patterns.

        Unsupported or ambiguous code returns None.
        """

        if (
            rule_id
            == "aegis.python.command-injection.subprocess-shell"
        ):
            assignment_pattern = re.compile(
                r"""(?mx)
                ^
                (?P<indent>[ \t]*)
                (?P<command>[A-Za-z_][A-Za-z0-9_]*)
                \s*=\s*f
                (?P<outer_quote>["'])
                printf[ ]
                (?P<format_quote>["'])
                %s
                (?P=format_quote)
                [ ]
                \{
                (?P<parameter>[A-Za-z_][A-Za-z0-9_]*)
                \}
                (?P=outer_quote)
                [ \t]*
                $
                """
            )

            assignment = assignment_pattern.search(
                source_code
            )

            if assignment is None:
                return None

            command_name = assignment.group("command")
            parameter_name = assignment.group("parameter")
            indent = assignment.group("indent")

            shell_matches = re.findall(
                r"\bshell\s*=\s*True\b",
                source_code,
            )

            if len(shell_matches) != 1:
                return None

            command_use_pattern = re.compile(
                rf"""(?x)
                subprocess\.run
                \(
                \s*
                {re.escape(command_name)}
                \s*,
                [\s\S]*?
                shell\s*=\s*True
                [\s\S]*?
                \)
                """
            )

            if (
                command_use_pattern.search(source_code)
                is None
            ):
                return None

            secure_assignment = (
                f'{indent}{command_name} = '
                f'["printf", "%s", {parameter_name}]'
            )

            patched_code = (
                source_code[:assignment.start()]
                + secure_assignment
                + source_code[assignment.end():]
            )

            patched_code, shell_replacements = (
                re.subn(
                    r"\bshell\s*=\s*True\b",
                    "shell=False",
                    patched_code,
                    count=1,
                )
            )

            if (
                shell_replacements != 1
                or patched_code == source_code
            ):
                return None

            return patched_code

        if (
            rule_id
            != "aegis.python.sql-injection.formatted-query"
        ):
            return None

        assignment_pattern = re.compile(
            r"""(?mx)
            ^
            (?P<indent>[ \t]*)
            (?P<query>[A-Za-z_][A-Za-z0-9_]*)
            \s*=\s*f
            (?P<quote>["'])
            (?P<before>[^\r\n]*?)
            \{
            (?P<parameter>[A-Za-z_][A-Za-z0-9_]*)
            \}
            (?P<after>[^\r\n]*?)
            (?P=quote)
            [ \t]*
            $
            """
        )

        assignment = assignment_pattern.search(
            source_code
        )

        if assignment is None:
            return None

        query_name = assignment.group("query")
        parameter_name = assignment.group("parameter")
        quote = assignment.group("quote")

        parameter_occurrences = len(
            re.findall(
                rf"\{{\s*{re.escape(parameter_name)}\s*\}}",
                assignment.group(0),
            )
        )

        if parameter_occurrences != 1:
            return None

        parameterized_sql = (
            assignment.group("before")
            + "?"
            + assignment.group("after")
        )

        secure_assignment = (
            f"{assignment.group('indent')}"
            f"{query_name} = "
            f"{quote}{parameterized_sql}{quote}"
        )

        patched_code = (
            source_code[:assignment.start()]
            + secure_assignment
            + source_code[assignment.end():]
        )

        execute_pattern = re.compile(
            rf"""(?x)
            (?P<prefix>
                \.execute
                \(
                \s*
                {re.escape(query_name)}
                \s*
            )
            \)
            """
        )

        patched_code, replacement_count = (
            execute_pattern.subn(
                rf"\g<prefix>, ({parameter_name},))",
                patched_code,
                count=1,
            )
        )

        if replacement_count != 1:
            return None

        if patched_code == source_code:
            return None

        return patched_code

    @classmethod
    def _scanner_evidence_to_finding(
        cls,
        evidence: ScannerEvidence,
        *,
        source_code: str | None = None,
        allow_local_patch: bool = False,
    ) -> SecurityFinding:
        severity_map = {
            "INFO": "info",
            "WARNING": "medium",
            "ERROR": "high",
        }

        severity = severity_map.get(
            evidence.severity.upper(),
            "medium",
        )

        corroborating_tools = list(
            dict.fromkeys(
                evidence.corroborated_by
                or [evidence.tool]
            )
        )

        confidence = (
            0.95
            if len(corroborating_tools) >= 2
            else 0.85
        )

        recommended_fix = (
            "Review the flagged code and run Deep Analysis "
            "for a context-aware remediation recommendation."
        )
        additional_notes: list[str] = []

        if len(corroborating_tools) >= 2:
            additional_notes.append(
                "Cross-validated by "
                f"{len(corroborating_tools)} scanners: "
                + ", ".join(corroborating_tools)
                + "."
            )

            if evidence.related_rule_ids:
                additional_notes.append(
                    "Correlated rules: "
                    + ", ".join(
                        evidence.related_rule_ids
                    )
                    + "."
                )

        if evidence.secret:
            confidence = evidence.secret.confidence
            recommended_fix = evidence.secret.remediation

            additional_notes.append(
                "Secret classification: "
                f"{evidence.secret.provider} / "
                f"{evidence.secret.secret_type}."
            )

            if evidence.secret.fingerprint:
                additional_notes.append(
                    "Protected fingerprint: "
                    f"{evidence.secret.fingerprint}."
                )

            if evidence.secret.likely_placeholder:
                severity = "low"
                additional_notes.append(
                    "The value appears to be example, test, or "
                    "placeholder data. Confirm that no production "
                    "credential is present."
                )
            elif evidence.secret.rotation_required:
                additional_notes.append(
                    "Credential rotation is recommended."
                )

        rule_parts = evidence.rule_id.split(".")

        if (
            len(rule_parts) >= 3
            and rule_parts[0] == "aegis"
        ):
            rule_parts = rule_parts[2:]

        title = (
            " ".join(rule_parts)
            .replace("-", " ")
            .title()
        )

        proposed_patch: str | None = None

        if allow_local_patch and source_code:
            proposed_patch = (
                cls._build_local_scanner_patch(
                    rule_id=evidence.rule_id,
                    source_code=source_code,
                )
            )

            if proposed_patch:
                recommended_fix = (
                    "Replace SQL string interpolation with a "
                    "parameterized query and pass values separately "
                    "to the database driver."
                )

                additional_notes.append(
                    "The AI review was unavailable, so Aegis produced "
                    "a deterministic local patch from the verified "
                    "Semgrep rule. Review the diff before applying it."
                )

        return SecurityFinding(
            title=title,
            severity=severity,
            confidence=confidence,
            summary=evidence.message,
            evidence=[
                (
                    f"{evidence.tool} matched rule "
                    f"{evidence.rule_id} on lines "
                    f"{evidence.line_start}-{evidence.line_end}."
                )
            ],
            scanner_evidence=[evidence],
            cwe=evidence.cwe,
            owasp=evidence.owasp,
            vulnerable_lines=list(
                range(
                    evidence.line_start,
                    evidence.line_end + 1,
                )
            ),
            false_positive_notes=[
                (
                    "This is a scanner-only result. "
                    "Run Deep Analysis for AI review, "
                    "context evaluation, and a proposed patch."
                ),
                *additional_notes,
            ],
            recommended_fix=recommended_fix,
            proposed_patch=proposed_patch,
        )
