from aegis.orchestrator.security_task_policy import (
    SecurityTaskPlanningPolicy,
)
from aegis.security.authorization import (
    ValidationAuthorizer,
)
from aegis.schemas.security_task_plan import (
    SecurityTaskDependency,
    SecurityTaskNode,
    SecurityTaskPlanRequest,
    SecurityTaskPlanResponse,
)


class SecurityTaskPlanner:
    planner = "aegis-security-task-planner-v1"

    def __init__(
        self,
        *,
        policy: SecurityTaskPlanningPolicy | None = None,
        authorizer: ValidationAuthorizer | None = None,
    ) -> None:
        self._policy = (
            policy
            if policy is not None
            else SecurityTaskPlanningPolicy()
        )
        self._authorizer = (
            authorizer
            if authorizer is not None
            else ValidationAuthorizer()
        )

    def plan(
        self,
        request: SecurityTaskPlanRequest,
    ) -> SecurityTaskPlanResponse:
        policy_decision = self._policy.evaluate(
            request
        )

        if request.operation == "fast_scan":
            tasks = self._fast_scan_tasks(request)

        elif request.operation == "deep_analysis":
            tasks = self._deep_analysis_tasks(request)

        elif request.operation == "repository_review":
            tasks = self._repository_review_tasks(
                request
            )

        else:
            tasks = self._fix_and_verify_tasks(
                request
            )

        task_ids = {
            task.task_id
            for task in tasks
        }

        depended_on = {
            dependency.task_id
            for task in tasks
            for dependency in task.dependencies
        }

        entry_task_ids = [
            task.task_id
            for task in tasks
            if not task.dependencies
        ]

        terminal_task_ids = [
            task.task_id
            for task in tasks
            if task.task_id not in depended_on
        ]

        blocked = [
            task
            for task in tasks
            if task.state == "blocked"
        ]

        ready = [
            task
            for task in tasks
            if task.state == "ready"
        ]

        operation_root_blocked = any(
            task.task_id == "secure_fix"
            and task.state == "blocked"
            for task in tasks
        )

        if operation_root_blocked:
            status = "blocked"
        elif blocked:
            status = (
                "partial"
                if ready
                else "blocked"
            )
        else:
            status = "ready"

        reasons = [
            (
                f"{len(tasks)} security task(s) "
                "were planned deterministically."
            ),
            *policy_decision.reasons,
        ]

        if blocked:
            reasons.append(
                f"{len(blocked)} task(s) require an "
                "unmet authorization or approval gate."
            )

        return SecurityTaskPlanResponse(
            planner=self.planner,
            operation=request.operation,
            status=status,
            tasks=tasks,
            entry_task_ids=entry_task_ids,
            terminal_task_ids=terminal_task_ids,
            reasons=reasons,
        )

    @staticmethod
    def _dependency(
        task_id: str,
    ) -> SecurityTaskDependency:
        return SecurityTaskDependency(
            task_id=task_id,
        )

    @staticmethod
    def _context_task() -> SecurityTaskNode:
        return SecurityTaskNode(
            task_id="repository_context",
            kind="repository_context",
            state="ready",
            reasons=[
                "Repository context is required before "
                "security analysis tasks."
            ],
            produces=[
                "repository_context",
            ],
        )

    def _fast_scan_tasks(
        self,
        request: SecurityTaskPlanRequest,
    ) -> list[SecurityTaskNode]:
        del request

        return [
            self._context_task(),
            SecurityTaskNode(
                task_id="deterministic_scan",
                kind="deterministic_scan",
                state="waiting",
                dependencies=[
                    self._dependency(
                        "repository_context"
                    )
                ],
                reasons=[
                    "Fast Scan uses local deterministic "
                    "security scanners only."
                ],
                produces=[
                    "scanner_coverage",
                    "scanner_evidence",
                    "scanner_findings",
                ],
            ),
        ]

    def _deep_analysis_tasks(
        self,
        request: SecurityTaskPlanRequest,
    ) -> list[SecurityTaskNode]:
        evidence_state = (
            "waiting"
            if request.has_scanner_evidence
            else "skipped"
        )

        evidence_reason = (
            "Scanner evidence is available for "
            "AI-assisted review."
            if request.has_scanner_evidence
            else (
                "AI review is skipped because no "
                "scanner evidence is available."
            )
        )

        tasks = [
            self._context_task(),
            SecurityTaskNode(
                task_id="deterministic_scan",
                kind="deterministic_scan",
                state="waiting",
                dependencies=[
                    self._dependency(
                        "repository_context"
                    )
                ],
                produces=[
                    "scanner_coverage",
                    "scanner_evidence",
                    "scanner_findings",
                ],
            ),
            SecurityTaskNode(
                task_id="primary_model_review",
                kind="primary_model_review",
                state=evidence_state,
                dependencies=[
                    self._dependency(
                        "deterministic_scan"
                    )
                ],
                gates=[
                    "scanner_evidence",
                    "ai_available",
                ],
                reasons=[
                    evidence_reason,
                ],
                produces=[
                    "primary_findings",
                    "primary_model_route",
                ],
            ),
            SecurityTaskNode(
                task_id="verifier_review",
                kind="verifier_review",
                state=evidence_state,
                dependencies=[
                    self._dependency(
                        "primary_model_review"
                    )
                ],
                gates=[
                    "scanner_evidence",
                    "ai_available",
                ],
                reasons=[
                    evidence_reason,
                ],
                produces=[
                    "verifier_decisions",
                    "verifier_model_route",
                ],
            ),
            SecurityTaskNode(
                task_id="model_consensus",
                kind="model_consensus",
                state=evidence_state,
                dependencies=[
                    self._dependency(
                        "primary_model_review"
                    ),
                    self._dependency(
                        "verifier_review"
                    ),
                ],
                reasons=[
                    (
                        "Consensus requires primary and "
                        "verifier results."
                    )
                ],
                produces=[
                    "consensus_decisions",
                    "consensus_claims",
                    "verified_findings",
                ],
            ),
        ]

        policy_decision = self._policy.evaluate(
            request
        )

        post_consensus_dependency = (
            "model_consensus"
        )

        if policy_decision.require_threat_model:
            tasks.append(
                SecurityTaskNode(
                    task_id="threat_model",
                    kind="threat_model",
                    state=evidence_state,
                    dependencies=[
                        self._dependency(
                            "model_consensus"
                        )
                    ],
                    reasons=[
                        *policy_decision.reasons,
                    ],
                    produces=[
                        "threat_model",
                    ],
                )
            )
            post_consensus_dependency = (
                "threat_model"
            )

        if request.include_security_memory:
            tasks.append(
                SecurityTaskNode(
                    task_id="security_memory",
                    kind="security_memory",
                    state="waiting",
                    dependencies=[
                        self._dependency(
                            post_consensus_dependency
                        )
                    ],
                    reasons=[
                        "Security memory stores the "
                        "resulting claim state."
                    ],
                    produces=[
                        "security_snapshot",
                    ],
                )
            )

        if request.include_policy_evaluation:
            dependency = (
                "security_memory"
                if request.include_security_memory
                else post_consensus_dependency
            )

            tasks.append(
                SecurityTaskNode(
                    task_id="policy_evaluation",
                    kind="policy_evaluation",
                    state="waiting",
                    dependencies=[
                        self._dependency(dependency)
                    ],
                    produces=[
                        "policy_decision",
                    ],
                )
            )

        return tasks

    def _repository_review_tasks(
        self,
        request: SecurityTaskPlanRequest,
    ) -> list[SecurityTaskNode]:
        tasks = [
            self._context_task(),
            SecurityTaskNode(
                task_id="secret_analysis",
                kind="secret_analysis",
                state="waiting",
                dependencies=[
                    self._dependency(
                        "repository_context"
                    )
                ],
                produces=[
                    "secret_findings",
                ],
            ),
            SecurityTaskNode(
                task_id="dependency_scan",
                kind="dependency_scan",
                state="waiting",
                dependencies=[
                    self._dependency(
                        "repository_context"
                    )
                ],
                produces=[
                    "dependency_findings",
                ],
            ),
            SecurityTaskNode(
                task_id="attack_surface",
                kind="attack_surface",
                state="waiting",
                dependencies=[
                    self._dependency(
                        "repository_context"
                    )
                ],
                produces=[
                    "attack_surface_graph",
                ],
            ),
            SecurityTaskNode(
                task_id="threat_model",
                kind="threat_model",
                state="waiting",
                dependencies=[
                    self._dependency(
                        "secret_analysis"
                    ),
                    self._dependency(
                        "dependency_scan"
                    ),
                    self._dependency(
                        "attack_surface"
                    ),
                ],
                produces=[
                    "threat_model",
                ],
            ),
        ]

        if request.include_security_memory:
            tasks.append(
                SecurityTaskNode(
                    task_id="security_memory",
                    kind="security_memory",
                    state="waiting",
                    dependencies=[
                        self._dependency(
                            "threat_model"
                        )
                    ],
                    produces=[
                        "security_snapshot",
                    ],
                )
            )

        if request.include_policy_evaluation:
            dependency = (
                "security_memory"
                if request.include_security_memory
                else "threat_model"
            )

            tasks.append(
                SecurityTaskNode(
                    task_id="policy_evaluation",
                    kind="policy_evaluation",
                    state="waiting",
                    dependencies=[
                        self._dependency(dependency)
                    ],
                    produces=[
                        "policy_decision",
                    ],
                )
            )

        return tasks

    def _evaluate_validation_authorization(
        self,
        request: SecurityTaskPlanRequest,
    ) -> dict[str, object]:
        if request.validation_authorization is not None:
            result = self._authorizer.authorize(
                request.validation_authorization
            )

            return {
                "authorized": result.authorized,
                "execution_allowed": (
                    result.execution_allowed
                ),
                "reasons": list(result.reasons),
                "denials": list(result.denials),
            }

        if request.authorization_confirmed:
            return {
                "authorized": True,
                "execution_allowed": True,
                "reasons": [
                    (
                        "Legacy authorization confirmation "
                        "was supplied without a structured "
                        "validation scope."
                    )
                ],
                "denials": [],
            }

        return {
            "authorized": False,
            "execution_allowed": False,
            "reasons": [],
            "denials": [
                (
                    "Explicit structured validation "
                    "authorization is required."
                )
            ],
        }

    def _fix_and_verify_tasks(
        self,
        request: SecurityTaskPlanRequest,
    ) -> list[SecurityTaskNode]:
        patch_available = (
            request.has_proposed_patch
        )
        approval_available = (
            request.human_approval_confirmed
        )

        if not patch_available:
            secure_fix_state = "blocked"
            secure_fix_reasons = [
                "A proposed patch is required before "
                "secure-fix execution."
            ]
        elif not approval_available:
            secure_fix_state = "blocked"
            secure_fix_reasons = [
                "Human approval is required before "
                "applying a secure patch."
            ]
        else:
            secure_fix_state = "ready"
            secure_fix_reasons = [
                "A proposed patch and explicit human "
                "approval are available."
            ]

        tasks = [
            self._context_task(),
            SecurityTaskNode(
                task_id="secure_fix",
                kind="secure_fix",
                state=secure_fix_state,
                dependencies=[
                    self._dependency(
                        "repository_context"
                    )
                ],
                gates=[
                    "proposed_patch",
                    "human_approval",
                ],
                reasons=secure_fix_reasons,
                produces=[
                    "applied_patch",
                    "remediation_manifest",
                ],
            ),
            SecurityTaskNode(
                task_id="fix_verification",
                kind="fix_verification",
                state=(
                    "waiting"
                    if secure_fix_state == "ready"
                    else "blocked"
                ),
                dependencies=[
                    self._dependency(
                        "secure_fix"
                    )
                ],
                reasons=[
                    (
                        "Fix verification waits for an "
                        "approved secure-fix task."
                    )
                ],
                produces=[
                    "fix_verification_result",
                ],
            ),
        ]

        if request.include_dynamic_validation:
            authorization = (
                self._evaluate_validation_authorization(
                    request
                )
            )

            if (
                secure_fix_state == "ready"
                and (
                    not authorization[
                        "authorized"
                    ]
                    or not authorization[
                        "execution_allowed"
                    ]
                )
            ):
                secure_fix_state = "blocked"
                tasks[1].state = "blocked"
                tasks[1].reasons.append(
                    "The patch was not applied "
                    "because the requested dynamic "
                    "verification cannot execute."
                )
                tasks[2].state = "blocked"
                tasks[2].reasons.append(
                    "Static fix verification cannot "
                    "start until the complete "
                    "requested verification chain is "
                    "authorized."
                )

            if secure_fix_state != "ready":
                validation_state = "blocked"
                validation_reasons = [
                    "Dynamic validation cannot proceed "
                    "until the secure fix is approved.",
                    *authorization["reasons"],
                    *authorization["denials"],
                    *(
                        [
                            (
                                "Validation scope is "
                                "authorized, but "
                                "execution is not "
                                "allowed."
                            )
                        ]
                        if (
                            authorization[
                                "authorized"
                            ]
                            and not authorization[
                                "execution_allowed"
                            ]
                        )
                        else []
                    ),
                ]
            elif not authorization["authorized"]:
                validation_state = "blocked"
                validation_reasons = [
                    *authorization["reasons"],
                    *authorization["denials"],
                ]
            elif not authorization["execution_allowed"]:
                validation_state = "blocked"
                validation_reasons = [
                    *authorization["reasons"],
                    (
                        "Validation scope is authorized, "
                        "but execution is not allowed."
                    ),
                ]
            else:
                validation_state = "waiting"
                validation_reasons = [
                    *authorization["reasons"],
                    (
                        "Authorized dynamic validation "
                        "will run after static fix "
                        "verification."
                    ),
                ]

            tasks.append(
                SecurityTaskNode(
                    task_id="dynamic_validation",
                    kind="dynamic_validation",
                    state=validation_state,
                    dependencies=[
                        self._dependency(
                            "fix_verification"
                        )
                    ],
                    gates=[
                        "authorization",
                        "runtime_available",
                    ],
                    reasons=validation_reasons,
                    produces=[
                        "dynamic_validation_evidence",
                        "remediation_lifecycle_outcome",
                    ],
                )
            )

        terminal_dependency = (
            "dynamic_validation"
            if request.include_dynamic_validation
            else "fix_verification"
        )

        if request.include_security_memory:
            tasks.append(
                SecurityTaskNode(
                    task_id="security_memory",
                    kind="security_memory",
                    state=(
                        "waiting"
                        if secure_fix_state == "ready"
                        else "blocked"
                    ),
                    dependencies=[
                        self._dependency(
                            terminal_dependency
                        )
                    ],
                    produces=[
                        "security_snapshot",
                    ],
                )
            )

        if request.include_policy_evaluation:
            dependency = (
                "security_memory"
                if request.include_security_memory
                else terminal_dependency
            )

            tasks.append(
                SecurityTaskNode(
                    task_id="policy_evaluation",
                    kind="policy_evaluation",
                    state=(
                        "waiting"
                        if secure_fix_state == "ready"
                        else "blocked"
                    ),
                    dependencies=[
                        self._dependency(dependency)
                    ],
                    produces=[
                        "policy_decision",
                    ],
                )
            )

        return tasks
