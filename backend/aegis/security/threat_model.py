import hashlib
import re

from aegis.schemas.attack_surface import (
    AttackSurfaceEdge,
    AttackSurfaceFile,
    AttackSurfaceNode,
)
from aegis.schemas.threat_model import (
    ThreatAsset,
    ThreatFinding,
    ThreatModelScanResponse,
    ThreatModelSummary,
    TrustBoundary,
)
from aegis.security.attack_surface import (
    AttackSurfaceMapper,
)


class ThreatModeler:
    name = "aegis-deterministic-threat-model"

    def __init__(
        self,
        mapper: AttackSurfaceMapper | None = None,
    ) -> None:
        self.mapper = mapper or AttackSurfaceMapper()

    def scan(
        self,
        files: list[AttackSurfaceFile],
    ) -> ThreatModelScanResponse:
        attack_surface = self.mapper.scan(files)

        assets = self._build_assets(
            attack_surface.nodes,
        )
        trust_boundaries = self._build_trust_boundaries(
            attack_surface.nodes,
            attack_surface.edges,
        )
        files_by_name = {
            file.filename: file
            for file in files
        }

        threats = self._build_threats(
            attack_surface.nodes,
            files_by_name,
            attack_surface.edges,
        )

        return ThreatModelScanResponse(
            modeler=self.name,
            attack_surface_nodes=attack_surface.nodes,
            attack_surface_edges=attack_surface.edges,
            assets=assets,
            trust_boundaries=trust_boundaries,
            threats=threats,
            summary=ThreatModelSummary(
                files_scanned=len(files),
                assets_found=len(assets),
                trust_boundaries_found=len(
                    trust_boundaries
                ),
                threats_found=len(threats),
                critical=self._count_severity(
                    threats,
                    "critical",
                ),
                high=self._count_severity(
                    threats,
                    "high",
                ),
                medium=self._count_severity(
                    threats,
                    "medium",
                ),
                low=self._count_severity(
                    threats,
                    "low",
                ),
                info=self._count_severity(
                    threats,
                    "info",
                ),
            ),
        )

    def _build_assets(
        self,
        nodes: list[AttackSurfaceNode],
    ) -> list[ThreatAsset]:
        asset_details = {
            "http_route": (
                "HTTP endpoint",
                "entry_point",
                "Application endpoint exposed to callers.",
            ),
            "database": (
                "Application data store",
                "data_store",
                "Database records read or modified by the application.",
            ),
            "filesystem": (
                "Application filesystem",
                "file_store",
                "Files accessed or modified by the application.",
            ),
            "outbound_request": (
                "External service",
                "external_service",
                "Remote service contacted by the application.",
            ),
            "process_execution": (
                "Host execution environment",
                "host",
                "Operating-system commands or child processes.",
            ),
            "secret_access": (
                "Application secrets",
                "secret_store",
                "Credentials and sensitive configuration values.",
            ),
        }

        assets: list[ThreatAsset] = []

        for node in nodes:
            details = asset_details.get(node.kind)

            if details is None:
                continue

            name, kind, description = details

            assets.append(
                ThreatAsset(
                    id=self._stable_id(
                        "asset",
                        node.id,
                    ),
                    name=name,
                    kind=kind,
                    file=node.file,
                    line=node.line_start,
                    description=description,
                    source_node_ids=[node.id],
                )
            )

        return self._deduplicate_assets(assets)

    def _build_trust_boundaries(
        self,
        nodes: list[AttackSurfaceNode],
        edges: list[AttackSurfaceEdge],
    ) -> list[TrustBoundary]:
        boundaries: list[TrustBoundary] = []

        nodes_by_id = {
            node.id: node
            for node in nodes
        }

        for node in nodes:
            if node.kind == "http_route":
                boundaries.append(
                    TrustBoundary(
                        id=self._stable_id(
                            "boundary",
                            node.id,
                            "http",
                        ),
                        label="HTTP request boundary",
                        file=node.file,
                        line=node.line_start,
                        boundary_type="network_input",
                        evidence=node.evidence,
                        source_node_ids=[node.id],
                    )
                )

            elif node.kind == "user_input":
                boundaries.append(
                    TrustBoundary(
                        id=self._stable_id(
                            "boundary",
                            node.id,
                            "input",
                        ),
                        label="Untrusted user-input boundary",
                        file=node.file,
                        line=node.line_start,
                        boundary_type="untrusted_input",
                        evidence=node.evidence,
                        source_node_ids=[node.id],
                    )
                )

            elif node.kind == "outbound_request":
                boundaries.append(
                    TrustBoundary(
                        id=self._stable_id(
                            "boundary",
                            node.id,
                            "outbound",
                        ),
                        label="External network boundary",
                        file=node.file,
                        line=node.line_start,
                        boundary_type="external_network",
                        evidence=node.evidence,
                        source_node_ids=[node.id],
                    )
                )

            elif node.kind == "secret_access":
                boundaries.append(
                    TrustBoundary(
                        id=self._stable_id(
                            "boundary",
                            node.id,
                            "secret",
                        ),
                        label="Secret configuration boundary",
                        file=node.file,
                        line=node.line_start,
                        boundary_type="sensitive_configuration",
                        evidence=node.evidence,
                        source_node_ids=[node.id],
                    )
                )

        for edge in edges:
            if edge.relationship != "data_flow":
                continue

            source = nodes_by_id.get(edge.source)
            target = nodes_by_id.get(edge.target)

            if (
                source is None
                or target is None
                or source.kind
                != "function_parameter"
            ):
                continue

            if target.kind == "process_execution":
                boundaries.append(
                    TrustBoundary(
                        id=self._stable_id(
                            "boundary",
                            source.id,
                            target.id,
                            "process-input",
                        ),
                        label=(
                            "Untrusted input to "
                            "operating-system process"
                        ),
                        file=source.file,
                        line=source.line_start,
                        boundary_type=(
                            "untrusted_process_input"
                        ),
                        evidence=(
                            f"{source.evidence} -> "
                            f"{target.evidence}"
                        ),
                        source_node_ids=[
                            source.id,
                            target.id,
                        ],
                    )
                )

        return self._deduplicate_boundaries(
            boundaries
        )

    def _build_threats(
        self,
        nodes: list[AttackSurfaceNode],
        files_by_name: dict[str, AttackSurfaceFile],
        edges: list[AttackSurfaceEdge],
    ) -> list[ThreatFinding]:
        threats: list[ThreatFinding] = []

        for node in nodes:
            context = self._node_context(
                node,
                files_by_name,
            )

            threat = self._threat_for_node(
                node,
                context,
                nodes,
            )

            if threat is not None:
                threats.append(
                    self._classify_exploitability(
                        threat=threat,
                        node=node,
                        context=context,
                        nodes=nodes,
                        edges=edges,
                        files_by_name=files_by_name,
                    )
                )

        return sorted(
            threats,
            key=lambda threat: (
                self._severity_rank(
                    threat.severity
                ),
                threat.file,
                threat.line,
                threat.category,
            ),
        )

    def _threat_for_node(
        self,
        node: AttackSurfaceNode,
        context: str,
        nodes: list[AttackSurfaceNode],
    ) -> ThreatFinding | None:
        if (
            node.kind == "process_execution"
            and self._process_execution_is_risky(
                context
            )
        ):
            return self._threat(
                node=node,
                title="Untrusted data may reach process execution",
                category="command_injection",
                severity="critical",
                confidence=0.90,
                affected_asset="Host execution environment",
                trust_boundary="Untrusted input to operating-system process",
                description=(
                    "Process execution can allow command injection "
                    "when attacker-controlled values reach command "
                    "arguments or a shell."
                ),
                attack_path=[
                    "Attacker controls an application input",
                    "Input reaches process or shell execution",
                    "Host command executes with application privileges",
                ],
                mitigations=[
                    "Avoid shell execution where possible",
                    "Pass arguments as a fixed list",
                    "Use strict allowlists for permitted values",
                    "Run the process with minimal privileges",
                ],
            )

        if (
            node.kind == "database"
            and self._database_operation_is_risky(
                context
            )
        ):
            return self._threat(
                node=node,
                title="Untrusted data may alter a database query",
                category="sql_injection",
                severity="high",
                confidence=0.82,
                affected_asset="Application data store",
                trust_boundary="Application-to-database boundary",
                description=(
                    "Dynamic or insufficiently constrained database "
                    "operations may allow query manipulation."
                ),
                attack_path=[
                    "Attacker supplies crafted input",
                    "Input influences a database operation",
                    "Database query behavior is altered",
                ],
                mitigations=[
                    "Use parameterized queries",
                    "Avoid string-built SQL",
                    "Apply least-privilege database permissions",
                    "Validate identifiers against allowlists",
                ],
            )

        if (
            node.kind == "filesystem"
            and self._filesystem_operation_is_risky(
                node,
                context,
                nodes,
            )
        ):
            return self._threat(
                node=node,
                title="Untrusted paths may escape the intended directory",
                category="path_traversal",
                severity="high",
                confidence=0.78,
                affected_asset="Application filesystem",
                trust_boundary="Application-to-filesystem boundary",
                description=(
                    "Attacker-controlled path components may permit "
                    "reading, writing, moving, or deleting unintended files."
                ),
                attack_path=[
                    "Attacker controls a filename or path",
                    "Path reaches a filesystem operation",
                    "Operation accesses data outside the intended root",
                ],
                mitigations=[
                    "Resolve paths against a fixed base directory",
                    "Reject paths that escape the allowed root",
                    "Use generated server-side filenames",
                    "Restrict filesystem permissions",
                ],
            )

        if (
            node.kind == "outbound_request"
            and self._outbound_request_is_risky(
                node,
                context,
                nodes,
            )
        ):
            return self._threat(
                node=node,
                title="User-controlled destinations may enable SSRF",
                category="ssrf",
                severity="high",
                confidence=0.84,
                affected_asset="External and internal network services",
                trust_boundary="Application-to-network boundary",
                description=(
                    "An attacker may influence an outbound request "
                    "destination and reach internal or privileged services."
                ),
                attack_path=[
                    "Attacker supplies a URL or hostname",
                    "Application performs an outbound request",
                    "Request reaches an internal or restricted service",
                ],
                mitigations=[
                    "Allowlist permitted schemes and hosts",
                    "Block private, loopback, and link-local addresses",
                    "Revalidate destinations after redirects",
                    "Use a restricted outbound proxy",
                ],
            )

        if (
            node.kind == "secret_access"
            and self._secret_access_is_risky(
                context
            )
        ):
            return self._threat(
                node=node,
                title="Sensitive configuration may be exposed",
                category="secret_exposure",
                severity="high",
                confidence=0.72,
                affected_asset="Application secrets",
                trust_boundary="Secret configuration boundary",
                description=(
                    "Credentials or sensitive configuration may leak "
                    "through logs, errors, responses, or insecure storage."
                ),
                attack_path=[
                    "Application loads a secret",
                    "Secret enters application memory",
                    "Secret is exposed through an unsafe output or store",
                ],
                mitigations=[
                    "Never log secret values",
                    "Redact secrets from errors and telemetry",
                    "Use a dedicated secret manager",
                    "Rotate credentials after suspected exposure",
                ],
            )

        if (
            node.kind == "http_route"
            and node.authenticated is False
        ):
            return self._threat(
                node=node,
                title="Sensitive route may lack authentication",
                category="authentication_bypass",
                severity="high",
                confidence=0.86,
                affected_asset="Protected application functionality",
                trust_boundary="Unauthenticated HTTP boundary",
                description=(
                    "The route appears reachable without a detected "
                    "authentication or authorization control."
                ),
                attack_path=[
                    "Unauthenticated caller reaches the route",
                    "Route performs a sensitive application action",
                    "Protected data or functionality is exposed",
                ],
                mitigations=[
                    "Require authentication middleware",
                    "Enforce authorization at the operation boundary",
                    "Use deny-by-default access policies",
                    "Add tests for unauthenticated access",
                ],
            )

        if node.kind == "user_input":
            return self._threat(
                node=node,
                title="Untrusted input crosses into application logic",
                category="unsafe_data_flow",
                severity="medium",
                confidence=0.68,
                affected_asset="Application processing logic",
                trust_boundary="Untrusted user-input boundary",
                description=(
                    "Request-controlled data enters application logic "
                    "and requires validation before sensitive use."
                ),
                attack_path=[
                    "Attacker supplies crafted request data",
                    "Application accepts the value",
                    "Value reaches a security-sensitive operation",
                ],
                mitigations=[
                    "Validate type, length, format, and allowed values",
                    "Normalize data before validation",
                    "Encode output for its destination context",
                    "Track data flow into sensitive sinks",
                ],
            )

        return None

    @staticmethod
    def _node_context(
        node: AttackSurfaceNode,
        files_by_name: dict[str, AttackSurfaceFile],
        radius: int = 8,
    ) -> str:
        file = files_by_name.get(node.file)

        if file is None:
            return node.evidence

        lines = file.code.splitlines()

        start = max(
            0,
            node.line_start - radius - 1,
        )
        end = min(
            len(lines),
            node.line_end + radius,
        )

        return "\n".join(
            lines[start:end]
        )

    @staticmethod
    def _process_execution_is_risky(
        context: str,
    ) -> bool:
        lowered = context.lower()
        compact = "".join(lowered.split())

        explicitly_dangerous = (
            "os.system(",
            "os.popen(",
            "child_process.exec(",
            "child_process.execsync(",
            "shell=true",
            "shell: true",
        )

        if any(
            marker in lowered
            for marker in explicitly_dangerous
        ):
            return True

        if (
            "subprocess.run" in lowered
            or "subprocess.popen" in lowered
            or "subprocess.call" in lowered
        ):
            has_argument_list = (
                "subprocess.run([" in compact
                or "subprocess.popen([" in compact
                or "subprocess.call([" in compact
            )

            return not has_argument_list

        if (
            "spawn(" in lowered
            or "spawnsync(" in lowered
        ):
            return "[" not in context

        return True

    @staticmethod
    def _database_operation_is_risky(
        context: str,
    ) -> bool:
        lowered = context.lower()

        sql_keywords = (
            "select ",
            "insert ",
            "update ",
            "delete ",
            " where ",
            " from ",
        )

        if not any(
            keyword in lowered
            for keyword in sql_keywords
        ):
            return False

        interpolation_markers = (
            "${",
            ".format(",
            "f\"",
            "f'",
            "%s\" %",
            "%s' %",
            " + ",
        )

        if any(
            marker in lowered
            for marker in interpolation_markers
        ):
            return True

        return bool(
            "execute(query)" in lowered
            and (
                "query = f" in lowered
                or "query=f" in lowered
            )
        )

    @classmethod
    def _filesystem_operation_is_risky(
        cls,
        node: AttackSurfaceNode,
        context: str,
        nodes: list[AttackSurfaceNode],
    ) -> bool:
        lowered = context.lower()

        safety_markers = (
            "realpath",
            ".resolve(",
            "startswith(",
            "relative_to(",
            "path.basename(",
            "os.path.basename(",
            "allowed_root",
            "allowed_directory",
        )

        if any(
            marker in lowered
            for marker in safety_markers
        ):
            return False

        input_markers = (
            "req.query",
            "req.params",
            "req.body",
            "request.args",
            "request.form",
            "request.query_params",
            "filename",
            "user_path",
            "input_path",
        )

        return (
            any(
                marker in lowered
                for marker in input_markers
            )
            or cls._has_nearby_user_input(
                node,
                nodes,
            )
        )

    @classmethod
    def _outbound_request_is_risky(
        cls,
        node: AttackSurfaceNode,
        context: str,
        nodes: list[AttackSurfaceNode],
    ) -> bool:
        lowered = context.lower()

        safety_markers = (
            "allowed_hosts",
            "allowed_host",
            "allowlist",
            "hostname not in",
            "protocol not in",
            "private_address",
            "is_private",
            "is_loopback",
            "ipaddress.",
        )

        if any(
            marker in lowered
            for marker in safety_markers
        ):
            return False

        input_markers = (
            "req.query",
            "req.params",
            "req.body",
            "request.args",
            "request.form",
            "request.query_params",
        )

        return (
            any(
                marker in lowered
                for marker in input_markers
            )
            or cls._has_nearby_user_input(
                node,
                nodes,
            )
        )

    @staticmethod
    def _secret_access_is_risky(
        context: str,
    ) -> bool:
        lowered = context.lower()

        exposure_markers = (
            "console.log(",
            "print(",
            "logger.info(",
            "logger.debug(",
            "res.send(",
            "res.json(",
            "jsonresponse(",
        )

        secret_markers = (
            "secret",
            "password",
            "token",
            "api_key",
            "apikey",
            "private_key",
            "database_url",
        )

        return (
            any(
                marker in lowered
                for marker in exposure_markers
            )
            and any(
                marker in lowered
                for marker in secret_markers
            )
        )

    @staticmethod
    def _has_direct_parameter_flow(
        *,
        evidence: str,
        context: str,
    ) -> bool:
        parameters = (
            ThreatModeler._extract_parameter_names(
                context
            )
        )

        return any(
            re.search(
                rf"\b{re.escape(parameter)}\b",
                evidence,
            )
            is not None
            for parameter in parameters
        )

    @classmethod
    def _has_intermediate_parameter_flow(
        cls,
        *,
        evidence: str,
        context: str,
    ) -> bool:
        parameter_names = cls._extract_parameter_names(
            context
        )

        sink_variables = re.findall(
            r"(?:os\.system|os\.popen|exec|execSync)"
            r"\s*\(\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\)",
            evidence,
        )

        if not sink_variables:
            return False

        for variable in sink_variables:
            assignments = re.findall(
                rf"\b{re.escape(variable)}\b\s*=\s*(.+)",
                context,
            )

            for expression in assignments:
                if any(
                    re.search(
                        rf"\b{re.escape(parameter)}\b",
                        expression,
                    )
                    is not None
                    for parameter in parameter_names
                ):
                    return True

        return False

    @staticmethod
    def _extract_parameter_names(
        context: str,
    ) -> set[str]:
        parameter_blocks: list[str] = []

        patterns = (
            r"def\s+[A-Za-z_]\w*\s*\(([^)]*)\)",
            r"function\s+[A-Za-z_$][A-Za-z0-9_$]*"
            r"\s*\(([^)]*)\)",
            r"\(([^)]*)\)\s*=>",
        )

        for pattern in patterns:
            parameter_blocks.extend(
                re.findall(
                    pattern,
                    context,
                    flags=re.MULTILINE,
                )
            )

        parameters: set[str] = set()

        for block in parameter_blocks:
            for raw_parameter in block.split(","):
                parameter = raw_parameter.strip()

                if not parameter:
                    continue

                parameter = parameter.split("=", 1)[0]
                parameter = parameter.split(":", 1)[0]
                parameter = parameter.lstrip("*").strip()

                match = re.search(
                    r"[A-Za-z_$][A-Za-z0-9_$]*",
                    parameter,
                )

                if match:
                    parameters.add(match.group(0))

        parameters.update(
            re.findall(
                r"\b([A-Za-z_$][A-Za-z0-9_$]*)\s*=>",
                context,
            )
        )

        return parameters

    @classmethod
    def _build_data_flow_path(
        cls,
        *,
        node: AttackSurfaceNode,
        nodes: list[AttackSurfaceNode],
        edges: list[AttackSurfaceEdge],
        files_by_name: dict[str, AttackSurfaceFile],
    ) -> tuple[list[str], list[str]]:
        matching_edges = [
            edge
            for edge in edges
            if edge.target == node.id
            and edge.relationship == "data_flow"
        ]

        if not matching_edges:
            return [], []

        nodes_by_id = {
            candidate.id: candidate
            for candidate in nodes
        }

        matching_sources = [
            nodes_by_id[edge.source]
            for edge in matching_edges
            if edge.source in nodes_by_id
        ]

        if not matching_sources:
            return [], []

        source_node = min(
            matching_sources,
            key=lambda candidate: (
                0
                if candidate.kind == "user_input"
                else 1,
                candidate.line_start,
                candidate.id,
            ),
        )

        source_file = files_by_name.get(node.file)

        if source_file is None:
            return [], []

        source_expression = (
            source_node.symbol
            if source_node.kind == "function_parameter"
            else AttackSurfaceMapper._extract_source_expression(
                source_node.evidence
            )
        )

        if not source_expression:
            return [], []

        path = AttackSurfaceMapper._trace_local_data_flow(
            code=source_file.code,
            source_expression=source_expression,
            sink_expression=node.evidence,
            source_line=source_node.line_start,
            sink_line=node.line_start,
        )

        if not path:
            return [], []

        return path, list(
            dict.fromkeys(
                [
                    *(
                        source.id
                        for source in matching_sources
                    ),
                    node.id,
                ]
            )
        )

    @staticmethod
    def _has_proven_data_flow(
        *,
        node: AttackSurfaceNode,
        edges: list[AttackSurfaceEdge],
    ) -> bool:
        return any(
            edge.target == node.id
            and edge.relationship == "data_flow"
            for edge in edges
        )

    @staticmethod
    def _has_nearby_user_input(
        node: AttackSurfaceNode,
        nodes: list[AttackSurfaceNode],
        distance: int = 12,
    ) -> bool:
        return any(
            candidate.kind == "user_input"
            and candidate.file == node.file
            and abs(
                candidate.line_start
                - node.line_start
            ) <= distance
            for candidate in nodes
        )

    def _classify_exploitability(
        self,
        *,
        threat: ThreatFinding,
        node: AttackSurfaceNode,
        context: str,
        nodes: list[AttackSurfaceNode],
        edges: list[AttackSurfaceEdge],
        files_by_name: dict[str, AttackSurfaceFile],
    ) -> ThreatFinding:
        lowered = context.lower()

        has_user_input = self._has_nearby_user_input(
            node,
            nodes,
        )
        has_proven_data_flow = (
            self._has_proven_data_flow(
                node=node,
                edges=edges,
            )
        )
        (
            data_flow,
            data_flow_node_ids,
        ) = self._build_data_flow_path(
            node=node,
            nodes=nodes,
            edges=edges,
            files_by_name=files_by_name,
        )
        has_direct_parameter_flow = (
            self._has_direct_parameter_flow(
                evidence=node.evidence,
                context=context,
            )
        )
        has_intermediate_parameter_flow = (
            self._has_intermediate_parameter_flow(
                evidence=node.evidence,
                context=context,
            )
        )

        exploitability = "possible"
        exploitability_confidence = 0.68
        reasons: list[str] = []
        prerequisites: list[str] = []
        blocking_controls: list[str] = []

        if threat.category == "command_injection":
            shell_execution = any(
                marker in lowered
                for marker in (
                    "os.system(",
                    "os.popen(",
                    "child_process.exec(",
                    "child_process.execsync(",
                    "exec(`",
                    "exec('",
                    'exec("',
                    "shell=true",
                    "shell: true",
                )
            )

            if (
                shell_execution
                and (
                    has_proven_data_flow
                    or has_user_input
                    or has_direct_parameter_flow
                    or has_intermediate_parameter_flow
                )
            ):
                exploitability = "confirmed"
                exploitability_confidence = 0.96
                if has_proven_data_flow:
                    reasons.extend(
                        [
                            "A source-to-sink data-flow edge proves that attacker-controlled input reaches process execution.",
                            "The process API invokes a shell or command-string execution path.",
                        ]
                    )
                else:
                    reasons.extend(
                        [
                            "Attacker-controlled input was detected near process execution.",
                            "The process API invokes a shell or command-string execution path.",
                        ]
                    )
            elif shell_execution:
                exploitability = "likely"
                exploitability_confidence = 0.88
                reasons.extend(
                    [
                        "A shell or command-string execution sink was detected.",
                        "Direct attacker control could not be proven from the static context.",
                    ]
                )
            else:
                exploitability = "possible"
                exploitability_confidence = 0.72
                reasons.append(
                    "A risky process-execution operation was detected."
                )

            prerequisites.extend(
                [
                    "An attacker can influence a value used by the process operation.",
                    "The application process has permission to execute the resulting command.",
                ]
            )

        elif threat.category == "sql_injection":
            dynamic_sql = any(
                marker in lowered
                for marker in (
                    "${",
                    ".format(",
                    "query = f",
                    "query=f",
                    "execute(query)",
                    "db.query(`",
                )
            )

            if (
                dynamic_sql
                and (
                    has_proven_data_flow
                    or has_user_input
                )
            ):
                exploitability = "confirmed"
                exploitability_confidence = 0.94
                if has_proven_data_flow:
                    reasons.extend(
                        [
                            "A source-to-sink data-flow edge proves that attacker-controlled input reaches the database operation.",
                            "The query is dynamically constructed or executed without parameters.",
                        ]
                    )
                else:
                    reasons.extend(
                        [
                            "Request-controlled input was detected near the database operation.",
                            "The query is dynamically constructed or executed without parameters.",
                        ]
                    )
            elif dynamic_sql:
                exploitability = "likely"
                exploitability_confidence = 0.85
                reasons.extend(
                    [
                        "A dynamically constructed database query was detected.",
                        "Static analysis could not prove the origin of every query value.",
                    ]
                )
            else:
                exploitability = "possible"
                exploitability_confidence = 0.70
                reasons.append(
                    "A database sink with insufficiently constrained query construction was detected."
                )

            prerequisites.extend(
                [
                    "An attacker can influence a value used in the query.",
                    "The database driver executes the constructed query.",
                ]
            )

        elif threat.category == "path_traversal":
            if has_proven_data_flow:
                exploitability = "likely"
                exploitability_confidence = 0.94
                reasons.extend(
                    [
                        "A source-to-sink data-flow edge proves that attacker-controlled input reaches the filesystem operation.",
                        "No effective root-containment control was detected.",
                    ]
                )
            elif has_user_input:
                exploitability = "likely"
                exploitability_confidence = 0.89
                reasons.extend(
                    [
                        "User-controlled data was detected near the filesystem operation.",
                        "No effective root-containment control was detected.",
                    ]
                )
            else:
                exploitability = "possible"
                exploitability_confidence = 0.69
                reasons.append(
                    "A filesystem path reaches a sensitive operation without proven containment."
                )

            prerequisites.extend(
                [
                    "An attacker can influence the filename or path.",
                    "The application can access data outside the intended directory.",
                ]
            )

        elif threat.category == "ssrf":
            if has_proven_data_flow:
                exploitability = "likely"
                exploitability_confidence = 0.95
                reasons.extend(
                    [
                        "A source-to-sink data-flow edge proves that attacker-controlled input reaches the outbound request.",
                        "No host or network-destination allowlist was detected.",
                    ]
                )
            elif has_user_input:
                exploitability = "likely"
                exploitability_confidence = 0.91
                reasons.extend(
                    [
                        "Request-controlled data was detected near an outbound request.",
                        "No host or network-destination allowlist was detected.",
                    ]
                )
            else:
                exploitability = "possible"
                exploitability_confidence = 0.70
                reasons.append(
                    "An outbound request destination may be influenced at runtime."
                )

            prerequisites.extend(
                [
                    "An attacker can influence the outbound destination.",
                    "The application can reach the targeted network service.",
                ]
            )

        elif threat.category == "secret_exposure":
            direct_output = any(
                marker in lowered
                for marker in (
                    "print(",
                    "console.log(",
                    "logger.info(",
                    "logger.debug(",
                    "res.send(",
                    "res.json(",
                    "jsonresponse(",
                )
            )

            if direct_output:
                exploitability = "confirmed"
                exploitability_confidence = 0.93
                reasons.extend(
                    [
                        "Sensitive configuration is loaded in the same context as an output or logging operation.",
                        "The detected output path can disclose the secret value.",
                    ]
                )
            else:
                exploitability = "possible"
                exploitability_confidence = 0.66
                reasons.append(
                    "Sensitive configuration enters an exposure-prone application context."
                )

            prerequisites.append(
                "An attacker or unauthorized observer can access the affected output, log, or response."
            )

        elif threat.category == "authentication_bypass":
            exploitability = "likely"
            exploitability_confidence = 0.87
            reasons.extend(
                [
                    "An externally reachable route lacks a detected authentication control.",
                    "The route may expose privileged behavior to unauthenticated callers.",
                ]
            )
            prerequisites.append(
                "The affected route is reachable by an unauthenticated attacker."
            )

        elif threat.category == "unsafe_data_flow":
            exploitability = "possible"
            exploitability_confidence = 0.74
            reasons.extend(
                [
                    "Request-controlled input enters application logic.",
                    "The complete source-to-sink path requires further data-flow verification.",
                ]
            )
            prerequisites.append(
                "The attacker-controlled value reaches a security-sensitive operation."
            )

        detected_controls = (
            self._detect_blocking_controls(
                category=threat.category,
                context=context,
                evidence=node.evidence,
            )
        )

        if detected_controls:
            blocking_controls.extend(
                detected_controls
            )

            (
                exploitability,
                exploitability_confidence,
            ) = self._downgrade_for_blocking_controls(
                exploitability=exploitability,
                confidence=exploitability_confidence,
            )

            reasons.append(
                "One or more blocking controls were detected "
                "in the same static context."
            )

        return threat.model_copy(
            update={
                "exploitability": exploitability,
                "exploitability_confidence":
                    exploitability_confidence,
                "exploitability_reasons": reasons,
                "prerequisites": prerequisites,
                "blocking_controls": blocking_controls,
                "data_flow": data_flow,
                "source_node_ids": list(
                    dict.fromkeys(
                        [
                            *threat.source_node_ids,
                            *data_flow_node_ids,
                        ]
                    )
                ),
            }
        )

    @staticmethod
    def _scope_context_to_evidence(
        *,
        context: str,
        evidence: str,
    ) -> str:
        if not evidence.strip():
            return context

        lines = context.splitlines()
        evidence_line = evidence.strip().splitlines()[0].strip()

        matching_indices: list[int] = []

        for index, line in enumerate(lines):
            stripped_line = line.strip()

            if (
                evidence_line
                and stripped_line
                and (
                    evidence_line in stripped_line
                    or stripped_line in evidence_line
                )
            ):
                matching_indices.append(index)

        if not matching_indices:
            return context

        # When identical sink evidence occurs more than once,
        # prefer the final occurrence. This avoids associating
        # controls from an earlier safe function with a later
        # vulnerable sink.
        evidence_index = matching_indices[-1]

        function_patterns = (
            re.compile(
                r"^\s*(?:async\s+)?def\s+"
                r"[A-Za-z_]\w*\s*\("
            ),
            re.compile(
                r"^\s*(?:async\s+)?function\s+"
                r"[A-Za-z_$][A-Za-z0-9_$]*\s*\("
            ),
        )

        start = 0

        for index in range(
            evidence_index,
            -1,
            -1,
        ):
            if any(
                pattern.search(lines[index])
                for pattern in function_patterns
            ):
                start = index
                break

        end = len(lines)

        for index in range(
            evidence_index + 1,
            len(lines),
        ):
            if any(
                pattern.search(lines[index])
                for pattern in function_patterns
            ):
                end = index
                break

        return "\n".join(lines[start:end])

    @staticmethod
    def _detect_blocking_controls(
        *,
        category: str,
        context: str,
        evidence: str = "",
    ) -> list[str]:
        scoped_context = (
            ThreatModeler._scope_context_to_evidence(
                context=context,
                evidence=evidence,
            )
        )
        lowered = scoped_context.lower()
        controls: list[str] = []

        if category == "command_injection":
            argument_list = re.search(
                r"(?:subprocess\.(?:run|popen|call|check_call|"
                r"check_output)|spawn|execfile)"
                r"\s*\(\s*\[",
                lowered,
            )

            shell_disabled = any(
                marker in lowered
                for marker in (
                    "shell=false",
                    "shell: false",
                )
            )

            if argument_list:
                controls.append(
                    "Process arguments are passed as a fixed "
                    "argument list instead of a shell string."
                )

            if shell_disabled:
                controls.append(
                    "Shell execution is explicitly disabled."
                )

        elif category == "sql_injection":
            parameterized_call = re.search(
                r"\.(?:execute|query)\s*\(\s*"
                r"(?:[rubf]*[\"'][\s\S]*?"
                r"(?:\?|%s|:\w+|\$\d+)"
                r"[\s\S]*?[\"'])"
                r"\s*,\s*(?:\(|\[|\{)",
                scoped_context,
                flags=re.IGNORECASE,
            )

            if parameterized_call:
                controls.append(
                    "The database operation uses parameter "
                    "binding instead of interpolating values "
                    "into SQL."
                )

        elif category == "path_traversal":
            canonicalization = any(
                marker in lowered
                for marker in (
                    "os.path.realpath(",
                    "os.path.abspath(",
                    "path.resolve(",
                    ".resolve()",
                )
            )

            root_containment = any(
                marker in lowered
                for marker in (
                    "os.path.commonpath(",
                    ".startswith(",
                    "path.relative(",
                    "relative_to(",
                    "is_relative_to(",
                )
            )

            if canonicalization:
                controls.append(
                    "The filesystem path is canonicalized "
                    "before sensitive use."
                )

            if root_containment:
                controls.append(
                    "The resolved path is checked against an "
                    "allowed root directory."
                )

        elif category == "ssrf":
            allowlist = any(
                marker in lowered
                for marker in (
                    "allowed_hosts",
                    "allowed_hosts",
                    "allowed_domains",
                    "allowed_urls",
                    "host_allowlist",
                    "url_allowlist",
                    "hostname_allowlist",
                    "if host not in",
                    "if hostname not in",
                    "includes(host)",
                    "includes(hostname)",
                )
            )

            parsed_destination = any(
                marker in lowered
                for marker in (
                    "urlparse(",
                    "new url(",
                    ".hostname",
                    ".host",
                )
            )

            if allowlist:
                controls.append(
                    "The outbound destination is checked "
                    "against an explicit allowlist."
                )

            if allowlist and parsed_destination:
                controls.append(
                    "The destination hostname is parsed before "
                    "the allowlist decision."
                )

        return controls

    @staticmethod
    def _downgrade_for_blocking_controls(
        *,
        exploitability: str,
        confidence: float,
    ) -> tuple[str, float]:
        if exploitability == "confirmed":
            return "likely", max(confidence, 0.86)

        if exploitability == "likely":
            return "unlikely", max(confidence, 0.84)

        if exploitability == "possible":
            return "unlikely", max(confidence, 0.78)

        return exploitability, confidence

    def _threat(
        self,
        *,
        node: AttackSurfaceNode,
        title: str,
        category: str,
        severity: str,
        confidence: float,
        affected_asset: str,
        trust_boundary: str,
        description: str,
        attack_path: list[str],
        mitigations: list[str],
    ) -> ThreatFinding:
        return ThreatFinding(
            id=self._stable_id(
                "threat",
                node.id,
                category,
            ),
            title=title,
            category=category,
            severity=severity,
            confidence=confidence,
            file=node.file,
            line=node.line_start,
            entry_point=(
                node.label
                if node.kind == "http_route"
                else None
            ),
            affected_asset=affected_asset,
            trust_boundary=trust_boundary,
            description=description,
            attack_path=attack_path,
            mitigations=mitigations,
            evidence=[node.evidence],
            source_node_ids=[node.id],
        )

    @staticmethod
    def _stable_id(
        *parts: str,
    ) -> str:
        value = "::".join(parts).encode(
            "utf-8"
        )

        return hashlib.sha256(
            value
        ).hexdigest()[:20]

    @staticmethod
    def _count_severity(
        threats: list[ThreatFinding],
        severity: str,
    ) -> int:
        return sum(
            threat.severity == severity
            for threat in threats
        )

    @staticmethod
    def _severity_rank(
        severity: str,
    ) -> int:
        return {
            "critical": 0,
            "high": 1,
            "medium": 2,
            "low": 3,
            "info": 4,
        }.get(severity, 5)

    @staticmethod
    def _deduplicate_assets(
        assets: list[ThreatAsset],
    ) -> list[ThreatAsset]:
        deduplicated = {
            asset.id: asset
            for asset in assets
        }

        return sorted(
            deduplicated.values(),
            key=lambda asset: (
                asset.file,
                asset.line,
                asset.kind,
            ),
        )

    @staticmethod
    def _deduplicate_boundaries(
        boundaries: list[TrustBoundary],
    ) -> list[TrustBoundary]:
        deduplicated = {
            boundary.id: boundary
            for boundary in boundaries
        }

        return sorted(
            deduplicated.values(),
            key=lambda boundary: (
                boundary.file,
                boundary.line,
                boundary.boundary_type,
            ),
        )
