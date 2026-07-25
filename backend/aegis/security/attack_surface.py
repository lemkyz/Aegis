import hashlib
import re
from dataclasses import dataclass

from aegis.schemas.attack_surface import (
    AttackSurfaceEdge,
    AttackSurfaceFile,
    AttackSurfaceNode,
    AttackSurfaceScanResponse,
    AttackSurfaceSummary,
)


@dataclass(frozen=True)
class _Pattern:
    kind: str
    expression: re.Pattern[str]
    label: str
    risk: str
    framework: str | None = None


class AttackSurfaceMapper:
    name = "aegis-static-attack-surface"

    _python_route_pattern = re.compile(
        r"""
        @(?P<app>[A-Za-z_][A-Za-z0-9_]*)
        \.
        (?P<method>get|post|put|patch|delete|options|head)
        \(
        \s*
        (?P<quote>["'])
        (?P<path>[^"']+)
        (?P=quote)
        """,
        re.IGNORECASE | re.VERBOSE,
    )

    _flask_route_pattern = re.compile(
        r"""
        @(?P<app>[A-Za-z_][A-Za-z0-9_]*)
        \.route
        \(
        \s*
        (?P<quote>["'])
        (?P<path>[^"']+)
        (?P=quote)
        (?P<options>[^)]*)
        \)
        """,
        re.IGNORECASE | re.VERBOSE,
    )

    _express_route_pattern = re.compile(
        r"""
        (?P<app>[A-Za-z_$][A-Za-z0-9_$]*)
        \.
        (?P<method>get|post|put|patch|delete|options|head|use)
        \(
        \s*
        (?P<quote>["'`])
        (?P<path>[^"'`]+)
        (?P=quote)
        """,
        re.IGNORECASE | re.VERBOSE,
    )

    _python_patterns = (
        _Pattern(
            kind="authentication",
            expression=re.compile(
                r"\b(?:Depends|Security)\s*\("
                r"[^)]*(?:auth|user|token|permission|role)",
                re.IGNORECASE,
            ),
            label="Authentication or authorization dependency",
            risk="info",
            framework="python",
        ),
        _Pattern(
            kind="user_input",
            expression=re.compile(
                r"\b(?:request\.(?:args|form|json|query_params|path_params)"
                r"|Body\s*\(|Query\s*\(|Path\s*\(|Header\s*\()",
                re.IGNORECASE,
            ),
            label="Request-controlled input",
            risk="medium",
            framework="python",
        ),
        _Pattern(
            kind="database",
            expression=re.compile(
                r"\b(?:execute|executemany|cursor|query|raw)\s*\(",
                re.IGNORECASE,
            ),
            label="Database operation",
            risk="high",
            framework="python",
        ),
        _Pattern(
            kind="filesystem",
            expression=re.compile(
                r"\b(?:open|Path\s*\([^)]*\)\.(?:read_text|write_text|unlink)"
                r"|os\.(?:remove|unlink|rename|replace)"
                r"|shutil\.(?:copy|copyfile|move|rmtree))\s*\(",
                re.IGNORECASE,
            ),
            label="Filesystem operation",
            risk="medium",
            framework="python",
        ),
        _Pattern(
            kind="outbound_request",
            expression=re.compile(
                r"\b(?:requests\.(?:get|post|put|patch|delete|request)"
                r"|httpx\.(?:get|post|put|patch|delete|request)"
                r"|urllib\.request\.urlopen"
                r"|aiohttp\.ClientSession)\b",
                re.IGNORECASE,
            ),
            label="Outbound HTTP request",
            risk="high",
            framework="python",
        ),
        _Pattern(
            kind="process_execution",
            expression=re.compile(
                r"\b(?:subprocess\.(?:run|call|Popen|check_output|check_call)"
                r"|os\.(?:system|popen))\s*\(",
                re.IGNORECASE,
            ),
            label="Process or shell execution",
            risk="critical",
            framework="python",
        ),
        _Pattern(
            kind="secret_access",
            expression=re.compile(
                r"\b(?:os\.(?:environ|getenv)"
                r"|getenv\s*\(|SecretStr\s*\()",
                re.IGNORECASE,
            ),
            label="Secret or environment configuration access",
            risk="medium",
            framework="python",
        ),
    )

    _javascript_patterns = (
        _Pattern(
            kind="authentication",
            expression=re.compile(
                r"\b(?:authenticate|authorize|requireAuth|verifyToken"
                r"|passport\.authenticate|authMiddleware)\b",
                re.IGNORECASE,
            ),
            label="Authentication or authorization middleware",
            risk="info",
            framework="nodejs",
        ),
        _Pattern(
            kind="user_input",
            expression=re.compile(
                r"\b(?:req|request)\."
                r"(?:body|query|params|headers|cookies)\b",
                re.IGNORECASE,
            ),
            label="Request-controlled input",
            risk="medium",
            framework="nodejs",
        ),
        _Pattern(
            kind="database",
            expression=re.compile(
                r"\b(?:query|execute|raw|findOne|findMany|findUnique"
                r"|create|update|deleteMany)\s*\(",
                re.IGNORECASE,
            ),
            label="Database operation",
            risk="high",
            framework="nodejs",
        ),
        _Pattern(
            kind="filesystem",
            expression=re.compile(
                r"\b(?:fs\.)"
                r"(?:readFile|readFileSync|writeFile|writeFileSync"
                r"|unlink|unlinkSync|rename|renameSync|createReadStream"
                r"|createWriteStream)\s*\(",
                re.IGNORECASE,
            ),
            label="Filesystem operation",
            risk="medium",
            framework="nodejs",
        ),
        _Pattern(
            kind="outbound_request",
            expression=re.compile(
                r"\b(?:fetch|axios\.(?:get|post|put|patch|delete|request)"
                r"|https?\.request|https?\.get)\s*\(",
                re.IGNORECASE,
            ),
            label="Outbound HTTP request",
            risk="high",
            framework="nodejs",
        ),
        _Pattern(
            kind="process_execution",
            expression=re.compile(
                r"\b(?:child_process\.)?"
                r"(?:exec|execSync|spawn|spawnSync|fork)\s*\(",
                re.IGNORECASE,
            ),
            label="Process or shell execution",
            risk="critical",
            framework="nodejs",
        ),
        _Pattern(
            kind="secret_access",
            expression=re.compile(
                r"\bprocess\.env(?:\.[A-Za-z_$][A-Za-z0-9_$]*"
                r"|\[[^\]]+\])",
                re.IGNORECASE,
            ),
            label="Secret or environment configuration access",
            risk="medium",
            framework="nodejs",
        ),
    )

    def scan(
        self,
        files: list[AttackSurfaceFile],
    ) -> AttackSurfaceScanResponse:
        nodes: list[AttackSurfaceNode] = []

        for file in files:
            nodes.extend(self._scan_file(file))

        nodes = self._deduplicate_nodes(nodes)
        edges = self._build_edges(
            nodes=nodes,
            files=files,
        )

        routes = [
            node
            for node in nodes
            if node.kind == "http_route"
        ]

        return AttackSurfaceScanResponse(
            mapper=self.name,
            nodes=nodes,
            edges=edges,
            summary=AttackSurfaceSummary(
                files_scanned=len(files),
                nodes_found=len(nodes),
                edges_found=len(edges),
                routes=len(routes),
                authenticated_routes=sum(
                    node.authenticated is True
                    for node in routes
                ),
                unauthenticated_routes=sum(
                    node.authenticated is False
                    for node in routes
                ),
                databases=self._count_kind(
                    nodes,
                    "database",
                ),
                filesystems=self._count_kind(
                    nodes,
                    "filesystem",
                ),
                outbound_requests=self._count_kind(
                    nodes,
                    "outbound_request",
                ),
                process_executions=self._count_kind(
                    nodes,
                    "process_execution",
                ),
                secret_accesses=self._count_kind(
                    nodes,
                    "secret_access",
                ),
            ),
        )

    def _scan_file(
        self,
        file: AttackSurfaceFile,
    ) -> list[AttackSurfaceNode]:
        language = file.language.lower().strip()

        if language in {
            "python",
            "py",
        }:
            return self._scan_python(file)

        if language in {
            "javascript",
            "javascriptreact",
            "typescript",
            "typescriptreact",
            "js",
            "ts",
        }:
            return self._scan_javascript(file)

        return []

    def _scan_python(
        self,
        file: AttackSurfaceFile,
    ) -> list[AttackSurfaceNode]:
        nodes: list[AttackSurfaceNode] = []
        lines = file.code.splitlines()

        for line_number, line in enumerate(
            lines,
            start=1,
        ):
            nodes.extend(
                self._function_parameter_nodes(
                    file=file,
                    line=line,
                    line_number=line_number,
                    language="python",
                )
            )

            route = self._python_route_pattern.search(
                line
            )

            if route:
                authenticated = self._nearby_authentication(
                    lines,
                    line_number,
                    language="python",
                )

                nodes.append(
                    self._node(
                        kind="http_route",
                        label=(
                            f"{route.group('method').upper()} "
                            f"{route.group('path')}"
                        ),
                        file=file.filename,
                        line=line_number,
                        evidence=line.strip(),
                        framework="fastapi",
                        method=route.group(
                            "method"
                        ).upper(),
                        path=route.group("path"),
                        authenticated=authenticated,
                        risk=(
                            "medium"
                            if authenticated
                            else "high"
                        ),
                    )
                )

            flask_route = (
                self._flask_route_pattern.search(
                    line
                )
            )

            if flask_route:
                methods = re.findall(
                    r"['\"]([A-Z]+)['\"]",
                    flask_route.group("options"),
                )

                method = (
                    ",".join(methods)
                    if methods
                    else "GET"
                )

                authenticated = self._nearby_authentication(
                    lines,
                    line_number,
                    language="python",
                )

                nodes.append(
                    self._node(
                        kind="http_route",
                        label=(
                            f"{method} "
                            f"{flask_route.group('path')}"
                        ),
                        file=file.filename,
                        line=line_number,
                        evidence=line.strip(),
                        framework="flask",
                        method=method,
                        path=flask_route.group("path"),
                        authenticated=authenticated,
                        risk=(
                            "medium"
                            if authenticated
                            else "high"
                        ),
                    )
                )

            (
                pattern_evidence,
                pattern_line_end,
            ) = self._collect_multiline_evidence(
                lines=lines,
                start_index=line_number - 1,
                patterns=self._python_patterns,
            )

            nodes.extend(
                self._match_patterns(
                    file=file,
                    line=pattern_evidence,
                    line_number=line_number,
                    line_end=pattern_line_end,
                    patterns=self._python_patterns,
                )
            )

        return nodes

    def _scan_javascript(
        self,
        file: AttackSurfaceFile,
    ) -> list[AttackSurfaceNode]:
        nodes: list[AttackSurfaceNode] = []
        lines = file.code.splitlines()

        for line_number, line in enumerate(
            lines,
            start=1,
        ):
            nodes.extend(
                self._function_parameter_nodes(
                    file=file,
                    line=line,
                    line_number=line_number,
                    language="javascript",
                )
            )

            route = self._express_route_pattern.search(
                line
            )

            if route:
                authenticated = self._nearby_authentication(
                    lines,
                    line_number,
                    language="javascript",
                )

                nodes.append(
                    self._node(
                        kind="http_route",
                        label=(
                            f"{route.group('method').upper()} "
                            f"{route.group('path')}"
                        ),
                        file=file.filename,
                        line=line_number,
                        evidence=line.strip(),
                        framework="express",
                        method=route.group(
                            "method"
                        ).upper(),
                        path=route.group("path"),
                        authenticated=authenticated,
                        risk=(
                            "medium"
                            if authenticated
                            else "high"
                        ),
                    )
                )

            (
                pattern_evidence,
                pattern_line_end,
            ) = self._collect_multiline_evidence(
                lines=lines,
                start_index=line_number - 1,
                patterns=self._javascript_patterns,
            )

            nodes.extend(
                self._match_patterns(
                    file=file,
                    line=pattern_evidence,
                    line_number=line_number,
                    line_end=pattern_line_end,
                    patterns=self._javascript_patterns,
                )
            )

        return nodes

    @staticmethod
    def _collect_multiline_evidence(
        *,
        lines: list[str],
        start_index: int,
        patterns: tuple[_Pattern, ...],
        max_lines: int = 30,
    ) -> tuple[str, int]:
        first_line = lines[start_index]
        stripped_first_line = first_line.strip()

        starts_relevant_match = any(
            pattern.expression.search(first_line)
            is not None
            for pattern in patterns
        )

        if not starts_relevant_match:
            return stripped_first_line, start_index + 1

        evidence_lines = [stripped_first_line]

        balance = (
            first_line.count("(")
            - first_line.count(")")
        )

        if balance <= 0:
            return first_line.strip(), start_index + 1

        final_index = start_index
        limit = min(
            len(lines),
            start_index + max_lines,
        )

        for index in range(
            start_index + 1,
            limit,
        ):
            current = lines[index]
            evidence_lines.append(current.strip())

            balance += (
                current.count("(")
                - current.count(")")
            )
            final_index = index

            if balance <= 0:
                break

        return (
            "\n".join(evidence_lines),
            final_index + 1,
        )

    def _function_parameter_nodes(
        self,
        *,
        file: AttackSurfaceFile,
        line: str,
        line_number: int,
        language: str,
    ) -> list[AttackSurfaceNode]:
        if language == "python":
            declaration = re.match(
                r"^\s*(?:async\s+)?def\s+"
                r"[A-Za-z_]\w*\s*\((?P<parameters>[^)]*)\)",
                line,
            )
            framework = "python"
        else:
            declaration = re.match(
                r"^\s*(?:export\s+)?(?:async\s+)?"
                r"function\s+"
                r"[A-Za-z_$][A-Za-z0-9_$]*"
                r"\s*\((?P<parameters>[^)]*)\)",
                line,
            )
            framework = "nodejs"

        if declaration is None:
            return []

        nodes: list[AttackSurfaceNode] = []

        for raw_parameter in declaration.group(
            "parameters"
        ).split(","):
            parameter = raw_parameter.strip()

            if not parameter:
                continue

            parameter = parameter.split("=", 1)[0]
            parameter = parameter.split(":", 1)[0]
            parameter = parameter.lstrip("*").strip()

            match = re.fullmatch(
                r"[A-Za-z_$][A-Za-z0-9_$]*",
                parameter,
            )

            if match is None:
                continue

            symbol = match.group(0)

            nodes.append(
                self._node(
                    kind="function_parameter",
                    label=f"Function parameter: {symbol}",
                    file=file.filename,
                    line=line_number,
                    evidence=line.strip(),
                    framework=framework,
                    risk="medium",
                    symbol=symbol,
                )
            )

        return nodes

    def _match_patterns(
        self,
        *,
        file: AttackSurfaceFile,
        line: str,
        line_number: int,
        line_end: int | None = None,
        patterns: tuple[_Pattern, ...],
    ) -> list[AttackSurfaceNode]:
        return [
            self._node(
                kind=pattern.kind,
                label=pattern.label,
                file=file.filename,
                line=line_number,
                line_end=line_end,
                evidence=line.strip(),
                framework=pattern.framework,
                risk=pattern.risk,
            )
            for pattern in patterns
            if pattern.expression.search(line)
        ]

    def _nearby_authentication(
        self,
        lines: list[str],
        route_line: int,
        *,
        language: str,
    ) -> bool:
        start = max(route_line - 1, 0)
        end = min(
            route_line + 7,
            len(lines),
        )

        context = "\n".join(
            lines[start:end]
        )

        patterns = (
            self._python_patterns
            if language == "python"
            else self._javascript_patterns
        )

        auth_pattern = next(
            pattern
            for pattern in patterns
            if pattern.kind == "authentication"
        )

        return bool(
            auth_pattern.expression.search(context)
        )

    @staticmethod
    def _expression_occurs(
        expression: str,
        text: str,
    ) -> bool:
        if re.fullmatch(
            r"[A-Za-z_$][A-Za-z0-9_$]*",
            expression,
        ):
            return (
                re.search(
                    rf"(?<![A-Za-z0-9_$])"
                    rf"{re.escape(expression)}"
                    rf"(?![A-Za-z0-9_$])",
                    text,
                )
                is not None
            )

        return expression in text

    @staticmethod
    def _nested_tainted_flow_steps(
        *,
        sink_expression: str,
        tainted_names: list[str],
    ) -> list[str]:
        nested_call_pattern = re.compile(
            r"(?P<name>"
            r"[A-Za-z_$][A-Za-z0-9_$]*"
            r"(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*"
            r")\s*\("
            r"(?P<arguments>[^()]*)"
            r"\)"
        )

        outer_call = re.search(
            r"(?:\breturn\s+)?"
            r"(?P<name>"
            r"[A-Za-z_$][A-Za-z0-9_$]*"
            r"(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*"
            r")\s*\(",
            sink_expression,
        )

        if outer_call is None:
            return []

        outer_name_start = outer_call.start("name")
        steps: list[str] = []

        for match in nested_call_pattern.finditer(
            sink_expression
        ):
            # A single-layer sink such as requests.get(target)
            # is the outer operation, not a nested transformation.
            if match.start("name") == outer_name_start:
                continue

            call = match.group(0).strip()
            arguments = match.group("arguments")

            contains_tainted_name = any(
                AttackSurfaceMapper._expression_occurs(
                    name,
                    arguments,
                )
                for name in tainted_names
            )

            if (
                contains_tainted_name
                and call not in steps
            ):
                steps.append(call)

        if not steps:
            return []

        outer_step = (
            f"{outer_call.group('name')}(...)"
        )

        return [
            *steps,
            outer_step,
        ]

    @staticmethod
    def _trace_local_data_flow(
        *,
        code: str,
        source_expression: str,
        sink_expression: str,
        source_line: int | None = None,
        sink_line: int | None = None,
    ) -> list[str]:
        lines = code.splitlines()

        source_index: int | None = (
            source_line - 1
            if source_line is not None
            else None
        )
        sink_index: int | None = (
            sink_line - 1
            if sink_line is not None
            else None
        )

        for index, line in enumerate(lines):
            if (
                source_index is None
                and AttackSurfaceMapper._expression_occurs(
                    source_expression,
                    line,
                )
            ):
                source_index = index

            if (
                sink_index is None
                and sink_expression in line
            ):
                sink_index = index

        if (
            source_index is None
            or sink_index is None
            or source_index > sink_index
            or source_index >= len(lines)
            or sink_index >= len(lines)
        ):
            return []

        function_declaration = re.compile(
            r"^\s*(?:export\s+)?(?:async\s+)?"
            r"(?:def|function)\s+"
            r"[A-Za-z_$][A-Za-z0-9_$]*"
            r"\s*\("
        )

        if any(
            function_declaration.match(lines[index])
            for index in range(
                source_index + 1,
                sink_index + 1,
            )
        ):
            return []

        assignment_pattern = re.compile(
            r"^\s*(?:(?:const|let|var)\s+)?"
            r"(?P<target>[A-Za-z_$][A-Za-z0-9_$]*)"
            r"(?:\s*:\s*[^=]+)?"
            r"\s*=\s*"
            r"(?P<value>.+?)"
            r"\s*;?\s*$"
        )

        tainted_variables: list[str] = []

        for index in range(
            source_index,
            sink_index + 1,
        ):
            line = lines[index]
            assignment = assignment_pattern.match(line)

            if assignment is None:
                continue

            target = assignment.group("target")
            value = assignment.group("value")

            receives_source = (
                AttackSurfaceMapper._expression_occurs(
                    source_expression,
                    value,
                )
            )
            receives_tainted_value = any(
                re.search(
                    rf"\b{re.escape(variable)}\b",
                    value,
                )
                is not None
                for variable in tainted_variables
            )

            if (
                receives_source
                or receives_tainted_value
            ):
                if target not in tainted_variables:
                    tainted_variables.append(target)

        sink_text = sink_expression

        source_reaches_sink = (
            AttackSurfaceMapper._expression_occurs(
                source_expression,
                sink_text,
            )
            or any(
                re.search(
                    rf"\b{re.escape(variable)}\b",
                    sink_text,
                )
                is not None
                for variable in tainted_variables
            )
        )

        if not source_reaches_sink:
            return []

        tainted_names = list(
            dict.fromkeys(
                [
                    source_expression,
                    *tainted_variables,
                ]
            )
        )

        nested_steps = (
            AttackSurfaceMapper
            ._nested_tainted_flow_steps(
                sink_expression=sink_expression,
                tainted_names=tainted_names,
            )
        )

        return [
            source_expression,
            *tainted_variables,
            *(
                nested_steps
                if nested_steps
                else [sink_expression]
            ),
        ]

    def _build_edges(
        self,
        *,
        nodes: list[AttackSurfaceNode],
        files: list[AttackSurfaceFile],
    ) -> list[AttackSurfaceEdge]:
        edges: list[AttackSurfaceEdge] = []

        routes = [
            node
            for node in nodes
            if node.kind == "http_route"
        ]

        for route in routes:
            for node in nodes:
                if (
                    node.file != route.file
                    or node.id == route.id
                    or node.kind == "http_route"
                ):
                    continue

                distance = (
                    node.line_start
                    - route.line_start
                )

                if 0 <= distance <= 40:
                    edges.append(
                        AttackSurfaceEdge(
                            source=route.id,
                            target=node.id,
                            relationship=(
                                f"route_reaches_{node.kind}"
                            ),
                            confidence=(
                                0.85
                                if distance <= 15
                                else 0.65
                            ),
                        )
                    )

        file_code = {
            file.filename: file.code
            for file in files
        }

        source_nodes = [
            node
            for node in nodes
            if node.kind in {
                "user_input",
                "function_parameter",
            }
        ]

        sink_kinds = {
            "database",
            "filesystem",
            "outbound_request",
            "process_execution",
        }

        sink_nodes = [
            node
            for node in nodes
            if node.kind in sink_kinds
        ]

        for source in source_nodes:
            code = file_code.get(source.file)

            if code is None:
                continue

            source_expression = (
                source.symbol
                if source.kind == "function_parameter"
                else self._extract_source_expression(
                    source.evidence
                )
            )

            if not source_expression:
                continue

            for sink in sink_nodes:
                if (
                    sink.file != source.file
                    or sink.line_start
                    < source.line_start
                ):
                    continue

                flow = self._trace_local_data_flow(
                    code=code,
                    source_expression=source_expression,
                    sink_expression=sink.evidence,
                    source_line=source.line_start,
                    sink_line=sink.line_start,
                )

                if not flow:
                    continue

                intermediate_count = max(
                    len(flow) - 2,
                    0,
                )

                confidence = max(
                    0.78,
                    0.96
                    - (0.04 * intermediate_count),
                )

                edges.append(
                    AttackSurfaceEdge(
                        source=source.id,
                        target=sink.id,
                        relationship="data_flow",
                        confidence=confidence,
                    )
                )

        return self._deduplicate_edges(edges)

    @staticmethod
    def _extract_source_expression(
        evidence: str,
    ) -> str:
        stripped = evidence.strip().rstrip(";")

        assignment = re.match(
            r"^(?:(?:const|let|var)\s+)?"
            r"[A-Za-z_$][A-Za-z0-9_$]*"
            r"(?:\s*:\s*[^=]+)?"
            r"\s*=\s*(?P<value>.+)$",
            stripped,
        )

        if assignment:
            return assignment.group("value").strip()

        source_patterns = (
            r"request\.(?:args|form|json|query_params|"
            r"path_params)[^,;)]*(?:\([^)]*\))?",
            r"(?:req|request)\."
            r"(?:body|query|params|headers|cookies)"
            r"(?:\.[A-Za-z_$][A-Za-z0-9_$]*)?",
        )

        for pattern in source_patterns:
            match = re.search(
                pattern,
                stripped,
                flags=re.IGNORECASE,
            )

            if match:
                return match.group(0)

        return ""

    @staticmethod
    def _deduplicate_edges(
        edges: list[AttackSurfaceEdge],
    ) -> list[AttackSurfaceEdge]:
        unique: dict[
            tuple[str, str, str],
            AttackSurfaceEdge,
        ] = {}

        for edge in edges:
            key = (
                edge.source,
                edge.target,
                edge.relationship,
            )

            existing = unique.get(key)

            if (
                existing is None
                or edge.confidence
                > existing.confidence
            ):
                unique[key] = edge

        return sorted(
            unique.values(),
            key=lambda edge: (
                edge.source,
                edge.target,
                edge.relationship,
            ),
        )

    @staticmethod
    def _node(
        *,
        kind: str,
        label: str,
        file: str,
        line: int,
        evidence: str,
        risk: str,
        line_end: int | None = None,
        framework: str | None = None,
        symbol: str | None = None,
        method: str | None = None,
        path: str | None = None,
        authenticated: bool | None = None,
    ) -> AttackSurfaceNode:
        identity = (
            f"{file}:{line}:{kind}:"
            f"{symbol or ''}:"
            f"{method or ''}:{path or ''}:"
            f"{evidence}"
        )

        digest = hashlib.sha256(
            identity.encode("utf-8")
        ).hexdigest()[:16]

        return AttackSurfaceNode(
            id=f"surface-{digest}",
            kind=kind,
            label=label,
            file=file,
            line_start=line,
            line_end=(
                line_end
                if line_end is not None
                else line
            ),
            symbol=symbol,
            framework=framework,
            method=method,
            path=path,
            authenticated=authenticated,
            risk=risk,
            evidence=evidence,
        )

    @staticmethod
    def _deduplicate_nodes(
        nodes: list[AttackSurfaceNode],
    ) -> list[AttackSurfaceNode]:
        unique: dict[
            str,
            AttackSurfaceNode,
        ] = {}

        for node in nodes:
            unique[node.id] = node

        return sorted(
            unique.values(),
            key=lambda node: (
                node.file,
                node.line_start,
                node.kind,
                node.id,
            ),
        )

    @staticmethod
    def _count_kind(
        nodes: list[AttackSurfaceNode],
        kind: str,
    ) -> int:
        return sum(
            node.kind == kind
            for node in nodes
        )
