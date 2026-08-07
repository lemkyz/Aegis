from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from collections.abc import Iterable

from aegis.schemas.attack_graph import (
    AttackGraphArtifact,
    AttackGraphStep,
    AttackGraphSummary,
    AttackPath,
    SensitiveDataExposure,
    TrustBoundaryCrossing,
)
from aegis.schemas.attack_surface import (
    AttackSurfaceEdge,
    AttackSurfaceNode,
    AttackSurfaceScanResponse,
)
from aegis.schemas.threat_model import (
    ThreatFinding,
    ThreatModelScanResponse,
    TrustBoundary,
)


class AttackGraphBuilder:
    name = "aegis-attack-graph-v1"

    _source_kinds = frozenset({
        "http_route",
        "user_input",
        "function_parameter",
        "secret_access",
    })

    _sink_kind_by_category = {
        "command_injection": {
            "process_execution",
        },
        "sql_injection": {
            "database",
        },
        "path_traversal": {
            "filesystem",
        },
        "ssrf": {
            "outbound_request",
        },
        "secret_exposure": {
            "outbound_request",
            "filesystem",
            "database",
            "process_execution",
        },
        "authentication_bypass": {
            "http_route",
            "authentication",
        },
        "unsafe_data_flow": {
            "database",
            "filesystem",
            "outbound_request",
            "process_execution",
            "secret_access",
        },
    }

    _sensitive_markers = {
        "credential": (
            "password",
            "passwd",
            "credential",
            "credentials",
            "api_key",
            "apikey",
            "access_key",
            "client_secret",
            "authorization",
            "bearer",
        ),
        "token": (
            "token",
            "jwt",
            "id_token",
            "access_token",
            "refresh_token",
        ),
        "session": (
            "session",
            "session_id",
            "sessionid",
            "cookie",
        ),
        "pii": (
            "pii",
            "email",
            "e-mail",
            "phone",
            "telephone",
            "ssn",
            "social security",
            "full_name",
            "first_name",
            "last_name",
            "address",
        ),
        "financial": (
            "credit_card",
            "credit card",
            "card_number",
            "cvv",
            "iban",
            "bank_account",
            "payment",
            "financial",
        ),
        "health": (
            "patient",
            "medical",
            "diagnosis",
            "health_record",
            "health record",
        ),
        "secret": (
            "secret",
            "private_key",
            "private key",
            "encryption_key",
            "signing_key",
            "api_key",
            "apikey",
        ),
    }

    _sink_kinds = frozenset({
        "database",
        "filesystem",
        "outbound_request",
        "process_execution",
        "secret_access",
    })

    def build(
        self,
        *,
        attack_surface: AttackSurfaceScanResponse,
        threat_model: ThreatModelScanResponse,
    ) -> AttackGraphArtifact:
        self._require_matching_provenance(
            attack_surface=attack_surface,
            threat_model=threat_model,
        )

        node_by_id = self._node_index(
            attack_surface.nodes
        )
        data_flow_edges = sorted(
            (
                edge
                for edge in attack_surface.edges
                if edge.relationship == "data_flow"
            ),
            key=self._edge_key,
        )
        boundaries_by_node = (
            self._boundaries_by_node(
                threat_model.trust_boundaries
            )
        )

        attack_paths: list[AttackPath] = []
        crossing_by_id: dict[
            str,
            TrustBoundaryCrossing,
        ] = {}
        exposures: list[
            SensitiveDataExposure
        ] = []

        for threat in sorted(
            threat_model.threats,
            key=lambda item: item.id,
        ):
            threat_paths = self._paths_for_threat(
                threat=threat,
                node_by_id=node_by_id,
                edges=data_flow_edges,
                boundaries_by_node=(
                    boundaries_by_node
                ),
                crossing_by_id=crossing_by_id,
            )
            attack_paths.extend(
                threat_paths
            )

            for path in threat_paths:
                exposure = (
                    self._exposure_for_path(
                        path=path,
                        threat=threat,
                        node_by_id=node_by_id,
                    )
                )
                if exposure is not None:
                    exposures.append(
                        exposure
                    )

        attack_paths = sorted(
            attack_paths,
            key=lambda item: item.path_id,
        )
        crossings = sorted(
            crossing_by_id.values(),
            key=lambda item: item.crossing_id,
        )
        exposures = sorted(
            exposures,
            key=lambda item: item.exposure_id,
        )

        return AttackGraphArtifact(
            builder=self.name,
            source_artifacts=[
                "attack_surface_graph",
                "threat_model",
            ],
            attack_paths=attack_paths,
            boundary_crossings=crossings,
            sensitive_data_exposures=(
                exposures
            ),
            summary=AttackGraphSummary(
                attack_paths=len(
                    attack_paths
                ),
                boundary_crossings=len(
                    crossings
                ),
                sensitive_data_exposures=len(
                    exposures
                ),
                critical_paths=sum(
                    item.risk == "critical"
                    for item in attack_paths
                ),
                high_paths=sum(
                    item.risk == "high"
                    for item in attack_paths
                ),
                confirmed_paths=sum(
                    item.exploitability
                    == "confirmed"
                    for item in attack_paths
                ),
            ),
        )

    def _paths_for_threat(
        self,
        *,
        threat: ThreatFinding,
        node_by_id: dict[
            str,
            AttackSurfaceNode,
        ],
        edges: list[AttackSurfaceEdge],
        boundaries_by_node: dict[
            str,
            list[TrustBoundary],
        ],
        crossing_by_id: dict[
            str,
            TrustBoundaryCrossing,
        ],
    ) -> list[AttackPath]:
        if not threat.data_flow:
            return []

        threat_nodes = {
            node_id
            for node_id
            in threat.source_node_ids
            if node_id in node_by_id
        }
        if len(threat_nodes) < 2:
            return []

        sink = self._sink_for_threat(
            threat=threat,
            node_by_id=node_by_id,
            threat_nodes=threat_nodes,
        )
        if sink is None:
            return []

        paths: list[AttackPath] = []

        for edge in edges:
            if (
                edge.target != sink.id
                or edge.source not in threat_nodes
                or edge.target not in threat_nodes
            ):
                continue

            source = node_by_id.get(
                edge.source
            )
            if source is None:
                continue

            if (
                source.kind
                not in self._source_kinds
            ):
                continue

            crossing_ids = (
                self._crossings_for_nodes(
                    node_ids=[
                        source.id,
                        sink.id,
                    ],
                    boundaries_by_node=(
                        boundaries_by_node
                    ),
                    crossing_by_id=(
                        crossing_by_id
                    ),
                )
            )

            step_evidence = (
                self._step_evidence(
                    edge=edge,
                    threat=threat,
                    source=source,
                    sink=sink,
                )
            )
            confidence = (
                self._path_confidence(
                    edge=edge,
                    threat=threat,
                )
            )
            path_id = self._stable_id(
                "attack-path",
                threat.id,
                source.id,
                sink.id,
                edge.relationship,
                *step_evidence,
            )

            paths.append(
                AttackPath(
                    path_id=path_id,
                    threat_id=threat.id,
                    source_node_id=source.id,
                    sink_node_id=sink.id,
                    node_ids=[
                        source.id,
                        sink.id,
                    ],
                    steps=[
                        AttackGraphStep(
                            source_node_id=source.id,
                            target_node_id=sink.id,
                            relationship=(
                                edge.relationship
                            ),
                            confidence=(
                                edge.confidence
                            ),
                            evidence=(
                                step_evidence
                            ),
                        )
                    ],
                    boundary_crossing_ids=(
                        crossing_ids
                    ),
                    risk=threat.severity,
                    exploitability=(
                        threat.exploitability
                    ),
                    confidence=confidence,
                    evidence=(
                        self._path_evidence(
                            threat=threat,
                            source=source,
                            sink=sink,
                        )
                    ),
                )
            )

        return sorted(
            paths,
            key=lambda item: item.path_id,
        )

    def _sink_for_threat(
        self,
        *,
        threat: ThreatFinding,
        node_by_id: dict[
            str,
            AttackSurfaceNode,
        ],
        threat_nodes: set[str],
    ) -> AttackSurfaceNode | None:
        preferred_kinds = (
            self._sink_kind_by_category.get(
                threat.category,
                self._sink_kinds,
            )
        )

        candidates = [
            node_by_id[node_id]
            for node_id in threat_nodes
            if (
                node_by_id[node_id].file
                == threat.file
                and (
                    node_by_id[node_id]
                    .line_start
                    == threat.line
                )
            )
        ]

        preferred = [
            node
            for node in candidates
            if node.kind in preferred_kinds
        ]
        if preferred:
            return sorted(
                preferred,
                key=lambda node: (
                    node.kind,
                    node.id,
                ),
            )[0]

        fallback = [
            node_by_id[node_id]
            for node_id in threat_nodes
            if (
                node_by_id[node_id].kind
                in preferred_kinds
            )
        ]
        if fallback:
            return sorted(
                fallback,
                key=lambda node: (
                    node.file,
                    node.line_start,
                    node.kind,
                    node.id,
                ),
            )[0]

        return None

    def _crossings_for_nodes(
        self,
        *,
        node_ids: list[str],
        boundaries_by_node: dict[
            str,
            list[TrustBoundary],
        ],
        crossing_by_id: dict[
            str,
            TrustBoundaryCrossing,
        ],
    ) -> list[str]:
        crossing_ids: list[str] = []

        for node_id in node_ids:
            for boundary in (
                boundaries_by_node.get(
                    node_id,
                    [],
                )
            ):
                direction = (
                    self._boundary_direction(
                        boundary.boundary_type
                    )
                )
                crossing_id = self._stable_id(
                    "boundary-crossing",
                    boundary.id,
                    node_id,
                    direction,
                )
                crossing = (
                    TrustBoundaryCrossing(
                        crossing_id=crossing_id,
                        boundary_id=boundary.id,
                        boundary_type=(
                            boundary.boundary_type
                        ),
                        node_id=node_id,
                        direction=direction,
                        evidence=[
                            boundary.evidence
                        ],
                    )
                )
                previous = (
                    crossing_by_id.get(
                        crossing_id
                    )
                )
                if (
                    previous is not None
                    and previous != crossing
                ):
                    raise ValueError(
                        "Trust-boundary crossing "
                        "identity collision."
                    )
                crossing_by_id[
                    crossing_id
                ] = crossing
                crossing_ids.append(
                    crossing_id
                )

        return sorted(
            set(crossing_ids)
        )

    def _exposure_for_path(
        self,
        *,
        path: AttackPath,
        threat: ThreatFinding,
        node_by_id: dict[
            str,
            AttackSurfaceNode,
        ],
    ) -> SensitiveDataExposure | None:
        source = node_by_id[
            path.source_node_id
        ]
        sink = node_by_id[
            path.sink_node_id
        ]

        classes = self._data_classes(
            threat=threat,
            source=source,
            sink=sink,
        )
        if not classes:
            return None

        sink_kind = (
            sink.kind
            if sink.kind in self._sink_kinds
            else "unknown"
        )

        exposure_id = self._stable_id(
            "data-exposure",
            path.path_id,
            source.id,
            sink.id,
            *classes,
        )

        return SensitiveDataExposure(
            exposure_id=exposure_id,
            path_id=path.path_id,
            source_node_id=source.id,
            sink_node_id=sink.id,
            data_classes=classes,
            sink_kind=sink_kind,
            risk=path.risk,
            evidence=[
                (
                    "Sensitive data markers are "
                    "present on a graph-proven "
                    "source-to-sink path."
                ),
                *(
                    [
                        "Data flow: "
                        + " -> ".join(
                            threat.data_flow
                        )
                    ]
                    if threat.data_flow
                    else []
                ),
            ],
        )

    def _data_classes(
        self,
        *,
        threat: ThreatFinding,
        source: AttackSurfaceNode,
        sink: AttackSurfaceNode,
    ) -> list[str]:
        material = "\n".join(
            [
                source.label,
                source.evidence,
                json.dumps(
                    source.metadata,
                    sort_keys=True,
                ),
                sink.label,
                sink.evidence,
                json.dumps(
                    sink.metadata,
                    sort_keys=True,
                ),
                threat.title,
                threat.description,
                threat.affected_asset,
                "\n".join(
                    threat.evidence
                ),
                "\n".join(
                    threat.data_flow
                ),
            ]
        ).lower()

        classes: set[str] = set()

        for class_name, markers in (
            self._sensitive_markers.items()
        ):
            if any(
                marker in material
                for marker in markers
            ):
                classes.add(
                    class_name
                )

        if (
            threat.category
            == "secret_exposure"
        ):
            classes.add("secret")

        if source.kind == "secret_access":
            classes.add("secret")

        return sorted(classes)

    @staticmethod
    def _path_confidence(
        *,
        edge: AttackSurfaceEdge,
        threat: ThreatFinding,
    ) -> float:
        values = [
            edge.confidence,
            threat.confidence,
        ]
        if (
            threat.exploitability_confidence
            > 0
        ):
            values.append(
                threat
                .exploitability_confidence
            )
        return min(values)

    @staticmethod
    def _step_evidence(
        *,
        edge: AttackSurfaceEdge,
        threat: ThreatFinding,
        source: AttackSurfaceNode,
        sink: AttackSurfaceNode,
    ) -> list[str]:
        evidence = [
            source.evidence,
            sink.evidence,
            (
                "Graph relationship: "
                f"{edge.relationship} "
                f"({edge.confidence:.2f})."
            ),
        ]
        if threat.data_flow:
            evidence.append(
                "Data flow: "
                + " -> ".join(
                    threat.data_flow
                )
            )
        return AttackGraphBuilder._unique(
            evidence
        )

    @staticmethod
    def _path_evidence(
        *,
        threat: ThreatFinding,
        source: AttackSurfaceNode,
        sink: AttackSurfaceNode,
    ) -> list[str]:
        evidence = [
            (
                f"Threat {threat.id}: "
                f"{threat.title}"
            ),
            (
                "Source: "
                f"{source.file}:"
                f"{source.line_start} "
                f"{source.label}"
            ),
            (
                "Sink: "
                f"{sink.file}:"
                f"{sink.line_start} "
                f"{sink.label}"
            ),
            *threat.evidence,
            *threat.exploitability_reasons,
        ]
        if threat.data_flow:
            evidence.append(
                "Data flow: "
                + " -> ".join(
                    threat.data_flow
                )
            )
        return AttackGraphBuilder._unique(
            evidence
        )

    @staticmethod
    def _boundary_direction(
        boundary_type: str,
    ) -> str:
        if boundary_type in {
            "network_input",
            "untrusted_input",
        }:
            return "entry"

        if boundary_type == (
            "external_network"
        ):
            return "outbound"

        return "internal"

    @staticmethod
    def _boundaries_by_node(
        boundaries: Iterable[
            TrustBoundary
        ],
    ) -> dict[
        str,
        list[TrustBoundary],
    ]:
        result: dict[
            str,
            list[TrustBoundary],
        ] = defaultdict(list)

        for boundary in boundaries:
            for node_id in (
                boundary.source_node_ids
            ):
                result[node_id].append(
                    boundary
                )

        for node_id in result:
            result[node_id] = sorted(
                result[node_id],
                key=lambda item: item.id,
            )

        return dict(result)

    @staticmethod
    def _node_index(
        nodes: Iterable[
            AttackSurfaceNode
        ],
    ) -> dict[str, AttackSurfaceNode]:
        result: dict[
            str,
            AttackSurfaceNode,
        ] = {}

        for node in nodes:
            previous = result.get(
                node.id
            )
            if (
                previous is not None
                and previous != node
            ):
                raise ValueError(
                    "Attack surface contains a "
                    "node identity collision."
                )
            result[node.id] = node

        return result

    @staticmethod
    def _require_matching_provenance(
        *,
        attack_surface: AttackSurfaceScanResponse,
        threat_model: ThreatModelScanResponse,
    ) -> None:
        surface_nodes = (
            AttackGraphBuilder
            ._canonical_models(
                attack_surface.nodes
            )
        )
        modeled_nodes = (
            AttackGraphBuilder
            ._canonical_models(
                threat_model
                .attack_surface_nodes
            )
        )
        surface_edges = (
            AttackGraphBuilder
            ._canonical_models(
                attack_surface.edges
            )
        )
        modeled_edges = (
            AttackGraphBuilder
            ._canonical_models(
                threat_model
                .attack_surface_edges
            )
        )

        if (
            surface_nodes != modeled_nodes
            or surface_edges
            != modeled_edges
        ):
            raise ValueError(
                "Attack graph provenance drift: "
                "the attack surface does not match "
                "the graph embedded in the threat "
                "model."
            )

    @staticmethod
    def _canonical_models(
        items: Iterable[object],
    ) -> list[str]:
        return sorted(
            json.dumps(
                item.model_dump(
                    mode="json"
                ),
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
            for item in items
        )

    @staticmethod
    def _edge_key(
        edge: AttackSurfaceEdge,
    ) -> tuple[str, str, str, float]:
        return (
            edge.source,
            edge.target,
            edge.relationship,
            edge.confidence,
        )

    @staticmethod
    def _unique(
        values: Iterable[str],
    ) -> list[str]:
        seen: set[str] = set()
        result: list[str] = []

        for value in values:
            normalized = value.strip()
            if (
                not normalized
                or normalized in seen
            ):
                continue
            seen.add(normalized)
            result.append(normalized)

        return result

    @staticmethod
    def _stable_id(
        prefix: str,
        *parts: str,
    ) -> str:
        material = json.dumps(
            [prefix, *parts],
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        digest = hashlib.sha256(
            material
        ).hexdigest()
        return f"{prefix}:sha256:{digest}"
