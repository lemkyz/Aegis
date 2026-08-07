import * as vscode from "vscode";

export type AttackGraphRisk =
  | "info"
  | "low"
  | "medium"
  | "high"
  | "critical";

export type AttackGraphExploitability =
  | "confirmed"
  | "likely"
  | "possible"
  | "unlikely"
  | "not_exploitable"
  | "unknown";

export interface AttackGraphStep {
  source_node_id: string;
  target_node_id: string;
  relationship: string;
  confidence: number;
  evidence: string[];
}

export interface TrustBoundaryCrossing {
  crossing_id: string;
  boundary_id: string;
  boundary_type: string;
  node_id: string;
  direction:
    | "entry"
    | "exit"
    | "outbound"
    | "internal";
  evidence: string[];
}

export interface AttackPath {
  path_id: string;
  threat_id: string;
  source_node_id: string;
  sink_node_id: string;
  node_ids: string[];
  steps: AttackGraphStep[];
  boundary_crossing_ids: string[];
  risk: AttackGraphRisk;
  exploitability: AttackGraphExploitability;
  confidence: number;
  evidence: string[];
}

export interface SensitiveDataExposure {
  exposure_id: string;
  path_id: string;
  source_node_id: string;
  sink_node_id: string;
  data_classes: string[];
  sink_kind: string;
  risk: AttackGraphRisk;
  evidence: string[];
}

export interface AttackGraphArtifact {
  schema_version: "1.0";
  builder: string;
  source_artifacts: string[];
  attack_paths: AttackPath[];
  boundary_crossings: TrustBoundaryCrossing[];
  sensitive_data_exposures: SensitiveDataExposure[];
  summary: {
    attack_paths: number;
    boundary_crossings: number;
    sensitive_data_exposures: number;
    critical_paths: number;
    high_paths: number;
    confirmed_paths: number;
  };
}

interface SurfaceNode {
  node_id: string;
  label: string;
  kind: string;
  file: string;
  line_start: number;
  risk: string;
  evidence: string;
}

interface ThreatSummary {
  threat_id: string;
  title: string;
  category: string;
  severity: string;
  exploitability: string;
  file: string;
  line: number;
}

function isRecord(
  value: unknown,
): value is Record<string, unknown> {
  return (
    typeof value === "object"
    && value !== null
    && !Array.isArray(value)
  );
}

function stringValue(
  value: unknown,
  fallback = "",
): string {
  return typeof value === "string"
    ? value
    : fallback;
}

function numberValue(
  value: unknown,
  fallback = 0,
): number {
  return typeof value === "number"
    ? value
    : fallback;
}

function normalizeSurfaceNodes(
  attackSurface: unknown,
): SurfaceNode[] {
  if (!isRecord(attackSurface)) {
    return [];
  }

  const nodes = attackSurface.nodes;
  if (!Array.isArray(nodes)) {
    return [];
  }

  return nodes
    .filter(isRecord)
    .map((node) => ({
      node_id: stringValue(node.node_id),
      label: stringValue(
        node.label,
        stringValue(node.node_id, "Unknown node"),
      ),
      kind: stringValue(node.kind, "unknown"),
      file: stringValue(node.file, "unknown"),
      line_start: numberValue(node.line_start, 1),
      risk: stringValue(node.risk, "unknown"),
      evidence: stringValue(node.evidence),
    }))
    .filter((node) => node.node_id.length > 0);
}

function normalizeThreats(
  threatModel: unknown,
): ThreatSummary[] {
  if (!isRecord(threatModel)) {
    return [];
  }

  const threats = threatModel.threats;
  if (!Array.isArray(threats)) {
    return [];
  }

  return threats
    .filter(isRecord)
    .map((threat) => ({
      threat_id: stringValue(threat.threat_id),
      title: stringValue(
        threat.title,
        stringValue(threat.threat_id, "Attack path"),
      ),
      category: stringValue(threat.category, "unknown"),
      severity: stringValue(threat.severity, "unknown"),
      exploitability: stringValue(
        threat.exploitability,
        "unknown",
      ),
      file: stringValue(threat.file, "unknown"),
      line: numberValue(threat.line, 1),
    }))
    .filter((threat) => threat.threat_id.length > 0);
}

function escapeHtml(value: unknown): string {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function humanize(value: string): string {
  return value
    .replaceAll("_", " ")
    .replace(/\b\w/g, (letter) =>
      letter.toUpperCase());
}

function compactIdentity(value: string): string {
  if (value.length <= 42) {
    return value;
  }

  return `${value.slice(0, 18)}…${value.slice(-18)}`;
}

function riskClass(
  risk: AttackGraphRisk,
): string {
  return `risk-${risk}`;
}

function nodeCard(
  nodeId: string,
  nodes: Map<string, SurfaceNode>,
): string {
  const node = nodes.get(nodeId);

  if (!node) {
    return [
      '<div class="flow-node">',
      '<span class="node-kind">Graph node</span>',
      `<strong>${escapeHtml(compactIdentity(nodeId))}</strong>`,
      `<code>${escapeHtml(nodeId)}</code>`,
      "</div>",
    ].join("");
  }

  return [
    '<div class="flow-node">',
    `<span class="node-kind">${escapeHtml(humanize(node.kind))}</span>`,
    `<strong>${escapeHtml(node.label)}</strong>`,
    `<span class="node-location">${escapeHtml(node.file)}:${node.line_start}</span>`,
    "</div>",
  ].join("");
}

function pathFlow(
  path: AttackPath,
  nodes: Map<string, SurfaceNode>,
): string {
  return path.node_ids
    .map((nodeId, index) => {
      const node = nodeCard(nodeId, nodes);
      if (index === path.node_ids.length - 1) {
        return node;
      }

      const step = path.steps[index];
      const relationship = step
        ? humanize(step.relationship)
        : "Data Flow";

      return [
        node,
        '<div class="flow-arrow">',
        '<span class="arrow-line"></span>',
        `<span>${escapeHtml(relationship)}</span>`,
        '<span class="arrow-glyph">→</span>',
        "</div>",
      ].join("");
    })
    .join("");
}

function evidenceList(
  evidence: string[],
): string {
  if (evidence.length === 0) {
    return '<p class="muted">No additional evidence recorded.</p>';
  }

  return [
    '<ul class="evidence-list">',
    ...evidence.slice(0, 8).map(
      (item) =>
        `<li>${escapeHtml(item)}</li>`,
    ),
    "</ul>",
  ].join("");
}

function crossingSection(
  path: AttackPath,
  crossings: Map<string, TrustBoundaryCrossing>,
): string {
  const items = path.boundary_crossing_ids
    .map((id) => crossings.get(id))
    .filter(
      (item): item is TrustBoundaryCrossing =>
        item !== undefined,
    );

  if (items.length === 0) {
    return [
      '<div class="proof-block">',
      '<div class="proof-label">Trust boundaries</div>',
      '<p class="muted">No boundary crossing is attached to this path.</p>',
      "</div>",
    ].join("");
  }

  return [
    '<div class="proof-block">',
    '<div class="proof-label">Trust boundaries</div>',
    '<div class="boundary-grid">',
    ...items.map((item) => [
      '<div class="boundary-chip">',
      `<span>${escapeHtml(humanize(item.boundary_type))}</span>`,
      `<strong>${escapeHtml(item.direction.toUpperCase())}</strong>`,
      "</div>",
    ].join("")),
    "</div>",
    "</div>",
  ].join("");
}

function exposureSection(
  path: AttackPath,
  exposures: SensitiveDataExposure[],
): string {
  const items = exposures.filter(
    (item) => item.path_id === path.path_id,
  );

  if (items.length === 0) {
    return "";
  }

  return [
    '<div class="path-sentinel">',
    '<div class="proof-label">Data Sentinel</div>',
    ...items.map((item) => [
      '<div class="sentinel-row">',
      '<div>',
      `<span class="sentinel-class">${escapeHtml(
        item.data_classes
          .map(humanize)
          .join(" · "),
      )}</span>`,
      `<p>Flow reaches ${escapeHtml(humanize(item.sink_kind))}</p>`,
      "</div>",
      `<span class="risk-pill ${riskClass(item.risk)}">${escapeHtml(
        item.risk.toUpperCase(),
      )}</span>`,
      "</div>",
    ].join("")),
    "</div>",
  ].join("");
}

function pathCard(
  path: AttackPath,
  index: number,
  nodes: Map<string, SurfaceNode>,
  threats: Map<string, ThreatSummary>,
  crossings: Map<string, TrustBoundaryCrossing>,
  exposures: SensitiveDataExposure[],
): string {
  const threat = threats.get(path.threat_id);

  const title = threat?.title
    ?? humanize(path.threat_id);

  const category = threat?.category
    ? humanize(threat.category)
    : "Graph-proven path";

  const confidence =
    `${Math.round(path.confidence * 100)}%`;

  return [
    `<details class="path-card ${riskClass(path.risk)}" ${index === 0 ? "open" : ""}>`,
    "<summary>",
    '<div class="path-heading">',
    `<span class="path-index">PATH ${String(index + 1).padStart(2, "0")}</span>`,
    `<h3>${escapeHtml(title)}</h3>`,
    `<p>${escapeHtml(category)}</p>`,
    "</div>",
    '<div class="path-badges">',
    `<span class="risk-pill ${riskClass(path.risk)}">${escapeHtml(
      path.risk.toUpperCase(),
    )}</span>`,
    `<span class="proof-pill">${escapeHtml(
      humanize(path.exploitability),
    )}</span>`,
    `<span class="confidence">${escapeHtml(confidence)}</span>`,
    "</div>",
    "</summary>",
    '<div class="path-body">',
    '<div class="flow-label">Proven source → sink chain</div>',
    `<div class="flow">${pathFlow(path, nodes)}</div>`,
    '<div class="proof-grid">',
    crossingSection(path, crossings),
    '<div class="proof-block">',
    '<div class="proof-label">Evidence</div>',
    evidenceList(path.evidence),
    "</div>",
    "</div>",
    exposureSection(path, exposures),
    `<div class="identity">Proof identity · ${escapeHtml(path.path_id)}</div>`,
    "</div>",
    "</details>",
  ].join("");
}

function sentinelSection(
  exposures: SensitiveDataExposure[],
  nodes: Map<string, SurfaceNode>,
): string {
  if (exposures.length === 0) {
    return [
      '<section class="section sentinel-section">',
      '<div class="section-heading">',
      '<div><span class="eyebrow">DATA SENTINEL</span>',
      "<h2>No graph-proven sensitive-data exposure</h2></div>",
      '<span class="sentinel-state clean">NO CLAIM</span>',
      "</div>",
      '<p class="section-copy">',
      "Aegis will not infer a sensitive-data leak without a proven path. ",
      "Attack paths remain visible above, but no data-exposure claim is emitted.",
      "</p>",
      "</section>",
    ].join("");
  }

  return [
    '<section class="section sentinel-section">',
    '<div class="section-heading">',
    '<div><span class="eyebrow">DATA SENTINEL</span>',
    `<h2>${exposures.length} sensitive-data exposure${exposures.length === 1 ? "" : "s"}</h2></div>`,
    `<span class="sentinel-state hot">${exposures.length} PROVEN</span>`,
    "</div>",
    '<div class="exposure-grid">',
    ...exposures.map((item) => {
      const source = nodes.get(item.source_node_id);
      const sink = nodes.get(item.sink_node_id);

      return [
        '<article class="exposure-card">',
        '<div class="exposure-top">',
        `<span class="risk-pill ${riskClass(item.risk)}">${escapeHtml(
          item.risk.toUpperCase(),
        )}</span>`,
        `<span>${escapeHtml(humanize(item.sink_kind))}</span>`,
        "</div>",
        `<h3>${escapeHtml(item.data_classes.map(humanize).join(" · "))}</h3>`,
        '<div class="exposure-flow">',
        `<span>${escapeHtml(source?.label ?? compactIdentity(item.source_node_id))}</span>`,
        "<b>→</b>",
        `<span>${escapeHtml(sink?.label ?? compactIdentity(item.sink_node_id))}</span>`,
        "</div>",
        evidenceList(item.evidence),
        "</article>",
      ].join("");
    }),
    "</div>",
    "</section>",
  ].join("");
}

function renderHtml(
  webview: vscode.Webview,
  artifact: AttackGraphArtifact,
  attackSurface: unknown,
  threatModel: unknown,
): string {
  const nodes = new Map(
    normalizeSurfaceNodes(attackSurface)
      .map((node) => [node.node_id, node]),
  );

  const threats = new Map(
    normalizeThreats(threatModel)
      .map((threat) => [
        threat.threat_id,
        threat,
      ]),
  );

  const crossings = new Map(
    artifact.boundary_crossings.map(
      (item) => [
        item.crossing_id,
        item,
      ],
    ),
  );

  const criticalOrHigh =
    artifact.summary.critical_paths
    + artifact.summary.high_paths;

  const paths = artifact.attack_paths.length === 0
    ? [
      '<div class="empty-state">',
      "<strong>No proven attack path.</strong>",
      "<span>Aegis did not materialize a source-to-sink chain from the supplied evidence.</span>",
      "</div>",
    ].join("")
    : artifact.attack_paths
      .map((path, index) =>
        pathCard(
          path,
          index,
          nodes,
          threats,
          crossings,
          artifact.sensitive_data_exposures,
        ))
      .join("");

  const csp = [
    "default-src 'none'",
    "img-src data:",
    "style-src 'unsafe-inline'",
  ].join("; ");

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta
  http-equiv="Content-Security-Policy"
  content="${escapeHtml(csp)}"
>
<meta
  name="viewport"
  content="width=device-width, initial-scale=1.0"
>
<title>Aegis Attack Graph</title>
<style>
:root {
  color-scheme: light;
  --ivory: #f7f3ea;
  --paper: #fffdf8;
  --ink: #10100f;
  --muted: #716c63;
  --line: #e8e2d6;
  --gold: #c6a24a;
  --gold-soft: #eadcae;
  --red: #b5473f;
  --red-soft: #f5d9d5;
  --orange: #a76021;
  --orange-soft: #f5e2cf;
  --green: #466a53;
  --green-soft: #dce9df;
}
* { box-sizing: border-box; }
html, body {
  margin: 0;
  min-height: 100%;
  background: var(--ivory);
  color: var(--ink);
  font-family:
    Inter,
    ui-sans-serif,
    -apple-system,
    BlinkMacSystemFont,
    "Segoe UI",
    sans-serif;
}
body { padding: 0 0 64px; }
.hero {
  background: var(--ink);
  color: var(--ivory);
  padding: 38px 44px 34px;
  border-bottom: 3px solid var(--gold);
}
.hero-top {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 24px;
}
.wordmark {
  font-size: 13px;
  letter-spacing: .28em;
  font-weight: 800;
  color: var(--gold-soft);
}
.proof-status {
  border: 1px solid #4b493f;
  color: #ece4cf;
  border-radius: 999px;
  padding: 7px 11px;
  font-size: 11px;
  letter-spacing: .08em;
}
.hero h1 {
  max-width: 900px;
  margin: 30px 0 12px;
  font-size: clamp(34px, 5vw, 64px);
  line-height: .98;
  letter-spacing: -.045em;
}
.hero p {
  max-width: 720px;
  color: #c8c2b7;
  font-size: 15px;
  line-height: 1.7;
}
.hero strong { color: var(--ivory); }
.shell {
  max-width: 1280px;
  margin: 0 auto;
  padding: 28px 34px;
}
.metrics {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
  margin-top: -46px;
  position: relative;
}
.metric {
  background: var(--paper);
  border: 1px solid var(--line);
  border-top: 3px solid var(--gold);
  padding: 18px;
  min-height: 108px;
  box-shadow: 0 12px 36px rgba(16,16,15,.08);
}
.metric span {
  display: block;
  color: var(--muted);
  text-transform: uppercase;
  letter-spacing: .1em;
  font-size: 10px;
  font-weight: 700;
}
.metric strong {
  display: block;
  margin-top: 13px;
  font-size: 29px;
  letter-spacing: -.035em;
}
.metric small {
  display: block;
  margin-top: 4px;
  color: var(--muted);
}
.section {
  margin-top: 34px;
}
.section-heading {
  display: flex;
  align-items: end;
  justify-content: space-between;
  gap: 18px;
  margin-bottom: 14px;
}
.eyebrow {
  color: #8d7029;
  letter-spacing: .17em;
  font-size: 10px;
  font-weight: 800;
}
.section h2 {
  margin: 5px 0 0;
  font-size: 27px;
  letter-spacing: -.025em;
}
.section-copy {
  max-width: 800px;
  color: var(--muted);
  line-height: 1.65;
}
.path-card {
  margin: 12px 0;
  background: var(--paper);
  border: 1px solid var(--line);
  border-left: 4px solid var(--gold);
}
.path-card.risk-critical {
  border-left-color: var(--red);
}
.path-card.risk-high {
  border-left-color: var(--orange);
}
.path-card summary {
  cursor: pointer;
  list-style: none;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 22px;
  padding: 19px 22px;
}
.path-card summary::-webkit-details-marker {
  display: none;
}
.path-heading h3 {
  margin: 5px 0 4px;
  font-size: 17px;
}
.path-heading p {
  margin: 0;
  color: var(--muted);
  font-size: 12px;
}
.path-index {
  font-size: 9px;
  color: #8d7029;
  letter-spacing: .15em;
  font-weight: 800;
}
.path-badges {
  display: flex;
  align-items: center;
  gap: 7px;
  flex-wrap: wrap;
  justify-content: flex-end;
}
.risk-pill,
.proof-pill,
.confidence {
  border-radius: 999px;
  padding: 6px 9px;
  font-size: 9px;
  font-weight: 800;
  letter-spacing: .07em;
  white-space: nowrap;
}
.risk-pill { background: #ece7dc; }
.risk-pill.risk-critical {
  color: #842e29;
  background: var(--red-soft);
}
.risk-pill.risk-high {
  color: #7f4515;
  background: var(--orange-soft);
}
.risk-pill.risk-medium {
  color: #745a12;
  background: #f0e7c7;
}
.risk-pill.risk-low,
.risk-pill.risk-info {
  color: #3f6450;
  background: var(--green-soft);
}
.proof-pill {
  color: #4d421f;
  background: var(--gold-soft);
}
.confidence {
  background: var(--ink);
  color: var(--ivory);
}
.path-body {
  border-top: 1px solid var(--line);
  padding: 22px;
}
.flow-label,
.proof-label {
  color: var(--muted);
  text-transform: uppercase;
  letter-spacing: .11em;
  font-size: 9px;
  font-weight: 800;
  margin-bottom: 10px;
}
.flow {
  display: flex;
  align-items: stretch;
  gap: 7px;
  overflow-x: auto;
  padding: 4px 0 18px;
}
.flow-node {
  min-width: 180px;
  max-width: 220px;
  border: 1px solid var(--line);
  background: #fff;
  padding: 13px 14px;
}
.node-kind {
  color: #8d7029;
  font-size: 9px;
  text-transform: uppercase;
  letter-spacing: .09em;
}
.flow-node strong {
  display: block;
  margin-top: 8px;
  line-height: 1.35;
}
.flow-node code,
.node-location {
  display: block;
  margin-top: 8px;
  color: var(--muted);
  font-size: 10px;
  overflow-wrap: anywhere;
}
.flow-arrow {
  min-width: 92px;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  color: #8d7029;
  font-size: 9px;
  text-align: center;
  gap: 5px;
}
.arrow-line {
  width: 46px;
  height: 1px;
  background: var(--gold);
}
.arrow-glyph {
  font-size: 18px;
  line-height: 1;
}
.proof-grid {
  display: grid;
  grid-template-columns: minmax(220px, .75fr) minmax(280px, 1.25fr);
  gap: 12px;
}
.proof-block {
  background: #f4efe5;
  border: 1px solid var(--line);
  padding: 15px;
}
.boundary-grid {
  display: flex;
  flex-wrap: wrap;
  gap: 7px;
}
.boundary-chip {
  display: flex;
  align-items: center;
  gap: 8px;
  background: var(--paper);
  border: 1px solid #ded4c0;
  padding: 8px 10px;
  font-size: 10px;
}
.boundary-chip strong {
  color: #8d7029;
  font-size: 8px;
  letter-spacing: .08em;
}
.evidence-list {
  margin: 0;
  padding-left: 18px;
  color: #45423c;
  line-height: 1.55;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 10px;
}
.path-sentinel {
  margin-top: 12px;
  border: 1px solid #e3cfc9;
  background: #fbefec;
  padding: 15px;
}
.sentinel-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 16px;
  border-top: 1px solid #ead7d2;
  padding: 11px 0;
}
.sentinel-row:first-of-type {
  border-top: 0;
}
.sentinel-row p {
  margin: 4px 0 0;
  color: var(--muted);
  font-size: 11px;
}
.sentinel-class {
  font-weight: 800;
  font-size: 12px;
}
.identity {
  margin-top: 14px;
  color: #9b958b;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 9px;
  overflow-wrap: anywhere;
}
.sentinel-section {
  background: var(--ink);
  color: var(--ivory);
  padding: 25px;
  border-top: 3px solid var(--gold);
}
.sentinel-section .eyebrow {
  color: var(--gold-soft);
}
.sentinel-section .section-copy {
  color: #bcb5a9;
}
.sentinel-state {
  border-radius: 999px;
  padding: 7px 10px;
  font-size: 9px;
  font-weight: 800;
  letter-spacing: .08em;
}
.sentinel-state.clean {
  color: #a8cbb1;
  background: #23352a;
}
.sentinel-state.hot {
  color: #ffd6cd;
  background: #572821;
}
.exposure-grid {
  display: grid;
  grid-template-columns: repeat(
    auto-fit,
    minmax(280px, 1fr)
  );
  gap: 12px;
  margin-top: 16px;
}
.exposure-card {
  background: #1b1b19;
  border: 1px solid #393832;
  padding: 17px;
}
.exposure-card h3 {
  margin: 16px 0 13px;
}
.exposure-top,
.exposure-flow {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
}
.exposure-top {
  color: #a9a397;
  font-size: 10px;
}
.exposure-flow {
  background: #11110f;
  border: 1px solid #33322e;
  padding: 10px;
  font-size: 10px;
}
.exposure-flow b {
  color: var(--gold);
}
.exposure-card .evidence-list {
  margin-top: 13px;
  color: #c7c0b5;
}
.provenance {
  margin-top: 30px;
  padding: 17px 19px;
  border: 1px solid var(--line);
  background: rgba(255,255,255,.45);
  display: flex;
  justify-content: space-between;
  gap: 16px;
  align-items: center;
}
.provenance strong {
  display: block;
  margin-bottom: 4px;
}
.provenance span {
  color: var(--muted);
  font-size: 10px;
}
.provenance code {
  font-size: 9px;
  color: #6b592c;
}
.empty-state {
  border: 1px dashed #cfc5b3;
  padding: 24px;
  color: var(--muted);
}
.empty-state strong {
  color: var(--ink);
  display: block;
  margin-bottom: 5px;
}
.muted {
  color: var(--muted);
  margin: 0;
  line-height: 1.55;
}
@media (max-width: 820px) {
  .metrics {
    grid-template-columns: repeat(2, 1fr);
  }
  .proof-grid {
    grid-template-columns: 1fr;
  }
  .path-card summary,
  .section-heading,
  .provenance {
    align-items: flex-start;
    flex-direction: column;
  }
  .path-badges {
    justify-content: flex-start;
  }
}
</style>
</head>
<body>
<header class="hero">
  <div class="hero-top">
    <div class="wordmark">AEGIS</div>
    <div class="proof-status">DETERMINISTIC · EVIDENCE-BOUND</div>
  </div>
  <h1>Attack Graph <span style="color:#c6a24a">/</span> Data Sentinel</h1>
  <p>
    Aegis does not stop at “a risk exists.”
    It materializes the <strong>source → sink path</strong>,
    records each trust-boundary crossing, and only emits
    sensitive-data claims when the graph proves them.
  </p>
</header>

<main class="shell">
  <section class="metrics">
    <div class="metric">
      <span>Proven attack paths</span>
      <strong>${artifact.summary.attack_paths}</strong>
      <small>${artifact.summary.confirmed_paths} confirmed</small>
    </div>
    <div class="metric">
      <span>Trust crossings</span>
      <strong>${artifact.summary.boundary_crossings}</strong>
      <small>material graph boundaries</small>
    </div>
    <div class="metric">
      <span>Sensitive flows</span>
      <strong>${artifact.summary.sensitive_data_exposures}</strong>
      <small>Data Sentinel claims</small>
    </div>
    <div class="metric">
      <span>High / critical</span>
      <strong>${criticalOrHigh}</strong>
      <small>paths requiring attention</small>
    </div>
  </section>

  <section class="section">
    <div class="section-heading">
      <div>
        <span class="eyebrow">PROOF GRAPH</span>
        <h2>Materialized attack paths</h2>
      </div>
      <span class="proof-pill">${artifact.summary.confirmed_paths} CONFIRMED</span>
    </div>
    <p class="section-copy">
      Every card below is derived from the exact attack-surface
      and threat-model artifacts supplied to the deterministic
      Attack Graph builder.
    </p>
    ${paths}
  </section>

  ${sentinelSection(
    artifact.sensitive_data_exposures,
    nodes,
  )}

  <section class="provenance">
    <div>
      <strong>Security claims need proof.</strong>
      <span>
        Builder ${escapeHtml(artifact.builder)} · schema
        ${escapeHtml(artifact.schema_version)}
      </span>
    </div>
    <code>${escapeHtml(artifact.source_artifacts.join(" → "))}</code>
  </section>
</main>
</body>
</html>`;
}

export function showAttackGraphPanel(
  artifact: AttackGraphArtifact,
  attackSurface: unknown,
  threatModel: unknown,
): void {
  const panel = vscode.window.createWebviewPanel(
    "aegis.attackGraph",
    "Aegis · Attack Graph / Data Sentinel",
    vscode.ViewColumn.Beside,
    {
      enableScripts: false,
      retainContextWhenHidden: true,
    },
  );

  panel.webview.html = renderHtml(
    panel.webview,
    artifact,
    attackSurface,
    threatModel,
  );
}
