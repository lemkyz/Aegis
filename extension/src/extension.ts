import { execFile } from "node:child_process";
import * as path from "node:path";
import { readdir, stat } from "node:fs/promises";
import { promisify } from "node:util";
import * as vscode from "vscode";
import {
  postBackendJson,
} from "./backendClient";
import {
  MAX_MODEL_CONTEXT_FILES,
  MAX_MODEL_FILE_BYTES,
  MAX_MODEL_PAYLOAD_BYTES,
  MAX_WORKSPACE_FILE_BYTES,
  MAX_WORKSPACE_SCAN_FILES,
  WORKSPACE_EXCLUDE_GLOB,
  WORKSPACE_SOURCE_GLOB,
  createPayloadBudget,
  readSafeWorkspaceFile,
} from "./workspaceSafety";

const execFileAsync = promisify(execFile);

const aegisReportScheme = "aegis-report";

type AegisReportKind =
  | "analysis"
  | "workspace"
  | "git-changes"
  | "dependencies"
  | "fix-verification"
  | "attack-surface"
  | "threat-model";

class AegisReportContentProvider
  implements vscode.TextDocumentContentProvider {
  private readonly contents =
    new Map<string, string>();

  private readonly changeEmitter =
    new vscode.EventEmitter<vscode.Uri>();

  readonly onDidChange =
    this.changeEmitter.event;

  provideTextDocumentContent(
    uri: vscode.Uri,
  ): string {
    return (
      this.contents.get(uri.toString()) ??
      "# Aegis Report\n\nNo report content is available."
    );
  }

  update(
    uri: vscode.Uri,
    content: string,
  ): void {
    this.contents.set(
      uri.toString(),
      content,
    );

    this.changeEmitter.fire(uri);
  }

  dispose(): void {
    this.contents.clear();
    this.changeEmitter.dispose();
  }
}

type Severity = "info" | "low" | "medium" | "high" | "critical";
type AnalysisMode = "fast" | "deep";

interface ScannerEvidence {
  tool: string;
  rule_id: string;
  message: string;
  severity: string;
  file: string;
  line_start: number;
  line_end: number;
  code: string | null;
}

type ConsensusVerdict =
  | "confirmed"
  | "disputed"
  | "uncertain"
  | "unverified";

type ModelConsensusStatus =
  | "completed"
  | "partial"
  | "failed";

interface FindingConsensusDecision {
  finding_index: number;
  verdict: ConsensusVerdict;
  confidence: number;
  primary_confidence: number;
  verifier_confidence: number | null;
  reasons: string[];
}

type RouteIndependence =
  | "same_route"
  | "same_model_distinct_endpoint"
  | "same_provider_distinct_model"
  | "independent";

interface ModelConsensusResult {
  primary_provider: string | null;
  primary_model: string;
  verifier_provider: string | null;
  verifier_model: string | null;
  route_independence: RouteIndependence | null;
  independently_verified: boolean | null;
  route_reasons: string[];
  status: ModelConsensusStatus;
  decisions: FindingConsensusDecision[];
  errors: string[];
}

interface SecurityFinding {
  title: string;
  severity: Severity;
  confidence: number;

  primary_model?: string | null;

  verifier_model?: string | null;
  verifier_verdict?: string | null;
  verifier_confidence?: number | null;
  verifier_reasoning?: string | null;
  verifier_evidence?: string[];

  consensus_verdict?: ConsensusVerdict | null;
  consensus_confidence?: number | null;
  consensus_reasons?: string[];

  summary: string;
  evidence: string[];
  scanner_evidence: ScannerEvidence[];
  cwe: string[];
  owasp: string[];
  vulnerable_lines: number[];
  false_positive_notes: string[];
  recommended_fix: string;
  proposed_patch: string | null;
}

type ClaimState =
  | "suspected"
  | "supported"
  | "confirmed"
  | "mitigated"
  | "verified_fixed"
  | "false_positive"
  | "accepted_risk"
  | "inconclusive";

type EvidenceKind =
  | "scanner"
  | "semantic_analysis"
  | "data_flow"
  | "runtime_execution"
  | "dynamic_probe"
  | "test_result"
  | "patch_diff"
  | "user_decision"
  | "model_review"
  | "model_verification"
  | "model_consensus";

interface ClaimCodeLocation {
  file: string;
  line_start: number;
  line_end: number;
  symbol: string | null;
}

interface ClaimEvidenceSource {
  kind: EvidenceKind;
  name: string;
  rule_id: string | null;
  version: string | null;
}

interface ClaimEvidenceItem {
  evidence_id: string;
  source: ClaimEvidenceSource;
  summary: string;
  confidence: number;
  locations: ClaimCodeLocation[];
  details: string[];
  observed_at: string | null;
}

interface ClaimEvidenceRelationship {
  relationship_id: string;
  source_evidence_id: string;
  target_evidence_id: string;
  kind:
    | "supports"
    | "contradicts"
    | "corroborates"
    | "derived_from"
    | "verifies"
    | "mitigates";
  reason: string | null;
}

interface SecurityClaim {
  schema_version: string;
  claim_id: string;
  statement: string;
  category: string;
  severity: Severity;
  confidence: number;
  state: ClaimState;
  cwe: string[];
  owasp: string[];
  locations: ClaimCodeLocation[];
  evidence: ClaimEvidenceItem[];
  relationships: ClaimEvidenceRelationship[];
  remediation: string | null;
  proposed_patch: string | null;
}

interface AnalyzeResponse {
  filename: string;
  language: string;
  model: string;
  scanner: string;
  analysis_status?: "completed" | "skipped" | "fallback";
  result_source?: "scanner" | "ai" | "scanner_fallback";
  findings: SecurityFinding[];
  claims?: SecurityClaim[];
  model_consensus?: ModelConsensusResult | null;
}


type ClaimDeltaStatus =
  | "new"
  | "persistent"
  | "changed"
  | "resolved"
  | "reopened";

interface RepositoryContext {
  schema_version: string;
  project_id: string;
  repository_root: string;
  identity_source:
    | "git_remote"
    | "local_path";
  remote: string | null;
  branch: string | null;
  head_commit: string | null;
  revision: string;
  dirty: boolean;
}

interface ProjectSecuritySnapshot {
  schema_version: string;
  snapshot_id: string;
  project_id: string;
  revision: string | null;
  created_at: string;
  claims: SecurityClaim[];
  claim_count: number;
}

interface ClaimDelta {
  claim_id: string;
  status: ClaimDeltaStatus;
  previous_state: ClaimState | null;
  current_state: ClaimState | null;
  reasons: string[];
}

interface ClaimReconciliationSummary {
  new: number;
  persistent: number;
  changed: number;
  resolved: number;
  reopened: number;
}

interface ClaimReconciliationResponse {
  reconciler: string;
  deltas: ClaimDelta[];
  summary: ClaimReconciliationSummary;
}

interface SecurityMemoryRecordResponse {
  service: string;
  repository: RepositoryContext;
  snapshot: ProjectSecuritySnapshot;
  previous_snapshot_id: string | null;
  reconciliation: ClaimReconciliationResponse;
  baseline_created: boolean;
  persisted_new_snapshot: boolean;
  project_snapshot_count: number;
}

type PolicyDecision =
  | "allow"
  | "review"
  | "block";

type PolicyRiskLevel =
  | "none"
  | "low"
  | "medium"
  | "high"
  | "critical";

interface PolicyClaimAssessment {
  claim_id: string;
  lifecycle_status: ClaimDeltaStatus;
  severity: Severity;
  confidence: number;
  risk_score: number;
  risk_level: PolicyRiskLevel;
  decision: PolicyDecision;
  reasons: string[];
}

interface MemoryPolicySummary {
  claims_evaluated: number;
  claims_ignored: number;
  allowed: number;
  review_required: number;
  blocked: number;
  highest_risk_score: number;
  highest_risk_level: PolicyRiskLevel;
  new: number;
  persistent: number;
  changed: number;
  reopened: number;
}

interface MemoryPolicyDecisionResponse {
  engine: string;
  policy_version: string;
  profile: "balanced";
  decision: PolicyDecision;
  risk_score: number;
  risk_level: PolicyRiskLevel;
  blocking_claim_ids: string[];
  review_claim_ids: string[];
  assessments: PolicyClaimAssessment[];
  summary: MemoryPolicySummary;
  reasons: string[];
}

interface SecurityMemoryPolicyRecordResponse {
  memory: SecurityMemoryRecordResponse;
  policy: MemoryPolicyDecisionResponse;
}

interface SecurityMemoryDisplay {
  response?: SecurityMemoryPolicyRecordResponse;
  error?: string;
}

interface LastAnalysis {
  documentUri: string;
  documentVersion: number;
  selection: vscode.Range;
  response: AnalyzeResponse;
  mode: AnalysisMode;
}

type ValidationTestType =
  | "command_injection"
  | "sql_injection"
  | "path_traversal"
  | "ssrf"
  | "authentication_bypass"
  | "unsafe_data_flow";

type ValidationRuntime = "python" | "node";

interface ValidationAuthorizationRequest {
  authorization_confirmed: boolean;
  target_type: "local_repository";
  target: string;
  allowed_test_types: ValidationTestType[];
  dry_run: boolean;
  timeout_seconds: number;
  memory_limit_mb: number;
  cpu_limit: number;
  network_policy: "disabled";
}

interface ValidationPlanRequest {
  authorization: ValidationAuthorizationRequest;
  runtime: ValidationRuntime;
  entrypoint: string;
  test_type: ValidationTestType;
}

interface ValidationExecutionResult {
  runner: string;
  status:
    | "completed"
    | "failed"
    | "timed_out"
    | "runtime_unavailable"
    | "rejected";
  runtime_executable: string | null;
  started: boolean;
  timed_out: boolean;
  exit_code: number | null;
  duration_ms: number;
  stdout: string;
  stderr: string;
  argv: string[];
  reasons: string[];
  denials: string[];
}

interface ValidationSuccessCriteria {
  expected_exit_code: number;
  stdout_contains?: string;
  stderr_contains?: string;
}

interface DynamicValidationEvidenceResponse {
  evaluator: string;
  threat_id: string;
  category: ValidationTestType;
  verdict:
    | "confirmed"
    | "not_reproduced"
    | "blocked"
    | "execution_error"
    | "timed_out";
  dynamically_confirmed: boolean;
  confidence: number;
  evidence: string[];
  reasons: string[];
  execution_status: ValidationExecutionResult["status"];
  exit_code: number | null;
  duration_ms: number;
}

interface ValidationReplayComparison {
  comparator: string;
  threat_id: string;
  category: ValidationTestType;
  verdict:
    | "fixed"
    | "still_exploitable"
    | "inconclusive";
  fixed: boolean;
  confidence: number;
  before_verdict:
    DynamicValidationEvidenceResponse["verdict"];
  after_verdict:
    DynamicValidationEvidenceResponse["verdict"];
  reasons: string[];
  denials: string[];
}

interface ValidationReplayResponse {
  orchestrator: string;
  threat_id: string;
  category: ValidationTestType;
  before_execution: ValidationExecutionResult;
  before_evidence:
    DynamicValidationEvidenceResponse;
  after_execution: ValidationExecutionResult;
  after_evidence:
    DynamicValidationEvidenceResponse;
  comparison: ValidationReplayComparison;
}

type UnifiedFixVerdict =
  | "verified"
  | "project_failed"
  | "target_not_resolved"
  | "regression_detected"
  | "still_exploitable"
  | "inconclusive";

interface UnifiedFixVerificationResponse {
  evaluator: string;
  threat_id: string;
  category: ValidationTestType;
  verdict: UnifiedFixVerdict;
  verified: boolean;
  confidence: number;
  project_checks_passed: boolean;
  static_target_resolved: boolean;
  static_regression_free: boolean;
  dynamic_replay_fixed: boolean;
  reasons: string[];
  failed_checks: string[];
}

interface AuthorizedDynamicBaseline {
  documentUri: string;
  documentVersion: number;
  repositoryRoot: string;
  threatId: string;
  category: ValidationTestType;
  plan: ValidationPlanRequest;
  successCriteria: ValidationSuccessCriteria;
  beforeExecution: ValidationExecutionResult;
  beforeEvidence: DynamicValidationEvidenceResponse;
}

interface AnalysisInput {
  backendUrl: string;
  code: string;
  filename: string;
  language: string;
  mode: AnalysisMode;
}

type VerificationStatus =
  | "passed"
  | "failed"
  | "skipped";

interface VerificationCheckResult {
  name: string;
  status: VerificationStatus;
  command?: string;
  details: string;
}

interface SecurityVerificationDelta {
  targetRuleIds: string[];
  remainingTargetFindings: SecurityFinding[];
  introducedFindings: SecurityFinding[];
  unchangedFindings: SecurityFinding[];
}

interface ProjectVerificationSuite {
  syntax: VerificationCheckResult;
  tests: VerificationCheckResult;
  build: VerificationCheckResult;
}

type DynamicReplayReportStatus =
  | "fixed"
  | "still_exploitable"
  | "inconclusive"
  | "not_run";

interface DynamicReplayReport {
  status: DynamicReplayReportStatus;
  confidence?: number;
  beforeVerdict?: string;
  afterVerdict?: string;
  reasons: string[];
}

interface FixVerificationReportInput {
  fileName: string;
  status: "VERIFIED" | "PARTIAL" | "FAILED";
  projectVerification: ProjectVerificationSuite;
  targetResolved?: boolean;
  regressionFree?: boolean;
  securityDelta?: SecurityVerificationDelta;
  dynamicReplay?: DynamicReplayReport;
  unifiedVerdict?: string;
  rollbackStatus?: string;
}

interface WorkspaceFileResult {
  uri: vscode.Uri;
  relativePath: string;
  response: AnalyzeResponse;
}

interface WorkspaceScanSummary {
  filesDiscovered: number;
  filesScanned: number;
  filesSkipped: number;
  filesFailed: number;
  results: WorkspaceFileResult[];
  errors: string[];
}

type ChangePolicyDecision =
  | "allow"
  | "review"
  | "block";

type ChangePolicyRiskLevel =
  | "none"
  | "low"
  | "medium"
  | "high"
  | "critical";

interface ChangeFilePolicyAssessment {
  path: string;
  old_path: string | null;
  status:
    | "added"
    | "modified"
    | "deleted"
    | "renamed"
    | "copied";
  risk_score: number;
  risk_level: ChangePolicyRiskLevel;
  decision: ChangePolicyDecision;
  reasons: string[];
}

interface ChangePolicySummary {
  files_evaluated: number;
  allowed: number;
  review_required: number;
  blocked: number;
  highest_risk_score: number;
  highest_risk_level: ChangePolicyRiskLevel;
  sensitive_files: number;
  dangerous_patterns: number;
  truncated_files: number;
  binary_files: number;
}

interface ChangePolicyDecisionResponse {
  engine: string;
  policy_version: string;
  profile: string;
  decision: ChangePolicyDecision;
  risk_score: number;
  risk_level: ChangePolicyRiskLevel;
  blocking_paths: string[];
  review_paths: string[];
  assessments: ChangeFilePolicyAssessment[];
  summary: ChangePolicySummary;
  reasons: string[];
}

interface ChangeSetSummary {
  collector: string;
  schema_version: string;
  repository_root: string;
  mode: "staged" | "uncommitted";
  base_revision: string | null;
  head_revision: string | null;
  file_count: number;
  additions: number;
  deletions: number;
  truncated: boolean;
}

interface ChangePolicyCollectionResponse {
  change_set: ChangeSetSummary;
  policy: ChangePolicyDecisionResponse;
}

interface ChangePolicyDisplay {
  response?: ChangePolicyCollectionResponse;
  error?: string;
}

type DependencyEcosystem =
  | "PyPI"
  | "npm"
  | "Maven"
  | "Go"
  | "NuGet"
  | "crates.io"
  | "Packagist";

type DependencySeverity =
  | "unknown"
  | "low"
  | "medium"
  | "high"
  | "critical";

interface DependencyPackage {
  name: string;
  version: string;
  ecosystem: DependencyEcosystem;
  manifest: string;
  direct: boolean;
}

interface DependencyManifestInput {
  filename: string;
  manifest: string;
  content: string;
}

interface DependencyManifestScanResponse {
  packages: DependencyPackage[];
  scan: DependencyScanResponse;
}

interface DependencyVulnerability {
  id: string;
  aliases: string[];
  package_name: string;
  installed_version: string;
  ecosystem: string;
  manifest: string;
  direct: boolean;
  summary: string;
  details: string;
  severity: DependencySeverity;
  fixed_versions: string[];
  references: string[];
  published: string | null;
  modified: string | null;
}

type DependencyScanStatus =
  | "completed"
  | "partial"
  | "failed";

interface DependencyScanResponse {
  scanner: string;
  packages_scanned: number;
  successful_packages: number;
  failed_packages: number;
  scan_status: DependencyScanStatus;
  errors: string[];
  vulnerable_packages: number;
  vulnerabilities: DependencyVulnerability[];
}

type AttackSurfaceNodeKind =
  | "http_route"
  | "authentication"
  | "user_input"
  | "function_parameter"
  | "database"
  | "filesystem"
  | "outbound_request"
  | "process_execution"
  | "secret_access";

type AttackSurfaceRisk =
  | "info"
  | "low"
  | "medium"
  | "high"
  | "critical";

interface AttackSurfaceFileInput {
  filename: string;
  language: string;
  code: string;
}

interface AttackSurfaceNode {
  id: string;
  kind: AttackSurfaceNodeKind;
  label: string;
  file: string;
  line_start: number;
  line_end: number;
  symbol: string | null;
  framework: string | null;
  method: string | null;
  path: string | null;
  authenticated: boolean | null;
  risk: AttackSurfaceRisk;
  evidence: string;
  metadata: Record<string, string>;
}

interface AttackSurfaceEdge {
  source: string;
  target: string;
  relationship: string;
  confidence: number;
}

interface AttackSurfaceSummary {
  files_scanned: number;
  nodes_found: number;
  edges_found: number;
  routes: number;
  authenticated_routes: number;
  unauthenticated_routes: number;
  databases: number;
  filesystems: number;
  outbound_requests: number;
  process_executions: number;
  secret_accesses: number;
}

interface AttackSurfaceScanResponse {
  mapper: string;
  nodes: AttackSurfaceNode[];
  edges: AttackSurfaceEdge[];
  summary: AttackSurfaceSummary;
}

type ThreatCategory =
  | "command_injection"
  | "sql_injection"
  | "path_traversal"
  | "ssrf"
  | "secret_exposure"
  | "authentication_bypass"
  | "unsafe_data_flow";

type ThreatSeverity = Severity;

type Exploitability =
  | "confirmed"
  | "likely"
  | "possible"
  | "unlikely"
  | "not_exploitable"
  | "unknown";

interface ThreatAsset {
  id: string;
  name: string;
  kind: string;
  file: string;
  line: number;
  description: string;
  source_node_ids: string[];
}

interface TrustBoundary {
  id: string;
  label: string;
  file: string;
  line: number;
  boundary_type: string;
  evidence: string;
  source_node_ids: string[];
}

interface ThreatFinding {
  id: string;
  title: string;
  category: ThreatCategory;
  severity: ThreatSeverity;
  confidence: number;
  file: string;
  line: number;
  entry_point: string | null;
  affected_asset: string;
  trust_boundary: string | null;
  description: string;
  attack_path: string[];
  mitigations: string[];
  evidence: string[];
  source_node_ids: string[];
  data_flow: string[];
  exploitability: Exploitability;
  exploitability_confidence: number;
  exploitability_reasons: string[];
  prerequisites: string[];
  blocking_controls: string[];
}

interface ThreatModelSummary {
  files_scanned: number;
  assets_found: number;
  trust_boundaries_found: number;
  threats_found: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

interface ThreatModelScanResponse {
  modeler: string;
  attack_surface_nodes: AttackSurfaceNode[];
  attack_surface_edges: AttackSurfaceEdge[];
  assets: ThreatAsset[];
  trust_boundaries: TrustBoundary[];
  threats: ThreatFinding[];
  summary: ThreatModelSummary;
}

let lastAnalysis: LastAnalysis | undefined;
let authorizedDynamicBaseline:
  | AuthorizedDynamicBaseline
  | undefined;
let latestWorkspaceScan: WorkspaceScanSummary | undefined;
let reportContentProvider:
  AegisReportContentProvider | undefined;
let latestDependencyScan: DependencyScanResponse | undefined;
let latestAttackSurface: AttackSurfaceScanResponse | undefined;
let latestThreatModel: ThreatModelScanResponse | undefined;
let diagnosticCollection: vscode.DiagnosticCollection | undefined;
let securityTreeProvider: AegisSecurityTreeProvider | undefined;

export function activate(context: vscode.ExtensionContext): void {
  diagnosticCollection =
    vscode.languages.createDiagnosticCollection("aegis");

  reportContentProvider =
    new AegisReportContentProvider();

  const reportProviderRegistration =
    vscode.workspace.registerTextDocumentContentProvider(
      aegisReportScheme,
      reportContentProvider,
    );

  securityTreeProvider = new AegisSecurityTreeProvider();

  const securityTreeView =
    vscode.window.createTreeView("aegis.securityView", {
      treeDataProvider: securityTreeProvider,
      showCollapseAll: true,
    });

  const openWorkspaceFindingCommand =
    vscode.commands.registerCommand(
      "aegis.openWorkspaceFinding",
      openWorkspaceFinding,
    );

  const openDependencyManifestCommand =
    vscode.commands.registerCommand(
      "aegis.openDependencyManifest",
      openDependencyManifest,
    );

  const openAttackSurfaceNodeCommand =
    vscode.commands.registerCommand(
      "aegis.openAttackSurfaceNode",
      openAttackSurfaceNode,
    );

  const refreshSecurityViewCommand =
    vscode.commands.registerCommand(
      "aegis.refreshSecurityView",
      () => securityTreeProvider?.refresh(),
    );

  const fastScanCommand = vscode.commands.registerCommand(
    "aegis.fastScanSelectedCode",
    async () => analyzeSelectedCode("fast"),
  );

  const fastScanCurrentFileCommand = vscode.commands.registerCommand(
    "aegis.fastScanCurrentFile",
    fastScanCurrentFile,
  );

  const scanWorkspaceCommand = vscode.commands.registerCommand(
    "aegis.scanWorkspace",
    scanEntireWorkspace,
  );

  const mapAttackSurfaceCommand =
    vscode.commands.registerCommand(
      "aegis.mapAttackSurface",
      mapWorkspaceAttackSurface,
    );

  const generateThreatModelCommand =
    vscode.commands.registerCommand(
      "aegis.generateThreatModel",
      generateWorkspaceThreatModel,
    );

  const scanDependenciesCommand =
    vscode.commands.registerCommand(
      "aegis.scanDependencies",
      scanDependencies,
    );

  const scanUncommittedChangesCommand =
    vscode.commands.registerCommand(
      "aegis.scanUncommittedChanges",
      () => scanGitChanges("uncommitted"),
    );

  const scanStagedChangesCommand =
    vscode.commands.registerCommand(
      "aegis.scanStagedChanges",
      () => scanGitChanges("staged"),
    );

  const deepAnalysisCommand = vscode.commands.registerCommand(
    "aegis.deepAnalyzeSelectedCode",
    async () => analyzeSelectedCode("deep"),
  );

  const applyFixCommand = vscode.commands.registerCommand(
    "aegis.applySecureFix",
    applySecureFix,
  );

  const runDynamicBaselineCommand =
    vscode.commands.registerCommand(
      "aegis.runAuthorizedDynamicBaseline",
      runAuthorizedDynamicBaseline,
    );

  const deepAnalyzeDiagnosticCommand =
    vscode.commands.registerCommand(
      "aegis.deepAnalyzeDiagnostic",
      deepAnalyzeDiagnostic,
    );

  const openLastReportCommand =
    vscode.commands.registerCommand(
      "aegis.openLastSecurityReport",
      openLastSecurityReport,
    );

  const codeActionProvider =
    vscode.languages.registerCodeActionsProvider(
      {
        scheme: "file",
        language: "*",
      },
      new AegisCodeActionProvider(),
      {
        providedCodeActionKinds: [
          vscode.CodeActionKind.QuickFix,
        ],
      },
    );

  context.subscriptions.push(
    diagnosticCollection,
    reportContentProvider,
    reportProviderRegistration,
    securityTreeView,
    openWorkspaceFindingCommand,
    openDependencyManifestCommand,
    openAttackSurfaceNodeCommand,
    refreshSecurityViewCommand,
    fastScanCommand,
    fastScanCurrentFileCommand,
    scanWorkspaceCommand,
    mapAttackSurfaceCommand,
    generateThreatModelCommand,
    scanDependenciesCommand,
    scanUncommittedChangesCommand,
    scanStagedChangesCommand,
    deepAnalysisCommand,
    applyFixCommand,
    runDynamicBaselineCommand,
    deepAnalyzeDiagnosticCommand,
    openLastReportCommand,
    codeActionProvider,
  );
}

type SecurityTreeElement =
  | SecuritySummaryTreeItem
  | SecurityFileTreeItem
  | SecurityFindingTreeItem
  | SecurityMessageTreeItem
  | DependencyRootTreeItem
  | DependencyPackageTreeItem
  | DependencyVulnerabilityTreeItem
  | AttackSurfaceRootTreeItem
  | AttackSurfaceGroupTreeItem
  | AttackSurfaceNodeTreeItem
  | ThreatModelRootTreeItem
  | ThreatSeverityGroupTreeItem
  | ThreatFindingTreeItem;

class AegisSecurityTreeProvider
  implements vscode.TreeDataProvider<SecurityTreeElement> {
  private readonly changeEmitter =
    new vscode.EventEmitter<
      SecurityTreeElement | undefined | null | void
    >();

  readonly onDidChangeTreeData =
    this.changeEmitter.event;

  refresh(): void {
    this.changeEmitter.fire();
  }

  getTreeItem(
    element: SecurityTreeElement,
  ): vscode.TreeItem {
    return element;
  }

  getChildren(
    element?: SecurityTreeElement,
  ): SecurityTreeElement[] {
    if (!element) {
      const items: SecurityTreeElement[] = [];

      if (latestWorkspaceScan) {
        const findingCount =
          latestWorkspaceScan.results.reduce(
            (total, result) =>
              total + result.response.findings.length,
            0,
          );

        const risk = getWorkspaceRisk(
          latestWorkspaceScan,
        );

        items.push(
          new SecuritySummaryTreeItem(
            `Workspace Risk: ${risk.toUpperCase()}`,
            risk,
          ),
          new SecuritySummaryTreeItem(
            `${findingCount} code finding(s) in ${latestWorkspaceScan.filesScanned} file(s)`,
            "summary",
          ),
        );

        const vulnerableFiles =
          latestWorkspaceScan.results.filter(
            (result) =>
              result.response.findings.length > 0,
          );

        items.push(
          ...vulnerableFiles.map(
            (result) =>
              new SecurityFileTreeItem(result),
          ),
        );
      }

      if (latestThreatModel) {
        items.push(
          new ThreatModelRootTreeItem(
            latestThreatModel,
          ),
        );
      }

      if (latestAttackSurface) {
        items.push(
          new AttackSurfaceRootTreeItem(
            latestAttackSurface,
          ),
        );
      }

      if (latestDependencyScan) {
        items.push(
          new DependencyRootTreeItem(
            latestDependencyScan,
          ),
        );
      }

      if (items.length === 0) {
        return [
          new SecurityMessageTreeItem(
            "Run Workspace Scan or Dependency Scan.",
            "shield",
          ),
        ];
      }

      return items;
    }

    if (element instanceof SecurityFileTreeItem) {
      return element.result.response.findings.map(
        (finding) =>
          new SecurityFindingTreeItem(
            element.result,
            finding,
          ),
      );
    }

    if (element instanceof ThreatModelRootTreeItem) {
      return groupThreatsBySeverity(
        element.result.threats,
      ).map(
        ([severity, threats]) =>
          new ThreatSeverityGroupTreeItem(
            severity,
            threats,
          ),
      );
    }

    if (element instanceof ThreatSeverityGroupTreeItem) {
      return element.threats.map(
        (threat) =>
          new ThreatFindingTreeItem(threat),
      );
    }

    if (element instanceof AttackSurfaceRootTreeItem) {
      return groupAttackSurfaceNodes(
        element.result.nodes,
      ).map(
        ([kind, nodes]) =>
          new AttackSurfaceGroupTreeItem(
            kind,
            nodes,
          ),
      );
    }

    if (element instanceof AttackSurfaceGroupTreeItem) {
      return element.nodes.map(
        (node) =>
          new AttackSurfaceNodeTreeItem(node),
      );
    }

    if (element instanceof DependencyRootTreeItem) {
      const grouped =
        groupDependencyVulnerabilities(
          element.result.vulnerabilities,
        );

      return Array.from(grouped.entries()).map(
        ([packageKey, vulnerabilities]) =>
          new DependencyPackageTreeItem(
            packageKey,
            vulnerabilities,
          ),
      );
    }

    if (element instanceof DependencyPackageTreeItem) {
      return element.vulnerabilities.map(
        (vulnerability) =>
          new DependencyVulnerabilityTreeItem(
            vulnerability,
          ),
      );
    }

    return [];
  }
}

class SecuritySummaryTreeItem extends vscode.TreeItem {
  constructor(
    label: string,
    kind: Severity | "summary" | "none",
  ) {
    super(
      label,
      vscode.TreeItemCollapsibleState.None,
    );

    this.contextValue = "aegisSecuritySummary";

    this.iconPath =
      kind === "critical" || kind === "high"
        ? new vscode.ThemeIcon("error")
        : kind === "medium"
          ? new vscode.ThemeIcon("warning")
          : kind === "low" || kind === "info"
            ? new vscode.ThemeIcon("info")
            : new vscode.ThemeIcon("shield");
  }
}

class SecurityFileTreeItem extends vscode.TreeItem {
  constructor(
    readonly result: WorkspaceFileResult,
  ) {
    super(
      result.relativePath,
      vscode.TreeItemCollapsibleState.Expanded,
    );

    this.description =
      `${result.response.findings.length} finding(s)`;

    this.tooltip =
      `${result.relativePath}\n${this.description}`;

    this.contextValue = "aegisSecurityFile";
    this.resourceUri = result.uri;
    this.iconPath = new vscode.ThemeIcon("file-code");
  }
}

function findingConsensusLabel(
  finding: SecurityFinding,
): string | undefined {
  if (!finding.consensus_verdict) {
    return undefined;
  }

  const verdict = finding.consensus_verdict
    .replaceAll("_", " ")
    .toUpperCase();

  const confidence =
    finding.consensus_confidence;

  if (
    confidence === undefined
    || confidence === null
  ) {
    return verdict;
  }

  return (
    `${verdict} `
    + `${Math.round(confidence * 100)}%`
  );
}


class SecurityFindingTreeItem extends vscode.TreeItem {
  constructor(
    readonly result: WorkspaceFileResult,
    readonly finding: SecurityFinding,
  ) {
    super(
      finding.title,
      vscode.TreeItemCollapsibleState.None,
    );

    const cwe = finding.cwe[0] ?? "Security";
    const line =
      finding.scanner_evidence[0]?.line_start ??
      finding.vulnerable_lines[0] ??
      1;

    const consensusLabel =
      findingConsensusLabel(finding);

    this.description = [
      finding.severity.toUpperCase(),
      cwe,
      consensusLabel,
    ]
      .filter(
        (value): value is string =>
          value !== undefined,
      )
      .join(" · ");

    this.tooltip = new vscode.MarkdownString(
      [
        `**${finding.title}**`,
        "",
        `- Severity: ${finding.severity.toUpperCase()}`,
        `- CWE: ${finding.cwe.join(", ") || "Not specified"}`,
        `- OWASP: ${finding.owasp.join(", ") || "Not specified"}`,
        `- File: ${result.relativePath}`,
        `- Line: ${line}`,
        "",
        finding.summary,
      ].join("\n"),
    );

    this.contextValue = "aegisSecurityFinding";
    this.iconPath = severityIcon(finding.severity);

    this.command = {
      command: "aegis.openWorkspaceFinding",
      title: "Open Security Finding",
      arguments: [
        result.uri,
        line,
      ],
    };
  }
}

class ThreatModelRootTreeItem
  extends vscode.TreeItem {
  constructor(
    readonly result: ThreatModelScanResponse,
  ) {
    super(
      "Threat Model",
      vscode.TreeItemCollapsibleState.Expanded,
    );

    this.description =
      `${result.summary.threats_found} threat(s) · `
      + `${result.summary.assets_found} asset(s)`;

    this.tooltip = new vscode.MarkdownString(
      [
        "**Aegis Threat Model**",
        "",
        `- Files scanned: ${result.summary.files_scanned}`,
        `- Threats: ${result.summary.threats_found}`,
        `- Critical: ${result.summary.critical}`,
        `- High: ${result.summary.high}`,
        `- Medium: ${result.summary.medium}`,
        `- Assets: ${result.summary.assets_found}`,
        `- Trust boundaries: ${result.summary.trust_boundaries_found}`,
      ].join("\n"),
    );

    this.contextValue = "aegisThreatModelRoot";
    this.iconPath = new vscode.ThemeIcon(
      result.summary.critical > 0
        || result.summary.high > 0
        ? "shield"
        : "pass-filled",
    );
  }
}


class ThreatSeverityGroupTreeItem
  extends vscode.TreeItem {
  constructor(
    readonly severity: ThreatSeverity,
    readonly threats: ThreatFinding[],
  ) {
    super(
      severity.toUpperCase(),
      vscode.TreeItemCollapsibleState.Expanded,
    );

    this.description =
      `${threats.length} threat(s)`;

    this.tooltip =
      `${threats.length} ${severity.toUpperCase()} threat(s)`;

    this.contextValue =
      "aegisThreatSeverityGroup";

    this.iconPath =
      severityIcon(severity);
  }
}


class ThreatFindingTreeItem
  extends vscode.TreeItem {
  constructor(
    readonly threat: ThreatFinding,
  ) {
    super(
      threat.title,
      vscode.TreeItemCollapsibleState.None,
    );

    this.description =
      `${formatExploitability(threat.exploitability)} · `
      + `${formatThreatCategory(threat.category)} · `
      + `${threat.file}:${threat.line}`;

    const firstMitigation =
      threat.mitigations[0]
      ?? "Review the affected security boundary.";

    this.tooltip = new vscode.MarkdownString(
      [
        `**${threat.title}**`,
        "",
        `- Severity: ${threat.severity.toUpperCase()}`,
        `- Category: ${formatThreatCategory(threat.category)}`,
        `- Threat confidence: ${Math.round(threat.confidence * 100)}%`,
        `- Exploitability: ${formatExploitability(threat.exploitability)}`,
        `- Exploitability confidence: ${Math.round(threat.exploitability_confidence * 100)}%`,
        `- File: ${threat.file}`,
        `- Line: ${threat.line}`,
        `- Affected asset: ${threat.affected_asset}`,
        `- Entry point: ${threat.entry_point ?? "Not identified"}`,
        `- Trust boundary: ${threat.trust_boundary ?? "Not identified"}`,
        "",
        threat.description,
        "",
        "**Exploitability reasons:**",
        ...formatMarkdownBulletLines(
          threat.exploitability_reasons,
          "No deterministic reason was recorded.",
        ),
        "",
        "**Data flow:**",
        ...formatDataFlowLines(
          threat.data_flow,
        ),
        "",
        "**Prerequisites:**",
        ...formatMarkdownBulletLines(
          threat.prerequisites,
          "No prerequisite was identified.",
        ),
        "",
        "**Blocking controls:**",
        ...formatMarkdownBulletLines(
          threat.blocking_controls,
          "None detected.",
        ),
        "",
        `**First mitigation:** ${firstMitigation}`,
      ].join("\n"),
    );

    this.contextValue =
      "aegisThreatFinding";

    this.iconPath =
      severityIcon(threat.severity);

    this.command = {
      command: "aegis.openAttackSurfaceNode",
      title: "Open Threat Location",
      arguments: [
        threat.file,
        threat.line,
      ],
    };
  }
}


class AttackSurfaceRootTreeItem
  extends vscode.TreeItem {
  constructor(
    readonly result: AttackSurfaceScanResponse,
  ) {
    super(
      "Attack Surface",
      vscode.TreeItemCollapsibleState.Expanded,
    );

    this.description =
      `${result.summary.nodes_found} node(s) · `
      + `${result.summary.routes} route(s)`;

    this.tooltip = new vscode.MarkdownString(
      [
        "**Aegis Attack Surface**",
        "",
        `- Files scanned: ${result.summary.files_scanned}`,
        `- Nodes: ${result.summary.nodes_found}`,
        `- Relationships: ${result.summary.edges_found}`,
        `- Routes: ${result.summary.routes}`,
        `- Unauthenticated routes: ${result.summary.unauthenticated_routes}`,
      ].join("\n"),
    );

    this.contextValue =
      "aegisAttackSurfaceRoot";

    this.iconPath =
      new vscode.ThemeIcon("target");
  }
}

class AttackSurfaceGroupTreeItem
  extends vscode.TreeItem {
  constructor(
    readonly kind: AttackSurfaceNodeKind,
    readonly nodes: AttackSurfaceNode[],
  ) {
    super(
      formatAttackSurfaceKind(kind),
      vscode.TreeItemCollapsibleState.Collapsed,
    );

    const strongest =
      strongestAttackSurfaceRisk(nodes);

    this.description =
      `${nodes.length} · ${strongest.toUpperCase()}`;

    this.tooltip =
      `${nodes.length} `
      + `${formatAttackSurfaceKind(kind)} node(s)`;

    this.contextValue =
      "aegisAttackSurfaceGroup";

    this.iconPath =
      attackSurfaceKindIcon(kind);
  }
}

class AttackSurfaceNodeTreeItem
  extends vscode.TreeItem {
  constructor(
    readonly node: AttackSurfaceNode,
  ) {
    super(
      node.label,
      vscode.TreeItemCollapsibleState.None,
    );

    this.description =
      `${node.risk.toUpperCase()} · `
      + `${node.file}:${node.line_start}`;

    const authentication =
      node.authenticated === null
        ? "Unknown"
        : node.authenticated
          ? "Detected"
          : "Not detected";

    this.tooltip = new vscode.MarkdownString(
      [
        `**${node.label}**`,
        "",
        `- Type: ${formatAttackSurfaceKind(node.kind)}`,
        `- Risk: ${node.risk.toUpperCase()}`,
        `- File: ${node.file}`,
        `- Line: ${node.line_start}`,
        `- Framework: ${node.framework ?? "Unknown"}`,
        `- Authentication: ${authentication}`,
        "",
        `\`${node.evidence.replaceAll("`", "\\`")}\``,
      ].join("\n"),
    );

    this.contextValue =
      "aegisAttackSurfaceNode";

    this.iconPath =
      attackSurfaceRiskIcon(node.risk);

    this.command = {
      command: "aegis.openAttackSurfaceNode",
      title: "Open Attack Surface Node",
      arguments: [
        node.file,
        node.line_start,
      ],
    };
  }
}

class DependencyRootTreeItem extends vscode.TreeItem {
  constructor(
    readonly result: DependencyScanResponse,
  ) {
    super(
      "Supply Chain Risks",
      vscode.TreeItemCollapsibleState.Expanded,
    );

    this.description = [
      `${result.vulnerable_packages} package(s)`,
      `${result.vulnerabilities.length} advisory(s)`,
      result.scan_status.toUpperCase(),
    ].join(" · ");

    this.tooltip = [
      `${result.successful_packages}/${result.packages_scanned} package version(s) checked successfully`,
      `${result.failed_packages} package query failure(s)`,
      `Scanner: ${result.scanner.toUpperCase()}`,
    ].join("\n");

    this.contextValue = "aegisDependencyRoot";

    const icon =
      result.scan_status === "failed"
        ? "error"
        : result.scan_status === "partial"
          ? "warning"
          : result.vulnerabilities.length > 0
            ? "package"
            : "pass-filled";

    this.iconPath =
      new vscode.ThemeIcon(icon);
  }
}

class DependencyPackageTreeItem extends vscode.TreeItem {
  constructor(
    readonly packageKey: string,
    readonly vulnerabilities:
      DependencyVulnerability[],
  ) {
    const first = vulnerabilities[0];

    super(
      `${first.package_name} ${first.installed_version}`,
      vscode.TreeItemCollapsibleState.Expanded,
    );

    const strongest =
      strongestDependencySeverity(
        vulnerabilities,
      );

    this.description =
      `${strongest.toUpperCase()} · ${vulnerabilities.length} advisory(s)`;

    this.tooltip = new vscode.MarkdownString(
      [
        `**${first.package_name} ${first.installed_version}**`,
        "",
        `- Ecosystem: ${first.ecosystem}`,
        `- Manifest: ${first.manifest}`,
        `- Direct dependency: ${first.direct ? "YES" : "NO"}`,
        `- Advisory records: ${vulnerabilities.length}`,
      ].join("\n"),
    );

    this.contextValue = "aegisDependencyPackage";
    this.iconPath = dependencySeverityIcon(strongest);

    this.command = {
      command: "aegis.openDependencyManifest",
      title: "Open Dependency Manifest",
      arguments: [first.manifest],
    };
  }
}

class DependencyVulnerabilityTreeItem
  extends vscode.TreeItem {
  constructor(
    readonly vulnerability:
      DependencyVulnerability,
  ) {
    super(
      vulnerability.id,
      vscode.TreeItemCollapsibleState.None,
    );

    const fixed =
      vulnerability.fixed_versions[0];

    this.description = fixed
      ? `${vulnerability.severity.toUpperCase()} · fix ${fixed}`
      : vulnerability.severity.toUpperCase();

    this.tooltip = new vscode.MarkdownString(
      [
        `**${vulnerability.summary}**`,
        "",
        `- Advisory: ${vulnerability.id}`,
        `- Severity: ${vulnerability.severity.toUpperCase()}`,
        `- Package: ${vulnerability.package_name} ${vulnerability.installed_version}`,
        `- Fixed versions: ${vulnerability.fixed_versions.join(", ") || "Not specified"}`,
        `- Manifest: ${vulnerability.manifest}`,
      ].join("\n"),
    );

    this.contextValue =
      "aegisDependencyVulnerability";

    this.iconPath = dependencySeverityIcon(
      vulnerability.severity,
    );

    this.command = {
      command: "aegis.openDependencyManifest",
      title: "Open Dependency Manifest",
      arguments: [vulnerability.manifest],
    };
  }
}

function groupThreatsBySeverity(
  threats: ThreatFinding[],
): Array<
  [ThreatSeverity, ThreatFinding[]]
> {
  const order: ThreatSeverity[] = [
    "critical",
    "high",
    "medium",
    "low",
    "info",
  ];

  const grouped = new Map<
    ThreatSeverity,
    ThreatFinding[]
  >();

  for (const threat of threats) {
    const existing =
      grouped.get(threat.severity) ?? [];

    existing.push(threat);
    grouped.set(
      threat.severity,
      existing,
    );
  }

  return order
    .filter((severity) =>
      grouped.has(severity)
    )
    .map((severity) => [
      severity,
      [...(grouped.get(severity) ?? [])].sort(
        (left, right) =>
          left.file.localeCompare(right.file)
          || left.line - right.line,
      ),
    ]);
}


function groupAttackSurfaceNodes(
  nodes: AttackSurfaceNode[],
): Array<
  [AttackSurfaceNodeKind, AttackSurfaceNode[]]
> {
  const order: AttackSurfaceNodeKind[] = [
    "http_route",
    "authentication",
    "user_input",
    "database",
    "filesystem",
    "outbound_request",
    "process_execution",
    "secret_access",
  ];

  const grouped = new Map<
    AttackSurfaceNodeKind,
    AttackSurfaceNode[]
  >();

  for (const node of nodes) {
    const existing =
      grouped.get(node.kind) ?? [];

    existing.push(node);
    grouped.set(node.kind, existing);
  }

  return order
    .filter((kind) => grouped.has(kind))
    .map((kind) => [
      kind,
      [...(grouped.get(kind) ?? [])].sort(
        (left, right) =>
          left.file.localeCompare(right.file)
          || left.line_start - right.line_start,
      ),
    ]);
}

function strongestAttackSurfaceRisk(
  nodes: AttackSurfaceNode[],
): AttackSurfaceRisk {
  const rank: Record<AttackSurfaceRisk, number> = {
    info: 0,
    low: 1,
    medium: 2,
    high: 3,
    critical: 4,
  };

  return nodes.reduce<AttackSurfaceRisk>(
    (strongest, node) =>
      rank[node.risk] > rank[strongest]
        ? node.risk
        : strongest,
    "info",
  );
}

function attackSurfaceRiskIcon(
  risk: AttackSurfaceRisk,
): vscode.ThemeIcon {
  switch (risk) {
    case "critical":
    case "high":
      return new vscode.ThemeIcon("error");

    case "medium":
      return new vscode.ThemeIcon("warning");

    case "low":
      return new vscode.ThemeIcon("info");

    case "info":
    default:
      return new vscode.ThemeIcon(
        "circle-outline",
      );
  }
}

function attackSurfaceKindIcon(
  kind: AttackSurfaceNodeKind,
): vscode.ThemeIcon {
  const icons:
    Record<AttackSurfaceNodeKind, string> = {
      http_route: "globe",
      authentication: "lock",
      user_input: "account",
      function_parameter: "symbol-parameter",
      database: "database",
      filesystem: "files",
      outbound_request: "remote",
      process_execution: "terminal",
      secret_access: "key",
    };

  return new vscode.ThemeIcon(
    icons[kind],
  );
}

function groupDependencyVulnerabilities(
  vulnerabilities: DependencyVulnerability[],
): Map<string, DependencyVulnerability[]> {
  const grouped =
    new Map<string, DependencyVulnerability[]>();

  for (const vulnerability of vulnerabilities) {
    const key = [
      vulnerability.ecosystem,
      vulnerability.package_name.toLowerCase(),
      vulnerability.installed_version,
    ].join(":");

    const packageItems = grouped.get(key) ?? [];
    packageItems.push(vulnerability);
    grouped.set(key, packageItems);
  }

  return new Map(
    Array.from(grouped.entries()).sort(
      ([left], [right]) =>
        left.localeCompare(right),
    ),
  );
}

function strongestDependencySeverity(
  vulnerabilities: DependencyVulnerability[],
): DependencySeverity {
  const rank: Record<DependencySeverity, number> = {
    unknown: 0,
    low: 1,
    medium: 2,
    high: 3,
    critical: 4,
  };

  return vulnerabilities.reduce<DependencySeverity>(
    (strongest, vulnerability) =>
      rank[vulnerability.severity] >
      rank[strongest]
        ? vulnerability.severity
        : strongest,
    "unknown",
  );
}

function dependencySeverityIcon(
  severity: DependencySeverity,
): vscode.ThemeIcon {
  switch (severity) {
    case "critical":
    case "high":
      return new vscode.ThemeIcon("error");

    case "medium":
      return new vscode.ThemeIcon("warning");

    case "low":
      return new vscode.ThemeIcon("info");

    case "unknown":
    default:
      return new vscode.ThemeIcon(
        "question",
      );
  }
}

async function openDependencyManifest(
  manifest: string,
): Promise<void> {
  const normalized =
    manifest.replaceAll("\\", "/");

  const matches = await vscode.workspace.findFiles(
    `**/${normalized}`,
    "**/{.git,node_modules,.venv,venv,dist,build,out}/**",
    10,
  );

  const fallbackMatches =
    matches.length > 0
      ? matches
      : await vscode.workspace.findFiles(
          `**/${path.basename(normalized)}`,
          "**/{.git,node_modules,.venv,venv,dist,build,out}/**",
          10,
        );

  if (fallbackMatches.length === 0) {
    void vscode.window.showWarningMessage(
      `Aegis: Could not locate dependency manifest ${manifest}.`,
    );
    return;
  }

  const document =
    await vscode.workspace.openTextDocument(
      fallbackMatches[0],
    );

  await vscode.window.showTextDocument(
    document,
    {
      preview: false,
      viewColumn: vscode.ViewColumn.One,
    },
  );
}

class SecurityMessageTreeItem extends vscode.TreeItem {
  constructor(
    label: string,
    icon: "shield" | "pass",
  ) {
    super(
      label,
      vscode.TreeItemCollapsibleState.None,
    );

    this.iconPath = new vscode.ThemeIcon(
      icon === "pass"
        ? "pass-filled"
        : "shield",
    );
  }
}

function severityIcon(
  severity: Severity,
): vscode.ThemeIcon {
  switch (severity) {
    case "critical":
    case "high":
      return new vscode.ThemeIcon("error");

    case "medium":
      return new vscode.ThemeIcon("warning");

    case "low":
    case "info":
    default:
      return new vscode.ThemeIcon("info");
  }
}

function getWorkspaceRisk(
  summary: WorkspaceScanSummary,
): Severity | "none" {
  const severities =
    summary.results.flatMap(
      (result) =>
        result.response.findings.map(
          (finding) => finding.severity,
        ),
    );

  if (severities.includes("critical")) {
    return "critical";
  }

  if (severities.includes("high")) {
    return "high";
  }

  if (severities.includes("medium")) {
    return "medium";
  }

  if (severities.includes("low")) {
    return "low";
  }

  if (severities.includes("info")) {
    return "info";
  }

  return "none";
}

async function openAttackSurfaceNode(
  relativePath: string,
  oneBasedLine: number,
): Promise<void> {
  const workspaceFolders =
    vscode.workspace.workspaceFolders;

  if (
    !workspaceFolders
    || workspaceFolders.length === 0
  ) {
    void vscode.window.showWarningMessage(
      "Aegis: No workspace is open.",
    );
    return;
  }

  for (const folder of workspaceFolders) {
    const candidate = vscode.Uri.joinPath(
      folder.uri,
      relativePath,
    );

    try {
      await vscode.workspace.fs.stat(candidate);

      await openWorkspaceFinding(
        candidate,
        oneBasedLine,
      );

      return;
    } catch {
      // Try the next workspace folder.
    }
  }

  void vscode.window.showErrorMessage(
    `Aegis: Could not locate ${relativePath}.`,
  );
}

async function openWorkspaceFinding(
  uri: vscode.Uri,
  oneBasedLine: number,
): Promise<void> {
  const document =
    await vscode.workspace.openTextDocument(uri);

  const editor =
    await vscode.window.showTextDocument(
      document,
      {
        preview: false,
        viewColumn: vscode.ViewColumn.One,
      },
    );

  const line = Math.max(
    0,
    Math.min(
      oneBasedLine - 1,
      document.lineCount - 1,
    ),
  );

  const range = document.lineAt(line).range;

  editor.selection = new vscode.Selection(
    range.start,
    range.start,
  );

  editor.revealRange(
    range,
    vscode.TextEditorRevealType.InCenter,
  );
}

async function scanDependencies(): Promise<void> {
  const workspaceFolders =
    vscode.workspace.workspaceFolders;

  if (!workspaceFolders || workspaceFolders.length === 0) {
    void vscode.window.showWarningMessage(
      "Aegis: Open a workspace before scanning dependencies.",
    );
    return;
  }

  const configuration =
    vscode.workspace.getConfiguration("aegis");

  const backendUrl = configuration
    .get<string>(
      "backendUrl",
      "http://127.0.0.1:8000",
    )
    .replace(/\/+$/, "");

  try {
    const manifests =
      await vscode.window.withProgress(
        {
          location:
            vscode.ProgressLocation.Notification,
          title:
            "Aegis is discovering dependency files",
          cancellable: false,
        },
        async () =>
          discoverWorkspaceDependencyManifests(),
      );

    if (manifests.length === 0) {
      void vscode.window.showInformationMessage(
        "Aegis: No supported dependency lockfile or pinned requirements file was found.",
      );
      return;
    }

    const manifestResult =
      await vscode.window.withProgress(
        {
          location:
            vscode.ProgressLocation.Notification,
          title:
            `Aegis is parsing and checking ${manifests.length} dependency file(s)`,
          cancellable: false,
        },
        async () =>
          requestDependencyManifestScan(
            backendUrl,
            manifests,
          ),
      );

    const packages = manifestResult.packages;
    const result = manifestResult.scan;

    latestDependencyScan = result;
    securityTreeProvider?.refresh();

    await showDependencyScanReport(
      result,
      packages,
    );

    if (result.scan_status === "failed") {
      void vscode.window.showErrorMessage(
        `Aegis Dependency Scan could not verify ${result.failed_packages} package(s) because OSV advisory queries failed.`,
        "Keep Report Open",
      );
      return;
    }

    if (result.scan_status === "partial") {
      void vscode.window.showWarningMessage(
        `Aegis Dependency Scan completed partially: ${result.successful_packages}/${result.packages_scanned} package(s) checked successfully and ${result.failed_packages} failed.`,
        "Keep Report Open",
      );
      return;
    }

    if (result.vulnerabilities.length === 0) {
      void vscode.window.showInformationMessage(
        `Aegis Dependency Scan completed: ${result.successful_packages} package(s) checked and no known vulnerabilities detected.`,
      );
      return;
    }

    void vscode.window.showWarningMessage(
      `Aegis found ${result.vulnerabilities.length} known vulnerability record(s) across ${result.vulnerable_packages} package(s).`,
      "Keep Report Open",
    );
  } catch (error: unknown) {
    const message =
      error instanceof Error
        ? error.message
        : "Unknown dependency scan error.";

    void vscode.window.showErrorMessage(
      `Aegis Dependency Scan failed: ${message}`,
    );
  }
}

async function discoverWorkspaceDependencyManifests():
  Promise<DependencyManifestInput[]> {
  const manifestUris =
    await vscode.workspace.findFiles(
      "**/{requirements.txt,requirements-*.txt,requirements.*.txt,package-lock.json,pnpm-lock.yaml,pnpm-lock.yml,yarn.lock,poetry.lock,Pipfile.lock,Cargo.lock}",
      "**/{.git,node_modules,.venv,venv,dist,build,out,coverage,target}/**",
      100,
    );

  const manifests: DependencyManifestInput[] = [];

  for (const uri of manifestUris) {
    const document =
      await vscode.workspace.openTextDocument(uri);

    manifests.push({
      filename: path.basename(uri.fsPath),
      manifest:
        vscode.workspace.asRelativePath(
          uri,
          false,
        ),
      content: document.getText(),
    });
  }

  return manifests.sort(
    (left, right) =>
      left.manifest.localeCompare(
        right.manifest,
      ),
  );
}


function parseRequirementsTxt(
  content: string,
  manifest: string,
): DependencyPackage[] {
  const packages: DependencyPackage[] = [];

  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();

    if (
      !line ||
      line.startsWith("#") ||
      line.startsWith("-")
    ) {
      continue;
    }

    const withoutComment =
      line.split(/\s+#/, 1)[0]?.trim() ?? "";

    const match = withoutComment.match(
      /^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?==([A-Za-z0-9_.+!-]+)$/,
    );

    if (!match) {
      continue;
    }

    packages.push({
      name: match[1],
      version: match[2],
      ecosystem: "PyPI",
      manifest,
      direct: true,
    });
  }

  return packages;
}

function parsePackageJson(
  content: string,
  manifest: string,
): DependencyPackage[] {
  let payload: unknown;

  try {
    payload = JSON.parse(content);
  } catch {
    throw new Error(
      `${manifest} contains invalid JSON.`,
    );
  }

  if (!isRecord(payload)) {
    return [];
  }

  const packages: DependencyPackage[] = [];

  for (const field of [
    "dependencies",
    "devDependencies",
    "optionalDependencies",
  ]) {
    const dependencies = payload[field];

    if (!isRecord(dependencies)) {
      continue;
    }

    for (const [name, rawVersion] of Object.entries(
      dependencies,
    )) {
      if (typeof rawVersion !== "string") {
        continue;
      }

      const version = normalizeExactNpmVersion(
        rawVersion,
      );

      if (!version) {
        continue;
      }

      packages.push({
        name,
        version,
        ecosystem: "npm",
        manifest,
        direct: true,
      });
    }
  }

  return packages;
}

function parsePackageLock(
  content: string,
  manifest: string,
): DependencyPackage[] {
  let payload: unknown;

  try {
    payload = JSON.parse(content);
  } catch {
    throw new Error(
      `${manifest} contains invalid JSON.`,
    );
  }

  if (!isRecord(payload)) {
    return [];
  }

  const packages: DependencyPackage[] = [];
  const lockPackages = payload.packages;

  if (isRecord(lockPackages)) {
    for (const [packagePath, rawMetadata] of Object.entries(
      lockPackages,
    )) {
      if (
        !packagePath.startsWith("node_modules/") ||
        !isRecord(rawMetadata)
      ) {
        continue;
      }

      const name = packagePath.replace(
        /^node_modules\//,
        "",
      );

      const version = rawMetadata.version;

      if (
        !name ||
        typeof version !== "string" ||
        !isExactVersion(version)
      ) {
        continue;
      }

      packages.push({
        name,
        version,
        ecosystem: "npm",
        manifest,
        direct: false,
      });
    }

    return packages;
  }

  const dependencies = payload.dependencies;

  if (isRecord(dependencies)) {
    collectLegacyPackageLockDependencies(
      dependencies,
      manifest,
      packages,
    );
  }

  return packages;
}

function collectLegacyPackageLockDependencies(
  dependencies: Record<string, unknown>,
  manifest: string,
  output: DependencyPackage[],
): void {
  for (const [name, rawMetadata] of Object.entries(
    dependencies,
  )) {
    if (!isRecord(rawMetadata)) {
      continue;
    }

    const version = rawMetadata.version;

    if (
      typeof version === "string" &&
      isExactVersion(version)
    ) {
      output.push({
        name,
        version,
        ecosystem: "npm",
        manifest,
        direct: false,
      });
    }

    const nestedDependencies =
      rawMetadata.dependencies;

    if (isRecord(nestedDependencies)) {
      collectLegacyPackageLockDependencies(
        nestedDependencies,
        manifest,
        output,
      );
    }
  }
}

function normalizeExactNpmVersion(
  rawVersion: string,
): string | undefined {
  const trimmed = rawVersion.trim();

  if (
    trimmed.startsWith("workspace:") ||
    trimmed.startsWith("file:") ||
    trimmed.startsWith("git+") ||
    trimmed.startsWith("http:") ||
    trimmed.startsWith("https:")
  ) {
    return undefined;
  }

  const normalized = trimmed.startsWith("=")
    ? trimmed.slice(1)
    : trimmed;

  return isExactVersion(normalized)
    ? normalized
    : undefined;
}

function isExactVersion(
  value: string,
): boolean {
  return /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(
    value,
  );
}

function deduplicateDependencies(
  packages: DependencyPackage[],
): DependencyPackage[] {
  const deduplicated =
    new Map<string, DependencyPackage>();

  for (const packageItem of packages) {
    const key = [
      packageItem.ecosystem,
      packageItem.name.toLowerCase(),
      packageItem.version,
    ].join(":");

    const existing = deduplicated.get(key);

    if (!existing || packageItem.direct) {
      deduplicated.set(
        key,
        packageItem,
      );
    }
  }

  return Array.from(
    deduplicated.values(),
  ).sort((left, right) =>
    `${left.ecosystem}:${left.name}`.localeCompare(
      `${right.ecosystem}:${right.name}`,
    ),
  );
}

function isRecord(
  value: unknown,
): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value)
  );
}

async function requestDependencyManifestScan(
  backendUrl: string,
  manifests: DependencyManifestInput[],
): Promise<DependencyManifestScanResponse> {
  return postBackendJson<
    DependencyManifestScanResponse
  >({
    backendUrl,
    endpoint:
      "/v1/dependencies/manifests/scan",
    body: {
      manifests,
    },
    timeoutMilliseconds: 180_000,
    timeoutMessage:
      "Dependency Scan timed out after three minutes.",
  });
}


async function requestDependencyScan(
  backendUrl: string,
  packages: DependencyPackage[],
): Promise<DependencyScanResponse> {
  return postBackendJson<
    DependencyScanResponse
  >({
    backendUrl,
    endpoint:
      "/v1/dependencies/scan",
    body: {
      packages,
    },
    timeoutMilliseconds: 180_000,
    timeoutMessage:
      "Dependency Scan timed out after three minutes.",
  });
}


async function requestThreatModelScan(
  backendUrl: string,
  files: AttackSurfaceFileInput[],
): Promise<ThreatModelScanResponse> {
  return postBackendJson<
    ThreatModelScanResponse
  >({
    backendUrl,
    endpoint:
      "/v1/threat-model/scan",
    body: {
      files,
    },
    timeoutMilliseconds: 180_000,
    timeoutMessage:
      "Threat modeling timed out after three minutes.",
  });
}


function buildThreatModelReport(
  result: ThreatModelScanResponse,
): string {
  const lines: string[] = [
    "# Aegis Threat Model",
    "",
    `- **Modeler:** ${result.modeler}`,
    `- **Files scanned:** ${result.summary.files_scanned}`,
    `- **Assets:** ${result.summary.assets_found}`,
    `- **Trust boundaries:** ${result.summary.trust_boundaries_found}`,
    `- **Threats:** ${result.summary.threats_found}`,
    "",
    "## Severity Summary",
    "",
    `- **Critical:** ${result.summary.critical}`,
    `- **High:** ${result.summary.high}`,
    `- **Medium:** ${result.summary.medium}`,
    `- **Low:** ${result.summary.low}`,
    `- **Info:** ${result.summary.info}`,
    "",
    "## Threats",
    "",
  ];

  if (result.threats.length === 0) {
    lines.push(
      "No deterministic threat was identified.",
      "",
    );
  }

  result.threats.forEach(
    (threat, index) => {
      lines.push(
        `### ${index + 1}. ${threat.title}`,
        "",
        `- **Severity:** ${threat.severity.toUpperCase()}`,
        `- **Category:** ${formatThreatCategory(threat.category)}`,
        `- **Threat confidence:** ${Math.round(threat.confidence * 100)}%`,
        `- **Exploitability:** ${formatExploitability(threat.exploitability)}`,
        `- **Exploitability confidence:** ${Math.round(threat.exploitability_confidence * 100)}%`,
        `- **Location:** \`${threat.file}:${threat.line}\``,
        `- **Affected asset:** ${threat.affected_asset}`,
        `- **Entry point:** ${threat.entry_point ?? "Not identified"}`,
        `- **Trust boundary:** ${threat.trust_boundary ?? "Not identified"}`,
        "",
        threat.description,
        "",
        "#### Exploitability Reasons",
        "",
      );

      if (threat.exploitability_reasons.length === 0) {
        lines.push(
          "- No deterministic reason was recorded.",
        );
      } else {
        for (const reason of threat.exploitability_reasons) {
          lines.push(`- ${reason}`);
        }
      }

      lines.push(
        "",
        "#### Data Flow",
        "",
      );

      if (threat.data_flow.length === 0) {
        lines.push(
          "- No proven source-to-sink flow.",
        );
      } else {
        lines.push(
          "```text",
          threat.data_flow.join("\n→ "),
          "```",
        );
      }

      lines.push(
        "",
        "#### Prerequisites",
        "",
      );

      if (threat.prerequisites.length === 0) {
        lines.push(
          "- No prerequisite was identified.",
        );
      } else {
        for (const prerequisite of threat.prerequisites) {
          lines.push(`- ${prerequisite}`);
        }
      }

      lines.push(
        "",
        "#### Blocking Controls",
        "",
      );

      if (threat.blocking_controls.length === 0) {
        lines.push("- None detected.");
      } else {
        for (const control of threat.blocking_controls) {
          lines.push(`- ${control}`);
        }
      }

      lines.push(
        "",
        "#### Attack Path",
        "",
      );

      for (const step of threat.attack_path) {
        lines.push(`- ${step}`);
      }

      lines.push(
        "",
        "#### Mitigations",
        "",
      );

      for (const mitigation of threat.mitigations) {
        lines.push(`- ${mitigation}`);
      }

      if (threat.evidence.length > 0) {
        lines.push(
          "",
          "#### Evidence",
          "",
        );

        for (const evidence of threat.evidence) {
          lines.push(
            `- \`${evidence.replaceAll("`", "\`")}\``,
          );
        }
      }

      lines.push("", "---", "");
    },
  );

  lines.push(
    "## Assets",
    "",
  );

  for (const asset of result.assets) {
    lines.push(
      `- **${asset.name}** — ${asset.description} `
      + `(\`${asset.file}:${asset.line}\`)`,
    );
  }

  lines.push(
    "",
    "## Trust Boundaries",
    "",
  );

  for (const boundary of result.trust_boundaries) {
    lines.push(
      `- **${boundary.label}** — `
      + `${boundary.boundary_type} `
      + `(\`${boundary.file}:${boundary.line}\`)`,
    );
  }

  lines.push(
    "",
    "---",
    "",
    "> This deterministic threat model is based on statically detected application behavior and may not capture every runtime data flow.",
  );

  return lines.join("\n");
}


function formatExploitability(
  exploitability: Exploitability,
): string {
  const labels: Record<Exploitability, string> = {
    confirmed: "CONFIRMED",
    likely: "LIKELY",
    possible: "POSSIBLE",
    unlikely: "UNLIKELY",
    not_exploitable: "NOT EXPLOITABLE",
    unknown: "UNKNOWN",
  };

  return labels[exploitability];
}


function formatDataFlowLines(
  dataFlow: string[],
): string[] {
  if (dataFlow.length === 0) {
    return [
      "- No proven source-to-sink flow.",
    ];
  }

  return [
    "```text",
    dataFlow.join("\n→ "),
    "```",
  ];
}


function formatMarkdownBulletLines(
  values: string[],
  emptyMessage: string,
): string[] {
  if (values.length === 0) {
    return [`- ${emptyMessage}`];
  }

  return values.map(
    (value) => `- ${value}`,
  );
}


function formatThreatCategory(
  category: ThreatCategory,
): string {
  const labels: Record<ThreatCategory, string> = {
    command_injection: "Command Injection",
    sql_injection: "SQL Injection",
    path_traversal: "Path Traversal",
    ssrf: "Server-Side Request Forgery",
    secret_exposure: "Secret Exposure",
    authentication_bypass: "Authentication Bypass",
    unsafe_data_flow: "Unsafe Data Flow",
  };

  return labels[category];
}


function buildAttackSurfaceReport(
  result: AttackSurfaceScanResponse,
): string {
  const nodeById = new Map(
    result.nodes.map(
      (node) => [node.id, node],
    ),
  );

  const lines: string[] = [
    "# Aegis Attack Surface Map",
    "",
    `- **Mapper:** ${result.mapper}`,
    `- **Files scanned:** ${result.summary.files_scanned}`,
    `- **Surface nodes:** ${result.summary.nodes_found}`,
    `- **Relationships:** ${result.summary.edges_found}`,
    "",
    "## Exposure Summary",
    "",
    `- **HTTP routes:** ${result.summary.routes}`,
    `- **Authenticated routes:** ${result.summary.authenticated_routes}`,
    `- **Unauthenticated routes:** ${result.summary.unauthenticated_routes}`,
    `- **Database operations:** ${result.summary.databases}`,
    `- **Filesystem operations:** ${result.summary.filesystems}`,
    `- **Outbound requests:** ${result.summary.outbound_requests}`,
    `- **Process executions:** ${result.summary.process_executions}`,
    `- **Secret/config accesses:** ${result.summary.secret_accesses}`,
    "",
    "## Routes",
    "",
  ];

  const routes = result.nodes.filter(
    (node) => node.kind === "http_route",
  );

  if (routes.length === 0) {
    lines.push(
      "No supported HTTP route declaration was detected.",
      "",
    );
  }

  routes.forEach((route, index) => {
    const authentication =
      route.authenticated === true
        ? "YES"
        : route.authenticated === false
          ? "NO"
          : "UNKNOWN";

    lines.push(
      `### ${index + 1}. ${route.label}`,
      "",
      `- **Risk:** ${route.risk.toUpperCase()}`,
      `- **Authentication detected:** ${authentication}`,
      `- **Framework:** ${route.framework ?? "Unknown"}`,
      `- **Location:** \`${route.file}:${route.line_start}\``,
      "",
    );

    const reachable = result.edges.filter(
      (edge) => edge.source === route.id,
    );

    if (reachable.length === 0) {
      return;
    }

    lines.push("#### Reachable operations", "");

    for (const edge of reachable) {
      const target = nodeById.get(edge.target);

      if (!target) {
        continue;
      }

      lines.push(
        `- **${formatAttackSurfaceKind(target.kind)}:** `
        + `\`${target.file}:${target.line_start}\` — `
        + `${target.label} `
        + `(${Math.round(edge.confidence * 100)}% confidence)`,
      );
    }

    lines.push("");
  });

  const operations = result.nodes.filter(
    (node) => node.kind !== "http_route",
  );

  lines.push(
    "## Security-Sensitive Operations",
    "",
  );

  if (operations.length === 0) {
    lines.push(
      "No supported security-sensitive operation was detected.",
      "",
    );
  }

  operations.forEach((node, index) => {
    const safeEvidence =
      node.evidence.replaceAll("`", "\\`");

    lines.push(
      `### ${index + 1}. ${formatAttackSurfaceKind(node.kind)}`,
      "",
      `- **Label:** ${node.label}`,
      `- **Risk:** ${node.risk.toUpperCase()}`,
      `- **Location:** \`${node.file}:${node.line_start}\``,
      `- **Framework:** ${node.framework ?? "Unknown"}`,
      `- **Evidence:** \`${safeEvidence}\``,
      "",
    );
  });

  lines.push(
    "---",
    "",
    "> This deterministic static map may not identify every application entry point or data flow.",
  );

  return lines.join("\n");
}

function formatAttackSurfaceKind(
  kind: AttackSurfaceNodeKind,
): string {
  const labels:
    Record<AttackSurfaceNodeKind, string> = {
      http_route: "HTTP Route",
      authentication: "Authentication Boundary",
      user_input: "User Input",
      function_parameter: "Function Parameter",
      database: "Database",
      filesystem: "Filesystem",
      outbound_request: "Outbound Request",
      process_execution: "Process Execution",
      secret_access: "Secret Access",
    };

  return labels[kind];
}

async function requestAttackSurfaceScan(
  backendUrl: string,
  files: AttackSurfaceFileInput[],
): Promise<AttackSurfaceScanResponse> {
  return postBackendJson<
    AttackSurfaceScanResponse
  >({
    backendUrl,
    endpoint:
      "/v1/attack-surface/scan",
    body: {
      files,
    },
    timeoutMilliseconds: 180_000,
    timeoutMessage:
      "Attack Surface mapping timed out after three minutes.",
  });
}

function aegisReportUri(
  kind: AegisReportKind,
): vscode.Uri {
  return vscode.Uri.from({
    scheme: aegisReportScheme,
    path: `/${kind}.md`,
  });
}

async function showReusableAegisReport(
  kind: AegisReportKind,
  content: string,
  viewColumn:
    vscode.ViewColumn =
      vscode.ViewColumn.Beside,
): Promise<void> {
  if (!reportContentProvider) {
    throw new Error(
      "Aegis report provider is unavailable.",
    );
  }

  const uri = aegisReportUri(kind);

  reportContentProvider.update(
    uri,
    content,
  );

  const document =
    await vscode.workspace.openTextDocument(uri);

  await vscode.languages.setTextDocumentLanguage(
    document,
    "markdown",
  );

  await vscode.window.showTextDocument(
    document,
    {
      preview: true,
      preserveFocus: false,
      viewColumn,
    },
  );
}

async function showDependencyScanReport(
  result: DependencyScanResponse,
  packages: DependencyPackage[],
): Promise<void> {
  const report = buildDependencyScanReport(
    result,
    packages,
  );

  await showReusableAegisReport(
    "dependencies",
    report,
  );
}

function buildDependencyScanReport(
  result: DependencyScanResponse,
  packages: DependencyPackage[],
): string {
  const severityOrder:
    Record<DependencySeverity, number> = {
      critical: 0,
      high: 1,
      medium: 2,
      low: 3,
      unknown: 4,
    };

  const vulnerabilities = [
    ...result.vulnerabilities,
  ].sort((left, right) => {
    const severityDifference =
      severityOrder[left.severity] -
      severityOrder[right.severity];

    if (severityDifference !== 0) {
      return severityDifference;
    }

    return left.package_name.localeCompare(
      right.package_name,
    );
  });

  const countSeverity = (
    severity: DependencySeverity,
  ): number =>
    vulnerabilities.filter(
      (item) => item.severity === severity,
    ).length;

  const manifests = Array.from(
    new Set(
      packages.map(
        (packageItem) => packageItem.manifest,
      ),
    ),
  );

  const lines: string[] = [
    "# Aegis Dependency Security Scan",
    "",
    `- **Scanner:** ${result.scanner.toUpperCase()}`,
    `- **Scan status:** ${result.scan_status.toUpperCase()}`,
    `- **Packages submitted:** ${result.packages_scanned}`,
    `- **Packages checked successfully:** ${result.successful_packages}`,
    `- **Package queries failed:** ${result.failed_packages}`,
    `- **Vulnerable packages:** ${result.vulnerable_packages}`,
    `- **Vulnerability records:** ${vulnerabilities.length}`,
    `- **Manifests:** ${manifests.length}`,
    "",
    "## Severity Summary",
    "",
    `- **Critical:** ${countSeverity("critical")}`,
    `- **High:** ${countSeverity("high")}`,
    `- **Medium:** ${countSeverity("medium")}`,
    `- **Low:** ${countSeverity("low")}`,
    `- **Unknown:** ${countSeverity("unknown")}`,
    "",
  ];

  if (result.scan_status !== "completed") {
    lines.push(
      "## Advisory Coverage Warning",
      "",
    );

    if (result.scan_status === "failed") {
      lines.push(
        "> Dependency advisory coverage failed. No package received a successful OSV result.",
        "",
        "> The absence of vulnerability records must not be interpreted as a clean dependency scan.",
        "",
      );
    } else {
      lines.push(
        `> Dependency advisory coverage was partial. ${result.failed_packages} package query or queries failed.`,
        "",
        "> Vulnerability records below cover only packages checked successfully.",
        "",
      );
    }

    if (result.errors.length > 0) {
      lines.push(
        "### Query Errors",
        "",
      );

      for (const error of result.errors) {
        lines.push(
          `- ${sanitizeMarkdownText(error)}`,
        );
      }

      lines.push("");
    }
  }

  if (
    vulnerabilities.length === 0
    && result.scan_status === "completed"
  ) {
    lines.push(
      "No known dependency vulnerability was found for the exact versions checked.",
      "",
      "> This result depends on available advisory data and does not guarantee that every dependency is secure.",
    );

    return lines.join("\n");
  }

  if (vulnerabilities.length === 0) {
    return lines.join("\n");
  }

  lines.push("## Vulnerabilities", "");

  vulnerabilities.forEach(
    (vulnerability, index) => {
      const aliases =
        vulnerability.aliases.length > 0
          ? vulnerability.aliases.join(", ")
          : "None";

      const fixedVersions =
        vulnerability.fixed_versions.length > 0
          ? vulnerability.fixed_versions.join(", ")
          : "No fixed version specified";

      lines.push(
        `### ${index + 1}. ${vulnerability.package_name} ${vulnerability.installed_version}`,
        "",
        `- **Severity:** ${vulnerability.severity.toUpperCase()}`,
        `- **Advisory:** ${vulnerability.id}`,
        `- **Aliases:** ${aliases}`,
        `- **Ecosystem:** ${vulnerability.ecosystem}`,
        `- **Manifest:** \`${vulnerability.manifest}\``,
        `- **Direct dependency:** ${vulnerability.direct ? "YES" : "NO"}`,
        `- **Fixed version(s):** ${fixedVersions}`,
        "",
        vulnerability.summary ||
          "Known dependency vulnerability.",
        "",
      );

      if (vulnerability.references.length > 0) {
        lines.push("#### References", "");

        for (const reference of
          vulnerability.references.slice(0, 5)) {
          lines.push(`- ${reference}`);
        }

        lines.push("");
      }

      lines.push("---", "");
    },
  );

  return lines.join("\n");
}

type GitScanMode = "uncommitted" | "staged";

async function scanGitChanges(
  mode: GitScanMode,
): Promise<void> {
  const workspaceFolder =
    vscode.workspace.workspaceFolders?.[0];

  if (!workspaceFolder) {
    void vscode.window.showWarningMessage(
      "Aegis: Open a Git workspace before scanning changes.",
    );
    return;
  }

  const workspacePath = workspaceFolder.uri.fsPath;

  const repositoryRoot = await findGitRepositoryRoot(
    workspacePath,
  );

  if (!repositoryRoot) {
    void vscode.window.showWarningMessage(
      "Aegis: The current workspace is not inside a Git repository.",
    );
    return;
  }

  let relativePaths: string[];

  try {
    relativePaths = await getGitChangedFiles(
      repositoryRoot,
      mode,
    );
  } catch (error: unknown) {
    const message =
      error instanceof Error
        ? error.message
        : "Unknown Git error.";

    void vscode.window.showErrorMessage(
      `Aegis: Git change discovery failed: ${message}`,
    );
    return;
  }

  const supportedPaths = relativePaths.filter(
    isSupportedSourcePath,
  );

  const configuration =
    vscode.workspace.getConfiguration("aegis");

  const backendUrl = configuration
    .get<string>(
      "backendUrl",
      "http://127.0.0.1:8000",
    )
    .replace(/\/+$/, "");

  const summary: WorkspaceScanSummary = {
    filesDiscovered: supportedPaths.length,
    filesScanned: 0,
    filesSkipped: 0,
    filesFailed: 0,
    results: [],
    errors: [],
  };

  const changePolicy: ChangePolicyDisplay = {};

  try {
    changePolicy.response =
      await requestChangePolicyGate(
        backendUrl,
        repositoryRoot,
        mode,
      );
  } catch (error: unknown) {
    changePolicy.error =
      error instanceof Error
        ? error.message
        : "Unknown Change Security Gate error.";
  }

  diagnosticCollection?.clear();

  const label =
    mode === "staged"
      ? "staged changes"
      : "uncommitted changes";

  if (supportedPaths.length === 0) {
    latestWorkspaceScan = summary;
    securityTreeProvider?.refresh();

    await showGitChangesReport(
      summary,
      mode,
      changePolicy,
    );

    showChangePolicyNotification(
      changePolicy,
      label,
    );

    if (!changePolicy.response) {
      void vscode.window.showInformationMessage(
        `Aegis: No supported source files were found in ${label}.`,
      );
    }

    return;
  }

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: `Aegis is scanning ${label}`,
      cancellable: true,
    },
    async (progress, cancellationToken) => {
      const increment = 100 / supportedPaths.length;

      for (
        const [index, relativePath] of
        supportedPaths.entries()
      ) {
        if (cancellationToken.isCancellationRequested) {
          break;
        }

        progress.report({
          increment,
          message:
            `${index + 1}/${supportedPaths.length} · ${relativePath}`,
        });

        const uri = vscode.Uri.file(
          path.join(repositoryRoot, relativePath),
        );

        try {
          const document =
            await vscode.workspace.openTextDocument(uri);

          const code = document.getText();

          if (!code.trim()) {
            summary.filesSkipped += 1;
            continue;
          }

          if (code.length > 1_000_000) {
            summary.filesSkipped += 1;
            summary.errors.push(
              `${relativePath}: skipped because the file exceeds 1 MB.`,
            );
            continue;
          }

          const result = await requestAnalysis({
            backendUrl,
            code,
            filename: relativePath,
            language: normalizeLanguage(
              document.languageId,
            ),
            mode: "fast",
          });

          summary.filesScanned += 1;
          summary.results.push({
            uri,
            relativePath,
            response: result,
          });

          updateDiagnostics(
            document,
            result,
            0,
          );
        } catch (error: unknown) {
          summary.filesFailed += 1;

          const message =
            error instanceof Error
              ? error.message
              : "Unknown scan error.";

          summary.errors.push(
            `${relativePath}: ${message}`,
          );
        }
      }
    },
  );

  latestWorkspaceScan = summary;
  securityTreeProvider?.refresh();

  await showGitChangesReport(
    summary,
    mode,
    changePolicy,
  );

  showChangePolicyNotification(
    changePolicy,
    label,
  );

  const totalFindings = summary.results.reduce(
    (total, result) =>
      total + result.response.findings.length,
    0,
  );

  if (totalFindings === 0) {
    void vscode.window.showInformationMessage(
      `Aegis found no security findings in ${summary.filesScanned} scanned ${label} file(s).`,
    );
    return;
  }

  const action = await vscode.window.showWarningMessage(
    `Aegis found ${totalFindings} security finding(s) in ${label}.`,
    "Open Problems",
    "Keep Report Open",
  );

  if (action === "Open Problems") {
    await vscode.commands.executeCommand(
      "workbench.actions.view.problems",
    );
  }
}

async function findGitRepositoryRoot(
  workspacePath: string,
): Promise<string | undefined> {
  try {
    const { stdout } = await execFileAsync(
      "git",
      ["rev-parse", "--show-toplevel"],
      {
        cwd: workspacePath,
        timeout: 10_000,
      },
    );

    const repositoryRoot = stdout.trim();

    return repositoryRoot || undefined;
  } catch {
    return undefined;
  }
}

async function getGitChangedFiles(
  workspacePath: string,
  mode: GitScanMode,
): Promise<string[]> {
  if (mode === "staged") {
    const { stdout } = await execFileAsync(
      "git",
      [
        "diff",
        "--cached",
        "--name-only",
        "--diff-filter=ACMR",
      ],
      {
        cwd: workspacePath,
        timeout: 15_000,
      },
    );

    return uniqueNonEmptyLines(stdout);
  }

  const [
    trackedResult,
    untrackedResult,
  ] = await Promise.all([
    execFileAsync(
      "git",
      [
        "diff",
        "--name-only",
        "--diff-filter=ACMR",
        "HEAD",
      ],
      {
        cwd: workspacePath,
        timeout: 15_000,
      },
    ),
    execFileAsync(
      "git",
      [
        "ls-files",
        "--others",
        "--exclude-standard",
      ],
      {
        cwd: workspacePath,
        timeout: 15_000,
      },
    ),
  ]);

  return Array.from(
    new Set([
      ...uniqueNonEmptyLines(
        trackedResult.stdout,
      ),
      ...uniqueNonEmptyLines(
        untrackedResult.stdout,
      ),
    ]),
  ).sort();
}

function uniqueNonEmptyLines(
  output: string,
): string[] {
  return Array.from(
    new Set(
      output
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter(Boolean),
    ),
  );
}

function isSupportedSourcePath(
  relativePath: string,
): boolean {
  return /\.(py|js|jsx|ts|tsx)$/i.test(
    relativePath,
  );
}

async function showGitChangesReport(
  summary: WorkspaceScanSummary,
  mode: GitScanMode,
  changePolicy: ChangePolicyDisplay,
): Promise<void> {
  const baseReport =
    buildWorkspaceScanReport(summary);

  const heading =
    mode === "staged"
      ? "# Aegis Staged Changes Security Scan"
      : "# Aegis Uncommitted Changes Security Scan";

  const scanReport = baseReport.replace(
    "# Aegis Workspace Security Scan",
    heading,
  );

  const content = [
    scanReport,
    "",
    ...buildChangePolicyReport(
      changePolicy,
    ),
  ].join("\n");

  await showReusableAegisReport(
    "git-changes",
    content,
  );
}


async function requestChangePolicyGate(
  backendUrl: string,
  repositoryPath: string,
  mode: GitScanMode,
): Promise<ChangePolicyCollectionResponse> {
  return requestValidationJson<
    ChangePolicyCollectionResponse
  >(
    backendUrl,
    "/v1/changes/collect-and-evaluate",
    {
      repository_path: repositoryPath,
      mode,
      profile: "balanced",
    },
    30_000,
  );
}


function buildChangePolicyReport(
  display: ChangePolicyDisplay,
): string[] {
  const lines: string[] = [
    "## Change Security Gate",
    "",
  ];

  if (!display.response) {
    lines.push(
      "> Change Security Gate could not be evaluated.",
      "",
    );

    if (display.error) {
      lines.push(
        `- **Reason:** ${sanitizeMarkdownText(display.error)}`,
        "",
      );
    }

    return lines;
  }

  const changeSet = display.response.change_set;
  const policy = display.response.policy;
  const summary = policy.summary;

  lines.push(
    `- **Decision:** ${policy.decision.toUpperCase()}`,
    `- **Risk:** ${policy.risk_score} / 100 — ${policy.risk_level.toUpperCase()}`,
    `- **Profile:** ${policy.profile}`,
    `- **Changed files:** ${changeSet.file_count}`,
    `- **Additions:** ${changeSet.additions}`,
    `- **Deletions:** ${changeSet.deletions}`,
    `- **Allowed:** ${summary.allowed}`,
    `- **Review required:** ${summary.review_required}`,
    `- **Blocked:** ${summary.blocked}`,
    `- **Sensitive files:** ${summary.sensitive_files}`,
    `- **Dangerous patterns:** ${summary.dangerous_patterns}`,
    `- **Binary files:** ${summary.binary_files}`,
    `- **Truncated patches:** ${summary.truncated_files}`,
    "",
  );

  if (policy.blocking_paths.length > 0) {
    lines.push(
      "### Blocking Paths",
      "",
      ...policy.blocking_paths.map(
        (filePath) =>
          `- \`${sanitizeMarkdownText(filePath)}\``,
      ),
      "",
    );
  }

  if (policy.review_paths.length > 0) {
    lines.push(
      "### Review Paths",
      "",
      ...policy.review_paths.map(
        (filePath) =>
          `- \`${sanitizeMarkdownText(filePath)}\``,
      ),
      "",
    );
  }

  if (policy.assessments.length > 0) {
    lines.push(
      "### File Assessments",
      "",
    );

    for (
      const assessment
      of policy.assessments
    ) {
      lines.push(
        `#### \`${sanitizeMarkdownText(assessment.path)}\``,
        "",
        `- **Decision:** ${assessment.decision.toUpperCase()}`,
        `- **Risk:** ${assessment.risk_score} / 100 — ${assessment.risk_level.toUpperCase()}`,
        `- **Status:** ${assessment.status}`,
        "",
      );

      for (const reason of assessment.reasons) {
        lines.push(
          `- ${sanitizeMarkdownText(reason)}`,
        );
      }

      lines.push("");
    }
  }

  return lines;
}


function showChangePolicyNotification(
  display: ChangePolicyDisplay,
  label: string,
): void {
  if (!display.response) {
    if (display.error) {
      void vscode.window.showWarningMessage(
        `Aegis Change Security Gate was unavailable: ${display.error}`,
      );
    }

    return;
  }

  const policy = display.response.policy;

  if (policy.decision === "block") {
    void vscode.window.showErrorMessage(
      `Aegis Change Security Gate: BLOCK — ${policy.blocking_paths.length} blocking file(s) in ${label}.`,
    );
    return;
  }

  if (policy.decision === "review") {
    void vscode.window.showWarningMessage(
      `Aegis Change Security Gate: REVIEW — ${policy.review_paths.length} file(s) require human review in ${label}.`,
    );
    return;
  }

  void vscode.window.showInformationMessage(
    `Aegis Change Security Gate: ALLOW — ${display.response.change_set.file_count} changed file(s) evaluated.`,
  );
}

async function collectSafeModelSourceFiles(
  maximumFiles:
    number = MAX_MODEL_CONTEXT_FILES,
): Promise<AttackSurfaceFileInput[]> {
  const fileUris =
    await vscode.workspace.findFiles(
      WORKSPACE_SOURCE_GLOB,
      WORKSPACE_EXCLUDE_GLOB,
      maximumFiles,
    );

  const files:
    AttackSurfaceFileInput[] = [];

  const payloadBudget =
    createPayloadBudget(
      MAX_MODEL_PAYLOAD_BYTES,
    );

  const seenRealPaths =
    new Set<string>();

  for (const uri of fileUris) {
    if (uri.scheme !== "file") {
      continue;
    }

    const workspaceFolder =
      vscode.workspace.getWorkspaceFolder(
        uri,
      );

    if (
      !workspaceFolder
      || workspaceFolder.uri.scheme
        !== "file"
    ) {
      continue;
    }

    const relativePath =
      vscode.workspace.asRelativePath(
        uri,
        false,
      );

    const safeResult =
      await readSafeWorkspaceFile(
        workspaceFolder.uri.fsPath,
        uri.fsPath,
        relativePath,
        MAX_MODEL_FILE_BYTES,
      );

    const safeFile =
      safeResult.file;

    if (!safeFile) {
      continue;
    }

    if (
      seenRealPaths.has(
        safeFile.realPath,
      )
    ) {
      continue;
    }

    if (
      !payloadBudget.canAdd(
        safeFile.sizeBytes,
      )
    ) {
      break;
    }

    payloadBudget.add(
      safeFile.sizeBytes,
    );

    seenRealPaths.add(
      safeFile.realPath,
    );

    files.push({
      filename:
        safeFile.relativePath,
      language:
        normalizeLanguage(
          path.extname(
            safeFile.relativePath,
          ).slice(1),
        ),
      code:
        safeFile.content,
    });
  }

  return files;
}


async function generateWorkspaceThreatModel():
  Promise<void> {
  const workspaceFolders =
    vscode.workspace.workspaceFolders;

  if (
    !workspaceFolders
    || workspaceFolders.length === 0
  ) {
    void vscode.window.showWarningMessage(
      "Aegis: Open a workspace folder before generating a threat model.",
    );
    return;
  }

  const backendUrl =
    vscode.workspace
      .getConfiguration("aegis")
      .get<string>(
        "backendUrl",
        "http://127.0.0.1:8000",
      )
      .replace(/\/+$/, "");

  try {
    const files =
      await collectSafeModelSourceFiles();

    if (files.length === 0) {
      void vscode.window.showInformationMessage(
        "Aegis: No supported source files were found.",
      );
      return;
    }

    const result =
      await vscode.window.withProgress(
        {
          location:
            vscode.ProgressLocation.Notification,
          title:
            "Aegis is generating the threat model",
          cancellable: true,
        },
        async (
          progress,
          cancellationToken,
        ): Promise<
          ThreatModelScanResponse | undefined
        > => {
          progress.report({
            increment: 45,
            message:
              `Modeling threats across ${files.length} source file(s)`,
          });

          return requestThreatModelScan(
            backendUrl,
            files,
          );
        },
      );

    if (!result) {
      void vscode.window.showInformationMessage(
        "Aegis: Threat modeling was cancelled.",
      );
      return;
    }

    latestThreatModel = result;
    securityTreeProvider?.refresh();

    await showReusableAegisReport(
      "threat-model",
      buildThreatModelReport(result),
    );

    const message =
      `Aegis identified ${result.summary.threats_found} threat(s), `
      + `${result.summary.assets_found} asset(s), and `
      + `${result.summary.trust_boundaries_found} trust boundary/boundaries.`;

    if (
      result.summary.critical > 0
      || result.summary.high > 0
    ) {
      void vscode.window.showWarningMessage(
        message,
        "Keep Report Open",
      );
    } else {
      void vscode.window.showInformationMessage(
        message,
      );
    }
  } catch (error: unknown) {
    const message =
      error instanceof Error
        ? error.message
        : String(error);

    void vscode.window.showErrorMessage(
      `Aegis Threat Modeling failed: ${message}`,
    );
  }
}


async function mapWorkspaceAttackSurface():
  Promise<void> {
  const workspaceFolders =
    vscode.workspace.workspaceFolders;

  if (
    !workspaceFolders
    || workspaceFolders.length === 0
  ) {
    void vscode.window.showWarningMessage(
      "Aegis: Open a workspace folder before mapping the attack surface.",
    );
    return;
  }

  const backendUrl =
    vscode.workspace
      .getConfiguration("aegis")
      .get<string>(
        "backendUrl",
        "http://127.0.0.1:8000",
      )
      .replace(/\/+$/, "");

  try {
    const files =
      await collectSafeModelSourceFiles();

    if (files.length === 0) {
      void vscode.window.showInformationMessage(
        "Aegis: No supported source files were found.",
      );
      return;
    }

    const result =
      await vscode.window.withProgress(
        {
          location:
            vscode.ProgressLocation.Notification,
          title:
            "Aegis is mapping the attack surface",
          cancellable: true,
        },
        async (
          progress,
          cancellationToken,
        ): Promise<
          AttackSurfaceScanResponse | undefined
        > => {
          progress.report({
            increment: 45,
            message:
              `Analyzing ${files.length} source file(s)`,
          });

          return requestAttackSurfaceScan(
            backendUrl,
            files,
          );
        },
      );

    if (!result) {
      void vscode.window.showInformationMessage(
        "Aegis: Attack Surface mapping was cancelled.",
      );
      return;
    }

    latestAttackSurface = result;
    securityTreeProvider?.refresh();

    await showReusableAegisReport(
      "attack-surface",
      buildAttackSurfaceReport(result),
    );

    void vscode.window.showInformationMessage(
      `Aegis mapped ${result.summary.routes} route(s), `
      + `${result.summary.nodes_found} node(s), and `
      + `${result.summary.edges_found} relationship(s).`,
    );
  } catch (error: unknown) {
    const message =
      error instanceof Error
        ? error.message
        : String(error);

    void vscode.window.showErrorMessage(
      `Aegis Attack Surface mapping failed: ${message}`,
    );
  }
}

async function scanEntireWorkspace(): Promise<void> {
  const workspaceFolders = vscode.workspace.workspaceFolders;

  if (!workspaceFolders || workspaceFolders.length === 0) {
    void vscode.window.showWarningMessage(
      "Aegis: Open a workspace folder before running Workspace Scan.",
    );
    return;
  }

  const configuration =
    vscode.workspace.getConfiguration("aegis");

  const backendUrl = configuration
    .get<string>(
      "backendUrl",
      "http://127.0.0.1:8000",
    )
    .replace(/\/+$/, "");

  const fileUris =
    await vscode.workspace.findFiles(
      WORKSPACE_SOURCE_GLOB,
      WORKSPACE_EXCLUDE_GLOB,
      MAX_WORKSPACE_SCAN_FILES,
    );

  if (fileUris.length === 0) {
    void vscode.window.showInformationMessage(
      "Aegis: No supported source files were found in this workspace.",
    );
    return;
  }

  diagnosticCollection?.clear();

  const summary: WorkspaceScanSummary = {
    filesDiscovered: fileUris.length,
    filesScanned: 0,
    filesSkipped: 0,
    filesFailed: 0,
    results: [],
    errors: [],
  };

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: "Aegis is scanning the workspace",
      cancellable: true,
    },
    async (progress, cancellationToken) => {
      const increment = 100 / fileUris.length;

      for (const [index, uri] of fileUris.entries()) {
        if (cancellationToken.isCancellationRequested) {
          break;
        }

        const relativePath =
          vscode.workspace.asRelativePath(uri, false);

        progress.report({
          increment,
          message:
            `${index + 1}/${fileUris.length} · ${relativePath}`,
        });

        try {
          if (uri.scheme !== "file") {
            summary.filesSkipped += 1;
            summary.errors.push(
              `${relativePath}: skipped because only local file workspaces are supported.`,
            );
            continue;
          }

          const workspaceFolder =
            vscode.workspace.getWorkspaceFolder(
              uri,
            );

          if (
            !workspaceFolder
            || workspaceFolder.uri.scheme
              !== "file"
          ) {
            summary.filesSkipped += 1;
            summary.errors.push(
              `${relativePath}: skipped because its workspace root could not be resolved safely.`,
            );
            continue;
          }

          const safeResult =
            await readSafeWorkspaceFile(
              workspaceFolder.uri.fsPath,
              uri.fsPath,
              relativePath,
              MAX_WORKSPACE_FILE_BYTES,
            );

          const safeFile =
            safeResult.file;

          if (!safeFile) {
            summary.filesSkipped += 1;
            summary.errors.push(
              `${relativePath}: skipped — ${safeResult.message ?? safeResult.reason ?? "unsafe file"}.`,
            );
            continue;
          }

          const document =
            await vscode.workspace.openTextDocument(
              uri,
            );

          const result =
            await requestAnalysis({
              backendUrl,
              code: safeFile.content,
              filename:
                safeFile.relativePath,
              language:
                normalizeLanguage(
                  document.languageId,
                ),
              mode: "fast",
            });

          summary.filesScanned += 1;

          summary.results.push({
            uri,
            relativePath:
              safeFile.relativePath,
            response: result,
          });

          updateDiagnostics(
            document,
            result,
            0,
          );
        } catch (error: unknown) {
          summary.filesFailed += 1;

          const message =
            error instanceof Error
              ? error.message
              : "Unknown scan error.";

          summary.errors.push(
            `${relativePath}: ${message}`,
          );
        }
      }
    },
  );

  latestWorkspaceScan = summary;
  securityTreeProvider?.refresh();

  await showWorkspaceScanReport(summary);

  const totalFindings = summary.results.reduce(
    (total, result) =>
      total + result.response.findings.length,
    0,
  );

  if (totalFindings === 0) {
    void vscode.window.showInformationMessage(
      `Aegis Workspace Scan completed: ${summary.filesScanned} file(s) scanned and no findings detected.`,
    );
    return;
  }

  const action = await vscode.window.showWarningMessage(
    `Aegis Workspace Scan found ${totalFindings} security finding(s) across ${summary.filesScanned} scanned file(s).`,
    "Open Problems",
    "Keep Report Open",
  );

  if (action === "Open Problems") {
    await vscode.commands.executeCommand(
      "workbench.actions.view.problems",
    );
  }
}

async function showWorkspaceScanReport(
  summary: WorkspaceScanSummary,
): Promise<void> {
  const content = buildWorkspaceScanReport(summary);

  await showReusableAegisReport(
    "workspace",
    content,
  );
}

function buildWorkspaceScanReport(
  summary: WorkspaceScanSummary,
): string {
  const findings = summary.results.flatMap(
    (result) =>
      result.response.findings.map((finding) => ({
        relativePath: result.relativePath,
        finding,
      })),
  );

  const countSeverity = (severity: Severity): number =>
    findings.filter(
      (item) => item.finding.severity === severity,
    ).length;

  const lines: string[] = [
    "# Aegis Workspace Security Scan",
    "",
    `- **Files discovered:** ${summary.filesDiscovered}`,
    `- **Files scanned:** ${summary.filesScanned}`,
    `- **Files skipped:** ${summary.filesSkipped}`,
    `- **Files failed:** ${summary.filesFailed}`,
    `- **Total findings:** ${findings.length}`,
    "",
    "## Severity Summary",
    "",
    `- **Critical:** ${countSeverity("critical")}`,
    `- **High:** ${countSeverity("high")}`,
    `- **Medium:** ${countSeverity("medium")}`,
    `- **Low:** ${countSeverity("low")}`,
    `- **Info:** ${countSeverity("info")}`,
    "",
  ];

  if (findings.length === 0) {
    lines.push(
      "No meaningful security finding was detected in the scanned files.",
      "",
      "> This result does not guarantee that the workspace is completely secure.",
    );
  } else {
    lines.push("## Findings", "");

    findings.forEach((item, index) => {
      const finding = item.finding;

      lines.push(
        `### ${index + 1}. ${finding.title}`,
        "",
        `- **File:** \`${item.relativePath}\``,
        `- **Severity:** ${finding.severity.toUpperCase()}`,
        `- **Confidence:** ${Math.round(finding.confidence * 100)}%`,
        `- **CWE:** ${finding.cwe.join(", ") || "Not specified"}`,
        `- **OWASP:** ${finding.owasp.join(", ") || "Not specified"}`,
        "",
        finding.summary,
        "",
      );

      if (finding.scanner_evidence.length > 0) {
        lines.push("#### Evidence", "");

        for (const evidence of finding.scanner_evidence) {
          lines.push(
            `- Lines ${evidence.line_start}-${evidence.line_end}: ${evidence.message}`,
          );
        }

        lines.push("");
      }

      lines.push("---", "");
    });
  }

  if (summary.errors.length > 0) {
    lines.push("## Scan Warnings", "");

    for (const error of summary.errors) {
      lines.push(`- ${error}`);
    }

    lines.push("");
  }

  return lines.join("\n");
}

async function fastScanCurrentFile(): Promise<void> {
  const editor = vscode.window.activeTextEditor;

  if (!editor) {
    void vscode.window.showErrorMessage(
      "Aegis: No active editor was found.",
    );
    return;
  }

  const document = editor.document;
  const code = document.getText();

  if (!code.trim()) {
    void vscode.window.showWarningMessage(
      "Aegis: The current file is empty.",
    );
    return;
  }

  const filename = path.basename(document.fileName || "unknown.py");
  const language = normalizeLanguage(document.languageId);

  const configuration = vscode.workspace.getConfiguration("aegis");

  const backendUrl = configuration
    .get<string>("backendUrl", "http://127.0.0.1:8000")
    .replace(/\/+$/, "");

  try {
    const result = await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: "Aegis is scanning the current file",
        cancellable: false,
      },
      async () =>
        requestAnalysis({
          backendUrl,
          code,
          filename,
          language,
          mode: "fast",
        }),
    );

    lastAnalysis = {
      documentUri: document.uri.toString(),
      documentVersion: document.version,
      selection: new vscode.Range(
        document.positionAt(0),
        document.positionAt(code.length),
      ),
      response: result,
      mode: "fast",
    };

    updateDiagnostics(
      document,
      result,
      0,
    );

    await showAnalysisResult(result, "fast");

    if (result.findings.length > 0) {
      const action = await vscode.window.showWarningMessage(
        `Aegis Fast Scan found ${result.findings.length} suspicious finding(s).`,
        "Run Deep Analysis",
        "Keep Report Open",
      );

      if (action === "Run Deep Analysis") {
        editor.selection = new vscode.Selection(
          document.positionAt(0),
          document.positionAt(code.length),
        );

        await analyzeSelectedCode("deep");
      }
    }
  } catch (error: unknown) {
    const message =
      error instanceof Error
        ? error.message
        : "Unknown analysis error.";

    void vscode.window.showErrorMessage(`Aegis: ${message}`);
  }
}

async function analyzeSelectedCode(mode: AnalysisMode): Promise<void> {
  const editor = vscode.window.activeTextEditor;

  if (!editor) {
    void vscode.window.showErrorMessage(
      "Aegis: No active editor was found.",
    );
    return;
  }

  if (editor.selection.isEmpty) {
    void vscode.window.showWarningMessage(
      "Aegis: Select the code you want to analyze first.",
    );
    return;
  }

  const document = editor.document;
  const selection = new vscode.Range(
    editor.selection.start,
    editor.selection.end,
  );

  const selectedCode = document.getText(selection);
  const filename = path.basename(document.fileName || "unknown.py");
  const language = normalizeLanguage(document.languageId);

  const configuration = vscode.workspace.getConfiguration("aegis");

  const backendUrl = configuration
    .get<string>("backendUrl", "http://127.0.0.1:8000")
    .replace(/\/+$/, "");

  const progressTitle =
    mode === "fast"
      ? "Aegis is running a fast security scan"
      : "Aegis is running deep AI analysis";

  try {
    const result = await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: progressTitle,
        cancellable: false,
      },
      async () =>
        requestAnalysis({
          backendUrl,
          code: selectedCode,
          filename,
          language,
          mode,
        }),
    );

    lastAnalysis = {
      documentUri: document.uri.toString(),
      documentVersion: document.version,
      selection,
      response: result,
      mode,
    };

    updateDiagnostics(
      document,
      result,
      selection.start.line,
    );

    await showAnalysisResult(result, mode);

    if (mode === "fast" && result.findings.length > 0) {
      const action = await vscode.window.showWarningMessage(
        `Aegis Fast Scan ${result.findings.length} suspicious finding(s).`,
        "Run Deep Analysis",
        "Keep Report Open",
      );

      if (action === "Run Deep Analysis") {
        await analyzeSelectedCode("deep");
      }

      return;
    }

    const firstPatch = findFirstPatch(result);

    if (mode === "deep" && firstPatch) {
      const action = await vscode.window.showInformationMessage(
        `Aegis ${result.findings.length} security finding(s).`,
        "Apply Secure Fix",
        "Keep Report Open",
      );

      if (action === "Apply Secure Fix") {
        await applySecureFix();
      }
    }
  } catch (error: unknown) {
    const message =
      error instanceof Error
        ? error.message
        : "Unknown analysis error.";

    void vscode.window.showErrorMessage(`Aegis: ${message}`);
  }
}

async function runAuthorizedDynamicBaseline():
  Promise<void> {
  const editor = vscode.window.activeTextEditor;

  if (!editor) {
    void vscode.window.showWarningMessage(
      "Aegis: Open the vulnerable source file first.",
    );
    return;
  }

  if (!lastAnalysis) {
    void vscode.window.showWarningMessage(
      "Aegis: Run Deep Analysis before recording a dynamic baseline.",
    );
    return;
  }

  const document = editor.document;

  if (
    document.uri.toString() !==
    lastAnalysis.documentUri
  ) {
    void vscode.window.showWarningMessage(
      "Aegis: The active file does not match the latest analysis.",
    );
    return;
  }

  if (
    document.version !==
    lastAnalysis.documentVersion
  ) {
    void vscode.window.showWarningMessage(
      "Aegis: The file changed after analysis. Run Deep Analysis again.",
    );
    return;
  }

  const repositoryRoot =
    await resolveVerificationProjectRoot(document);

  const relativeEntrypoint = path.relative(
    repositoryRoot,
    document.fileName,
  );

  if (
    !relativeEntrypoint ||
    relativeEntrypoint.startsWith("..") ||
    path.isAbsolute(relativeEntrypoint)
  ) {
    void vscode.window.showErrorMessage(
      "Aegis: The active file must be inside the resolved repository.",
    );
    return;
  }

  const category = await vscode.window.showQuickPick<
    vscode.QuickPickItem & {
      value: ValidationTestType;
    }
  >(
    [
      {
        label: "Command Injection",
        value: "command_injection",
      },
      {
        label: "SQL Injection",
        value: "sql_injection",
      },
      {
        label: "Path Traversal",
        value: "path_traversal",
      },
      {
        label: "SSRF",
        value: "ssrf",
      },
      {
        label: "Authentication Bypass",
        value: "authentication_bypass",
      },
      {
        label: "Unsafe Data Flow",
        value: "unsafe_data_flow",
      },
    ],
    {
      title: "Aegis Authorized Dynamic Baseline",
      placeHolder:
        "Choose the validation category matching the analyzed vulnerability.",
    },
  );

  if (!category) {
    return;
  }

  const defaultRuntime: ValidationRuntime =
    document.languageId === "javascript" ||
    document.languageId === "typescript" ||
    document.languageId === "javascriptreact" ||
    document.languageId === "typescriptreact"
      ? "node"
      : "python";

  const runtimeChoice =
    await vscode.window.showQuickPick<
      vscode.QuickPickItem & {
        value: ValidationRuntime;
      }
    >(
      [
        {
          label: "Python",
          value: "python",
        },
        {
          label: "Node.js",
          value: "node",
        },
      ],
      {
        title: "Validation Runtime",
        placeHolder: `Recommended: ${defaultRuntime}`,
      },
    );

  if (!runtimeChoice) {
    return;
  }

  const entrypoint =
    await vscode.window.showInputBox({
      title: "Validation Entrypoint",
      prompt:
        "Repository-relative file executed inside the read-only sandbox.",
      value: relativeEntrypoint
        .split(path.sep)
        .join("/"),
      validateInput: (value) => {
        const normalized = value.trim();

        if (!normalized) {
          return "Entrypoint is required.";
        }

        if (
          path.isAbsolute(normalized) ||
          normalized === ".." ||
          normalized.startsWith("../") ||
          normalized.includes("/../")
        ) {
          return "Entrypoint must stay inside the repository.";
        }

        return undefined;
      },
    });

  if (!entrypoint) {
    return;
  }

  const stdoutMarker =
    await vscode.window.showInputBox({
      title: "Required Evidence Marker",
      prompt:
        "Exact stdout text proving that the authorized validation reproduced the vulnerable behavior.",
      placeHolder: "AEGIS_EXPLOIT_CONFIRMED",
      validateInput: (value) =>
        value.trim().length === 0
          ? "A deterministic evidence marker is required."
          : value.length > 1_000
            ? "Marker must not exceed 1,000 characters."
            : undefined,
    });

  if (!stdoutMarker) {
    return;
  }

  const authorization =
    await vscode.window.showWarningMessage(
      "Authorize isolated dynamic validation for this local repository?",
      {
        modal: true,
        detail: [
          `Repository: ${repositoryRoot}`,
          `Entrypoint: ${entrypoint}`,
          `Category: ${category.value}`,
          "",
          "Aegis will run this file in a hardened local container with no network, a read-only repository mount, dropped capabilities, and strict resource limits.",
        ].join("\n"),
      },
      "I Authorize This Validation",
      "Cancel",
    );

  if (
    authorization !==
    "I Authorize This Validation"
  ) {
    return;
  }

  const configuration =
    vscode.workspace.getConfiguration("aegis");

  const backendUrl = configuration
    .get<string>(
      "backendUrl",
      "http://127.0.0.1:8000",
    )
    .replace(/\/+$/, "");

  const finding =
    lastAnalysis.response.findings[0];

  const firstRuleId =
    finding?.scanner_evidence[0]?.rule_id;

  const threatId = [
    firstRuleId ||
      finding?.title ||
      category.value,
    path.basename(document.fileName),
  ].join(":");

  const authorizationRequest:
    ValidationAuthorizationRequest = {
      authorization_confirmed: true,
      target_type: "local_repository",
      target: repositoryRoot,
      allowed_test_types: [
        category.value,
      ],
      dry_run: false,
      timeout_seconds: 30,
      memory_limit_mb: 256,
      cpu_limit: 0.5,
      network_policy: "disabled",
    };

  const plan: ValidationPlanRequest = {
    authorization: authorizationRequest,
    runtime: runtimeChoice.value,
    entrypoint: entrypoint.trim(),
    test_type: category.value,
  };

  const successCriteria:
    ValidationSuccessCriteria = {
      expected_exit_code: 0,
      stdout_contains: stdoutMarker.trim(),
    };

  try {
    const beforeExecution =
      await vscode.window.withProgress(
        {
          location:
            vscode.ProgressLocation.Notification,
          title:
            "Aegis is running the authorized dynamic baseline",
          cancellable: false,
        },
        () =>
          requestValidationExecution(
            backendUrl,
            plan,
          ),
      );

    const beforeEvidence =
      await requestValidationEvidence(
        backendUrl,
        {
          threat_id: threatId,
          category: category.value,
          execution: beforeExecution,
          success_criteria:
            successCriteria,
        },
      );

    if (
      beforeEvidence.verdict !==
      "confirmed"
    ) {
      authorizedDynamicBaseline = undefined;

      void vscode.window.showWarningMessage(
        `Aegis dynamic baseline was not stored because the vulnerable behavior was not confirmed: ${beforeEvidence.verdict}. Fix verification will remain partial.`,
      );
      return;
    }

    authorizedDynamicBaseline = {
      documentUri:
        document.uri.toString(),
      documentVersion:
        document.version,
      repositoryRoot,
      threatId,
      category: category.value,
      plan,
      successCriteria,
      beforeExecution,
      beforeEvidence,
    };

    void vscode.window.showInformationMessage(
      `Aegis dynamic baseline CONFIRMED for ${category.label}. The same authorized plan can now be replayed after applying the fix.`,
    );
  } catch (error: unknown) {
    authorizedDynamicBaseline = undefined;

    const message =
      error instanceof Error
        ? error.message
        : "Unknown dynamic validation error.";

    void vscode.window.showErrorMessage(
      `Aegis dynamic baseline failed: ${message}`,
    );
  }
}


async function requestValidationExecution(
  backendUrl: string,
  plan: ValidationPlanRequest,
): Promise<ValidationExecutionResult> {
  return requestValidationJson<
    ValidationExecutionResult
  >(
    backendUrl,
    "/v1/validation/run",
    {
      plan,
    },
    90_000,
  );
}


async function requestValidationEvidence(
  backendUrl: string,
  payload: {
    threat_id: string;
    category: ValidationTestType;
    execution: ValidationExecutionResult;
    success_criteria:
      ValidationSuccessCriteria;
  },
): Promise<DynamicValidationEvidenceResponse> {
  return requestValidationJson<
    DynamicValidationEvidenceResponse
  >(
    backendUrl,
    "/v1/validation/evidence",
    payload,
    30_000,
  );
}


async function requestValidationReplay(
  backendUrl: string,
  baseline: AuthorizedDynamicBaseline,
): Promise<ValidationReplayResponse> {
  return requestValidationJson<
    ValidationReplayResponse
  >(
    backendUrl,
    "/v1/validation/replay",
    {
      threat_id: baseline.threatId,
      category: baseline.category,
      plan: baseline.plan,
      success_criteria:
        baseline.successCriteria,
      before_execution:
        baseline.beforeExecution,
    },
    90_000,
  );
}


async function requestUnifiedFixVerification(
  backendUrl: string,
  input: {
    replay: ValidationReplayComparison;
    projectVerification:
      ProjectVerificationSuite;
    targetResolved: boolean;
    regressionFree: boolean;
  },
): Promise<UnifiedFixVerificationResponse> {
  const projectChecks = [
    input.projectVerification.syntax,
    input.projectVerification.tests,
    input.projectVerification.build,
  ].map((check) => ({
    name: check.name,
    status: check.status,
    details: check.details,
  }));

  return requestValidationJson<
    UnifiedFixVerificationResponse
  >(
    backendUrl,
    "/v1/validation/fix-verification",
    {
      replay: input.replay,
      project_checks: projectChecks,
      static_target_resolved:
        input.targetResolved,
      static_regression_free:
        input.regressionFree,
    },
    30_000,
  );
}


async function requestValidationJson<T>(
  backendUrl: string,
  endpoint: string,
  body: unknown,
  timeoutMilliseconds: number,
): Promise<T> {
  return postBackendJson<T>({
    backendUrl,
    endpoint,
    body,
    timeoutMilliseconds,
    timeoutMessage:
      `Validation request timed out after ${Math.round(timeoutMilliseconds / 1_000)} seconds.`,
  });
}


async function applySecureFix(): Promise<void> {
  if (!lastAnalysis) {
    void vscode.window.showWarningMessage(
      "Aegis: Run Deep Analysis before applying a fix.",
    );
    return;
  }

  if (lastAnalysis.mode !== "deep") {
    void vscode.window.showWarningMessage(
      "Aegis: Fast Scan does not produce patches. Run Deep Analysis first.",
    );
    return;
  }

  const analyzedState = lastAnalysis;

  const dynamicBaselineForFix =
    authorizedDynamicBaseline &&
    authorizedDynamicBaseline.documentUri ===
      analyzedState.documentUri &&
    authorizedDynamicBaseline.documentVersion ===
      analyzedState.documentVersion &&
    authorizedDynamicBaseline.beforeEvidence.verdict ===
      "confirmed"
      ? authorizedDynamicBaseline
      : undefined;

  const documentUri = vscode.Uri.parse(
    analyzedState.documentUri,
  );

  const document = await vscode.workspace.openTextDocument(
    documentUri,
  );

  const editor = await vscode.window.showTextDocument(
    document,
    {
      preview: false,
      viewColumn: vscode.ViewColumn.One,
    },
  );

  if (document.version !== analyzedState.documentVersion) {
    void vscode.window.showWarningMessage(
      "Aegis: The file changed after analysis. Run Deep Analysis again.",
    );
    return;
  }

  const patch = findFirstPatch(analyzedState.response);

  if (!patch) {
    void vscode.window.showWarningMessage(
      "Aegis: No applicable secure patch was found.",
    );
    return;
  }

  const configuration =
    vscode.workspace.getConfiguration("aegis");

  const backendUrl = configuration
    .get<string>(
      "backendUrl",
      "http://127.0.0.1:8000",
    )
    .replace(/\/+$/, "");

  const baselineResult =
    await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: "Aegis is recording the security baseline",
        cancellable: false,
      },
      async () =>
        requestAnalysis({
          backendUrl,
          code: document.getText(),
          filename:
            path.basename(document.fileName) || "unknown.py",
          language: normalizeLanguage(document.languageId),
          mode: "fast",
        }),
    );

  const originalSelectionCode = document.getText(
    analyzedState.selection,
  );

  const originalSelectionStartOffset =
    document.offsetAt(analyzedState.selection.start);

  const secureSelectionCode = preserveIndentation(
    originalSelectionCode,
    patch,
  );

  const originalDocument = await vscode.workspace.openTextDocument({
    language: document.languageId,
    content: originalSelectionCode,
  });

  const secureDocument = await vscode.workspace.openTextDocument({
    language: document.languageId,
    content: secureSelectionCode,
  });

  await vscode.commands.executeCommand(
    "vscode.diff",
    originalDocument.uri,
    secureDocument.uri,
    `Aegis Secure Fix Preview — ${path.basename(document.fileName)}`,
    {
      preview: true,
      viewColumn: vscode.ViewColumn.Beside,
    },
  );

  const decision = await vscode.window.showWarningMessage(
    "Review the Aegis secure fix in the diff editor.",
    {
      modal: true,
      detail:
        "Apply Fix replaces only the code selection analyzed by Aegis. The file will then be saved and scanned again automatically.",
    },
    "Apply Fix",
    "Cancel",
  );

  if (decision !== "Apply Fix") {
    return;
  }

  const edit = new vscode.WorkspaceEdit();

  edit.replace(
    document.uri,
    analyzedState.selection,
    secureSelectionCode,
  );

  const applied = await vscode.workspace.applyEdit(edit);

  if (!applied) {
    void vscode.window.showErrorMessage(
      "Aegis: The secure fix could not be applied.",
    );
    return;
  }

  const saved = await document.save();

  if (!saved) {
    void vscode.window.showWarningMessage(
      "Aegis: The fix was applied, but the file could not be saved.",
    );
    return;
  }

  const projectVerification =
    await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: "Aegis is verifying syntax, tests, and build",
        cancellable: false,
      },
      async () =>
        verifyPatchedProject(document),
    );

  const failedProjectChecks = [
    projectVerification.syntax,
    projectVerification.tests,
    projectVerification.build,
  ].filter(
    (check) => check.status === "failed",
  );

  if (failedProjectChecks.length > 0) {
    const patchedSelection = new vscode.Range(
      document.positionAt(
        originalSelectionStartOffset,
      ),
      document.positionAt(
        originalSelectionStartOffset +
          secureSelectionCode.length,
      ),
    );

    const rollbackEdit = new vscode.WorkspaceEdit();

    rollbackEdit.replace(
      document.uri,
      patchedSelection,
      originalSelectionCode,
    );

    const rolledBack =
      await vscode.workspace.applyEdit(
        rollbackEdit,
      );

    if (rolledBack) {
      await document.save();
    }

    diagnosticCollection?.delete(document.uri);
    lastAnalysis = undefined;

    const rollbackStatus = rolledBack
      ? "The original code was restored automatically."
      : "Automatic rollback failed. Review the file immediately.";

    const failedCheckSummary =
      failedProjectChecks
        .map(
          (check) =>
            `${check.name}: ${check.details}`,
        )
        .join(" | ");

    await showFixVerificationReport({
      fileName: document.fileName,
      status: "FAILED",
      projectVerification,
      dynamicReplay: {
        status: "not_run",
        reasons: [
          "Dynamic replay was not attempted because project verification failed.",
        ],
      },
      rollbackStatus,
    });

    void vscode.window.showErrorMessage(
      [
        "Aegis Fix Status: FAILED — project verification did not pass.",
        failedCheckSummary,
        rollbackStatus,
      ].join(" "),
      "Open File",
    ).then((action) => {
      if (action === "Open File") {
        void vscode.window.showTextDocument(
          document,
          {
            preview: false,
            viewColumn: vscode.ViewColumn.One,
          },
        );
      }
    });

    return;
  }

  diagnosticCollection?.delete(document.uri);
  lastAnalysis = undefined;

  const verificationResult =
    await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: "Aegis is verifying the secure fix",
        cancellable: false,
      },
      async () =>
        requestAnalysis({
          backendUrl,
          code: document.getText(),
          filename:
            path.basename(document.fileName) || "unknown.py",
          language: normalizeLanguage(document.languageId),
          mode: "fast",
        }),
    );

  const securityDelta =
    compareSecurityVerificationResults(
      analyzedState.response,
      baselineResult,
      verificationResult,
    );

  updateDiagnostics(
    document,
    verificationResult,
    0,
  );

  lastAnalysis = {
    documentUri: document.uri.toString(),
    documentVersion: document.version,
    selection: new vscode.Range(
      document.positionAt(0),
      document.positionAt(document.getText().length),
    ),
    response: verificationResult,
    mode: "fast",
  };

  await showAnalysisResult(
    verificationResult,
    "fast",
  );

  const verificationMessages = [
    formatVerificationCheck(
      projectVerification.syntax,
    ),
    formatVerificationCheck(
      projectVerification.tests,
    ),
    formatVerificationCheck(
      projectVerification.build,
    ),
  ];

  const targetResolved =
    securityDelta.remainingTargetFindings.length === 0;

  const regressionFree =
    securityDelta.introducedFindings.length === 0;

  let dynamicReplayReport:
    DynamicReplayReport = {
      status: "not_run",
      reasons: [
        "No matching confirmed dynamic baseline was available for replay.",
      ],
    };

  let unifiedResult:
    UnifiedFixVerificationResponse | undefined;

  if (dynamicBaselineForFix) {
    try {
      const replayResult =
        await vscode.window.withProgress(
          {
            location:
              vscode.ProgressLocation.Notification,
            title:
              "Aegis is replaying the authorized dynamic validation",
            cancellable: false,
          },
          () =>
            requestValidationReplay(
              backendUrl,
              dynamicBaselineForFix,
            ),
        );

      dynamicReplayReport = {
        status:
          replayResult.comparison.verdict,
        confidence:
          replayResult.comparison.confidence,
        beforeVerdict:
          replayResult.comparison.before_verdict,
        afterVerdict:
          replayResult.comparison.after_verdict,
        reasons: [
          ...replayResult.comparison.reasons,
          ...replayResult.comparison.denials,
        ],
      };

      unifiedResult =
        await requestUnifiedFixVerification(
          backendUrl,
          {
            replay:
              replayResult.comparison,
            projectVerification,
            targetResolved,
            regressionFree,
          },
        );
    } catch (error: unknown) {
      const message =
        error instanceof Error
          ? error.message
          : "Unknown dynamic replay error.";

      dynamicReplayReport = {
        status: "inconclusive",
        reasons: [
          `Dynamic replay could not be completed: ${message}`,
        ],
      };
    } finally {
      authorizedDynamicBaseline = undefined;
    }
  }

  const finalReportStatus:
    FixVerificationReportInput["status"] =
    unifiedResult?.verdict === "verified"
      ? "VERIFIED"
      : unifiedResult?.verdict ===
          "inconclusive" ||
        dynamicReplayReport.status ===
          "inconclusive" ||
        dynamicReplayReport.status ===
          "not_run"
        ? (
            targetResolved &&
            regressionFree
              ? "PARTIAL"
              : "FAILED"
          )
        : "FAILED";

  await showFixVerificationReport({
    fileName: document.fileName,
    status: finalReportStatus,
    projectVerification,
    targetResolved,
    regressionFree,
    securityDelta,
    dynamicReplay:
      dynamicReplayReport,
    unifiedVerdict:
      unifiedResult?.verdict,
  });

  if (
    unifiedResult?.verified &&
    finalReportStatus === "VERIFIED"
  ) {
    const existingMessage =
      securityDelta.unchangedFindings.length > 0
        ? `${securityDelta.unchangedFindings.length} unrelated pre-existing finding(s) remain.`
        : "No pre-existing findings remain.";

    void vscode.window.showInformationMessage(
      [
        "Aegis Fix Status: VERIFIED.",
        ...verificationMessages,
        "Target vulnerability: RESOLVED.",
        "Regression check: PASSED.",
        "Dynamic replay: FIXED.",
        `Unified verdict: ${unifiedResult.verdict.toUpperCase()}.`,
        existingMessage,
      ].join(" "),
    );

    return;
  }

  if (
    targetResolved &&
    regressionFree &&
    finalReportStatus === "PARTIAL"
  ) {
    const existingMessage =
      securityDelta.unchangedFindings.length > 0
        ? `${securityDelta.unchangedFindings.length} unrelated pre-existing finding(s) remain.`
        : "No pre-existing findings remain.";

    void vscode.window.showInformationMessage(
      [
        "Aegis Fix Status: PARTIAL — available checks passed, but complete dynamic proof was not obtained.",
        ...verificationMessages,
        "Target vulnerability: RESOLVED.",
        "Regression check: PASSED.",
        `Dynamic replay: ${formatDynamicReplayStatus(dynamicReplayReport)}.`,
        "A confirmed and successfully completed dynamic replay is required for VERIFIED status.",
        existingMessage,
      ].join(" "),
    );

    return;
  }

  const failureReasons: string[] = [];

  if (!targetResolved) {
    failureReasons.push(
      `${securityDelta.remainingTargetFindings.length} target finding(s) remain`,
    );
  }

  if (!regressionFree) {
    failureReasons.push(
      `${securityDelta.introducedFindings.length} new finding(s) were introduced`,
    );
  }

  if (
    dynamicReplayReport.status ===
    "still_exploitable"
  ) {
    failureReasons.push(
      "the authorized dynamic validation still reproduces",
    );
  }

  if (
    unifiedResult &&
    unifiedResult.verdict !== "verified" &&
    unifiedResult.verdict !== "inconclusive"
  ) {
    failureReasons.push(
      `unified verdict: ${unifiedResult.verdict}`,
    );
  }

  if (failureReasons.length === 0) {
    failureReasons.push(
      "complete fix verification was not obtained",
    );
  }

  void vscode.window.showWarningMessage(
    `Aegis Fix Status: FAILED — ${failureReasons.join("; ")}.`,
    "Open Problems",
  ).then((action) => {
    if (action === "Open Problems") {
      void vscode.commands.executeCommand(
        "workbench.actions.view.problems",
      );
    }
  });

  editor.revealRange(
    analyzedState.selection,
    vscode.TextEditorRevealType.InCenter,
  );
}

async function showFixVerificationReport(
  input: FixVerificationReportInput,
): Promise<void> {
  await showReusableAegisReport(
    "fix-verification",
    buildFixVerificationReport(input),
  );
}

function buildFixVerificationReport(
  input: FixVerificationReportInput,
): string {
  const checks = [
    input.projectVerification.syntax,
    input.projectVerification.tests,
    input.projectVerification.build,
  ];

  const checkSections = checks
    .map(buildVerificationCheckSection)
    .join("\n\n");

  const targetStatus =
    input.targetResolved === undefined
      ? "NOT RUN"
      : input.targetResolved
        ? "PASSED"
        : "FAILED";

  const regressionStatus =
    input.regressionFree === undefined
      ? "NOT RUN"
      : input.regressionFree
        ? "PASSED"
        : "FAILED";

  const dynamicReplayStatus =
    formatDynamicReplayStatus(
      input.dynamicReplay,
    );

  const unifiedVerdict =
    input.unifiedVerdict?.toUpperCase() ??
    (input.dynamicReplay?.status === "not_run" ||
    input.dynamicReplay === undefined
      ? "NOT RUN"
      : "INCONCLUSIVE");

  const remainingTargetFindings =
    input.securityDelta?.remainingTargetFindings ?? [];

  const introducedFindings =
    input.securityDelta?.introducedFindings ?? [];

  const unchangedFindings =
    input.securityDelta?.unchangedFindings ?? [];

  const securitySections = [
    buildFindingListSection(
      "Remaining Target Findings",
      remainingTargetFindings,
    ),
    buildFindingListSection(
      "Newly Introduced Findings",
      introducedFindings,
    ),
    buildFindingListSection(
      "Unchanged Pre-existing Findings",
      unchangedFindings,
    ),
  ].join("\n\n");

  const rollbackSection =
    input.rollbackStatus
      ? [
          "## Rollback",
          "",
          input.rollbackStatus,
        ].join("\n")
      : [
          "## Rollback",
          "",
          "Not required.",
        ].join("\n");

  return [
    "# Aegis Fix Verification",
    "",
    `- **File:** ${path.basename(input.fileName)}`,
    `- **Final Status:** ${input.status}`,
    `- **Target Vulnerability:** ${targetStatus}`,
    `- **Regression Check:** ${regressionStatus}`,
    `- **Dynamic Replay:** ${dynamicReplayStatus}`,
    `- **Unified Verdict:** ${unifiedVerdict}`,
    `- **Generated:** ${new Date().toISOString()}`,
    "",
    "> VERIFIED requires project checks, static verification, regression analysis, and a successful dynamic replay. PARTIAL means available checks passed but dynamic proof was not completed.",
    "",
    "## Project Verification",
    "",
    checkSections,
    "",
    "## Security Verification",
    "",
    `- **Target findings remaining:** ${remainingTargetFindings.length}`,
    `- **New findings introduced:** ${introducedFindings.length}`,
    `- **Unchanged findings:** ${unchangedFindings.length}`,
    "",
    securitySections,
    "",
    buildDynamicReplaySection(
      input.dynamicReplay,
    ),
    "",
    rollbackSection,
  ].join("\n");
}

function formatDynamicReplayStatus(
  replay: DynamicReplayReport | undefined,
): string {
  if (!replay || replay.status === "not_run") {
    return "NOT RUN";
  }

  if (replay.status === "fixed") {
    return "FIXED";
  }

  if (replay.status === "still_exploitable") {
    return "STILL EXPLOITABLE";
  }

  return "INCONCLUSIVE";
}

function buildDynamicReplaySection(
  replay: DynamicReplayReport | undefined,
): string {
  if (!replay || replay.status === "not_run") {
    return [
      "## Dynamic Replay",
      "",
      "- **Status:** NOT RUN",
      "",
      "No explicitly authorized dynamic baseline was available. Static and project checks alone do not prove that the exploit path was closed.",
    ].join("\n");
  }

  const confidence =
    replay.confidence === undefined
      ? "Not reported"
      : `${Math.round(replay.confidence * 100)}%`;

  const reasons =
    replay.reasons.length > 0
      ? replay.reasons.map(
          (reason) => `- ${reason}`,
        )
      : ["- No additional reason was provided."];

  return [
    "## Dynamic Replay",
    "",
    `- **Status:** ${formatDynamicReplayStatus(replay)}`,
    `- **Confidence:** ${confidence}`,
    `- **Before Verdict:** ${replay.beforeVerdict ?? "Not reported"}`,
    `- **After Verdict:** ${replay.afterVerdict ?? "Not reported"}`,
    "",
    "### Evidence Summary",
    "",
    ...reasons,
  ].join("\n");
}

function buildVerificationCheckSection(
  check: VerificationCheckResult,
): string {
  const lines = [
    `### ${check.name}`,
    "",
    `- **Status:** ${check.status.toUpperCase()}`,
  ];

  if (check.command) {
    lines.push(
      `- **Command:** \`${escapeMarkdownInlineCode(check.command)}\``,
    );
  }

  lines.push(
    "",
    "```text",
    sanitizeVerificationDetails(check.details),
    "```",
  );

  return lines.join("\n");
}

function buildFindingListSection(
  heading: string,
  findings: SecurityFinding[],
): string {
  if (findings.length === 0) {
    return [
      `### ${heading}`,
      "",
      "None.",
    ].join("\n");
  }

  const items = findings.map(
    (finding, index) => {
      const ruleIds = finding.scanner_evidence
        .map((evidence) => evidence.rule_id)
        .filter(
          (ruleId, ruleIndex, allRuleIds) =>
            allRuleIds.indexOf(ruleId) === ruleIndex,
        );

      const cwes =
        finding.cwe.length > 0
          ? finding.cwe.join(", ")
          : "Not specified";

      return [
        `${index + 1}. **${finding.title}**`,
        `   - Severity: ${finding.severity.toUpperCase()}`,
        `   - CWE: ${cwes}`,
        `   - Rules: ${ruleIds.join(", ") || "Not specified"}`,
      ].join("\n");
    },
  );

  return [
    `### ${heading}`,
    "",
    ...items,
  ].join("\n");
}

function escapeMarkdownInlineCode(
  value: string,
): string {
  return value.replace(/`/g, "\\`");
}

function sanitizeVerificationDetails(
  details: string,
): string {
  const trimmed = details.trim();

  if (!trimmed) {
    return "No additional details were provided.";
  }

  return trimmed
    .replace(/```/g, "~~~")
    .slice(0, 12_000);
}

function compareSecurityVerificationResults(
  analyzedResponse: AnalyzeResponse,
  baselineResponse: AnalyzeResponse,
  verificationResponse: AnalyzeResponse,
): SecurityVerificationDelta {
  const findingRuleIds = (
    finding: SecurityFinding,
  ): string[] =>
    Array.from(
      new Set(
        finding.scanner_evidence.map(
          (evidence) => evidence.rule_id,
        ),
      ),
    );

  const countRules = (
    findings: SecurityFinding[],
  ): Map<string, number> => {
    const counts = new Map<string, number>();

    for (const finding of findings) {
      for (const ruleId of findingRuleIds(
        finding,
      )) {
        counts.set(
          ruleId,
          (counts.get(ruleId) ?? 0) + 1,
        );
      }
    }

    return counts;
  };

  const analyzedTargetCounts = countRules(
    analyzedResponse.findings,
  );

  const targetRuleIds = Array.from(
    analyzedTargetCounts.keys(),
  );

  const baselineRuleCounts = countRules(
    baselineResponse.findings,
  );

  const verificationRuleCounts = countRules(
    verificationResponse.findings,
  );

  const remainingRuleBudgets =
    new Map<string, number>();

  for (const ruleId of targetRuleIds) {
    const baselineCount =
      baselineRuleCounts.get(ruleId) ?? 0;

    const targetCount =
      analyzedTargetCounts.get(ruleId) ?? 0;

    const verificationCount =
      verificationRuleCounts.get(ruleId) ?? 0;

    const expectedUnrelatedRemaining =
      Math.max(
        0,
        baselineCount - targetCount,
      );

    remainingRuleBudgets.set(
      ruleId,
      Math.max(
        0,
        verificationCount -
          expectedUnrelatedRemaining,
      ),
    );
  }

  const remainingTargetFindings:
    SecurityFinding[] = [];

  for (
    const finding
    of verificationResponse.findings
  ) {
    const matchedRuleId = findingRuleIds(
      finding,
    ).find(
      (ruleId) =>
        (remainingRuleBudgets.get(ruleId) ?? 0)
          > 0,
    );

    if (!matchedRuleId) {
      continue;
    }

    remainingTargetFindings.push(finding);

    remainingRuleBudgets.set(
      matchedRuleId,
      (
        remainingRuleBudgets.get(
          matchedRuleId,
        ) ?? 1
      ) - 1,
    );
  }

  const baselineIdentities = new Set(
    baselineResponse.findings.map(
      securityFindingIdentity,
    ),
  );

  const introducedFindings =
    verificationResponse.findings.filter(
      (finding) =>
        !baselineIdentities.has(
          securityFindingIdentity(finding),
        ) &&
        !isExpectedCommandInjectionMitigation(
          finding,
          targetRuleIds,
        ),
    );

  const unchangedFindings =
    verificationResponse.findings.filter(
      (finding) =>
        baselineIdentities.has(
          securityFindingIdentity(finding),
        ),
    );

  return {
    targetRuleIds,
    remainingTargetFindings,
    introducedFindings,
    unchangedFindings,
  };
}

function isExpectedCommandInjectionMitigation(
  finding: SecurityFinding,
  targetRuleIds: string[],
): boolean {
  const fixesCommandInjection =
    targetRuleIds.some((ruleId) => {
      const normalized =
        ruleId.toLowerCase();

      return (
        normalized.includes(
          "command-injection",
        ) ||
        normalized.includes(
          "subprocess-popen-with-shell-equals-true",
        ) ||
        normalized.includes(
          "subprocess-shell",
        ) ||
        normalized.includes(".b602.")
      );
    });

  if (!fixesCommandInjection) {
    return false;
  }

  const ruleIds = finding.scanner_evidence.map(
    (evidence) =>
      evidence.rule_id.toLowerCase(),
  );

  if (ruleIds.length === 0) {
    return false;
  }

  return ruleIds.every(
    (ruleId) =>
      ruleId ===
        "bandit.python.b603.subprocess-without-shell-equals-true" ||
      ruleId.endsWith(
        ".b603.subprocess-without-shell-equals-true",
      ),
  );
}

function securityFindingIdentity(
  finding: SecurityFinding,
): string {
  const ruleIds = finding.scanner_evidence
    .map(
      (evidence) => evidence.rule_id,
    )
    .sort()
    .join(",");

  return [
    ruleIds || finding.title,
    finding.severity,
    finding.cwe.slice().sort().join(","),
  ].join("|");
}

const verificationRootMarkers = [
  ".git",
  "pyproject.toml",
  "pytest.ini",
  "setup.cfg",
  "tox.ini",
  "package.json",
  "pnpm-workspace.yaml",
  "yarn.lock",
  "package-lock.json",
];

const ignoredVerificationDirectories =
  new Set([
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    "coverage",
    ".pytest_cache",
    "__pycache__",
  ]);

async function resolveVerificationProjectRoot(
  document: vscode.TextDocument,
): Promise<string> {
  const documentDirectory =
    path.resolve(
      path.dirname(document.fileName),
    );

  try {
    const gitResult = await execFileAsync(
      "git",
      [
        "-C",
        documentDirectory,
        "rev-parse",
        "--show-toplevel",
      ],
      {
        timeout: 10_000,
        maxBuffer: 64 * 1024,
      },
    );

    const gitRoot =
      gitResult.stdout.trim();

    if (gitRoot) {
      return path.resolve(gitRoot);
    }
  } catch {
    // The document may not belong to a Git repository.
  }

  let currentDirectory =
    documentDirectory;

  while (true) {
    for (
      const marker
      of verificationRootMarkers
    ) {
      if (
        await pathExists(
          path.join(
            currentDirectory,
            marker,
          ),
        )
      ) {
        return currentDirectory;
      }
    }

    const parentDirectory =
      path.dirname(currentDirectory);

    if (
      parentDirectory === currentDirectory
    ) {
      break;
    }

    currentDirectory =
      parentDirectory;
  }

  const workspaceFolder =
    vscode.workspace.getWorkspaceFolder(
      document.uri,
    );

  return (
    workspaceFolder?.uri.fsPath ??
    documentDirectory
  );
}

async function pathExists(
  filePath: string,
): Promise<boolean> {
  try {
    await stat(filePath);
    return true;
  } catch {
    return false;
  }
}

async function hasAnyProjectEntry(
  projectRoot: string,
  relativePaths: string[],
): Promise<boolean> {
  for (const relativePath of relativePaths) {
    if (
      await pathExists(
        path.join(
          projectRoot,
          relativePath,
        ),
      )
    ) {
      return true;
    }
  }

  return false;
}

async function resolvePythonTestScope(
  projectRoot: string,
  document: vscode.TextDocument,
): Promise<string> {
  const normalizedRoot =
    path.resolve(projectRoot);

  const normalizedFile =
    path.resolve(document.fileName);

  const documentDirectory =
    path.dirname(normalizedFile);

  const relativeFile =
    path.relative(
      normalizedRoot,
      normalizedFile,
    );

  if (
    relativeFile.startsWith("..") ||
    path.isAbsolute(relativeFile)
  ) {
    return documentDirectory;
  }

  const pythonProjectMarkers = [
    "pytest.ini",
    "pyproject.toml",
    "setup.cfg",
    "tox.ini",
  ];

  let currentDirectory =
    documentDirectory;

  while (true) {
    if (
      await hasAnyProjectEntry(
        currentDirectory,
        pythonProjectMarkers,
      )
    ) {
      return currentDirectory;
    }

    if (
      await pathExists(
        path.join(
          currentDirectory,
          "tests",
        ),
      )
    ) {
      return currentDirectory;
    }

    if (
      currentDirectory === normalizedRoot
    ) {
      break;
    }

    const parentDirectory =
      path.dirname(currentDirectory);

    if (
      parentDirectory === currentDirectory ||
      !parentDirectory.startsWith(
        normalizedRoot,
      )
    ) {
      break;
    }

    currentDirectory =
      parentDirectory;
  }

  return documentDirectory;
}

async function hasPythonTestFiles(
  projectRoot: string,
): Promise<boolean> {
  return directoryContainsPythonTests(
    projectRoot,
    0,
    6,
  );
}

async function directoryContainsPythonTests(
  directory: string,
  depth: number,
  maximumDepth: number,
): Promise<boolean> {
  if (depth > maximumDepth) {
    return false;
  }

  let entries;

  try {
    entries = await readdir(
      directory,
      {
        withFileTypes: true,
      },
    );
  } catch {
    return false;
  }

  for (const entry of entries) {
    const name = entry.name;

    if (
      entry.isFile() &&
      (
        /^test_.*\.py$/i.test(name) ||
        /_test\.py$/i.test(name)
      )
    ) {
      return true;
    }

    if (
      !entry.isDirectory() ||
      ignoredVerificationDirectories.has(name)
    ) {
      continue;
    }

    if (
      await directoryContainsPythonTests(
        path.join(
          directory,
          name,
        ),
        depth + 1,
        maximumDepth,
      )
    ) {
      return true;
    }
  }

  return false;
}

async function resolvePythonExecutable(
  workspacePath: string,
  documentPath: string,
): Promise<string> {
  const documentUri =
    vscode.Uri.file(documentPath);

  const workspaceFolder =
    vscode.workspace.getWorkspaceFolder(
      documentUri,
    );

  const configuredInterpreter =
    vscode.workspace
      .getConfiguration(
        "python",
        documentUri,
      )
      .get<string>(
        "defaultInterpreterPath",
      );

  const expandedConfiguredInterpreter =
    configuredInterpreter?.replace(
      /\$\{workspaceFolder\}/g,
      workspaceFolder?.uri.fsPath ??
        workspacePath,
    );

  const candidates = [
    expandedConfiguredInterpreter,
    path.join(
      workspacePath,
      ".venv",
      "bin",
      "python",
    ),
    path.join(
      workspacePath,
      "venv",
      "bin",
      "python",
    ),
    path.join(
      workspacePath,
      "backend",
      ".venv",
      "bin",
      "python",
    ),
  ].filter(
    (candidate): candidate is string =>
      Boolean(candidate),
  );

  for (
    const candidate of new Set(candidates)
  ) {
    if (await pathExists(candidate)) {
      return candidate;
    }
  }

  return "python3";
}

async function verifyPatchedProject(
  document: vscode.TextDocument,
): Promise<ProjectVerificationSuite> {
  const syntax =
    await verifyPatchedDocumentSyntax(document);

  if (syntax.status === "failed") {
    return {
      syntax,
      tests: {
        name: "Project tests",
        status: "skipped",
        details:
          "Tests were skipped because syntax verification failed.",
      },
      build: {
        name: "Build/typecheck",
        status: "skipped",
        details:
          "Build was skipped because syntax verification failed.",
      },
    };
  }

  const workspacePath =
    await resolveVerificationProjectRoot(
      document,
    );

  const tests =
    await discoverAndRunProjectTests(
      workspacePath,
      document,
    );

  if (tests.status === "failed") {
    return {
      syntax,
      tests,
      build: {
        name: "Build/typecheck",
        status: "skipped",
        details:
          "Build was skipped because project tests failed.",
      },
    };
  }

  const build =
    await discoverAndRunProjectBuild(
      workspacePath,
      document,
    );

  return {
    syntax,
    tests,
    build,
  };
}

function formatVerificationCheck(
  check: VerificationCheckResult,
): string {
  return (
    `${check.name}: ${check.status.toUpperCase()}.`
  );
}

async function discoverAndRunProjectTests(
  workspacePath: string,
  document: vscode.TextDocument,
): Promise<VerificationCheckResult> {
  const language = normalizeLanguage(
    document.languageId,
  );

  if (language === "python") {
    const testScope =
      await resolvePythonTestScope(
        workspacePath,
        document,
      );

    const hasPytestConfiguration =
      await hasAnyProjectEntry(
        testScope,
        [
          "pytest.ini",
          "pyproject.toml",
          "setup.cfg",
          "tox.ini",
        ],
      );

    const hasPythonTests =
      await hasPythonTestFiles(
        testScope,
      );

    if (
      hasPytestConfiguration ||
      hasPythonTests
    ) {
      const pythonPath = [
        testScope,
        workspacePath,
        process.env.PYTHONPATH,
      ]
        .filter(
          (value): value is string =>
            Boolean(value),
        )
        .join(path.delimiter);

      const pythonExecutable =
        await resolvePythonExecutable(
          workspacePath,
          document.fileName,
        );

      return runVerificationCommand({
        name: "Python tests",
        command: pythonExecutable,
        args: [
          "-m",
          "pytest",
          "-q",
          testScope,
        ],
        cwd: testScope,
        env: {
          ...process.env,
          PYTHONPATH: pythonPath,
        },
        timeout: 120_000,
        missingToolMeansSkipped: true,
      });
    }

    return {
      name: "Python tests",
      status: "skipped",
      details:
        `No relevant Python tests were discovered under ${testScope}.`,
    };
  }

  if (
    language === "javascript" ||
    language === "typescript"
  ) {
    const packageJsonPath = await findNearestPackageJson(
      document.fileName,
      workspacePath,
    );

    if (!packageJsonPath) {
      return {
        name: "Node tests",
        status: "skipped",
        details:
          "No package.json was found for the patched file.",
      };
    }

    const scripts = await readPackageScripts(
      packageJsonPath,
    );

    const testScript = scripts.test;

    if (
      !testScript ||
      isDefaultNpmTestScript(testScript)
    ) {
      return {
        name: "Node tests",
        status: "skipped",
        details:
          "No meaningful npm test script was configured.",
      };
    }

    return runVerificationCommand({
      name: "Node tests",
      command: "npm",
      args: [
        "test",
        "--",
        "--runInBand",
      ],
      cwd: path.dirname(packageJsonPath),
      timeout: 180_000,
      missingToolMeansSkipped: true,
    });
  }

  return {
    name: "Project tests",
    status: "skipped",
    details:
      `No test runner is configured for ${document.languageId}.`,
  };
}

async function discoverAndRunProjectBuild(
  workspacePath: string,
  document: vscode.TextDocument,
): Promise<VerificationCheckResult> {
  const language = normalizeLanguage(
    document.languageId,
  );

  if (language === "python") {
    const hasPyproject =
      await pathExists(
        path.join(
          workspacePath,
          "pyproject.toml",
        ),
      );

    if (!hasPyproject) {
      return {
        name: "Python build",
        status: "skipped",
        details:
          "No Python project build configuration was discovered.",
      };
    }

    return runVerificationCommand({
      name: "Python compile-all",
      command: "python3",
      args: [
        "-m",
        "compileall",
        "-q",
        workspacePath,
      ],
      cwd: workspacePath,
      timeout: 120_000,
    });
  }

  if (
    language === "javascript" ||
    language === "typescript"
  ) {
    const packageJsonPath = await findNearestPackageJson(
      document.fileName,
      workspacePath,
    );

    if (!packageJsonPath) {
      return {
        name: "Build/typecheck",
        status: "skipped",
        details:
          "No package.json was found for build discovery.",
      };
    }

    const scripts = await readPackageScripts(
      packageJsonPath,
    );

    const packageDirectory =
      path.dirname(packageJsonPath);

    if (scripts.typecheck) {
      return runVerificationCommand({
        name: "Typecheck",
        command: "npm",
        args: [
          "run",
          "typecheck",
          "--",
          "--pretty",
          "false",
        ],
        cwd: packageDirectory,
        timeout: 180_000,
        missingToolMeansSkipped: true,
      });
    }

    if (scripts.build) {
      return runVerificationCommand({
        name: "Project build",
        command: "npm",
        args: [
          "run",
          "build",
        ],
        cwd: packageDirectory,
        timeout: 180_000,
        missingToolMeansSkipped: true,
      });
    }

    if (language === "typescript") {
      return runVerificationCommand({
        name: "TypeScript project check",
        command: "npx",
        args: [
          "--no-install",
          "tsc",
          "--noEmit",
          "--pretty",
          "false",
        ],
        cwd: packageDirectory,
        timeout: 180_000,
        missingToolMeansSkipped: true,
      });
    }

    return {
      name: "Build/typecheck",
      status: "skipped",
      details:
        "No build or typecheck script was configured.",
    };
  }

  return {
    name: "Build/typecheck",
    status: "skipped",
    details:
      `No build verifier is configured for ${document.languageId}.`,
  };
}

async function findNearestPackageJson(
  fileName: string,
  workspacePath: string,
): Promise<string | undefined> {
  let currentDirectory =
    path.dirname(fileName);

  const normalizedWorkspace =
    path.resolve(workspacePath);

  while (
    currentDirectory.startsWith(
      normalizedWorkspace,
    )
  ) {
    const candidate =
      path.join(
        currentDirectory,
        "package.json",
      );

    try {
      await vscode.workspace.fs.stat(
        vscode.Uri.file(candidate),
      );

      return candidate;
    } catch {
      // Continue toward the workspace root.
    }

    if (
      currentDirectory === normalizedWorkspace
    ) {
      break;
    }

    const parent =
      path.dirname(currentDirectory);

    if (parent === currentDirectory) {
      break;
    }

    currentDirectory = parent;
  }

  return undefined;
}

async function readPackageScripts(
  packageJsonPath: string,
): Promise<Record<string, string>> {
  try {
    const content =
      await vscode.workspace.fs.readFile(
        vscode.Uri.file(packageJsonPath),
      );

    const parsed = JSON.parse(
      Buffer.from(content).toString("utf-8"),
    ) as {
      scripts?: Record<string, unknown>;
    };

    const scripts:
      Record<string, string> = {};

    for (const [
      name,
      value,
    ] of Object.entries(
      parsed.scripts ?? {},
    )) {
      if (typeof value === "string") {
        scripts[name] = value;
      }
    }

    return scripts;
  } catch {
    return {};
  }
}

function isDefaultNpmTestScript(
  script: string,
): boolean {
  const normalized =
    script.toLowerCase();

  return (
    normalized.includes(
      "error: no test specified",
    ) ||
    normalized.trim() === ""
  );
}

async function verifyPatchedDocumentSyntax(
  document: vscode.TextDocument,
): Promise<VerificationCheckResult> {
  const language = normalizeLanguage(
    document.languageId,
  );

  const workspaceFolder =
    vscode.workspace.getWorkspaceFolder(
      document.uri,
    );

  const workingDirectory =
    workspaceFolder?.uri.fsPath ??
    path.dirname(document.fileName);

  if (language === "python") {
    const pythonExecutable =
      await resolvePythonExecutable(
        workingDirectory,
        document.fileName,
      );

    return runVerificationCommand({
      name: "Python syntax",
      command: pythonExecutable,
      args: [
        "-m",
        "py_compile",
        document.fileName,
      ],
      cwd: workingDirectory,
      timeout: 30_000,
    });
  }

  if (language === "javascript") {
    return runVerificationCommand({
      name: "JavaScript syntax",
      command: "node",
      args: [
        "--check",
        document.fileName,
      ],
      cwd: workingDirectory,
      timeout: 30_000,
    });
  }

  if (language === "typescript") {
    const result = await runVerificationCommand({
      name: "TypeScript check",
      command: "npx",
      args: [
        "--no-install",
        "tsc",
        "--noEmit",
        "--pretty",
        "false",
        "--skipLibCheck",
        "--target",
        "ES2022",
        "--module",
        "commonjs",
        document.fileName,
      ],
      cwd: workingDirectory,
      timeout: 90_000,
      missingToolMeansSkipped: true,
    });

    return result;
  }

  return {
    name: "Syntax check",
    status: "skipped",
    details:
      `No syntax verifier is configured for ${document.languageId}.`,
  };
}

interface VerificationCommandInput {
  name: string;
  command: string;
  args: string[];
  cwd: string;
  timeout: number;
  env?: NodeJS.ProcessEnv;
  missingToolMeansSkipped?: boolean;
}

async function runVerificationCommand(
  input: VerificationCommandInput,
): Promise<VerificationCheckResult> {
  const printableCommand = [
    input.command,
    ...input.args,
  ].join(" ");

  try {
    const result = await execFileAsync(
      input.command,
      input.args,
      {
        cwd: input.cwd,
        env: input.env ?? process.env,
        timeout: input.timeout,
        maxBuffer: 1024 * 1024,
      },
    );

    const output = [
      result.stdout,
      result.stderr,
    ]
      .filter(
        (value) =>
          typeof value === "string" &&
          value.trim().length > 0,
      )
      .join("\n")
      .trim();

    return {
      name: input.name,
      status: "passed",
      command: printableCommand,
      details:
        output ||
        `${input.name} completed successfully.`,
    };
  } catch (error: unknown) {
    const commandError = error as {
      code?: string | number;
      stdout?: string;
      stderr?: string;
      message?: string;
      killed?: boolean;
      signal?: string;
    };

    const missingTool =
      commandError.code === "ENOENT" ||
      (
        typeof commandError.stderr === "string" &&
        (
          commandError.stderr.includes(
            "could not determine executable",
          ) ||
          commandError.stderr.includes(
            "not found",
          ) ||
          commandError.stderr.includes(
            "No module named pytest",
          )
        )
      );

    if (
      missingTool &&
      input.missingToolMeansSkipped
    ) {
      return {
        name: input.name,
        status: "skipped",
        command: printableCommand,
        details:
          `${input.name} was skipped because the required local tool is unavailable.`,
      };
    }

    const details = [
      commandError.stderr,
      commandError.stdout,
      commandError.message,
    ]
      .filter(
        (value) =>
          typeof value === "string" &&
          value.trim().length > 0,
      )
      .join("\n")
      .trim();

    return {
      name: input.name,
      status: "failed",
      command: printableCommand,
      details:
        details ||
        `${input.name} failed without diagnostic output.`,
    };
  }
}

async function requestAnalysis(
  input: AnalysisInput,
): Promise<AnalyzeResponse> {
  const timeoutMilliseconds =
    input.mode === "fast"
      ? 30_000
      : 300_000;

  const endpoint =
    input.mode === "fast"
      ? "/v1/analyze/fast"
      : "/v1/analyze/deep";

  const timeoutMessage =
    input.mode === "fast"
      ? "Fast Scan timed out after 30 seconds."
      : "Deep Analysis timed out after five minutes.";

  return postBackendJson<
    AnalyzeResponse
  >({
    backendUrl: input.backendUrl,
    endpoint,
    body: {
      code: input.code,
      filename: input.filename,
      language: input.language,
    },
    timeoutMilliseconds,
    timeoutMessage,
  });
}

class AegisCodeActionProvider
  implements vscode.CodeActionProvider {
  provideCodeActions(
    document: vscode.TextDocument,
    _range: vscode.Range,
    context: vscode.CodeActionContext,
  ): vscode.CodeAction[] {
    const storedDiagnostics =
      diagnosticCollection?.get(document.uri) ?? [];

    const aegisDiagnostics = [
      ...context.diagnostics,
      ...storedDiagnostics,
    ].filter(
      (diagnostic, index, diagnostics) =>
        diagnostic.source === "Aegis" &&
        diagnostics.findIndex(
          (candidate) =>
            candidate.source === diagnostic.source &&
            candidate.message === diagnostic.message &&
            candidate.range.isEqual(diagnostic.range),
        ) === index,
    );

    if (aegisDiagnostics.length === 0) {
      return [];
    }

    const actions: vscode.CodeAction[] = [];

    for (const diagnostic of aegisDiagnostics) {
      const deepAnalysisAction = new vscode.CodeAction(
        "Aegis: Run Deep Analysis",
        vscode.CodeActionKind.QuickFix,
      );

      deepAnalysisAction.diagnostics = [diagnostic];
      deepAnalysisAction.isPreferred = true;
      deepAnalysisAction.command = {
        command: "aegis.deepAnalyzeDiagnostic",
        title: "Run Aegis Deep Analysis",
        arguments: [
          document.uri,
          diagnostic.range,
        ],
      };

      actions.push(deepAnalysisAction);
    }

    const analysisMatchesDocument =
      lastAnalysis?.documentUri === document.uri.toString();

    if (analysisMatchesDocument && lastAnalysis) {
      const openReportAction = new vscode.CodeAction(
        "Aegis: Open Security Report",
        vscode.CodeActionKind.QuickFix,
      );

      openReportAction.command = {
        command: "aegis.openLastSecurityReport",
        title: "Open Aegis Security Report",
      };

      actions.push(openReportAction);

      if (
        lastAnalysis.mode === "deep" &&
        findFirstPatch(lastAnalysis.response)
      ) {
        const applyFixAction = new vscode.CodeAction(
          "Aegis: Apply Secure Fix",
          vscode.CodeActionKind.QuickFix,
        );

        applyFixAction.command = {
          command: "aegis.applySecureFix",
          title: "Apply Aegis Secure Fix",
        };

        actions.push(applyFixAction);
      }
    }

    return actions;
  }
}

async function deepAnalyzeDiagnostic(
  documentUri: vscode.Uri,
  range: vscode.Range,
): Promise<void> {
  const document = await vscode.workspace.openTextDocument(
    documentUri,
  );

  const editor = await vscode.window.showTextDocument(
    document,
    {
      preview: false,
      viewColumn: vscode.ViewColumn.One,
    },
  );

  editor.selection = new vscode.Selection(
    range.start,
    range.end,
  );

  editor.revealRange(
    range,
    vscode.TextEditorRevealType.InCenter,
  );

  await analyzeSelectedCode("deep");
}

async function openLastSecurityReport(): Promise<void> {
  if (!lastAnalysis) {
    void vscode.window.showWarningMessage(
      "Aegis: No previous security report is available.",
    );
    return;
  }

  await showAnalysisResult(
    lastAnalysis.response,
    lastAnalysis.mode,
  );
}

function updateDiagnostics(
  document: vscode.TextDocument,
  result: AnalyzeResponse,
  lineOffset: number,
): void {
  if (!diagnosticCollection) {
    return;
  }

  const diagnostics: vscode.Diagnostic[] = [];

  for (const finding of result.findings) {
    const evidenceItems =
      finding.scanner_evidence.length > 0
        ? finding.scanner_evidence
        : [
            {
              line_start:
                finding.vulnerable_lines[0] ?? 1,
              line_end:
                finding.vulnerable_lines.at(-1) ?? 1,
            },
          ];

    for (const evidence of evidenceItems) {
      const startLine = clampLine(
        evidence.line_start - 1 + lineOffset,
        document,
      );

      const endLine = clampLine(
        evidence.line_end - 1 + lineOffset,
        document,
      );

      const endCharacter =
        document.lineAt(endLine).text.length;

      const range = new vscode.Range(
        new vscode.Position(startLine, 0),
        new vscode.Position(endLine, endCharacter),
      );

      const diagnostic = new vscode.Diagnostic(
        range,
        buildDiagnosticMessage(finding),
        mapDiagnosticSeverity(finding.severity),
      );

      diagnostic.source = "Aegis";
      diagnostic.code =
        finding.cwe[0] ??
        finding.scanner_evidence[0]?.rule_id ??
        "security";

      diagnostics.push(diagnostic);
    }
  }

  diagnosticCollection.set(document.uri, diagnostics);
}

function buildDiagnosticMessage(
  finding: SecurityFinding,
): string {
  const metadata = [
    finding.severity.toUpperCase(),
    finding.cwe[0],
    finding.owasp[0],
  ].filter(Boolean);

  return `${metadata.join(" · ")} — ${finding.title}`;
}

function mapDiagnosticSeverity(
  severity: Severity,
): vscode.DiagnosticSeverity {
  switch (severity) {
    case "critical":
    case "high":
      return vscode.DiagnosticSeverity.Error;

    case "medium":
      return vscode.DiagnosticSeverity.Warning;

    case "low":
      return vscode.DiagnosticSeverity.Information;

    case "info":
    default:
      return vscode.DiagnosticSeverity.Hint;
  }
}

function clampLine(
  line: number,
  document: vscode.TextDocument,
): number {
  return Math.max(
    0,
    Math.min(line, document.lineCount - 1),
  );
}

async function showAnalysisResult(
  result: AnalyzeResponse,
  mode: AnalysisMode,
  memory?: SecurityMemoryDisplay,
): Promise<void> {
  await showReusableAegisReport(
    "analysis",
    buildMarkdownReport(
      result,
      mode,
      memory,
    ),
  );
}

function normalizeProposedPatch(
  proposedPatch: string,
): string | undefined {
  const trimmed = proposedPatch.trim();

  if (!trimmed) {
    return undefined;
  }

  const fencedBlocks = Array.from(
    trimmed.matchAll(
      /```[^\\n]*\\n([\\s\\S]*?)```/g,
    ),
  );

  if (fencedBlocks.length > 1) {
    return undefined;
  }

  if (
    trimmed.includes("```")
    && fencedBlocks.length === 0
  ) {
    return undefined;
  }

  const candidate =
    fencedBlocks.length === 1
      ? fencedBlocks[0][1].trim()
      : trimmed;

  if (!candidate) {
    return undefined;
  }

  const containsUnifiedDiffMetadata =
    candidate
      .split(/\\r?\\n/)
      .some((line) =>
        /^(?:diff --git |index |--- |\\+\\+\\+ |@@(?: |$))/.test(
          line,
        ),
      );

  if (containsUnifiedDiffMetadata) {
    return undefined;
  }

  return candidate;
}

function findFirstPatch(
  result: AnalyzeResponse,
): string | undefined {
  for (const finding of result.findings) {
    if (!finding.proposed_patch) {
      continue;
    }

    const normalized =
      normalizeProposedPatch(
        finding.proposed_patch,
      );

    if (normalized) {
      return normalized;
    }
  }

  return undefined;
}

function preserveIndentation(
  originalCode: string,
  proposedPatch: string,
): string {
  const sourceLine =
    originalCode
      .split("\n")
      .find((line) => line.trim().length > 0) ?? "";

  const indentation = sourceLine.match(/^\s*/)?.[0] ?? "";

  return proposedPatch
    .split("\n")
    .map((line) => (line.length > 0 ? `${indentation}${line}` : line))
    .join("\n");
}

async function recordAnalysisSecurityMemory(
  result: AnalyzeResponse,
): Promise<SecurityMemoryDisplay> {
  const editor =
    vscode.window.activeTextEditor;

  if (
    !editor
    || editor.document.uri.scheme !== "file"
  ) {
    return {
      error:
        "No local source document was available for project memory.",
    };
  }

  const configuration =
    vscode.workspace.getConfiguration("aegis");

  const backendUrl = configuration
    .get<string>(
      "backendUrl",
      "http://127.0.0.1:8000",
    )
    .replace(/\/+$/, "");

  try {
    const repositoryRoot =
      await resolveVerificationProjectRoot(
        editor.document,
      );

    const response =
      await requestSecurityMemoryRecord(
        backendUrl,
        repositoryRoot,
        result.claims ?? [],
      );

    return { response };
  } catch (error: unknown) {
    const message =
      error instanceof Error
        ? error.message
        : String(error);

    return {
      error: message,
    };
  }
}


async function requestSecurityMemoryRecord(
  backendUrl: string,
  repositoryPath: string,
  claims: SecurityClaim[],
): Promise<SecurityMemoryPolicyRecordResponse> {
  return postBackendJson<
    SecurityMemoryPolicyRecordResponse
  >({
    backendUrl,
    endpoint:
      "/v1/security-memory/record-and-evaluate",
    body: {
      repository_path:
        repositoryPath,
      claims,
      profile: "balanced",
    },
    timeoutMilliseconds: 30_000,
    timeoutMessage:
      "Security Memory request timed out after 30 seconds.",
  });
}


function buildSecurityMemoryDeltaReport(
  memory?: SecurityMemoryDisplay,
): string[] {
  const lines: string[] = [
    "## Security Memory Delta",
    "",
  ];

  if (!memory) {
    lines.push(
      "> Security Memory was not evaluated for this analysis.",
      "",
    );

    return lines;
  }

  if (!memory.response) {
    lines.push(
      "> Security Memory could not be updated. The analysis result remains available.",
      "",
    );

    if (memory.error) {
      lines.push(
        `- **Reason:** ${sanitizeMarkdownText(memory.error)}`,
        "",
      );
    }

    return lines;
  }

  const combinedResponse = memory.response;
  const response = combinedResponse.memory;
  const policy = combinedResponse.policy;
  const summary =
    response.reconciliation.summary;

  lines.push(
    "### Security Policy Gate",
    "",
    `- **Decision:** ${policy.decision.toUpperCase()}`,
    `- **Risk:** ${policy.risk_score} / 100 — ${policy.risk_level.toUpperCase()}`,
    `- **Profile:** ${policy.profile}`,
    `- **Blocked Claims:** ${policy.summary.blocked}`,
    `- **Review Claims:** ${policy.summary.review_required}`,
    `- **Ignored Claims:** ${policy.summary.claims_ignored}`,
    "",
  );

  for (const reason of policy.reasons) {
    lines.push(
      `- ${sanitizeMarkdownText(reason)}`,
    );
  }

  lines.push(
    "",
    "### Project Security Memory",
    "",
    `- **Project:** \`${escapeMarkdownInlineCode(response.repository.project_id)}\``,
    `- **Revision:** \`${escapeMarkdownInlineCode(response.repository.revision)}\``,
    `- **Working Tree:** ${response.repository.dirty ? "DIRTY" : "CLEAN"}`,
    `- **Snapshot:** \`${escapeMarkdownInlineCode(response.snapshot.snapshot_id)}\``,
    `- **Stored Snapshots:** ${response.project_snapshot_count}`,
    `- **Baseline Created:** ${response.baseline_created ? "YES" : "NO"}`,
    `- **New Snapshot Stored:** ${response.persisted_new_snapshot ? "YES" : "NO"}`,
    "",
    "### Lifecycle Summary",
    "",
    `- **New:** ${summary.new}`,
    `- **Persistent:** ${summary.persistent}`,
    `- **Changed:** ${summary.changed}`,
    `- **Resolved:** ${summary.resolved}`,
    `- **Reopened:** ${summary.reopened}`,
    "",
  );

  if (
    response.reconciliation.deltas.length === 0
  ) {
    lines.push(
      "No claim lifecycle change was recorded.",
      "",
    );

    return lines;
  }

  lines.push(
    "### Claim Transitions",
    "",
  );

  for (
    const delta
    of response.reconciliation.deltas
  ) {
    const transition = [
      delta.previous_state
        ?.replaceAll("_", " ")
        .toUpperCase()
        ?? "NONE",
      delta.current_state
        ?.replaceAll("_", " ")
        .toUpperCase()
        ?? "NONE",
    ].join(" → ");

    lines.push(
      `#### ${formatClaimDeltaStatus(delta.status)}`,
      "",
      `- **Claim ID:** \`${escapeMarkdownInlineCode(delta.claim_id)}\``,
      `- **Transition:** ${transition}`,
    );

    for (const reason of delta.reasons) {
      lines.push(
        `- ${sanitizeMarkdownText(reason)}`,
      );
    }

    lines.push("");
  }

  return lines;
}


function formatClaimDeltaStatus(
  status: ClaimDeltaStatus,
): string {
  const labels:
    Record<ClaimDeltaStatus, string> = {
      new: "NEW CLAIM",
      persistent: "PERSISTENT CLAIM",
      changed: "CHANGED CLAIM",
      resolved: "RESOLVED CLAIM",
      reopened: "REOPENED CLAIM",
    };

  return labels[status];
}


function sanitizeMarkdownText(
  value: string,
): string {
  return value
    .replace(/\r?\n/g, " ")
    .replace(/[<>]/g, "")
    .trim();
}


function buildClaimGraphReport(
  claims: SecurityClaim[],
): string[] {
  const lines: string[] = [
    "## Claim & Evidence Graph",
    "",
    `- **Canonical Claims:** ${claims.length}`,
    "",
  ];

  if (claims.length === 0) {
    lines.push(
      "No canonical security claim was returned by the backend.",
      "",
    );

    return lines;
  }

  claims.forEach((claim, index) => {
    const locations = claim.locations.length > 0
      ? claim.locations
          .map(
            (location) =>
              `${location.file}:${location.line_start}-${location.line_end}`,
          )
          .join(", ")
      : "No source location";

    const evidenceKinds = Array.from(
      new Set(
        claim.evidence.map(
          (evidence) => evidence.source.kind,
        ),
      ),
    );

    lines.push(
      `### Claim ${index + 1}: ${claim.category}`,
      "",
      `- **Claim ID:** \`${escapeMarkdownInlineCode(claim.claim_id)}\``,
      `- **State:** ${claim.state.replaceAll("_", " ").toUpperCase()}`,
      `- **Severity:** ${claim.severity.toUpperCase()}`,
      `- **Confidence:** ${Math.round(claim.confidence * 100)}%`,
      `- **Locations:** ${locations}`,
      `- **Evidence Items:** ${claim.evidence.length}`,
      `- **Evidence Types:** ${evidenceKinds.join(", ") || "None"}`,
      `- **Relationships:** ${claim.relationships.length}`,
      "",
      claim.statement,
      "",
    );

    if (claim.evidence.length > 0) {
      lines.push("#### Evidence Nodes", "");

      claim.evidence.forEach((evidence) => {
        const sourceLabel = [
          evidence.source.name,
          evidence.source.rule_id,
        ]
          .filter(Boolean)
          .join(" / ");

        lines.push(
          `- **${evidence.source.kind} — ${sourceLabel || "Unknown source"}**`,
          `  - Evidence ID: \`${escapeMarkdownInlineCode(evidence.evidence_id)}\``,
          `  - Confidence: ${Math.round(evidence.confidence * 100)}%`,
          `  - ${evidence.summary}`,
        );

        evidence.details.forEach((detail) => {
          lines.push(
            `  - ${detail.replace(/\n/g, " ")}`,
          );
        });
      });

      lines.push("");
    }

    if (claim.relationships.length > 0) {
      lines.push("#### Evidence Relationships", "");

      claim.relationships.forEach((relationship) => {
        lines.push(
          `- **${relationship.kind}**: `
          + `\`${escapeMarkdownInlineCode(relationship.source_evidence_id)}\``
          + " → "
          + `\`${escapeMarkdownInlineCode(relationship.target_evidence_id)}\``
          + (
            relationship.reason
              ? ` — ${relationship.reason}`
              : ""
          ),
        );
      });

      lines.push("");
    }
  });

  return lines;
}

function buildMarkdownReport(
  result: AnalyzeResponse,
  mode: AnalysisMode,
  memory?: SecurityMemoryDisplay,
): string {
  const modeLabel =
    mode === "fast" ? "Fast Scan" : "Deep Analysis";

  const lines: string[] = [
    `# Aegis ${modeLabel}`,
    "",
    `- **File:** ${result.filename}`,
    `- **Language:** ${result.language}`,
    `- **Mode:** ${modeLabel}`,
    `- **Model:** ${result.model}`,
    `- **Scanner:** ${result.scanner}`,
    `- **AI Review Status:** ${(result.analysis_status ?? "completed").toUpperCase()}`,
    `- **Result Source:** ${(result.result_source ?? "scanner").replaceAll("_", " ").toUpperCase()}`,
    `- **Patch Available:** ${findFirstPatch(result) ? "YES" : "NO"}`,
    `- **Findings:** ${result.findings.length}`,
    `- **Canonical Claims:** ${(result.claims ?? []).length}`,
    "",
  ];

  if (mode === "fast") {
    lines.push(
      "> Fast Scan displays local scanner evidence only. Run Deep Analysis for AI review and a proposed patch.",
      "",
    );
  }

  lines.push(
    ...buildSecurityMemoryDeltaReport(
      memory,
    ),
  );

  lines.push(
    ...buildClaimGraphReport(
      result.claims ?? [],
    ),
  );

  if (result.findings.length === 0) {
    lines.push(
      "No meaningful security finding was detected.",
      "",
      "> This result does not guarantee that the code is completely secure.",
    );

    return lines.join("\n");
  }

  result.findings.forEach((finding, index) => {
    lines.push(
      `## ${index + 1}. ${finding.title}`,
      "",
      `- **Severity:** ${finding.severity.toUpperCase()}`,
      `- **Confidence:** ${Math.round(finding.confidence * 100)}%`,
      `- **CWE:** ${finding.cwe.join(", ") || "Not mapped"}`,
      `- **OWASP:** ${finding.owasp.join(", ") || "Not mapped"}`,
      "",
      "### Summary",
      "",
      finding.summary,
      "",
      "### Evidence",
      "",
    );

    finding.evidence.forEach((evidence) => {
      lines.push(`- ${evidence}`);
    });

    if (finding.consensus_verdict) {
      lines.push(
        "",
        "### Multi-Model Verification",
        "",
        `- **Consensus Verdict:** ${
          finding.consensus_verdict
            .replaceAll("_", " ")
            .toUpperCase()
        }`,
      );

      if (
        finding.consensus_confidence !== undefined
        && finding.consensus_confidence !== null
      ) {
        lines.push(
          `- **Consensus Confidence:** ${
            Math.round(
              finding.consensus_confidence * 100,
            )
          }%`,
        );
      }

      const consensus = result.model_consensus;

      if (consensus?.primary_provider) {
        lines.push(
          `- **Primary Provider:** ${
            consensus.primary_provider
          }`,
        );
      }

      if (finding.primary_model) {
        lines.push(
          `- **Primary Model:** ${finding.primary_model}`,
        );
      }

      if (consensus?.verifier_provider) {
        lines.push(
          `- **Verifier Provider:** ${
            consensus.verifier_provider
          }`,
        );
      }

      if (finding.verifier_model) {
        lines.push(
          `- **Verifier Model:** ${finding.verifier_model}`,
        );
      }

      if (consensus?.route_independence) {
        lines.push(
          `- **Route Classification:** ${
            consensus.route_independence
              .replaceAll("_", " ")
              .toUpperCase()
          }`,
        );
      }

      if (
        consensus?.independently_verified !== undefined
        && consensus.independently_verified !== null
      ) {
        lines.push(
          `- **Independent Verification:** ${
            consensus.independently_verified
              ? "YES"
              : "NO"
          }`,
        );
      }

      if (
        consensus?.route_reasons
        && consensus.route_reasons.length > 0
      ) {
        lines.push(
          "",
          "#### Route Assessment",
          "",
        );

        consensus.route_reasons.forEach(
          (reason: string) => {
            lines.push(`- ${reason}`);
          },
        );
      }

      if (finding.verifier_verdict) {
        lines.push(
          `- **Verifier Verdict:** ${
            finding.verifier_verdict
              .replaceAll("_", " ")
              .toUpperCase()
          }`,
        );
      }

      if (
        finding.verifier_confidence !== undefined
        && finding.verifier_confidence !== null
      ) {
        lines.push(
          `- **Verifier Confidence:** ${
            Math.round(
              finding.verifier_confidence * 100,
            )
          }%`,
        );
      }

      if (finding.verifier_reasoning) {
        lines.push(
          `- **Verifier Reasoning:** ${
            finding.verifier_reasoning
          }`,
        );
      }

      if (
        finding.verifier_evidence
        && finding.verifier_evidence.length > 0
      ) {
        lines.push(
          "",
          "#### Verifier Evidence",
          "",
        );

        finding.verifier_evidence.forEach(
          (evidence) => {
            lines.push(`- ${evidence}`);
          },
        );
      }

      if (
        finding.consensus_reasons
        && finding.consensus_reasons.length > 0
      ) {
        lines.push(
          "",
          "#### Consensus Reasons",
          "",
        );

        finding.consensus_reasons.forEach(
          (reason) => {
            lines.push(`- ${reason}`);
          },
        );
      }
    }

    lines.push("", "### Scanner Evidence", "");

    finding.scanner_evidence.forEach((evidence) => {
      lines.push(
        `- **${evidence.tool} / ${evidence.rule_id}**`,
        `  - Lines: ${evidence.line_start}-${evidence.line_end}`,
        `  - Severity: ${evidence.severity}`,
        `  - ${evidence.message}`,
      );

      if (evidence.code) {
        lines.push(
          "",
          `\`\`\`${result.language}`,
          evidence.code,
          "\`\`\`",
        );
      }
    });

    lines.push(
      "",
      "### Recommended Fix",
      "",
      finding.recommended_fix,
      "",
    );

    if (finding.false_positive_notes.length > 0) {
      lines.push("### Notes", "");

      finding.false_positive_notes.forEach((note) => {
        lines.push(`- ${note}`);
      });

      lines.push("");
    }

    if (finding.proposed_patch) {
      lines.push(
        "### Proposed Patch",
        "",
        `\`\`\`${result.language}`,
        finding.proposed_patch,
        "```",
        "",
      );
    }

    lines.push("---", "");
  });

  return lines.join("\n");
}

function normalizeLanguage(languageId: string): string {
  const supported: Record<string, string> = {
    python: "python",
    javascript: "javascript",
    javascriptreact: "javascript",
    typescript: "typescript",
    typescriptreact: "typescript",
  };

  return supported[languageId] ?? languageId;
}

export function deactivate(): void {
  diagnosticCollection?.clear();
  diagnosticCollection = undefined;
  reportContentProvider = undefined;
  securityTreeProvider = undefined;
  latestDependencyScan = undefined;
  latestAttackSurface = undefined;
  latestWorkspaceScan = undefined;
  lastAnalysis = undefined;
}
