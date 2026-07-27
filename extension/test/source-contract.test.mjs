import assert from "node:assert/strict";
import {
  readFile,
} from "node:fs/promises";
import test from "node:test";

const manifest = JSON.parse(
  await readFile(
    new URL(
      "../package.json",
      import.meta.url,
    ),
    "utf-8",
  ),
);

const source = await readFile(
  new URL(
    "../src/extension.ts",
    import.meta.url,
  ),
  "utf-8",
);

test(
  "every contributed command is registered",
  () => {
    const commandIds =
      manifest.contributes.commands.map(
        (command) => command.command,
      );

    for (const commandId of commandIds) {
      assert.ok(
        source.includes(
          `"${commandId}"`,
        )
        || source.includes(
          `'${commandId}'`,
        ),
        (
          "Extension source does not contain "
          + `command ID: ${commandId}`
        ),
      );
    }
  },
);

test(
  "extension exports activate and deactivate",
  () => {
    assert.match(
      source,
      /export\s+(?:async\s+)?function\s+activate\s*\(/u,
    );

    assert.match(
      source,
      /export\s+function\s+deactivate\s*\(/u,
    );
  },
);

test(
  "extension uses the configured backend URL",
  () => {
    assert.ok(
      source.includes(
        "getConfiguration",
      ),
      "Extension does not read VS Code configuration.",
    );

    assert.ok(
      source.includes(
        '"aegis"',
      )
      || source.includes(
        "'aegis'",
      ),
      "Extension does not read the Aegis configuration section.",
    );

    assert.ok(
      source.includes(
        '"backendUrl"',
      )
      || source.includes(
        "'backendUrl'",
      ),
      "Extension does not read aegis.backendUrl.",
    );
  },
);

test(
  "extension does not spawn a shell",
  () => {
    assert.ok(
      !source.includes(
        "shell: true",
      ),
    );

    assert.ok(
      !source.includes(
        "exec(",
      ),
    );
  },
);

test(
  "extension avoids obvious embedded secrets",
  () => {
    const forbidden = [
      "BEGIN PRIVATE KEY",
      "OPENAI_API_KEY=",
      "GITHUB_TOKEN=",
      "api_key =",
      "apiKey =",
    ];

    for (const marker of forbidden) {
      assert.ok(
        !source.includes(marker),
        (
          "Potential embedded secret marker: "
          + marker
        ),
      );
    }
  },
);


test(
  "all backend HTTP traffic uses the centralized client",
  () => {
    assert.ok(
      source.includes(
        'from "./backendClient"',
      ),
    );

    assert.ok(
      source.includes(
        "postBackendJson",
      ),
    );

    assert.ok(
      !source.includes(
        "fetch(",
      ),
      "extension.ts still contains a direct fetch call.",
    );
  },
);



test(
  "workspace scanning uses the centralized safety boundary",
  () => {
    assert.ok(
      source.includes(
        'from "./workspaceSafety"',
      ),
    );

    assert.ok(
      source.includes(
        "readSafeWorkspaceFile",
      ),
    );

    assert.ok(
      source.includes(
        "collectSafeModelSourceFiles",
      ),
    );

    assert.ok(
      source.includes(
        "WORKSPACE_EXCLUDE_GLOB",
      ),
    );
  },
);


test(
  "partial analysis reports do not persist project security memory",
  () => {
    const showResultStart =
      source.indexOf(
        "async function showAnalysisResult(",
      );

    const nextFunctionStart =
      source.indexOf(
        "\nfunction findFirstPatch(",
        showResultStart,
      );

    assert.ok(
      showResultStart >= 0,
      "showAnalysisResult was not found.",
    );

    assert.ok(
      nextFunctionStart > showResultStart,
      "showAnalysisResult boundary was not found.",
    );

    const showResultSource =
      source.slice(
        showResultStart,
        nextFunctionStart,
      );

    assert.ok(
      !showResultSource.includes(
        "recordAnalysisSecurityMemory(",
      ),
      "Partial analysis still persists project memory.",
    );

    assert.ok(
      showResultSource.includes(
        "memory?: SecurityMemoryDisplay",
      ),
      "Analysis report does not accept explicit memory context.",
    );
  },
);


test(
  "dependency reports never treat incomplete OSV coverage as clean",
  () => {
    assert.ok(
      source.includes(
        'result.scan_status === "failed"',
      ),
    );

    assert.ok(
      source.includes(
        'result.scan_status === "partial"',
      ),
    );

    assert.ok(
      source.includes(
        "The absence of vulnerability records must not be interpreted as a clean dependency scan.",
      ),
    );

    assert.ok(
      source.includes(
        "Packages checked successfully",
      ),
    );

    assert.ok(
      source.includes(
        "Package queries failed",
      ),
    );
  },
);


test(
  "fix verification separates the selected target from unrelated matching findings",
  () => {
    assert.ok(
      source.includes(
        "expectedUnrelatedRemaining",
      ),
    );

    assert.ok(
      source.includes(
        "remainingRuleBudgets",
      ),
    );

    assert.ok(
      source.includes(
        "subprocess-popen-with-shell-equals-true",
      ),
    );

    assert.ok(
      source.includes(
        'normalized.includes(".b602.")',
      ),
    );
  },
);


test(
  "secure fixes reject malformed unified diff patches before editing files",
  () => {
    assert.ok(
      source.includes(
        "function normalizeProposedPatch",
      ),
    );

    assert.ok(
      source.includes(
        "containsUnifiedDiffMetadata",
      ),
    );

    assert.ok(
      source.includes(
        "/^(?:diff --git |index |--- |\\\\+\\\\+\\\\+ |@@(?: |$))/",
      ),
    );

    assert.ok(
      source.includes(
        "fencedBlocks.length > 1",
      ),
    );

    assert.ok(
      source.includes(
        "normalizeProposedPatch(",
      ),
    );
  },
);


test(
  "analysis response models multi-model verification metadata",
  () => {
    assert.match(
      source,
      /type ConsensusVerdict =[\s\S]*"confirmed"[\s\S]*"disputed"[\s\S]*"uncertain"[\s\S]*"unverified"/,
    );

    assert.match(
      source,
      /interface ModelConsensusResult \{[\s\S]*primary_model: string;[\s\S]*verifier_model: string \| null;[\s\S]*status: ModelConsensusStatus;[\s\S]*decisions: FindingConsensusDecision\[\];[\s\S]*errors: string\[\];[\s\S]*\}/,
    );

    assert.match(
      source,
      /interface SecurityFinding \{[\s\S]*primary_model\?: string \| null;[\s\S]*verifier_model\?: string \| null;[\s\S]*verifier_verdict\?: string \| null;[\s\S]*consensus_verdict\?: ConsensusVerdict \| null;[\s\S]*consensus_confidence\?: number \| null;/,
    );

    assert.match(
      source,
      /model_consensus\?: ModelConsensusResult \| null;/,
    );
  },
);


test(
  "canonical claim evidence supports verifier and consensus nodes",
  () => {
    assert.match(
      source,
      /\| "model_review"[\s\S]*\| "model_verification"[\s\S]*\| "model_consensus";/,
    );
  },
);


test(
  "security finding tree displays consensus when present",
  () => {
    assert.match(
      source,
      /function findingConsensusLabel\(/,
    );

    assert.match(
      source,
      /if \(!finding\.consensus_verdict\) \{/,
    );

    assert.match(
      source,
      /const consensusLabel =\s*findingConsensusLabel\(finding\);/,
    );

    assert.match(
      source,
      /\.filter\([\s\S]*value !== undefined[\s\S]*\)\s*\.join\(" · "\);/,
    );
  },
);


test(
  "markdown report displays multi-model verification",
  () => {
    assert.match(
      source,
      /if \(finding\.consensus_verdict\) \{/,
    );

    assert.match(
      source,
      /### Multi-Model Verification/,
    );

    assert.match(
      source,
      /\*\*Consensus Verdict:\*\*/,
    );

    assert.match(
      source,
      /\*\*Primary Model:\*\*/,
    );

    assert.match(
      source,
      /\*\*Verifier Model:\*\*/,
    );

    assert.match(
      source,
      /#### Verifier Evidence/,
    );

    assert.match(
      source,
      /#### Consensus Reasons/,
    );
  },
);


test(
  "markdown report exposes model route independence",
  () => {
    assert.match(
      source,
      /Primary Provider/,
    );
    assert.match(
      source,
      /Verifier Provider/,
    );
    assert.match(
      source,
      /Route Classification/,
    );
    assert.match(
      source,
      /Independent Verification/,
    );
    assert.match(
      source,
      /Route Assessment/,
    );
  },
);


test(
  "extension honors model route presentation settings",
  () => {
    assert.match(
      source,
      /showModelRouteMetadata/,
    );
    assert.match(
      source,
      /warnOnNonIndependentVerification/,
    );
    assert.match(
      source,
      /independently_verified !== false/,
    );
    assert.match(
      source,
      /corroborated rather than/,
    );
  },
);



test(
  "security task plan preview uses the safe planner endpoint",
  () => {
    assert.ok(
      source.includes(
        '"aegis.previewSecurityTaskPlan"',
      ),
    );

    assert.ok(
      source.includes(
        '"/v1/security/tasks/plan"',
      ),
    );

    assert.ok(
      source.includes(
        "requestSecurityTaskPlan",
      ),
    );

    assert.ok(
      source.includes(
        "buildSecurityTaskPlanReport",
      ),
    );

    assert.ok(
      source.includes(
        '"security-task-plan"',
      ),
    );
  },
);


test(
  "security task plan preview does not invoke execution transitions",
  () => {
    const previewStart =
      source.indexOf(
        "async function previewSecurityTaskPlan",
      );

    const nextFunction =
      source.indexOf(
        "\n\nasync function requestTrustedAnalysis",
        previewStart,
      );

    assert.ok(
      previewStart >= 0,
      "Security task plan preview was not found.",
    );

    assert.ok(
      nextFunction > previewStart,
      "Security task plan preview boundary was not found.",
    );

    const previewSource =
      source.slice(
        previewStart,
        nextFunction,
      );

    for (const forbiddenEndpoint of [
      "/v1/security/tasks/execution/create",
      "/v1/security/tasks/execution/start",
      "/v1/security/tasks/execution/complete",
      "/v1/security/tasks/execution/fail",
      "/v1/security/tasks/execution/skip",
      "/v1/security/tasks/aggregate",
      "/v1/security/tasks/run",
    ]) {
      assert.ok(
        !previewSource.includes(
          forbiddenEndpoint,
        ),
        (
          "Plan preview must not call "
          + forbiddenEndpoint
        ),
      );
    }
  },
);


test(
  "trusted analysis executes the production workflow",
  () => {
    for (const marker of [
      '"aegis.runTrustedAnalysis"',
      '"/v1/security/tasks/run"',
      '"trusted-analysis"',
      "buildTrustedAnalysisReport",
      "workflow_status",
      "security_memory",
      "policy_decision",
      "audit_event_count",
      "timeout_seconds: 285",
      "artifact_manifest_sha256",
      "createHash",
      "sourceDigest",
      "backend integrity attestation",
      "Security Memory is present only when scanner coverage",
    ]) {
      assert.ok(
        source.includes(marker),
        (
          "Missing trusted-analysis marker: "
          + marker
        ),
      );
    }
  },
);


test(
  "trusted analysis preserves explicit safety gates",
  () => {
    assert.ok(
      source.includes(
        "Dynamic execution still requires separate explicit authorization.",
      ),
    );
    assert.ok(
      source.includes(
        "Partial or failed workflows are never presented as a clean baseline.",
      ),
    );
    assert.ok(
      source.includes(
        "resolveVerificationProjectRoot",
      ),
    );
    assert.ok(
      source.includes(
        "MAX_MODEL_FILE_BYTES",
      ),
    );
    assert.ok(
      source.includes(
        "document.isDirty",
      ),
    );
    assert.ok(
      source.includes(
        "matches repository provenance",
      ),
    );
  },
);


test(
  "security task plan report exposes graph and safety metadata",
  () => {
    for (const marker of [
      "# Aegis Security Task Plan",
      "## Execution Order",
      "## Task Details",
      "## Plan Decisions",
      "## Blocked Tasks",
      "## Skipped Tasks",
      "## Safety Boundary",
      "Dynamic validation still requires explicit structured authorization.",
    ]) {
      assert.ok(
        source.includes(marker),
        `Missing task-plan report marker: ${marker}`,
      );
    }
  },
);


test(
  "task-plan report escapes evidence Markdown safely",
  () => {
    assert.ok(
      source.includes(
        'evidence.replaceAll("`", "\\\\`")',
      ),
    );

    assert.ok(
      !source.includes(
        'evidence.replaceAll("`", "\\`")',
      ),
    );
  },
);
