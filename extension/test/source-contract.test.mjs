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
