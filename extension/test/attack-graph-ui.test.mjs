import assert from "node:assert/strict";
import {
  existsSync,
  readFileSync,
} from "node:fs";
import path from "node:path";
import test from "node:test";
import {
  fileURLToPath,
} from "node:url";


const here = path.dirname(
  fileURLToPath(import.meta.url),
);
const extensionRoot = path.resolve(
  here,
  "..",
);

const manifest = JSON.parse(
  readFileSync(
    path.join(
      extensionRoot,
      "package.json",
    ),
    "utf8",
  ),
);

const extensionSource = readFileSync(
  path.join(
    extensionRoot,
    "src",
    "extension.ts",
  ),
  "utf8",
);

const panelPath = path.join(
  extensionRoot,
  "src",
  "attackGraphPanel.ts",
);

const panelSource = existsSync(panelPath)
  ? readFileSync(panelPath, "utf8")
  : "";


test(
  "manifest exposes the Attack Graph and Data Sentinel command",
  () => {
    const command =
      manifest.contributes.commands.find(
        (item) =>
          item.command
          === "aegis.showAttackGraph",
      );

    assert.ok(command);
    assert.equal(
      command.title,
      "Aegis: Show Attack Graph & Data Sentinel",
    );
    assert.match(
      command.enablement,
      /isWorkspaceTrusted/,
    );
  },
);


test(
  "extension registers the Attack Graph command",
  () => {
    assert.match(
      extensionSource,
      /"aegis\.showAttackGraph"/,
    );
    assert.match(
      extensionSource,
      /showWorkspaceAttackGraph/,
    );
  },
);


test(
  "Attack Graph command uses the exact deterministic backend artifact",
  () => {
    assert.match(
      extensionSource,
      /"\/v1\/attack-graph\/build"/,
    );
    assert.match(
      extensionSource,
      /requestAttackSurfaceScan\(/,
    );
    assert.match(
      extensionSource,
      /requestThreatModelScan\(/,
    );
    assert.match(
      extensionSource,
      /requestAttackGraphBuild\(/,
    );
    assert.match(
      extensionSource,
      /showAttackGraphPanel\(/,
    );
  },
);


test(
  "Attack Graph panel is static and CSP constrained",
  () => {
    assert.ok(
      panelSource.length > 0,
      "Attack Graph panel source is missing.",
    );
    assert.match(
      panelSource,
      /enableScripts:\s*false/,
    );
    assert.match(
      panelSource,
      /default-src 'none'/,
    );
    assert.doesNotMatch(
      panelSource,
      /<script[\s>]/i,
    );
  },
);


test(
  "Attack Graph panel exposes proof and Data Sentinel concepts",
  () => {
    assert.match(
      panelSource,
      /Attack Graph/,
    );
    assert.match(
      panelSource,
      /Data Sentinel/,
    );
    assert.match(
      panelSource,
      /Security claims need proof\./,
    );
    assert.match(
      panelSource,
      /source → sink/,
    );
    assert.match(
      panelSource,
      /Trust boundaries/,
    );
  },
);


test(
  "Attack Graph panel escapes dynamic content before HTML rendering",
  () => {
    assert.match(
      panelSource,
      /function escapeHtml\(/,
    );
    assert.match(
      panelSource,
      /\.replaceAll\("&", "&amp;"\)/,
    );
    assert.match(
      panelSource,
      /\.replaceAll\("<", "&lt;"\)/,
    );
  },
);
