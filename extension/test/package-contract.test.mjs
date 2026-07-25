import assert from "node:assert/strict";
import {
  readFile,
} from "node:fs/promises";
import test from "node:test";

const ignore = await readFile(
  new URL(
    "../.vscodeignore",
    import.meta.url,
  ),
  "utf-8",
);

test(
  "VSIX ignore rules exclude development files",
  () => {
    for (const rule of [
      ".vscode/**",
      "src/**",
      "node_modules/**",
      "tsconfig.json",
      "*.vsix",
      "dist/**/*.map",
    ]) {
      assert.ok(
        ignore.includes(rule),
        `Missing .vscodeignore rule: ${rule}`,
      );
    }
  },
);

test(
  "VSIX ignore rules exclude tests and scripts",
  () => {
    for (const rule of [
      "test/**",
      "scripts/**",
    ]) {
      assert.ok(
        ignore.includes(rule),
        `Missing .vscodeignore rule: ${rule}`,
      );
    }
  },
);

test(
  "VSIX verifier handles VSCE filename normalization",
  async () => {
    const verifier = await readFile(
      new URL(
        "../scripts/verify-vsix.mjs",
        import.meta.url,
      ),
      "utf-8",
    );

    assert.ok(
      verifier.includes(
        "normalizedLower",
      ),
    );

    assert.ok(
      verifier.includes(
        "extension/readme.md",
      ),
    );

    assert.ok(
      verifier.includes(
        "extension/license.txt",
      ),
    );
  },
);
