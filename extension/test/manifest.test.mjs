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

test(
  "manifest has canonical identity metadata",
  () => {
    assert.equal(
      manifest.name,
      "aegis-security",
    );

    assert.equal(
      manifest.displayName,
      "Aegis Security",
    );

    assert.equal(
      manifest.repository.url,
      "https://github.com/lemkyz/Aegis.git",
    );

    assert.equal(
      manifest.homepage,
      "https://github.com/lemkyz/Aegis",
    );

    assert.equal(
      manifest.license,
      "Apache-2.0",
    );

    assert.equal(
      manifest.version,
      "0.2.0",
    );

    assert.equal(
      Object.hasOwn(manifest, "private"),
      false,
    );
  },
);

test(
  "manifest is ready for a preview marketplace listing",
  async () => {
    assert.equal(manifest.preview, true);
    assert.equal(manifest.pricing, "Free");
    assert.equal(manifest.markdown, "github");
    assert.equal(
      manifest.icon,
      "images/icon.png",
    );

    assert.match(
      manifest.galleryBanner.color,
      /^#[0-9A-F]{6}$/iu,
    );

    const icon = await readFile(
      new URL(
        "../images/icon.png",
        import.meta.url,
      ),
    );

    assert.equal(
      icon.subarray(1, 4).toString("ascii"),
      "PNG",
    );

    assert.equal(icon.readUInt32BE(16), 512);
    assert.equal(icon.readUInt32BE(20), 512);
  },
);

test(
  "repository commands require a trusted local workspace",
  () => {
    assert.deepEqual(
      manifest.extensionKind,
      ["workspace"],
    );

    assert.equal(
      manifest.capabilities
        .untrustedWorkspaces
        .supported,
      false,
    );

    assert.equal(
      manifest.capabilities
        .virtualWorkspaces
        .supported,
      false,
    );

    for (
      const command
      of manifest.contributes.commands
    ) {
      assert.equal(
        command.enablement,
        "isWorkspaceTrusted",
        (
          "Command is missing the workspace "
          + `trust boundary: ${command.command}`
        ),
      );
    }
  },
);

test(
  "manifest defines the production entry point",
  () => {
    assert.equal(
      manifest.main,
      "./dist/extension.js",
    );

    assert.match(
      manifest.engines.vscode,
      /^\^1\.\d+\.\d+$/u,
    );
  },
);

test(
  "manifest command IDs are unique",
  () => {
    const commands =
      manifest.contributes.commands;

    const commandIds = commands.map(
      (command) => command.command,
    );

    assert.equal(
      new Set(commandIds).size,
      commandIds.length,
    );

    assert.ok(
      commandIds.length >= 12,
    );

    for (const commandId of commandIds) {
      assert.match(
        commandId,
        /^aegis\.[A-Za-z0-9]+$/u,
      );
    }
  },
);

test(
  "all contributed menu commands exist",
  () => {
    const commandIds = new Set(
      manifest.contributes.commands.map(
        (command) => command.command,
      ),
    );

    const menus =
      manifest.contributes.menus;

    for (
      const menuItems
      of Object.values(menus)
    ) {
      for (const item of menuItems) {
        assert.ok(
          commandIds.has(item.command),
          (
            "Menu references unknown command: "
            + item.command
          ),
        );
      }
    }
  },
);

test(
  "backend URL defaults to local-only HTTP",
  () => {
    const backendUrl =
      manifest.contributes
        .configuration
        .properties[
          "aegis.backendUrl"
        ];

    assert.equal(
      backendUrl.type,
      "string",
    );

    assert.equal(
      backendUrl.default,
      "http://127.0.0.1:8000",
    );

    assert.ok(
      !backendUrl.default.includes(
        "0.0.0.0",
      ),
    );
  },
);

test(
  "release scripts cover build test and package",
  () => {
    const scripts = manifest.scripts;

    for (const required of [
      "clean",
      "compile",
      "test",
      "package",
      "package:list",
      "verify:vsix",
      "release:check",
    ]) {
      assert.equal(
        typeof scripts[required],
        "string",
        `Missing npm script: ${required}`,
      );
    }
  },
);

test(
  "package keywords describe security scope",
  () => {
    assert.ok(
      manifest.keywords.includes(
        "security",
      ),
    );

    assert.ok(
      manifest.keywords.includes(
        "devsecops",
      ),
    );

    assert.ok(
      manifest.keywords.includes(
        "trust-layer",
      ),
    );
  },
);


test(
  "manifest exposes model route display settings",
  () => {
    const properties =
      manifest.contributes.configuration.properties;

    const showMetadata =
      properties[
        "aegis.showModelRouteMetadata"
      ];

    const warnNonIndependent =
      properties[
        "aegis.warnOnNonIndependentVerification"
      ];

    assert.equal(showMetadata.type, "boolean");
    assert.equal(showMetadata.default, true);

    assert.equal(
      warnNonIndependent.type,
      "boolean",
    );
    assert.equal(
      warnNonIndependent.default,
      true,
    );
  },
);



test(
  "manifest contributes security task plan preview",
  () => {
    const command =
      manifest.contributes.commands.find(
        (item) =>
          item.command
          === "aegis.previewSecurityTaskPlan",
      );

    assert.ok(command);

    assert.equal(
      command.title,
      "Aegis: Preview Security Task Plan",
    );

    assert.equal(
      command.category,
      "Aegis",
    );
  },
);


test(
  "manifest contributes trusted analysis",
  () => {
    const command =
      manifest.contributes.commands.find(
        (item) =>
          item.command
          === "aegis.runTrustedAnalysis",
      );

    assert.ok(command);
    assert.equal(
      command.title,
      "Aegis: Run Trusted Analysis",
    );
    assert.equal(
      command.category,
      "Aegis",
    );
  },
);
