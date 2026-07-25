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
