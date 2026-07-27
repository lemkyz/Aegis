import {
  execFileSync,
} from "node:child_process";
import {
  readdir,
  stat,
} from "node:fs/promises";
import {
  basename,
  join,
} from "node:path";
import process from "node:process";

const root = process.cwd();

const entries = await readdir(
  root,
  {
    withFileTypes: true,
  },
);

const packages = entries
  .filter(
    (entry) =>
      entry.isFile()
      && entry.name.endsWith(".vsix"),
  )
  .map(
    (entry) => join(root, entry.name),
  );

if (packages.length !== 1) {
  throw new Error(
    "Expected exactly one VSIX package; "
    + `found ${packages.length}.`,
  );
}

const vsixPath = packages[0];
const packageStat = await stat(vsixPath);

if (packageStat.size < 1_000) {
  throw new Error(
    "VSIX package is unexpectedly small.",
  );
}

if (packageStat.size > 10_000_000) {
  throw new Error(
    "VSIX package exceeds the 10 MB "
    + "release safety limit.",
  );
}

const listing = execFileSync(
  "unzip",
  [
    "-Z1",
    vsixPath,
  ],
  {
    cwd: root,
    encoding: "utf-8",
  },
)
  .split(/\r?\n/u)
  .map(
    (value) => value.trim(),
  )
  .filter(Boolean);

const normalized = listing.map(
  (value) => value.replaceAll("\\", "/"),
);

const normalizedLower = normalized.map(
  (value) => value.toLowerCase(),
);

const requiredFiles = [
  {
    label: "extension manifest",
    acceptedSuffixes: [
      "extension/package.json",
    ],
  },
  {
    label: "extension README",
    acceptedSuffixes: [
      "extension/readme.md",
    ],
  },
  {
    label: "extension license",
    acceptedSuffixes: [
      "extension/license",
      "extension/license.txt",
    ],
  },
  {
    label: "extension changelog",
    acceptedSuffixes: [
      "extension/changelog.md",
    ],
  },
  {
    label: "extension support guide",
    acceptedSuffixes: [
      "extension/support.md",
    ],
  },
  {
    label: "compiled extension entry point",
    acceptedSuffixes: [
      "extension/dist/extension.js",
    ],
  },
  {
    label: "compiled backend client",
    acceptedSuffixes: [
      "extension/dist/backendclient.js",
    ],
  },
  {
    label: "compiled workspace safety module",
    acceptedSuffixes: [
      "extension/dist/workspacesafety.js",
    ],
  },
];

for (const requirement of requiredFiles) {
  const found = requirement.acceptedSuffixes.some(
    (suffix) =>
      normalizedLower.some(
        (entry) => entry.endsWith(suffix),
      ),
  );

  if (!found) {
    throw new Error(
      "Required VSIX file is missing: "
      + requirement.label
      + " (accepted: "
      + requirement.acceptedSuffixes.join(", ")
      + ")",
    );
  }
}

const forbiddenSegments = [
  "/.git/",
  "/.vscode/",
  "/node_modules/",
  "/src/",
  "/test/",
  "/tests/",
  "/scripts/",
  "/backend/",
  "/.venv/",
  "/__pycache__/",
  "/.pytest_cache/",
];

const forbiddenNames = new Set([
  ".env",
  "credentials.json",
  "secrets.json",
]);

const forbiddenSuffixes = [
  ".pem",
  ".key",
  ".p12",
  ".pfx",
  ".map",
  ".ts",
  ".py",
  ".pyc",
  ".vsix",
];

for (const entry of normalized) {
  const surrounded = `/${entry}`;

  for (
    const segment
    of forbiddenSegments
  ) {
    if (surrounded.includes(segment)) {
      throw new Error(
        `Forbidden VSIX path: ${entry}`,
      );
    }
  }

  const name = basename(entry);

  if (forbiddenNames.has(name)) {
    throw new Error(
      `Sensitive VSIX file: ${entry}`,
    );
  }

  if (
    forbiddenSuffixes.some(
      (suffix) =>
        entry.toLowerCase()
          .endsWith(suffix),
    )
  ) {
    throw new Error(
      `Forbidden VSIX file type: ${entry}`,
    );
  }
}

const packageJsonCount = normalized.filter(
  (entry) =>
    entry.endsWith(
      "extension/package.json",
    ),
).length;

if (packageJsonCount !== 1) {
  throw new Error(
    "VSIX must contain exactly one "
    + "extension package.json.",
  );
}

console.log(
  "AEGIS VSIX VERIFICATION: PASS",
);
console.log(
  `Package: ${basename(vsixPath)}`,
);
console.log(
  `Size: ${packageStat.size} bytes`,
);
console.log(
  `Entries: ${normalized.length}`,
);
