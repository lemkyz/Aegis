import assert from "node:assert/strict";
import {
  mkdtemp,
  mkdir,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  containsBinaryMarker,
  createPayloadBudget,
  isIgnoredWorkspacePath,
  isPathInside,
  isSupportedSourcePath,
  normalizeWorkspaceRelativePath,
  readSafeWorkspaceFile,
} from "../dist/workspaceSafety.js";


test(
  "normalizes safe workspace paths",
  () => {
    assert.equal(
      normalizeWorkspaceRelativePath(
        "./src\\service.py",
      ),
      "src/service.py",
    );

    assert.equal(
      normalizeWorkspaceRelativePath(
        "src/index.ts",
      ),
      "src/index.ts",
    );
  },
);

test(
  "rejects path traversal and absolute paths",
  () => {
    for (const value of [
      "../secret.py",
      "src/../../secret.py",
      "/etc/passwd",
      "src//file.py",
      ".",
      "",
      "src/\0/file.py",
    ]) {
      assert.equal(
        normalizeWorkspaceRelativePath(
          value,
        ),
        undefined,
      );
    }
  },
);

test(
  "recognizes supported source extensions",
  () => {
    for (const value of [
      "app.py",
      "src/app.js",
      "src/app.jsx",
      "src/app.ts",
      "src/app.tsx",
    ]) {
      assert.equal(
        isSupportedSourcePath(value),
        true,
      );
    }

    for (const value of [
      "README.md",
      "image.png",
      "app.pyc",
      "archive.zip",
    ]) {
      assert.equal(
        isSupportedSourcePath(value),
        false,
      );
    }
  },
);

test(
  "recognizes ignored workspace directories",
  () => {
    for (const value of [
      "node_modules/pkg/index.js",
      ".git/hooks/test.py",
      ".venv/lib/module.py",
      "dist/index.js",
      "build/generated.ts",
      "target/generated.rs",
    ]) {
      assert.equal(
        isIgnoredWorkspacePath(value),
        true,
      );
    }

    assert.equal(
      isIgnoredWorkspacePath(
        "src/index.ts",
      ),
      false,
    );
  },
);

test(
  "checks whether a path remains inside its parent",
  () => {
    assert.equal(
      isPathInside(
        "/workspace/project",
        "/workspace/project/src/app.py",
      ),
      true,
    );

    assert.equal(
      isPathInside(
        "/workspace/project",
        "/workspace/project-two/app.py",
      ),
      false,
    );

    assert.equal(
      isPathInside(
        "/workspace/project",
        "/workspace/secret.py",
      ),
      false,
    );
  },
);

test(
  "detects a binary null marker",
  () => {
    assert.equal(
      containsBinaryMarker(
        Buffer.from(
          "safe source code",
          "utf-8",
        ),
      ),
      false,
    );

    assert.equal(
      containsBinaryMarker(
        Buffer.from([
          65,
          66,
          0,
          67,
        ]),
      ),
      true,
    );
  },
);

test(
  "enforces the cumulative payload budget",
  () => {
    const budget =
      createPayloadBudget(10);

    assert.equal(
      budget.canAdd(6),
      true,
    );

    budget.add(6);

    assert.equal(
      budget.usedBytes,
      6,
    );

    assert.equal(
      budget.remainingBytes,
      4,
    );

    assert.equal(
      budget.canAdd(5),
      false,
    );

    assert.throws(
      () => budget.add(5),
      /budget exceeded/iu,
    );
  },
);

test(
  "reads a safe source file",
  async () => {
    const root =
      await mkdtemp(
        path.join(
          os.tmpdir(),
          "aegis-workspace-",
        ),
      );

    try {
      const sourceDirectory =
        path.join(root, "src");

      await mkdir(
        sourceDirectory,
        {
          recursive: true,
        },
      );

      const sourcePath =
        path.join(
          sourceDirectory,
          "app.py",
        );

      await writeFile(
        sourcePath,
        "print('safe')\n",
        "utf-8",
      );

      const result =
        await readSafeWorkspaceFile(
          root,
          sourcePath,
          "src/app.py",
          1_000,
        );

      assert.equal(
        result.reason,
        undefined,
      );

      assert.equal(
        result.file?.relativePath,
        "src/app.py",
      );

      assert.equal(
        result.file?.content,
        "print('safe')\n",
      );
    } finally {
      await rm(
        root,
        {
          recursive: true,
          force: true,
        },
      );
    }
  },
);

test(
  "rejects oversized and binary source files",
  async () => {
    const root =
      await mkdtemp(
        path.join(
          os.tmpdir(),
          "aegis-workspace-",
        ),
      );

    try {
      const largePath =
        path.join(root, "large.py");

      await writeFile(
        largePath,
        "a".repeat(100),
        "utf-8",
      );

      const largeResult =
        await readSafeWorkspaceFile(
          root,
          largePath,
          "large.py",
          10,
        );

      assert.equal(
        largeResult.reason,
        "too_large",
      );

      const binaryPath =
        path.join(root, "binary.py");

      await writeFile(
        binaryPath,
        Buffer.from([
          65,
          0,
          66,
        ]),
      );

      const binaryResult =
        await readSafeWorkspaceFile(
          root,
          binaryPath,
          "binary.py",
          100,
        );

      assert.equal(
        binaryResult.reason,
        "binary",
      );
    } finally {
      await rm(
        root,
        {
          recursive: true,
          force: true,
        },
      );
    }
  },
);

test(
  "rejects a symbolic link escaping the workspace",
  async () => {
    const workspaceRoot =
      await mkdtemp(
        path.join(
          os.tmpdir(),
          "aegis-workspace-",
        ),
      );

    const externalRoot =
      await mkdtemp(
        path.join(
          os.tmpdir(),
          "aegis-external-",
        ),
      );

    try {
      const externalFile =
        path.join(
          externalRoot,
          "secret.py",
        );

      await writeFile(
        externalFile,
        "SECRET = 'outside'\n",
        "utf-8",
      );

      const linkPath =
        path.join(
          workspaceRoot,
          "linked.py",
        );

      await symlink(
        externalFile,
        linkPath,
      );

      const result =
        await readSafeWorkspaceFile(
          workspaceRoot,
          linkPath,
          "linked.py",
          1_000,
        );

      assert.equal(
        result.reason,
        "outside_workspace",
      );
    } finally {
      await rm(
        workspaceRoot,
        {
          recursive: true,
          force: true,
        },
      );

      await rm(
        externalRoot,
        {
          recursive: true,
          force: true,
        },
      );
    }
  },
);
