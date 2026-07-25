import {
  lstat,
  readFile,
  realpath,
  stat,
} from "node:fs/promises";
import * as path from "node:path";


export const WORKSPACE_SOURCE_GLOB =
  "**/*.{py,js,jsx,ts,tsx}";

export const WORKSPACE_EXCLUDE_GLOB =
  "**/{.git,node_modules,.venv,venv,dist,build,out,coverage,__pycache__,.pytest_cache,.mypy_cache,.ruff_cache,.tox,.nox,target,vendor}/**";

export const MAX_WORKSPACE_SCAN_FILES =
  500;

export const MAX_MODEL_CONTEXT_FILES =
  300;

export const MAX_WORKSPACE_FILE_BYTES =
  1_000_000;

export const MAX_MODEL_FILE_BYTES =
  200_000;

export const MAX_MODEL_PAYLOAD_BYTES =
  10_000_000;

const supportedSourcePattern =
  /\.(py|js|jsx|ts|tsx)$/iu;

const ignoredPathSegments =
  new Set([
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "dist",
    "build",
    "out",
    "coverage",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
    ".nox",
    "target",
    "vendor",
  ]);

export type WorkspaceFileSkipReason =
  | "unsupported_uri"
  | "invalid_relative_path"
  | "unsupported_extension"
  | "ignored_path"
  | "not_a_regular_file"
  | "outside_workspace"
  | "too_large"
  | "binary"
  | "empty"
  | "changed_during_read";

export interface SafeWorkspaceFile {
  absolutePath: string;
  realPath: string;
  relativePath: string;
  content: string;
  sizeBytes: number;
}

export interface SafeWorkspaceFileResult {
  file?: SafeWorkspaceFile;
  reason?: WorkspaceFileSkipReason;
  message?: string;
}

export interface PayloadBudget {
  readonly maximumBytes: number;
  readonly usedBytes: number;
  readonly remainingBytes: number;
  canAdd(sizeBytes: number): boolean;
  add(sizeBytes: number): void;
}

export function normalizeWorkspaceRelativePath(
  relativePath: string,
): string | undefined {
  const normalized =
    relativePath
      .replaceAll("\\", "/")
      .replace(/^\.\/+/u, "")
      .trim();

  if (
    !normalized
    || normalized.startsWith("/")
    || normalized.includes("\0")
  ) {
    return undefined;
  }

  const segments =
    normalized.split("/");

  if (
    segments.some(
      (segment) =>
        !segment
        || segment === "."
        || segment === "..",
    )
  ) {
    return undefined;
  }

  return segments.join("/");
}

export function isSupportedSourcePath(
  relativePath: string,
): boolean {
  return supportedSourcePattern.test(
    relativePath,
  );
}

export function isIgnoredWorkspacePath(
  relativePath: string,
): boolean {
  const normalized =
    normalizeWorkspaceRelativePath(
      relativePath,
    );

  if (!normalized) {
    return true;
  }

  return normalized
    .split("/")
    .some(
      (segment) =>
        ignoredPathSegments.has(
          segment.toLowerCase(),
        ),
    );
}

export function isPathInside(
  parentPath: string,
  candidatePath: string,
): boolean {
  const parent =
    path.resolve(parentPath);

  const candidate =
    path.resolve(candidatePath);

  const relative =
    path.relative(
      parent,
      candidate,
    );

  return (
    relative === ""
    || (
      !relative.startsWith("..")
      && !path.isAbsolute(relative)
    )
  );
}

export function containsBinaryMarker(
  content: Buffer,
): boolean {
  const sample =
    content.subarray(
      0,
      Math.min(
        content.length,
        8_192,
      ),
    );

  return sample.includes(0);
}

export function createPayloadBudget(
  maximumBytes: number,
): PayloadBudget {
  if (
    !Number.isSafeInteger(maximumBytes)
    || maximumBytes <= 0
  ) {
    throw new Error(
      "Payload budget must be a positive safe integer.",
    );
  }

  let usedBytes = 0;

  return {
    maximumBytes,

    get usedBytes(): number {
      return usedBytes;
    },

    get remainingBytes(): number {
      return maximumBytes - usedBytes;
    },

    canAdd(sizeBytes: number): boolean {
      return (
        Number.isSafeInteger(sizeBytes)
        && sizeBytes >= 0
        && usedBytes + sizeBytes
          <= maximumBytes
      );
    },

    add(sizeBytes: number): void {
      if (!this.canAdd(sizeBytes)) {
        throw new Error(
          "Workspace payload budget exceeded.",
        );
      }

      usedBytes += sizeBytes;
    },
  };
}

export async function readSafeWorkspaceFile(
  workspaceRoot: string,
  candidatePath: string,
  relativePath: string,
  maximumBytes: number,
): Promise<SafeWorkspaceFileResult> {
  const normalizedRelativePath =
    normalizeWorkspaceRelativePath(
      relativePath,
    );

  if (!normalizedRelativePath) {
    return {
      reason: "invalid_relative_path",
      message:
        "The file has an unsafe workspace-relative path.",
    };
  }

  if (
    !isSupportedSourcePath(
      normalizedRelativePath,
    )
  ) {
    return {
      reason: "unsupported_extension",
      message:
        "The file extension is not supported.",
    };
  }

  if (
    isIgnoredWorkspacePath(
      normalizedRelativePath,
    )
  ) {
    return {
      reason: "ignored_path",
      message:
        "The file belongs to an ignored generated or dependency directory.",
    };
  }

  const resolvedWorkspaceRoot =
    path.resolve(workspaceRoot);

  const resolvedCandidate =
    path.resolve(candidatePath);

  if (
    !isPathInside(
      resolvedWorkspaceRoot,
      resolvedCandidate,
    )
  ) {
    return {
      reason: "outside_workspace",
      message:
        "The file path resolves outside the workspace.",
    };
  }

  let candidateMetadata;

  try {
    candidateMetadata =
      await lstat(resolvedCandidate);
  } catch (error: unknown) {
    return {
      reason: "not_a_regular_file",
      message:
        error instanceof Error
          ? error.message
          : "The file could not be inspected.",
    };
  }

  if (
    !candidateMetadata.isFile()
    && !candidateMetadata.isSymbolicLink()
  ) {
    return {
      reason: "not_a_regular_file",
      message:
        "The path is not a regular source file.",
    };
  }

  let realWorkspaceRoot: string;
  let realCandidatePath: string;

  try {
    [
      realWorkspaceRoot,
      realCandidatePath,
    ] = await Promise.all([
      realpath(resolvedWorkspaceRoot),
      realpath(resolvedCandidate),
    ]);
  } catch (error: unknown) {
    return {
      reason: "not_a_regular_file",
      message:
        error instanceof Error
          ? error.message
          : "The real file path could not be resolved.",
    };
  }

  if (
    !isPathInside(
      realWorkspaceRoot,
      realCandidatePath,
    )
  ) {
    return {
      reason: "outside_workspace",
      message:
        "The file or symbolic link resolves outside the workspace.",
    };
  }

  const metadataBeforeRead =
    await stat(realCandidatePath);

  if (!metadataBeforeRead.isFile()) {
    return {
      reason: "not_a_regular_file",
      message:
        "The resolved path is not a regular file.",
    };
  }

  if (
    metadataBeforeRead.size
    > maximumBytes
  ) {
    return {
      reason: "too_large",
      message:
        `The file exceeds ${maximumBytes} bytes.`,
    };
  }

  const contentBuffer =
    await readFile(realCandidatePath);

  if (
    contentBuffer.length
    > maximumBytes
  ) {
    return {
      reason: "too_large",
      message:
        `The file exceeds ${maximumBytes} bytes.`,
    };
  }

  if (
    containsBinaryMarker(
      contentBuffer,
    )
  ) {
    return {
      reason: "binary",
      message:
        "The file appears to contain binary data.",
    };
  }

  const metadataAfterRead =
    await stat(realCandidatePath);

  if (
    metadataBeforeRead.size
      !== metadataAfterRead.size
    || metadataBeforeRead.mtimeMs
      !== metadataAfterRead.mtimeMs
  ) {
    return {
      reason: "changed_during_read",
      message:
        "The file changed while Aegis was reading it.",
    };
  }

  const content =
    contentBuffer.toString("utf-8");

  if (!content.trim()) {
    return {
      reason: "empty",
      message:
        "The file contains no source code.",
    };
  }

  return {
    file: {
      absolutePath:
        resolvedCandidate,
      realPath:
        realCandidatePath,
      relativePath:
        normalizedRelativePath,
      content,
      sizeBytes:
        contentBuffer.length,
    },
  };
}
