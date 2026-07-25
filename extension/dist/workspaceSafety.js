"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.MAX_MODEL_PAYLOAD_BYTES = exports.MAX_MODEL_FILE_BYTES = exports.MAX_WORKSPACE_FILE_BYTES = exports.MAX_MODEL_CONTEXT_FILES = exports.MAX_WORKSPACE_SCAN_FILES = exports.WORKSPACE_EXCLUDE_GLOB = exports.WORKSPACE_SOURCE_GLOB = void 0;
exports.normalizeWorkspaceRelativePath = normalizeWorkspaceRelativePath;
exports.isSupportedSourcePath = isSupportedSourcePath;
exports.isIgnoredWorkspacePath = isIgnoredWorkspacePath;
exports.isPathInside = isPathInside;
exports.containsBinaryMarker = containsBinaryMarker;
exports.createPayloadBudget = createPayloadBudget;
exports.readSafeWorkspaceFile = readSafeWorkspaceFile;
const promises_1 = require("node:fs/promises");
const path = __importStar(require("node:path"));
exports.WORKSPACE_SOURCE_GLOB = "**/*.{py,js,jsx,ts,tsx}";
exports.WORKSPACE_EXCLUDE_GLOB = "**/{.git,node_modules,.venv,venv,dist,build,out,coverage,__pycache__,.pytest_cache,.mypy_cache,.ruff_cache,.tox,.nox,target,vendor}/**";
exports.MAX_WORKSPACE_SCAN_FILES = 500;
exports.MAX_MODEL_CONTEXT_FILES = 300;
exports.MAX_WORKSPACE_FILE_BYTES = 1_000_000;
exports.MAX_MODEL_FILE_BYTES = 200_000;
exports.MAX_MODEL_PAYLOAD_BYTES = 10_000_000;
const supportedSourcePattern = /\.(py|js|jsx|ts|tsx)$/iu;
const ignoredPathSegments = new Set([
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
function normalizeWorkspaceRelativePath(relativePath) {
    const normalized = relativePath
        .replaceAll("\\", "/")
        .replace(/^\.\/+/u, "")
        .trim();
    if (!normalized
        || normalized.startsWith("/")
        || normalized.includes("\0")) {
        return undefined;
    }
    const segments = normalized.split("/");
    if (segments.some((segment) => !segment
        || segment === "."
        || segment === "..")) {
        return undefined;
    }
    return segments.join("/");
}
function isSupportedSourcePath(relativePath) {
    return supportedSourcePattern.test(relativePath);
}
function isIgnoredWorkspacePath(relativePath) {
    const normalized = normalizeWorkspaceRelativePath(relativePath);
    if (!normalized) {
        return true;
    }
    return normalized
        .split("/")
        .some((segment) => ignoredPathSegments.has(segment.toLowerCase()));
}
function isPathInside(parentPath, candidatePath) {
    const parent = path.resolve(parentPath);
    const candidate = path.resolve(candidatePath);
    const relative = path.relative(parent, candidate);
    return (relative === ""
        || (!relative.startsWith("..")
            && !path.isAbsolute(relative)));
}
function containsBinaryMarker(content) {
    const sample = content.subarray(0, Math.min(content.length, 8_192));
    return sample.includes(0);
}
function createPayloadBudget(maximumBytes) {
    if (!Number.isSafeInteger(maximumBytes)
        || maximumBytes <= 0) {
        throw new Error("Payload budget must be a positive safe integer.");
    }
    let usedBytes = 0;
    return {
        maximumBytes,
        get usedBytes() {
            return usedBytes;
        },
        get remainingBytes() {
            return maximumBytes - usedBytes;
        },
        canAdd(sizeBytes) {
            return (Number.isSafeInteger(sizeBytes)
                && sizeBytes >= 0
                && usedBytes + sizeBytes
                    <= maximumBytes);
        },
        add(sizeBytes) {
            if (!this.canAdd(sizeBytes)) {
                throw new Error("Workspace payload budget exceeded.");
            }
            usedBytes += sizeBytes;
        },
    };
}
async function readSafeWorkspaceFile(workspaceRoot, candidatePath, relativePath, maximumBytes) {
    const normalizedRelativePath = normalizeWorkspaceRelativePath(relativePath);
    if (!normalizedRelativePath) {
        return {
            reason: "invalid_relative_path",
            message: "The file has an unsafe workspace-relative path.",
        };
    }
    if (!isSupportedSourcePath(normalizedRelativePath)) {
        return {
            reason: "unsupported_extension",
            message: "The file extension is not supported.",
        };
    }
    if (isIgnoredWorkspacePath(normalizedRelativePath)) {
        return {
            reason: "ignored_path",
            message: "The file belongs to an ignored generated or dependency directory.",
        };
    }
    const resolvedWorkspaceRoot = path.resolve(workspaceRoot);
    const resolvedCandidate = path.resolve(candidatePath);
    if (!isPathInside(resolvedWorkspaceRoot, resolvedCandidate)) {
        return {
            reason: "outside_workspace",
            message: "The file path resolves outside the workspace.",
        };
    }
    let candidateMetadata;
    try {
        candidateMetadata =
            await (0, promises_1.lstat)(resolvedCandidate);
    }
    catch (error) {
        return {
            reason: "not_a_regular_file",
            message: error instanceof Error
                ? error.message
                : "The file could not be inspected.",
        };
    }
    if (!candidateMetadata.isFile()
        && !candidateMetadata.isSymbolicLink()) {
        return {
            reason: "not_a_regular_file",
            message: "The path is not a regular source file.",
        };
    }
    let realWorkspaceRoot;
    let realCandidatePath;
    try {
        [
            realWorkspaceRoot,
            realCandidatePath,
        ] = await Promise.all([
            (0, promises_1.realpath)(resolvedWorkspaceRoot),
            (0, promises_1.realpath)(resolvedCandidate),
        ]);
    }
    catch (error) {
        return {
            reason: "not_a_regular_file",
            message: error instanceof Error
                ? error.message
                : "The real file path could not be resolved.",
        };
    }
    if (!isPathInside(realWorkspaceRoot, realCandidatePath)) {
        return {
            reason: "outside_workspace",
            message: "The file or symbolic link resolves outside the workspace.",
        };
    }
    const metadataBeforeRead = await (0, promises_1.stat)(realCandidatePath);
    if (!metadataBeforeRead.isFile()) {
        return {
            reason: "not_a_regular_file",
            message: "The resolved path is not a regular file.",
        };
    }
    if (metadataBeforeRead.size
        > maximumBytes) {
        return {
            reason: "too_large",
            message: `The file exceeds ${maximumBytes} bytes.`,
        };
    }
    const contentBuffer = await (0, promises_1.readFile)(realCandidatePath);
    if (contentBuffer.length
        > maximumBytes) {
        return {
            reason: "too_large",
            message: `The file exceeds ${maximumBytes} bytes.`,
        };
    }
    if (containsBinaryMarker(contentBuffer)) {
        return {
            reason: "binary",
            message: "The file appears to contain binary data.",
        };
    }
    const metadataAfterRead = await (0, promises_1.stat)(realCandidatePath);
    if (metadataBeforeRead.size
        !== metadataAfterRead.size
        || metadataBeforeRead.mtimeMs
            !== metadataAfterRead.mtimeMs) {
        return {
            reason: "changed_during_read",
            message: "The file changed while Aegis was reading it.",
        };
    }
    const content = contentBuffer.toString("utf-8");
    if (!content.trim()) {
        return {
            reason: "empty",
            message: "The file contains no source code.",
        };
    }
    return {
        file: {
            absolutePath: resolvedCandidate,
            realPath: realCandidatePath,
            relativePath: normalizedRelativePath,
            content,
            sizeBytes: contentBuffer.length,
        },
    };
}
//# sourceMappingURL=workspaceSafety.js.map