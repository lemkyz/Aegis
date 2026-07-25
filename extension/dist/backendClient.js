"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.BackendRequestError = void 0;
exports.normalizeBackendUrl = normalizeBackendUrl;
exports.postBackendJson = postBackendJson;
const DEFAULT_MAX_REQUEST_BYTES = 20 * 1024 * 1024;
const DEFAULT_MAX_RESPONSE_BYTES = 10 * 1024 * 1024;
class BackendRequestError extends Error {
    kind;
    status;
    backendUrl;
    constructor(kind, message, options) {
        super(message, options?.cause === undefined
            ? undefined
            : {
                cause: options.cause,
            });
        this.name = "BackendRequestError";
        this.kind = kind;
        this.status = options?.status;
        this.backendUrl = options?.backendUrl;
    }
}
exports.BackendRequestError = BackendRequestError;
function normalizeBackendUrl(rawValue) {
    const value = rawValue.trim();
    if (!value) {
        throw new BackendRequestError("configuration", "Aegis backend URL is empty. Configure aegis.backendUrl and retry.");
    }
    let parsed;
    try {
        parsed = new URL(value);
    }
    catch (error) {
        throw new BackendRequestError("configuration", `Aegis backend URL is invalid: ${value}`, {
            cause: error,
        });
    }
    if (parsed.protocol !== "http:"
        && parsed.protocol !== "https:") {
        throw new BackendRequestError("configuration", "Aegis backend URL must use http:// or https://.");
    }
    if (parsed.username
        || parsed.password) {
        throw new BackendRequestError("configuration", "Aegis backend URL must not contain embedded credentials.");
    }
    if (parsed.search
        || parsed.hash) {
        throw new BackendRequestError("configuration", "Aegis backend URL must not contain a query string or fragment.");
    }
    parsed.pathname =
        parsed.pathname.replace(/\/+$/u, "");
    return parsed.toString().replace(/\/+$/u, "");
}
function validateEndpoint(endpoint) {
    if (!endpoint.startsWith("/")
        || endpoint.startsWith("//")) {
        throw new BackendRequestError("configuration", `Invalid Aegis backend endpoint: ${endpoint}`);
    }
}
function byteLength(value) {
    return Buffer.byteLength(value, "utf-8");
}
async function readLimitedText(response, maxBytes, backendUrl) {
    const contentLength = response.headers.get("content-length");
    if (contentLength) {
        const declaredLength = Number.parseInt(contentLength, 10);
        if (Number.isFinite(declaredLength)
            && declaredLength > maxBytes) {
            throw new BackendRequestError("response_too_large", ("Aegis backend response exceeds "
                + `${maxBytes} bytes.`), {
                backendUrl,
            });
        }
    }
    if (!response.body) {
        return "";
    }
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    const chunks = [];
    let receivedBytes = 0;
    try {
        while (true) {
            const { done, value, } = await reader.read();
            if (done) {
                break;
            }
            receivedBytes +=
                value.byteLength;
            if (receivedBytes > maxBytes) {
                await reader.cancel();
                throw new BackendRequestError("response_too_large", ("Aegis backend response exceeds "
                    + `${maxBytes} bytes.`), {
                    backendUrl,
                });
            }
            chunks.push(decoder.decode(value, {
                stream: true,
            }));
        }
        chunks.push(decoder.decode());
        return chunks.join("");
    }
    finally {
        reader.releaseLock();
    }
}
function extractHttpDetail(rawBody) {
    if (!rawBody.trim()) {
        return "The backend returned an empty error response.";
    }
    try {
        const payload = JSON.parse(rawBody);
        if (typeof payload === "object"
            && payload !== null
            && !Array.isArray(payload)
            && "detail" in payload) {
            const detail = payload.detail;
            if (typeof detail === "string"
                && detail.trim()) {
                return detail.trim();
            }
            if (detail !== undefined) {
                return JSON.stringify(detail);
            }
        }
    }
    catch {
        // Preserve plain-text backend errors.
    }
    return rawBody.trim();
}
function parseJsonResponse(rawBody, backendUrl) {
    if (!rawBody.trim()) {
        throw new BackendRequestError("invalid_json", "Aegis backend returned an empty response instead of JSON.", {
            backendUrl,
        });
    }
    try {
        return JSON.parse(rawBody);
    }
    catch (error) {
        throw new BackendRequestError("invalid_json", "Aegis backend returned malformed JSON.", {
            backendUrl,
            cause: error,
        });
    }
}
function isAbortError(error) {
    return (error instanceof Error
        && error.name === "AbortError");
}
async function postBackendJson(options) {
    const backendUrl = normalizeBackendUrl(options.backendUrl);
    validateEndpoint(options.endpoint);
    if (!Number.isFinite(options.timeoutMilliseconds)
        || options.timeoutMilliseconds <= 0) {
        throw new BackendRequestError("configuration", "Aegis backend request timeout must be greater than zero.", {
            backendUrl,
        });
    }
    const maxRequestBytes = options.maxRequestBytes
        ?? DEFAULT_MAX_REQUEST_BYTES;
    const maxResponseBytes = options.maxResponseBytes
        ?? DEFAULT_MAX_RESPONSE_BYTES;
    const requestBody = JSON.stringify(options.body);
    const requestBytes = byteLength(requestBody);
    if (requestBytes > maxRequestBytes) {
        throw new BackendRequestError("request_too_large", ("Aegis request payload exceeds "
            + `${maxRequestBytes} bytes.`), {
            backendUrl,
        });
    }
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), options.timeoutMilliseconds);
    const requestUrl = `${backendUrl}${options.endpoint}`;
    try {
        const response = await fetch(requestUrl, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                Accept: "application/json",
            },
            body: requestBody,
            signal: controller.signal,
        });
        const rawBody = await readLimitedText(response, maxResponseBytes, backendUrl);
        if (!response.ok) {
            const detail = extractHttpDetail(rawBody);
            throw new BackendRequestError("http", (`Aegis backend HTTP ${response.status}: `
                + detail), {
                status: response.status,
                backendUrl,
            });
        }
        return parseJsonResponse(rawBody, backendUrl);
    }
    catch (error) {
        if (error
            instanceof BackendRequestError) {
            throw error;
        }
        if (isAbortError(error)) {
            const seconds = Math.round(options.timeoutMilliseconds
                / 1_000);
            throw new BackendRequestError("timeout", (options.timeoutMessage
                ?? ("Aegis backend request timed out "
                    + `after ${seconds} seconds.`)), {
                backendUrl,
                cause: error,
            });
        }
        throw new BackendRequestError("unavailable", ("Aegis backend is unavailable at "
            + `${backendUrl}. Start the local backend and retry.`), {
            backendUrl,
            cause: error,
        });
    }
    finally {
        clearTimeout(timeout);
    }
}
//# sourceMappingURL=backendClient.js.map