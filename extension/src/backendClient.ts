const DEFAULT_MAX_REQUEST_BYTES =
  20 * 1024 * 1024;

const DEFAULT_MAX_RESPONSE_BYTES =
  10 * 1024 * 1024;

export type BackendRequestErrorKind =
  | "configuration"
  | "request_too_large"
  | "unavailable"
  | "timeout"
  | "http"
  | "response_too_large"
  | "invalid_json";

export class BackendRequestError
  extends Error {
  readonly kind: BackendRequestErrorKind;
  readonly status?: number;
  readonly backendUrl?: string;

  constructor(
    kind: BackendRequestErrorKind,
    message: string,
    options?: {
      status?: number;
      backendUrl?: string;
      cause?: unknown;
    },
  ) {
    super(
      message,
      options?.cause === undefined
        ? undefined
        : {
            cause: options.cause,
          },
    );

    this.name = "BackendRequestError";
    this.kind = kind;
    this.status = options?.status;
    this.backendUrl = options?.backendUrl;
  }
}

export interface PostBackendJsonOptions {
  backendUrl: string;
  endpoint: string;
  body: unknown;
  timeoutMilliseconds: number;
  timeoutMessage?: string;
  maxRequestBytes?: number;
  maxResponseBytes?: number;
}

export function normalizeBackendUrl(
  rawValue: string,
): string {
  const value = rawValue.trim();

  if (!value) {
    throw new BackendRequestError(
      "configuration",
      "Aegis backend URL is empty. Configure aegis.backendUrl and retry.",
    );
  }

  let parsed: URL;

  try {
    parsed = new URL(value);
  } catch (error: unknown) {
    throw new BackendRequestError(
      "configuration",
      `Aegis backend URL is invalid: ${value}`,
      {
        cause: error,
      },
    );
  }

  if (
    parsed.protocol !== "http:"
    && parsed.protocol !== "https:"
  ) {
    throw new BackendRequestError(
      "configuration",
      "Aegis backend URL must use http:// or https://.",
    );
  }

  if (
    parsed.username
    || parsed.password
  ) {
    throw new BackendRequestError(
      "configuration",
      "Aegis backend URL must not contain embedded credentials.",
    );
  }

  if (
    parsed.search
    || parsed.hash
  ) {
    throw new BackendRequestError(
      "configuration",
      "Aegis backend URL must not contain a query string or fragment.",
    );
  }

  parsed.pathname =
    parsed.pathname.replace(/\/+$/u, "");

  return parsed.toString().replace(/\/+$/u, "");
}

function validateEndpoint(
  endpoint: string,
): void {
  if (
    !endpoint.startsWith("/")
    || endpoint.startsWith("//")
  ) {
    throw new BackendRequestError(
      "configuration",
      `Invalid Aegis backend endpoint: ${endpoint}`,
    );
  }
}

function byteLength(
  value: string,
): number {
  return Buffer.byteLength(
    value,
    "utf-8",
  );
}

async function readLimitedText(
  response: Response,
  maxBytes: number,
  backendUrl: string,
): Promise<string> {
  const contentLength =
    response.headers.get(
      "content-length",
    );

  if (contentLength) {
    const declaredLength =
      Number.parseInt(
        contentLength,
        10,
      );

    if (
      Number.isFinite(declaredLength)
      && declaredLength > maxBytes
    ) {
      throw new BackendRequestError(
        "response_too_large",
        (
          "Aegis backend response exceeds "
          + `${maxBytes} bytes.`
        ),
        {
          backendUrl,
        },
      );
    }
  }

  if (!response.body) {
    return "";
  }

  const reader =
    response.body.getReader();

  const decoder =
    new TextDecoder();

  const chunks: string[] = [];
  let receivedBytes = 0;

  try {
    while (true) {
      const {
        done,
        value,
      } = await reader.read();

      if (done) {
        break;
      }

      receivedBytes +=
        value.byteLength;

      if (
        receivedBytes > maxBytes
      ) {
        await reader.cancel();

        throw new BackendRequestError(
          "response_too_large",
          (
            "Aegis backend response exceeds "
            + `${maxBytes} bytes.`
          ),
          {
            backendUrl,
          },
        );
      }

      chunks.push(
        decoder.decode(
          value,
          {
            stream: true,
          },
        ),
      );
    }

    chunks.push(decoder.decode());

    return chunks.join("");
  } finally {
    reader.releaseLock();
  }
}

function extractHttpDetail(
  rawBody: string,
): string {
  if (!rawBody.trim()) {
    return "The backend returned an empty error response.";
  }

  try {
    const payload =
      JSON.parse(rawBody) as unknown;

    if (
      typeof payload === "object"
      && payload !== null
      && !Array.isArray(payload)
      && "detail" in payload
    ) {
      const detail =
        (
          payload as {
            detail?: unknown;
          }
        ).detail;

      if (
        typeof detail === "string"
        && detail.trim()
      ) {
        return detail.trim();
      }

      if (
        detail !== undefined
      ) {
        return JSON.stringify(detail);
      }
    }
  } catch {
    // Preserve plain-text backend errors.
  }

  return rawBody.trim();
}

function parseJsonResponse<T>(
  rawBody: string,
  backendUrl: string,
): T {
  if (!rawBody.trim()) {
    throw new BackendRequestError(
      "invalid_json",
      "Aegis backend returned an empty response instead of JSON.",
      {
        backendUrl,
      },
    );
  }

  try {
    return JSON.parse(rawBody) as T;
  } catch (error: unknown) {
    throw new BackendRequestError(
      "invalid_json",
      "Aegis backend returned malformed JSON.",
      {
        backendUrl,
        cause: error,
      },
    );
  }
}

function isAbortError(
  error: unknown,
): boolean {
  return (
    error instanceof Error
    && error.name === "AbortError"
  );
}

export async function postBackendJson<T>(
  options: PostBackendJsonOptions,
): Promise<T> {
  const backendUrl =
    normalizeBackendUrl(
      options.backendUrl,
    );

  validateEndpoint(
    options.endpoint,
  );

  if (
    !Number.isFinite(
      options.timeoutMilliseconds,
    )
    || options.timeoutMilliseconds <= 0
  ) {
    throw new BackendRequestError(
      "configuration",
      "Aegis backend request timeout must be greater than zero.",
      {
        backendUrl,
      },
    );
  }

  const maxRequestBytes =
    options.maxRequestBytes
    ?? DEFAULT_MAX_REQUEST_BYTES;

  const maxResponseBytes =
    options.maxResponseBytes
    ?? DEFAULT_MAX_RESPONSE_BYTES;

  const requestBody =
    JSON.stringify(options.body);

  const requestBytes =
    byteLength(requestBody);

  if (
    requestBytes > maxRequestBytes
  ) {
    throw new BackendRequestError(
      "request_too_large",
      (
        "Aegis request payload exceeds "
        + `${maxRequestBytes} bytes.`
      ),
      {
        backendUrl,
      },
    );
  }

  const controller =
    new AbortController();

  const timeout = setTimeout(
    () => controller.abort(),
    options.timeoutMilliseconds,
  );

  const requestUrl =
    `${backendUrl}${options.endpoint}`;

  try {
    const response = await fetch(
      requestUrl,
      {
        method: "POST",
        headers: {
          "Content-Type":
            "application/json",
          Accept:
            "application/json",
        },
        body: requestBody,
        signal: controller.signal,
      },
    );

    const rawBody =
      await readLimitedText(
        response,
        maxResponseBytes,
        backendUrl,
      );

    if (!response.ok) {
      const detail =
        extractHttpDetail(rawBody);

      throw new BackendRequestError(
        "http",
        (
          `Aegis backend HTTP ${response.status}: `
          + detail
        ),
        {
          status: response.status,
          backendUrl,
        },
      );
    }

    return parseJsonResponse<T>(
      rawBody,
      backendUrl,
    );
  } catch (error: unknown) {
    if (
      error
      instanceof BackendRequestError
    ) {
      throw error;
    }

    if (isAbortError(error)) {
      const seconds =
        Math.round(
          options.timeoutMilliseconds
          / 1_000,
        );

      throw new BackendRequestError(
        "timeout",
        (
          options.timeoutMessage
          ?? (
            "Aegis backend request timed out "
            + `after ${seconds} seconds.`
          )
        ),
        {
          backendUrl,
          cause: error,
        },
      );
    }

    throw new BackendRequestError(
      "unavailable",
      (
        "Aegis backend is unavailable at "
        + `${backendUrl}. Start the local backend and retry.`
      ),
      {
        backendUrl,
        cause: error,
      },
    );
  } finally {
    clearTimeout(timeout);
  }
}
