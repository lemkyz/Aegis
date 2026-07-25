import assert from "node:assert/strict";
import http from "node:http";
import test from "node:test";

import {
  BackendRequestError,
  normalizeBackendUrl,
  postBackendJson,
} from "../dist/backendClient.js";

async function startServer(
  handler,
) {
  const server =
    http.createServer(handler);

  await new Promise(
    (resolve, reject) => {
      server.once(
        "error",
        reject,
      );

      server.listen(
        0,
        "127.0.0.1",
        resolve,
      );
    },
  );

  const address =
    server.address();

  if (
    !address
    || typeof address === "string"
  ) {
    throw new Error(
      "Test HTTP server has no TCP address.",
    );
  }

  return {
    server,
    url:
      `http://127.0.0.1:${address.port}`,
  };
}

async function closeServer(
  server,
) {
  if (
    typeof server.closeAllConnections
    === "function"
  ) {
    server.closeAllConnections();
  }

  await new Promise(
    (resolve) => {
      server.close(resolve);
    },
  );
}

test(
  "normalizes a backend URL",
  () => {
    assert.equal(
      normalizeBackendUrl(
        "  http://127.0.0.1:8000///  ",
      ),
      "http://127.0.0.1:8000",
    );

    assert.equal(
      normalizeBackendUrl(
        "https://example.test/aegis/",
      ),
      "https://example.test/aegis",
    );
  },
);

test(
  "rejects unsafe backend URL forms",
  () => {
    for (const value of [
      "",
      "not a URL",
      "file:///tmp/aegis",
      "ftp://example.test",
      "http://user:password@example.test",
      "http://example.test?token=value",
      "http://example.test/#fragment",
    ]) {
      assert.throws(
        () =>
          normalizeBackendUrl(value),
        BackendRequestError,
      );
    }
  },
);

test(
  "posts JSON and parses a successful response",
  async () => {
    const {
      server,
      url,
    } = await startServer(
      (request, response) => {
        let body = "";

        request.setEncoding(
          "utf-8",
        );

        request.on(
          "data",
          (chunk) => {
            body += chunk;
          },
        );

        request.on(
          "end",
          () => {
            const payload =
              JSON.parse(body);

            response.writeHead(
              200,
              {
                "Content-Type":
                  "application/json",
              },
            );

            response.end(
              JSON.stringify({
                received:
                  payload.value,
              }),
            );
          },
        );
      },
    );

    try {
      const result =
        await postBackendJson({
          backendUrl: `${url}/`,
          endpoint: "/v1/test",
          body: {
            value: "ok",
          },
          timeoutMilliseconds: 1_000,
        });

      assert.deepEqual(
        result,
        {
          received: "ok",
        },
      );
    } finally {
      await closeServer(server);
    }
  },
);

test(
  "extracts FastAPI detail from HTTP errors",
  async () => {
    const {
      server,
      url,
    } = await startServer(
      (_request, response) => {
        response.writeHead(
          422,
          {
            "Content-Type":
              "application/json",
          },
        );

        response.end(
          JSON.stringify({
            detail:
              "Invalid scan request.",
          }),
        );
      },
    );

    try {
      await assert.rejects(
        postBackendJson({
          backendUrl: url,
          endpoint: "/v1/test",
          body: {},
          timeoutMilliseconds: 1_000,
        }),
        (error) => {
          assert.ok(
            error
            instanceof BackendRequestError,
          );
          assert.equal(
            error.kind,
            "http",
          );
          assert.equal(
            error.status,
            422,
          );
          assert.match(
            error.message,
            /Invalid scan request/u,
          );
          return true;
        },
      );
    } finally {
      await closeServer(server);
    }
  },
);

test(
  "preserves plain-text HTTP errors",
  async () => {
    const {
      server,
      url,
    } = await startServer(
      (_request, response) => {
        response.writeHead(500);
        response.end(
          "backend exploded safely",
        );
      },
    );

    try {
      await assert.rejects(
        postBackendJson({
          backendUrl: url,
          endpoint: "/v1/test",
          body: {},
          timeoutMilliseconds: 1_000,
        }),
        /backend exploded safely/u,
      );
    } finally {
      await closeServer(server);
    }
  },
);

test(
  "rejects malformed JSON responses",
  async () => {
    const {
      server,
      url,
    } = await startServer(
      (_request, response) => {
        response.writeHead(
          200,
          {
            "Content-Type":
              "application/json",
          },
        );

        response.end(
          "{ definitely not json",
        );
      },
    );

    try {
      await assert.rejects(
        postBackendJson({
          backendUrl: url,
          endpoint: "/v1/test",
          body: {},
          timeoutMilliseconds: 1_000,
        }),
        (error) => {
          assert.ok(
            error
            instanceof BackendRequestError,
          );
          assert.equal(
            error.kind,
            "invalid_json",
          );
          return true;
        },
      );
    } finally {
      await closeServer(server);
    }
  },
);

test(
  "aborts a timed-out request",
  async () => {
    const {
      server,
      url,
    } = await startServer(
      (_request, response) => {
        setTimeout(
          () => {
            if (!response.destroyed) {
              response.writeHead(200);
              response.end("{}");
            }
          },
          200,
        );
      },
    );

    try {
      await assert.rejects(
        postBackendJson({
          backendUrl: url,
          endpoint: "/v1/test",
          body: {},
          timeoutMilliseconds: 20,
          timeoutMessage:
            "Aegis timeout fixture.",
        }),
        (error) => {
          assert.ok(
            error
            instanceof BackendRequestError,
          );
          assert.equal(
            error.kind,
            "timeout",
          );
          assert.equal(
            error.message,
            "Aegis timeout fixture.",
          );
          return true;
        },
      );
    } finally {
      await closeServer(server);
    }
  },
);

test(
  "rejects an oversized request before network I/O",
  async () => {
    await assert.rejects(
      postBackendJson({
        backendUrl:
          "http://127.0.0.1:8000",
        endpoint: "/v1/test",
        body: {
          value: "abcdef",
        },
        timeoutMilliseconds: 1_000,
        maxRequestBytes: 5,
      }),
      (error) => {
        assert.ok(
          error
          instanceof BackendRequestError,
        );
        assert.equal(
          error.kind,
          "request_too_large",
        );
        return true;
      },
    );
  },
);

test(
  "rejects an oversized backend response",
  async () => {
    const {
      server,
      url,
    } = await startServer(
      (_request, response) => {
        response.writeHead(
          200,
          {
            "Content-Type":
              "application/json",
          },
        );

        response.end(
          JSON.stringify({
            value:
              "response-is-too-large",
          }),
        );
      },
    );

    try {
      await assert.rejects(
        postBackendJson({
          backendUrl: url,
          endpoint: "/v1/test",
          body: {},
          timeoutMilliseconds: 1_000,
          maxResponseBytes: 5,
        }),
        (error) => {
          assert.ok(
            error
            instanceof BackendRequestError,
          );
          assert.equal(
            error.kind,
            "response_too_large",
          );
          return true;
        },
      );
    } finally {
      await closeServer(server);
    }
  },
);

test(
  "reports an unavailable backend clearly",
  async () => {
    const {
      server,
      url,
    } = await startServer(
      (_request, response) => {
        response.end("{}");
      },
    );

    await closeServer(server);

    await assert.rejects(
      postBackendJson({
        backendUrl: url,
        endpoint: "/v1/test",
        body: {},
        timeoutMilliseconds: 500,
      }),
      (error) => {
        assert.ok(
          error
          instanceof BackendRequestError,
        );
        assert.equal(
          error.kind,
          "unavailable",
        );
        assert.match(
          error.message,
          /Aegis backend is unavailable/u,
        );
        assert.match(
          error.message,
          /Start the local backend and retry/u,
        );
        return true;
      },
    );
  },
);
