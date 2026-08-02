// src/mcp/routes.error-handling.test.ts
//
// Review finding on Task 5: reply.hijack() takes the response fully off
// Fastify's plate, including on handler rejection -- server.ts's central
// setErrorHandler (the one place every other route's throw gets audited)
// never runs for a hijacked route. Confirmed real, not hypothetical: this is
// exactly how the shared-transport-reuse bug surfaced during Task 5's own
// verification (transport.handleRequest threw a real Error under a real
// condition). This file mocks the SDK's transport so handleRequest always
// throws, independent of that now-fixed bug, to prove the route's own
// catch block still produces an audited row and a real error response
// rather than a hung connection.
import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";

vi.mock("@modelcontextprotocol/sdk/server/streamableHttp.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@modelcontextprotocol/sdk/server/streamableHttp.js")>();
  class ThrowingTransport extends actual.StreamableHTTPServerTransport {
    async handleRequest(): Promise<void> {
      throw new Error("simulated transport failure");
    }
  }
  return { ...actual, StreamableHTTPServerTransport: ThrowingTransport };
});

const { buildServer } = await import("../api/server.js");
const q = await import("../db/queries.js");

let app: Awaited<ReturnType<typeof buildServer>>;
let baseUrl: string;

beforeAll(async () => {
  app = await buildServer({ dbPath: ":memory:", email: { async send() {} } });
  await app.listen({ port: 0, host: "127.0.0.1" });
  const address = app.server.address();
  const port = typeof address === "object" && address ? address.port : 0;
  baseUrl = `http://127.0.0.1:${port}`;
});

afterAll(async () => {
  await app.close();
});

describe("POST /mcp when the transport throws mid-request", () => {
  it("returns a real error response instead of hanging the connection", async () => {
    const res = await fetch(`${baseUrl}/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json, text/event-stream" },
      body: JSON.stringify({
        jsonrpc: "2.0", id: 1, method: "initialize",
        params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "probe", version: "1.0.0" } },
      }),
    });
    expect(res.status).toBe(500);
    expect(await res.json()).toEqual({ error: "internal_error" });
  });

  it("writes an audit_log row for the failed request", async () => {
    const rows = app.ctx.db
      .prepare("SELECT event, detail FROM audit_log WHERE event = 'mcp_request_failed'")
      .all() as { event: string; detail: string }[];
    expect(rows.length).toBeGreaterThan(0);
    expect(rows[0].detail).toContain("simulated transport failure");
  });
});
