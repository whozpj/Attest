import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { buildServer } from "../api/server.js";
import * as q from "../db/queries.js";

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

async function connectRealClient() {
  const client = new Client({ name: "test-client", version: "1.0.0" });
  const transport = new StreamableHTTPClientTransport(new URL(`${baseUrl}/mcp`));
  await client.connect(transport);
  return client;
}

describe("POST /mcp over a real HTTP server", () => {
  it("lists the four tools through a real Streamable HTTP round trip", async () => {
    const client = await connectRealClient();
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual(
      ["check_approval", "consume_approval", "request_approval", "wait_for_approval"].sort(),
    );
  });

  it("calling request_approval over real HTTP actually creates a real attestation", async () => {
    q.insertPrincipal(app.ctx.db, { id: "prin_http", email: "http@e.com", display_name: "Http" });
    const client = await connectRealClient();
    const result = await client.callTool({
      name: "request_approval",
      arguments: {
        type: "generic", risk_tier: "low", payload: { title: "t", detail: "d" },
        approver_emails: ["http@e.com"],
      },
    });
    const structured = result.structuredContent as { attestation_id: string };
    expect(q.getAttestation(app.ctx.db, structured.attestation_id)).toBeDefined();
  });
});

describe("GET /mcp", () => {
  it("returns 405, since this server runs stateless with no SSE stream to attach to", async () => {
    const res = await fetch(`${baseUrl}/mcp`, { headers: { accept: "text/event-stream" } });
    expect(res.status).toBe(405);
  });
});
