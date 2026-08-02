// src/mcp/routes.disconnect.test.ts
//
// Review finding: wait_for_approval's poll loop had no way to notice a
// disconnected client (it didn't accept the SDK's `extra` param, so
// extra.signal was never consulted), leaving the server-side loop running
// real SQLite queries once a second for up to WAIT_MAX_SECONDS after the
// client walked away -- a cheap resource-exhaustion vector given /mcp has no
// caller auth. This proves the fix: aborting the client's transport (which
// closes the underlying HTTP connection, which routes.ts's own
// reply.raw "close" handler already reacts to) makes server-side polling
// against the real DB actually stop, instead of continuing for the rest of
// the timeout.
import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { buildServer } from "../api/server.js";
import * as q from "../db/queries.js";
import { createAttestation } from "../api/attestations-core.js";

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

describe("wait_for_approval stops polling once the client disconnects", () => {
  it("real SQLite polling activity stops shortly after the client's transport is aborted, instead of continuing until the timeout", async () => {
    q.insertPrincipal(app.ctx.db, { id: "prin_disc", email: "disc@e.com", display_name: "Disc" });
    const created = createAttestation(app.ctx.db, app.ctx.email, app.ctx.baseUrl, {
      requested_by: "agent-disc", approver_ids: ["prin_disc"],
      action: { type: "generic", risk_tier: "low", payload: { title: "t", detail: "d" } },
    });

    // getAttestationView reads the attestations table by id on every poll
    // (src/db/queries.ts's getAttestation); spying on db.prepare and
    // counting calls whose SQL matches that specific query gives a direct,
    // real signal of poll activity -- not a mock of the polling logic
    // itself, just an observation point on the real statement the real
    // loop issues against the real (in-process) SQLite connection.
    let pollCount = 0;
    const originalPrepare = app.ctx.db.prepare.bind(app.ctx.db);
    const prepareSpy = vi.spyOn(app.ctx.db, "prepare").mockImplementation((sql: string) => {
      if (sql.includes("FROM attestations WHERE id")) pollCount++;
      return originalPrepare(sql);
    });

    const client = new Client({ name: "disconnect-test", version: "1.0.0" });
    const transport = new StreamableHTTPClientTransport(new URL(`${baseUrl}/mcp`));
    await client.connect(transport);

    const callPromise = client.callTool({
      name: "wait_for_approval",
      arguments: { attestation_id: created.attestation_id, timeout_seconds: 8 },
    }).catch(() => {
      // Expected: closing the transport rejects the in-flight call locally.
    });

    // Let at least one real poll cycle happen before disconnecting.
    await new Promise((resolve) => setTimeout(resolve, 1500));
    expect(pollCount).toBeGreaterThan(0);

    // Aborts the transport's underlying fetch, which tears down the
    // connection carrying this request -- the same disconnect routes.ts's
    // reply.raw "close" handler reacts to for a real client walking away.
    await transport.close();
    await callPromise;

    // Give the server a moment to process the close event and abort the
    // in-flight tool handler via extra.signal. One poll cycle already
    // in flight when the abort lands is expected to still complete --
    // the loop only re-checks extra.signal.aborted once that setTimeout
    // resolves -- so this grace window needs to cover a full WAIT_POLL_MS
    // (1000ms), not just an instant.
    await new Promise((resolve) => setTimeout(resolve, 1300));
    const countAfterClose = pollCount;

    // Wait well past what would be at least two more 1s poll intervals if
    // the loop were still running unattended.
    await new Promise((resolve) => setTimeout(resolve, 2500));

    expect(pollCount).toBe(countAfterClose);

    prepareSpy.mockRestore();
  }, 10000);
});
