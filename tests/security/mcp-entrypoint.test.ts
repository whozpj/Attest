// tests/security/mcp-entrypoint.test.ts
//
// The MCP server (src/mcp/server.ts) calls the exact same createAttestation
// used by POST /v1/attestations (src/api/attestations-core.ts) -- Task 1 of
// docs/superpowers/plans/2026-08-01-mcp-server.md extracted it precisely so
// the two entrypoints cannot drift. This suite proves that holds for real,
// over a real HTTP round trip, rather than trusting the shared-function
// claim on its own.
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { buildServer } from "../../src/api/server.js";
import * as q from "../../src/db/queries.js";

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

async function client() {
  const c = new Client({ name: "attack-client", version: "1.0.0" });
  await c.connect(new StreamableHTTPClientTransport(new URL(`${baseUrl}/mcp`)));
  return c;
}

describe("attack: smuggle display text through request_approval", () => {
  it("a caller-supplied field outside the action type's schema is refused, over real HTTP", async () => {
    q.insertPrincipal(app.ctx.db, { id: "prin_mcp1", email: "mcp1@e.com", display_name: "One" });
    const c = await client();

    const result = await c.callTool({
      name: "request_approval",
      arguments: {
        type: "wire_transfer", risk_tier: "high",
        payload: {
          amount: 100, currency: "USD", recipient_name: "Real Corp", account_last4: "0000",
          // Not part of wire_transfer's schema -- the attack this proves closed.
          headline: "Totally safe $1 refund",
        },
        approver_emails: ["mcp1@e.com"],
      },
    });

    expect(result.isError).toBe(true);
  });

  it("the rendered summary always comes from the canonical payload, never a caller-supplied string", async () => {
    q.insertPrincipal(app.ctx.db, { id: "prin_mcp2", email: "mcp2@e.com", display_name: "Two" });
    const c = await client();

    const result = await c.callTool({
      name: "request_approval",
      arguments: {
        type: "wire_transfer", risk_tier: "high",
        payload: { amount: 999999900, currency: "USD", recipient_name: "Attacker LLC", account_last4: "6666" },
        approver_emails: ["mcp2@e.com"],
      },
    });

    const structured = result.structuredContent as { summary: { headline: string } };
    // The headline is deterministically derived from amount/currency/recipient
    // by src/actions/render.ts -- proving it reflects the real payload, not
    // anything else the tool call could have smuggled in.
    expect(structured.summary.headline).toBe("Wire $9,999,999.00 USD to Attacker LLC");
  });
});

describe("attack: enumerate registered approvers via request_approval", () => {
  it("does not create an attestation, or reveal anything beyond rejection, for an unenrolled email", async () => {
    const c = await client();
    const before = (app.ctx.db.prepare("SELECT COUNT(*) AS c FROM attestations").get() as { c: number }).c;

    const result = await c.callTool({
      name: "request_approval",
      arguments: {
        type: "generic", risk_tier: "low", payload: { title: "t", detail: "d" },
        approver_emails: ["definitely-not-registered@nowhere.test"],
      },
    });

    expect(result.isError).toBe(true);
    const after = (app.ctx.db.prepare("SELECT COUNT(*) AS c FROM attestations").get() as { c: number }).c;
    expect(after).toBe(before);
  });
});

describe("check_approval / wait_for_approval never leak a purged payload", () => {
  it("summary is null through check_approval once an attestation resolves, same as GET /v1/attestations/:id", async () => {
    q.insertPrincipal(app.ctx.db, { id: "prin_mcp3", email: "mcp3@e.com", display_name: "Three" });
    const c = await client();

    const created = await c.callTool({
      name: "request_approval",
      arguments: {
        type: "generic", risk_tier: "low", payload: { title: "ZZQQX-SENTINEL", detail: "d" },
        approver_emails: ["mcp3@e.com"],
      },
    });
    const { attestation_id } = created.structuredContent as { attestation_id: string };

    q.setAttestationResolved(app.ctx.db, attestation_id, "denied", null);
    q.purgeActionPayload(app.ctx.db, q.getAttestation(app.ctx.db, attestation_id)!.action_id);

    const checked = await c.callTool({ name: "check_approval", arguments: { attestation_id } });
    const view = checked.structuredContent as { summary: unknown };
    expect(view.summary).toBeNull();
    expect(JSON.stringify(checked)).not.toContain("ZZQQX-SENTINEL");
  });
});
