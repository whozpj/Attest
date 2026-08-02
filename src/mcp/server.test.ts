import { describe, it, expect, beforeEach } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { openDb, type Database } from "../db/index.js";
import * as q from "../db/queries.js";
import { createAttestation } from "../api/attestations-core.js";
import { buildMcpServer } from "./server.js";
import type { EmailTransport } from "../email/index.js";

const noopEmail: EmailTransport = { async send() {} };

async function connectedClient(db: Database) {
  const server = buildMcpServer({ db, email: noopEmail, baseUrl: "http://localhost:3000" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test-client", version: "1.0.0" });
  await Promise.all([
    client.connect(clientTransport),
    server.connect(serverTransport),
  ]);
  return client;
}

describe("MCP server: tools/list", () => {
  it("advertises exactly the three tools this plan builds", async () => {
    const db = openDb(":memory:");
    const client = await connectedClient(db);
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual(["check_approval", "request_approval"]);
  });
});

describe("check_approval tool", () => {
  let db: Database;
  beforeEach(() => {
    db = openDb(":memory:");
    q.insertPrincipal(db, { id: "prin_1", email: "one@e.com", display_name: "One" });
  });

  it("returns the pending status and summary for a real attestation", async () => {
    const created = createAttestation(db, noopEmail, "http://localhost:3000", {
      requested_by: "agent-7", approver_ids: ["prin_1"], required_approvals: 1,
      action: {
        type: "wire_transfer", risk_tier: "high",
        payload: { amount: 2500000, currency: "USD", recipient_name: "Acme Corp", account_last4: "4821" },
      },
    });

    const client = await connectedClient(db);
    const result = await client.callTool({
      name: "check_approval",
      arguments: { attestation_id: created.attestation_id },
    });

    expect(result.isError).not.toBe(true);
    const structured = result.structuredContent as { status: string; token: string | null };
    expect(structured.status).toBe("pending");
    expect(structured.token).toBeNull();
  });

  it("returns a tool error, not a thrown exception, for an unknown attestation id", async () => {
    const client = await connectedClient(db);
    const result = await client.callTool({
      name: "check_approval",
      arguments: { attestation_id: "att_does_not_exist" },
    });
    expect(result.isError).toBe(true);
  });
});

describe("request_approval tool", () => {
  let db: Database;
  beforeEach(() => {
    db = openDb(":memory:");
    q.insertPrincipal(db, { id: "prin_1", email: "approver@e.com", display_name: "Approver" });
  });

  it("creates a real, pending attestation and returns its summary", async () => {
    const client = await connectedClient(db);
    const result = await client.callTool({
      name: "request_approval",
      arguments: {
        type: "wire_transfer", risk_tier: "high",
        payload: { amount: 2500000, currency: "USD", recipient_name: "Acme Corp", account_last4: "4821" },
        approver_emails: ["approver@e.com"],
      },
    });

    expect(result.isError).not.toBe(true);
    const structured = result.structuredContent as { attestation_id: string; status: string; summary: { headline: string } };
    expect(structured.status).toBe("pending");
    expect(structured.summary.headline).toBe("Wire $25,000.00 USD to Acme Corp");

    const att = q.getAttestation(db, structured.attestation_id);
    expect(att?.approver_ids).toEqual(["prin_1"]);
  });

  it("rejects closed, and creates nothing, when an approver email is not enrolled", async () => {
    const client = await connectedClient(db);
    const result = await client.callTool({
      name: "request_approval",
      arguments: {
        type: "generic", risk_tier: "low", payload: { title: "t", detail: "d" },
        approver_emails: ["nobody@e.com"],
      },
    });

    expect(result.isError).toBe(true);
    expect(db.prepare("SELECT COUNT(*) AS c FROM attestations").get()).toEqual({ c: 0 });
  });

  it("does not accept a caller-supplied display field outside the closed-world action schema", async () => {
    const client = await connectedClient(db);
    const result = await client.callTool({
      name: "request_approval",
      arguments: {
        type: "generic", risk_tier: "low",
        payload: { title: "t", detail: "d", headline: "SPOOFED DISPLAY TEXT" },
        approver_emails: ["approver@e.com"],
      },
    });
    // validateAction's closed-world check refuses any field outside the
    // type's schema -- "generic" only allows title/detail. This is the same
    // guarantee POST /v1/attestations already has; this test proves the MCP
    // entrypoint didn't quietly bypass it.
    expect(result.isError).toBe(true);
  });

  it("defaults requested_by to the connecting client's declared name", async () => {
    const server = buildMcpServer({ db, email: noopEmail, baseUrl: "http://localhost:3000" });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: "langgraph", version: "9.9.9" });
    await Promise.all([client.connect(clientTransport), server.connect(serverTransport)]);

    const result = await client.callTool({
      name: "request_approval",
      arguments: {
        type: "generic", risk_tier: "low", payload: { title: "t", detail: "d" },
        approver_emails: ["approver@e.com"],
      },
    });
    const structured = result.structuredContent as { attestation_id: string };
    const action = q.getAction(db, q.getAttestation(db, structured.attestation_id)!.action_id);
    expect(action?.requested_by).toBe("langgraph");
  });

  it("an explicit requested_by overrides the client's declared name", async () => {
    const client = await connectedClient(db);
    const result = await client.callTool({
      name: "request_approval",
      arguments: {
        type: "generic", risk_tier: "low", payload: { title: "t", detail: "d" },
        approver_emails: ["approver@e.com"], requested_by: "nightly-deploy-bot",
      },
    });
    const structured = result.structuredContent as { attestation_id: string };
    const action = q.getAction(db, q.getAttestation(db, structured.attestation_id)!.action_id);
    expect(action?.requested_by).toBe("nightly-deploy-bot");
  });
});
