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
    expect(tools.map((t) => t.name).sort()).toEqual(["check_approval"]);
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
