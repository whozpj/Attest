import { describe, it, expect, beforeEach } from "vitest";
import { openDb, type Database } from "../db/index.js";
import * as q from "../db/queries.js";
import { emailApprovers } from "./notify.js";
import type { EmailMessage, EmailTransport } from "../email/index.js";

function recorder(): EmailTransport & { sent: EmailMessage[] } {
  const sent: EmailMessage[] = [];
  return { sent, async send(msg) { sent.push(msg); } };
}

function seed(db: Database) {
  q.insertPrincipal(db, { id: "prin_1", email: "one@e.com", display_name: "One" });
  q.insertPrincipal(db, { id: "prin_2", email: "two@e.com", display_name: "Two" });
  q.insertAction(db, {
    id: "act_1", requested_by: "agent-7", type: "wire_transfer",
    canonical_json: '{"amount":2500000}', payload_hash: "sha256:abc", risk_tier: "high",
  });
  q.insertAttestation(db, {
    id: "att_1", action_id: "act_1", required_approvals: 2,
    approver_ids: ["prin_1", "prin_2"], expires_at: new Date(Date.now() + 60_000).toISOString(),
  });
}

const summary = { headline: "Wire $25,000.00 USD to Acme Corp", fields: [{ label: "Amount", value: "$25,000.00 USD" }] };

describe("emailApprovers", () => {
  let db: Database;
  beforeEach(() => { db = openDb(":memory:"); seed(db); });

  it("mails every approver a link unique to them", async () => {
    const t = recorder();
    await emailApprovers(db, t, {
      attestation_id: "att_1", approverIds: ["prin_1", "prin_2"], summary,
      requestedBy: "agent-7", expiresAt: "2026-08-01T12:00:00.000Z",
      baseUrl: "http://localhost:3000",
    });

    expect(t.sent.map((m) => m.to).sort()).toEqual(["one@e.com", "two@e.com"]);
    const tokens = t.sent.map((m) => m.text.match(/\/a\/([A-Za-z0-9_-]+)/)![1]);
    expect(new Set(tokens).size).toBe(2);
    expect(q.getApprovalLink(db, tokens[0])!.principal_id).toBeTruthy();
  });

  it("persists one approval_links row per approver", async () => {
    await emailApprovers(db, recorder(), {
      attestation_id: "att_1", approverIds: ["prin_1", "prin_2"], summary,
      requestedBy: "agent-7", expiresAt: "x", baseUrl: "http://localhost:3000",
    });
    expect(q.getApprovalLinkFor(db, "att_1", "prin_1")).toBeDefined();
    expect(q.getApprovalLinkFor(db, "att_1", "prin_2")).toBeDefined();
  });

  it("never throws when the transport fails, and audits the failure", async () => {
    const failing: EmailTransport = { async send() { throw new Error("smtp down"); } };
    await expect(emailApprovers(db, failing, {
      attestation_id: "att_1", approverIds: ["prin_1"], summary,
      requestedBy: "agent-7", expiresAt: "x", baseUrl: "http://localhost:3000",
    })).resolves.toBeUndefined();

    const events = q.getAuditFor(db, "att_1").map((r) => r.event);
    expect(events).toContain("email_failed");
  });

  it("keeps mailing the remaining approvers after one fails", async () => {
    let calls = 0;
    const flaky: EmailTransport = {
      async send() { calls += 1; if (calls === 1) throw new Error("first fails"); },
    };
    await emailApprovers(db, flaky, {
      attestation_id: "att_1", approverIds: ["prin_1", "prin_2"], summary,
      requestedBy: "agent-7", expiresAt: "x", baseUrl: "http://localhost:3000",
    });
    expect(calls).toBe(2);
  });

  it("skips an approver id that is not a real principal without throwing", async () => {
    const t = recorder();
    await emailApprovers(db, t, {
      attestation_id: "att_1", approverIds: ["prin_ghost"], summary,
      requestedBy: "agent-7", expiresAt: "x", baseUrl: "http://localhost:3000",
    });
    expect(t.sent).toHaveLength(0);
  });

  it("audits a successful send", async () => {
    await emailApprovers(db, recorder(), {
      attestation_id: "att_1", approverIds: ["prin_1"], summary,
      requestedBy: "agent-7", expiresAt: "x", baseUrl: "http://localhost:3000",
    });
    expect(q.getAuditFor(db, "att_1").map((r) => r.event)).toContain("email_sent");
  });
});
