import { describe, it, expect, beforeEach } from "vitest";
import { openDb, type Database } from "../db/index.js";
import * as q from "../db/queries.js";
import { createAttestation, getAttestationView } from "./attestations-core.js";
import { FailClosedError } from "../types.js";
import type { EmailTransport, EmailMessage } from "../email/index.js";

function recorder(): EmailTransport & { sent: EmailMessage[] } {
  const sent: EmailMessage[] = [];
  return { sent, async send(msg) { sent.push(msg); } };
}

const wireInput = {
  requested_by: "agent-7",
  approver_ids: ["prin_1"],
  required_approvals: 1,
  action: {
    type: "wire_transfer", risk_tier: "high",
    payload: { amount: 2500000, currency: "USD", recipient_name: "Acme Corp", account_last4: "4821" },
  },
};

describe("createAttestation", () => {
  let db: Database;
  beforeEach(() => {
    db = openDb(":memory:");
    q.insertPrincipal(db, { id: "prin_1", email: "one@e.com", display_name: "One" });
  });

  it("creates a pending attestation with the rendered summary and approve_url", () => {
    const result = createAttestation(db, recorder(), "http://localhost:3000", wireInput);
    expect(result.status).toBe("pending");
    expect(result.summary.headline).toBe("Wire $25,000.00 USD to Acme Corp");
    expect(result.approve_url).toBe(`http://localhost:3000/requests/${result.attestation_id}`);
    expect(result.payload_hash).toMatch(/^sha256:/);
  });

  it("persists the attestation so it can be read back", () => {
    const result = createAttestation(db, recorder(), "http://localhost:3000", wireInput);
    const att = q.getAttestation(db, result.attestation_id);
    expect(att?.status).toBe("pending");
    expect(att?.approver_ids).toEqual(["prin_1"]);
  });

  it("emails every approver", async () => {
    const t = recorder();
    createAttestation(db, t, "http://localhost:3000", wireInput);
    await new Promise((r) => setTimeout(r, 20)); // emailApprovers is fire-and-forget
    expect(t.sent).toHaveLength(1);
    expect(t.sent[0].to).toBe("one@e.com");
  });

  it("throws FailClosedError for an invalid action, and creates nothing", () => {
    expect(() =>
      createAttestation(db, recorder(), "http://localhost:3000", {
        ...wireInput, action: { type: "wire_transfer", risk_tier: "high", payload: { amount: "not-a-number" } },
      }),
    ).toThrow(FailClosedError);
    expect(db.prepare("SELECT COUNT(*) AS c FROM attestations").get()).toEqual({ c: 0 });
  });
});

describe("getAttestationView", () => {
  let db: Database;
  beforeEach(() => {
    db = openDb(":memory:");
    q.insertPrincipal(db, { id: "prin_1", email: "one@e.com", display_name: "One" });
  });

  it("returns the pending view with a non-null summary", () => {
    const created = createAttestation(db, recorder(), "http://localhost:3000", wireInput);
    const view = getAttestationView(db, created.attestation_id);
    expect(view.status).toBe("pending");
    expect(view.summary?.headline).toBe("Wire $25,000.00 USD to Acme Corp");
    expect(view.token).toBeNull();
  });

  it("throws unknown_attestation for a nonexistent id", () => {
    expect(() => getAttestationView(db, "att_nope")).toThrow(FailClosedError);
    try {
      getAttestationView(db, "att_nope");
    } catch (err) {
      expect((err as FailClosedError).code).toBe("unknown_attestation");
    }
  });
});
