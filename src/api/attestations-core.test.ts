import { describe, it, expect, beforeEach, beforeAll } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openDb, type Database } from "../db/index.js";
import * as q from "../db/queries.js";
import { createAttestation, getAttestationView, verifyAndConsumeAttestation } from "./attestations-core.js";
import { loadOrCreateKeypair, signAttestation, publicJwks, type Keypair } from "../crypto/tokens.js";
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

describe("verifyAndConsumeAttestation", () => {
  let db: Database;
  let kp: Keypair;

  beforeAll(async () => {
    kp = await loadOrCreateKeypair(mkdtempSync(join(tmpdir(), "ha-verify-")));
  });

  beforeEach(async () => {
    db = openDb(":memory:");
    q.insertPrincipal(db, { id: "prin_1", email: "one@e.com", display_name: "One" });
  });

  async function approvedToken() {
    const created = createAttestation(db, recorder(), "http://localhost:3000", wireInput);
    const token = await signAttestation(kp, {
      jti: created.attestation_id, sub: "prin_1", act: created.payload_hash,
      approvers: ["prin_1"], mth: "passkey",
    }, 300);
    q.setAttestationResolved(db, created.attestation_id, "approved", token);
    return { attestationId: created.attestation_id, token };
  }

  it("consumes a valid token on the first call", async () => {
    const { token } = await approvedToken();
    const result = await verifyAndConsumeAttestation(db, await publicJwks(kp), token);
    expect(result.valid).toBe(true);
  });

  it("rejects a second call on the same token as already_consumed", async () => {
    const { token } = await approvedToken();
    await verifyAndConsumeAttestation(db, await publicJwks(kp), token);
    const second = await verifyAndConsumeAttestation(db, await publicJwks(kp), token);
    expect(second.valid).toBe(false);
    expect(second.reason).toBe("already_consumed");
  });

  it("audits the already_consumed rejection", async () => {
    const { attestationId, token } = await approvedToken();
    await verifyAndConsumeAttestation(db, await publicJwks(kp), token);
    await verifyAndConsumeAttestation(db, await publicJwks(kp), token);
    const rows = db.prepare(
      `SELECT * FROM audit_log WHERE attestation_id = ? AND event = 'token_already_consumed'`,
    ).all(attestationId);
    expect(rows).toHaveLength(1);
  });

  it("leaves an invalid token's response untouched, without auditing anything", async () => {
    const result = await verifyAndConsumeAttestation(db, await publicJwks(kp), "not-a-jwt");
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("signature_invalid");
    // A garbage token never reaches consumeAttestationToken at all (there's
    // no attestation_id to consume against), so nothing gets written here --
    // unlike the already_consumed case below, which does write a row.
    expect(db.prepare("SELECT COUNT(*) AS c FROM audit_log").get()).toEqual({ c: 0 });
  });

  it("exactly one of two racing calls on the same token wins", async () => {
    const { token } = await approvedToken();
    const jwks = await publicJwks(kp);
    const [a, b] = await Promise.all([
      verifyAndConsumeAttestation(db, jwks, token),
      verifyAndConsumeAttestation(db, jwks, token),
    ]);
    const validCount = [a, b].filter((r) => r.valid).length;
    expect(validCount).toBe(1);
  });
});
