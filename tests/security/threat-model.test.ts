// tests/security/threat-model.test.ts
import { describe, it, expect, beforeEach } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openDb } from "../../src/db/index.js";
import * as q from "../../src/db/queries.js";
import { prepareAction } from "../../src/actions/render.js";
import { challengeFor } from "../../src/webauthn/authentication.js";
import { loadOrCreateKeypair, signAttestation, verifyAttestation, publicJwks, type Keypair } from "../../src/crypto/tokens.js";
import { recordDecision } from "../../src/api/state.js";
import type { Database } from "better-sqlite3";

const wire = {
  type: "wire_transfer", risk_tier: "high",
  payload: { amount: 2500000, currency: "USD", recipient_name: "Acme Corp", account_last4: "4821" },
};

let db: Database;
let kp: Keypair;

beforeEach(async () => {
  db = openDb(":memory:");
  kp = await loadOrCreateKeypair(mkdtempSync(join(tmpdir(), "ha-sec-")));
});

describe("attack: agent shows one thing and executes another", () => {
  it("refuses a payload carrying display text", () => {
    expect(() => prepareAction({
      ...wire, payload: { ...wire.payload, headline: "Pay $50 to Netflix" },
    })).toThrow(/unexpected field/);
  });

  it("gives the attacker a different challenge if they alter the amount", () => {
    const honest = prepareAction(wire);
    const attack = prepareAction({ ...wire, payload: { ...wire.payload, amount: 2500000000 } });
    expect(challengeFor(attack.payload_hash)).not.toBe(challengeFor(honest.payload_hash));
  });
});

describe("attack: replay a stolen token against a different action", () => {
  it("binds the token to one action hash", async () => {
    const honest = prepareAction(wire);
    const other = prepareAction({ ...wire, payload: { ...wire.payload, recipient_name: "Attacker LLC" } });

    const token = await signAttestation(kp, {
      jti: "att_1", sub: "prin_1", act: honest.payload_hash,
      approvers: ["prin_1"], mth: "passkey",
    }, 300);

    const result = await verifyAttestation(await publicJwks(kp), token);
    expect(result.valid).toBe(true);
    // A verifier comparing against the action it is about to execute must fail.
    expect(result.action_hash).not.toBe(other.payload_hash);
  });
});

describe("attack: forge a token with an attacker-controlled key", () => {
  it("rejects a token signed by a foreign key", async () => {
    const attacker = await loadOrCreateKeypair(mkdtempSync(join(tmpdir(), "ha-atk-")));
    const forged = await signAttestation(attacker, {
      jti: "att_1", sub: "prin_1", act: prepareAction(wire).payload_hash,
      approvers: ["prin_1"], mth: "passkey",
    }, 300);
    const result = await verifyAttestation(await publicJwks(kp), forged);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("signature_invalid");
  });

  it("rejects an expired token", async () => {
    const token = await signAttestation(kp, {
      jti: "att_1", sub: "prin_1", act: prepareAction(wire).payload_hash,
      approvers: ["prin_1"], mth: "passkey",
    }, -5);
    expect((await verifyAttestation(await publicJwks(kp), token)).valid).toBe(false);
  });
});

describe("attack: subvert multi-party approval", () => {
  beforeEach(() => {
    for (const id of ["prin_1", "prin_2"]) {
      q.insertPrincipal(db, { id, email: `${id}@t.test`, display_name: id });
    }
    const action = prepareAction(wire);
    q.insertAction(db, {
      id: "act_1", requested_by: "attacker", type: action.type,
      canonical_json: action.canonical_json, payload_hash: action.payload_hash, risk_tier: "high",
    });
    q.insertAttestation(db, {
      id: "att_1", action_id: "act_1", required_approvals: 2,
      approver_ids: ["prin_1", "prin_2"],
      expires_at: new Date(Date.now() + 60_000).toISOString(),
    });
  });

  it("refuses to let one principal approve twice to reach quorum", async () => {
    await recordDecision(db, kp, "att_1", "prin_1", "approve", "{}");
    await expect(recordDecision(db, kp, "att_1", "prin_1", "approve", "{}")).rejects.toThrow();
  });

  it("refuses an approver outside the declared set", async () => {
    q.insertPrincipal(db, { id: "prin_x", email: "x@t.test", display_name: "X" });
    await expect(recordDecision(db, kp, "att_1", "prin_x", "approve", "{}"))
      .rejects.toThrow(/not an approver/);
  });

  it("cannot outvote a dissenter", async () => {
    await recordDecision(db, kp, "att_1", "prin_1", "deny", "{}");
    await expect(recordDecision(db, kp, "att_1", "prin_2", "approve", "{}"))
      .rejects.toThrow(/already resolved/);
  });
});

describe("data retention", () => {
  it("purges the payload but keeps the hash after resolution", async () => {
    q.insertPrincipal(db, { id: "prin_1", email: "a@t.test", display_name: "A" });
    const action = prepareAction(wire);
    q.insertAction(db, {
      id: "act_1", requested_by: "agent", type: action.type,
      canonical_json: action.canonical_json, payload_hash: action.payload_hash, risk_tier: "high",
    });
    q.insertAttestation(db, {
      id: "att_1", action_id: "act_1", required_approvals: 1,
      approver_ids: ["prin_1"], expires_at: new Date(Date.now() + 60_000).toISOString(),
    });

    await recordDecision(db, kp, "att_1", "prin_1", "approve", "{}");

    const row = q.getAction(db, "act_1")!;
    expect(row.canonical_json).toBeNull();
    expect(row.purged_at).not.toBeNull();
    expect(row.payload_hash).toBe(action.payload_hash);
  });
});

describe("audit trail", () => {
  it("records every rejection", async () => {
    q.insertPrincipal(db, { id: "prin_1", email: "a@t.test", display_name: "A" });
    q.insertPrincipal(db, { id: "prin_x", email: "x@t.test", display_name: "X" });
    q.insertAction(db, {
      id: "act_1", requested_by: "agent", type: "generic",
      canonical_json: "{}", payload_hash: "sha256:" + "a".repeat(64), risk_tier: "low",
    });
    q.insertAttestation(db, {
      id: "att_1", action_id: "act_1", required_approvals: 1,
      approver_ids: ["prin_1"], expires_at: new Date(Date.now() + 60_000).toISOString(),
    });

    await expect(recordDecision(db, kp, "att_1", "prin_x", "approve", "{}")).rejects.toThrow();

    const rows = db.prepare(`SELECT event FROM audit_log WHERE event = 'unauthorised_approver'`).all();
    expect(rows).toHaveLength(1);
  });
});
