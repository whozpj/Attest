// src/api/state.test.ts
import { describe, it, expect, beforeEach } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openDb } from "../db/index.js";
import * as q from "../db/queries.js";
import { loadOrCreateKeypair, type Keypair } from "../crypto/tokens.js";
import { effectiveStatus, recordDecision } from "./state.js";
import type { Database } from "better-sqlite3";

let db: Database;
let kp: Keypair;
const HASH = "sha256:" + "a".repeat(64);

async function seed(required: number, approvers: string[], ttlMs = 60_000) {
  db = openDb(":memory:");
  for (const id of approvers) {
    q.insertPrincipal(db, { id, email: `${id}@t.test`, display_name: id });
  }
  q.insertAction(db, {
    id: "act_1", requested_by: "agent", type: "generic",
    canonical_json: "{}", payload_hash: HASH, risk_tier: "high",
  });
  q.insertAttestation(db, {
    id: "att_1", action_id: "act_1", required_approvals: required,
    approver_ids: approvers, expires_at: new Date(Date.now() + ttlMs).toISOString(),
  });
}

beforeEach(async () => {
  kp = await loadOrCreateKeypair(mkdtempSync(join(tmpdir(), "ha-state-")));
});

describe("single-approver quorum", () => {
  it("resolves to approved and issues a token", async () => {
    await seed(1, ["prin_1"]);
    const r = await recordDecision(db, kp, "att_1", "prin_1", "approve", "{}");
    expect(r.status).toBe("approved");
    expect(r.token).toBeTruthy();
  });

  it("resolves to denied with no token", async () => {
    await seed(1, ["prin_1"]);
    const r = await recordDecision(db, kp, "att_1", "prin_1", "deny", "{}");
    expect(r.status).toBe("denied");
    expect(r.token).toBeNull();
  });
});

describe("multi-party quorum", () => {
  it("stays pending until quorum is met", async () => {
    await seed(2, ["prin_1", "prin_2"]);
    const first = await recordDecision(db, kp, "att_1", "prin_1", "approve", "{}");
    expect(first.status).toBe("pending");
    expect(first.token).toBeNull();

    const second = await recordDecision(db, kp, "att_1", "prin_2", "approve", "{}");
    expect(second.status).toBe("approved");
    expect(second.token).toBeTruthy();
  });

  it("fails closed: one denial resolves the whole attestation", async () => {
    await seed(2, ["prin_1", "prin_2"]);
    await recordDecision(db, kp, "att_1", "prin_1", "approve", "{}");
    const r = await recordDecision(db, kp, "att_1", "prin_2", "deny", "{}");
    expect(r.status).toBe("denied");
  });

  it("lists every approver in the token claims", async () => {
    await seed(2, ["prin_1", "prin_2"]);
    await recordDecision(db, kp, "att_1", "prin_1", "approve", "{}");
    const r = await recordDecision(db, kp, "att_1", "prin_2", "approve", "{}");
    const claims = JSON.parse(Buffer.from(r.token!.split(".")[1], "base64url").toString());
    expect(claims.approvers.sort()).toEqual(["prin_1", "prin_2"]);
    expect(claims.mth).toBe("passkey_multi");
  });
});

describe("rejections", () => {
  it("refuses an approver outside the approver set", async () => {
    await seed(1, ["prin_1"]);
    q.insertPrincipal(db, { id: "prin_x", email: "x@t.test", display_name: "X" });
    await expect(recordDecision(db, kp, "att_1", "prin_x", "approve", "{}"))
      .rejects.toThrow(/not an approver/);
  });

  it("refuses a decision on a terminal attestation", async () => {
    await seed(1, ["prin_1"]);
    await recordDecision(db, kp, "att_1", "prin_1", "approve", "{}");
    await expect(recordDecision(db, kp, "att_1", "prin_1", "approve", "{}"))
      .rejects.toThrow(/already resolved/);
  });

  it("refuses a decision after expiry and reports expired", async () => {
    await seed(1, ["prin_1"], -1000);
    expect(effectiveStatus(db, "att_1")).toBe("expired");
    await expect(recordDecision(db, kp, "att_1", "prin_1", "approve", "{}"))
      .rejects.toThrow(/expired/);
  });

  it("purges the payload once resolved", async () => {
    await seed(1, ["prin_1"]);
    await recordDecision(db, kp, "att_1", "prin_1", "approve", "{}");
    expect(q.getAction(db, "act_1")!.canonical_json).toBeNull();
  });
});
