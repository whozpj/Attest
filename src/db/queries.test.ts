// src/db/queries.test.ts
import { describe, it, expect, beforeEach } from "vitest";
import { openDb } from "./index.js";
import * as q from "./queries.js";
import type { Database } from "better-sqlite3";

let db: Database;

beforeEach(() => { db = openDb(":memory:"); });

describe("principals and credentials", () => {
  it("round-trips a principal", () => {
    q.insertPrincipal(db, { id: "prin_1", email: "a@b.test", display_name: "A" });
    expect(q.getPrincipal(db, "prin_1")?.email).toBe("a@b.test");
  });

  it("stores and lists credentials for a principal", () => {
    q.insertPrincipal(db, { id: "prin_1", email: "a@b.test", display_name: "A" });
    q.insertCredential(db, {
      id: "cred_1", principal_id: "prin_1", credential_id: "abc",
      public_key: Buffer.from([1, 2, 3]), transports: "internal",
    });
    expect(q.getCredentialsFor(db, "prin_1")).toHaveLength(1);
  });

  it("rejects a duplicate credential id", () => {
    q.insertPrincipal(db, { id: "prin_1", email: "a@b.test", display_name: "A" });
    const cred = {
      id: "cred_1", principal_id: "prin_1", credential_id: "abc",
      public_key: Buffer.from([1]), transports: null,
    };
    q.insertCredential(db, cred);
    expect(() => q.insertCredential(db, { ...cred, id: "cred_2" })).toThrow();
  });
});

describe("enrolment tokens", () => {
  beforeEach(() => {
    q.insertPrincipal(db, { id: "prin_1", email: "a@b.test", display_name: "A" });
  });

  it("round-trips a fresh token", () => {
    q.insertEnrolmentToken(db, {
      token: "tok_1", principal_id: "prin_1",
      expires_at: new Date(Date.now() + 60_000).toISOString(),
    });
    const row = q.getEnrolmentToken(db, "tok_1");
    expect(row?.principal_id).toBe("prin_1");
    expect(row?.used_at).toBeNull();
  });

  it("returns undefined for a token that was never issued", () => {
    expect(q.getEnrolmentToken(db, "tok_ghost")).toBeUndefined();
  });

  it("consumeEnrolmentToken succeeds exactly once for a fresh, matching, unexpired token", () => {
    q.insertEnrolmentToken(db, {
      token: "tok_2", principal_id: "prin_1",
      expires_at: new Date(Date.now() + 60_000).toISOString(),
    });
    expect(q.consumeEnrolmentToken(db, "tok_2", "prin_1")).toBe(true);
    // Single-use: a second attempt, even with the exact same valid inputs, fails.
    expect(q.consumeEnrolmentToken(db, "tok_2", "prin_1")).toBe(false);
  });

  it("consumeEnrolmentToken fails for a token bound to a different principal", () => {
    q.insertPrincipal(db, { id: "prin_2", email: "z@b.test", display_name: "Z" });
    q.insertEnrolmentToken(db, {
      token: "tok_3", principal_id: "prin_1",
      expires_at: new Date(Date.now() + 60_000).toISOString(),
    });
    expect(q.consumeEnrolmentToken(db, "tok_3", "prin_2")).toBe(false);
    // And it's still unused — a mismatched-principal attempt must not burn it.
    expect(q.getEnrolmentToken(db, "tok_3")?.used_at).toBeNull();
  });

  it("consumeEnrolmentToken fails for an expired token", () => {
    q.insertEnrolmentToken(db, {
      token: "tok_4", principal_id: "prin_1",
      expires_at: new Date(Date.now() - 1000).toISOString(),
    });
    expect(q.consumeEnrolmentToken(db, "tok_4", "prin_1")).toBe(false);
  });

  it("consumeEnrolmentToken fails for an unknown token", () => {
    expect(q.consumeEnrolmentToken(db, "tok_never_issued", "prin_1")).toBe(false);
  });
});

describe("actions", () => {
  it("purges the payload but retains the hash", () => {
    q.insertAction(db, {
      id: "act_1", requested_by: "agent", type: "wire_transfer",
      canonical_json: '{"a":1}', payload_hash: "sha256:" + "a".repeat(64), risk_tier: "high",
    });
    q.purgeActionPayload(db, "act_1");
    const row = q.getAction(db, "act_1")!;
    expect(row.canonical_json).toBeNull();
    expect(row.purged_at).not.toBeNull();
    expect(row.payload_hash).toBe("sha256:" + "a".repeat(64));
  });
});

describe("approvals", () => {
  beforeEach(() => {
    q.insertPrincipal(db, { id: "prin_1", email: "a@b.test", display_name: "A" });
    q.insertAction(db, {
      id: "act_1", requested_by: "agent", type: "generic",
      canonical_json: "{}", payload_hash: "sha256:" + "a".repeat(64), risk_tier: "low",
    });
    q.insertAttestation(db, {
      id: "att_1", action_id: "act_1", required_approvals: 1,
      approver_ids: ["prin_1"], expires_at: new Date(Date.now() + 60000).toISOString(),
    });
  });

  it("refuses two approvals from the same principal", () => {
    const a = {
      id: "ap_1", attestation_id: "att_1", principal_id: "prin_1",
      decision: "approve" as const, client_data_json: "{}",
    };
    q.insertApproval(db, a);
    expect(() => q.insertApproval(db, { ...a, id: "ap_2" })).toThrow();
  });

  it("writes audit rows", () => {
    q.audit(db, { attestation_id: "att_1", event: "binding_mismatch", actor: "prin_1", detail: null });
    const rows = db.prepare("SELECT * FROM audit_log").all();
    expect(rows).toHaveLength(1);
  });

  it("returns approvals in the order they were signed, not row/index order", () => {
    // Without an ORDER BY, SQLite is free to return rows via whichever index
    // it picks — here that's the UNIQUE(attestation_id, principal_id) index,
    // which sorts by principal_id. principal_id has nothing to do with who
    // approved first, so a caller relying on array order (state.ts takes
    // approvers[0] as the token's `sub`) would silently get the wrong human
    // whenever approval order and principal_id order disagree.
    q.insertPrincipal(db, { id: "prin_2", email: "z@b.test", display_name: "Z" });

    // "prin_2" sorts before "prin_1"... no it doesn't; pick ids that make the
    // point unambiguous: zoe approves first even though her id is
    // lexicographically *after* alice's.
    const earlier = new Date(Date.now() - 10_000).toISOString();
    const later = new Date().toISOString();

    db.prepare(
      `INSERT INTO attestation_approvals (id, attestation_id, principal_id, decision, client_data_json, signed_at)
       VALUES (?, ?, ?, 'approve', '{}', ?)`,
    ).run("ap_later", "att_1", "prin_1", later);
    db.prepare(
      `INSERT INTO attestation_approvals (id, attestation_id, principal_id, decision, client_data_json, signed_at)
       VALUES (?, ?, ?, 'approve', '{}', ?)`,
    ).run("ap_earlier", "att_1", "prin_2", earlier);

    const approvals = q.getApprovals(db, "att_1");
    expect(approvals.map((a) => a.principal_id)).toEqual(["prin_2", "prin_1"]);
  });
});

describe("push subscriptions", () => {
  beforeEach(() => {
    q.insertPrincipal(db, { id: "prin_1", email: "a@b.test", display_name: "A" });
  });

  it("round-trips a push subscription for a principal", () => {
    q.upsertPushSubscription(db, {
      id: "psub_1", principal_id: "prin_1",
      endpoint: "https://push.example/abc", p256dh: "p256dh-key", auth: "auth-secret",
    });
    const subs = q.getPushSubscriptionsFor(db, "prin_1");
    expect(subs).toHaveLength(1);
    expect(subs[0]).toMatchObject({ endpoint: "https://push.example/abc", p256dh: "p256dh-key", auth: "auth-secret" });
  });

  it("rebinds an existing endpoint to whichever principal last registered it, rather than throwing", () => {
    q.insertPrincipal(db, { id: "prin_2", email: "b@b.test", display_name: "B" });
    q.upsertPushSubscription(db, {
      id: "psub_1", principal_id: "prin_1",
      endpoint: "https://push.example/shared", p256dh: "key-1", auth: "auth-1",
    });
    q.upsertPushSubscription(db, {
      id: "psub_2", principal_id: "prin_2",
      endpoint: "https://push.example/shared", p256dh: "key-2", auth: "auth-2",
    });
    expect(q.getPushSubscriptionsFor(db, "prin_1")).toHaveLength(0);
    const subs = q.getPushSubscriptionsFor(db, "prin_2");
    expect(subs).toHaveLength(1);
    expect(subs[0]).toMatchObject({ endpoint: "https://push.example/shared", p256dh: "key-2", auth: "auth-2" });
  });

  it("deletes a subscription by endpoint", () => {
    q.upsertPushSubscription(db, {
      id: "psub_1", principal_id: "prin_1",
      endpoint: "https://push.example/gone", p256dh: "key", auth: "auth",
    });
    q.deletePushSubscription(db, "https://push.example/gone");
    expect(q.getPushSubscriptionsFor(db, "prin_1")).toHaveLength(0);
  });
});
