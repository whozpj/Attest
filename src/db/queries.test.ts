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
});
