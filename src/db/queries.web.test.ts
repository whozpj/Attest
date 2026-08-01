import { describe, it, expect, beforeEach } from "vitest";
import { openDb, type Database } from "./index.js";
import * as q from "./queries.js";

const iso = (msFromNow: number) => new Date(Date.now() + msFromNow).toISOString();

function seedPrincipal(db: Database, id: string, email: string) {
  q.insertPrincipal(db, { id, email, display_name: `User ${id}` });
}

function seedAttestation(db: Database, attId: string, approverIds: string[]) {
  const actionId = `act_${attId}`;
  q.insertAction(db, {
    id: actionId, requested_by: "agent-7", type: "wire_transfer",
    canonical_json: '{"amount":100}', payload_hash: `sha256:${attId}`, risk_tier: "high",
  });
  q.insertAttestation(db, {
    id: attId, action_id: actionId, required_approvals: 1,
    approver_ids: approverIds, expires_at: iso(60_000),
  });
  return actionId;
}

describe("approval links", () => {
  let db: Database;
  beforeEach(() => {
    db = openDb(":memory:");
    seedPrincipal(db, "prin_1", "one@e.com");
    seedAttestation(db, "att_1", ["prin_1"]);
  });

  it("round-trips a link token to its attestation and principal", () => {
    q.insertApprovalLink(db, { token: "tok_a", attestation_id: "att_1", principal_id: "prin_1" });
    expect(q.getApprovalLink(db, "tok_a")).toMatchObject({
      token: "tok_a", attestation_id: "att_1", principal_id: "prin_1",
    });
  });

  it("returns undefined for an unknown token", () => {
    expect(q.getApprovalLink(db, "nope")).toBeUndefined();
  });

  it("allows one link per (attestation, principal) pair", () => {
    q.insertApprovalLink(db, { token: "tok_a", attestation_id: "att_1", principal_id: "prin_1" });
    expect(() =>
      q.insertApprovalLink(db, { token: "tok_b", attestation_id: "att_1", principal_id: "prin_1" }),
    ).toThrow();
  });
});

describe("sessions", () => {
  let db: Database;
  beforeEach(() => {
    db = openDb(":memory:");
    seedPrincipal(db, "prin_1", "one@e.com");
  });

  it("round-trips a live session", () => {
    q.insertSession(db, { id: "sess_1", principal_id: "prin_1", expires_at: iso(60_000) });
    expect(q.getSession(db, "sess_1")).toMatchObject({ id: "sess_1", principal_id: "prin_1" });
  });

  it("does not return an expired session", () => {
    q.insertSession(db, { id: "sess_old", principal_id: "prin_1", expires_at: iso(-1000) });
    expect(q.getSession(db, "sess_old")).toBeUndefined();
  });

  it("deletes a session", () => {
    q.insertSession(db, { id: "sess_1", principal_id: "prin_1", expires_at: iso(60_000) });
    q.deleteSession(db, "sess_1");
    expect(q.getSession(db, "sess_1")).toBeUndefined();
  });
});

describe("login challenges", () => {
  let db: Database;
  beforeEach(() => {
    db = openDb(":memory:");
    seedPrincipal(db, "prin_1", "one@e.com");
  });

  it("consumes a valid challenge exactly once", () => {
    q.insertLoginChallenge(db, { challenge: "chal_1", principal_id: "prin_1", expires_at: iso(60_000) });
    expect(q.consumeLoginChallenge(db, "chal_1", "prin_1")).toBe(true);
    expect(q.consumeLoginChallenge(db, "chal_1", "prin_1")).toBe(false);
  });

  it("refuses an expired challenge", () => {
    q.insertLoginChallenge(db, { challenge: "chal_x", principal_id: "prin_1", expires_at: iso(-1000) });
    expect(q.consumeLoginChallenge(db, "chal_x", "prin_1")).toBe(false);
  });

  it("refuses a challenge bound to a different principal", () => {
    seedPrincipal(db, "prin_2", "two@e.com");
    q.insertLoginChallenge(db, { challenge: "chal_1", principal_id: "prin_1", expires_at: iso(60_000) });
    expect(q.consumeLoginChallenge(db, "chal_1", "prin_2")).toBe(false);
  });
});

describe("principal lookup by email", () => {
  it("finds a principal by exact email and returns undefined otherwise", () => {
    const db = openDb(":memory:");
    seedPrincipal(db, "prin_1", "one@e.com");
    expect(q.getPrincipalByEmail(db, "one@e.com")).toMatchObject({ id: "prin_1" });
    expect(q.getPrincipalByEmail(db, "missing@e.com")).toBeUndefined();
  });
});

describe("listRequestsFor", () => {
  let db: Database;
  beforeEach(() => {
    db = openDb(":memory:");
    seedPrincipal(db, "prin_1", "one@e.com");
    seedPrincipal(db, "prin_2", "two@e.com");
    seedAttestation(db, "att_mine", ["prin_1"]);
    seedAttestation(db, "att_theirs", ["prin_2"]);
  });

  it("returns only attestations naming this principal as an approver", () => {
    const rows = q.listRequestsFor(db, "prin_1", { limit: 50 });
    expect(rows.map((r) => r.attestation_id)).toEqual(["att_mine"]);
  });

  it("reports this principal's own recorded decision", () => {
    q.insertApproval(db, {
      id: "ap_1", attestation_id: "att_mine", principal_id: "prin_1",
      decision: "approve", client_data_json: "{}",
    });
    expect(q.listRequestsFor(db, "prin_1", { limit: 50 })[0].my_decision).toBe("approve");
    expect(q.listRequestsFor(db, "prin_2", { limit: 50 })[0].my_decision).toBeNull();
  });

  it("filters by status", () => {
    expect(q.listRequestsFor(db, "prin_1", { limit: 50, status: "approved" })).toHaveLength(0);
    expect(q.listRequestsFor(db, "prin_1", { limit: 50, status: "pending" })).toHaveLength(1);
  });
});
