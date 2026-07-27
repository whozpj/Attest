// tests/security/expiry-retention.test.ts
//
// Attack: data exfiltration via payload retention past silent expiry.
// `purgeActionPayload` was originally called only from the denied and
// approved branches of recordDecision. An attestation nobody ever decides —
// it simply times out — stayed "pending" in the database forever, with its
// full payload (wire amounts, recipient names, email bodies) intact:
// exactly the content the product spec §7 says should never be retained
// past the hash. Fixed at src/api/state.ts (API-State, e3ef253):
// effectiveStatus purges on the first read that observes expiry, since the
// design has no background scheduler ("expiry is evaluated on read").
//
// This test targets the two specific properties the fix must establish —
// payload_hash retained forever, purged_at stamped — at the same layer the
// defect lived in (effectiveStatus), independent of which HTTP route
// happens to be the caller that triggers the read.
import { describe, it, expect, beforeEach } from "vitest";
import { openDb } from "../../src/db/index.js";
import * as q from "../../src/db/queries.js";
import { prepareAction } from "../../src/actions/render.js";
import { effectiveStatus } from "../../src/api/state.js";
import type { Database } from "better-sqlite3";

const wire = {
  type: "wire_transfer", risk_tier: "high",
  payload: { amount: 2500000, currency: "USD", recipient_name: "Acme Corp", account_last4: "4821" },
};

let db: Database;

beforeEach(() => {
  db = openDb(":memory:");
});

describe("attack: data exfiltration via an attestation that silently expires, never decided", () => {
  it("purges canonical_json on first observation while keeping payload_hash, and stamps purged_at", () => {
    q.insertPrincipal(db, { id: "prin_1", email: "a@t.test", display_name: "A" });
    const action = prepareAction(wire);
    q.insertAction(db, {
      id: "act_1", requested_by: "agent", type: action.type,
      canonical_json: action.canonical_json, payload_hash: action.payload_hash, risk_tier: "high",
    });
    // Already expired at creation, and never touched by any decision --
    // nobody calls /options or /decision on it, matching "quietly times out".
    q.insertAttestation(db, {
      id: "att_1", action_id: "act_1", required_approvals: 1,
      approver_ids: ["prin_1"], expires_at: new Date(Date.now() - 1000).toISOString(),
    });

    const before = q.getAction(db, "act_1")!;
    expect(before.canonical_json).not.toBeNull(); // sanity: payload really is there before the read

    // The attacker's read: anyone holding only the attestation_id (leaked via
    // a shared link, log line, or referrer header) triggers this.
    const status = effectiveStatus(db, "att_1");
    expect(status).toBe("expired");

    const after = q.getAction(db, "act_1")!;
    expect(after.canonical_json).toBeNull();
    expect(after.purged_at).not.toBeNull();
    expect(after.payload_hash).toBe(action.payload_hash);
  });

  it("a still-pending, unexpired attestation keeps its payload untouched", () => {
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

    expect(effectiveStatus(db, "att_1")).toBe("pending");
    const row = q.getAction(db, "act_1")!;
    expect(row.canonical_json).not.toBeNull();
    expect(row.purged_at).toBeNull();
  });
});
