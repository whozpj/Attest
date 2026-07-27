// tests/security/concurrent-decision-race.test.ts
//
// Attack found by whole-branch review (Reviewer), reproduced by calling
// recordDecision exactly as the route does: `recordDecision`'s
// `await signAttestation(...)` sits *inside* the state machine's critical
// section, after a dissent has already been recorded and read but before the
// final resolution is written. A concurrent approve that reaches its own
// quorum can suspend on that await, let a denial land and resolve the
// attestation to "denied" in the meantime, then resume and unconditionally
// overwrite that resolution to "approved" with a freshly minted, valid
// token — leaving a `deny` row and a `decision_deny` audit entry sitting
// right next to status "approved". This is fail-open under concurrency, in
// a state machine whose one documented invariant (design spec §8) is
// "terminal is terminal."
//
// Races make flaky tests, so this does not race wall-clock time. It drives
// the interleaving deterministically: `signAttestation` is replaced with a
// controllable gate, so the exact moment recordDecision(approve) suspends
// and resumes is under the test's control, not the scheduler's.
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openDb } from "../../src/db/index.js";
import * as q from "../../src/db/queries.js";
import { prepareAction } from "../../src/actions/render.js";
import { loadOrCreateKeypair, type Keypair } from "../../src/crypto/tokens.js";
import * as tokens from "../../src/crypto/tokens.js";
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
  kp = await loadOrCreateKeypair(mkdtempSync(join(tmpdir(), "ha-race-")));
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("attack: a concurrent approve overwrites an already-recorded denial", () => {
  it("must not leave status approved (with a minted token) next to a deny row and decision_deny audit entry", async () => {
    q.insertPrincipal(db, { id: "prin_A", email: "a@t.test", display_name: "A" });
    q.insertPrincipal(db, { id: "prin_B", email: "b@t.test", display_name: "B" });
    const action = prepareAction(wire);
    q.insertAction(db, {
      id: "act_1", requested_by: "attacker", type: action.type,
      canonical_json: action.canonical_json, payload_hash: action.payload_hash, risk_tier: "high",
    });
    // required_approvals: 1 with two declared approvers -- either one alone
    // can approve, but a dissent from either must still stop it outright
    // (the existing "cannot outvote a dissenter" guarantee). The race
    // targets the gap *between* checking that invariant and writing it down.
    q.insertAttestation(db, {
      id: "att_1", action_id: "act_1", required_approvals: 1,
      approver_ids: ["prin_A", "prin_B"],
      expires_at: new Date(Date.now() + 60_000).toISOString(),
    });

    // A controllable gate standing in for signAttestation: recordDecision's
    // approve-and-quorum-met branch will suspend here until the test
    // releases it, deterministically, instead of racing real time.
    let releaseSigning!: (token: string) => void;
    const signingGate = new Promise<string>((resolve) => { releaseSigning = resolve; });
    vi.spyOn(tokens, "signAttestation").mockImplementation(() => signingGate);

    // B approves. required_approvals is 1, so B alone reaches quorum and
    // recordDecision runs synchronously through the status check, the
    // approval insert, and the quorum check -- all before the mocked
    // signAttestation is ever called. It suspends there; this call does not
    // block because we don't await it yet.
    const bPromise = recordDecision(db, kp, "att_1", "prin_B", "approve", "{}");

    // While B is suspended mid-resolution, A denies. Nothing about the deny
    // path touches signAttestation, so this runs to completion synchronously
    // and, per the existing (and tested) fail-closed rule, resolves the
    // whole attestation to "denied".
    const aResult = await recordDecision(db, kp, "att_1", "prin_A", "deny", "{}");
    expect(aResult.status).toBe("denied");

    const afterDeny = q.getAttestation(db, "att_1")!;
    expect(afterDeny.status).toBe("denied");

    // Now let B's suspended call resume.
    releaseSigning("forged-continuation-token");
    await bPromise;

    // The defended claim: A's denial, once resolved, is terminal. B's
    // approve — already in flight when the denial landed — must not be
    // able to clobber it on resume.
    const finalRow = q.getAttestation(db, "att_1")!;
    expect(finalRow.status).toBe("denied");
    expect(finalRow.token).toBeNull();

    // The forensic trail must be consistent with "denied", not show a
    // decision_deny audit entry sitting next to an approved resolution.
    const events = db.prepare(
      "SELECT event FROM audit_log WHERE attestation_id = ? ORDER BY id",
    ).all("att_1") as Array<{ event: string }>;
    expect(events.some((e) => e.event === "decision_deny")).toBe(true);
    expect(events.some((e) => e.event === "attestation_approved")).toBe(false);
  });
});
