// src/api/state.race.test.ts
//
// TOCTOU in recordDecision: `await signAttestation` is a yield point inside
// the read-quorum-check-and-resolve critical section. Since Fastify can
// serve two decision requests concurrently, a second decision can commit a
// terminal resolution (denied, or a different approval) while the first is
// still suspended mid-signature. Without a re-check immediately before the
// final write, the first call resumes and blindly overwrites whatever the
// second one already committed — "terminal is terminal" breaks, and it
// breaks in the permissive direction.
//
// This is deliberately a separate file from state.test.ts: it mocks
// signAttestation to gate on a controllable promise, and that mock is
// scoped to this file only.
import { describe, it, expect, beforeEach, vi } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Database } from "better-sqlite3";

vi.mock("../crypto/tokens.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../crypto/tokens.js")>();
  return { ...actual, signAttestation: vi.fn(actual.signAttestation) };
});

import { openDb } from "../db/index.js";
import * as q from "../db/queries.js";
import { loadOrCreateKeypair, signAttestation, type Keypair } from "../crypto/tokens.js";
import { recordDecision } from "./state.js";

type SignFn = typeof signAttestation;

let db: Database;
let kp: Keypair;
let realSign: SignFn;
const HASH = "sha256:" + "a".repeat(64);

beforeEach(async () => {
  kp = await loadOrCreateKeypair(mkdtempSync(join(tmpdir(), "ha-race-")));
  db = openDb(":memory:");
  q.insertPrincipal(db, { id: "prin_1", email: "p1@t.test", display_name: "P1" });
  q.insertPrincipal(db, { id: "prin_2", email: "p2@t.test", display_name: "P2" });
  q.insertAction(db, {
    id: "act_1", requested_by: "agent", type: "generic",
    canonical_json: "{}", payload_hash: HASH, risk_tier: "high",
  });
  q.insertAttestation(db, {
    id: "att_1", action_id: "act_1", required_approvals: 1,
    approver_ids: ["prin_1", "prin_2"], expires_at: new Date(Date.now() + 60_000).toISOString(),
  });
  realSign = (await vi.importActual<typeof import("../crypto/tokens.js")>("../crypto/tokens.js")).signAttestation;
  vi.mocked(signAttestation).mockReset();
});

/** Gates the next call to signAttestation until the test releases it, and
 * resolves `called` the instant signAttestation is invoked (so the test can
 * deterministically wait for the suspension point instead of guessing at
 * microtask ticks). */
function gateNextSignature(): { called: Promise<void>; release: () => void } {
  let notifyCalled!: () => void;
  const called = new Promise<void>((resolve) => { notifyCalled = resolve; });
  let release!: () => void;
  const gate = new Promise<void>((resolve) => { release = resolve; });
  vi.mocked(signAttestation).mockImplementationOnce(async (...args) => {
    notifyCalled();
    await gate;
    return realSign(...(args as Parameters<SignFn>));
  });
  return { called, release };
}

describe("TOCTOU: a concurrent decision resolved during signAttestation's await", () => {
  it("does not let a suspended approve overwrite a denial committed in the meantime", async () => {
    const { called, release } = gateNextSignature();

    // required_approvals is 1, so prin_1's approve alone reaches quorum and
    // calls the gated signAttestation, suspending here.
    const approvePromise = recordDecision(db, kp, "att_1", "prin_1", "approve", "{}");
    await called;

    // While that's suspended mid-signature, prin_2 denies. Deny has no
    // await in its path, so it commits synchronously and completes here,
    // in full, before the approve call resumes.
    const denyResult = await recordDecision(db, kp, "att_1", "prin_2", "deny", "{}");
    expect(denyResult.status).toBe("denied");

    release();
    const approveResult = await approvePromise;

    // The fix under test: approve must not clobber the denial it missed.
    // It discards its own freshly-signed token and reports the actual,
    // already-committed outcome instead.
    expect(approveResult.status).toBe("denied");
    expect(approveResult.token).toBeNull();

    const finalAtt = q.getAttestation(db, "att_1")!;
    expect(finalAtt.status).toBe("denied");
    expect(finalAtt.token).toBeNull();

    // The deny itself is still on the record, untouched.
    const approvals = q.getApprovals(db, "att_1");
    expect(approvals.find((a) => a.principal_id === "prin_2")?.decision).toBe("deny");
  });

  it("does not let two concurrent approvals each commit a distinct token — the later one converges on the earlier commit", async () => {
    const { called, release } = gateNextSignature();

    const approveAPromise = recordDecision(db, kp, "att_1", "prin_1", "approve", "{}");
    await called;

    // prin_2 also approves (required_approvals is 1, so this alone reaches
    // quorum too) while A's signature is still pending. B is not gated, so
    // it signs and commits first.
    const approveBResult = await recordDecision(db, kp, "att_1", "prin_2", "approve", "{}");
    expect(approveBResult.status).toBe("approved");
    expect(approveBResult.token).toBeTruthy();

    release();
    const approveAResult = await approveAPromise;

    // A must not overwrite B's already-committed token with a distinct one
    // of its own ("last write wins" is exactly the bug).
    expect(approveAResult.status).toBe("approved");
    expect(approveAResult.token).toBe(approveBResult.token);

    const finalAtt = q.getAttestation(db, "att_1")!;
    expect(finalAtt.token).toBe(approveBResult.token);
  });
});
