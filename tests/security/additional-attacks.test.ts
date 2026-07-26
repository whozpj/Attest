// tests/security/additional-attacks.test.ts
//
// Attacks beyond the plan's baseline suite (threat-model.test.ts), added per
// the design spec's invitation once that suite is green. Each test here
// targets a *defended* row of the product spec's threat-model table
// (docs/human-attest-mvp.md §4) or a structural invariant the design spec
// derives from it (docs/superpowers/specs/2026-07-26-human-attest-mvp-design.md
// §7-8). None of these touch the honestly-undefended assumptions (compromised
// principal device, a willing-but-deceived human, a malicious agent platform).
import { describe, it, expect, beforeEach } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openDb } from "../../src/db/index.js";
import * as q from "../../src/db/queries.js";
import { prepareAction } from "../../src/actions/render.js";
import {
  loadOrCreateKeypair, signAttestation, verifyAttestation, publicJwks, type Keypair,
} from "../../src/crypto/tokens.js";
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
  kp = await loadOrCreateKeypair(mkdtempSync(join(tmpdir(), "ha-sec2-")));
});

// Threat row: "Your API server compromised (token forgery)". Forging with no
// key at all — the "alg: none" family of attacks — is a distinct vector from
// forging with an attacker's own key: it tests whether the verifier trusts an
// unsigned assertion instead of demanding a signature it can check at all.
describe("attack: forge an unsigned token (alg:none)", () => {
  it("rejects a token that declares alg:none and carries no signature", async () => {
    const honest = prepareAction(wire);
    const header = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url");
    const payload = Buffer.from(JSON.stringify({
      sub: "prin_1",
      act: honest.payload_hash,
      approvers: ["prin_1"],
      mth: "passkey",
      jti: "att_1",
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 300,
    })).toString("base64url");
    const noneToken = `${header}.${payload}.`; // empty signature segment

    const result = await verifyAttestation(await publicJwks(kp), noneToken);
    expect(result.valid).toBe(false);
  });
});

// Threat row: "Your API server compromised (token forgery)", read together
// with the global fail-closed constraint. A verifier that throws on garbage
// input is only safe if every caller remembers to wrap it in try/catch; a
// verifier that *answers* {valid:false} is safe by construction. This locks
// in the latter.
describe("attack: malformed tokens fail closed instead of throwing", () => {
  it("returns valid:false — never throws — for structurally broken input", async () => {
    const jwks = await publicJwks(kp);
    const garbageInputs = ["", "not-a-jwt-at-all", "a.b.c", "....", "a.b.c.d.e"];
    for (const garbage of garbageInputs) {
      const result = await verifyAttestation(jwks, garbage);
      expect(result.valid).toBe(false);
    }
  });
});

// Threat row: "Rogue/compromised agent executes an unauthorized action",
// combined with the state machine's stated invariant (design spec §8):
// "Terminal is terminal. No transition out of approved, denied, expired."
// The baseline suite proves an early dissent blocks a later approval; this
// proves the converse — once quorum is met and a token is issued, a late
// "deny" cannot claw the resolution back to denied or invalidate the token
// already handed to the agent.
describe("attack: late dissent cannot revoke an already-issued approval", () => {
  it("refuses a deny submitted after the attestation already resolved to approved", async () => {
    q.insertPrincipal(db, { id: "prin_1", email: "prin_1@t.test", display_name: "prin_1" });
    const action = prepareAction(wire);
    q.insertAction(db, {
      id: "act_1", requested_by: "agent", type: action.type,
      canonical_json: action.canonical_json, payload_hash: action.payload_hash, risk_tier: "high",
    });
    q.insertAttestation(db, {
      id: "att_1", action_id: "act_1", required_approvals: 1,
      approver_ids: ["prin_1"], expires_at: new Date(Date.now() + 60_000).toISOString(),
    });

    const approved = await recordDecision(db, kp, "att_1", "prin_1", "approve", "{}");
    expect(approved.status).toBe("approved");
    const issuedToken = approved.token;
    expect(issuedToken).toBeTruthy();

    // Same principal tries to walk it back after the fact.
    await expect(recordDecision(db, kp, "att_1", "prin_1", "deny", "{}")).rejects.toThrow(/already resolved/);

    // The token already handed to the agent must still verify — a late,
    // rejected deny attempt must not have mutated the issued attestation.
    const result = await verifyAttestation(await publicJwks(kp), issuedToken!);
    expect(result.valid).toBe(true);
    expect(result.action_hash).toBe(action.payload_hash);
  });
});

// Strengthens the baseline suite's "replay a stolen token against a different
// action" test. The plan's version only asserts the two payload hashes
// differ from each other — true by construction of the fixtures, regardless
// of whether the token is actually bound to anything. This version asserts
// the property that actually matters: the token's `act` claim equals the
// *honest* hash it was signed over, so a verifier comparing it against the
// hash of whatever action it is about to execute genuinely detects the swap.
describe("attack: replay a stolen token — verifier-side rejection", () => {
  it("the token's action_hash matches only the action it was actually signed for", async () => {
    const honest = prepareAction(wire);
    const swapped = prepareAction({ ...wire, payload: { ...wire.payload, recipient_name: "Attacker LLC" } });

    const token = await signAttestation(kp, {
      jti: "att_1", sub: "prin_1", act: honest.payload_hash,
      approvers: ["prin_1"], mth: "passkey",
    }, 300);

    const result = await verifyAttestation(await publicJwks(kp), token);
    expect(result.valid).toBe(true);
    expect(result.action_hash).toBe(honest.payload_hash);

    // This is the check a real verifier is required to make (design spec §7,
    // point 6 and docs/integration/quickstart.md): compare the token's `act`
    // claim against the hash of the action about to be executed, and refuse
    // on mismatch. Simulate an attacker trying to execute `swapped` while
    // presenting the token approved for `honest`.
    const verifierAcceptsSwappedAction = result.action_hash === swapped.payload_hash;
    expect(verifierAcceptsSwappedAction).toBe(false);
  });
});
