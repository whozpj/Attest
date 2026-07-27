// tests/security/cross-attestation-replay.test.ts
//
// Attack flagged by API-State while reviewing their own decision-binding
// fix, confirmed independently by the coordinator, and fixed by Ceremony at
// ca95146: challengeFor originally bound only (payload_hash, decision) — not
// attestation_id. Nothing about POST /v1/attestations deduplicates on
// payload_hash, so two independently-created attestations can legitimately
// reference the exact same action content and therefore, before the fix,
// the exact same challenge. A human's one real signature, captured for
// attestation A, verified just as validly against a completely separate
// attestation B that happened to share A's payload_hash. What made this
// sharper than an ordinary replay: the product spec's stated defense
// assumes the *token* gets replayed, which short expiry limits, whereas
// replaying the *signature* mints a brand-new token with a fresh timestamp
// and a distinct jti for the second attestation — expiry never engages.
//
// The fix adds attestation_id as a second term in the preimage:
// hashCanonical(canonicalize({act: payload_hash, att: attestation_id,
// decision})). This test now proves the closed form: a signature captured
// for attestation A's challenge, replayed verbatim (not re-signed) against
// attestation B's finishApproval, is rejected as a binding mismatch.
import { describe, it, expect, beforeEach } from "vitest";
import { randomUUID } from "node:crypto";
import { openDb } from "../../src/db/index.js";
import * as q from "../../src/db/queries.js";
import { prepareAction } from "../../src/actions/render.js";
import { beginApproval, finishApproval } from "../../src/webauthn/authentication.js";
import { FailClosedError } from "../../src/types.js";
import type { Database } from "better-sqlite3";
import { makeFakeCredential, signAssertion } from "./lib/webauthn-fake.js";

const wire = {
  type: "wire_transfer", risk_tier: "high",
  payload: { amount: 2500000, currency: "USD", recipient_name: "Acme Corp", account_last4: "4821" },
};

let db: Database;

beforeEach(() => {
  db = openDb(":memory:");
});

describe("attack: a signature captured for one attestation is replayed verbatim against a different attestation sharing its payload_hash", () => {
  it("rejects the replayed assertion, and it never advances the credential's sign counter", async () => {
    q.insertPrincipal(db, { id: "prin_1", email: "a@t.test", display_name: "A" });
    const cred = makeFakeCredential();
    q.insertCredential(db, {
      id: `cred_${randomUUID()}`, principal_id: "prin_1",
      credential_id: cred.credentialId, public_key: cred.publicKeyCose, transports: null,
    });

    const action = prepareAction(wire);

    // Attestation A: the legitimate request the human actually means to approve.
    q.insertAction(db, {
      id: "act_A", requested_by: "legit-agent", type: action.type,
      canonical_json: action.canonical_json, payload_hash: action.payload_hash, risk_tier: "high",
    });
    q.insertAttestation(db, {
      id: "att_A", action_id: "act_A", required_approvals: 1,
      approver_ids: ["prin_1"], expires_at: new Date(Date.now() + 60_000).toISOString(),
    });

    // Attestation B: created independently -- by an attacker's own agent
    // platform, or simply a second, unrelated caller -- referencing the
    // *identical* payload, so it shares A's payload_hash. Nothing rejects
    // this at creation time; the two attestations are still distinguished
    // by attestation_id alone, which is exactly what the fix now binds in.
    q.insertAction(db, {
      id: "act_B", requested_by: "attacker-agent", type: action.type,
      canonical_json: action.canonical_json, payload_hash: action.payload_hash, risk_tier: "high",
    });
    q.insertAttestation(db, {
      id: "att_B", action_id: "act_B", required_approvals: 1,
      approver_ids: ["prin_1"], expires_at: new Date(Date.now() + 60_000).toISOString(),
    });

    // The human genuinely signs *once*, for attestation A.
    const optionsA = await beginApproval(db, "prin_1", action.payload_hash, "att_A", "approve");
    const responseA = signAssertion(cred, optionsA.challenge, 1);
    const finishedForA = await finishApproval(db, "prin_1", action.payload_hash, "att_A", "approve", responseA as never);
    expect(finishedForA.client_data_json).toContain(optionsA.challenge);

    // The attack: that exact signed material -- not a second signing --
    // replayed against attestation B's finishApproval. Before the fix this
    // verified (both attestations shared the same challenge); now the
    // preimage differs by attestation_id, so it must be rejected.
    //
    // The specific code is counter_regression here, not binding_mismatch:
    // Ceremony's separate df7e020 fix checks the authenticator counter
    // before the WebAuthn challenge comparison, and a byte-for-byte replay
    // is, by construction, also a counter regression (same counter value
    // presented twice). That's a second, independent layer catching the
    // same attack, not a weaker result — verified directly rather than
    // assumed, since the exact rejection reason is a real, checkable fact
    // and asserting the wrong one would be a test that passes for the wrong
    // reason.
    let caught: FailClosedError | undefined;
    try {
      await finishApproval(db, "prin_1", action.payload_hash, "att_B", "approve", responseA as never);
    } catch (e) {
      caught = e as FailClosedError;
    }
    expect(caught?.code).toBe("counter_regression");

    // The rejected replay must have had zero effect on the credential.
    const credRow = q.getCredential(db, cred.credentialId)!;
    expect(credRow.sign_count).toBe(1); // only A's genuine signature advanced it
  });

  it("isolates the attestation-id binding itself: a freshly-countered signature for A's challenge still fails as binding_mismatch against B", async () => {
    // The test above proves the attack is rejected, but counter_regression
    // fires first and could in principle mask a missing attestation-id
    // check entirely. This constructs a signature that does NOT regress the
    // counter (so that check passes) but is still signed over att_A's
    // challenge, then submits it against att_B -- isolating the
    // attestation-id-binding mechanism specifically.
    q.insertPrincipal(db, { id: "prin_iso", email: "iso@t.test", display_name: "Iso" });
    const cred = makeFakeCredential();
    q.insertCredential(db, {
      id: `cred_${randomUUID()}`, principal_id: "prin_iso",
      credential_id: cred.credentialId, public_key: cred.publicKeyCose, transports: null,
    });
    const action = prepareAction(wire);
    for (const actId of ["act_E", "act_F"]) {
      q.insertAction(db, {
        id: actId, requested_by: "agent", type: action.type,
        canonical_json: action.canonical_json, payload_hash: action.payload_hash, risk_tier: "high",
      });
    }
    q.insertAttestation(db, {
      id: "att_E", action_id: "act_E", required_approvals: 1,
      approver_ids: ["prin_iso"], expires_at: new Date(Date.now() + 60_000).toISOString(),
    });
    q.insertAttestation(db, {
      id: "att_F", action_id: "act_F", required_approvals: 1,
      approver_ids: ["prin_iso"], expires_at: new Date(Date.now() + 60_000).toISOString(),
    });

    // Sign for att_E's challenge with a counter that has never been used —
    // this signature, on its own, would pass the counter check.
    const optionsE = await beginApproval(db, "prin_iso", action.payload_hash, "att_E", "approve");
    const responseE = signAssertion(cred, optionsE.challenge, 1);

    let caught: FailClosedError | undefined;
    try {
      // Submitted against att_F, not att_E -- the challenge in this
      // response was computed for att_E and will not match what
      // finishApproval expects for att_F.
      await finishApproval(db, "prin_iso", action.payload_hash, "att_F", "approve", responseE as never);
    } catch (e) {
      caught = e as FailClosedError;
    }
    expect(caught?.code).toBe("binding_mismatch");
  });

  it("a human who deliberately signs twice can still approve two genuinely distinct attestations sharing the same content", async () => {
    // Control case, so the fix above is proven to close the *replay*
    // specifically, not to break the (legitimate) case of a human
    // consciously approving two separate requests that happen to look
    // identical. Two real, independent ceremonies -- distinct signatures,
    // distinct sign counts -- both resolve, because each attestation gets
    // its own honestly-produced proof.
    q.insertPrincipal(db, { id: "prin_2", email: "b@t.test", display_name: "B" });
    const cred = makeFakeCredential();
    q.insertCredential(db, {
      id: `cred_${randomUUID()}`, principal_id: "prin_2",
      credential_id: cred.credentialId, public_key: cred.publicKeyCose, transports: null,
    });
    const action = prepareAction(wire);
    for (const actId of ["act_C", "act_D"]) {
      q.insertAction(db, {
        id: actId, requested_by: "agent", type: action.type,
        canonical_json: action.canonical_json, payload_hash: action.payload_hash, risk_tier: "high",
      });
    }
    q.insertAttestation(db, {
      id: "att_C", action_id: "act_C", required_approvals: 1,
      approver_ids: ["prin_2"], expires_at: new Date(Date.now() + 60_000).toISOString(),
    });
    q.insertAttestation(db, {
      id: "att_D", action_id: "act_D", required_approvals: 1,
      approver_ids: ["prin_2"], expires_at: new Date(Date.now() + 60_000).toISOString(),
    });

    const optionsC = await beginApproval(db, "prin_2", action.payload_hash, "att_C", "approve");
    const responseC = signAssertion(cred, optionsC.challenge, 1);
    const finishedC = await finishApproval(db, "prin_2", action.payload_hash, "att_C", "approve", responseC as never);
    expect(finishedC.client_data_json).toContain(optionsC.challenge);

    const optionsD = await beginApproval(db, "prin_2", action.payload_hash, "att_D", "approve");
    const responseD = signAssertion(cred, optionsD.challenge, 2);
    const finishedD = await finishApproval(db, "prin_2", action.payload_hash, "att_D", "approve", responseD as never);
    expect(finishedD.client_data_json).toContain(optionsD.challenge);
  });
});
