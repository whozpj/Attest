// tests/security/decision-binding.test.ts
//
// Attack: decision interchangeability. Background (the lead): `deny` used
// to require no WebAuthn signature at all, so anyone who knew an
// attestation_id and an approver's principal_id could unilaterally block a
// pending attestation. The naive fix — have deny also call finishApproval
// against the *same* challenge approve uses — was rejected, because it would
// make an approve and a deny for the same action sign identical bytes:
// cryptographically interchangeable. An assertion captured for one could be
// resubmitted as the other. Ceremony's actual fix
// (src/webauthn/authentication.ts, 579220b, extended in ca95146 to also
// bind attestation_id) binds the decision into the challenge preimage —
// hashCanonical(canonicalize({act: payload_hash, att: attestation_id,
// decision})) — so approve and deny sign genuinely different bytes.
//
// This suite proves the interchangeability is actually closed, with real
// cryptography: a self-contained software WebAuthn authenticator (see
// tests/security/lib/webauthn-fake.ts) signs a real ECDSA assertion over the
// challenge issued for one decision, and that signed material is submitted
// for the *other* decision on the same action. If the naive (undifferentiated
// challenge) design were still in place, this attack would succeed — a
// valid signature is a valid signature, and the verifier would accept it
// regardless of which decision it was declared for. Written to fail if that
// property doesn't hold, not merely to observe that it does.
import { describe, it, expect, beforeEach } from "vitest";
import { randomUUID } from "node:crypto";
import { openDb } from "../../src/db/index.js";
import * as q from "../../src/db/queries.js";
import { prepareAction } from "../../src/actions/render.js";
import { challengeFor, beginApproval, finishApproval } from "../../src/webauthn/authentication.js";
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

/** Registers a fresh principal + real (software-signed) credential, and a fresh action for `wire`. */
function seedPrincipalAndAction(principalId: string) {
  q.insertPrincipal(db, { id: principalId, email: `${principalId}@t.test`, display_name: principalId });
  const cred = makeFakeCredential();
  q.insertCredential(db, {
    id: `cred_${randomUUID()}`, principal_id: principalId,
    credential_id: cred.credentialId, public_key: cred.publicKeyCose, transports: null,
  });
  const action = prepareAction(wire);
  return { cred, payloadHash: action.payload_hash };
}

describe("attack: decision interchangeability", () => {
  it("byte-level: the approve and deny challenges for the same action are genuinely different bytes", () => {
    const { payloadHash } = seedPrincipalAndAction("prin_bytes");
    const approveBytes = Buffer.from(challengeFor(payloadHash, "att_1", "approve"), "base64url");
    const denyBytes = Buffer.from(challengeFor(payloadHash, "att_1", "deny"), "base64url");

    expect(approveBytes.length).toBeGreaterThan(0);
    expect(approveBytes.equals(denyBytes)).toBe(false);
  });

  it("a deny-signed assertion is genuinely valid for deny (the harness signs real, verifiable material)", async () => {
    const principalId = "prin_sanity";
    const { cred, payloadHash } = seedPrincipalAndAction(principalId);

    const denyOptions = await beginApproval(db, principalId, payloadHash, "att_1", "deny");
    const response = signAssertion(cred, denyOptions.challenge, 1);

    const result = await finishApproval(db, principalId, payloadHash, "att_1", "deny", response as never);
    expect(result.client_data_json).toContain(denyOptions.challenge);
  });

  it("rejects a deny-signed assertion submitted as an approval", async () => {
    const principalId = "prin_deny_to_approve";
    const { cred, payloadHash } = seedPrincipalAndAction(principalId);

    const denyOptions = await beginApproval(db, principalId, payloadHash, "att_1", "deny");
    const forgedApprove = signAssertion(cred, denyOptions.challenge, 1);

    // The attack: material honestly signed for "deny", replayed as "approve"
    // on the *same* attestation (att_1 in both).
    await expect(
      finishApproval(db, principalId, payloadHash, "att_1", "approve", forgedApprove as never),
    ).rejects.toThrow(FailClosedError);

    let caught: FailClosedError | undefined;
    try {
      await finishApproval(db, principalId, payloadHash, "att_1", "approve", forgedApprove as never);
    } catch (e) {
      caught = e as FailClosedError;
    }
    expect(caught?.code).toBe("binding_mismatch");

    // The rejected replay must not have advanced the credential's sign
    // counter — it had zero effect, not a partial one.
    const credRow = q.getCredential(db, cred.credentialId)!;
    expect(credRow.sign_count).toBe(0);
  });

  it("mirrors the attack: rejects an approve-signed assertion submitted as a deny", async () => {
    const principalId = "prin_approve_to_deny";
    const { cred, payloadHash } = seedPrincipalAndAction(principalId);

    const approveOptions = await beginApproval(db, principalId, payloadHash, "att_1", "approve");
    const forgedDeny = signAssertion(cred, approveOptions.challenge, 1);

    let caught: FailClosedError | undefined;
    try {
      await finishApproval(db, principalId, payloadHash, "att_1", "deny", forgedDeny as never);
    } catch (e) {
      caught = e as FailClosedError;
    }
    expect(caught?.code).toBe("binding_mismatch");
  });

  it("mutation control: with an undifferentiated (decision-agnostic) challenge, the same replay would succeed", async () => {
    // Rather than mutate src/webauthn/authentication.ts in the shared
    // working tree (this file is under active, concurrent edit by
    // Ceremony/API-State this session — a hazard confirmed firsthand
    // earlier), this reconstructs the *naive, rejected* design's decision
    // procedure directly and shows it would accept the same forged replay
    // that the real (bound) design rejects above. This is the counterfactual
    // half of "must be red under naive, green under bound-decision" — done
    // without touching a file three other agents are actively iterating on.
    const principalId = "prin_naive_counterfactual";
    const { cred, payloadHash } = seedPrincipalAndAction(principalId);

    // Naive design: challenge = hash(payload) alone, decision not in the
    // preimage -- exactly the pre-fix behavior this session closed.
    const naiveChallenge = payloadHash.replace(/^sha256:/, "");
    const naiveChallengeB64url = Buffer.from(naiveChallenge, "hex").toString("base64url");

    const denySignedUnderNaiveDesign = signAssertion(cred, naiveChallengeB64url, 1);
    // Under the naive scheme, "approve" and "deny" both resolve to this same
    // challenge, so verifying the deny-signed material *as if it were an
    // approval's expected challenge* must succeed -- demonstrating the
    // interchangeability the real fix specifically closes.
    const { verifyAuthenticationResponse } = await import("@simplewebauthn/server");
    const { RP } = await import("../../src/webauthn/config.js");
    const verification = await verifyAuthenticationResponse({
      response: denySignedUnderNaiveDesign,
      expectedChallenge: naiveChallengeB64url, // what "approve" would also expect, naively
      expectedOrigin: RP.origin,
      expectedRPID: RP.id,
      credential: { id: cred.credentialId, publicKey: new Uint8Array(cred.publicKeyCose), counter: 0 },
    });
    expect(verification.verified).toBe(true);
  });
});
