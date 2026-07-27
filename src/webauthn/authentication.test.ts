// src/webauthn/authentication.test.ts
import { describe, it, expect, beforeEach } from "vitest";
import { openDb } from "../db/index.js";
import * as q from "../db/queries.js";
import { beginApproval, challengeFor, finishApproval } from "./authentication.js";
import { hashCanonical } from "../crypto/canonical.js";
import { auditDetailOf, auditEventOf } from "../audit-detail.js";
import { RP } from "./config.js";
import type { Database } from "better-sqlite3";
import type { AuthenticationResponseJSON } from "@simplewebauthn/server";
// Adversary's self-contained software authenticator (real EC P-256 keys,
// genuine ECDSA signatures) — reused here rather than hand-rolled, since it
// already round-trips through this file's actual verification path. See
// tests/security/decision-binding.test.ts for its other use.
import { makeFakeCredential, signAssertion } from "../../tests/security/lib/webauthn-fake.js";

let db: Database;
const hash = hashCanonical('{"amount":2500000}');

/**
 * A syntactically valid (unsigned) authenticator-data buffer: 32-byte rpIdHash
 * (arbitrary — never inspected before either test path below throws) + 1-byte
 * flags (user-present) + 4-byte big-endian counter. No attested credential
 * data or extensions, so this is exactly 37 bytes.
 */
function authenticatorData(counter: number): string {
  const buf = Buffer.alloc(37);
  buf[32] = 0x01;
  buf.writeUInt32BE(counter, 33);
  return buf.toString("base64url");
}

function clientDataJSON(challenge: string): string {
  return Buffer.from(JSON.stringify({ type: "webauthn.get", challenge, origin: RP.origin })).toString("base64url");
}

/**
 * A hand-crafted assertion response. Both branches under test here throw
 * inside verifyAuthenticationResponse (or before it's even called) ahead of
 * signature verification, so no real passkey signature is needed — see the
 * step order in the library's own verifyAuthenticationResponse.js.
 */
function assertion(counter: number, challenge: string): AuthenticationResponseJSON {
  return {
    id: "YWJj",
    rawId: "YWJj",
    type: "public-key",
    clientExtensionResults: {},
    response: {
      clientDataJSON: clientDataJSON(challenge),
      authenticatorData: authenticatorData(counter),
      signature: Buffer.from("sig").toString("base64url"),
    },
  };
}

beforeEach(() => {
  db = openDb(":memory:");
  q.insertPrincipal(db, { id: "prin_1", email: "a@b.test", display_name: "A" });
  q.insertCredential(db, {
    id: "cred_1", principal_id: "prin_1", credential_id: "YWJj",
    public_key: Buffer.from([1]), transports: null,
  });
});

describe("challengeFor", () => {
  it("is deterministic for the same action, attestation, and decision", () => {
    expect(challengeFor(hash, "att_1", "approve")).toBe(challengeFor(hash, "att_1", "approve"));
  });

  it("differs for different actions", () => {
    expect(challengeFor(hash, "att_1", "approve"))
      .not.toBe(challengeFor(hashCanonical('{"amount":1}'), "att_1", "approve"));
  });

  it("differs for approve vs deny on the same action and attestation", () => {
    expect(challengeFor(hash, "att_1", "approve")).not.toBe(challengeFor(hash, "att_1", "deny"));
  });

  it("differs for different attestations sharing the same action and decision", () => {
    // The fix this round: two attestations that happen to carry identical
    // payload content (and therefore the identical payload_hash) must not
    // collide on the challenge — otherwise a signature captured approving
    // one attestation is valid input for a completely different one.
    expect(challengeFor(hash, "att_1", "approve")).not.toBe(challengeFor(hash, "att_2", "approve"));
  });

  it("produces four distinct challenges across two attestations and two decisions", () => {
    const challenges = new Set([
      challengeFor(hash, "att_1", "approve"),
      challengeFor(hash, "att_1", "deny"),
      challengeFor(hash, "att_2", "approve"),
      challengeFor(hash, "att_2", "deny"),
    ]);
    expect(challenges.size).toBe(4);
  });

  it("rejects a malformed action hash", () => {
    expect(() => challengeFor("sha256:nope", "att_1", "approve")).toThrow(/malformed hash/);
  });
});

describe("beginApproval", () => {
  it("uses the bound (action, attestation, decision) hash as the challenge, not a random value", async () => {
    const opts = await beginApproval(db, "prin_1", hash, "att_1", "approve");
    expect(opts.challenge).toBe(challengeFor(hash, "att_1", "approve"));
  });

  it("produces a different challenge for deny than for approve on the same action and attestation", async () => {
    const approve = await beginApproval(db, "prin_1", hash, "att_1", "approve");
    const deny = await beginApproval(db, "prin_1", hash, "att_1", "deny");
    expect(approve.challenge).not.toBe(deny.challenge);
  });

  it("produces a different challenge for a different attestation sharing the same action and decision", async () => {
    const a = await beginApproval(db, "prin_1", hash, "att_1", "approve");
    const b = await beginApproval(db, "prin_1", hash, "att_2", "approve");
    expect(a.challenge).not.toBe(b.challenge);
  });

  it("is deterministic for the same action, attestation, and decision", async () => {
    const a = await beginApproval(db, "prin_1", hash, "att_1", "approve");
    const b = await beginApproval(db, "prin_1", hash, "att_1", "approve");
    expect(a.challenge).toBe(b.challenge);
  });

  it("restricts to the principal's own credentials", async () => {
    const opts = await beginApproval(db, "prin_1", hash, "att_1", "approve");
    expect(opts.allowCredentials?.map((c) => c.id)).toEqual(["YWJj"]);
  });

  it("rejects a principal with no enrolled credential", async () => {
    q.insertPrincipal(db, { id: "prin_2", email: "c@d.test", display_name: "C" });
    await expect(beginApproval(db, "prin_2", hash, "att_1", "approve")).rejects.toThrow(/no enrolled credential/);
  });

  it("rejects a malformed action hash", async () => {
    await expect(beginApproval(db, "prin_1", "sha256:nope", "att_1", "approve")).rejects.toThrow(/malformed hash/);
  });
});

describe("finishApproval", () => {
  it("reports a counter regression as possible_credential_clone, not binding_mismatch", async () => {
    // finishApproval no longer writes audit_log itself — that's the central
    // HTTP handler's job now (src/api/server.ts), reading the event-name
    // override and detail this function attaches to the thrown error via
    // withAuditEvent/withAuditDetail. Asserting against the database here
    // would test a layer this function no longer touches; the properties it
    // actually owns are what's attached to the error it throws.
    q.updateSignCount(db, "YWJj", 5);
    const response = assertion(3, challengeFor(hash, "att_1", "approve"));

    const err = await finishApproval(db, "prin_1", hash, "att_1", "approve", response)
      .catch((e: unknown) => e);
    expect(err).toMatchObject({ code: "counter_regression", httpStatus: 401 });
    expect(auditEventOf(err)).toBe("possible_credential_clone");
    // No real key was ever involved (garbage public_key, garbage signature),
    // so this must record as unverified — an unauthenticated forger, not a
    // credential that's cryptographically proven itself compromised.
    expect(auditDetailOf(err)).toMatch(/verified=false$/);
  });

  it("still reports a genuine challenge mismatch as binding_mismatch", async () => {
    // Counter is fine (no regression); the crafted clientDataJSON carries the
    // wrong challenge, so this must fail the binding check instead.
    const response = assertion(1, "not-the-real-challenge");

    const err = await finishApproval(db, "prin_1", hash, "att_1", "approve", response)
      .catch((e: unknown) => e);
    expect(err).toMatchObject({ code: "binding_mismatch", httpStatus: 400 });
    // binding_mismatch is already both the error code and the desired event
    // name, so there's no override — the central handler falls back to
    // err.code, which auditEventOf correctly reports as undefined here.
    expect(auditEventOf(err)).toBeUndefined();
    // Same reasoning as above: no real key, so unverified — this crafted
    // response proves nothing about whether an actual credential is
    // compromised.
    expect(auditDetailOf(err)).toMatch(/verified=false$/);
  });

  it("records verified=true when a counter regression occurs on a genuinely signed response", async () => {
    // The other half of the distinction: a real EC keypair signs a real
    // assertion — the exact bytes @simplewebauthn/server verifies — but its
    // counter is behind what's stored. This is what an actual cloned
    // authenticator looks like: it has the key, but its usage history has
    // diverged from the original device.
    const cred = makeFakeCredential();
    q.insertCredential(db, {
      id: "cred_real", principal_id: "prin_1",
      credential_id: cred.credentialId, public_key: cred.publicKeyCose, transports: null,
    });
    q.updateSignCount(db, cred.credentialId, 42);

    const challenge = challengeFor(hash, "att_1", "approve");
    const response = signAssertion(cred, challenge, 1); // genuinely signed, counter=1 < stored 42

    const err = await finishApproval(db, "prin_1", hash, "att_1", "approve", response)
      .catch((e: unknown) => e);
    expect(err).toMatchObject({ code: "counter_regression", httpStatus: 401 });
    expect(auditEventOf(err)).toBe("possible_credential_clone");
    expect(auditDetailOf(err)).toBe("stored=42 presented=1 verified=true");
  });

  it("rejects a signature captured for one attestation when submitted against a different attestation sharing the same payload", async () => {
    // The central finding this round: two independently-created attestations
    // can legitimately carry identical payload content (hence identical
    // payload_hash). Before this fix, the challenge depended only on
    // (payload_hash, decision), so a genuine signature captured approving
    // attestation "att_1" was cryptographically valid input for a totally
    // separate "att_2" that merely happens to share the same payload — one
    // human approval, redeemable against every attestation with that
    // content. Binding the attestation id into the preimage closes this: a
    // signature captured for one attestation cannot be replayed against
    // another, even when both cover byte-for-byte the same action.
    const cred = makeFakeCredential();
    q.insertCredential(db, {
      id: "cred_real", principal_id: "prin_1",
      credential_id: cred.credentialId, public_key: cred.publicKeyCose, transports: null,
    });

    const optionsForA = await beginApproval(db, "prin_1", hash, "att_1", "approve");
    const signedForA = signAssertion(cred, optionsForA.challenge, 1);

    await expect(finishApproval(db, "prin_1", hash, "att_2", "approve", signedForA))
      .rejects.toMatchObject({ code: "binding_mismatch", httpStatus: 400 });

    // And the honest case must still work: the same signature, submitted
    // against the attestation it was actually signed for, succeeds.
    const finished = await finishApproval(db, "prin_1", hash, "att_1", "approve", signedForA);
    expect(finished.client_data_json).toContain(optionsForA.challenge);
  });
});
