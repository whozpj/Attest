// src/webauthn/authentication.test.ts
import { describe, it, expect, beforeEach } from "vitest";
import { openDb } from "../db/index.js";
import * as q from "../db/queries.js";
import { beginApproval, challengeFor, finishApproval } from "./authentication.js";
import { hashCanonical } from "../crypto/canonical.js";
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
  it("is deterministic for the same action and decision", () => {
    expect(challengeFor(hash, "approve")).toBe(challengeFor(hash, "approve"));
  });

  it("differs for different actions", () => {
    expect(challengeFor(hash, "approve"))
      .not.toBe(challengeFor(hashCanonical('{"amount":1}'), "approve"));
  });

  it("differs for approve vs deny on the same action", () => {
    expect(challengeFor(hash, "approve")).not.toBe(challengeFor(hash, "deny"));
  });

  it("is identical for the same action and decision pair", () => {
    expect(challengeFor(hash, "deny")).toBe(challengeFor(hash, "deny"));
  });

  it("rejects a malformed action hash", () => {
    expect(() => challengeFor("sha256:nope", "approve")).toThrow(/malformed hash/);
  });
});

describe("beginApproval", () => {
  it("uses the bound (action, decision) hash as the challenge, not a random value", async () => {
    const opts = await beginApproval(db, "prin_1", hash, "approve");
    expect(opts.challenge).toBe(challengeFor(hash, "approve"));
  });

  it("produces a different challenge for deny than for approve on the same action", async () => {
    const approve = await beginApproval(db, "prin_1", hash, "approve");
    const deny = await beginApproval(db, "prin_1", hash, "deny");
    expect(approve.challenge).not.toBe(deny.challenge);
  });

  it("is deterministic for the same action and decision", async () => {
    const a = await beginApproval(db, "prin_1", hash, "approve");
    const b = await beginApproval(db, "prin_1", hash, "approve");
    expect(a.challenge).toBe(b.challenge);
  });

  it("restricts to the principal's own credentials", async () => {
    const opts = await beginApproval(db, "prin_1", hash, "approve");
    expect(opts.allowCredentials?.map((c) => c.id)).toEqual(["YWJj"]);
  });

  it("rejects a principal with no enrolled credential", async () => {
    q.insertPrincipal(db, { id: "prin_2", email: "c@d.test", display_name: "C" });
    await expect(beginApproval(db, "prin_2", hash, "approve")).rejects.toThrow(/no enrolled credential/);
  });

  it("rejects a malformed action hash", async () => {
    await expect(beginApproval(db, "prin_1", "sha256:nope", "approve")).rejects.toThrow(/malformed hash/);
  });
});

describe("finishApproval", () => {
  it("reports a counter regression as possible_credential_clone, not binding_mismatch", async () => {
    q.updateSignCount(db, "YWJj", 5);
    const response = assertion(3, challengeFor(hash, "approve"));

    await expect(finishApproval(db, "prin_1", hash, "approve", response))
      .rejects.toMatchObject({ code: "counter_regression", httpStatus: 401 });

    const events = db.prepare(`SELECT event, detail FROM audit_log`).all() as
      Array<{ event: string; detail: string | null }>;
    expect(events).toHaveLength(1);
    expect(events[0]?.event).toBe("possible_credential_clone");
    // No real key was ever involved (garbage public_key, garbage signature),
    // so this must record as unverified — an unauthenticated forger, not a
    // credential that's cryptographically proven itself compromised.
    expect(events[0]?.detail).toMatch(/verified=false$/);
  });

  it("still reports a genuine challenge mismatch as binding_mismatch", async () => {
    // Counter is fine (no regression); the crafted clientDataJSON carries the
    // wrong challenge, so this must fail the binding check instead.
    const response = assertion(1, "not-the-real-challenge");

    await expect(finishApproval(db, "prin_1", hash, "approve", response))
      .rejects.toMatchObject({ code: "binding_mismatch", httpStatus: 400 });

    const events = db.prepare(`SELECT event, detail FROM audit_log`).all() as
      Array<{ event: string; detail: string | null }>;
    expect(events).toHaveLength(1);
    expect(events[0]?.event).toBe("binding_mismatch");
    // Same reasoning: no real key, so unverified — this crafted response
    // proves nothing about whether an actual credential is compromised.
    expect(events[0]?.detail).toMatch(/verified=false$/);
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

    const challenge = challengeFor(hash, "approve");
    const response = signAssertion(cred, challenge, 1); // genuinely signed, counter=1 < stored 42

    await expect(finishApproval(db, "prin_1", hash, "approve", response))
      .rejects.toMatchObject({ code: "counter_regression", httpStatus: 401 });

    const events = db.prepare(`SELECT event, detail FROM audit_log`).all() as
      Array<{ event: string; detail: string | null }>;
    expect(events).toHaveLength(1);
    expect(events[0]?.event).toBe("possible_credential_clone");
    expect(events[0]?.detail).toBe("stored=42 presented=1 verified=true");
  });
});
