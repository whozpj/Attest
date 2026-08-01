// tests/security/session-approval-separation.test.ts
//
// Attack: cross-ceremony assertion replay between sign-in and approval.
//
// The design doc (§2/D7) claims sign-in and approval are structurally
// non-interchangeable: a sign-in challenge is 32 random bytes stored in
// `login_challenges`, while an approval challenge is
// hash({act, att, decision}) and is never stored anywhere. The claim is that
// this asymmetry makes it *impossible* -- not merely unlikely -- for an
// assertion captured during one ceremony to be redeemed in the other.
//
// That claim is only worth anything if the assertions under test are
// genuinely valid. A test that submits a garbage blob to the wrong endpoint
// and observes a rejection proves nothing: the rejection could be for any of
// a dozen unrelated reasons. So every replay below is *sandwiched* -- the
// exact same signed assertion object is first shown to be rejected by the
// wrong endpoint, and then shown to be accepted by the right one. The second
// half is what makes the first half evidence rather than coincidence.
//
// Signatures are produced by tests/security/lib/webauthn-fake.ts, a real
// software authenticator over a real P-256 key, so both endpoints run their
// genuine @simplewebauthn verification path.
import { describe, it, expect, beforeEach } from "vitest";
import { randomUUID } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { FastifyInstance } from "fastify";
import { buildServer, type AppContext } from "../../src/api/server.js";
import * as q from "../../src/db/queries.js";
import { challengeFor } from "../../src/webauthn/authentication.js";
import { makeFakeCredential, type FakeCredential, signAssertion } from "./lib/webauthn-fake.js";

type App = FastifyInstance & { ctx: AppContext };

const wire = {
  type: "wire_transfer",
  risk_tier: "high",
  payload: { amount: 2500000, currency: "USD", recipient_name: "Acme Corp", account_last4: "4821" },
};

async function newApp(baseUrl?: string): Promise<App> {
  return buildServer({
    dbPath: ":memory:",
    keyDir: mkdtempSync(join(tmpdir(), "ha-sep-")),
    // A recorder that drops the message: these tests are about the ceremony,
    // not delivery, and the real file transport would scatter .eml files.
    email: { async send() {} },
    ...(baseUrl ? { baseUrl } : {}),
  }) as Promise<App>;
}

/** A principal with a real, verifiable credential enrolled. */
function seedApprover(app: App, id: string, email: string): FakeCredential {
  q.insertPrincipal(app.ctx.db, { id, email, display_name: id });
  const cred = makeFakeCredential();
  q.insertCredential(app.ctx.db, {
    id: `cred_${randomUUID()}`,
    principal_id: id,
    credential_id: cred.credentialId,
    public_key: cred.publicKeyCose,
    transports: null,
  });
  return cred;
}

async function createAttestation(app: App, approverIds: string[], required = 1): Promise<string> {
  const res = await app.inject({
    method: "POST",
    url: "/v1/attestations",
    payload: {
      requested_by: "agent-7",
      approver_ids: approverIds,
      required_approvals: required,
      ttl_seconds: 900,
      action: wire,
    },
  });
  expect(res.statusCode).toBe(201);
  return res.json().attestation_id as string;
}

async function loginChallengeFor(app: App, email: string): Promise<string> {
  const res = await app.inject({
    method: "POST", url: "/web/session/options", payload: { email },
  });
  expect(res.statusCode).toBe(200);
  return res.json().challenge as string;
}

async function approvalChallengeFor(
  app: App, attestationId: string, principalId: string, decision: "approve" | "deny",
): Promise<string> {
  const res = await app.inject({
    method: "POST",
    url: `/v1/attestations/${attestationId}/options`,
    payload: { principal_id: principalId, decision },
  });
  expect(res.statusCode).toBe(200);
  return res.json().challenge as string;
}

function sessionRowCount(app: App): number {
  return (app.ctx.db.prepare(`SELECT COUNT(*) AS c FROM sessions`).get() as { c: number }).c;
}

describe("attack: a sign-in assertion replayed as an approval", () => {
  let app: App;
  let cred: FakeCredential;
  let attestationId: string;

  beforeEach(async () => {
    app = await newApp();
    cred = seedApprover(app, "prin_a", "a@t.test");
    attestationId = await createAttestation(app, ["prin_a"]);
  });

  it("is rejected as binding_mismatch, records no approval, and leaves the attestation pending", async () => {
    const challenge = await loginChallengeFor(app, "a@t.test");
    const assertion = signAssertion(cred, challenge);

    const res = await app.inject({
      method: "POST",
      url: `/v1/attestations/${attestationId}/decision`,
      payload: { principal_id: "prin_a", decision: "approve", response: assertion },
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe("binding_mismatch");
    expect(q.getApprovals(app.ctx.db, attestationId)).toHaveLength(0);
    expect(q.getAttestation(app.ctx.db, attestationId)!.status).toBe("pending");
    expect(q.getAttestation(app.ctx.db, attestationId)!.token).toBeNull();
  });

  it("is rejected for deny as well, so the replay cannot force a denial either", async () => {
    const challenge = await loginChallengeFor(app, "a@t.test");
    const assertion = signAssertion(cred, challenge);

    const res = await app.inject({
      method: "POST",
      url: `/v1/attestations/${attestationId}/decision`,
      payload: { principal_id: "prin_a", decision: "deny", response: assertion },
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe("binding_mismatch");
    expect(q.getApprovals(app.ctx.db, attestationId)).toHaveLength(0);
    expect(q.getAttestation(app.ctx.db, attestationId)!.status).toBe("pending");
  });

  // The control that makes the two tests above meaningful: this is the SAME
  // signed object, byte for byte, refused as an approval and then accepted as
  // a sign-in. The rejection above is therefore about which ceremony the
  // bytes were bound to, not about the assertion being malformed.
  it("control: that identical assertion IS accepted by the sign-in endpoint", async () => {
    const challenge = await loginChallengeFor(app, "a@t.test");
    const assertion = signAssertion(cred, challenge);

    const refused = await app.inject({
      method: "POST",
      url: `/v1/attestations/${attestationId}/decision`,
      payload: { principal_id: "prin_a", decision: "approve", response: assertion },
    });
    expect(refused.statusCode).toBe(400);

    const accepted = await app.inject({
      method: "POST", url: "/web/session", payload: { email: "a@t.test", response: assertion },
    });
    expect(accepted.statusCode).toBe(204);
    expect(sessionRowCount(app)).toBe(1);
  });

  it("structural: a login challenge never equals the approve or deny challenge for any live attestation", async () => {
    const action = q.getAction(
      app.ctx.db, q.getAttestation(app.ctx.db, attestationId)!.action_id,
    )!;
    const forbidden = new Set([
      challengeFor(action.payload_hash, attestationId, "approve"),
      challengeFor(action.payload_hash, attestationId, "deny"),
    ]);

    for (let i = 0; i < 25; i += 1) {
      expect(forbidden.has(await loginChallengeFor(app, "a@t.test"))).toBe(false);
    }
  });
});

describe("attack: an approval assertion replayed as a sign-in", () => {
  let app: App;
  let cred: FakeCredential;
  let attestationId: string;

  beforeEach(async () => {
    app = await newApp();
    cred = seedApprover(app, "prin_a", "a@t.test");
    attestationId = await createAttestation(app, ["prin_a"]);
  });

  it("is rejected with 401, sets no cookie, and creates no session row", async () => {
    const challenge = await approvalChallengeFor(app, attestationId, "prin_a", "approve");
    const assertion = signAssertion(cred, challenge);

    const res = await app.inject({
      method: "POST", url: "/web/session", payload: { email: "a@t.test", response: assertion },
    });

    expect(res.statusCode).toBe(401);
    expect(res.json().error).toBe("login_challenge_invalid");
    expect(res.headers["set-cookie"]).toBeUndefined();
    expect(sessionRowCount(app)).toBe(0);
  });

  it("is rejected even when a login challenge is outstanding for the same principal", async () => {
    // The attacker's best case: force the server to hold an unused login
    // challenge, then present an approval assertion, hoping the verifier
    // matches on "some challenge exists" rather than on the exact bytes.
    await loginChallengeFor(app, "a@t.test");

    const challenge = await approvalChallengeFor(app, attestationId, "prin_a", "approve");
    const res = await app.inject({
      method: "POST",
      url: "/web/session",
      payload: { email: "a@t.test", response: signAssertion(cred, challenge) },
    });

    expect(res.statusCode).toBe(401);
    expect(sessionRowCount(app)).toBe(0);
  });

  // The mirror-image control.
  it("control: that identical assertion IS accepted by the decision endpoint", async () => {
    const challenge = await approvalChallengeFor(app, attestationId, "prin_a", "approve");
    const assertion = signAssertion(cred, challenge);

    const refused = await app.inject({
      method: "POST", url: "/web/session", payload: { email: "a@t.test", response: assertion },
    });
    expect(refused.statusCode).toBe(401);

    const accepted = await app.inject({
      method: "POST",
      url: `/v1/attestations/${attestationId}/decision`,
      payload: { principal_id: "prin_a", decision: "approve", response: assertion },
    });
    expect(accepted.statusCode).toBe(200);
    expect(accepted.json().status).toBe("approved");
    expect(sessionRowCount(app)).toBe(0);
  });
});

describe("login challenges are single-use", () => {
  let app: App;
  let cred: FakeCredential;

  beforeEach(async () => {
    app = await newApp();
    cred = seedApprover(app, "prin_a", "a@t.test");
  });

  it("yields one session, not two, when a successful sign-in payload is replayed verbatim", async () => {
    const challenge = await loginChallengeFor(app, "a@t.test");
    const payload = { email: "a@t.test", response: signAssertion(cred, challenge, 1) };

    const first = await app.inject({ method: "POST", url: "/web/session", payload });
    const second = await app.inject({ method: "POST", url: "/web/session", payload });

    expect(first.statusCode).toBe(204);
    expect(second.statusCode).toBe(401);
    expect(second.headers["set-cookie"]).toBeUndefined();
    expect(sessionRowCount(app)).toBe(1);
  });

  it("burns the challenge row itself, so the replay fails on the challenge and not incidentally", async () => {
    const challenge = await loginChallengeFor(app, "a@t.test");
    // Unused: still redeemable.
    const fresh = app.ctx.db
      .prepare(`SELECT used_at FROM login_challenges WHERE challenge = ?`)
      .get(challenge) as { used_at: string | null };
    expect(fresh.used_at).toBeNull();

    await app.inject({
      method: "POST",
      url: "/web/session",
      payload: { email: "a@t.test", response: signAssertion(cred, challenge, 1) },
    });

    expect(q.consumeLoginChallenge(app.ctx.db, challenge, "prin_a")).toBe(false);
  });

  it("control: a fresh challenge still signs in, so the replay rejection is about reuse alone", async () => {
    const first = await loginChallengeFor(app, "a@t.test");
    expect((await app.inject({
      method: "POST", url: "/web/session",
      payload: { email: "a@t.test", response: signAssertion(cred, first, 1) },
    })).statusCode).toBe(204);

    const second = await loginChallengeFor(app, "a@t.test");
    expect((await app.inject({
      method: "POST", url: "/web/session",
      payload: { email: "a@t.test", response: signAssertion(cred, second, 2) },
    })).statusCode).toBe(204);

    expect(sessionRowCount(app)).toBe(2);
  });

  it("refuses a challenge minted for one principal but signed by another's credential", async () => {
    const other = seedApprover(app, "prin_b", "b@t.test");
    const challenge = await loginChallengeFor(app, "a@t.test");

    // Presented under B's email with B's key, over A's outstanding challenge.
    const res = await app.inject({
      method: "POST",
      url: "/web/session",
      payload: { email: "b@t.test", response: signAssertion(other, challenge, 1) },
    });

    expect(res.statusCode).toBe(401);
    expect(sessionRowCount(app)).toBe(0);
  });

  it("refuses a credential that belongs to a different principal than the submitted email", async () => {
    seedApprover(app, "prin_b", "b@t.test");
    const challenge = await loginChallengeFor(app, "a@t.test");

    // A's own valid assertion, submitted under B's email.
    const res = await app.inject({
      method: "POST",
      url: "/web/session",
      payload: { email: "b@t.test", response: signAssertion(cred, challenge, 1) },
    });

    expect(res.statusCode).toBe(401);
    expect(sessionRowCount(app)).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// QA-1, closed. Design doc §4.3: "POST /web/session/options must return an
// indistinguishable response for a real address with a credential, a real
// address without one, and an address that does not exist." QA found it did
// not: the handler sent the principal's real allowCredentials when the email
// was registered and `[]` otherwise, leaking both account existence and the
// credential ID itself -- the same oracle routes.attestations.ts's /options
// endpoint already refuses to be for approvals.
//
// Fixed (src/api/routes.web.session.ts) by omitting allowCredentials
// entirely rather than conditionally emptying it. That is not a workaround:
// registration.ts already registers with `residentKey: "preferred"`, so an
// omitted allowCredentials is the standard, spec-documented way to trigger a
// discoverable-credential prompt -- the authenticator itself offers the
// user's passkeys for this RP ID, and the browser reports back which one was
// used. The three cases below are now byte-identical in response shape.
// ---------------------------------------------------------------------------
describe("anti-enumeration: POST /web/session/options (design doc §4.3)", () => {
  async function optionsFor(app: App, email: string) {
    const res = await app.inject({
      method: "POST", url: "/web/session/options", payload: { email },
    });
    expect(res.statusCode).toBe(200);
    return res.json() as { challenge: string; allowCredentials?: Array<{ id: string }> };
  }

  it(
    "does not reveal, via allowCredentials, whether an address has an enrolled passkey",
    async () => {
      const app = await newApp();
      seedApprover(app, "prin_a", "registered@t.test");
      q.insertPrincipal(app.ctx.db, {
        id: "prin_nocred", email: "nopasskey@t.test", display_name: "No Passkey",
      });

      const registered = await optionsFor(app, "registered@t.test");
      const credentialless = await optionsFor(app, "nopasskey@t.test");
      const unknown = await optionsFor(app, "ghost@t.test");

      const shape = (o: { allowCredentials?: Array<{ id: string }> }) =>
        (o.allowCredentials ?? []).length;

      expect(shape(registered)).toBe(shape(credentialless));
      expect(shape(registered)).toBe(shape(unknown));
      expect(shape(registered)).toBe(0);
    },
  );

  it(
    "does not hand an unauthenticated caller a real credential ID for a known email",
    async () => {
      const app = await newApp();
      const cred = seedApprover(app, "prin_a", "registered@t.test");

      const body = (await app.inject({
        method: "POST", url: "/web/session/options", payload: { email: "registered@t.test" },
      })).body;

      // routes.attestations.ts:158-171 refuses to give allowCredentials to a
      // caller who is not a listed approver, precisely so a stranger cannot
      // fish out a real credential ID and use it to forge assertions that
      // spam possible_credential_clone against a real human. This endpoint
      // must not give up the same value on a weaker precondition: knowing
      // the email.
      expect(body).not.toContain(cred.credentialId);
    },
  );

  it("is at least identical between an unknown address and a credential-less one", async () => {
    const app = await newApp();
    q.insertPrincipal(app.ctx.db, {
      id: "prin_nocred", email: "nopasskey@t.test", display_name: "No Passkey",
    });

    const credentialless = await optionsFor(app, "nopasskey@t.test");
    const unknown = await optionsFor(app, "ghost@t.test");

    expect(credentialless.allowCredentials).toEqual(unknown.allowCredentials);
    expect(Object.keys(credentialless).sort()).toEqual(Object.keys(unknown).sort());
  });

  it("mints no redeemable login challenge for an address with no credential", async () => {
    const app = await newApp();
    q.insertPrincipal(app.ctx.db, {
      id: "prin_nocred", email: "nopasskey@t.test", display_name: "No Passkey",
    });

    const { challenge } = await optionsFor(app, "nopasskey@t.test");

    expect(q.consumeLoginChallenge(app.ctx.db, challenge, "prin_nocred")).toBe(false);
    expect(
      (app.ctx.db.prepare(`SELECT COUNT(*) AS c FROM login_challenges`).get() as { c: number }).c,
    ).toBe(0);
  });
});

describe("the session cookie itself", () => {
  async function signIn(app: App, cred: FakeCredential, email: string): Promise<string> {
    const challenge = await loginChallengeFor(app, email);
    const res = await app.inject({
      method: "POST", url: "/web/session",
      payload: { email, response: signAssertion(cred, challenge, 1) },
    });
    expect(res.statusCode).toBe(204);
    return res.headers["set-cookie"] as string;
  }

  it("is HttpOnly, SameSite=Lax and Path=/ so script cannot read it and cross-site POSTs cannot ride it", async () => {
    const app = await newApp();
    const cookie = await signIn(app, seedApprover(app, "prin_a", "a@t.test"), "a@t.test");

    expect(cookie).toContain("HttpOnly");
    expect(cookie).toContain("SameSite=Lax");
    expect(cookie).toContain("Path=/");
  });

  it("omits Secure on an http base URL and sets it on an https one", async () => {
    const insecure = await newApp("http://localhost:3000");
    expect(await signIn(insecure, seedApprover(insecure, "prin_a", "a@t.test"), "a@t.test"))
      .not.toContain("Secure");

    const secure = await newApp("https://attest.example.com");
    expect(await signIn(secure, seedApprover(secure, "prin_a", "a@t.test"), "a@t.test"))
      .toContain("Secure");
  });

  it("carries the opaque session id and never the principal id or email", async () => {
    const app = await newApp();
    const cookie = await signIn(app, seedApprover(app, "prin_a", "a@t.test"), "a@t.test");
    const value = cookie.split(";")[0].slice("ha_session=".length);

    const row = app.ctx.db
      .prepare(`SELECT id FROM sessions`)
      .get() as { id: string };
    expect(value).toBe(row.id);
    expect(cookie).not.toContain("prin_a");
    expect(cookie).not.toContain("a@t.test");
  });
});
