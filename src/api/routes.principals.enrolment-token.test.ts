// src/api/routes.principals.enrolment-token.test.ts
//
// Finding 3: POST /v1/principals/:id/credentials/options and POST
// /v1/principals/:id/credentials required no authentication and no proof of
// control over the principal. principal_id is not secret — it's embedded in
// the enrol/approve_url query string handed to the human — so anyone who
// learned it could attach their own authenticator to that human's identity
// and later mint a verifiable token claiming that human approved whatever
// the attacker wants.
//
// Fix: a single-use, principal-bound, expiring enrolment token, required by
// both endpoints (passed as ?token=... — neither endpoint's JSON body is the
// right place for it: /credentials's body IS the raw WebAuthn
// RegistrationResponseJSON, not a wrapper object). A missing, wrong,
// expired, or already-used token is rejected exactly like the same
// endpoint's existing "unknown principal" case — no separate code, no
// separate shape — so an attacker can't distinguish "this principal is real
// but my token is wrong" from "this principal doesn't exist".
//
// This is a separate file from routes.principals.test.ts (matching the
// state.race.test.ts precedent) because it mocks webauthn/registration.js's
// finishRegistration to isolate the token-gating logic in this route from
// the real WebAuthn ceremony, which is Ceremony's — already covered by its
// own tests, and not re-creatable here without a full CBOR attestation
// object. beginRegistration is left real: it does no cryptographic
// verification, just an existence check and options generation.
import { describe, it, expect, beforeEach, vi } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

vi.mock("../webauthn/registration.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../webauthn/registration.js")>();
  return {
    ...actual,
    finishRegistration: vi.fn(async (_db: unknown, _principalId: string) => ({
      credential_id: "mock_credential_id",
    })),
  };
});

import { buildServer } from "./server.js";
import { finishRegistration } from "../webauthn/registration.js";
import * as q from "../db/queries.js";
import { FailClosedError } from "../types.js";
import type { Database } from "better-sqlite3";

let app: Awaited<ReturnType<typeof buildServer>>;

beforeEach(async () => {
  vi.mocked(finishRegistration).mockClear();
  app = await buildServer({
    dbPath: ":memory:",
    keyDir: mkdtempSync(join(tmpdir(), "ha-enroltok-")),
  });
});

async function createPrincipal(email: string): Promise<{ principalId: string; token: string }> {
  const res = await app.inject({
    method: "POST", url: "/v1/principals",
    payload: { email, display_name: email },
  });
  const body = res.json();
  return { principalId: body.principal_id, token: body.enrolment_token };
}

describe("POST /v1/principals issues a single-use enrolment token", () => {
  it("returns an enrolment_token alongside principal_id", async () => {
    const res = await app.inject({
      method: "POST", url: "/v1/principals",
      payload: { email: "tok-issue@test.local", display_name: "T" },
    });
    expect(res.statusCode).toBe(201);
    expect(typeof res.json().enrolment_token).toBe("string");
    expect(res.json().enrolment_token.length).toBeGreaterThan(0);
  });

  it("issues a different token for each principal", async () => {
    const a = await createPrincipal("tok-a@test.local");
    const b = await createPrincipal("tok-b@test.local");
    expect(a.token).not.toBe(b.token);
  });
});

describe("POST /v1/principals/:id/credentials/options requires the enrolment token", () => {
  it("rejects a request with no token the same way as a principal that doesn't exist", async () => {
    const { principalId } = await createPrincipal("opt-notoken@test.local");

    const realNoToken = await app.inject({
      method: "POST", url: `/v1/principals/${principalId}/credentials/options`,
    });
    const fakePrincipal = await app.inject({
      method: "POST", url: `/v1/principals/prin_does_not_exist/credentials/options`,
    });

    expect(realNoToken.statusCode).toBe(fakePrincipal.statusCode);
    expect(realNoToken.body).toBe(fakePrincipal.body);
    expect(realNoToken.json().error).toBe("unknown_principal");
  });

  it("rejects a token that belongs to a different principal", async () => {
    const victim = await createPrincipal("opt-victim@test.local");
    const attacker = await createPrincipal("opt-attacker@test.local");

    // Attacker tries to enrol against the victim's principal id, using their
    // own (validly-issued, unexpired, unused) token.
    const res = await app.inject({
      method: "POST",
      url: `/v1/principals/${victim.principalId}/credentials/options?token=${attacker.token}`,
    });
    expect(res.statusCode).toBe(404);
    expect(res.json().error).toBe("unknown_principal");
    expect(res.json()).not.toHaveProperty("challenge");
  });

  it("rejects an expired token", async () => {
    const { principalId } = await createPrincipal("opt-expired@test.local");
    const expiredToken = "tok_expired_manually_inserted";
    app.ctx.db.prepare(
      `INSERT INTO enrolment_tokens (token, principal_id, expires_at, used_at, created_at)
       VALUES (?, ?, ?, NULL, ?)`,
    ).run(expiredToken, principalId, new Date(Date.now() - 1000).toISOString(), new Date().toISOString());

    const res = await app.inject({
      method: "POST", url: `/v1/principals/${principalId}/credentials/options?token=${expiredToken}`,
    });
    expect(res.statusCode).toBe(404);
    expect(res.json().error).toBe("unknown_principal");
  });

  it("accepts the correct, unused, unexpired token and returns real registration options", async () => {
    const { principalId, token } = await createPrincipal("opt-valid@test.local");

    const res = await app.inject({
      method: "POST", url: `/v1/principals/${principalId}/credentials/options?token=${token}`,
    });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toHaveProperty("challenge");
  });

  it("does not consume the token on its own (options is a peek, not a burn)", async () => {
    const { principalId, token } = await createPrincipal("opt-peek@test.local");

    await app.inject({ method: "POST", url: `/v1/principals/${principalId}/credentials/options?token=${token}` });
    const second = await app.inject({
      method: "POST", url: `/v1/principals/${principalId}/credentials/options?token=${token}`,
    });
    expect(second.statusCode).toBe(200);
  });
});

describe("POST /v1/principals/:id/credentials requires the enrolment token", () => {
  it("rejects a request with no token the same way as a principal with no pending registration", async () => {
    const { principalId } = await createPrincipal("fin-notoken@test.local");

    const realNoToken = await app.inject({
      method: "POST", url: `/v1/principals/${principalId}/credentials`, payload: {},
    });
    const fakePrincipal = await app.inject({
      method: "POST", url: `/v1/principals/prin_does_not_exist/credentials`, payload: {},
    });

    expect(realNoToken.statusCode).toBe(fakePrincipal.statusCode);
    expect(realNoToken.body).toBe(fakePrincipal.body);
    expect(realNoToken.json().error).toBe("no_pending_registration");
    expect(finishRegistration).not.toHaveBeenCalled();
  });

  it("rejects a token bound to a different principal, and never calls finishRegistration", async () => {
    const victim = await createPrincipal("fin-victim@test.local");
    const attacker = await createPrincipal("fin-attacker@test.local");
    await app.inject({
      method: "POST",
      url: `/v1/principals/${attacker.principalId}/credentials/options?token=${attacker.token}`,
    });

    const res = await app.inject({
      method: "POST",
      url: `/v1/principals/${victim.principalId}/credentials?token=${attacker.token}`,
      payload: { id: "forged" },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe("no_pending_registration");
    expect(finishRegistration).not.toHaveBeenCalled();
  });

  it("with the correct token, completes registration and burns the token (single-use)", async () => {
    const { principalId, token } = await createPrincipal("fin-valid@test.local");
    await app.inject({
      method: "POST", url: `/v1/principals/${principalId}/credentials/options?token=${token}`,
    });

    const first = await app.inject({
      method: "POST", url: `/v1/principals/${principalId}/credentials?token=${token}`,
      payload: { id: "cred_1" },
    });
    expect(first.statusCode).toBe(201);
    expect(finishRegistration).toHaveBeenCalledTimes(1);

    // Re-run begin+finish with the SAME token: it must now be rejected, even
    // though it was, at the time it was first presented, entirely valid.
    await app.inject({
      method: "POST", url: `/v1/principals/${principalId}/credentials/options?token=${token}`,
    });
    const second = await app.inject({
      method: "POST", url: `/v1/principals/${principalId}/credentials?token=${token}`,
      payload: { id: "cred_2" },
    });
    expect(second.statusCode).toBe(400);
    expect(second.json().error).toBe("no_pending_registration");
    expect(finishRegistration).toHaveBeenCalledTimes(1);
  });
});

// Bug: a failed enrolment ceremony permanently bricks the principal.
//
// The route used to consume (burn) the single-use enrolment token BEFORE
// calling finishRegistration -- so any ceremony failure (malformed
// response, origin mismatch, wrong browser, anything) left the token
// already spent with no way to retry and no re-issue endpoint. Since
// principals.email is UNIQUE, that principal could never enrol a passkey
// again.
//
// Fix: verify first (finishRegistration), and only burn the token once
// that verification actually succeeds. Because finishRegistration
// (src/webauthn/registration.ts) persists the credential as an
// inseparable part of a successful verification -- it cannot verify
// without writing, and this file must not touch webauthn/registration.ts
// -- two different, genuinely-successful ceremonies (two different
// authenticators) can both reach that persistence step while racing on
// one still-unspent token. The atomic consumeEnrolmentToken call after
// verification is what decides the single winner; the loser's
// already-persisted row is deleted (queries.ts's deleteCredential) so it
// never actually attaches to the principal, and the loser is rejected
// with the exact same opaque shape a spent token always produces.
describe("a failed enrolment ceremony must not permanently brick the principal", () => {
  it("a failed/garbage registration response leaves the enrolment token unspent in the DB", async () => {
    const { principalId, token } = await createPrincipal("brick-repro@test.local");
    await app.inject({
      method: "POST", url: `/v1/principals/${principalId}/credentials/options?token=${token}`,
    });

    vi.mocked(finishRegistration).mockRejectedValueOnce(
      new FailClosedError("registration_failed", 400, "registration could not be verified"),
    );
    const failed = await app.inject({
      method: "POST", url: `/v1/principals/${principalId}/credentials?token=${token}`,
      payload: { garbage: "not a real webauthn response" },
    });
    expect(failed.statusCode).toBe(400);

    const row = app.ctx.db.prepare(`SELECT used_at FROM enrolment_tokens WHERE token = ?`).get(token) as
      { used_at: string | null };
    expect(row.used_at).toBeNull();
  });

  it("a second, genuine registration attempt under the same token succeeds after a failed first attempt", async () => {
    const { principalId, token } = await createPrincipal("brick-retry@test.local");
    await app.inject({
      method: "POST", url: `/v1/principals/${principalId}/credentials/options?token=${token}`,
    });

    vi.mocked(finishRegistration).mockRejectedValueOnce(
      new FailClosedError("registration_failed", 400, "registration could not be verified"),
    );
    const failed = await app.inject({
      method: "POST", url: `/v1/principals/${principalId}/credentials?token=${token}`,
      payload: { garbage: "not a real webauthn response" },
    });
    expect(failed.statusCode).toBe(400);

    // Retry, same token, this time a genuine ceremony (mock resolves
    // normally again -- the default implementation set in beforeEach).
    await app.inject({
      method: "POST", url: `/v1/principals/${principalId}/credentials/options?token=${token}`,
    });
    const retry = await app.inject({
      method: "POST", url: `/v1/principals/${principalId}/credentials?token=${token}`,
      payload: { id: "genuine_cred_after_retry" },
    });
    expect(retry.statusCode).toBe(201);

    const row = app.ctx.db.prepare(`SELECT used_at FROM enrolment_tokens WHERE token = ?`).get(token) as
      { used_at: string | null };
    expect(row.used_at).not.toBeNull();
  });

  it("a successful ceremony still burns the token -- a second attempt is rejected the same way a spent token always is", async () => {
    const { principalId, token } = await createPrincipal("burn-on-success@test.local");
    await app.inject({
      method: "POST", url: `/v1/principals/${principalId}/credentials/options?token=${token}`,
    });
    const first = await app.inject({
      method: "POST", url: `/v1/principals/${principalId}/credentials?token=${token}`,
      payload: { id: "cred_first" },
    });
    expect(first.statusCode).toBe(201);

    await app.inject({
      method: "POST", url: `/v1/principals/${principalId}/credentials/options?token=${token}`,
    });
    const second = await app.inject({
      method: "POST", url: `/v1/principals/${principalId}/credentials?token=${token}`,
      payload: { id: "cred_second_valid_looking" },
    });
    expect(second.statusCode).toBe(400);
    expect(second.json()).toEqual({
      error: "no_pending_registration",
      message: "no pending registration challenge for this principal",
    });
  });

  it("two concurrent, genuinely-successful ceremonies (two different authenticators) racing on one still-unspent token: exactly one credential persists, the other is rejected identically to a spent-token rejection", async () => {
    const { principalId, token } = await createPrincipal("race-two-auth@test.local");
    await app.inject({
      method: "POST", url: `/v1/principals/${principalId}/credentials/options?token=${token}`,
    });

    // Each mock implementation does what the real finishRegistration does on
    // success (src/webauthn/registration.ts): persists a credential row,
    // then returns its credential_id. A small delay forces both requests to
    // genuinely be in flight together, rather than relying on incidental
    // Fastify dispatch timing.
    vi.mocked(finishRegistration)
      .mockImplementationOnce(async (db, pid) => {
        await new Promise((resolve) => setTimeout(resolve, 15));
        q.insertCredential(db as Database, {
          id: "cred_row_authenticator_1", principal_id: pid as string, credential_id: "authenticator_1",
          public_key: Buffer.from([1]), transports: null,
        });
        return { credential_id: "authenticator_1" };
      })
      .mockImplementationOnce(async (db, pid) => {
        await new Promise((resolve) => setTimeout(resolve, 15));
        q.insertCredential(db as Database, {
          id: "cred_row_authenticator_2", principal_id: pid as string, credential_id: "authenticator_2",
          public_key: Buffer.from([2]), transports: null,
        });
        return { credential_id: "authenticator_2" };
      });

    const [r1, r2] = await Promise.allSettled([
      app.inject({
        method: "POST", url: `/v1/principals/${principalId}/credentials?token=${token}`,
        payload: { id: "authenticator_1" },
      }),
      app.inject({
        method: "POST", url: `/v1/principals/${principalId}/credentials?token=${token}`,
        payload: { id: "authenticator_2" },
      }),
    ]);

    const results = [r1, r2].map((r) => (r.status === "fulfilled" ? r.value : null));
    const codes = results.map((r) => r?.statusCode);
    expect(codes.filter((c) => c === 201).length).toBe(1);
    expect(codes.filter((c) => c === 400).length).toBe(1);

    const loser = results.find((r) => r?.statusCode === 400);
    expect(loser?.json()).toEqual({
      error: "no_pending_registration",
      message: "no pending registration challenge for this principal",
    });

    const row = app.ctx.db.prepare(
      `SELECT COUNT(*) as n FROM credentials WHERE principal_id = ?`,
    ).get(principalId) as { n: number };
    expect(row.n).toBe(1);

    // The rejection is byte-for-byte identical to an ordinary already-spent
    // token rejection -- no distinguishable "you lost a race" signal.
    const spentTokenProbe = await app.inject({
      method: "POST", url: `/v1/principals/${principalId}/credentials?token=${token}`,
      payload: { id: "third_attempt" },
    });
    expect(spentTokenProbe.statusCode).toBe(400);
    expect(loser?.body).toBe(spentTokenProbe.body);
  });
});
