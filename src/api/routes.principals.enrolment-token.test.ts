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
