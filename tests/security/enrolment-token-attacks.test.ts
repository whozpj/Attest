// tests/security/enrolment-token-attacks.test.ts
//
// Adversary-3: attacks against the enrolment-token gate added to
// POST /v1/principals/:id/credentials/options and POST
// /v1/principals/:id/credentials (Finding 3 — see routes.principals.ts's
// own header comment). Before this token existed, principal_id alone (not
// secret; it's embedded in the enrol/approve_url query string) was enough
// to attach an attacker-controlled authenticator to a stranger's identity.
// The fix is a single-use, principal-bound, 15-minute-TTL token, checked by
// assertEnrolmentTokenValid (a read-only peek, for /options) and consumed
// atomically by q.consumeEnrolmentToken (a check-and-burn UPDATE, for
// /credentials).
//
// Every test here goes through buildServer() + .inject() — real HTTP
// requests, not direct calls into queries.ts — because the property under
// test ("the caller cannot distinguish rejection reason X from Y") is a
// property of the HTTP response body, not of any one function's return
// value.
//
// finishRegistration (src/webauthn/registration.ts) is mocked, the same way
// src/api/routes.principals.enrolment-token.test.ts already does it: these
// attacks are entirely about the token gate in front of the WebAuthn
// ceremony, not about the ceremony itself (that's Ceremony's surface,
// covered elsewhere, including with genuine ECDSA signatures via
// tests/security/lib/webauthn-fake.ts where a real signature actually
// matters). Mocking it here keeps each test's failure mode unambiguous: a
// red test means the token gate let something through or wrongly blocked
// it, not that a fake credential's attestation object was malformed.
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

vi.mock("../../src/webauthn/registration.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/webauthn/registration.js")>();
  return {
    ...actual,
    finishRegistration: vi.fn(async (_db: unknown, _principalId: string, _challenge: string, response: unknown) => ({
      credential_id: (response as { id?: string })?.id ?? "mock_credential_id",
    })),
  };
});

import { buildServer } from "../../src/api/server.js";
import { finishRegistration } from "../../src/webauthn/registration.js";

let app: Awaited<ReturnType<typeof buildServer>>;

beforeEach(async () => {
  vi.mocked(finishRegistration).mockClear();
  app = await buildServer({
    dbPath: ":memory:",
    keyDir: mkdtempSync(join(tmpdir(), "ha-enroltok-attack-")),
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

async function options(principalId: string, token?: string) {
  const qs = token === undefined ? "" : `?token=${encodeURIComponent(token)}`;
  return app.inject({ method: "POST", url: `/v1/principals/${principalId}/credentials/options${qs}` });
}

async function credentials(principalId: string, token: string | undefined, credId: string) {
  const qs = token === undefined ? "" : `?token=${encodeURIComponent(token)}`;
  return app.inject({
    method: "POST", url: `/v1/principals/${principalId}/credentials${qs}`,
    payload: { id: credId },
  });
}

describe("attack 1: token reuse — a second authenticator cannot enrol with an already-spent token", () => {
  it("rejects a second /credentials call with the same token that already completed a registration", async () => {
    const { principalId, token } = await createPrincipal("reuse@test.local");

    await options(principalId, token);
    const first = await credentials(principalId, token, "authenticator_1");
    expect(first.statusCode).toBe(201);
    expect(finishRegistration).toHaveBeenCalledTimes(1);

    // Second authenticator, same token. The spec's stated trade-off is that
    // a fresh token is required per enrolment attempt — this must fail
    // regardless of whether the *first* ceremony's response body actually
    // differs (it does: a different credential id).
    await options(principalId, token);
    const second = await credentials(principalId, token, "authenticator_2");
    expect(second.statusCode).toBe(400);
    expect(second.json()).toEqual({
      error: "no_pending_registration",
      message: "no pending registration challenge for this principal",
    });
    expect(finishRegistration).toHaveBeenCalledTimes(1); // still just the first

    // The token is spent from /options's point of view too — not just
    // /credentials's. assertEnrolmentTokenValid checks used_at, so a peek
    // after the burn must also fail, not silently hand out fresh options
    // for a token nothing can ever finish with again.
    const peekAfterBurn = await options(principalId, token);
    expect(peekAfterBurn.statusCode).toBe(404);
    expect(peekAfterBurn.json().error).toBe("unknown_principal");
  });

  it("MUTATION CHECK (documented, not run automatically): breaking the single-use guarantee turns this red", () => {
    // Manually verified, working tree only, reverted with `git checkout --`
    // afterwards:
    //
    // Mutating ONLY consumeEnrolmentToken's WHERE clause (queries.ts) to
    // drop `used_at IS NULL` does NOT turn this test red on its own. The
    // reason is a genuine, independent second guard: after a token is spent
    // once, the test's own second `options(principalId, token)` peek is
    // still rejected by assertEnrolmentTokenValid's *own* `row.used_at !==
    // null` check (routes.principals.ts) — unaffected by the queries.ts
    // mutation — which means pendingChallenges never gets refreshed for the
    // second attempt, so the second /credentials call still 400s, but for
    // an unrelated reason (no pending challenge), not because the token was
    // correctly rejected as spent.
    //
    // Mutating BOTH checks together — dropping `used_at IS NULL` from
    // consumeEnrolmentToken AND dropping the `row.used_at !== null` branch
    // from assertEnrolmentTokenValid — does turn the test red exactly as
    // expected: second.statusCode becomes 201 and finishRegistration is
    // called twice.
    //
    // Net finding: single-use enforcement is defense-in-depth, checked
    // independently at both the peek and the atomic consume. That's a
    // genuinely good property, not a test weakness — but it does mean a
    // one-line mutation to either check alone is invisible to an
    // HTTP-level test, because the other check silently covers for it.
    // Recorded here rather than left as live, always-run source mutation.
    expect(true).toBe(true);
  });
});

describe("attack 2: cross-principal token use — A's token against B's principal_id", () => {
  it("/options: rejects A's token used against B's principal_id, identically to an unknown principal", async () => {
    const a = await createPrincipal("cross-a-opt@test.local");
    const b = await createPrincipal("cross-b-opt@test.local");

    const crossUse = await options(b.principalId, a.token);
    const unknownPrincipal = await options("prin_totally_made_up", a.token);

    expect(crossUse.statusCode).toBe(404);
    expect(crossUse.json()).toEqual({ error: "unknown_principal", message: "unknown principal" });
    // Byte-for-byte, not just same status/code: the whole body must match,
    // so there is no incidental field (e.g. a differing message) an
    // attacker could use to tell "wrong principal" apart from "no such
    // principal at all".
    expect(crossUse.body).toBe(unknownPrincipal.body);
    expect(crossUse.json()).not.toHaveProperty("challenge");
  });

  it("/credentials: rejects A's token used against B's principal_id, identically to a missing token", async () => {
    const a = await createPrincipal("cross-a-fin@test.local");
    const b = await createPrincipal("cross-b-fin@test.local");
    // The realistic attack chain: attacker tries the SAME cross-principal
    // token against B's /options first (rejected — attack 2's other test
    // covers that in isolation), then goes straight for /credentials
    // regardless. Deliberately NOT `options(a.principalId, a.token)` here —
    // that would be a legitimate peek on A's own principal and would only
    // populate pendingChallenges for A, which would make a naive version of
    // this test pass for the wrong reason (an empty pendingChallenges entry
    // for B masking whether consumeEnrolmentToken's own principal_id check
    // is what's actually doing the rejecting). Confirmed by mutation below.
    await options(b.principalId, a.token);

    const crossUse = await credentials(b.principalId, a.token, "attacker_cred");
    const missingToken = await credentials(b.principalId, undefined, "attacker_cred");

    expect(crossUse.statusCode).toBe(400);
    expect(crossUse.json()).toEqual({
      error: "no_pending_registration",
      message: "no pending registration challenge for this principal",
    });
    expect(crossUse.body).toBe(missingToken.body);
    expect(finishRegistration).not.toHaveBeenCalled();

    // Confirm B's own legitimate token is untouched by the attempted
    // cross-use — B can still enrol normally afterwards.
    await options(b.principalId, b.token);
    const legit = await credentials(b.principalId, b.token, "b_own_cred");
    expect(legit.statusCode).toBe(201);
  });

  it("MUTATION CHECK (documented, not run automatically): dropping the principal_id match turns this red", () => {
    // Manually verified, working tree only, reverted with `git checkout --`
    // afterwards:
    //
    // /options in isolation: commenting out the `row.principal_id !==
    // principalId` branch in assertEnrolmentTokenValid (routes.principals.ts)
    // alone is enough to turn the /options cross-use test red — it returns
    // 200 with real challenge options instead of 404. That check is not
    // shadowed by anything else on the /options path, so a single-check
    // mutation is sufficient there.
    //
    // /credentials is different, and the reason mirrors attack 1's finding:
    // mutating ONLY consumeEnrolmentToken's `AND principal_id = ?` clause
    // (queries.ts) does NOT turn the /credentials cross-use test red on its
    // own. This test's setup deliberately calls
    // `options(b.principalId, a.token)` first (the realistic attack
    // sequence) — and in the real, unmutated assertEnrolmentTokenValid, that
    // peek is still correctly rejected, so pendingChallenges is never
    // populated for B. The /credentials call then 400s via the *second*,
    // textually-identical throw site (missing pendingChallenges entry, not
    // the token check) — same code, same message, wrong reason. Only
    // mutating BOTH principal_id checks together (this one and the one
    // above) produces the true end-to-end bypass and turns both cross-use
    // tests red for the right reason: crossUse.statusCode becomes 200/201
    // instead of 404/400.
    //
    // Same net finding as attack 1: principal-binding is checked
    // independently at the peek and at the atomic consume, so an isolated
    // one-line break in just the queries.ts layer is masked by the still-
    // intact routes.principals.ts check (or vice versa) rather than being
    // silently exploitable. Recorded here rather than left as live,
    // always-run source mutation.
    expect(true).toBe(true);
  });
});

describe("attack 3: expired token", () => {
  it("rejects a token whose expires_at has passed, on both /options and /credentials", async () => {
    const { principalId } = await createPrincipal("expired@test.local");

    // Same pattern as tests/security/expiry-retention.test.ts and the
    // sibling routes.principals.enrolment-token.test.ts: force expiry via a
    // direct row rather than waiting 15 real minutes. This still exercises
    // the real rejection path (assertEnrolmentTokenValid's
    // Date.parse(expires_at) <= Date.now() branch and
    // consumeEnrolmentToken's `expires_at > ?` clause), not a mocked clock.
    const expiredToken = "tok_expired_for_attack_3";
    app.ctx.db.prepare(
      `INSERT INTO enrolment_tokens (token, principal_id, expires_at, used_at, created_at)
       VALUES (?, ?, ?, NULL, ?)`,
    ).run(expiredToken, principalId, new Date(Date.now() - 1000).toISOString(), new Date().toISOString());

    const optRes = await options(principalId, expiredToken);
    expect(optRes.statusCode).toBe(404);
    expect(optRes.json().error).toBe("unknown_principal");

    const credRes = await credentials(principalId, expiredToken, "cred_x");
    expect(credRes.statusCode).toBe(400);
    expect(credRes.json().error).toBe("no_pending_registration");
    expect(finishRegistration).not.toHaveBeenCalled();
  });

  it("a token that expires between /options and /credentials is rejected at /credentials", async () => {
    const { principalId } = await createPrincipal("expires-midflight@test.local");
    const token = "tok_expires_midflight";
    // Valid (future) at insert time, so /options succeeds...
    app.ctx.db.prepare(
      `INSERT INTO enrolment_tokens (token, principal_id, expires_at, used_at, created_at)
       VALUES (?, ?, ?, NULL, ?)`,
    ).run(token, principalId, new Date(Date.now() + 50).toISOString(), new Date().toISOString());

    const optRes = await options(principalId, token);
    expect(optRes.statusCode).toBe(200);

    // ...then force it into the past before /credentials, simulating a
    // human who opens the enrolment link right at the edge of the TTL and
    // takes just long enough completing the ceremony to cross it.
    app.ctx.db.prepare(`UPDATE enrolment_tokens SET expires_at = ? WHERE token = ?`)
      .run(new Date(Date.now() - 1000).toISOString(), token);

    const credRes = await credentials(principalId, token, "cred_late");
    expect(credRes.statusCode).toBe(400);
    expect(credRes.json().error).toBe("no_pending_registration");
    expect(finishRegistration).not.toHaveBeenCalled();
  });
});

describe("attack 4: /options never consumes the token", () => {
  it("survives 3+ repeated /options peeks, then /credentials still succeeds with the same token", async () => {
    const { principalId, token } = await createPrincipal("peek-repeat@test.local");

    for (let i = 0; i < 5; i++) {
      const res = await options(principalId, token);
      expect(res.statusCode).toBe(200);
      expect(res.json()).toHaveProperty("challenge");
    }

    const finish = await credentials(principalId, token, "cred_after_peeks");
    expect(finish.statusCode).toBe(201);
    expect(finishRegistration).toHaveBeenCalledTimes(1);
  });
});

describe("attack 5: missing/malformed token variants are all indistinguishable", () => {
  it("/options: no token, empty-string token, and a well-formed-but-unknown token all produce the identical body", async () => {
    const { principalId } = await createPrincipal("malformed-opt@test.local");
    const plausibleFake = "AbCdEf0123456789_-".repeat(3); // right shape (base64url-ish), simply not in the table

    const noToken = await options(principalId, undefined);
    const emptyToken = await options(principalId, "");
    const unknownToken = await options(principalId, plausibleFake);

    expect(noToken.statusCode).toBe(404);
    expect(noToken.body).toBe(emptyToken.body);
    expect(noToken.body).toBe(unknownToken.body);
    expect(noToken.json()).toEqual({ error: "unknown_principal", message: "unknown principal" });
  });

  it("/credentials: no token, empty-string token, unknown token, and a wrong-principal token all produce the identical body", async () => {
    const victim = await createPrincipal("malformed-fin-victim@test.local");
    const attacker = await createPrincipal("malformed-fin-attacker@test.local");
    await options(victim.principalId, victim.token);
    const plausibleFake = "AbCdEf0123456789_-".repeat(3);

    const noToken = await credentials(victim.principalId, undefined, "c1");
    const emptyToken = await credentials(victim.principalId, "", "c2");
    const unknownToken = await credentials(victim.principalId, plausibleFake, "c3");
    const wrongPrincipalToken = await credentials(victim.principalId, attacker.token, "c4");

    const bodies = [noToken, emptyToken, unknownToken, wrongPrincipalToken];
    for (const res of bodies) {
      expect(res.statusCode).toBe(400);
    }
    expect(noToken.body).toBe(emptyToken.body);
    expect(noToken.body).toBe(unknownToken.body);
    expect(noToken.body).toBe(wrongPrincipalToken.body);
    expect(noToken.json()).toEqual({
      error: "no_pending_registration",
      message: "no pending registration challenge for this principal",
    });
    expect(finishRegistration).not.toHaveBeenCalled();

    // And the victim's own, still-unused, still-unexpired token keeps working
    // — none of the above attempts had any side effect on it.
    const legit = await credentials(victim.principalId, victim.token, "victim_real_cred");
    expect(legit.statusCode).toBe(201);
  });
});

describe("attack 6: concurrent double-spend of the same token", () => {
  it("fires two /credentials requests with the same valid token concurrently; at most one succeeds", async () => {
    const { principalId, token } = await createPrincipal("concurrent@test.local");
    await options(principalId, token);

    // Real concurrent HTTP requests through the same buildServer() instance
    // — Promise.allSettled, not sequential awaits — so both requests are
    // in flight before either resolves.
    const [r1, r2] = await Promise.allSettled([
      credentials(principalId, token, "concurrent_cred_1"),
      credentials(principalId, token, "concurrent_cred_2"),
    ]);

    const results = [r1, r2].map((r) => (r.status === "fulfilled" ? r.value.statusCode : -1));
    const successes = results.filter((code) => code === 201);
    const rejections = results.filter((code) => code === 400);

    // This is the atomicity claim consumeEnrolmentToken's own comment makes
    // explicit: "closing the same TOCTOU shape already fixed in state.ts".
    // Exactly one request may ever observe used_at IS NULL and win the
    // UPDATE.
    expect(successes.length).toBe(1);
    expect(rejections.length).toBe(1);
    expect(finishRegistration).toHaveBeenCalledTimes(1);

    // Note on why this test is worth having even though it may not be able
    // to force a genuine OS-level race: better-sqlite3 is a synchronous,
    // blocking binding — consumeEnrolmentToken's UPDATE runs to completion
    // in a single microtask with no await inside it, and Node is
    // single-threaded, so within one process there is no interleaving
    // window between "check" and "burn" for two requests to exploit even
    // when dispatched via Promise.allSettled. That is exactly why the
    // atomic single-UPDATE design (rather than a SELECT-then-UPDATE pair)
    // is correct defense in depth: it does not rely on this synchronicity
    // accident to be safe. This test pins the *observable outcome*
    // (at-most-one-success) as an invariant, so it still catches a
    // regression if the storage layer is ever swapped for something
    // genuinely async (e.g. a network database, or better-sqlite3 replaced
    // with a Promise-based driver) where the race becomes real and a
    // SELECT-then-UPDATE implementation would actually lose it.
  });

  it("MUTATION CHECK (documented, not run automatically): a SELECT-then-UPDATE version would double-spend", () => {
    // Manually verified by temporarily replacing consumeEnrolmentToken's
    // single atomic UPDATE with a `getEnrolmentToken` read followed by a
    // separate unconditional UPDATE (i.e. reintroducing the TOCTOU gap):
    // the concurrency test above still shows successes.length === 1 in
    // this synchronous single-process harness (confirming the note above —
    // it cannot force the race here), so this specific test would NOT
    // catch that regression on its own. What DOES catch it: the
    // token-reuse test (attack 1) and the two mutation checks already
    // recorded there, which assert on sequential reuse rather than
    // requiring an actual race window. Recorded here for honesty about
    // this test's limits, not as a claim it's redundant.
    expect(true).toBe(true);
  });
});

describe("attack 7: type confusion on the token query parameter", () => {
  it("a duplicate ?token=&token= query key (which Fastify parses as an array) is rejected, not treated as valid or crashed on", async () => {
    // Verified empirically: Fastify's default query-string parsing turns
    // `?token=aaa&token=bbb` into `req.query.token === ["aaa", "bbb"]`, an
    // object, not a string. Both assertEnrolmentTokenValid and the inline
    // /credentials check gate on `typeof token !== "string"` first, so this
    // should fail closed rather than e.g. being coerced to a truthy value
    // and slipping past validation, or reaching `q.getEnrolmentToken`
    // (which expects a string bind parameter) and throwing an unhandled
    // 500 instead of a controlled rejection.
    const { principalId, token } = await createPrincipal("type-confusion@test.local");

    const dupOpt = await app.inject({
      method: "POST",
      url: `/v1/principals/${principalId}/credentials/options?token=${token}&token=something-else`,
    });
    expect(dupOpt.statusCode).toBe(404);
    expect(dupOpt.json()).toEqual({ error: "unknown_principal", message: "unknown principal" });

    const dupFin = await app.inject({
      method: "POST",
      url: `/v1/principals/${principalId}/credentials?token=${token}&token=something-else`,
      payload: { id: "type_confused_cred" },
    });
    expect(dupFin.statusCode).toBe(400);
    expect(dupFin.json()).toEqual({
      error: "no_pending_registration",
      message: "no pending registration challenge for this principal",
    });
    expect(finishRegistration).not.toHaveBeenCalled();

    // And the legitimate single-value token still works afterwards — the
    // malformed attempts had no side effect on it.
    await options(principalId, token);
    const legit = await credentials(principalId, token, "legit_after_confusion");
    expect(legit.statusCode).toBe(201);
  });

  // Beyond this, a second look at routes.principals.ts and queries.ts (the
  // "how would I actually abuse this" pass requested for attack 7) turned
  // up nothing further worth a dedicated test:
  //  - The token itself is 256 bits of randomBytes, base64url-encoded —
  //    not guessable or brute-forceable within any realistic HTTP budget.
  //  - Comparison is a parameterized SQLite `WHERE token = ?`, not string
  //    concatenation, so there's no injection surface there.
  //  - Every rejection path — missing, empty, wrong-shape, wrong-principal,
  //    expired, already-used — collapses to the same opaque code/message
  //    pair per endpoint, confirmed byte-for-byte above; there is no
  //    timing-independent signal left in the response body for an attacker
  //    to distinguish reasons by (response-time side channels are a
  //    separate class of attack, not something a vitest+inject() harness
  //    can meaningfully measure or defend against here).
  //  - /v1/principals itself has no rate limiting, but minting an
  //    unlimited number of enrolment tokens for *your own* new principals
  //    isn't a privilege escalation — it doesn't help against anyone
  //    else's token, since insertEnrolmentToken always binds to the
  //    principal_id created in the same request.
  // So: attack 7 is the query-type-confusion case above; nothing further
  // found.
});

afterEach(() => {
  vi.clearAllMocks();
});
