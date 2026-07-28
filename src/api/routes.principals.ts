import { randomBytes, randomUUID } from "node:crypto";
import type { Database } from "better-sqlite3";
import type { FastifyInstance } from "fastify";
import type { AppContext } from "./server.js";
import * as q from "../db/queries.js";
import { beginRegistration, finishRegistration } from "../webauthn/registration.js";
import { FailClosedError } from "../types.js";
import { withAuditDetail } from "../audit-detail.js";

const pendingChallenges = new Map<string, string>();

// 15 minutes: long enough for a human to open the enrolment link and
// complete a WebAuthn ceremony, short enough that a leaked/unused token
// doesn't stay live indefinitely.
const ENROLMENT_TOKEN_TTL_SECONDS = 900;

/**
 * Finding 3: both credential-enrolment endpoints took only a principal_id —
 * not secret, since it's embedded in the enrol/approve_url query string
 * handed to the human — as proof that the caller controls that principal.
 * Anyone who learned a principal_id could attach their own authenticator to
 * a stranger's identity and later mint a verifiable token claiming that
 * stranger approved anything.
 *
 * The fix is a single-use, principal-bound, expiring token, checked against
 * whatever the caller presents in `?token=`. It deliberately does NOT
 * distinguish *why* the token was rejected (missing, wrong principal,
 * expired, already used) in anything visible to the caller — only in the
 * audit-only detail string, via withAuditDetail — for the same
 * anti-enumeration reason the rest of this file already follows: a
 * distinguishable rejection is a probe an attacker can iterate on.
 */
function rejectInvalidToken(code: string, httpStatus: number, message: string, detail: string): never {
  throw withAuditDetail(new FailClosedError(code, httpStatus, message), detail);
}

/**
 * Read-only check for POST .../credentials/options: confirms the token
 * exists, matches this principal, and isn't expired or already used, without
 * consuming it. Options is the "begin" half of a two-step ceremony — burning
 * the token here would make it impossible to ever reach "finish" with it.
 * Mirrors beginRegistration's own rejection (unknown_principal, 404) so a bad
 * token is indistinguishable from a principal that doesn't exist at all.
 */
export function assertEnrolmentTokenValid(db: Database, principalId: string, token: unknown): void {
  if (typeof token !== "string" || token.length === 0) {
    rejectInvalidToken("unknown_principal", 404, "unknown principal", "missing enrolment token");
  }
  const row = q.getEnrolmentToken(db, token);
  if (!row) {
    rejectInvalidToken("unknown_principal", 404, "unknown principal", "unknown enrolment token");
  }
  if (row.principal_id !== principalId) {
    rejectInvalidToken(
      "unknown_principal", 404, "unknown principal", "enrolment token bound to a different principal",
    );
  }
  if (row.used_at !== null) {
    rejectInvalidToken("unknown_principal", 404, "unknown principal", "enrolment token already used");
  }
  if (Date.parse(row.expires_at) <= Date.now()) {
    rejectInvalidToken("unknown_principal", 404, "unknown principal", "enrolment token expired");
  }
}

/**
 * Non-consuming peek for POST .../credentials, mirroring
 * assertEnrolmentTokenValid's four conditions (exists, bound to this
 * principal, unused, unexpired) but as a boolean rather than a throw --
 * this endpoint's opaque rejection is "no_pending_registration"/400, not
 * options's "unknown_principal"/404, so it can't just call that function.
 * Deliberately read-only: the actual single-use burn happens later, via
 * consumeEnrolmentToken, only after a successful ceremony.
 */
function enrolmentTokenLooksUsable(db: Database, principalId: string, token: unknown): boolean {
  if (typeof token !== "string" || token.length === 0) return false;
  const row = q.getEnrolmentToken(db, token);
  if (!row) return false;
  if (row.principal_id !== principalId) return false;
  if (row.used_at !== null) return false;
  if (Date.parse(row.expires_at) <= Date.now()) return false;
  return true;
}

export function registerPrincipalRoutes(app: FastifyInstance & { ctx: AppContext }): void {
  app.post("/v1/principals", async (req, reply) => {
    const body = req.body as { email?: unknown; display_name?: unknown };
    const email = body.email;
    const display_name = body.display_name;

    // One opaque code and message for both a malformed body and a duplicate
    // email. Spec's "say why without leaking" principle: a distinct
    // duplicate-email error would be an account-enumeration vector on an
    // enrolment endpoint. The audit row (written centrally, in server.ts's
    // error handler) still records which one actually happened via
    // withAuditDetail — server-side only, never echoed in the response.
    if (typeof email !== "string" || email.length === 0 ||
        typeof display_name !== "string" || display_name.length === 0) {
      throw withAuditDetail(
        new FailClosedError("principal_invalid", 400, "email and display_name are required"),
        "malformed enrolment body",
      );
    }

    const id = `prin_${randomUUID()}`;
    try {
      q.insertPrincipal(app.ctx.db, { id, email, display_name });
    } catch {
      throw withAuditDetail(
        new FailClosedError("principal_invalid", 400, "email and display_name are required"),
        `duplicate email: ${email}`,
      );
    }

    // Finding 3: issue the single-use enrolment token here, at creation, so
    // whoever delivers the enrolment link to the human (out of band — email,
    // Slack, etc. — genuinely out of scope for this prototype) has something
    // to include in it besides the non-secret principal_id.
    const enrolment_token = randomBytes(32).toString("base64url");
    q.insertEnrolmentToken(app.ctx.db, {
      token: enrolment_token, principal_id: id,
      expires_at: new Date(Date.now() + ENROLMENT_TOKEN_TTL_SECONDS * 1000).toISOString(),
    });

    return reply.status(201).send({ principal_id: id, enrolment_token });
  });

  app.post("/v1/principals/:id/credentials/options", async (req) => {
    const { id } = req.params as { id: string };
    const { token } = req.query as { token?: unknown };
    assertEnrolmentTokenValid(app.ctx.db, id, token);

    const options = await beginRegistration(app.ctx.db, id);
    pendingChallenges.set(id, options.challenge);
    return options;
  });

  app.post("/v1/principals/:id/credentials", async (req, reply) => {
    const { id } = req.params as { id: string };
    const { token } = req.query as { token?: unknown };

    // Bug fixed here: this used to consume (burn) the token BEFORE calling
    // finishRegistration, so any ceremony failure (malformed response,
    // origin mismatch, wrong browser, anything) left the token already
    // spent -- with no re-issue endpoint anywhere, and principals.email
    // UNIQUE meaning the principal could never be re-created either. That
    // permanently bricked the principal on the single most mundane failure.
    //
    // Fix: a non-consuming peek first (same opaque code as before, still
    // never distinguishing missing/wrong/expired/used), then verification,
    // and only burn the token once verification actually succeeds.
    if (!enrolmentTokenLooksUsable(app.ctx.db, id, token)) {
      throw withAuditDetail(
        new FailClosedError(
          "no_pending_registration", 400, "no pending registration challenge for this principal",
        ),
        "missing, wrong, expired, or already-used enrolment token",
      );
    }
    const tokenStr = token as string;

    const challenge = pendingChallenges.get(id);
    if (!challenge) {
      throw new FailClosedError(
        "no_pending_registration", 400, "no pending registration challenge for this principal",
      );
    }

    // Deliberately NOT deleting the pendingChallenges entry yet: it's only
    // removed once the token is actually, successfully burned below. A
    // ceremony that throws here (bad signature, malformed response, etc.)
    // makes no DB writes of its own (see src/webauthn/registration.ts) and
    // leaves both the token and the challenge exactly as they were, so a
    // retry under the same token needs nothing re-issued.
    const result = await finishRegistration(app.ctx.db, id, challenge, req.body as never);

    // Verification succeeded -- and, as an inseparable part of that same
    // call, finishRegistration already persisted the credential (it cannot
    // verify without writing, and webauthn/registration.ts is out of scope
    // to change here). Burn the token now, atomically. Two different,
    // genuinely-successful ceremonies (two different authenticators) can
    // race here on one still-unspent token; credentials.credential_id being
    // UNIQUE does not stop both from persisting, since two authenticators
    // produce two different credential ids. consumeEnrolmentToken's atomic
    // check-and-burn UPDATE is what picks the single winner: if this call
    // loses -- because a concurrent request already burned the token first
    // -- undo the credential this call just persisted, and reject with the
    // exact same opaque shape a spent token always produces. This request's
    // own signature was cryptographically valid; that fact must not leak.
    if (!q.consumeEnrolmentToken(app.ctx.db, tokenStr, id)) {
      q.deleteCredential(app.ctx.db, result.credential_id);
      throw withAuditDetail(
        new FailClosedError(
          "no_pending_registration", 400, "no pending registration challenge for this principal",
        ),
        "enrolment token consumed by a concurrent request during the ceremony",
      );
    }
    pendingChallenges.delete(id);

    return reply.status(201).send(result);
  });
}
