import { randomBytes, randomUUID } from "node:crypto";
import type { Database } from "better-sqlite3";
import type { FastifyInstance } from "fastify";
import type { AppContext } from "./server.js";
import * as q from "../db/queries.js";
import { beginRegistration, finishRegistration } from "../webauthn/registration.js";
import { FailClosedError } from "../types.js";
import { withAuditDetail } from "./audit-detail.js";

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
function assertEnrolmentTokenValid(db: Database, principalId: string, token: unknown): void {
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

    // Same opaque code the "no pending challenge" branch below already uses
    // for an unknown principal — a bad token must not be distinguishable
    // from either "you never called .../options" or "this principal doesn't
    // exist". Consuming here (not just checking) is what makes this a
    // single-use token: the atomic UPDATE inside consumeEnrolmentToken means
    // a token can pass this gate at most once, closing the same TOCTOU shape
    // already fixed in state.ts's approval path. A ceremony that fails after
    // this point (bad signature, etc.) still leaves the token burned — an
    // accepted prototype-scope trade-off for keeping the gate race-free —
    // so a failed enrolment attempt requires re-issuing a fresh token.
    if (typeof token !== "string" || token.length === 0 || !q.consumeEnrolmentToken(app.ctx.db, token, id)) {
      throw withAuditDetail(
        new FailClosedError(
          "no_pending_registration", 400, "no pending registration challenge for this principal",
        ),
        "missing, wrong, expired, or already-used enrolment token",
      );
    }

    const challenge = pendingChallenges.get(id);
    if (!challenge) {
      throw new FailClosedError(
        "no_pending_registration", 400, "no pending registration challenge for this principal",
      );
    }
    pendingChallenges.delete(id);
    const result = await finishRegistration(app.ctx.db, id, challenge, req.body as never);
    return reply.status(201).send(result);
  });
}
