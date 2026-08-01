import { randomBytes } from "node:crypto";
import {
  generateAuthenticationOptions, verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import type { FastifyInstance, FastifyRequest, FastifyReply } from "fastify";
import type { AppContext } from "./server.js";
import * as q from "../db/queries.js";
import { RP } from "../webauthn/config.js";
import { FailClosedError } from "../types.js";
import { withAuditDetail } from "../audit-detail.js";
import { loadConfig } from "../config.js";

const COOKIE = "ha_session";
const LOGIN_CHALLENGE_TTL_SECONDS = 300;

/**
 * A sign-in challenge is random and stored server-side. It is deliberately
 * NOT derived from any action -- unlike an approval challenge, which is
 * hash({act, att, decision}). That asymmetry is the security property: an
 * assertion captured during sign-in signs bytes that no approval challenge
 * can ever equal, so it can never be replayed to approve an action, and an
 * approval assertion can never be replayed to sign in. tests/security asserts
 * this directly.
 */
function newLoginChallenge(): string {
  return randomBytes(32).toString("base64url");
}

function readCookie(req: FastifyRequest, name: string): string | undefined {
  const header = req.headers.cookie;
  if (!header) return undefined;
  for (const part of header.split(";")) {
    const [k, ...rest] = part.trim().split("=");
    if (k === name) return rest.join("=");
  }
  return undefined;
}

export function requireSession(
  app: FastifyInstance & { ctx: AppContext }, req: FastifyRequest,
): { principal_id: string } {
  const id = readCookie(req, COOKIE);
  if (!id) throw new FailClosedError("no_session", 401, "sign-in required");
  const session = q.getSession(app.ctx.db, id);
  if (!session) throw new FailClosedError("session_expired", 401, "sign-in required");
  return { principal_id: session.principal_id };
}

function assertEmail(email: unknown): asserts email is string {
  if (typeof email !== "string" || email.length === 0) {
    throw new FailClosedError("payload_invalid", 400, "email is required");
  }
}

export function registerWebSessionRoutes(app: FastifyInstance & { ctx: AppContext }): void {
  const { db } = app.ctx;
  const secure = app.ctx.baseUrl.startsWith("https://");
  const ttlHours = loadConfig().sessionTtlHours;

  /**
   * Rate-limited like the other credential-adjacent unauthenticated
   * endpoints (30/min, matching /v1/attestations/:id/options).
   */
  app.post("/web/session/options", {
    config: { rateLimit: { max: 30, timeWindow: "1 minute" } },
  }, async (req) => {
    const body = req.body as { email?: unknown };
    assertEmail(body.email);

    const principal = q.getPrincipalByEmail(db, body.email);
    const creds = principal ? q.getCredentialsFor(db, principal.id) : [];

    // An unregistered email, and a registered one with no enrolled
    // credential, both get a well-formed options object with a real random
    // challenge that simply cannot be satisfied. Returning 404 or an empty
    // allowCredentials for one and not the other would turn this endpoint
    // into an account-enumeration oracle -- the same reasoning that makes
    // POST /v1/principals opaque about duplicate emails.
    const challenge = newLoginChallenge();
    if (principal && creds.length > 0) {
      q.insertLoginChallenge(db, {
        challenge, principal_id: principal.id,
        expires_at: new Date(Date.now() + LOGIN_CHALLENGE_TTL_SECONDS * 1000).toISOString(),
      });
    }

    return generateAuthenticationOptions({
      rpID: RP.id,
      // `.slice()` narrows to Uint8Array<ArrayBuffer>, matching the library's
      // own Uint8Array_ type under strict mode -- same reason beginApproval
      // does it in src/webauthn/authentication.ts.
      challenge: new Uint8Array(Buffer.from(challenge, "base64url")).slice(),
      allowCredentials: creds.map((c) => ({ id: c.credential_id })),
      userVerification: "preferred",
    });
  });

  app.post("/web/session", {
    config: { rateLimit: { max: 30, timeWindow: "1 minute" } },
  }, async (req, reply) => {
    const body = req.body as { email?: unknown; response?: unknown };
    assertEmail(body.email);
    const response = body.response as { id?: unknown } | undefined;
    if (!response || typeof response.id !== "string") {
      throw new FailClosedError("payload_invalid", 400, "a signed assertion is required");
    }

    // One opaque rejection for every failure below, for the same
    // anti-enumeration reason as above.
    const reject = (detail: string): never => {
      throw withAuditDetail(
        new FailClosedError("login_challenge_invalid", 401, "sign-in failed"), detail,
      );
    };

    const principal = q.getPrincipalByEmail(db, body.email);
    if (!principal) reject("unknown email");
    const cred = q.getCredential(db, response.id);
    if (!cred || cred.principal_id !== principal!.id) reject("credential not bound to this principal");

    let verification;
    try {
      verification = await verifyAuthenticationResponse({
        response: body.response as never,
        // Consuming the challenge inside the verifier's own predicate is what
        // makes a sign-in assertion single-use: the row is burned atomically
        // as part of the same verification that accepts it, so a captured
        // assertion cannot be replayed into a second session. The predicate
        // also scopes the challenge to this principal, so one principal's
        // outstanding challenge is not satisfiable by another's signature.
        expectedChallenge: (challenge) =>
          q.consumeLoginChallenge(db, challenge, principal!.id),
        expectedOrigin: RP.origin,
        expectedRPID: RP.id,
        credential: {
          id: cred!.credential_id,
          publicKey: new Uint8Array(cred!.public_key),
          counter: cred!.sign_count,
        },
      });
    } catch (err) {
      reject(`assertion rejected: ${String(err)}`);
    }
    if (!verification!.verified) reject("verified=false");

    q.updateSignCount(db, cred!.credential_id, verification!.authenticationInfo.newCounter);

    const sessionId = randomBytes(32).toString("base64url");
    q.insertSession(db, {
      id: sessionId, principal_id: principal!.id,
      expires_at: new Date(Date.now() + ttlHours * 3600 * 1000).toISOString(),
    });
    q.audit(db, {
      attestation_id: null, event: "session_created", actor: principal!.id, detail: null,
    });

    return reply
      .header("set-cookie",
        `${COOKIE}=${sessionId}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${ttlHours * 3600}` +
        (secure ? "; Secure" : ""))
      .status(204)
      .send();
  });

  app.delete("/web/session", async (req: FastifyRequest, reply: FastifyReply) => {
    const id = readCookie(req, COOKIE);
    if (id) {
      const session = q.getSession(db, id);
      q.deleteSession(db, id);
      if (session) {
        q.audit(db, {
          attestation_id: null, event: "session_ended",
          actor: session.principal_id, detail: null,
        });
      }
    }
    return reply
      .header("set-cookie", `${COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`)
      .status(204)
      .send();
  });

  app.get("/web/me", async (req) => {
    const { principal_id } = requireSession(app, req);
    const principal = q.getPrincipal(db, principal_id)!;
    return {
      principal_id, email: principal.email, display_name: principal.display_name,
    };
  });
}
