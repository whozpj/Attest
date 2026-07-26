import { randomUUID } from "node:crypto";
import type { FastifyInstance } from "fastify";
import type { AppContext } from "./server.js";
import * as q from "../db/queries.js";
import { beginRegistration, finishRegistration } from "../webauthn/registration.js";
import { FailClosedError } from "../types.js";
import { withAuditDetail } from "./audit-detail.js";

const pendingChallenges = new Map<string, string>();

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
    return reply.status(201).send({ principal_id: id });
  });

  app.post("/v1/principals/:id/credentials/options", async (req) => {
    const { id } = req.params as { id: string };
    const options = await beginRegistration(app.ctx.db, id);
    pendingChallenges.set(id, options.challenge);
    return options;
  });

  app.post("/v1/principals/:id/credentials", async (req, reply) => {
    const { id } = req.params as { id: string };
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
