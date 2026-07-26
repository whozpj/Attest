import { randomUUID } from "node:crypto";
import type { FastifyInstance } from "fastify";
import type { AppContext } from "./server.js";
import * as q from "../db/queries.js";
import { beginRegistration, finishRegistration } from "../webauthn/registration.js";
import { FailClosedError } from "../types.js";

const pendingChallenges = new Map<string, string>();

export function registerPrincipalRoutes(app: FastifyInstance & { ctx: AppContext }): void {
  app.post("/v1/principals", async (req, reply) => {
    const body = req.body as { email?: unknown; display_name?: unknown };
    const email = body.email;
    const display_name = body.display_name;

    // One opaque code for both a malformed body and a duplicate email.
    // Spec's "say why without leaking" principle: a distinct duplicate-email
    // error would be an account-enumeration vector on an enrolment endpoint.
    // The audit detail records which it actually was, server-side only.
    if (typeof email !== "string" || email.length === 0 ||
        typeof display_name !== "string" || display_name.length === 0) {
      q.audit(app.ctx.db, {
        attestation_id: null, event: "principal_invalid", actor: null,
        detail: "malformed enrolment body",
      });
      throw new FailClosedError("principal_invalid", 400, "email and display_name are required");
    }

    const id = `prin_${randomUUID()}`;
    try {
      q.insertPrincipal(app.ctx.db, { id, email, display_name });
    } catch {
      q.audit(app.ctx.db, {
        attestation_id: null, event: "principal_invalid", actor: null,
        detail: `duplicate email: ${email}`,
      });
      throw new FailClosedError("principal_invalid", 400, "email and display_name are required");
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
      q.audit(app.ctx.db, {
        attestation_id: null, event: "no_pending_registration", actor: id, detail: null,
      });
      throw new FailClosedError(
        "no_pending_registration", 400, "no pending registration challenge for this principal",
      );
    }
    pendingChallenges.delete(id);
    const result = await finishRegistration(app.ctx.db, id, challenge, req.body as never);
    return reply.status(201).send(result);
  });
}
