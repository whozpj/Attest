import { randomUUID } from "node:crypto";
import type { FastifyInstance } from "fastify";
import type { AppContext } from "./server.js";
import * as q from "../db/queries.js";
import { beginRegistration, finishRegistration } from "../webauthn/registration.js";

const pendingChallenges = new Map<string, string>();

export function registerPrincipalRoutes(app: FastifyInstance & { ctx: AppContext }): void {
  app.post("/v1/principals", async (req, reply) => {
    const { email, display_name } = req.body as { email: string; display_name: string };
    const id = `prin_${randomUUID()}`;
    q.insertPrincipal(app.ctx.db, { id, email, display_name });
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
    if (!challenge) return reply.status(400).send({ error: "no_pending_registration" });
    pendingChallenges.delete(id);
    const result = await finishRegistration(app.ctx.db, id, challenge, req.body as never);
    return reply.status(201).send(result);
  });
}
