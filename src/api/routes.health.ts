import type { FastifyInstance } from "fastify";
import type { AppContext } from "./server.js";

export function registerHealthRoutes(app: FastifyInstance & { ctx: AppContext }): void {
  app.get("/healthz", async (_req, reply) => {
    try {
      app.ctx.db.prepare("SELECT 1").get();
    } catch {
      return reply.status(503).send({ status: "unhealthy" });
    }
    return { status: "ok" };
  });
}
