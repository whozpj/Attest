import type { FastifyInstance } from "fastify";
import type { AppContext } from "./server.js";

export function registerHealthRoutes(app: FastifyInstance & { ctx: AppContext }): void {
  // Exempt from rate limiting: a load balancer / orchestrator health probe
  // shares the global rate-limit budget with real traffic otherwise (worse
  // still behind a reverse proxy without TRUST_PROXY set, where every
  // request -- probe and real client alike -- keys on the same address), and
  // could see a false 429 under load and incorrectly pull a healthy instance
  // from rotation.
  app.get("/healthz", { config: { rateLimit: false } }, async (_req, reply) => {
    try {
      app.ctx.db.prepare("SELECT 1").get();
    } catch (err) {
      app.log.error({ err }, "health check failed");
      return reply.status(503).send({ status: "unhealthy" });
    }
    return { status: "ok" };
  });
}
