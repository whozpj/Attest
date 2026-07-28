import { randomUUID } from "node:crypto";
import type { FastifyInstance } from "fastify";
import type { AppContext } from "./server.js";
import * as q from "../db/queries.js";
import { FailClosedError } from "../types.js";
import { withAuditDetail } from "../audit-detail.js";
import { assertEnrolmentTokenValid } from "./routes.principals.js";

function assertPushSubscription(body: unknown): asserts body is {
  subscription: { endpoint: string; keys: { p256dh: string; auth: string } };
} {
  const b = body as { subscription?: { endpoint?: unknown; keys?: { p256dh?: unknown; auth?: unknown } } };
  const sub = b.subscription;
  const valid =
    typeof sub?.endpoint === "string" && sub.endpoint.startsWith("https://") &&
    typeof sub?.keys?.p256dh === "string" && sub.keys.p256dh.length > 0 &&
    typeof sub?.keys?.auth === "string" && sub.keys.auth.length > 0;
  if (!valid) {
    throw withAuditDetail(
      new FailClosedError("push_subscription_invalid", 400, "a valid push subscription is required"),
      "malformed push subscription body",
    );
  }
}

export function registerPushRoutes(app: FastifyInstance & { ctx: AppContext }): void {
  app.get("/v1/push/vapid-public-key", async () => ({ publicKey: app.ctx.vapid.publicKey }));

  app.post("/v1/principals/:id/push-subscription", async (req, reply) => {
    const { id } = req.params as { id: string };
    const { token } = req.query as { token?: unknown };
    // Same non-consuming check .../credentials/options already uses:
    // registering a push subscription must not burn the token that
    // .../credentials still needs to finish the passkey ceremony.
    assertEnrolmentTokenValid(app.ctx.db, id, token);
    assertPushSubscription(req.body);

    q.upsertPushSubscription(app.ctx.db, {
      id: `psub_${randomUUID()}`,
      principal_id: id,
      endpoint: req.body.subscription.endpoint,
      p256dh: req.body.subscription.keys.p256dh,
      auth: req.body.subscription.keys.auth,
    });
    return reply.status(201).send({ ok: true });
  });
}
