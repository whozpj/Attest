import type { FastifyInstance } from "fastify";
import type { AppContext } from "./server.js";
import { publicJwks, verifyAttestation } from "../crypto/tokens.js";

export function registerVerifyRoutes(app: FastifyInstance & { ctx: AppContext }): void {
  app.get("/.well-known/jwks.json", async () => publicJwks(app.ctx.kp));

  // Returns 200 with valid:false on a bad token — a verifier answering
  // truthfully is not an HTTP error. verifyAttestation's own catch-all is
  // already fail-closed for a malformed *value* (wrong type, garbage
  // string) since jose's parse failure just falls through to
  // `{valid:false}`. The one gap was a missing body entirely: destructuring
  // `token` straight out of `req.body` throws before ever reaching that
  // safety net if there's no body at all.
  app.post("/v1/attestations/verify", async (req) => {
    const body = (req.body ?? {}) as { token?: unknown };
    return verifyAttestation(await publicJwks(app.ctx.kp), body.token as never);
  });
}
