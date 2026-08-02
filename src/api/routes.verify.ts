import type { FastifyInstance } from "fastify";
import type { AppContext } from "./server.js";
import { publicJwks } from "../crypto/tokens.js";
import { verifyAndConsumeAttestation } from "./attestations-core.js";

export function registerVerifyRoutes(app: FastifyInstance & { ctx: AppContext }): void {
  app.get("/.well-known/jwks.json", async () => publicJwks(app.ctx.kp));

  // Returns 200 with valid:false on a bad or already-used token — a
  // verifier answering truthfully is not an HTTP error.
  // verifyAndConsumeAttestation's signature check is fail-closed for a
  // malformed *value* (wrong type, garbage string) since jose's parse
  // failure just falls through to `{valid:false}`. The one gap was a
  // missing body entirely: destructuring `token` straight out of
  // `req.body` throws before ever reaching that safety net if there's no
  // body at all.
  //
  // A first, successful call also consumes the token: this is the only
  // call in the whole API that a single human approval can win exactly
  // once. See docs/superpowers/specs/2026-08-02-single-use-verify-design.md.
  app.post("/v1/attestations/verify", async (req) => {
    const body = (req.body ?? {}) as { token?: unknown };
    return verifyAndConsumeAttestation(app.ctx.db, await publicJwks(app.ctx.kp), body.token as never);
  });
}
