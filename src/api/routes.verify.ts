import type { FastifyInstance } from "fastify";
import type { AppContext } from "./server.js";
import { publicJwks, verifyAttestation } from "../crypto/tokens.js";

export function registerVerifyRoutes(app: FastifyInstance & { ctx: AppContext }): void {
  app.get("/.well-known/jwks.json", async () => publicJwks(app.ctx.kp));

  // Returns 200 with valid:false on a bad token — a verifier answering
  // truthfully is not an HTTP error.
  app.post("/v1/attestations/verify", async (req) => {
    const { token } = req.body as { token: string };
    return verifyAttestation(await publicJwks(app.ctx.kp), token);
  });
}
