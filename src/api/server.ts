import Fastify, { type FastifyInstance } from "fastify";
import fastifyStatic from "@fastify/static";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { openDb, type Database } from "../db/index.js";
import { loadOrCreateKeypair, type Keypair } from "../crypto/tokens.js";
import { FailClosedError } from "../types.js";
import { registerPrincipalRoutes } from "./routes.principals.js";
import { registerAttestationRoutes } from "./routes.attestations.js";
import { registerVerifyRoutes } from "./routes.verify.js";

const here = dirname(fileURLToPath(import.meta.url));

export interface AppContext { db: Database; kp: Keypair; }

export async function buildServer(
  opts: { dbPath?: string; keyDir?: string } = {},
): Promise<FastifyInstance & { ctx: AppContext }> {
  // Two-step cast: Fastify's own instance type and our decorated type don't
  // sufficiently overlap for a direct assertion under this TS toolchain.
  const app = Fastify({ logger: false }) as unknown as FastifyInstance & { ctx: AppContext };

  app.ctx = {
    db: openDb(opts.dbPath ?? ":memory:"),
    kp: await loadOrCreateKeypair(opts.keyDir ?? join(process.cwd(), "keys")),
  };

  await app.register(fastifyStatic, {
    root: join(here, "../../demo/public"),
    prefix: "/approve/",
  });

  // Vendor bundle so the demo pages can use @simplewebauthn/browser without a
  // build step. Snippet from QA (Task 11 step 2) — server.ts is our file, so
  // the edit lands here rather than in demo/.
  await app.register(fastifyStatic, {
    root: join(here, "../../node_modules/@simplewebauthn/browser/dist/bundle"),
    prefix: "/vendor/",
    decorateReply: false,
  });

  app.get("/vendor/simplewebauthn-browser.js", (_req, reply) =>
    reply.sendFile("index.umd.min.js", join(here, "../../node_modules/@simplewebauthn/browser/dist/bundle")),
  );

  app.setErrorHandler((err, _req, reply) => {
    if (err instanceof FailClosedError) {
      return reply.status(err.httpStatus).send({ error: err.code, message: err.message });
    }
    return reply.status(500).send({ error: "internal_error" });
  });

  registerPrincipalRoutes(app);
  registerAttestationRoutes(app);
  registerVerifyRoutes(app);

  return app;
}
