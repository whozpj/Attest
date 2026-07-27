import Fastify, { type FastifyInstance } from "fastify";
import fastifyStatic from "@fastify/static";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { openDb, type Database } from "../db/index.js";
import { loadOrCreateKeypair, type Keypair } from "../crypto/tokens.js";
import * as q from "../db/queries.js";
import { FailClosedError } from "../types.js";
import { auditDetailOf, auditEventOf } from "../audit-detail.js";
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

  // A request with no body at all (no Content-Type, nothing on the wire)
  // leaves Fastify's req.body as the bare JS value `undefined` — not `{}`.
  // Every route handler does `req.body as {...}` and reads fields straight
  // off it, so an absent body throws a raw TypeError (reading a property of
  // undefined) before that route's own "is this field present" validation
  // ever runs, escaping as an unaudited 500. This is the one place that
  // normalizes it, so every route's existing field-level validation sees the
  // same shape it already handles correctly for an explicit `{}` body,
  // rather than each route re-guarding against `undefined` individually —
  // the same defect, at a different call site, recurring across
  // routes.principals.ts, routes.attestations.ts, and routes.verify.ts.
  app.addHook("preValidation", (req, _reply, done) => {
    if (req.body === undefined || req.body === null) {
      req.body = {};
    }
    done();
  });

  // Centralized audit logging: this is the one place every rejection in the
  // app passes through, regardless of which route or module threw it. That
  // makes it the right choke point for "every rejection writes an
  // audit_log row" instead of a per-throw-site call sprinkled across
  // actions/, db/, api/, and webauthn/ that's trivially easy to miss (and
  // was missed, repeatedly, before this). It also backstops unhandled
  // exceptions: those still resolve to a generic 500, but they no longer
  // vanish without a trace either.
  app.setErrorHandler((err: unknown, req, reply) => {
    const routeUrl = req.routeOptions?.url ?? "";
    const params = req.params as Record<string, unknown> | undefined;
    const body = req.body as Record<string, unknown> | undefined;

    const paramId = typeof params?.id === "string" ? params.id : null;
    const bodyPrincipalId = typeof body?.principal_id === "string" ? body.principal_id : null;

    // :id means different things on different routes (an attestation_id
    // under /v1/attestations/:id, a principal_id under
    // /v1/principals/:id/...) — resolve it against the matched route
    // pattern rather than guessing from the value alone.
    const attestationId = routeUrl.startsWith("/v1/attestations/:id") ? paramId : null;
    const actor = bodyPrincipalId
      ?? (routeUrl.startsWith("/v1/principals/:id") ? paramId : null);

    const isFailClosed = err instanceof FailClosedError;
    // A throw site can attach a richer, audit-only explanation (never sent
    // over HTTP) via `withAuditDetail` below when its generic message would
    // otherwise flatten two meaningfully different causes — e.g. "malformed
    // body" vs "duplicate email" behind the same opaque anti-enumeration
    // response — without that distinction ever reaching the caller.
    const auditDetail = isFailClosed ? auditDetailOf(err) : undefined;
    // A throw site can similarly override the event name (`withAuditEvent`)
    // when its own signal is more specific than its HTTP error code — e.g.
    // possible_credential_clone is a materially different alarm than the
    // generic counter_regression code alone would convey — so that richer
    // name is the one row this rejection writes, not a second row alongside it.
    const auditEvent = isFailClosed ? auditEventOf(err) : undefined;
    const message = err instanceof Error ? err.message : String(err);

    q.audit(app.ctx.db, {
      attestation_id: attestationId,
      event: auditEvent ?? (isFailClosed ? err.code : "internal_error"),
      actor,
      detail: auditDetail ?? message,
    });

    if (isFailClosed) {
      return reply.status(err.httpStatus).send({ error: err.code, message: err.message });
    }
    return reply.status(500).send({ error: "internal_error" });
  });

  registerPrincipalRoutes(app);
  registerAttestationRoutes(app);
  registerVerifyRoutes(app);

  return app;
}
