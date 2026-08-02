import Fastify, { type FastifyInstance, type FastifyServerOptions } from "fastify";
import fastifyStatic from "@fastify/static";
import fastifyRateLimit from "@fastify/rate-limit";
import fastifyHelmet from "@fastify/helmet";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { existsSync } from "node:fs";
import { openDb, type Database } from "../db/index.js";
import { loadOrCreateKeypair, type Keypair } from "../crypto/tokens.js";
import { loadTransport, type EmailTransport } from "../email/index.js";
import * as q from "../db/queries.js";
import { FailClosedError } from "../types.js";
import { auditDetailOf, auditEventOf } from "../audit-detail.js";
import { registerPrincipalRoutes } from "./routes.principals.js";
import { registerAttestationRoutes } from "./routes.attestations.js";
import { registerVerifyRoutes } from "./routes.verify.js";
import { registerHealthRoutes } from "./routes.health.js";
import { registerWebSessionRoutes } from "./routes.web.session.js";
import { registerWebRequestRoutes } from "./routes.web.requests.js";
import { loadConfig } from "../config.js";
import { registerMcpRoutes } from "../mcp/routes.js";

const here = dirname(fileURLToPath(import.meta.url));

// The Vite build output the SPA is served from. Absent in a fresh checkout
// until `npm run build:web` has run, and absent in unit tests, which never
// need it -- so the mount below is conditional rather than assumed. Left
// unconditional, @fastify/static throws ENOENT at registration time and takes
// every API test down with it over a missing frontend asset directory.
const WEB_DIST = join(here, "../../web/dist");

export interface AppContext { db: Database; kp: Keypair; email: EmailTransport; baseUrl: string; }

export async function buildServer(
  opts: {
    dbPath?: string; keyDir?: string; baseUrl?: string;
    logger?: FastifyServerOptions["logger"]; trustProxy?: boolean;
    email?: EmailTransport;
    // Defaults to the documented production value (docs/PRODUCTION.md's
    // capacity-planning math is written against 100/min) -- only
    // tests/e2e/server.ts, an isolated throwaway instance that real traffic
    // never reaches, overrides this. Five parallel Playwright workers
    // hitting one shared dev process produce a request burst no single real
    // client ever would; that's a test-infrastructure fact, not a reason to
    // loosen what a real deployment enforces.
    globalRateLimit?: { max: number; timeWindow: string };
  } = {},
): Promise<FastifyInstance & { ctx: AppContext }> {
  // Two-step cast: Fastify's own instance type and our decorated type don't
  // sufficiently overlap for a direct assertion under this TS toolchain.
  // trustProxy defaults to false -- exactly today's behavior -- so
  // @fastify/rate-limit keys on the raw TCP peer address unless the operator
  // has explicitly opted in (see src/config.ts's TRUST_PROXY / Finding 2 of
  // the 2026-07-29 final review).
  const app = Fastify({
    logger: opts.logger ?? false,
    trustProxy: opts.trustProxy ?? false,
  }) as unknown as FastifyInstance & { ctx: AppContext };

  const cfg = loadConfig();

  app.ctx = {
    db: openDb(opts.dbPath ?? ":memory:"),
    kp: await loadOrCreateKeypair(opts.keyDir ?? join(process.cwd(), "keys")),
    // Injectable so a test can record what would have been sent without
    // touching the filesystem or an SMTP host.
    email: opts.email ?? loadTransport({
      smtpUrl: cfg.smtpUrl, mailFrom: cfg.mailFrom, mailDir: cfg.mailDir,
    }),
    baseUrl: opts.baseUrl ?? cfg.baseUrl,
  };

  // The SPA replaces the demo/public pages formerly mounted at /approve/. It
  // is served from the root so the app's own URLs (/signin, /requests/:id,
  // /a/:token) are real paths a mail client can link to, not hash fragments.
  const hasWebDist = existsSync(WEB_DIST);
  if (hasWebDist) {
    await app.register(fastifyStatic, { root: WEB_DIST, prefix: "/" });
  }

  await app.register(fastifyRateLimit, opts.globalRateLimit ?? {
    max: 100,
    timeWindow: "1 minute",
  });

  await app.register(fastifyHelmet, {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        // Tightened from ['self', 'unsafe-inline'] now that the hand-written
        // demo pages are gone: the Vite-built SPA ships external CSS only,
        // and vite.config.ts's assetsInlineLimit: 0 keeps it that way.
        styleSrc: ["'self'"],
        imgSrc: ["'self'", "data:"],
        connectSrc: ["'self'"],
        manifestSrc: ["'self'"],
        workerSrc: ["'self'"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        frameAncestors: ["'none'"],
      },
    },
  });

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

    // A 429 from @fastify/rate-limit reaches this same handler (it's not a
    // FailClosedError) and, before this, fell through to the generic
    // "internal_error" event -- indistinguishable from a genuine unhandled
    // exception in anything alerting on that event name. Rate limiting
    // working as designed is not a fault; give it its own event.
    const isRateLimited = !isFailClosed
      && (err as { statusCode?: unknown }).statusCode === 429;

    q.audit(app.ctx.db, {
      attestation_id: attestationId,
      event: auditEvent ?? (isFailClosed ? err.code : isRateLimited ? "rate_limited" : "internal_error"),
      actor,
      detail: auditDetail ?? message,
    });

    if (isFailClosed) {
      return reply.status(err.httpStatus).send({ error: err.code, message: err.message });
    }
    // Not one of our own FailClosedErrors, but Fastify's own machinery
    // (body-parser JSON errors, content-type negotiation, etc.) throws
    // FastifyError instances that already carry an accurate `statusCode` —
    // e.g. 400 for malformed JSON, 415 for an unsupported content-type.
    // Trusting that over a blanket 500 means a caller sees the right class
    // of error (their request was bad, not that we broke) while the event
    // itself is still audited as `internal_error` below, same as any other
    // unrecognised throw — this only changes what status code is reported,
    // not whether the rejection is tracked.
    const nativeStatus = typeof (err as { statusCode?: unknown }).statusCode === "number"
      ? (err as { statusCode: number }).statusCode
      : 500;
    return reply.status(nativeStatus).send({ error: "internal_error" });
  });

  // Fastify's default notFoundHandler intercepts before setErrorHandler ever
  // sees the request, so an unknown route would otherwise write zero rows to
  // audit_log — a blind spot design §9 doesn't allow ("every rejection
  // writes to audit_log"). Route-space probing is a rejection like any
  // other; this makes it one too, without changing the 404 body Fastify
  // would have sent on its own.
  app.setNotFoundHandler((req, reply) => {
    // SPA history fallback. React Router owns /signin, /requests/:id, /a/:token
    // and friends; those are real URLs a browser navigates to directly (an
    // approver clicks one straight out of an email), so an unmatched GET that
    // wants HTML has to return the app shell rather than a 404.
    //
    // Deliberately narrow. It never applies to the API namespaces, so a
    // mistyped /v1 or /web route still 404s as a rejection instead of quietly
    // returning 200 and an HTML page to a caller expecting JSON -- which would
    // turn every API typo into a confusing parse error at the client and,
    // worse, hide route-space probing from the audit log. Non-GET requests and
    // requests that don't accept HTML fall through to the audited 404 below
    // for the same reason.
    const isApiPath = req.url.startsWith("/v1")
      || req.url.startsWith("/web")
      || req.url.startsWith("/.well-known");
    const wantsHtml = (req.headers.accept ?? "").includes("text/html");
    if (hasWebDist && req.method === "GET" && !isApiPath && wantsHtml) {
      return reply.status(200).type("text/html").sendFile("index.html", WEB_DIST);
    }

    q.audit(app.ctx.db, {
      attestation_id: null,
      event: "route_not_found",
      actor: null,
      detail: `${req.method} ${req.url}`,
    });
    // Reproduces Fastify's own default 404 body (rather than calling
    // reply.callNotFound(), which would re-enter this same handler) so the
    // only observable change for a real caller is the new audit row.
    reply.status(404).send({
      message: `Route ${req.method}:${req.url} not found`,
      error: "Not Found",
      statusCode: 404,
    });
  });

  registerPrincipalRoutes(app);
  registerAttestationRoutes(app);
  registerVerifyRoutes(app);
  registerWebSessionRoutes(app);
  registerWebRequestRoutes(app);
  registerHealthRoutes(app);
  await registerMcpRoutes(app);

  return app;
}
