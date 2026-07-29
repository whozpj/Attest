# Production Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Take Human-Attest from a working prototype to genuinely production-quality code: real config/secrets handling, rate limiting, structured logging with audit-visible push failures, security headers, a correctness fix for key rotation, a verified Docker deployment, CI, and a real local load/concurrency probe — everything buildable and verifiable without needing a real cloud account, domain, or payment processor.

**Architecture:** Entirely additive/config-driven. No change to the cryptographic trust model (WebAuthn ceremonies, canonicalization, JWS signing) except a scoped correctness fix in Task 7 (JWT verification must select the signing key by `kid`, not always index 0 — a real bug that only matters once a JWKS ever legitimately contains more than one key, which today it never does, but which any future key rotation would immediately need). Every new behavior is opt-in or environment-driven with a default that exactly reproduces today's behavior, so the full existing test suite (234 unit/integration tests, 11 e2e specs) must stay green, unmodified, after every task.

**Tech Stack:** Same as the existing project, plus `@fastify/rate-limit`, `@fastify/helmet` (both official, actively-maintained Fastify v5 plugins). No database migration (SQLite/WAL stays — see Task 10's PRODUCTION.md for the documented single-instance tradeoff this implies). No compiled build step (the app already runs via `tsx` in dev/test; Task 8's Docker image keeps that pattern rather than introducing a `tsc`-compiled `dist/` pipeline, which would require re-deriving `demo/public`'s static-file path resolution and isn't worth the risk for this pass).

## Global Constraints

- Node 20+, ESM only. TypeScript `strict: true`. No `any` in `src/`.
- **Zero regression.** After every task: `npx tsc --noEmit`, `npx vitest run` (full suite), and — for any task touching `demo/public/*` or server request handling — `npm run e2e` (all specs) must all pass unmodified. This plan touches security- and availability-sensitive code throughout; the existing suite is the safety net.
- Every new env-var-driven behavior needs a default that exactly reproduces today's behavior. No test file may need to change just because a task landed — the only test changes in this plan are new tests for new behavior.
- **Logging defaults to off.** `buildServer`'s `logger` option defaults to `false` exactly as today; only `src/main.ts` (the real server entrypoint) opts in. This keeps every existing and new test's output pristine without needing to touch every test file that calls `buildServer`.
- No changes to `src/crypto/canonical.ts`, `src/webauthn/registration.ts`, or `src/webauthn/authentication.ts`'s verification logic, and no change to how `crypto/tokens.ts` signs. The one crypto-adjacent change (Task 7) is scoped to `verifyAttestation`'s key *selection*, not verification itself.
- Fail closed, consistently: a misconfigured production deployment should refuse to boot loudly (see Task 1's `loadConfig`), not silently serve broken behavior.
- New dependencies are limited to `@fastify/rate-limit` and `@fastify/helmet` — both official Fastify plugins, both already compatible with Fastify v5. No other new runtime dependencies.

---

## File Structure

```
src/
  config.ts                     [new] env-driven AppConfig + fail-closed production check
  webauthn/config.ts            [modify] RP.id/origin from env vars
  api/
    server.ts                   [modify] baseUrl + logger opts, rate-limit, helmet, health route
    routes.attestations.ts      [modify] use app.ctx.baseUrl instead of hardcoded localhost
    routes.principals.ts        [modify] per-route rate-limit config
    routes.health.ts            [new] GET /healthz
  crypto/tokens.ts              [modify] SIGNING_KEY_JSON env support; kid-aware verify
  push/
    send.ts                     [modify] optional logger param
    vapid.ts                    [modify] VAPID_KEYS_JSON env support + shape validation
  main.ts                       [modify] loadConfig(), logger, graceful shutdown
demo/public/
  index.html, enrol.html, app.html   [modify] external <script src> instead of inline
  index.js, enrol.js, app.js         [new] the extracted script content
db/queries.ts                   [modify] doc comment only — the upsert tradeoff, no code change
scripts/
  load-test.mts                 [new] local concurrency/latency probe
  export-audit-log.mts          [new] direct-DB-file audit_log export (not an HTTP endpoint)
Dockerfile, .dockerignore, docker-compose.yml   [new]
.github/workflows/ci.yml        [new]
docs/PRODUCTION.md              [new]
```

---

## Task 1: `src/config.ts` and env-driven RP settings — DONE (Lead)

**Owner:** Lead. No other task starts until this is committed — every later task reads `AppConfig` or the env vars it derives from.

Already implemented directly (not dispatched), matching this project's precedent for small, everything-depends-on-it foundational tasks (see the original MVP plan's Task 1 and this session's earlier push-notification plan's Task 1).

**Produced, for later tasks to consume:**
- `src/config.ts`: `interface AppConfig { nodeEnv, port, host, baseUrl, rpId, rpOrigin, dbPath, keyDir }` and `loadConfig(env?: NodeJS.ProcessEnv): AppConfig`, which throws if `nodeEnv === "production"` and `rpId`/`baseUrl` still point at `localhost`.
- `src/webauthn/config.ts`'s `RP.id`/`RP.origin` now read `process.env.RP_ID`/`process.env.RP_ORIGIN`/`process.env.BASE_URL`, defaulting to the exact same `"localhost"`/`"http://localhost:3000"` as before when unset.

**Step 1 — `src/config.ts`:**

```ts
export interface AppConfig {
  nodeEnv: "development" | "production" | "test";
  port: number;
  host: string;
  baseUrl: string;
  rpId: string;
  rpOrigin: string;
  dbPath: string;
  keyDir: string;
}

/**
 * Fail closed on boot, not on the first request: a production deployment
 * still pointing RP_ID/BASE_URL at localhost would silently issue tokens
 * whose WebAuthn origin/RP-ID checks can never match a real browser's real
 * origin -- every approval would fail, indistinguishably from a config typo
 * anywhere else. Refusing to start is louder and cheaper to debug.
 */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const nodeEnv = (env.NODE_ENV as AppConfig["nodeEnv"]) ?? "development";
  const baseUrl = env.BASE_URL ?? "http://localhost:3000";
  const config: AppConfig = {
    nodeEnv,
    port: env.PORT ? Number(env.PORT) : 3000,
    host: env.HOST ?? "127.0.0.1",
    baseUrl,
    rpId: env.RP_ID ?? "localhost",
    rpOrigin: env.RP_ORIGIN ?? baseUrl,
    dbPath: env.DB_PATH ?? "human-attest.db",
    keyDir: env.KEY_DIR ?? "keys",
  };

  if (config.nodeEnv === "production" &&
      (config.rpId === "localhost" || config.baseUrl.includes("localhost"))) {
    throw new Error(
      "refusing to start with NODE_ENV=production while RP_ID/BASE_URL still " +
      "point at localhost -- set RP_ID and BASE_URL to your real domain",
    );
  }

  return config;
}
```

**Step 2 — `src/config.test.ts`:**

```ts
import { describe, it, expect } from "vitest";
import { loadConfig } from "./config.js";

describe("loadConfig", () => {
  it("defaults to localhost development settings with no env vars", () => {
    const config = loadConfig({});
    expect(config).toEqual({
      nodeEnv: "development", port: 3000, host: "127.0.0.1",
      baseUrl: "http://localhost:3000", rpId: "localhost",
      rpOrigin: "http://localhost:3000", dbPath: "human-attest.db", keyDir: "keys",
    });
  });

  it("reads every value from the environment when set", () => {
    const config = loadConfig({
      NODE_ENV: "production", PORT: "8080", HOST: "0.0.0.0",
      BASE_URL: "https://attest.example.com", RP_ID: "example.com",
      RP_ORIGIN: "https://attest.example.com", DB_PATH: "/data/attest.db",
      KEY_DIR: "/secrets/keys",
    });
    expect(config).toEqual({
      nodeEnv: "production", port: 8080, host: "0.0.0.0",
      baseUrl: "https://attest.example.com", rpId: "example.com",
      rpOrigin: "https://attest.example.com", dbPath: "/data/attest.db",
      keyDir: "/secrets/keys",
    });
  });

  it("derives rpOrigin from baseUrl when RP_ORIGIN is not set", () => {
    const config = loadConfig({ BASE_URL: "https://attest.example.com" });
    expect(config.rpOrigin).toBe("https://attest.example.com");
  });

  it("refuses to start in production pointed at localhost", () => {
    expect(() => loadConfig({ NODE_ENV: "production" })).toThrow(/localhost/);
    expect(() => loadConfig({ NODE_ENV: "production", RP_ID: "example.com" })).toThrow(/localhost/);
  });

  it("allows production once both RP_ID and BASE_URL point at a real domain", () => {
    expect(() => loadConfig({
      NODE_ENV: "production", RP_ID: "example.com", BASE_URL: "https://attest.example.com",
    })).not.toThrow();
  });
});
```

**Step 3 — `src/webauthn/config.ts`**, replace the file with:

```ts
export const RP = {
  name: "Human-Attest",
  id: process.env.RP_ID ?? "localhost",
  origin: process.env.RP_ORIGIN ?? process.env.BASE_URL ?? "http://localhost:3000",
} as const;
```

Run: `npx tsc --noEmit && npx vitest run` — expect clean, zero regressions (this only changes literals `RP` evaluates to when the relevant env vars happen to be unset, which they are throughout the existing suite).

---

## Task 2: thread config through the server (replace hardcoded `localhost:3000`)

**Files:**
- Modify: `src/api/server.ts`, `src/main.ts`, `src/api/routes.attestations.ts`
- Test: `src/api/routes.attestations.test.ts`

**Interfaces:**
- Consumes: `loadConfig` (`../config.js`, Task 1).
- Produces: `AppContext.baseUrl: string`, and `buildServer`'s `opts.baseUrl?: string`, consumed by Task 3 (logger opt, same pattern) and read directly by `routes.attestations.ts`.

- [ ] **Step 1: Write the failing test**

Add to `src/api/routes.attestations.test.ts` (the file already imports `buildServer`, `mkdtempSync`/`tmpdir`/`join`, and defines a `wire` payload constant and a `beforeEach` — reuse them):

```ts
describe("POST /v1/attestations builds URLs from the server's configured baseUrl", () => {
  it("uses the configured baseUrl, not a hardcoded host", async () => {
    const customApp = await buildServer({
      dbPath: ":memory:", keyDir: mkdtempSync(join(tmpdir(), "ha-baseurl-")),
      baseUrl: "https://attest.example.com",
    });
    const principalRes = await customApp.inject({
      method: "POST", url: "/v1/principals",
      payload: { email: "baseurl@test.local", display_name: "Base URL" },
    });
    const { principal_id } = principalRes.json();
    const res = await customApp.inject({
      method: "POST", url: "/v1/attestations",
      payload: { requested_by: "int", approver_ids: [principal_id], action: wire },
    });
    expect(res.json().approve_url).toBe(
      `https://attest.example.com/approve/index.html?attestation=${res.json().attestation_id}`,
    );
  });

  it("still defaults to http://localhost:3000 when no baseUrl is passed", async () => {
    const res = await app.inject({
      method: "POST", url: "/v1/attestations",
      payload: { requested_by: "int", approver_ids: ["prin_whatever"], action: wire },
    });
    expect(res.json().approve_url).toContain("http://localhost:3000/approve/index.html");
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run src/api/routes.attestations.test.ts`
Expected: the first new test FAILS (approve_url still hardcoded to localhost regardless of `baseUrl`); the second passes already.

- [ ] **Step 3: Thread `baseUrl` through `server.ts`**

In `src/api/server.ts`, add the import and extend the context/options:

```ts
import { loadConfig } from "../config.js";
```

```ts
export interface AppContext { db: Database; kp: Keypair; vapid: VapidKeys; baseUrl: string; }

export async function buildServer(
  opts: { dbPath?: string; keyDir?: string; baseUrl?: string } = {},
): Promise<FastifyInstance & { ctx: AppContext }> {
  const app = Fastify({ logger: false }) as unknown as FastifyInstance & { ctx: AppContext };

  app.ctx = {
    db: openDb(opts.dbPath ?? ":memory:"),
    kp: await loadOrCreateKeypair(opts.keyDir ?? join(process.cwd(), "keys")),
    vapid: loadOrCreateVapidKeys(opts.keyDir ?? join(process.cwd(), "keys")),
    baseUrl: opts.baseUrl ?? loadConfig().baseUrl,
  };
  ...
```

(Only the `AppContext` interface, the `opts` type, and the `app.ctx = {...}` block change — everything else in the file is unchanged.)

- [ ] **Step 4: Use `app.ctx.baseUrl` in `routes.attestations.ts`**

In `src/api/routes.attestations.ts`, change the two hardcoded URLs inside `POST /v1/attestations`:

```ts
      approveUrlBase: `${app.ctx.baseUrl}/approve/app.html?attestation=${attestationId}`,
```

```ts
      approve_url: `${app.ctx.baseUrl}/approve/index.html?attestation=${attestationId}`,
```

(Both lines already exist with `http://localhost:3000` hardcoded — just the two template-literal prefixes change.)

- [ ] **Step 5: Update `main.ts`**

Replace `src/main.ts` with:

```ts
import { buildServer } from "./api/server.js";
import { loadConfig } from "./config.js";

const config = loadConfig();
const app = await buildServer({
  dbPath: config.dbPath, keyDir: config.keyDir, baseUrl: config.baseUrl,
});
await app.listen({ port: config.port, host: config.host });
console.log(`human-attest listening on ${config.baseUrl}`);
```

- [ ] **Step 6: Run test to verify it passes, then full regression**

Run: `npx vitest run src/api/routes.attestations.test.ts` — both new tests PASS.
Run: `npx tsc --noEmit && npx vitest run && npm run e2e` — everything else unchanged.

- [ ] **Step 7: Commit**

```bash
git add src/config.ts src/config.test.ts src/webauthn/config.ts src/api/server.ts src/api/routes.attestations.ts src/api/routes.attestations.test.ts src/main.ts
git commit -m "feat: environment-driven config, replacing hardcoded localhost URLs"
```

(Task 1's files are included here since they were never separately committed — see Task 1's note.)

---

## Task 3: structured logging (opt-in) + push-send failure visibility

**Files:**
- Modify: `src/api/server.ts`, `src/main.ts`, `src/push/send.ts`, `src/api/routes.attestations.ts`
- Test: `src/push/send.test.ts`

**Interfaces:**
- Consumes: nothing new.
- Produces: `buildServer`'s `opts.logger?: FastifyServerOptions["logger"]`; `notifyApprovers`'s new optional 5th parameter `logger?: SendLogger`, where `interface SendLogger { warn(obj: Record<string, unknown>, msg: string): void }` (structurally compatible with Fastify's `app.log`, which is a Pino instance).

- [ ] **Step 1: Write the failing tests**

Add to `src/push/send.test.ts` (the file already has `db`, `vapid`, and the mocked `sendNotification` set up — reuse them):

```ts
it("calls the logger with details when a send fails", async () => {
  q.upsertPushSubscription(db, {
    id: "psub_1", principal_id: "prin_1",
    endpoint: "https://push.example/fails", p256dh: "k", auth: "s",
  });
  sendNotification.mockRejectedValueOnce(Object.assign(new Error("gone"), { statusCode: 410 }));
  const warn = vi.fn();
  await notifyApprovers(db, vapid, ["prin_1"], {
    attestation_id: "att_1", headline: "x", approveUrlBase: "http://x/approve/app.html?attestation=att_1",
  }, { warn });
  expect(warn).toHaveBeenCalledWith(
    expect.objectContaining({ principal_id: "prin_1", endpoint: "https://push.example/fails", status_code: 410 }),
    "push send failed",
  );
});

it("works with no logger passed (logger is optional)", async () => {
  q.upsertPushSubscription(db, {
    id: "psub_1", principal_id: "prin_1",
    endpoint: "https://push.example/nologger", p256dh: "k", auth: "s",
  });
  sendNotification.mockRejectedValueOnce(new Error("boom"));
  await expect(notifyApprovers(db, vapid, ["prin_1"], {
    attestation_id: "att_1", headline: "x", approveUrlBase: "http://x/approve/app.html?attestation=att_1",
  })).resolves.toBeUndefined();
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `npx vitest run src/push/send.test.ts`
Expected: the first new test FAILS (`notifyApprovers` doesn't accept a 5th argument / never calls `warn`). The second passes already (it's really a regression guard for the next step).

- [ ] **Step 3: Add the logger parameter to `send.ts`**

In `src/push/send.ts`, add the interface and thread `logger` through both catch blocks (the file's structure — outer per-principal `try`, inner per-subscription `try` — is otherwise unchanged):

```ts
export interface SendLogger {
  warn(obj: Record<string, unknown>, msg: string): void;
}

export async function notifyApprovers(
  db: Database, vapid: VapidKeys, approverIds: string[], notice: PushNotice, logger?: SendLogger,
): Promise<void> {
  for (const principalId of approverIds) {
    try {
      const subs = q.getPushSubscriptionsFor(db, principalId);
      if (subs.length === 0) continue;

      const message = JSON.stringify({
        title: "Approval requested",
        body: notice.headline,
        attestation_id: notice.attestation_id,
        url: `${notice.approveUrlBase}&principal=${principalId}`,
      });

      for (const sub of subs) {
        try {
          await webpush.sendNotification(
            { endpoint: sub.endpoint, keys: { p256dh: sub.p256dh, auth: sub.auth } },
            message,
            { vapidDetails: { subject: VAPID_SUBJECT, publicKey: vapid.publicKey, privateKey: vapid.privateKey } },
          );
        } catch (err) {
          const statusCode = (err as { statusCode?: number }).statusCode;
          if (statusCode === 404 || statusCode === 410) {
            q.deletePushSubscription(db, sub.endpoint);
          }
          logger?.warn(
            { principal_id: principalId, endpoint: sub.endpoint, status_code: statusCode ?? null },
            "push send failed",
          );
        }
      }
    } catch (err) {
      logger?.warn({ principal_id: principalId, err: String(err) }, "push notification processing failed");
    }
  }
}
```

- [ ] **Step 4: Pass `app.log` at the call site**

In `src/api/routes.attestations.ts`, the existing `void notifyApprovers(db, app.ctx.vapid, envelope.approver_ids, {...})` call gets a 5th argument:

```ts
    void notifyApprovers(db, app.ctx.vapid, envelope.approver_ids, {
      attestation_id: attestationId,
      headline: action.summary.headline,
      approveUrlBase: `${app.ctx.baseUrl}/approve/app.html?attestation=${attestationId}`,
    }, app.log);
```

(`app.log` always exists — Fastify decorates it with a no-op-ish logger even when `logger: false`, so this is safe regardless of whether real logging is enabled.)

- [ ] **Step 5: Make logging opt-in in `server.ts` and enable it in `main.ts`**

In `src/api/server.ts`, change the import and the `Fastify(...)` call:

```ts
import Fastify, { type FastifyInstance, type FastifyServerOptions } from "fastify";
```

```ts
export async function buildServer(
  opts: { dbPath?: string; keyDir?: string; baseUrl?: string; logger?: FastifyServerOptions["logger"] } = {},
): Promise<FastifyInstance & { ctx: AppContext }> {
  const app = Fastify({ logger: opts.logger ?? false }) as unknown as FastifyInstance & { ctx: AppContext };
```

In `src/main.ts`, add the `logger` option:

```ts
const app = await buildServer({
  dbPath: config.dbPath, keyDir: config.keyDir, baseUrl: config.baseUrl,
  logger: { level: config.nodeEnv === "production" ? "info" : "debug" },
});
```

- [ ] **Step 6: Run to verify it passes, then full regression**

Run: `npx vitest run src/push/send.test.ts` — both new tests PASS.
Run: `npx tsc --noEmit && npx vitest run` — every existing test still passes with pristine output (no test file besides `main.ts`, which isn't under test, opts into real logging).

- [ ] **Step 7: Commit**

```bash
git add src/api/server.ts src/main.ts src/push/send.ts src/api/routes.attestations.ts src/push/send.test.ts
git commit -m "feat: opt-in structured logging, and visibility into push send failures"
```

---

## Task 4: rate limiting

**Files:**
- Modify: `src/api/server.ts`, `src/api/routes.principals.ts`, `src/api/routes.attestations.ts`
- Test: `src/api/rate-limit.test.ts`

**Interfaces:**
- Consumes: `@fastify/rate-limit` (new dependency).
- Produces: nothing later tasks consume directly.

- [ ] **Step 1: Install the dependency**

```bash
npm i @fastify/rate-limit
```

- [ ] **Step 2: Write the failing test**

Create `src/api/rate-limit.test.ts`:

```ts
// src/api/rate-limit.test.ts
import { describe, it, expect, beforeEach } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildServer } from "./server.js";

let app: Awaited<ReturnType<typeof buildServer>>;

beforeEach(async () => {
  app = await buildServer({
    dbPath: ":memory:",
    keyDir: mkdtempSync(join(tmpdir(), "ha-ratelimit-")),
  });
});

describe("rate limiting", () => {
  it("returns 429 after exceeding the principal-creation limit", async () => {
    let lastStatus = 200;
    for (let i = 0; i < 15; i++) {
      const res = await app.inject({
        method: "POST", url: "/v1/principals",
        payload: { email: `rl-${i}@test.local`, display_name: `RL ${i}` },
      });
      lastStatus = res.statusCode;
      if (lastStatus === 429) break;
    }
    expect(lastStatus).toBe(429);
  });

  it("does not rate-limit far below the configured threshold", async () => {
    const res = await app.inject({
      method: "POST", url: "/v1/principals",
      payload: { email: "rl-single@test.local", display_name: "Single" },
    });
    expect(res.statusCode).toBe(201);
  });
});
```

- [ ] **Step 3: Run to verify it fails**

Run: `npx vitest run src/api/rate-limit.test.ts`
Expected: first test FAILS (no rate limiting registered yet, all 15 requests return 201); second passes already.

- [ ] **Step 4: Register the plugin and per-route limits**

In `src/api/server.ts`, add the import and register it early (before route registration, after the static-file registrations — placement matters: it must wrap every route registered after it):

```ts
import fastifyRateLimit from "@fastify/rate-limit";
```

```ts
  await app.register(fastifyRateLimit, {
    max: 100,
    timeWindow: "1 minute",
  });
```

Add it directly after the two `fastifyStatic` registrations, before the `preValidation` hook.

In `src/api/routes.principals.ts`, add a per-route override to `POST /v1/principals` (principal + enrolment-token creation — the endpoint most worth protecting against being spammed to exhaust or enumerate tokens):

```ts
  app.post("/v1/principals", {
    config: { rateLimit: { max: 10, timeWindow: "1 minute" } },
  }, async (req, reply) => {
```

(Only the route registration's second argument changes — the handler body is untouched. `app.post(url, handler)` becomes `app.post(url, options, handler)`.)

In `src/api/routes.attestations.ts`, add the same style of override to `POST /v1/attestations/:id/options` (the WebAuthn ceremony's most probe-able endpoint — see the file's own comments on why this endpoint already guards against approver-enumeration; rate limiting is a second, independent layer):

```ts
  app.post("/v1/attestations/:id/options", {
    config: { rateLimit: { max: 30, timeWindow: "1 minute" } },
  }, async (req) => {
```

- [ ] **Step 5: Run to verify it passes, then full regression**

Run: `npx vitest run src/api/rate-limit.test.ts` — both PASS.
Run: `npx tsc --noEmit && npx vitest run && npm run e2e` — every existing test still passes (the global 100/min and route-level 10-30/min limits are far above what any single existing test performs in one run).

- [ ] **Step 6: Commit**

```bash
git add package.json package-lock.json src/api/server.ts src/api/routes.principals.ts src/api/routes.attestations.ts src/api/rate-limit.test.ts
git commit -m "feat: rate limit the API, with stricter limits on enrolment and WebAuthn ceremony endpoints"
```

---

## Task 5: security headers — extract inline scripts, add a real CSP

**Files:**
- Modify: `src/api/server.ts`
- Modify: `demo/public/index.html`, `demo/public/enrol.html`, `demo/public/app.html`
- Create: `demo/public/index.js`, `demo/public/enrol.js`, `demo/public/app.js`

**Interfaces:**
- Consumes: `@fastify/helmet` (new dependency).
- Produces: nothing later tasks consume.

**This is the highest-regression-risk task in this plan** — it changes every page every e2e spec drives, and a wrong CSP directive silently breaks a `<script>` tag or the service-worker registration with no helpful error in the DOM, only a browser console warning a headless run won't surface unless you look. Run the full e2e suite after every sub-step, not just at the end.

- [ ] **Step 1: Extract each page's inline script**

For each of `demo/public/index.html`, `demo/public/enrol.html`, `demo/public/app.html`: move the exact, unmodified content currently between `<script type="module">` and `</script>` into a new sibling file with the same base name and a `.js` extension (`index.js`, `enrol.js`, `app.js`), then replace the inline block with `<script type="module" src="/approve/index.js"></script>` (respectively `/approve/enrol.js`, `/approve/app.js`) at the exact same position in the HTML. Nothing about the script's logic changes — this is a pure code move. The `<script src="/vendor/simplewebauthn-browser.js"></script>` tag and any inline `<style>` blocks are untouched.

- [ ] **Step 2: Regression-check before adding the CSP**

Run: `npm run e2e`
Expected: all 11 specs still pass, unchanged — this isolates "did the extraction alone break anything" from "did the CSP break something," so a failure here is unambiguous.

- [ ] **Step 3: Install and register `@fastify/helmet` with an explicit CSP**

```bash
npm i @fastify/helmet
```

In `src/api/server.ts`, add the import and register it (placement: after the rate-limit registration from Task 4, before the `preValidation` hook):

```ts
import fastifyHelmet from "@fastify/helmet";
```

```ts
  await app.register(fastifyHelmet, {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
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
```

`styleSrc` keeps `'unsafe-inline'` because every page's `<head>` has an inline `<style>` block — extracting those too is a reasonable future improvement but out of scope here (style injection is a materially lower-severity vector than script injection, and this pass's priority is closing the bigger gap first). Every other directive is `'self'`-only, matching what these pages actually need: same-origin scripts (now external, per Step 1), same-origin fetches, same-origin manifest, same-origin service-worker registration.

- [ ] **Step 4: Run the full e2e suite again**

Run: `npm run e2e`
Expected: all 11 specs still pass. If any spec that drives `enrol.html` or `app.html` starts failing here (and only here, not in Step 2), the CSP is the cause — check the exact directive against what failed (a blocked service-worker registration means `workerSrc` is wrong; a blocked fetch means `connectSrc`; a blocked manifest link means `manifestSrc`) rather than loosening the policy broadly.

- [ ] **Step 5: Full regression**

Run: `npx tsc --noEmit && npx vitest run && npm run e2e`

- [ ] **Step 6: Commit**

```bash
git add package.json package-lock.json src/api/server.ts demo/public/index.html demo/public/enrol.html demo/public/app.html demo/public/index.js demo/public/enrol.js demo/public/app.js
git commit -m "feat: extract inline scripts and add a real Content-Security-Policy"
```

---

## Task 6: secrets via environment, health endpoint, graceful shutdown

**Files:**
- Modify: `src/crypto/tokens.ts`, `src/push/vapid.ts`, `src/api/server.ts`, `src/main.ts`
- Create: `src/api/routes.health.ts`
- Test: `src/crypto/tokens.test.ts`, `src/push/vapid.test.ts`, `src/api/routes.health.test.ts`

**Interfaces:**
- Consumes: nothing new.
- Produces: `registerHealthRoutes(app)`, called from `server.ts` like the other four `register*Routes` calls.

- [ ] **Step 1: Write the failing tests**

Add to `src/crypto/tokens.test.ts` (inside the existing `describe("attestation tokens", ...)` block, reusing the file's existing `kp` fixture and imports — add `existsSync` to the existing `node:fs` import and `exportJWK` to the existing `jose` import):

```ts
it("loads a keypair from SIGNING_KEY_JSON when set, without touching disk", async () => {
  const dir = mkdtempSync(join(tmpdir(), "ha-envkey-"));
  const privateJwk = await exportJWK(kp.privateKey);
  process.env.SIGNING_KEY_JSON = JSON.stringify({ privateJwk, publicJwk: kp.publicJwk, kid: kp.kid });
  try {
    const loaded = await loadOrCreateKeypair(dir);
    expect(loaded.kid).toBe(kp.kid);
    expect(existsSync(join(dir, "signing-key.json"))).toBe(false);
  } finally {
    delete process.env.SIGNING_KEY_JSON;
  }
});
```

Add to `src/push/vapid.test.ts` (add `existsSync, writeFileSync` to the existing `node:fs` import):

```ts
it("loads keys from VAPID_KEYS_JSON when set, without touching disk", () => {
  const dir = mkdtempSync(join(tmpdir(), "ha-vapid-envkey-"));
  process.env.VAPID_KEYS_JSON = JSON.stringify({ publicKey: "env-pub", privateKey: "env-priv" });
  try {
    const keys = loadOrCreateVapidKeys(dir);
    expect(keys).toEqual({ publicKey: "env-pub", privateKey: "env-priv" });
    expect(existsSync(join(dir, "vapid-keys.json"))).toBe(false);
  } finally {
    delete process.env.VAPID_KEYS_JSON;
  }
});

it("throws if VAPID_KEYS_JSON is malformed", () => {
  process.env.VAPID_KEYS_JSON = JSON.stringify({ publicKey: "" });
  try {
    expect(() => loadOrCreateVapidKeys(mkdtempSync(join(tmpdir(), "ha-vapid-bad-")))).toThrow(/malformed/);
  } finally {
    delete process.env.VAPID_KEYS_JSON;
  }
});

it("throws if the on-disk vapid-keys.json is malformed", () => {
  const dir = mkdtempSync(join(tmpdir(), "ha-vapid-corrupt-"));
  writeFileSync(join(dir, "vapid-keys.json"), JSON.stringify({ publicKey: "" }));
  expect(() => loadOrCreateVapidKeys(dir)).toThrow(/malformed/);
});
```

Create `src/api/routes.health.test.ts`:

```ts
// src/api/routes.health.test.ts
import { describe, it, expect, beforeEach } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildServer } from "./server.js";

let app: Awaited<ReturnType<typeof buildServer>>;

beforeEach(async () => {
  app = await buildServer({
    dbPath: ":memory:",
    keyDir: mkdtempSync(join(tmpdir(), "ha-health-")),
  });
});

describe("GET /healthz", () => {
  it("reports ok when the database is reachable", async () => {
    const res = await app.inject({ method: "GET", url: "/healthz" });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ status: "ok" });
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `npx vitest run src/crypto/tokens.test.ts src/push/vapid.test.ts src/api/routes.health.test.ts`
Expected: FAIL — `SIGNING_KEY_JSON`/`VAPID_KEYS_JSON` aren't read yet, malformed VAPID files aren't validated yet, and `/healthz` doesn't exist yet (connection refused / 404).

- [ ] **Step 3: `SIGNING_KEY_JSON` support in `crypto/tokens.ts`**

In `src/crypto/tokens.ts`, change `loadOrCreateKeypair` to check the env var first:

```ts
export async function loadOrCreateKeypair(dir: string): Promise<Keypair> {
  const envKey = process.env.SIGNING_KEY_JSON;
  if (envKey) {
    const stored = JSON.parse(envKey) as { privateJwk: JWK; publicJwk: JWK; kid: string };
    return {
      privateKey: (await importJWK(stored.privateJwk, ALG)) as CryptoKey,
      publicJwk: stored.publicJwk,
      kid: stored.kid,
    };
  }

  mkdirSync(dir, { recursive: true });
  const path = join(dir, "signing-key.json");
  // ... rest of the function is unchanged from here down.
```

- [ ] **Step 4: `VAPID_KEYS_JSON` support + shape validation in `push/vapid.ts`**

Replace `src/push/vapid.ts` with:

```ts
import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import webpush from "web-push";

export interface VapidKeys { publicKey: string; privateKey: string; }

function assertShape(keys: unknown, source: string): asserts keys is VapidKeys {
  const k = keys as { publicKey?: unknown; privateKey?: unknown };
  if (typeof k.publicKey !== "string" || k.publicKey.length === 0 ||
      typeof k.privateKey !== "string" || k.privateKey.length === 0) {
    throw new Error(`${source} is malformed -- expected {publicKey, privateKey} non-empty strings`);
  }
}

/**
 * Same on-disk pattern as crypto/tokens.ts's loadOrCreateKeypair: generate
 * once, persist under the same keys/ directory, and reuse thereafter so
 * subscriptions registered against an old public key don't silently stop
 * verifying after a restart. VAPID_KEYS_JSON, when set, takes priority and
 * never touches disk -- the portable way to inject key material from a
 * secrets manager (AWS Secrets Manager, Vault, k8s Secrets, ...) without a
 * cloud-provider-specific SDK: every one of them can ultimately expose a
 * secret as an environment variable.
 */
export function loadOrCreateVapidKeys(dir: string): VapidKeys {
  const envKeys = process.env.VAPID_KEYS_JSON;
  if (envKeys) {
    const keys = JSON.parse(envKeys) as unknown;
    assertShape(keys, "VAPID_KEYS_JSON");
    return keys;
  }

  mkdirSync(dir, { recursive: true });
  const path = join(dir, "vapid-keys.json");

  if (existsSync(path)) {
    const keys = JSON.parse(readFileSync(path, "utf8")) as unknown;
    assertShape(keys, path);
    return keys;
  }

  const keys = webpush.generateVAPIDKeys();
  writeFileSync(path, JSON.stringify(keys, null, 2), { mode: 0o600 });
  return keys;
}
```

- [ ] **Step 5: `GET /healthz`**

Create `src/api/routes.health.ts`:

```ts
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
```

In `src/api/server.ts`, import and register it alongside the other four:

```ts
import { registerHealthRoutes } from "./routes.health.js";
```

```ts
  registerPrincipalRoutes(app);
  registerAttestationRoutes(app);
  registerVerifyRoutes(app);
  registerPushRoutes(app);
  registerHealthRoutes(app);
```

- [ ] **Step 6: Graceful shutdown in `main.ts`**

Append to `src/main.ts` (after the existing `console.log` line):

```ts
async function shutdown(signal: string): Promise<void> {
  app.log.info({ signal }, "shutting down");
  await app.close();
  app.ctx.db.close();
  process.exit(0);
}
process.on("SIGTERM", () => void shutdown("SIGTERM"));
process.on("SIGINT", () => void shutdown("SIGINT"));
```

- [ ] **Step 7: Run to verify it passes, then full regression**

Run: `npx vitest run src/crypto/tokens.test.ts src/push/vapid.test.ts src/api/routes.health.test.ts` — all new tests PASS.
Run: `npx tsc --noEmit && npx vitest run && npm run e2e`

- [ ] **Step 8: Commit**

```bash
git add src/crypto/tokens.ts src/crypto/tokens.test.ts src/push/vapid.ts src/push/vapid.test.ts src/api/routes.health.ts src/api/routes.health.test.ts src/api/server.ts src/main.ts
git commit -m "feat: env-injectable secrets, key-file shape validation, health check, graceful shutdown"
```

---

## Task 7: key-rotation-correct JWT verification, and two parked findings

**Files:**
- Modify: `src/crypto/tokens.ts`, `demo/public/enrol.html`, `src/db/queries.ts`
- Test: `src/crypto/tokens.test.ts`

**Interfaces:**
- Consumes: nothing new.
- Produces: nothing later tasks consume — this is a correctness fix plus two small cleanups parked from the session's earlier final review.

- [ ] **Step 1: Write the failing test**

Add to `src/crypto/tokens.test.ts`, inside `describe("attestation tokens", ...)`:

```ts
it("verifies a token by matching its kid against the JWKS, not just the first entry", async () => {
  const other = await loadOrCreateKeypair(mkdtempSync(join(tmpdir(), "ha-rotate-other-")));
  const token = await signAttestation(kp, {
    jti: "att_1", sub: "prin_1", act: "sha256:abc", approvers: ["prin_1"], mth: "passkey",
  }, 300);
  // A rotated JWKS where the token's real signing key is NOT at index 0.
  const result = await verifyAttestation({ keys: [other.publicJwk, kp.publicJwk] }, token);
  expect(result.valid).toBe(true);
});

it("rejects a token whose kid matches no key in the JWKS", async () => {
  const other = await loadOrCreateKeypair(mkdtempSync(join(tmpdir(), "ha-rotate-missing-")));
  const token = await signAttestation(kp, {
    jti: "att_1", sub: "prin_1", act: "sha256:abc", approvers: ["prin_1"], mth: "passkey",
  }, 300);
  const result = await verifyAttestation({ keys: [other.publicJwk] }, token);
  expect(result.valid).toBe(false);
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `npx vitest run src/crypto/tokens.test.ts`
Expected: the first new test FAILS — `verifyAttestation` today always tries `jwks.keys[0]` (`other.publicJwk` in this test), which is the wrong key for this token, so verification incorrectly reports `valid: false`.

- [ ] **Step 3: Fix `verifyAttestation`**

In `src/crypto/tokens.ts`, replace the function body:

```ts
export async function verifyAttestation(
  jwks: { keys: JWK[] }, token: string,
): Promise<VerifyResult> {
  try {
    const [headerB64] = token.split(".");
    const header = JSON.parse(Buffer.from(headerB64, "base64url").toString()) as { kid?: string };
    const jwk = header.kid ? jwks.keys.find((k) => k.kid === header.kid) : jwks.keys[0];
    if (!jwk) return { valid: false, reason: "signature_invalid" };

    const key = (await importJWK(jwk, ALG)) as CryptoKey;
    const { payload } = await jwtVerify(token, key, { algorithms: [ALG] });
    return {
      valid: true,
      principal_id: payload.sub,
      action_hash: payload.act as string,
      approved_at: new Date((payload.iat ?? 0) * 1000).toISOString(),
    };
  } catch (err) {
    const code = (err as { code?: string }).code;
    if (code === "ERR_JWT_EXPIRED") return { valid: false, reason: "expired" };
    return { valid: false, reason: "signature_invalid" };
  }
}
```

(The header-parsing step is inside the same `try`, so a malformed token still falls through to the existing `catch` and the existing opaque `signature_invalid` — no new failure mode.)

- [ ] **Step 4: Widen `enrol.html`'s push-subscribe timeout**

The final whole-branch review from this session's earlier push-notification plan parked a Minor finding: 5 seconds may be too tight for a real user actually reading the notification-permission prompt (as opposed to the pathological "walked away" case it's meant to guard against). In `demo/public/enrol.html`, change the `setTimeout` call from `5000` to `15000`, and update the adjacent comment's "5s" reference to "15s" to match.

- [ ] **Step 5: Document the push-subscription upsert tradeoff**

The same final review parked a second Minor finding about `upsertPushSubscription`'s `endpoint`-only uniqueness. In `src/db/queries.ts`, append to the existing doc comment directly above `upsertPushSubscription` (do not replace it — add this as a new paragraph after the existing one):

```
 *
 * Accepted tradeoff (production-hardening review, 2026-07-29): because
 * `endpoint` is globally unique rather than scoped per-principal, a second
 * principal who already knows a first principal's real endpoint URL could
 * re-register it to themselves, silently unsubscribing the original owner.
 * In practice this requires already knowing a high-entropy, server-generated
 * value that is never exposed to any other principal or caller -- reachable
 * only via database access or intercepting the original subscribe call, at
 * which point far worse is already possible. Impact is bounded to
 * denial-of-notification (a push message encrypted for the wrong browser's
 * keys can't be read by anyone), never disclosure, on a best-effort channel.
 * Scoping the constraint to (principal_id, endpoint) instead was considered
 * and rejected: it would let two principals coexist on one real browser
 * subscription, which cannot happen in practice (one browser, one
 * subscription, one owner) and would just mask the same re-registration
 * behavior under a different key.
```

- [ ] **Step 6: Run to verify it passes, then full regression**

Run: `npx vitest run src/crypto/tokens.test.ts` — both new tests PASS.
Run: `npx tsc --noEmit && npx vitest run && npm run e2e`

- [ ] **Step 7: Commit**

```bash
git add src/crypto/tokens.ts src/crypto/tokens.test.ts demo/public/enrol.html src/db/queries.ts
git commit -m "fix: verify JWTs by kid (not always the first JWKS entry); widen enrol.html's push timeout; document a parked tradeoff"
```

---

## Task 8: Docker deployment, verified locally

**Files:**
- Create: `Dockerfile`, `.dockerignore`, `docker-compose.yml`
- Modify: `package.json` (move `tsx` from `devDependencies` to `dependencies` — the chosen no-build deployment runs the app via `tsx` in production, so it is a runtime dependency, not a dev-only one; `typescript` itself stays dev-only, since `tsx` uses esbuild for type-stripping and never invokes `tsc` at runtime)

**Interfaces:** none — this task is deployment packaging only.

- [ ] **Step 1: Move `tsx` to `dependencies`**

In `package.json`, cut `"tsx": "^4.23.1"` from `devDependencies` and add it to `dependencies`. Run `npm install` afterward so the lockfile reflects the move.

- [ ] **Step 2: `Dockerfile`**

```dockerfile
FROM node:22-slim

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY src ./src
COPY demo ./demo
COPY tsconfig.json ./

ENV NODE_ENV=production
EXPOSE 3000

CMD ["npx", "tsx", "src/main.ts"]
```

- [ ] **Step 3: `.dockerignore`**

```
node_modules
dist
*.db
keys
test-results
.git
.superpowers
docs
tests
```

- [ ] **Step 4: `docker-compose.yml`**

```yaml
services:
  human-attest:
    build: .
    ports:
      - "3000:3000"
    environment:
      NODE_ENV: production
      PORT: "3000"
      HOST: "0.0.0.0"
      BASE_URL: ${BASE_URL:?set BASE_URL to your real https domain}
      RP_ID: ${RP_ID:?set RP_ID to your real domain}
      DB_PATH: /data/human-attest.db
      KEY_DIR: /data/keys
    volumes:
      - human-attest-data:/data
volumes:
  human-attest-data:
```

`${VAR:?message}` makes `docker compose up` fail loudly if `BASE_URL`/`RP_ID` aren't set, rather than silently booting misconfigured — matching `loadConfig`'s own fail-closed check from Task 1 (which would independently refuse to start anyway, but failing at the compose layer gives a clearer message).

- [ ] **Step 5: Build and actually run it — this step is not optional**

```bash
docker build -t human-attest-demo .
docker run -d --name ha-verify -p 3001:3000 \
  -e NODE_ENV=production -e PORT=3000 -e HOST=0.0.0.0 \
  -e BASE_URL=https://attest.verify.test -e RP_ID=attest.verify.test \
  human-attest-demo
sleep 3
curl -sf http://localhost:3001/healthz && echo " -- healthz OK"
docker logs ha-verify
docker rm -f ha-verify
```

Expected: `curl` prints `{"status":"ok"} -- healthz OK`, and `docker logs` shows a clean structured-JSON startup log line (`"human-attest listening on https://attest.verify.test"` message, or the pino-formatted equivalent) with no stack traces. This is a real container, actually built and actually run — paste the real output in your report, not a paraphrase.

- [ ] **Step 6: Commit**

```bash
git add Dockerfile .dockerignore docker-compose.yml package.json package-lock.json
git commit -m "feat: Docker deployment (verified: built and run locally, /healthz responds)"
```

---

## Task 9: CI pipeline + dependency audit

**Files:**
- Create: `.github/workflows/ci.yml`

**Interfaces:** none.

- [ ] **Step 1: `npm audit`**

Run: `npm audit`
If it reports fixable vulnerabilities, run `npm audit fix` and then the full regression suite (`npx tsc --noEmit && npx vitest run && npm run e2e`) to confirm nothing broke. If `npm audit fix` would require a breaking major-version bump to resolve something, do not force it — report the finding instead of forcing a risky upgrade mid-hardening-pass.

- [ ] **Step 2: `.github/workflows/ci.yml`**

```yaml
name: CI
on:
  push:
    branches: [main]
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
          cache: npm
      - run: npm ci
      - run: npx playwright install --with-deps chromium
      - run: npx tsc --noEmit
      - run: npm test
      - run: npm run e2e
      - run: npm audit --audit-level=high
```

Every command in this workflow is one already run and verified locally throughout this plan and the session before it — this file just sequences them for CI. **This cannot be verified by actually running on GitHub's runners in this environment** (that needs a real GitHub repo with Actions enabled); what's verified here is that the YAML is syntactically valid and every command it runs has already succeeded locally in this exact working tree.

Validate the YAML syntax before committing — try `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))"` (works if Python+PyYAML is available in this environment; if not, any other YAML parser you have on hand is fine). If nothing is available, carefully re-check the indentation by eye instead of skipping this check silently, and say in your report which path you took.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml package.json package-lock.json
git commit -m "ci: add a GitHub Actions workflow running typecheck, unit/integration tests, e2e, and an audit"
```

(Include `package.json`/`package-lock.json` only if Step 1's `npm audit fix` changed them; otherwise omit them from this commit.)

---

## Task 10: local load/concurrency probe, audit-log export, `docs/PRODUCTION.md`

**Files:**
- Create: `scripts/load-test.mts`, `scripts/export-audit-log.mts`, `docs/PRODUCTION.md`

**Interfaces:** none.

- [ ] **Step 0: `scripts/export-audit-log.mts`**

`audit_log` has no way to get its contents out today short of opening the SQLite file directly with a generic tool. This is deliberately a **local script that opens the DB file directly, not an HTTP endpoint** — an unauthenticated `GET /v1/audit-log` would be new, real attack surface (the audit trail includes principal emails and rejection detail), and adding real authentication/authorization for one read-only operator tool is a disproportionate amount of new surface for this pass. A script that requires the same filesystem access as the database file itself matches who should actually be able to read it: an operator with access to the deployment, not the network.

```ts
// Dumps audit_log to newline-delimited JSON on stdout, oldest first.
// Requires direct access to the database file -- deliberately not an HTTP
// endpoint (see the note in docs/superpowers/plans/2026-07-29-production-hardening.md,
// Task 10) so reading the audit trail needs the same access as the DB file
// itself, not a new authenticated network surface.
//
// Usage: npx tsx scripts/export-audit-log.mts <path-to-db> [--since=<ISO8601>]

import Database from "better-sqlite3";

const dbPath = process.argv[2];
if (!dbPath) {
  console.error("usage: npx tsx scripts/export-audit-log.mts <path-to-db> [--since=<ISO8601>]");
  process.exit(1);
}

const sinceArg = process.argv.find((a) => a.startsWith("--since="));
const since = sinceArg ? sinceArg.slice("--since=".length) : null;

const db = new Database(dbPath, { readonly: true });
const rows = since
  ? db.prepare("SELECT * FROM audit_log WHERE created_at >= ? ORDER BY id ASC").all(since)
  : db.prepare("SELECT * FROM audit_log ORDER BY id ASC").all();

for (const row of rows) {
  process.stdout.write(JSON.stringify(row) + "\n");
}
db.close();
```

Run it against a real DB with real rows in it (e.g. the one `scripts/load-test.mts` in Step 2 below will populate) and confirm the output is genuine newline-delimited JSON, one real row per line — paste a few real lines (redact nothing, this is a local dev DB) in your report.

- [ ] **Step 1: `scripts/load-test.mts`**

```ts
// Local concurrency/load probe against a running Human-Attest server.
// Not a CI-gated test -- SQLite (this project's storage engine) is
// single-writer by design, so the interesting question isn't "how many
// requests/sec" but "does concurrent write contention ever produce wrong
// results," which src/api/state.race.test.ts already covers at the unit
// level. This script instead measures real HTTP-layer latency under
// concurrent load and confirms the server stays correct (every attestation
// created is independently readable back) while under it.
//
// Usage: BASE=http://localhost:3000 npx tsx scripts/load-test.mts [concurrency] [total]

const BASE = process.env.BASE ?? "http://localhost:3000";
const CONCURRENCY = Number(process.argv[2] ?? 20);
const TOTAL = Number(process.argv[3] ?? 200);

async function createAttestation(): Promise<number> {
  const start = performance.now();
  const principal = await fetch(`${BASE}/v1/principals`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ email: `load-${crypto.randomUUID()}@test.local`, display_name: "Load Test" }),
  }).then((r) => r.json());

  const res = await fetch(`${BASE}/v1/attestations`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({
      requested_by: "load-test", approver_ids: [principal.principal_id],
      action: { type: "generic", risk_tier: "low", payload: { title: "Load test", detail: "x" } },
    }),
  });
  if (res.status !== 201) throw new Error(`unexpected status ${res.status}`);
  const body = await res.json();

  const readback = await fetch(`${BASE}/v1/attestations/${body.attestation_id}`).then((r) => r.json());
  if (readback.attestation_id !== body.attestation_id || readback.status !== "pending") {
    throw new Error(`readback mismatch for ${body.attestation_id}`);
  }

  return performance.now() - start;
}

async function worker(latencies: number[], remaining: { count: number }): Promise<void> {
  while (remaining.count > 0) {
    remaining.count--;
    latencies.push(await createAttestation());
  }
}

function percentile(sorted: number[], p: number): number {
  const idx = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length));
  return sorted[idx];
}

const latencies: number[] = [];
const remaining = { count: TOTAL };
const started = performance.now();
await Promise.all(Array.from({ length: CONCURRENCY }, () => worker(latencies, remaining)));
const elapsed = performance.now() - started;

const sorted = [...latencies].sort((a, b) => a - b);
console.log(`\n${TOTAL} attestations created and read back correctly, concurrency=${CONCURRENCY}`);
console.log(`  total wall time:  ${elapsed.toFixed(0)}ms`);
console.log(`  throughput:       ${(TOTAL / (elapsed / 1000)).toFixed(1)} attestations/sec`);
console.log(`  latency p50:      ${percentile(sorted, 50).toFixed(1)}ms`);
console.log(`  latency p95:      ${percentile(sorted, 95).toFixed(1)}ms`);
console.log(`  latency p99:      ${percentile(sorted, 99).toFixed(1)}ms`);
console.log(`  latency max:      ${sorted[sorted.length - 1].toFixed(1)}ms`);
```

- [ ] **Step 2: Actually run it against a real local server — not optional**

```bash
npx tsx src/main.ts &
sleep 2
npx tsx scripts/load-test.mts 20 200
kill %1
```

Paste the real printed numbers into your report. If any request in the run throws (non-201 status, or a readback mismatch), that is a real bug this task surfaced — stop and report it rather than re-running until it happens to pass.

- [ ] **Step 3: `docs/PRODUCTION.md`**

Write a deployment doc covering, in this order:
1. **Required environment variables** — a table of every var `loadConfig` (Task 1) and the key-loading functions (Task 6) read: `NODE_ENV`, `PORT`, `HOST`, `BASE_URL`, `RP_ID`, `RP_ORIGIN`, `DB_PATH`, `KEY_DIR`, `SIGNING_KEY_JSON` (optional), `VAPID_KEYS_JSON` (optional) — what each does, and its default.
2. **Secrets** — two supported patterns: on-disk files under `KEY_DIR` (the default, fine for a single trusted host) or `SIGNING_KEY_JSON`/`VAPID_KEYS_JSON` env vars (the portable pattern for injecting from AWS Secrets Manager, Vault, or Kubernetes Secrets — all of which can ultimately expose a secret as an environment variable, which is why this plan didn't build a cloud-provider-specific SDK integration).
3. **Running it** — `docker compose up` with `BASE_URL`/`RP_ID` set, referencing Task 8's `docker-compose.yml`.
4. **Data durability** — SQLite with WAL mode (already the schema's `PRAGMA journal_mode = WAL`) survives process crashes, but this is a **single-instance deployment**: SQLite is single-writer, there is no built-in replication, and the Docker volume is the only copy. Recommend a periodic file-level backup of `DB_PATH` at minimum, and name Litestream (continuous SQLite replication to object storage) as the standard tool for this if durability beyond "single host, single disk" is required. State plainly that migrating to a client-server database (Postgres) is the natural next step if this needs to run as more than one instance, and that this plan deliberately did not do that migration (out of scope — a storage-engine change is a materially different, riskier undertaking than the hardening covered here).
5. **What this deployment does NOT include**, stated plainly: TLS termination (put a real reverse proxy or load balancer in front — this app expects to be reached over HTTPS at `BASE_URL`, but doesn't terminate TLS itself), horizontal scaling (single SQLite file), a compiled build step (runs via `tsx`, see Task 8's Dockerfile), and any cloud-provider-specific secrets integration (only the portable env-var injection point from Task 6).
6. **Load characteristics** — the real numbers from Step 2's run, with a one-line caveat that these were measured on a shared development machine, not representative production hardware.
7. **Audit trail** — how to run `scripts/export-audit-log.mts` against the deployed DB file to get the full audit trail as newline-delimited JSON, and why it's a local script requiring filesystem access rather than an HTTP endpoint (Step 0's rationale).

- [ ] **Step 4: Commit**

```bash
git add scripts/load-test.mts scripts/export-audit-log.mts docs/PRODUCTION.md
git commit -m "docs: production deployment guide, plus a local load/concurrency probe and an audit-log export script"
```

---

## Definition of Done

- [ ] All 10 tasks committed (Task 1 already is, as the lead's foundational commit).
- [ ] `npx tsc --noEmit` clean.
- [ ] `npx vitest run` — every unit/integration test passes, pristine output.
- [ ] `npm run e2e` — all 11 specs pass, unmodified from before this plan.
- [ ] `npm audit --audit-level=high` clean (or any unresolved finding explicitly reported, not silently left).
- [ ] The Docker image builds and actually runs, `/healthz` responds `{"status":"ok"}`, verified with real command output in the task report.
- [ ] `scripts/load-test.mts` has actually been run against a real local server, with real numbers in `docs/PRODUCTION.md`.
- [ ] A misconfigured `NODE_ENV=production` deployment (still pointed at `localhost`) refuses to boot with a clear error, verified by a real test.
