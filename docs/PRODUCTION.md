# Production deployment guide

This document is for someone deploying Human-Attest for real, tying together
the env-driven config, secrets handling, containerized deployment, durability
model, and operational tooling built across this hardening plan
(`docs/superpowers/plans/2026-07-29-production-hardening.md`).

## 1. Required environment variables

Read by `loadConfig` (`src/config.ts`) and the key-loading function
(`src/crypto/tokens.ts`):

| Variable              | What it does                                                                 | Default                  |
|-----------------------|-------------------------------------------------------------------------------|---------------------------|
| `NODE_ENV`            | `development` \| `production` \| `test`. In `production`, boot fails closed if `RP_ID`/`APP_BASE_URL` still point at `localhost`, or if `SMTP_URL` is unset (see §5). | `development` |
| `PORT`                | TCP port the HTTP server listens on.                                          | `3000`                    |
| `HOST`                | Interface to bind. Use `0.0.0.0` inside a container so it's reachable from outside it. | `127.0.0.1`        |
| `APP_BASE_URL`        | The public HTTPS origin this app is reached at (used to build every link mailed to an approver, and as the default `RP_ORIGIN`). **Not** `BASE_URL` — that name is reserved by Vite/Vitest and gets silently overwritten under the test runner; this app deliberately uses its own name to avoid the collision. | `http://localhost:3000` |
| `RP_ID`               | WebAuthn Relying Party ID — must be your real domain (e.g. `attest.example.com`), not an IP or `localhost`, for registered credentials to verify in production. | `localhost` |
| `RP_ORIGIN`           | WebAuthn expected origin. Normally leave unset — it defaults to `APP_BASE_URL`. Only set separately if the RP ID's origin differs from the app's own base URL. | value of `APP_BASE_URL` |
| `DB_PATH`             | Path to the SQLite database file.                                             | `human-attest.db` (relative to CWD) |
| `KEY_DIR`             | Directory for on-disk key material (`signing-key.json`) when `SIGNING_KEY_JSON` isn't set. | `keys` (relative to CWD) |
| `TRUST_PROXY`         | Set to `true` when deployed behind a single reverse proxy you control, so rate limiting (and any other IP-derived logic) keys on the real client's `X-Forwarded-For` address instead of the proxy's own. See §3's note below before enabling this. | `false` |
| `SIGNING_KEY_JSON`    | *Optional.* JSON blob `{"privateJwk": {...}, "publicJwk": {...}, "kid": "..."}` — injects the ES256 attestation-token signing keypair without touching disk. | unset (falls back to `KEY_DIR/signing-key.json`, generated on first boot) |
| `SMTP_URL`            | An SMTP connection URL (`smtp://user:pass@host:port`), passed straight to `nodemailer`. **Required in production** — see §5. Unset in any other `NODE_ENV`, every approval and enrolment email is written to `MAIL_DIR` as an `.eml` file instead of sent. | unset |
| `MAIL_FROM`           | The `From:` address on every outgoing email.                                  | `no-reply@<APP_BASE_URL host>` |
| `MAIL_DIR`            | Where the file transport writes `.eml` files when `SMTP_URL` is unset. Irrelevant once `SMTP_URL` is set. | `mail` (relative to CWD) |
| `SESSION_TTL_HOURS`   | How long a dashboard sign-in session (`GET /web/requests` and friends) stays valid. | `168` (one week) |

## 2. Secrets

Two supported patterns for the attestation-signing keypair:

- **An on-disk file under `KEY_DIR`** (the default). On first boot, if no key
  file exists, one is generated and written to `KEY_DIR/signing-key.json`
  (mode `0600`). Fine for a single trusted host where the volume itself is
  the secret boundary — this is what `docker-compose.yml`'s named volume
  does.
- **`SIGNING_KEY_JSON`** — the portable pattern for injecting key material
  from AWS Secrets Manager, HashiCorp Vault, or Kubernetes Secrets. All three
  ultimately expose a secret to a process as an environment variable, which
  is why this plan didn't build a cloud-provider-specific SDK integration on
  top — set this var from whatever secret store you use, and the app never
  touches disk for key material. When set, it takes priority over `KEY_DIR`
  unconditionally.

Either way, **generate this once and keep it** — rotating the signing key
invalidates every outstanding attestation token.

`SMTP_URL` is not a secret in the same sense — it's a connection string,
typically already including credentials in its own userinfo component — but
it belongs in the same secret store as the two keys above, for the same
reason: it grants the ability to send mail as this service.

## 3. Running it

The committed `docker-compose.yml` builds the image from the repo's
multi-stage `Dockerfile` and runs it with a persistent volume for the
database and keys:

```bash
APP_BASE_URL=https://attest.example.com RP_ID=attest.example.com \
  SMTP_URL=smtps://user:pass@smtp.example.com:465 \
  docker compose up --build
```

`APP_BASE_URL`, `RP_ID`, and `SMTP_URL` are all required —
`docker-compose.yml` uses Compose's `${VAR:?message}` syntax so it refuses to
start without any of them, rather than silently defaulting to `localhost` (a
deployment that can never pass a WebAuthn origin check) or silently writing
approval emails to a directory inside the container that no approver will
ever see (a deployment where requests just sit pending until they expire,
with nothing in the logs to say why). `docker-compose.yml` already sets
`NODE_ENV=production`, `PORT=3000`, `HOST=0.0.0.0`, `DB_PATH=/data/human-attest.db`,
and `KEY_DIR=/data/keys`, all backed by the single `human-attest-data` named
volume, so state survives a container recreate.

The image builds the React SPA (`web/dist`) in its own stage and copies only
the built output into the runtime image — `web/src` and the Vite toolchain
never ship. It is otherwise a **multi-stage build**, not a single-stage one:
`better-sqlite3`'s native addon needs a compiler toolchain (Python + `make` +
`g++`) to build from source via node-gyp, and its bundled prebuilt binary can
be linked against a newer glibc than a slim Debian base actually ships,
making it silently ABI-incompatible on some hosts. The `deps` build stage
installs with `--ignore-scripts`, deletes the bundled prebuild, and forces a
real `node_modules/.bin` node-gyp compile against the toolchain; the final
stage copies only the resulting `node_modules`, app source, and `web/dist`
into a clean `node:22-slim` image with no compiler toolchain or Vite in it,
keeping the runtime image slim. There is no TypeScript compilation step for
the server — it runs directly via `tsx` (`CMD ["npx", "tsx", "src/main.ts"]`)
in both stages, so "build" here means "compile the one native addon and
bundle the SPA," not "transpile the server."

Once it's up, confirm liveness with:

```bash
curl https://attest.example.com/healthz
# {"status":"ok"}
```

`/healthz` checks that a `SELECT 1` succeeds against the SQLite connection
before reporting `ok`, so a DB-file permission problem or a corrupted volume
shows up here rather than as a mysterious 500 on the first real request.

## 4. Data durability

The schema sets `PRAGMA journal_mode = WAL`, so SQLite's write-ahead log
lets the database survive an ungraceful process crash without corruption.
That said, **this is a single-instance deployment**:

- SQLite is single-writer by design — there is no built-in replication, and
  no supported way to run two app instances against the same database file
  concurrently.
- The Docker named volume (`human-attest-data`) is the **only copy** of the
  data. Losing that volume (host disk failure, an accidental `docker volume
  rm`) loses the entire audit trail and every principal/credential/
  attestation record with it.

Recommendations, in increasing order of durability:

- **At minimum**, take periodic file-level backups of `DB_PATH` (copy
  `human-attest.db` — WAL mode makes a live file copy safe as long as you
  copy the `-wal` and `-shm` sidecar files alongside it, or better, run
  SQLite's own `.backup` command / `VACUUM INTO` against a stopped or
  quiesced instance).
- **For continuous durability beyond a single host/single disk**,
  [Litestream](https://litestream.io/) is the standard tool for this: it
  streams SQLite's WAL to object storage (S3, GCS, etc.) continuously, with
  point-in-time restore. It runs as a sidecar and needs no application code
  changes.
- **If this needs to run as more than one instance** (for availability or to
  scale writes), the natural next step is migrating off SQLite to a
  client-server database (Postgres being the obvious choice given the
  existing schema's shape). This plan **deliberately did not do that
  migration** — a storage-engine change is a materially different, riskier
  undertaking than the operational hardening covered here, and was out of
  scope for this pass.

## 5. What this deployment does NOT include

Stated plainly, so it isn't discovered the hard way in an incident:

- **TLS termination.** This app expects to be reached over HTTPS at
  `APP_BASE_URL` (WebAuthn requires a secure context, and browsers will
  refuse the credential ceremonies otherwise) but does **not** terminate TLS
  itself. Put a real reverse proxy or load balancer in front of it (nginx,
  Caddy, an ALB/cloud load balancer, etc.) and point `APP_BASE_URL`/`RP_ID`
  at the domain that proxy serves.

  **If you do put a reverse proxy in front, set `TRUST_PROXY=true`.**
  `@fastify/rate-limit` keys on `req.ip`, which is the raw TCP peer address
  unless Fastify's `trustProxy` option is on. Behind a reverse proxy, every
  request's TCP peer is the proxy itself, so without `TRUST_PROXY=true` the
  global 100/min limit (and `POST /v1/principals`'s 30/min) becomes a
  whole-service budget shared by every real client, not a per-client one --
  one abusive client trips it for everyone else. Setting `TRUST_PROXY=true`
  makes Fastify key on the client's real address from `X-Forwarded-For`
  instead. Leave it unset (`false`, the default) for a direct-to-internet
  deployment with no proxy in front -- enabling it there would let any client
  spoof `X-Forwarded-For` and bypass rate limiting entirely. This assumes
  **exactly one** trusted proxy hop; it is not safe to enable if there are
  multiple hops or any untrusted intermediary between the client and that one
  proxy.
- **Horizontal scaling.** Covered in §4 — a single SQLite file means a
  single writer, and this deployment is one app instance against one file.
- **A compiled build step for the server.** The Fastify app runs via `tsx`
  directly from TypeScript source in both Docker build stages (see §3) —
  there is no `dist/` or transpiled server output to inspect or deploy
  separately. (The React SPA under `web/` is the exception: it genuinely is
  built, to `web/dist`, in its own Docker stage — see §3.)
- **Cloud-provider-specific secrets integration.** The only secrets-injection
  point is the portable `SIGNING_KEY_JSON` env var from §2 (and `SMTP_URL`,
  which is itself a connection string rather than something to further
  inject) — there's no bundled AWS/GCP/Azure SDK client for pulling secrets
  directly from a provider's secrets manager. Wire that up in whatever wraps
  this container (an entrypoint script, an init container, an
  ECS task definition's `secrets` block, etc.) and pass the result in as
  those two env vars.
- Failing closed on bad config: a misconfigured `NODE_ENV=production` run
  still pointed at `localhost` for `RP_ID`/`APP_BASE_URL`, or with `SMTP_URL`
  unset, refuses to boot at all (see `src/config.ts`'s `loadConfig`) rather
  than starting and silently failing every WebAuthn ceremony, or silently
  writing every approval email to a directory no approver will ever read —
  this is included, not omitted, but is
  worth calling out here since it's the thing most likely to look like a
  deployment bug on first boot.
- **Caller authentication on `/mcp`.** Same posture as `/v1/*`: this
  deployment does not authenticate the caller of the MCP endpoint itself. Any
  client that can reach `/mcp` can invoke `request_approval`,
  `check_approval`, and `wait_for_approval`. Put this endpoint behind the
  same network boundary you'd put `/v1/*` behind.

## 6. Load characteristics

Measured locally with `scripts/load-test.mts` against a real running
instance (`npx tsx src/main.ts`), concurrency 10, 25 attestations created and
independently read back:

```
25 attestations created and read back correctly, concurrency=10
  total wall time:  21ms
  throughput:       1194.4 attestations/sec
  latency p50:      5.1ms
  latency p95:      17.6ms
  latency p99:      18.7ms
  latency max:      18.7ms
```

**Caveat:** these numbers were measured on a shared development machine, not
representative production hardware, and are not a substitute for load
testing your actual deployment target.

This app's own rate limits also shape what a run of this script can measure.
`POST /v1/principals` has its own route-specific override, 30/minute
(`src/api/routes.principals.ts`) — an already-shipped Task 4 protection
against enrolment spam/enumeration (raised from an original 10/minute by
Finding 4 of the 2026-07-29 final review, to give the e2e suite's own
principal-creation count some headroom). `scripts/load-test.mts` creates one
shared approver principal up front specifically so its own concurrent run
never touches that endpoint again after the first call, and instead drives
its load entirely at `POST /v1/attestations` and `GET
/v1/attestations/:id`, neither of which has a route-specific override, so
both fall under the global default registered in `src/api/server.ts`
(`fastifyRateLimit`, `max: 100, timeWindow: "1 minute"`), applied
cumulatively across every route without its own override. (`POST
/v1/attestations/:id/options` — the WebAuthn ceremony-begin endpoint — also
happens to share that same 30/minute number today, coincidentally; it is a
separate override and this script never calls it.) Since the script makes 2
requests per attestation (1 POST + 1 GET), the real per-run ceiling under
the global limit is roughly 100 / 2 ≈ **49 attestations per rolling
minute**, not 30. Keep `total` comfortably under that per one-minute run, or
space runs out across multiple windows to test higher totals.

This math is REST-only and doesn't cover `/mcp`, which draws from the same
global bucket but with a different shape: an MCP client's `connect()` and
each subsequent tool call (`request_approval`, `check_approval`,
`wait_for_approval`) each cost some number of requests against `POST /mcp`,
so an MCP-heavy integration doesn't map cleanly onto the "2 requests per
attestation" figure above. `wait_for_approval` in particular holds its
underlying HTTP connection open for as long as it polls (up to its timeout),
rather than completing in one quick round trip like the REST reads above —
so the request count alone understates how long that one request occupies a
connection. Size any deployment expecting significant MCP traffic with this
difference in mind rather than reusing the REST-only numbers directly.

## 7. Audit trail

Every rejection on `/v1/*` and `/web/*`, every approval decision, and every
expiry writes a row to the `audit_log` table (see `src/api/server.ts`'s
central error handler and `src/api/state.ts`).

**`/mcp` is a documented exception, not an oversight.** A `FailClosedError`
a tool handler catches — an unenrolled `approver_emails` address, an unknown
`attestation_id`, an invalid action payload — is audited at the point the
handler catches it (`src/mcp/server.ts`'s `toolError`). But three narrower
classes of MCP rejection are answered by `@modelcontextprotocol/sdk`'s own
machinery *before* any tool handler runs at all, and never reach that audit
point: a request whose arguments fail the tool's Zod input schema, a call
naming a tool that doesn't exist, and a malformed JSON-RPC envelope. None of
these represent an authorization bypass — each is still rejected, no
attestation or credential state changes — but none leaves a trace in
`audit_log` today. Since `/mcp` requires no caller authentication (§5), an
unauthenticated client can currently drive an unbounded number of these
three specific rejections with zero forensic trail. Closing this fully
means intercepting responses the SDK's transport writes directly, before
any application-level handler exists to catch them — a real design change,
not a one-line fix, and deliberately not attempted as part of closing out
the MCP feature. Known limitation; revisit before relying on `/mcp`'s audit
trail for anything adversarial.

To get the full audit trail out as newline-delimited JSON, oldest first:

```bash
npx tsx scripts/export-audit-log.mts /path/to/human-attest.db
# or, filtered to events at or after a timestamp:
npx tsx scripts/export-audit-log.mts /path/to/human-attest.db --since=2026-07-01T00:00:00.000Z
```

This is deliberately a **local script that opens the database file directly,
not an HTTP endpoint**. An unauthenticated `GET /v1/audit-log` would be new,
real attack surface — the audit trail includes principal emails and
rejection detail — and adding real authentication/authorization for one
read-only operator tool would be a disproportionate amount of new surface
for what it's for. Requiring the same filesystem access as the database file
itself matches who should actually be able to read the audit trail: an
operator with access to the deployment (e.g. `docker compose exec` into the
container, or a copy of the volume), not the network.
