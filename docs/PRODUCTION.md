# Production deployment guide

This document is for someone deploying Human-Attest for real, tying together
the env-driven config, secrets handling, containerized deployment, durability
model, and operational tooling built across this hardening plan
(`docs/superpowers/plans/2026-07-29-production-hardening.md`).

## 1. Required environment variables

Read by `loadConfig` (`src/config.ts`) and the key-loading functions
(`src/crypto/tokens.ts`, `src/push/vapid.ts`):

| Variable           | What it does                                                                 | Default                  |
|--------------------|-------------------------------------------------------------------------------|---------------------------|
| `NODE_ENV`         | `development` \| `production` \| `test`. In `production`, boot fails closed if `RP_ID`/`APP_BASE_URL` still point at `localhost` (see §5). | `development` |
| `PORT`             | TCP port the HTTP server listens on.                                          | `3000`                    |
| `HOST`             | Interface to bind. Use `0.0.0.0` inside a container so it's reachable from outside it. | `127.0.0.1`        |
| `APP_BASE_URL`     | The public HTTPS origin this app is reached at (used to build `approve_url` links, push payloads, and as the default `RP_ORIGIN`). **Not** `BASE_URL` — that name is reserved by Vite/Vitest and gets silently overwritten under the test runner; this app deliberately uses its own name to avoid the collision. | `http://localhost:3000` |
| `RP_ID`            | WebAuthn Relying Party ID — must be your real domain (e.g. `attest.example.com`), not an IP or `localhost`, for registered credentials to verify in production. | `localhost` |
| `RP_ORIGIN`        | WebAuthn expected origin. Normally leave unset — it defaults to `APP_BASE_URL`. Only set separately if the RP ID's origin differs from the app's own base URL. | value of `APP_BASE_URL` |
| `DB_PATH`          | Path to the SQLite database file.                                             | `human-attest.db` (relative to CWD) |
| `KEY_DIR`          | Directory for on-disk key material (`signing-key.json`, `vapid-keys.json`) when the corresponding `*_JSON` env var isn't set. | `keys` (relative to CWD) |
| `SIGNING_KEY_JSON` | *Optional.* JSON blob `{"privateJwk": {...}, "publicJwk": {...}, "kid": "..."}` — injects the ES256 attestation-token signing keypair without touching disk. | unset (falls back to `KEY_DIR/signing-key.json`, generated on first boot) |
| `VAPID_KEYS_JSON`  | *Optional.* JSON blob `{"publicKey": "...", "privateKey": "..."}` — injects the Web Push VAPID keypair without touching disk. | unset (falls back to `KEY_DIR/vapid-keys.json`, generated on first boot) |

## 2. Secrets

Two supported patterns for the signing keypair and VAPID keypair:

- **On-disk files under `KEY_DIR`** (the default). On first boot, if no key
  file exists, one is generated and written to `KEY_DIR/signing-key.json` and
  `KEY_DIR/vapid-keys.json` (mode `0600`). Fine for a single trusted host
  where the volume itself is the secret boundary — this is what
  `docker-compose.yml`'s named volume does.
- **`SIGNING_KEY_JSON` / `VAPID_KEYS_JSON` env vars** — the portable pattern
  for injecting key material from AWS Secrets Manager, HashiCorp Vault, or
  Kubernetes Secrets. All three of those ultimately expose a secret to a
  process as an environment variable, which is why this plan didn't build a
  cloud-provider-specific SDK integration on top — set these two vars from
  whatever secret store you use, and the app never touches disk for key
  material. When set, they take priority over `KEY_DIR` unconditionally.

Either way, **generate these once and keep them** — rotating the signing key
invalidates every outstanding attestation token, and rotating the VAPID
keypair invalidates every registered push subscription's ability to verify
against the old public key.

## 3. Running it

The committed `docker-compose.yml` builds the image from the repo's
multi-stage `Dockerfile` and runs it with a persistent volume for the
database and keys:

```bash
APP_BASE_URL=https://attest.example.com RP_ID=attest.example.com docker compose up --build
```

`APP_BASE_URL` and `RP_ID` are required — `docker-compose.yml` uses Compose's
`${VAR:?message}` syntax so it refuses to start without them, rather than
silently defaulting to `localhost` and shipping a deployment that can never
pass a WebAuthn origin check. `docker-compose.yml` already sets
`NODE_ENV=production`, `PORT=3000`, `HOST=0.0.0.0`, `DB_PATH=/data/human-attest.db`,
and `KEY_DIR=/data/keys`, all backed by the single `human-attest-data` named
volume, so state survives a container recreate.

The image itself is a **two-stage build**, not a simple single-stage one:
`better-sqlite3`'s native addon needs a compiler toolchain (Python + `make` +
`g++`) to build from source via node-gyp, and its bundled prebuilt binary can
be linked against a newer glibc than a slim Debian base actually ships,
making it silently ABI-incompatible on some hosts. The `deps` build stage
installs with `--ignore-scripts`, deletes the bundled prebuild, and forces a
real `node_modules/.bin` node-gyp compile against the toolchain; the final
stage copies only the resulting `node_modules` (and app source) into a clean
`node:22-slim` image with no compiler toolchain in it, keeping the runtime
image slim. There is no separate TypeScript compilation step — the app runs
directly via `tsx` (`CMD ["npx", "tsx", "src/main.ts"]`) in both stages, so
"build" here means "compile the one native addon," not "transpile the app."

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
- **Horizontal scaling.** Covered in §4 — a single SQLite file means a
  single writer, and this deployment is one app instance against one file.
- **A compiled build step.** The app runs via `tsx` directly from
  TypeScript source in both Docker build stages (see §3) — there is no
  `dist/` or transpiled output to inspect or deploy separately.
- **Cloud-provider-specific secrets integration.** The only secrets-injection
  point is the portable `SIGNING_KEY_JSON` / `VAPID_KEYS_JSON` env-var
  pattern from §2 — there's no bundled AWS/GCP/Azure SDK client for pulling
  secrets directly from a provider's secrets manager. Wire that up in
  whatever wraps this container (an entrypoint script, an init container, an
  ECS task definition's `secrets` block, etc.) and pass the result in as
  those two env vars.
- Failing closed on bad config: a misconfigured `NODE_ENV=production` run
  still pointed at `localhost` for `RP_ID`/`APP_BASE_URL` refuses to boot at
  all (see `src/config.ts`'s `loadConfig`) rather than starting and silently
  failing every WebAuthn ceremony — this is included, not omitted, but is
  worth calling out here since it's the thing most likely to look like a
  deployment bug on first boot.

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

Two of this app's own endpoints are also rate-limited (`src/api/
routes.principals.ts`, `src/api/routes.attestations.ts`, on top of a global
100/minute default registered in `src/api/server.ts`): `POST /v1/principals`
at 10/minute and `POST /v1/attestations` at 30/minute, both keyed per client.
That's the practical throughput ceiling for a single client identity by
design (abuse/enumeration protection, not a performance limit) — worth
knowing before assuming a load test's low numbers indicate a performance
problem rather than the rate limiter doing its job. `scripts/load-test.mts`
creates one shared approver principal up front specifically so its own
concurrent run exercises `POST /v1/attestations` without tripping the
principal-creation limit; keep `total` under ~30 per one-minute run for the
same reason, or space out runs across multiple windows to test higher
totals.

## 7. Audit trail

Every rejection, approval decision, and expiry writes a row to the
`audit_log` table (see `src/api/server.ts`'s central error handler and
`src/api/state.ts`). To get the full audit trail out as newline-delimited
JSON, oldest first:

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
