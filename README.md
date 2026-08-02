# Human-Attest

![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
[![Node](https://img.shields.io/badge/node-%3E%3D20-brightgreen)](package.json)

Human-Attest lets an AI agent get real human sign-off, with a passkey,
before it does something risky — a wire transfer, an email, a document
signature, an infra change. It's not identity verification or deepfake
detection. It's a signed, non-replayable proof that a specific human
approved a specific action, and nothing else.

**TypeScript · Fastify · WebAuthn (passkeys) · React · SQLite · MCP**

## How it works

1. An agent submits a structured action instead of executing it directly.
2. The service hashes the action and renders a plain-language summary of
   it. The agent never controls what the human actually sees.
3. A human approves or denies using a passkey (Face ID, Touch ID, Windows
   Hello, or a security key). The signature covers that exact action, not
   just "a human was present."
4. The service issues a signed token. The first time it's verified, the
   token is consumed — one approval authorizes exactly one execution, not
   an unlimited number.

The agent can reach this three ways — plain REST, the browser UI, or MCP
tool calls — but all three go through the same code path, so no surface
can show a human different text than what actually got signed.

```
                              /v1/*  (REST — agents & verifiers)
Agent / MCP client ─────┐     /web/* (browser — sign-in, history)
                         ├──▶ /mcp   (Model Context Protocol tools)
                         │
                         ▼
              src/api/attestations-core.ts
        (canonicalize → hash → render → email → purge)
```

Approvals go out over **email**. Each message links to the web UI, where
the human reviews the request and decides with their passkey — the link
itself can't approve anything, only the authenticator can.

The service only keeps the action's data long enough to show it to the
approver. Once a request resolves, the payload is deleted and only its
hash is kept, permanently — this is not a store of wire amounts or email
bodies.

## What it doesn't prove

Whether the human actually read or understood the summary. A passkey
signs bytes, not a screen — it can't prove comprehension, only that this
authenticator signed this exact action.

## Setup

Requires Node.js 20+.

```bash
npm install
npm run build:web   # builds the React app the server serves at /
npm run dev         # starts the server on http://localhost:3000
```

The server uses a local SQLite file and a signing key generated on first
run, both gitignored. With no `SMTP_URL` set, approval emails are written
to `mail/` as `.eml` files instead of actually being sent — open them in
any mail client, or just read them.

## Try it

Create a principal and enrol a passkey:

```bash
curl -s -X POST http://localhost:3000/v1/principals \
  -H 'content-type: application/json' \
  -d '{"email":"demo@example.com","display_name":"Demo User"}'
```

This emails an enrolment link (check `mail/` locally) and also returns the
link's pieces directly, for programmatic setup:

```
http://localhost:3000/enrol?principal=<principal_id>&token=<enrolment_token>
```

Open that link with a platform authenticator available and click **Enrol
passkey**.

From there, an agent requests approval with `POST /v1/attestations`
(or the MCP equivalent, `request_approval`), polls or waits for a
decision, and verifies the resulting token before acting on it. See
`docs/api/reference.md` locally for the full request/response shapes and
the MCP tool list (`request_approval`, `check_approval`,
`wait_for_approval`, `consume_approval`).

Sign in at `/signin` with the same email and passkey to browse your
request history at `/requests`.

## Tests

```bash
npm test
```

Runs the unit tests colocated with the source. A larger integration,
security, and end-to-end (real browser, real passkeys, real emails) suite
was used during development but isn't part of this published repo.

## Known limitations

Resolved requests keep only metadata and a hash, never the original
payload text, by design — history won't show "Wire $25,000 to Acme Corp,"
just that it happened and what its hash was. This is a permanent
trade-off, not something the roadmap below fixes.

## Roadmap to public use

This is a working prototype, not a hardened multi-tenant service. Roughly
in priority order:

**Security**
- [ ] Real caller authentication on `/v1/*` and `/mcp` — right now anyone
  who can reach these endpoints can use them; they're meant to sit behind
  your own network boundary today
- [ ] Encrypt the signing key at rest, or move it to a KMS/HSM instead of
  a local `keys/signing-key.json`
- [ ] Device-loss recovery — a principal who loses their passkey has no
  way back in today
- [ ] Abuse prevention on principal creation — nothing stops someone from
  spamming an arbitrary email address with enrolment/approval emails

**Scale & reliability**
- [ ] Move off a single SQLite file to a real database (Postgres) with
  backups
- [ ] Support running more than one server instance (SQLite is
  single-writer, single-host)
- [ ] A real transactional email provider (SES, Postmark, etc.) with
  deliverability monitoring, not just an SMTP URL
- [ ] Metrics, error alerting, and uptime monitoring

**Product**
- [ ] Multi-tenancy — every principal currently lives in one flat
  namespace; separate organizations don't exist yet
- [ ] Webhooks, so an integrator doesn't have to poll or hold a
  `wait_for_approval` connection open
- [ ] An admin UI for managing API keys, team members, and approvers per
  organization
- [ ] Official client SDKs
- [ ] Billing and usage metering

**Legal**
- [ ] Terms of service and a privacy policy
- [ ] A real support/incident-reporting channel

## License

MIT
