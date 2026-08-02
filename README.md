# Human-Attest

[![CI](https://github.com/whozpj/Attest/actions/workflows/ci.yml/badge.svg)](https://github.com/whozpj/Attest/actions/workflows/ci.yml)
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

Requires Node.js 20+, and Chromium (via Playwright) if you want to run the
end-to-end tests.

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
passkey**. Then run the demo agent:

```bash
npm run demo -- <principal_id>
```

It requests a $25,000 wire transfer, prints a link, and waits. Open the
approval email or the printed link, approve with your passkey, and the
agent verifies the resulting token before printing that it executed.

There's an MCP version too, for MCP-compatible agent frameworks, exposing
`request_approval`, `check_approval`, `wait_for_approval`, and
`consume_approval`:

```bash
npm run demo:mcp -- <approver_email>
```

Sign in at `/signin` with the same email and passkey to browse your
request history at `/requests`.

## Tests

```bash
npm test                              # unit + integration + security suites

npx playwright install chromium
npm run build:web
npm run e2e                           # real browser, real passkeys, real emails
```

The end-to-end suite drives an actual Chromium instance with a virtual
authenticator, so the full passkey and email flow runs for real, not
mocked.

## Known limitations

This is a prototype, not a hardened production system:

- The signing key sits on disk unencrypted (`keys/signing-key.json`).
- No device-loss recovery — a principal who loses their authenticator has
  no way to re-enrol.
- Resolved requests keep only metadata and a hash, never the original
  payload text, by design — history won't show "Wire $25,000 to Acme
  Corp," just that it happened and what its hash was.
- `/v1/*` and `/mcp` don't authenticate their caller; they're meant to sit
  behind your own network boundary, not be exposed publicly.

## License

MIT
