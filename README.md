# Human-Attest

A local prototype of a service that proves a specific human cryptographically
authorized a specific agent action.

## What this proves

An AI agent submits a structured action (a wire transfer, an email, a
document to sign) to this service instead of executing it directly. The
service canonicalizes the payload, hashes it, and renders a human-readable
summary from that same canonical form — the agent never supplies display
text. A registered human is asked to approve or deny the rendered summary.

The approval itself is a WebAuthn ceremony in which the **challenge is
derived from the action's hash**, not a random nonce: specifically, the hash
of the canonicalized pair `{ act: payload_hash, decision }`, where `decision`
is `approve` or `deny`. Binding the decision into the challenge (rather than
signing the bare action hash for both) means an approve and a deny for the
same action sign different bytes, so a signature captured for one can never
be replayed as the other. Either way, the authenticator's signature covers
the specific action, not just "a human was present." The service issues an
ES256 JWS whose `act` claim carries the plain action hash, signed with a key
whose public half is published at `/.well-known/jwks.json`. Anyone holding
the token can verify it offline against that key, without calling back to
this service.

What this does **not** prove: that the human read or understood the summary.
WebAuthn signs opaque bytes; it cannot show transaction text on the
authenticator itself. The binding proves the authenticator signed this
action hash and that the agent supplied no display text of its own — it does
not prove comprehension. See `docs/human-attest-mvp.md` for the full threat
model.

The service stores the canonicalized payload only long enough to render the
summary and check the signature against it. Once an attestation resolves —
approved, denied, or expired, whichever happens first and however it's
first observed (a decision or just a poll) — the payload is purged and only
`payload_hash` is retained, forever. It is not a permanent store of wire
amounts, recipient names, or email bodies.

## Prerequisites

- Node.js 20 or later
- Chromium, for the end-to-end suite (installed via Playwright, see below)

## Install

```bash
npm install
```

## Run the server

```bash
npm run dev
```

Starts Fastify on `http://localhost:3000`, backed by a SQLite file at
`human-attest.db` and a signing keypair generated on first run under `keys/`
(both are gitignored). Stop it with `Ctrl-C`.

## Enrol a passkey

Registering a principal and enrolling a passkey are separate steps. First
create a principal:

```bash
curl -s -X POST http://localhost:3000/v1/principals \
  -H 'content-type: application/json' \
  -d '{"email":"demo@example.com","display_name":"Demo User"}'
```

This returns `{ "principal_id": "prin_...", "enrolment_token": "..." }`. The
token is single-use and expires in 15 minutes — it's what proves whoever
opens the enrolment link next is the party this principal was created for,
since `principal_id` alone is not secret (it ends up in `approve_url`'s query
string). Then, with a platform authenticator available (Touch ID, Windows
Hello, or a security key), open:

```
http://localhost:3000/approve/enrol.html?principal=<principal_id>&token=<enrolment_token>
```

and click **Enrol passkey**. The page reports `enrolled` on success. Without
a valid token, or with one already used, the request fails the same way a
request for a principal that doesn't exist would — see
`docs/api/reference.md`.

## Run the demo agent

```bash
npm run demo -- <principal_id>
```

The demo agent requests a $25,000 wire transfer approval, prints the
rendered headline and an approval URL, and blocks. Open the printed URL in
the same browser you enrolled with, click **Approve**, and the agent
verifies the resulting token against the action it originally requested
before printing `Verified. Executing wire transfer.`

## Run the tests

```bash
npm test
```

Runs the Vitest suites: unit tests colocated with each module, integration
tests across module seams, and the threat-model security suite.

## Run the end-to-end suite

```bash
npx playwright install chromium
npm run e2e
```

Drives a real Chromium instance against the running server, using a CDP
virtual authenticator so the passkey ceremonies run unattended.

## Prototype limitations

This is a prototype, not a production system:

- The signing key sits on disk unencrypted.
- There is no device-loss recovery.
- Push delivery is replaced by a local URL.
- None of this is production-ready.
