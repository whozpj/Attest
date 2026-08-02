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

## Build the web UI

```bash
npm run build:web
```

Builds the React SPA to `web/dist`, which the server mounts at `/`. Do this
before starting the server (and again after changing anything under `web/`),
or every page will 404. It is gitignored, so a fresh clone always needs it.

## Run the server

```bash
npm run dev
```

Starts Fastify on `http://localhost:3000`, backed by a SQLite file at
`human-attest.db` and a signing keypair generated on first run under `keys/`
(both are gitignored). Stop it with `Ctrl-C`.

## How the approver is reached

Approvers are notified by **email**. Each message carries a link to this
service's web UI, where the approver reviews the request and decides with
their passkey. The link is a view capability only — opening it reveals the
request, but it cannot approve or deny anything. Only the authenticator can
do that, which is the whole point: a click-to-approve link would downgrade
the claim from "this human's authenticator signed this exact action hash" to
"someone read this inbox."

With `SMTP_URL` unset (the default for local development), mail is not sent
anywhere — each message is written to `mail/` as an `.eml` file you can open
in any mail client, or just read. That is also what lets the end-to-end suite
drive the real notification path with no external account.

## Enrol a passkey

Registering a principal and enrolling a passkey are separate steps. First
create a principal:

```bash
curl -s -X POST http://localhost:3000/v1/principals \
  -H 'content-type: application/json' \
  -d '{"email":"demo@example.com","display_name":"Demo User"}'
```

This returns `{ "principal_id": "prin_...", "enrolment_token": "..." }`, and
also emails an enrolment link to that address — locally, look in `mail/` for
the newest `.eml`. The response still carries the token because an agent
platform provisioning users programmatically has a legitimate need for it;
the email is additive.

The token is single-use and expires in 15 minutes — it's what proves whoever
opens the enrolment link next is the party this principal was created for,
since `principal_id` alone is not secret. Then, with a platform authenticator
available (Touch ID, Windows Hello, or a security key), open the link from
the email, or construct it yourself:

```
http://localhost:3000/enrol?principal=<principal_id>&token=<enrolment_token>
```

and click **Enrol passkey**. Without a valid token, or with one already used,
the request fails the same way a request for a principal that doesn't exist
would — see `docs/api/reference.md`.

## Run the demo agent

```bash
npm run demo -- <principal_id>
```

The demo agent requests a $25,000 wire transfer approval, prints the rendered
headline and a link to the request, and blocks. An approval email lands in
`mail/` at the same moment. Open either link in the same browser you enrolled
with, click **Approve**, complete the passkey ceremony, and the agent
verifies the resulting token against the action it originally requested
before printing `Verified. Executing wire transfer.`

## Call it from an MCP client

The same server also speaks [MCP](https://modelcontextprotocol.io) at
`/mcp` -- `request_approval`, `check_approval`, `wait_for_approval`. Any
MCP-compatible agent framework can point at `http://localhost:3000/mcp`
directly; see `docs/api/reference.md`'s MCP section for the tool schemas, or
run the reference client:

```bash
npm run demo:mcp -- <approver_email>
```

## Browse your request history

Sign in at `http://localhost:3000/signin` with the email you registered, using
the same passkey. `/requests` lists every attestation you have been asked to
decide, and each row opens a detail view with its audit trail.

Sign-in challenges are random and stored server-side — deliberately *not*
derived from any action, unlike an approval challenge. That asymmetry is
load-bearing: an assertion captured during sign-in signs bytes no approval
challenge can ever equal, so it can never be replayed to approve an action,
and vice versa. The security suite asserts this directly.

Note what a resolved request does **not** show: the original payload text.
See the limitations below.

## Run the tests

```bash
npm test
```

Runs the Vitest suites: unit tests colocated with each module, integration
tests across module seams, and the threat-model security suite.

## Run the end-to-end suite

```bash
npx playwright install chromium
npm run build:web
npm run e2e
```

Drives a real Chromium instance against the running server, using a CDP
virtual authenticator so the passkey ceremonies run unattended. Because the
file transport writes real `.eml` files, the suite reads the actual approval
email off disk, extracts the actual link, and drives the actual flow — the
notification path is covered end to end rather than mocked.

`npm run build:web` is required first: the specs drive the real SPA, and
`web/dist` is gitignored.

## Prototype limitations

This is a prototype, not a production system:

- **The signing key sits on disk unencrypted.** Anyone who can read
  `keys/signing-key.json` can mint attestation tokens.
- **There is no device-loss recovery.** A principal who loses their
  authenticator cannot enrol a replacement; there is no re-enrolment or
  account-recovery flow, and that is the honest cost of having no second
  factor to fall back on.
- **`SMTP_URL` is required in production.** With `NODE_ENV=production` and no
  `SMTP_URL`, the server refuses to boot rather than silently writing approval
  emails to a local directory — a failure that would otherwise be invisible
  until someone noticed nothing was ever being approved.
- **Resolved requests show metadata only.** Once an attestation is approved,
  denied, or expired, the payload is purged, so history shows the action type,
  status, requester, timestamps, `payload_hash`, each approver's decision, and
  the audit trail — but never the original "Wire $25,000.00 USD to Acme Corp"
  text. This is a deliberate tradeoff, not an oversight: retaining rendered
  payload text forever to make history prettier would turn this service into
  exactly the permanent store of wire amounts and recipient names it promises
  above not to be. A party holding the original action can still verify the
  hash matches.
- None of this is production-ready.
