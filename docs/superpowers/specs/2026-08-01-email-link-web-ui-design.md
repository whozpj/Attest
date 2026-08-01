# Human-Attest as a website: email delivery + web approval UI

**Date:** 2026-08-01
**Status:** Approved for implementation

## 1. What changes, in one paragraph

Today an agent creates an attestation and the approver learns about it via Web
Push into a PWA (or, on iOS, a native app blocked on a paid Apple account).
After this change, the approver gets an **email** containing a link to a real
web UI where they review the request and approve or deny it with their
passkey, and where they can sign in separately to browse every request they
have ever been asked to decide. Web Push, the PWA, and the iOS app are
removed. **The cryptographic core does not change at all**: the WebAuthn
challenge is still `hash({act, att, decision})`, the summary is still rendered
server-side from canonical JSON, and the attestation token is still an ES256
JWS verifiable offline.

## 2. Decisions and their rationale

| # | Decision | Why |
|---|---|---|
| D1 | Email is **transport only**; the passkey still authorizes | The product claim is "this human's authenticator signed this exact action hash." A click-to-approve link would downgrade that to "someone read this inbox," which is the claim the whole codebase exists to make stronger than. |
| D2 | Dashboard auth is **passkey sign-in** | The approver already enrolled one. No password, no second secret, no magic-link path to rate-limit and harden. |
| D3 | Email transport is **pluggable**: SMTP in production, file on disk in dev/test | Lets the e2e suite read a real message, extract the real link, and drive the real flow with no external account — mirroring how `loadOrCreateKeypair`/`loadOrCreateVapidKeys` already make crypto locally runnable. |
| D4 | **Retire** Web Push, the PWA, and `ios/` | "Rework this so it is a website." One delivery path instead of three. Also removes the documented limitation that push subscriptions cannot be established in headless Chromium, so the notification path becomes testable for the first time. |
| D5 | Frontend is **React + Vite**, built to `web/dist`, served by Fastify | Chosen by the project owner for a real dashboard. Costs a build stage in Docker and CI. |
| D6 | Resolved requests show **metadata only**, never retained payload text | See §7. This is the one genuinely contested call and the most important thing in this document. |
| D7 | Sign-in challenges are **random and server-stored**, never action-bound | Makes it structurally impossible for a sign-in assertion to be replayed as an approval. Enforced by test. |
| D8 | The link token is a **view capability**, not an authorization | It reveals a pending request's summary, which is sensitive. It can never cause a state change on its own. |

## 3. Architecture

```
                    ┌──────────────────────────────────────┐
  AI agent ────────▶│  /v1/*        (unchanged, for agents)│
                    │  POST /v1/attestations               │
                    └───────────────┬──────────────────────┘
                                    │ on create
                                    ▼
                          ┌──────────────────┐
                          │  src/email/      │  SMTP_URL set → real send
                          │  EmailTransport  │  unset        → ./mail/*.eml
                          └────────┬─────────┘
                                   │ one link per approver
                                   ▼
                        approver's inbox: /a/<link_token>
                                   │
                                   ▼
                    ┌──────────────────────────────────────┐
   browser ────────▶│  web/  React SPA (Vite → web/dist)   │
                    │       served by Fastify at /          │
                    └───────────────┬──────────────────────┘
                                    │ session cookie or link token
                                    ▼
                    ┌──────────────────────────────────────┐
                    │  /web/*   (browser-facing API)       │
                    │  session, history, link resolution   │
                    └──────────────────────────────────────┘
                                    │
                    approve/deny still POST to the existing
                    /v1/attestations/:id/options + /decision
```

Two API surfaces with different audiences and different auth:

- **`/v1/*`** — for agents and verifiers. Unchanged. No cookies, no sessions.
- **`/web/*`** — for the browser. Cookie-session or link-token authenticated.
  New.

The approve/deny ceremony deliberately keeps using the existing
`/v1/attestations/:id/options` and `/v1/attestations/:id/decision` endpoints
rather than getting `/web/` twins. Those two routes carry the security
properties this project has spent its whole history hardening; duplicating
them would mean duplicating every guard and inviting the two copies to drift.

## 4. Module boundaries

Each unit below has one purpose, a defined interface, and can be tested alone.

### 4.1 `src/email/` (new)

```ts
// transport.ts
export interface EmailMessage {
  to: string; subject: string; text: string; html: string;
}
export interface EmailTransport {
  send(msg: EmailMessage): Promise<void>;
}

// smtp.ts   → createSmtpTransport(url: string): EmailTransport
// file.ts   → createFileTransport(dir: string): EmailTransport
// index.ts  → loadTransport(config): EmailTransport   // picks by SMTP_URL
// templates.ts → renderApprovalEmail(...), renderEnrolmentEmail(...)
```

`templates.ts` takes the **already-rendered `RenderedSummary`** from
`src/actions/render.ts` — it never touches the raw payload and never accepts
caller-supplied display text. This is D1 and the project's core invariant
extended to a new output medium.

Sending is **best-effort and never blocks attestation creation**, exactly
mirroring how `notifyApprovers` behaves today: fire-and-forget, guaranteed
never to throw, failures logged and audited. An SMTP outage must not fail an
agent's `POST /v1/attestations`.

### 4.2 `src/db/` (extended)

New tables:

```sql
CREATE TABLE approval_links (
  token TEXT PRIMARY KEY,           -- 32 random bytes, base64url
  attestation_id TEXT NOT NULL REFERENCES attestations(id),
  principal_id  TEXT NOT NULL REFERENCES principals(id),
  created_at TEXT NOT NULL,
  UNIQUE (attestation_id, principal_id)
);

CREATE TABLE sessions (
  id TEXT PRIMARY KEY,              -- 32 random bytes, base64url
  principal_id TEXT NOT NULL REFERENCES principals(id),
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE login_challenges (
  challenge TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL REFERENCES principals(id),
  expires_at TEXT NOT NULL,
  used_at TEXT
);
```

Dropped: `push_subscriptions`.

`approval_links` has no `expires_at` of its own — it inherits the
attestation's, which is the single source of truth for whether a request is
live. A link to a resolved attestation still resolves; the page then shows
the outcome rather than a dead end. It reveals no payload, because the payload
was purged on resolution.

### 4.3 `src/api/routes.web.ts` (new)

| Method | Path | Auth | Returns |
|---|---|---|---|
| `POST` | `/web/session/options` | none | WebAuthn options w/ random challenge |
| `POST` | `/web/session` | assertion | sets session cookie |
| `DELETE` | `/web/session` | cookie | clears cookie |
| `GET` | `/web/me` | cookie | `{principal_id, email, display_name}` |
| `GET` | `/web/requests` | cookie | paginated history for that principal |
| `GET` | `/web/requests/:id` | cookie | detail + audit trail |
| `GET` | `/web/link/:token` | link token | `{attestation_id, principal_id, ...}` |

Session cookie: `HttpOnly`, `SameSite=Lax`, `Secure` when
`baseUrl` is https, 7-day expiry, value is the opaque `sessions.id`.

**Enumeration parity.** `POST /web/session/options` must return an
indistinguishable response for a real address with a credential, a real
address without one, and an address that does not exist. This project already
made that choice twice (`no_credential` on `/options`, the opaque duplicate-
email rejection on `POST /v1/principals`); sign-in must not become the one
endpoint that confirms whether an email is registered.

### 4.4 `web/` (new, React + Vite)

```
web/
  index.html
  vite.config.ts          build.outDir = dist, no inline assets
  src/
    main.tsx
    api.ts                typed fetch wrappers for /web/* and /v1/*
    webauthn.ts           @simplewebauthn/browser ceremonies
    routes/
      SignIn.tsx          /signin
      Enrol.tsx           /enrol?principal=&token=
      Requests.tsx        /requests          (history + filter tabs)
      Request.tsx         /requests/:id      (detail + audit trail)
      ApprovalLink.tsx    /a/:token          (email landing)
    components/
      SummaryCard.tsx  StatusPill.tsx  AuditTrail.tsx  Layout.tsx
```

`vite.config.ts` sets `build.assetsInlineLimit: 0` so no asset is inlined as a
`data:` URI or inline `<script>`, which keeps the existing strict CSP working
with `scriptSrc: ['self']` unchanged. `styleSrc` **tightens** from
`['self', 'unsafe-inline']` to `['self']`; the SPA uses external CSS only, no
inline `style` attributes.

Fastify serves `web/dist` at `/` with an SPA history fallback, replacing the
`demo/public` static mount at `/approve/`.

## 5. Data flow: the full loop

1. Agent `POST /v1/attestations` with a structured payload.
2. `prepareAction` canonicalizes, hashes, renders the summary. **Unchanged.**
3. For each `approver_id`: insert an `approval_links` row, render the email
   from the `RenderedSummary`, hand it to the transport. Fire-and-forget.
4. Approver opens `/a/<token>`. SPA calls `GET /web/link/:token`, gets the
   attestation id, then `GET /v1/attestations/:id` for the live summary.
5. Approver clicks Approve or Deny → `POST /v1/attestations/:id/options` with
   the declared decision → passkey ceremony → `POST
   /v1/attestations/:id/decision`. **Entirely unchanged.**
6. On quorum, the ES256 token is minted and the payload is purged. Unchanged.
7. Later, the approver signs in at `/signin` and sees the request in
   `/requests` with its status and audit trail.

## 6. Error handling

Everything routes through the existing `setErrorHandler` in `src/api/server.ts`,
which guarantees an `audit_log` row per rejection. New typed `FailClosedError`
codes:

| Code | HTTP | When |
|---|---|---|
| `unknown_link` | 404 | link token not found |
| `no_session` | 401 | `/web/*` requires a session, none present |
| `session_expired` | 401 | session row past `expires_at` |
| `login_challenge_invalid` | 401 | unknown, expired, or already-used challenge |

New audit events: `email_sent`, `email_failed`, `session_created`,
`session_ended`, `login_rejected`, `approval_link_viewed`.

Email failures are audited as `email_failed` and logged, never surfaced to the
agent — consistent with push's existing best-effort contract.

Rate limits: `/web/session/options` and `/web/session` get the stricter
per-route limit already applied to the WebAuthn ceremony endpoints
(30/minute), since both are unauthenticated and credential-adjacent.

## 7. The retention tradeoff (D6), stated plainly

`src/api/state.ts` purges `canonical_json` the moment an attestation reaches
any terminal state. The README leads with this: *"It is not a permanent store
of wire amounts, recipient names, or email bodies."*

A history view wants to show "Wire $25,000.00 USD to Acme Corp" next to a
row from three weeks ago. Doing that requires retaining rendered payload text
forever, which makes this service exactly the database it promises not to be
— and quietly, in a feature nobody would think to threat-model.

**Resolved requests therefore show metadata only:** action type, status,
requester, created/resolved timestamps, `payload_hash`, the approvers' decisions,
and the full audit trail for that attestation. **Pending** requests show the
complete summary, because the payload legitimately still exists.

This is a real UX cost and it is the right call. A row that reads
"Wire transfer · Approved Jul 30 2:14 PM · sha256:1c8d…" plus a linked audit
trail is what an auditor actually needs, and a party who holds the original
action can still verify the hash matches. Retaining the pretty headline buys
recognizability at the cost of the property the product is sold on.

If this is ever revisited, the correct shape is an explicit, per-deployment
opt-in with a bounded retention window — not a default.

## 8. Testing

| Layer | What |
|---|---|
| Unit | `src/email/*` (both transports, template rendering from `RenderedSummary` only), link-token generation, session create/expire, login-challenge single-use |
| Integration | create attestation → email written → link resolves → passkey approve → token verifies, in-process |
| Security | **(a)** a sign-in assertion cannot be replayed as an approval and vice versa (D7); **(b)** a link token grants view but never mutates state (D8); **(c)** `/web/requests` never returns another principal's requests; **(d)** `/web/session/options` responds identically for registered, unregistered, and credential-less emails; **(e)** resolved requests never leak purged payload text |
| E2E | Playwright, virtual authenticator, reading real `.eml` files off disk: full email → link → approve → verify loop, plus deny, expiry, and multi-approver |

Every existing security suite in `tests/security/` must still pass unchanged.
Any that referenced push get removed with it; none of their assertions about
the challenge binding may be weakened.

## 9. Removal list (D4)

```
src/push/vapid.ts            src/push/vapid.test.ts
src/push/send.ts             src/push/send.test.ts
src/api/routes.push.ts       src/api/routes.push.test.ts
demo/public/                 (entire directory, replaced by web/)
ios/                         (entire directory)
tests/e2e/push-approval.spec.ts
push_subscriptions table + its queries
web-push dependency, VAPID key handling in server.ts + config
```

**`demo/agent.ts` stays.** It is the reference integration — the script that
proves an agent can request an attestation and verify the resulting token —
and it is unrelated to how the approver is notified. It needs one update: the
`approve_url` it prints now points at the SPA.

Two files are touched by removal but are **not** D's to edit, because B owns
them and would conflict:

- `src/api/routes.attestations.ts` — B replaces the `notifyApprovers` call
  with the email call. D does not delete `src/push/` until B has landed that
  swap; until then the import must keep resolving.
- `src/api/server.ts` — B removes VAPID from `AppContext` and registers the
  new routes.

Docs to update: `README.md`, `docs/PRODUCTION.md`, `docs/api/reference.md`,
`docs/integration/quickstart.md`, `docs/human-attest-mvp.md` §9.

## 10. Config additions

| Var | Default | Meaning |
|---|---|---|
| `SMTP_URL` | unset | when set, real SMTP; when unset, file transport |
| `MAIL_FROM` | `no-reply@<baseUrl host>` | From: header |
| `MAIL_DIR` | `./mail` | file-transport output directory |
| `SESSION_TTL_HOURS` | `168` | session lifetime |

`loadConfig`'s existing production guard extends: `NODE_ENV=production` with
no `SMTP_URL` must refuse to start, for the same reason it already refuses a
localhost `RP_ID` — a production deployment silently writing approval emails
to a local directory would mean no approver ever hears about a request, and
that failure is invisible until someone notices nothing is being approved.

## 11. Work breakdown

Each worker owns a disjoint file set, so there are no write conflicts.

| Worker | Owns | Depends on |
|---|---|---|
| **A — email** | `src/email/**` | nothing |
| **B — data + web API** | `src/db/**`, `src/api/routes.web.ts`, `src/api/routes.attestations.ts`, `src/api/routes.principals.ts`, `src/api/server.ts`, `src/config.ts` | A's `EmailTransport` interface (§4.1), which is frozen by this spec |
| **C — frontend** | `web/**`, `demo/agent.ts`'s printed URL | §4.3 contract only, not B's code |
| **D — removal + docs + build** | deletions in §9 except the two files noted there, `Dockerfile`, `.github/`, `docs/**`, `README.md`, `package.json` deps | B landing the `notifyApprovers` swap before `src/push/` is deleted |
| **QA** | `tests/**`, runs everything, security review | A–D |

A, B, C, D run in parallel. QA reviews continuously and gates completion.

The interfaces in §4.1 and §4.3 are **frozen contracts**. A worker that wants
to change one stops and raises it rather than editing unilaterally, because
another worker is already building against it.

## 12. Enrolment by email

`POST /v1/principals` currently returns the enrolment token in its response
body and expects the caller to deliver it out-of-band. It now *also* emails
the enrolment link to the principal's address, via `renderEnrolmentEmail`.

The response body keeps returning the token, unchanged — the demo agent and
the existing tests depend on it, and an agent platform provisioning users
programmatically has a legitimate need for it. The email is additive.

This does not weaken the §2/D8 reasoning or the threat-model row about
enrolment tokens: the token remains single-use, principal-bound, and
15-minute-expiring. It does narrow the out-of-band channel to "the email
address the principal was registered with," which is a more honest
description of the trust assumption than the current "some channel this
prototype cannot see."
