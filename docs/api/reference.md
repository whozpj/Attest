# API reference

Base URL for the local prototype: `http://localhost:3000`. RP ID `localhost`,
origin `http://localhost:3000` throughout — the passkey ceremonies will not
work against any other host or port.

All request and response bodies are JSON. All hashes are the string form
`sha256:<lowercase-hex>`. Errors (except the one noted under `verify`) are
returned as `{ "error": "<code>", "message": "<text>" }` with the HTTP status
listed in [Error codes](#error-codes) below.

This document describes the routes as specified — method, path, and the
shape of each body — not the runtime behavior of a deployed instance.

## Endpoints

- [`POST /v1/principals`](#post-v1principals)
- [`POST /v1/principals/:id/credentials/options`](#post-v1principalsidcredentialsoptions)
- [`POST /v1/principals/:id/credentials`](#post-v1principalsidcredentials)
- [`POST /v1/attestations`](#post-v1attestations)
- [`GET /v1/attestations/:id`](#get-v1attestationsid)
- [`POST /v1/attestations/:id/options`](#post-v1attestationsidoptions)
- [`POST /v1/attestations/:id/decision`](#post-v1attestationsiddecision)
- [`POST /v1/attestations/verify`](#post-v1attestationsverify)
- [`GET /.well-known/jwks.json`](#get-well-knownjwksjson)

---

### `POST /v1/principals`

Registers a principal — the human who will later authorize actions.

**Request body**

```json
{
  "email": "demo@example.com",
  "display_name": "Demo User"
}
```

**Response** — `201 Created`

```json
{ "principal_id": "prin_<uuid>", "enrolment_token": "<base64url, single-use>" }
```

`enrolment_token` is single-use and expires 15 minutes after issuance. It is
the only thing that gates the two credential-enrolment endpoints below —
`principal_id` alone proves nothing, since it is not secret: this same
service embeds it in `approve_url`'s query string, so it is routinely handed
around outside any trust boundary. Whoever delivers the enrolment link to
the human (out of band — email, Slack, or similar; genuinely out of scope
for this prototype, see [`docs/human-attest-mvp.md`](../human-attest-mvp.md)
§4) needs to include this token in it, not just `principal_id`.

**Status codes**

| Status | Meaning |
|---|---|
| 201 | Principal created |
| 400 | `principal_invalid` — see below |

`email` is unique per principal. `principal_invalid` covers two distinct
situations with the **same** code, message, and status: a malformed body
(missing or non-string `email`/`display_name`) and a duplicate `email`. This
collapsing is deliberate, not an oversight — a distinct response for
"email already registered" would let a caller enumerate which addresses are
already enrolled against this endpoint, which is exactly the kind of leak
spec §9 ("say why without leaking") rules out. The two cases remain
distinguishable server-side, in `audit_log.detail`, just never in the HTTP
response.

---

### `POST /v1/principals/:id/credentials/options`

Begins passkey registration for principal `:id`. Returns WebAuthn
`PublicKeyCredentialCreationOptions` (as JSON) to pass to
`@simplewebauthn/browser`'s `startRegistration`.

**Request:** no body. Query parameter `token` (required) — the
`enrolment_token` from `POST /v1/principals`.

```
POST /v1/principals/prin_abc123/credentials/options?token=<enrolment_token>
```

**Response** — `200 OK`, a `PublicKeyCredentialCreationOptionsJSON` object,
including a freshly generated `challenge` and, if the principal already has
credentials, an `excludeCredentials` list so the same authenticator cannot
be enrolled twice.

**Status codes**

| Status | Meaning |
|---|---|
| 200 | Options generated |
| 404 | `unknown_principal` — no principal with this id, **or** `token` is missing, malformed, bound to a different principal, expired, or already used |

This call only *checks* the token — it does not consume it, since it's the
"begin" half of a two-step ceremony and burning the token here would make it
impossible to ever reach the "finish" step with it. All of the token-related
rejections above return the exact same `unknown_principal`/`404` a
nonexistent principal would, on purpose: a caller who knows a real
`principal_id` but has a wrong token cannot tell that apart from the
principal not existing at all, which is what keeps a stolen or guessed
`principal_id` from being useful on its own. See
[`docs/human-attest-mvp.md`](../human-attest-mvp.md) §4 for why this
endpoint needed gating in the first place.

The server holds the pending challenge in memory, keyed by principal id, until
`POST /v1/principals/:id/credentials` completes it. Only one registration can
be in flight per principal at a time — starting a second overwrites the
first's challenge.

---

### `POST /v1/principals/:id/credentials`

Completes passkey registration with the authenticator's response.

**Request body:** the `RegistrationResponseJSON` produced by
`startRegistration` in the browser. Query parameter `token` (required) — the
same `enrolment_token`, presented again.

```
POST /v1/principals/prin_abc123/credentials?token=<enrolment_token>
```

**Response** — `201 Created`

```json
{ "credential_id": "<base64url credential id>" }
```

**Status codes**

| Status | Meaning |
|---|---|
| 201 | Credential stored |
| 400 | `no_pending_registration` — no options call preceded this one, it already completed, **or** `token` is missing, malformed, bound to a different principal, expired, or already used |
| 400 | `registration_failed` — the authenticator response did not verify |

This call *consumes* the token — atomically, so two concurrent requests
racing on the same token cannot both succeed — which is what makes it
single-use. As with `.../options`, a bad token collapses into the same
response a caller would get without ever having called `.../options` at
all; there is no way to distinguish "wrong token" from "no pending
registration" from the HTTP response. Consumption happens before the
WebAuthn ceremony is checked, so a failed ceremony (bad signature, etc.)
still burns the token — a design partner retrying a failed enrolment needs
to call `POST /v1/principals` again for a fresh one, not just retry
`.../credentials`.

---

### `POST /v1/attestations`

Requests human authorization for an action. The caller submits the full
structured payload, never display text; the service canonicalizes it (RFC
8785), hashes it, and renders the summary server-side.

**Request body**

```json
{
  "action": {
    "type": "wire_transfer",
    "risk_tier": "high",
    "payload": {
      "amount": 2500000,
      "currency": "USD",
      "recipient_name": "Acme Corp",
      "account_last4": "4821"
    }
  },
  "approver_ids": ["prin_abc123"],
  "required_approvals": 1,
  "requested_by": "demo-agent",
  "ttl_seconds": 900
}
```

`required_approvals` defaults to `1` if omitted. `ttl_seconds` defaults to
`900`. `action.type` must be one of `wire_transfer`, `send_email`,
`sign_document`, `generic`; each has its own required payload fields, and any
field outside that schema — including a caller-supplied `summary` or
`headline` — is rejected rather than silently dropped.

**Response** — `201 Created`

```json
{
  "attestation_id": "att_<uuid>",
  "status": "pending",
  "payload_hash": "sha256:<hex>",
  "summary": {
    "headline": "Wire $25,000.00 USD to Acme Corp",
    "fields": [
      { "label": "Amount", "value": "$25,000.00 USD" },
      { "label": "Recipient", "value": "Acme Corp" },
      { "label": "Account", "value": "••••4821" }
    ]
  },
  "approve_url": "http://localhost:3000/approve/index.html?attestation=att_<uuid>"
}
```

**Status codes**

| Status | Meaning |
|---|---|
| 201 | Attestation created, status `pending` |
| 400 | `payload_invalid` — action failed schema validation, before anything was hashed |

Keep `payload_hash` from this response. It is what you compare the resolved
token against later — see the [quickstart](../integration/quickstart.md).

---

### `GET /v1/attestations/:id`

Polls attestation status. Expiry is evaluated on read: a `pending`
attestation whose TTL has elapsed is reported as `expired` even before any
decision is recorded.

**Response** — `200 OK`

```json
{
  "attestation_id": "att_<uuid>",
  "status": "pending",
  "payload_hash": "sha256:<hex>",
  "required_approvals": 1,
  "approvals": 0,
  "summary": { "headline": "...", "fields": [] },
  "token": null
}
```

`approvals` counts every recorded decision (approvals and denials alike), not
just approvals. `summary` is `null` once the attestation resolves — the
underlying payload is purged from storage on resolution, so only
`payload_hash` survives. `token` is populated only once `status` is
`approved`.

**Purge timing.** The payload is purged the first time resolution is
*observed*, not the first time it happens to be decided. An `approve` or
`deny` purges it immediately, same as before. An attestation that simply
times out with nobody ever calling `decision` on it is purged on the next
`GET` that notices the TTL has elapsed — including this one: if this
response is the read that first observes `expired`, it already reflects the
purge (`summary: null`), not the pre-purge state. There is no window where a
timed-out attestation sits retaining its payload because nobody happened to
poll it at the right moment; the retention guarantee holds on read, not on a
background job. `payload_hash` is retained forever regardless of which of
the three terminal states purged it.

**Status codes**

| Status | Meaning |
|---|---|
| 200 | Found (regardless of status) |
| 404 | `unknown_attestation` — no attestation with this id |

---

### `POST /v1/attestations/:id/options`

Begins the WebAuthn authentication ceremony for one principal's decision on
this attestation — **approve or deny alike; both are signed ceremonies.**
The WebAuthn **challenge** is derived from the action's `payload_hash`
*and* the `decision` you declare here: it's the hash of the canonicalized
pair `{ act: payload_hash, decision }`. You must say which decision you're
about to sign for before the ceremony starts, because approve and deny get
different challenges for the same attestation — that's what stops a
signature captured for one from being replayable as the other.

**Request body**

```json
{ "principal_id": "prin_abc123", "decision": "approve" }
```

`decision` is required here too (not just on the `/decision` call below) —
the challenge can't be generated without knowing which decision it's for.

**Response** — `200 OK`, a `PublicKeyCredentialRequestOptionsJSON` object.
`allowCredentials` is restricted to the calling principal's own enrolled
credentials. Calling this twice for the same attestation and principal with
`decision: "approve"` and then `decision: "deny"` returns two different
`challenge` values.

**Status codes**

| Status | Meaning |
|---|---|
| 200 | Options generated |
| 404 | `unknown_attestation` |
| 400 | `invalid_decision` — `decision` missing or not `"approve"`/`"deny"` |
| 400 | `payload_invalid` — `principal_id` missing or not a string |
| 400 | `no_credential` — the principal has no enrolled passkey |
| 410 | `expired` — the attestation's TTL has elapsed; no challenge is issued |

Expiry is checked first, before anything else about the request — the same
`effectiveStatus` read that `GET /v1/attestations/:id` and `.../decision`
already use. An expired attestation never hands out a live WebAuthn
challenge or the approver's real credential IDs, regardless of what else is
wrong or right about the request.

---

### `POST /v1/attestations/:id/decision`

Records one principal's approve or deny decision — **both require a
verified WebAuthn signature over the decision-bound challenge from the
`/options` call above; there is no unsigned path for either.** Resolution
depends on `required_approvals` (N-of-M quorum): the attestation stays
`pending` until enough approvals accumulate, and a single verified `deny`
from any listed approver resolves the whole attestation to `denied`
immediately, discarding any approvals already recorded.

**Request body — approve**

```json
{
  "principal_id": "prin_abc123",
  "decision": "approve",
  "response": { "...": "the AuthenticationResponseJSON from startAuthentication" }
}
```

**Request body — deny**

```json
{
  "principal_id": "prin_abc123",
  "decision": "deny",
  "response": { "...": "the AuthenticationResponseJSON from startAuthentication" }
}
```

Both shapes are identical apart from `decision`. `response` must be the
assertion produced against the `challenge` this same principal obtained from
`/options` with the *same* `decision` — a `response` signed against the
approve-challenge will not verify as a deny, and vice versa. `response` is
required for both decisions; a request with no `response` field at all —
just `principal_id` and `decision`, the two identifiers an attacker needs to
attempt this endpoint — is rejected as `signature_required`, the same code
as a `response` present but missing a string `id`. One opaque code for
"sent nothing" and "sent garbage" alike, the same anti-enumeration reasoning
as `principal_invalid` on `POST /v1/principals`: a caller probing this
endpoint shouldn't be able to tell the two apart. Every rejection here —
`invalid_decision`, `payload_invalid`, `signature_required`, and everything
below — is audited and leaves the attestation exactly as it was; none of
them can be used to force a resolution.

**Response** — `200 OK`

```json
{ "status": "approved", "token": "eyJ..." }
```

`token` is `null` unless this decision brought the attestation to `approved`.

**Status codes**

| Status | Meaning |
|---|---|
| 200 | Decision recorded (whatever the resulting status) |
| 404 | `unknown_attestation` |
| 400 | `invalid_decision` — `decision` missing or not `"approve"`/`"deny"` |
| 400 | `payload_invalid` — `principal_id` missing or not a string |
| 400 | `signature_required` — `response` is missing, or present but malformed (no string `id`) |
| 401 | `unknown_credential` — the credential in `response` isn't recognised, or belongs to a different principal |
| 400 | `binding_mismatch` — the signed challenge does not match this action's hash for the declared decision, or the request was never signed at all (see note below) |
| 401 | `signature_invalid` — signature verification failed |
| 401 | `counter_regression` — the authenticator's signature counter went backwards — **not on its own proof of a cloned credential** (see note below) |
| 410 | `expired` — the attestation's TTL has elapsed |
| 409 | `already_resolved` — the **attestation** is already `approved`, `denied`, or `expired` |
| 409 | `already_decided` — this **principal** already recorded a decision for this attestation, even though the attestation itself may still be `pending` on other approvers |
| 403 | `not_an_approver` — this principal is not in `approver_ids` for this attestation |

`already_resolved` and `already_decided` are easy to conflate; they are not
the same condition. `already_resolved` means the whole attestation has
reached a terminal state — nobody can decide on it anymore, regardless of
who they are. `already_decided` means this specific principal already
submitted a decision, but the attestation may still be legitimately
`pending`, waiting on the rest of a multi-approver quorum. A second,
genuinely fresh and validly-signed decision from the same principal is
rejected as `already_decided` — one signature counts once toward
`required_approvals`, never twice, even when nothing about the second
attempt is itself invalid.

A rejected decision (any 4xx/401/409 above) never resolves the attestation
— an attacker who can't produce a valid signature can't force it to
`denied` by throwing failed attempts at this endpoint, and a principal who
already decided can't inflate their own vote by deciding again; it stays
exactly as it was.

**`binding_mismatch` and `counter_regression` do not, by themselves, prove a
real authenticator produced the request.** Both fire before the actual
signature is checked — a challenge, origin, or counter mismatch is detected
ahead of verifying who signed anything — and forgery of everything else in
the request is cheap: RP ID and origin are public constants, and
`POST /v1/attestations/:id/options` hands the real challenge and the
principal's real credential IDs to any caller who can name an attestation
id, no proof of identity required. So a `binding_mismatch` or
`counter_regression` response looks identical over HTTP whether it came
from a genuinely-keyed authenticator (a human who signed the wrong thing,
or an authenticator that really is behind/cloned) or from someone with no
key at all who forged the rest of the payload. The HTTP response cannot
tell these apart. The audit log can: an `audit_log` row written for both
events carries `verified=true` or `verified=false` in `detail`, computed by an
independent check of the actual signature against the credential's stored
public key. `verified=true` means a real key was behind the rejection;
`verified=false` means it wasn't. This field is not exposed through any API
response — it's visible only to whoever can read the database directly.

**Say this plainly, because it's easy to over-read:** the `counter_regression`
response (and its internal audit event, `possible_credential_clone` — a
harder-sounding name than the wire code) only indicates a genuinely detected
cloned or behind-schedule authenticator when the matching audit row has
`verified=true`. A `possible_credential_clone` row with `verified=false` is
an unauthenticated probe — anyone can produce those, cheaply, with no key at
all. Whoever reviews this audit log should filter on `verified` before
treating a `possible_credential_clone` row as evidence a real credential was
compromised; treating every occurrence as a compromised authenticator means
chasing ghosts.

`signature_invalid`'s audit row carries the same `detail` field for a
uniform shape, always `verified=false` there — but with no ambiguity to
resolve, since reaching that branch already means the real signature check
ran and failed.

---

### `POST /v1/attestations/verify`

Verifies an attestation token against the service's published key. Intended
for a receiving system (the agent platform itself, in this prototype) to
check before executing an action — but it can equally be done fully offline
using [`/.well-known/jwks.json`](#get-well-knownjwksjson) and a JWT library,
without calling this endpoint at all. See the
[quickstart](../integration/quickstart.md) for that path.

**Request body**

```json
{ "token": "eyJ..." }
```

**Response** — always `200 OK`

```json
{
  "valid": true,
  "principal_id": "prin_abc123",
  "action_hash": "sha256:<hex>",
  "approved_at": "2026-07-26T18:03:11.000Z"
}
```

or, for an invalid token:

```json
{ "valid": false, "reason": "signature_invalid" }
```

**This endpoint never returns a non-2xx status for an invalid or expired
token.** `valid: false` with a `reason` (`signature_invalid` or `expired`) is
the correct, complete answer — a verifier truthfully reporting "no" is not an
error condition, and treating it as one is a caller bug. Always check the
`valid` field; do not branch on HTTP status.

**Status codes**

| Status | Meaning |
|---|---|
| 200 | Always, whether `valid` is `true` or `false` |

---

### `GET /.well-known/jwks.json`

Publishes the service's public signing key(s) as a JSON Web Key Set. No
private key material is ever included.

**Response** — `200 OK`

```json
{
  "keys": [
    { "kty": "EC", "crv": "P-256", "x": "...", "y": "...", "kid": "k_...", "alg": "ES256", "use": "sig" }
  ]
}
```

**Status codes**

| Status | Meaning |
|---|---|
| 200 | Always |

---

## Error codes

Every rejection is fail-closed and, on the server, written to the audit log.
The following codes are the ones specified in the design (spec §9) and are
stable across endpoints:

| Code | HTTP status | Condition |
|---|---|---|
| `payload_invalid` | 400 | Request body failed validation — an action payload against its per-type schema (before hashing), or a missing/non-string `principal_id` on the attestation decision routes below |
| `unknown_principal` | 404 | No principal with the given id |
| `binding_mismatch` | 400 | The signed WebAuthn challenge does not match the action's `payload_hash` and declared `decision` — **or the request was never signed at all; the HTTP response can't tell you which, see the note under `/decision`** |
| `signature_invalid` | 401 | WebAuthn signature verification failed |
| `counter_regression` | 401 | Authenticator signature counter went backwards — **not on its own proof of a cloned credential; see the note under `/decision`** |
| `not_an_approver` | 403 | Principal is not in the attestation's `approver_ids` |
| `already_resolved` | 409 | Attestation is already `approved`, `denied`, or `expired` |
| `expired` | 410 | Attestation's TTL has elapsed |

**`POST /v1/attestations/verify` is the deliberate exception to this table.**
It returns `200` with `{ "valid": false, "reason": ... }` rather than any of
the above statuses — see that endpoint's section.

A few additional codes appear in specific routes and are not part of the
stable table above, because they concern registration and lookup rather than
the attestation/approval binding: `principal_invalid` (400, `POST
/v1/principals` given a malformed body or a duplicate email — deliberately
indistinguishable, see that endpoint's section), `invalid_decision` (400,
`POST /v1/attestations/:id/options` or `.../decision` given a `decision`
that is missing or isn't `"approve"`/`"deny"`), `unknown_attestation` (404,
any attestation route given an unknown id), `no_credential` (400, approval
requested for a principal with no enrolled passkey), `signature_required`
(400, `POST /v1/attestations/:id/decision` given no `response` field, or one
present but missing a string `id` — one code for both, so a caller can't
distinguish "sent nothing" from "sent garbage"), `unknown_credential` (401,
a decision response naming a credential that isn't recognised or belongs to
someone else), and `registration_failed` / `no_pending_registration` (400,
passkey registration failures).
