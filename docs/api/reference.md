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
{ "principal_id": "prin_<uuid>" }
```

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

**Request body:** none.

**Response** — `200 OK`, a `PublicKeyCredentialCreationOptionsJSON` object,
including a freshly generated `challenge` and, if the principal already has
credentials, an `excludeCredentials` list so the same authenticator cannot
be enrolled twice.

**Status codes**

| Status | Meaning |
|---|---|
| 200 | Options generated |
| 404 | `unknown_principal` — no principal with this id |

The server holds the pending challenge in memory, keyed by principal id, until
`POST /v1/principals/:id/credentials` completes it. Only one registration can
be in flight per principal at a time — starting a second overwrites the
first's challenge.

---

### `POST /v1/principals/:id/credentials`

Completes passkey registration with the authenticator's response.

**Request body:** the `RegistrationResponseJSON` produced by
`startRegistration` in the browser.

**Response** — `201 Created`

```json
{ "credential_id": "<base64url credential id>" }
```

**Status codes**

| Status | Meaning |
|---|---|
| 201 | Credential stored |
| 400 | `no_pending_registration` — no options call preceded this one, or it already completed |
| 400 | `registration_failed` — the authenticator response did not verify |

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

**Status codes**

| Status | Meaning |
|---|---|
| 200 | Found (regardless of status) |
| 404 | `unknown_attestation` — no attestation with this id |

---

### `POST /v1/attestations/:id/options`

Begins the WebAuthn authentication ceremony for one principal's approval of
this attestation. The action's `payload_hash` is used as the WebAuthn
**challenge** — this is the mechanism that binds the authenticator's
signature to this specific action rather than a generic presence check.

**Request body**

```json
{ "principal_id": "prin_abc123" }
```

**Response** — `200 OK`, a `PublicKeyCredentialRequestOptionsJSON` object.
`allowCredentials` is restricted to the calling principal's own enrolled
credentials.

**Status codes**

| Status | Meaning |
|---|---|
| 200 | Options generated |
| 404 | `unknown_attestation` |
| 400 | `no_credential` — the principal has no enrolled passkey |

---

### `POST /v1/attestations/:id/decision`

Records one principal's approve or deny decision. Resolution depends on
`required_approvals` (N-of-M quorum): the attestation stays `pending` until
enough approvals accumulate, and a single `deny` from any listed approver
resolves the whole attestation to `denied` immediately, discarding any
approvals already recorded.

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
{ "principal_id": "prin_abc123", "decision": "deny" }
```

**Note:** `deny` does not require a `response` field and is not verified
against any WebAuthn signature — only `approve` is bound to the action hash
this way. A `deny` is authenticated by nothing beyond knowing the
`principal_id`. See [known gaps](#known-gaps).

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
| 401 | `unknown_credential` — the credential in `response` isn't recognised, or belongs to a different principal (approve only) |
| 400 | `binding_mismatch` — the signed challenge does not match this action's hash (approve only) |
| 401 | `signature_invalid` — signature verification failed (approve only) |
| 401 | `counter_regression` — the authenticator's signature counter went backwards, a cloned-credential signal (approve only) |
| 410 | `expired` — the attestation's TTL has elapsed |
| 409 | `already_resolved` — the attestation is already `approved`, `denied`, or `expired` |
| 403 | `not_an_approver` — this principal is not in `approver_ids` for this attestation |

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
| `payload_invalid` | 400 | Action payload failed its per-type schema, before hashing |
| `unknown_principal` | 404 | No principal with the given id |
| `binding_mismatch` | 400 | The signed WebAuthn challenge does not match the action's `payload_hash` |
| `signature_invalid` | 401 | WebAuthn signature verification failed |
| `counter_regression` | 401 | Authenticator signature counter went backwards (possible cloned credential) |
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
indistinguishable, see that endpoint's section), `unknown_attestation` (404,
any attestation route given an unknown id), `no_credential` (400, approval
requested for a principal with no enrolled passkey), `unknown_credential`
(401, an approval response naming a credential that isn't recognised or
belongs to someone else), and `registration_failed` /
`no_pending_registration` (400, passkey registration failures).

## Known gaps

Documenting this API surfaced one thing worth flagging rather than papering
over, still open as of this writing:

**`deny` requires no proof of identity.** Approving an attestation is bound
to a WebAuthn signature over the action hash; denying one is not — it
succeeds for any `principal_id` listed in `approver_ids`, with no credential
check at all (see the request body for
[`POST /v1/attestations/:id/decision`](#post-v1attestationsiddecision)). For
a single-approver attestation this means anyone who knows (or guesses) the
approver's principal id can deny their pending action. This is a plausible
product decision — a false denial is an availability problem, not a security
one, on the theory that a dissenting approver should never need to prove
more than a dissenting vote — but it is not stated anywhere as a decision, so
it currently reads as an oversight rather than a choice.
