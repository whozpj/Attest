# Single-Use Token Verification Design

**Goal:** `POST /v1/attestations/verify` currently checks a token's signature,
expiry, and payload hash, but never marks it used — so one human approval can
be "verified valid" an unlimited number of times. This closes that gap: the
first successful verify call consumes the token; every call after that fails
closed, even though the token remains cryptographically valid.

## Problem

`docs/api/reference.md`'s current documentation for `verify` says it's
"intended for a receiving system... to check before executing an action" —
but nothing stops that receiving system (or two different systems, or one
system retrying) from calling `verify`, getting `valid: true`, and executing
twice off the same approval. The token itself carries no notion of having
been spent.

## Design

**Schema:** add `token_consumed_at TEXT` to the `attestations` table
(`src/db/schema.sql`), mirroring the existing `used_at` column on
`enrolment_tokens` and `login_challenges`.

**Query layer** (`src/db/queries.ts`): add `consumeAttestationToken(db,
attestationId)`, an atomic check-and-burn `UPDATE ... WHERE id = ? AND
token_consumed_at IS NULL`, returning whether *this* call is the one that
consumed it — the same shape as the existing `consumeEnrolmentToken` and
`consumeLoginChallenge`.

**Shared core logic** (`src/api/attestations-core.ts`, the file that already
exists to keep REST and MCP from drifting on `createAttestation`/
`getAttestationView`): add `verifyAndConsumeAttestation(db, jwks, token)`.
It calls the existing, unchanged `verifyAttestation()` (kept pure/stateless,
since it's also the function documented for fully-offline verification via
`/.well-known/jwks.json` — that path has no server round-trip to consume
anything through, which is an inherent limit of self-verifiable tokens, not
a gap this design can close). If the signature check fails, return that
result unchanged. If it passes, attempt to consume the token by the
attestation id already embedded in the JWT's `jti` claim; if consumption
fails (already spent), return `{ valid: false, reason: "already_consumed" }`
and write an audit row; otherwise return the original valid result.

**REST route** (`src/api/routes.verify.ts`): becomes a thin call into
`verifyAndConsumeAttestation` — no route-level logic changes beyond that.
Non-breaking: response shape for a first, successful call is unchanged;
`already_consumed` is a new value for the existing `reason` field, which
callers were already required to treat opaquely per current docs ("Always
check the `valid` field; do not branch on HTTP status" / do not branch on
`reason` values not yet seen).

**MCP tool** (`src/mcp/server.ts`): add `consume_approval`, taking the
`token` string returned by `wait_for_approval`/`check_approval`, calling the
same `verifyAndConsumeAttestation`. Fails closed through the existing
`toolError()` path (audited) on any invalid result, matching every other
MCP tool's error contract. `check_approval` is untouched and stays freely
repeatable — it reports status, it does not authorize execution.

**Threading `kp` into MCP:** `buildMcpServer`'s `McpContext` gains a `kp:
Keypair` field (already available as `app.ctx.kp` in the REST server),
passed through from `registerMcpRoutes`.

## Data flow

```
agent: request_approval -> pending attestation, email sent
human:  approves via browser passkey ceremony
agent: wait_for_approval -> { status: "approved", token }
agent: consume_approval(token) -> first call: { valid: true, ... }
                                -> execute the real action
agent (or a second agent, or a retry): consume_approval(token)
                                -> { valid: false, reason: "already_consumed" }
                                -> must NOT execute
```

## Error handling

- Bad/garbage/expired token: unchanged existing behavior
  (`signature_invalid` / `expired`).
- Valid signature, already consumed: `{ valid: false, reason:
  "already_consumed" }`, audited as `token_already_consumed`.
- Concurrent double-consume race: the `UPDATE ... WHERE token_consumed_at IS
  NULL` is atomic at the SQLite level, so exactly one of two racing calls
  wins; this is the same primitive already relied on for enrolment tokens
  and login challenges, not new machinery.

## Testing

- `consumeAttestationToken`: first call true, second call false, unknown id
  false.
- `verifyAndConsumeAttestation`: valid token consumed once; second call on
  same token returns `already_consumed`; invalid/expired tokens pass
  through unchanged; a race (two calls issued back to back against the same
  token) results in exactly one `valid: true`.
- REST `POST /v1/attestations/verify`: full-stack test hitting a real
  server twice with the same token.
- MCP `consume_approval`: full round trip (request → approve → wait →
  consume → consume again fails), plus an `unaudited-rejection-sweep`-style
  check that the second call's rejection is audited.

## Documentation

- `docs/api/reference.md`: rewrite the `verify` section to state the
  single-use guarantee plainly, document `reason: "already_consumed"`, and
  add the new `consume_approval` MCP tool.
- `docs/integration/quickstart.md`: the line recommending offline JWKS
  verification needs a caveat that only the HTTP `verify` call — not
  self-verification — gives a single-use guarantee, so an integrator who
  wants enforcement must call it.

## Non-goals

- Human-Attest does not execute the downstream action itself (still not a
  payments/email/document-signing broker) — this design only makes the
  *authorization* single-use, which is the boundary the product has always
  drawn.
- No change to `check_approval`, `request_approval`, or attestation status
  semantics.
