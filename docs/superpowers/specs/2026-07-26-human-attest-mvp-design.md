# Human-Attest MVP — Implementation Design

**Date:** 2026-07-26
**Status:** Approved for planning
**Product spec:** [`docs/human-attest-mvp.md`](../../human-attest-mvp.md) — architecture, threat model, pricing, and open questions live there. This document covers *how we build it*.

---

## 1. Goal and definition of done

A **working local prototype** that proves the cryptographic core end to end: a
human enrolls a passkey, an agent requests authorization for a concrete action,
the human approves it on a page that renders the action from the signed payload,
and the resulting token verifies offline against a published key.

Done means all of the following run locally:

1. A principal enrolls a passkey via WebAuthn.
2. A demo agent requests a wire transfer and blocks.
3. The approval page renders the action summary from the canonicalized payload.
4. The human approves; the authenticator signs the action hash.
5. The service issues a JWS the demo agent verifies offline before executing.
6. A second flow requires two approvers and refuses to resolve on one.
7. The security suite demonstrates the threat-model claims hold.

**Not done, deliberately:** deployment, real push delivery, liveness detection,
native apps, dashboard UI, multi-tenant API keys.

---

## 2. Scope

**In:** passkey enrolment; attestation request / approve / deny; server-side
canonicalization, hashing, and summary rendering; JWS issuance and offline
verification; Tier 4 N-of-M multi-party approval; demo agent; threat-model test
suite; `audit_log` table.

**Out:** dashboard UI (table only, no page); Tier 3 liveness; push notification
delivery (approval is a local URL); hosted deploy; SDKs beyond the demo client.

---

## 3. Stack

| Concern | Choice | Rationale |
|---|---|---|
| Language | TypeScript (Node 20+, ESM) | Mature WebAuthn tooling; one language for server and approval page |
| HTTP | Fastify | Schema-first validation fits typed action payloads |
| WebAuthn | `@simplewebauthn/server` + `@simplewebauthn/browser` | Most complete implementation available |
| JWS | `jose` | ES256 signing, JWKS publication, offline verify |
| Canonicalization | RFC 8785 (JCS) | A standard, rather than a bespoke ordering scheme |
| Storage | SQLite via `better-sqlite3` | Zero-setup, synchronous, sufficient for a prototype |
| Tests | Vitest; Playwright for E2E | Playwright reaches CDP for virtual authenticators |

---

## 4. Module boundaries

Five source modules with one job each, plus tests and demo. Ownership maps 1:1
to agents (§10), so no two agents write the same file.

```
src/
  types.ts           # frozen shared contract — lead owns
  crypto/            # canonicalize, hash, sign, verify, keys
  webauthn/          # registration + authentication ceremonies
  actions/           # payload schemas + summary rendering
  api/               # routes, state machine, quorum
  db/                # schema, migrations, queries
tests/
  integration/       # seams between modules
  e2e/               # full browser flows
  security/          # threat-model suite
demo/                # reference agent + approval page
```

`crypto/` and `actions/` are pure — no I/O, no database, no HTTP. That keeps the
two components involved in the system's central invariant (§7) trivially
testable in isolation.

---

## 5. The shared contract

`src/types.ts` is written **before any agent spawns** and frozen. Everything
else builds against it. Changes to it go through the lead, never a teammate.

```ts
export type RiskTier = "low" | "medium" | "high" | "critical";

export type AttestationStatus =
  | "pending" | "approved" | "denied" | "expired";

export type ActionType =
  | "wire_transfer" | "send_email" | "sign_document" | "generic";

export interface ActionRequest {
  type: ActionType;
  payload: Record<string, unknown>;   // validated against a per-type schema
  risk_tier: RiskTier;
}

export interface CanonicalAction {
  type: ActionType;
  canonical_json: string;             // RFC 8785 output
  payload_hash: string;               // "sha256:<hex>"
  summary: RenderedSummary;           // derived, never caller-supplied
}

export interface RenderedSummary {
  headline: string;                   // "Wire $25,000.00 to Acme Corp"
  fields: Array<{ label: string; value: string }>;
}

export interface AttestationRecord {
  id: string;
  action_id: string;
  status: AttestationStatus;
  required_approvals: number;         // N
  approver_ids: string[];             // M
  expires_at: string;                 // ISO 8601
  resolved_at: string | null;
}

export interface AttestationToken {
  jti: string;                        // attestation id
  sub: string;                        // principal id (primary approver)
  act: string;                        // payload_hash — the binding
  approvers: string[];                // all principals who approved
  mth: "passkey" | "passkey_multi";
  iat: number;
  exp: number;
}
```

---

## 6. Data model

```sql
principals(id, email, display_name, status, created_at)

credentials(id, principal_id, credential_id, public_key,
            sign_count, transports, created_at)

actions(id, requested_by, type, canonical_json, payload_hash,
        risk_tier, created_at, purged_at)

attestations(id, action_id, status, required_approvals,
             expires_at, created_at, resolved_at, token)

attestation_approvals(id, attestation_id, principal_id, decision,
                      client_data_json, authenticator_data,
                      signature, signed_at)

audit_log(id, attestation_id, event, actor, detail, created_at)
```

**On storing payloads.** The product spec says store only the hash. We cannot
render the approval summary without the payload, so `actions.canonical_json`
holds the RFC 8785 output during the pending window, and a purge on resolution
nulls it, stamping `purged_at`. `payload_hash` persists forever. This is a
deliberate, documented amendment to the product spec, and the purge is covered
by a test.

Storing the *canonical* form rather than the raw payload means hash recomputation
during the pending window is byte-exact and needs no re-canonicalization step.

`sign_count` is stored to detect authenticator counter regression, which is a
cloned-credential signal.

---

## 7. The central invariant

The one property the whole product rests on:

> The bytes the human sees and the bytes the authenticator signs derive from a
> single canonicalization of a single caller-supplied payload.

Enforced structurally:

1. The caller submits `ActionRequest.payload` — **never** display text.
2. `actions/` validates it against the per-type schema; malformed input is
   rejected before anything is hashed.
3. `crypto/canonicalize` produces RFC 8785 JSON; `crypto/hash` produces
   `payload_hash`.
4. `actions/render` produces `RenderedSummary` **from the canonical JSON**, via
   a per-type template. There is no code path where the caller influences it.
5. The WebAuthn authentication ceremony's **challenge** is derived from
   `payload_hash`, not equal to it: the challenge is
   `hash(canonicalize({ act: payload_hash, att: attestation_id, decision }))`,
   RFC 8785-canonicalized and hashed the same way as an action payload, where
   `decision` is the closed enum `"approve" | "deny"` being recorded and
   `att` is the specific attestation instance the ceremony is for.
   `payload_hash` is still the dominant term — it is still what ties the
   signature to *this action* — but folding `att` and `decision` into the
   same preimage means the hash lands inside signed `clientDataJSON` for
   both approve and deny, and is unique to one attestation record even when
   two records share an identical action.
6. At **decision time** — for both `approve` and `deny`, not `approve` alone —
   the server recomputes the expected challenge from the stored
   `canonical_json`, the attestation id being decided, and the decision being
   submitted, and compares it to the challenge inside `clientDataJSON`. At
   **verify time** — after the payload has been purged — the token's `act`
   claim is compared against the retained `payload_hash` directly; `act` is
   always the plain action hash, never the bound challenge hash, so offline
   verification is unaffected by any of this. Either mismatch fails closed.

Step 5 is the crux, and why `decision` and `att` are each bound in rather than
left out deserves recording — two separate reasons, for two separate fields,
found in two separate rounds:

WebAuthn already signs its challenge, so binding a decision to the action
needs no novel cryptography — it needs the challenge to *be derived from* the
action hash. The obvious simpler fix — require a signature over the bare
action hash for `deny` too, same as `approve` — was rejected, because it would
make the two decisions sign identical bytes for the same action. That makes
them cryptographically interchangeable: an assertion captured during a `deny`
could be replayed as an `approve` for the same action, which is strictly worse
than the gap it would close (an unauthenticated `deny`). Folding `decision`
into the challenge's preimage gives `approve` and `deny` on the same action
distinct, non-interchangeable challenges, so a signature over one can never
stand in for the other.

Binding `att` closes a second, separate gap that `decision` alone does not:
nothing about creating an attestation deduplicates on `payload_hash`, so two
independently-created attestations can legitimately carry byte-for-byte
identical payload content, and therefore the identical `payload_hash`. Without
the attestation id in the preimage, both attestations got the *identical*
challenge for the same decision — a genuine signature captured approving one
was cryptographically valid input for the other, letting an attacker mint a
brand-new, validly-timestamped token against a completely different
attestation using a signature the human only ever meant for the first one.
Because the resulting token is freshly issued (its own `iat`/`exp`/`jti`), the
threat model's stated defense against token replay — short expiry — never
engages; the attacker isn't replaying an old token, they're using a captured
signature to mint a new one. Binding `att` into the challenge means no two
attestations ever share a challenge for the same decision, signed or not, so a
captured signature is redeemable only against the one specific attestation
record it was produced for.

**Do not simplify either binding away as redundant.** Dropping `decision` back
out reintroduces approve/deny interchangeability; dropping `att` back out
reintroduces cross-attestation signature replay whenever two attestations
happen to share a payload. Both fields are load-bearing for a different attack
each, not belt-and-suspenders duplication of one.

**Honest limit.** WebAuthn cannot display transaction text; authenticators sign
opaque bytes. The binding proves the authenticator signed *this action hash*,
and that the agent never supplied display text. It does not prove the human
read the summary. The trust assumption is that the approval page is ours. This
belongs in the threat model as a stated assumption, not a defended claim.

---

## 8. Attestation state machine

```
                  ┌── approve (quorum unmet) ──┐
                  │                            v
  created ──> pending ──── approve (quorum met) ──> approved
                  │                                  (token issued)
                  ├──── any deny ──────────────> denied
                  └──── ttl elapsed ───────────> expired
```

Rules:

- **Fail closed.** Any single denial resolves the whole attestation to `denied`,
  even with approvals already recorded. A dissenting approver is a stop signal.
- **Terminal is terminal.** No transition out of `approved`, `denied`, `expired`.
- **Expiry is evaluated on read**, not by a background job, so a prototype
  without a scheduler cannot serve a stale-but-unexpired attestation.
- **Quorum:** `required_approvals` (N) of `approver_ids` (M). N = 1 is the
  ordinary single-approver case — Tier 1 and Tier 4 share one code path.
- **One approval per principal per attestation**, enforced by unique index.
- Approvals from principals outside `approver_ids` are rejected.

---

## 9. Error handling

Fail closed, and say why without leaking. Every rejection writes to `audit_log`.

| Condition | Response |
|---|---|
| Payload fails type schema | `400`, before hashing |
| Unknown principal or credential | `404` / `401`, no distinction leaked to caller |
| Challenge ≠ expected `payload_hash` | `400`, logged as `binding_mismatch` — high-signal event |
| Signature invalid | `401`, logged |
| `sign_count` regression | `401`, logged as `possible_credential_clone` |
| Approval after terminal state | `409` |
| Approval after `expires_at` | `410` |
| Token expired or signature invalid at verify | `{ valid: false, reason }`, HTTP `200` — verification answering truthfully is not an error |

---

## 10. Testing strategy

Three tiers, three owners, no overlap:

- **Unit (builders, test-first).** Colocated `*.test.ts`. Each builder tests
  their own module in isolation. `crypto/` and `actions/` are pure, so these are
  fast and exhaustive — including JCS vectors from RFC 8785.
- **Integration + E2E (QA).** The seams: canonicalize → hash → render → sign →
  verify. E2E drives a real browser with a CDP virtual authenticator
  (`WebAuthn.addVirtualAuthenticator`, Chromium only) so passkey flows run
  unattended.
- **Security (Adversary).** One test per row of the product spec's threat-model
  table, plus the summary/payload binding bypass. These are written as attacks
  that must fail, not features that must work.

---

## 11. Team split and sequencing

| Agent | Owns |
|---|---|
| **Crypto Core** | `src/crypto/**` |
| **Ceremony** | `src/webauthn/**` |
| **API & State** | `src/api/**`, `src/db/**`, `src/actions/**` |
| **QA** | `tests/integration/**`, `tests/e2e/**`, `demo/**` |
| **Adversary** | `tests/security/**` |
| **Docs** | `docs/api/**`, `docs/integration/**`, `README.md` |
| **Lead** | `src/types.ts`, this spec, integration decisions |

**Order of operations:**

1. Lead writes and freezes `src/types.ts` plus project scaffolding. No agent
   spawns before this exists — three agents inventing signatures against an
   unwritten contract is the standard way these runs fail.
2. Crypto Core and Ceremony start in parallel; they share no files and no
   dependencies.
3. API & State starts immediately on schema and state machine, integrating with
   1 and 2 as their interfaces land.
4. QA's first task is the harness and virtual-authenticator rig — independent
   work that unblocks everyone — then integration tests as modules land.
5. Docs writes the API reference from the frozen contract, before the
   implementation exists. Awkward docs are a signal the API needs revision, and
   that signal is only useful early.
6. Adversary writes attacks from the threat model, failing until targets exist.

**Known bottleneck.** API & State owns the most surface and everyone integrates
through it. If teammates idle, they claim from the shared task list rather than
inventing scope.

---

## 12. Deferred

Carried from the product spec, not resolved here: key custody (self-custodial
vs. HSM), device-loss recovery, and whether to align to emerging
agent-authorization standards. The prototype uses a local dev keypair on disk
and no recovery path — both flagged in the README as prototype-only.
