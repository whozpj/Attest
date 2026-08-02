# MCP server for Human-Attest

**Date:** 2026-08-01
**Status:** Approved for implementation

## 1. What this adds, in one paragraph

Human-Attest gets a third API surface, `/mcp`, alongside the existing `/v1/*`
(agents/verifiers) and `/web/*` (browser). It exposes three MCP tools —
`request_approval`, `check_approval`, `wait_for_approval` — that any MCP
client (Claude, LangGraph, or anything else speaking Model Context Protocol)
can call directly, without hand-rolling HTTP requests against `/v1/*`. Under
the hood, every tool call routes through the exact same validation, hashing,
rendering, email delivery, and token-signing logic the REST API already
uses — the MCP layer is a protocol adapter, not a second implementation of
anything security-relevant.

## 2. Decisions and their rationale

| # | Decision | Why |
|---|---|---|
| D1 | Mounted on the existing Fastify app at `/mcp`, not a separate process | One deployment, one Docker image, no new infra. Matches the product framing: "every compatible MCP client integrates with the same approval service." |
| D2 | Stateless Streamable HTTP transport (`sessionIdGenerator: undefined`) | Each of the three tools is a short, self-contained request — none needs continuity with a prior call. Stateless mode needs no in-memory session map, nothing to leak memory if a client disconnects without closing, and no session-affinity requirement if this is ever run behind a load balancer (today it's explicitly a single-instance deployment per `docs/PRODUCTION.md`, but stateless costs nothing and removes a future migration concern). |
| D3 | Tool handlers call shared internal functions, not their own logic and not a loopback HTTP call to `/v1/*` | A loopback call is wasteful and, worse, invites the MCP and REST surfaces to drift apart if one is patched and the other isn't. Extracting `createAttestation`/`getAttestationView` out of `routes.attestations.ts` so both callers share one implementation is the only way to guarantee they can't diverge. |
| D4 | `request_approval` keeps the existing `{type, risk_tier, payload}` action shape — no new action types, no free-text title field | This is the one place a scope-creeping "nicer" design would have quietly reopened the project's central invariant: the agent never supplies display text. A `title` field on the MCP tool would be exactly that. Every example in the product pitch (merge a PR, refund a customer, wire a transfer) fits `type: "generic"` with a structured `payload.detail`, or one of the other three existing types. |
| D5 | Approvers are named by `approver_emails`, resolved server-side to `principal_id` | The REST API takes raw `principal_id`s, which an agent-platform operator wiring this up is unlikely to already have. Email is what a human operator actually knows. Resolution uses the existing `getPrincipalByEmail` query (added for sign-in); an unresolvable email is a clear, closed rejection — this endpoint is already unauthenticated by the existing threat model (same as `POST /v1/attestations` today), so this isn't a new trust boundary, just a friendlier one. |
| D6 | `requested_by` defaults to the connecting MCP client's declared name (`getClientVersion()`), overridable, with a final fallback of the literal string `"mcp-client"` | Audit rows read "claude-code" or "langgraph" instead of a placeholder string, at zero cost — the MCP handshake already carries this. `requested_by` must be a non-empty string (`validateEnvelope` rejects otherwise), and `getClientVersion()` returns `undefined` before a client has completed the initialize handshake or if a client declares no name — the literal fallback is what keeps that edge from ever reaching `validateEnvelope` as an empty/missing value. |
| D7 | `wait_for_approval` polls server-side with a bounded timeout (default 300s, hard cap 3600s) | Mirrors `demo/agent.ts`'s existing poll loop as a reusable primitive, so an agent framework doesn't have to implement its own. Bounded so a call can't hold a connection open indefinitely — some MCP clients enforce their own request timeouts, and an unbounded wait is a resource leak regardless. |
| D8 | No `verify_approval_token` MCP tool | The offline-JWKS verification path (`docs/integration/quickstart.md`) already serves a receiving system that isn't the calling agent. Duplicating it as an MCP tool adds surface for a use case with no MCP client on the other end. Cut for this pass; trivial to add later against the same shared functions if ever needed. |
| D9 | No additional auth on `/mcp` beyond what `/v1/*` already has | Consistent, not an oversight: the design doc's existing threat model states the agent platform is trusted to be "honest-but-vulnerable," and `POST /v1/attestations` has never required caller authentication. `/mcp` inherits that exact posture rather than inventing a new, inconsistent one. Worth revisiting if this project ever adds platform-level API keys — noted as a follow-up, not solved here. |

## 3. Architecture

```
MCP client (Claude, LangGraph, ...)
        │  Streamable HTTP (JSON-RPC over POST, stateless)
        ▼
┌─────────────────────────────────────┐
│  src/mcp/server.ts                  │
│    buildMcpServer() → McpServer     │
│      registers 3 tools              │
└───────────────┬─────────────────────┘
                │ calls
                ▼
┌─────────────────────────────────────┐
│  src/api/attestations-core.ts (new) │
│    createAttestation(...)           │  ← extracted from
│    getAttestationView(...)          │    routes.attestations.ts
└───────────────┬─────────────────────┘
                │ calls (unchanged)
                ▼
  validateEnvelope → prepareAction → q.insertAction/insertAttestation
  → emailApprovers → effectiveStatus → q.getAttestation/getAction
```

`src/api/routes.attestations.ts`'s `POST /v1/attestations` and
`GET /v1/attestations/:id` handlers become thin wrappers around the same two
extracted functions — parse/validate the HTTP-specific bits (path params,
JSON body), call the shared function, shape the HTTP response. No behavior
change on `/v1/*`; every existing test for those routes must still pass
unmodified.

## 4. The three tools

### `request_approval`

```ts
inputSchema: {
  type: z.enum(["wire_transfer", "send_email", "sign_document", "generic"]),
  risk_tier: z.enum(["low", "medium", "high", "critical"]),
  payload: z.record(z.unknown()),
  approver_emails: z.array(z.string().email()).min(1),
  requested_by: z.string().optional(),
  required_approvals: z.number().int().min(1).optional(),
  ttl_seconds: z.number().optional(),
}
```

Resolves each `approver_emails` entry to a `principal_id` via
`getPrincipalByEmail`; rejects (tool error, not a thrown protocol error) if
any address has no enrolled principal, naming which address failed — this
is a configuration-time error for the operator wiring up the integration,
not a runtime probe against arbitrary end users, so it does not need the
`/web/session/options`-style opacity that endpoint requires. Calls
`createAttestation` with the resolved `principal_id`s. Returns
`{attestation_id, status, payload_hash, summary, approve_url}` as both a
text summary (for a model to read) and `structuredContent` (for a caller to
parse).

### `check_approval`

```ts
inputSchema: { attestation_id: z.string() }
```

Calls `getAttestationView`. Returns the same shape `GET /v1/attestations/:id`
returns today.

### `wait_for_approval`

```ts
inputSchema: {
  attestation_id: z.string(),
  timeout_seconds: z.number().int().min(1).max(3600).optional(), // default 300
}
```

Polls `getAttestationView` every 1 second (matching `demo/agent.ts`) until
`status !== "pending"` or the timeout elapses. Returns
`{status, token, timed_out}`. `timed_out: true` with `status: "pending"` is
a distinct, non-error result — a caller can decide to poll again or give up;
it is not a tool failure.

## 5. Error handling

**Corrected after the final whole-branch review** (the review found this
section made a claim about the codebase's auditing that was never actually
true, and every task built and reviewed correctly against that false claim
— the gap was real, not an implementation slip): this codebase has exactly
one audit choke point, `server.ts`'s central `setErrorHandler`, which fires
on a *thrown* exception that reaches Fastify's request lifecycle. There is
no second, independent "throw-site auditing" mechanism anywhere in
`src/` — every other audited rejection in the app (`state.ts`, `notify.ts`,
`routes.web.*`, `registration.ts`) is either a direct `q.audit` call at that
specific site or, for HTTP rejections, a throw that reaches the central
handler. An MCP tool handler that catches a `FailClosedError` and *returns*
`{isError: true, content: [...]}` never throws past its own `try/catch`, so
it never reaches the central handler and writes **zero** `audit_log` rows —
a real, structural gap `docs/PRODUCTION.md`'s "every rejection writes a row"
claim does not survive for this surface without fixing at the source.

Tool input validation is Zod's job (the SDK validates `inputSchema` before
the handler ever runs). Everything past that boundary reuses the existing
`FailClosedError` machinery: `createAttestation`/`getAttestationView` throw
the same typed errors the REST routes already throw, and the MCP tool
handler catches them, **audits directly at that catch site** (the one place
every tool rejection funnels through, since there is no throw left to reach
the central handler), and returns an MCP tool error result
(`{isError: true, content: [...]}`) carrying the same `code`/`message` —
never a raw 500-equivalent, and never silently swallowed. Every rejection
still writes to `audit_log`: for anything that reaches an HTTP layer outside
a tool call (a malformed JSON-RPC envelope, an unhandled non-`FailClosedError`
throw), via `server.ts`'s central error handler exactly as before; for a
`FailClosedError` caught inside a tool handler, via the explicit `q.audit`
call at that catch site described above.

`GET /mcp` (the standalone SSE stream for server-initiated notifications) is
not supported in stateless mode — returns `405`, per the transport's
documented behavior, since there is no session to attach a notification
stream to.

## 6. Testing

| Layer | What |
|---|---|
| Unit | `attestations-core.ts`'s extracted functions, tested directly (mirrors existing `routes.attestations.test.ts` coverage, now exercising the shared function rather than only through `app.inject`) |
| Unit | Each MCP tool handler, using the SDK's own in-memory `Client`/`InMemoryTransport` pair — proves the wire protocol actually round-trips (schema validation, `structuredContent`, error shape), not just that the internal function is correct |
| Integration | `request_approval` → `check_approval` → (real WebAuthn approval via existing test infra) → `wait_for_approval` resolves with the token, in-process |
| Security | `request_approval` cannot smuggle a caller-supplied display string past `validateAction`'s closed-world schema (same guarantee the REST API already has, proven again through the new entrypoint); an unresolvable `approver_emails` entry rejects closed and creates nothing |
| Regression | Full existing `/v1/attestations` test suite passes unmodified against the post-extraction `routes.attestations.ts` |
| E2E | One Playwright spec: MCP tool creates a real attestation → real approval email → real passkey approval via the SPA → `wait_for_approval` (driven via the MCP SDK's `Client` against the real running server) returns the verified token |

## 7. Non-goals for this pass

- No new `ActionType`s (e.g. a first-class `merge_pull_request` type). `generic` covers it; see D4.
- No authentication/API-key gating on `/mcp` (D9) — inherits the existing posture.
- No `verify_approval_token` tool (D8).
- No MCP *resources* or *prompts* — only tools. Nothing in the product pitch calls for them.
