# MCP Server Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expose Human-Attest's approval workflow as three MCP tools (`request_approval`, `check_approval`, `wait_for_approval`) that any MCP client can call directly, mounted at `/mcp` on the existing Fastify app.

**Architecture:** Extract the core logic of `POST /v1/attestations` and `GET /v1/attestations/:id` out of `routes.attestations.ts` into shared functions in a new `src/api/attestations-core.ts`. Both the existing REST routes and the new MCP tool handlers call those same functions — the MCP layer is a protocol adapter, never a second implementation. The MCP server is mounted stateless (no session tracking) via `@modelcontextprotocol/sdk`'s Streamable HTTP transport — a fresh `McpServer`/transport pair per request, per the SDK's own stateless-mode contract (see Task 5's note on the shared-instance correction).

**Tech Stack:** TypeScript, `@modelcontextprotocol/sdk` 1.30 (already installed), `zod` 4.4 (already installed), Fastify 5, Vitest, Playwright.

**Spec:** `docs/superpowers/specs/2026-08-01-mcp-server-design.md` — read it before starting any task.

## Global Constraints

- **Never touch `src/webauthn/`, `src/crypto/`, or `src/actions/`.** The challenge binding and closed-world action validation are the product's security core and are out of scope for every task in this plan.
- **No new `ActionType`s and no free-text display field on any MCP tool.** `request_approval` takes exactly `{type, risk_tier, payload}`, the same shape `POST /v1/attestations` already validates. An agent must never be able to supply display text directly (design doc D4).
- **Every rejection is a `FailClosedError`**, mapped to an MCP tool error result (`{isError: true, content: [...]}`) — never an uncaught exception that surfaces as a raw protocol error with no audit trail.
- **`/v1/attestations` and `/v1/attestations/:id`'s existing test suites must pass unmodified** after the Task 1 extraction. If a test needs to change to keep passing, that is a sign the extraction changed behavior — stop and reconcile, don't edit the test to match.
- **`npm install` is not needed** — `@modelcontextprotocol/sdk` (1.30.0) and `zod` (4.4.3) are already installed. Zod v4 API confirmed: `z.string().email()`, `z.record(z.string(), z.unknown())`, `z.enum([...])` all work as used below.
- Node 20+, ESM (`"type": "module"`) — every relative import ends in `.js`.
- Test runner: `npm test` (Vitest). E2E: `npm run e2e` (Playwright, requires `npm run build:web` first).

---

### Task 1: Extract shared attestation-core functions

**Files:**
- Create: `src/api/attestations-core.ts`
- Modify: `src/api/routes.attestations.ts`
- Test: `src/api/attestations-core.test.ts`

**Interfaces:**
- Consumes: `validateEnvelope` (`src/actions/schemas.js`), `prepareAction`/`renderSummary` (`src/actions/render.js`), `effectiveStatus` (`src/api/state.js`), `emailApprovers` (`src/api/notify.js`), `q.*` (`src/db/queries.js`)
- Produces:
  ```ts
  export interface CreateAttestationResult {
    attestation_id: string;
    status: "pending";
    payload_hash: string;
    summary: RenderedSummary;
    approve_url: string;
  }
  export interface AttestationView {
    attestation_id: string;
    status: AttestationStatus;
    payload_hash: string;
    required_approvals: number;
    approvals: number;
    summary: RenderedSummary | null;
    token: string | null;
  }
  export function createAttestation(
    db: Database, email: EmailTransport, baseUrl: string, input: unknown,
    logger?: { warn(obj: Record<string, unknown>, msg: string): void },
  ): CreateAttestationResult;
  export function getAttestationView(db: Database, id: string): AttestationView;
  ```

- [ ] **Step 1: Write the failing test**

```ts
// src/api/attestations-core.test.ts
import { describe, it, expect, beforeEach } from "vitest";
import { openDb, type Database } from "../db/index.js";
import * as q from "../db/queries.js";
import { createAttestation, getAttestationView } from "./attestations-core.js";
import { FailClosedError } from "../types.js";
import type { EmailTransport, EmailMessage } from "../email/index.js";

function recorder(): EmailTransport & { sent: EmailMessage[] } {
  const sent: EmailMessage[] = [];
  return { sent, async send(msg) { sent.push(msg); } };
}

const wireInput = {
  requested_by: "agent-7",
  approver_ids: ["prin_1"],
  required_approvals: 1,
  action: {
    type: "wire_transfer", risk_tier: "high",
    payload: { amount: 2500000, currency: "USD", recipient_name: "Acme Corp", account_last4: "4821" },
  },
};

describe("createAttestation", () => {
  let db: Database;
  beforeEach(() => {
    db = openDb(":memory:");
    q.insertPrincipal(db, { id: "prin_1", email: "one@e.com", display_name: "One" });
  });

  it("creates a pending attestation with the rendered summary and approve_url", () => {
    const result = createAttestation(db, recorder(), "http://localhost:3000", wireInput);
    expect(result.status).toBe("pending");
    expect(result.summary.headline).toBe("Wire $25,000.00 USD to Acme Corp");
    expect(result.approve_url).toBe(`http://localhost:3000/requests/${result.attestation_id}`);
    expect(result.payload_hash).toMatch(/^sha256:/);
  });

  it("persists the attestation so it can be read back", () => {
    const result = createAttestation(db, recorder(), "http://localhost:3000", wireInput);
    const att = q.getAttestation(db, result.attestation_id);
    expect(att?.status).toBe("pending");
    expect(att?.approver_ids).toEqual(["prin_1"]);
  });

  it("emails every approver", async () => {
    const t = recorder();
    createAttestation(db, t, "http://localhost:3000", wireInput);
    await new Promise((r) => setTimeout(r, 20)); // emailApprovers is fire-and-forget
    expect(t.sent).toHaveLength(1);
    expect(t.sent[0].to).toBe("one@e.com");
  });

  it("throws FailClosedError for an invalid action, and creates nothing", () => {
    expect(() =>
      createAttestation(db, recorder(), "http://localhost:3000", {
        ...wireInput, action: { type: "wire_transfer", risk_tier: "high", payload: { amount: "not-a-number" } },
      }),
    ).toThrow(FailClosedError);
    expect(db.prepare("SELECT COUNT(*) AS c FROM attestations").get()).toEqual({ c: 0 });
  });
});

describe("getAttestationView", () => {
  let db: Database;
  beforeEach(() => {
    db = openDb(":memory:");
    q.insertPrincipal(db, { id: "prin_1", email: "one@e.com", display_name: "One" });
  });

  it("returns the pending view with a non-null summary", () => {
    const created = createAttestation(db, recorder(), "http://localhost:3000", wireInput);
    const view = getAttestationView(db, created.attestation_id);
    expect(view.status).toBe("pending");
    expect(view.summary?.headline).toBe("Wire $25,000.00 USD to Acme Corp");
    expect(view.token).toBeNull();
  });

  it("throws unknown_attestation for a nonexistent id", () => {
    expect(() => getAttestationView(db, "att_nope")).toThrow(FailClosedError);
    try {
      getAttestationView(db, "att_nope");
    } catch (err) {
      expect((err as FailClosedError).code).toBe("unknown_attestation");
    }
  });
});
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `npx vitest run src/api/attestations-core.test.ts`
Expected: FAIL — cannot resolve `./attestations-core.js`.

- [ ] **Step 3: Write `src/api/attestations-core.ts`**

```ts
import { randomUUID } from "node:crypto";
import type { Database } from "better-sqlite3";
import * as q from "../db/queries.js";
import { prepareAction, renderSummary } from "../actions/render.js";
import { validateEnvelope } from "../actions/schemas.js";
import { effectiveStatus } from "./state.js";
import { emailApprovers } from "./notify.js";
import { FailClosedError, type AttestationStatus, type RenderedSummary } from "../types.js";
import type { EmailTransport } from "../email/index.js";

export interface CreateAttestationResult {
  attestation_id: string;
  status: "pending";
  payload_hash: string;
  summary: RenderedSummary;
  approve_url: string;
}

export interface AttestationView {
  attestation_id: string;
  status: AttestationStatus;
  payload_hash: string;
  required_approvals: number;
  approvals: number;
  summary: RenderedSummary | null;
  token: string | null;
}

export interface NotifyLogger {
  warn(obj: Record<string, unknown>, msg: string): void;
}

/**
 * Shared by POST /v1/attestations (routes.attestations.ts) and the
 * request_approval MCP tool (src/mcp/server.ts) -- extracted so the two
 * entrypoints cannot drift: a fix or a new validation rule applied to one
 * automatically applies to the other, since there is only one implementation.
 */
export function createAttestation(
  db: Database,
  email: EmailTransport,
  baseUrl: string,
  input: unknown,
  logger?: NotifyLogger,
): CreateAttestationResult {
  const envelope = validateEnvelope(input);

  const action = prepareAction(envelope.action);
  const actionId = `act_${randomUUID()}`;
  q.insertAction(db, {
    id: actionId, requested_by: envelope.requested_by, type: action.type,
    canonical_json: action.canonical_json, payload_hash: action.payload_hash,
    risk_tier: (envelope.action as { risk_tier: string }).risk_tier,
  });

  const attestationId = `att_${randomUUID()}`;
  q.insertAttestation(db, {
    id: attestationId, action_id: actionId,
    required_approvals: envelope.required_approvals,
    approver_ids: envelope.approver_ids,
    expires_at: new Date(Date.now() + envelope.ttl_seconds * 1000).toISOString(),
  });

  // Best-effort, fire-and-forget: see notify.ts -- emailApprovers never
  // throws, and a slow/blackholed mail host must never add latency to (or
  // block on) attestation creation, regardless of which entrypoint created it.
  void emailApprovers(db, email, {
    attestation_id: attestationId,
    approverIds: envelope.approver_ids,
    summary: action.summary,
    requestedBy: envelope.requested_by,
    expiresAt: new Date(Date.now() + envelope.ttl_seconds * 1000).toISOString(),
    baseUrl,
  }, logger);

  return {
    attestation_id: attestationId,
    status: "pending",
    payload_hash: action.payload_hash,
    summary: action.summary,
    approve_url: `${baseUrl}/requests/${attestationId}`,
  };
}

/** Shared by GET /v1/attestations/:id and the check_approval/wait_for_approval MCP tools. */
export function getAttestationView(db: Database, id: string): AttestationView {
  // effectiveStatus must run before the action row is read: if this is the
  // read that observes a fresh expiry, it purges canonical_json as a side
  // effect. Reading the action first would return the pre-purge summary from
  // this very response, one write later than the DB actually has it.
  const status = effectiveStatus(db, id);
  const att = q.getAttestation(db, id);
  if (!att) throw new FailClosedError("unknown_attestation", 404, "unknown attestation");
  const action = q.getAction(db, att.action_id)!;
  return {
    attestation_id: id,
    status,
    payload_hash: action.payload_hash,
    required_approvals: att.required_approvals,
    approvals: q.getApprovals(db, id).length,
    summary: action.canonical_json
      ? renderSummary(action.type as never, action.canonical_json)
      : null,
    token: att.token,
  };
}
```

- [ ] **Step 4: Run the new tests and confirm they pass**

Run: `npx vitest run src/api/attestations-core.test.ts`
Expected: PASS (6 tests)

- [ ] **Step 5: Rewrite `routes.attestations.ts`'s POST and GET handlers to call the extracted functions**

Replace the imports at the top of `src/api/routes.attestations.ts`:

```ts
import type { FastifyInstance } from "fastify";
import type { AppContext } from "./server.js";
import * as q from "../db/queries.js";
import { createAttestation, getAttestationView } from "./attestations-core.js";
import { beginApproval, finishApproval } from "../webauthn/authentication.js";
import { effectiveStatus, recordDecision } from "./state.js";
import { FailClosedError, type Decision } from "../types.js";
```

(Drop the now-unused `randomUUID`, `prepareAction`/`renderSummary`, `validateEnvelope`, and `emailApprovers` imports — everything they were used for now lives in `attestations-core.ts`.)

Replace the `POST /v1/attestations` and `GET /v1/attestations/:id` handler bodies:

```ts
  app.post("/v1/attestations", async (req, reply) => {
    const result = createAttestation(db, app.ctx.email, app.ctx.baseUrl, req.body, app.log);
    return reply.status(201).send(result);
  });

  app.get("/v1/attestations/:id", async (req) => {
    const { id } = req.params as { id: string };
    return getAttestationView(db, id);
  });
```

Leave `POST /v1/attestations/:id/options` and `POST /v1/attestations/:id/decision` exactly as they are — they are not part of this extraction, and still import `q`, `effectiveStatus`, `beginApproval`, `finishApproval`, `recordDecision` directly for their own needs.

- [ ] **Step 6: Run the full existing attestations test suite and confirm nothing changed**

Run: `npx vitest run src/api/routes.attestations.test.ts src/api/notify.test.ts`
Expected: PASS, same test count as before this task. Any failure here means the extraction changed observable behavior — find and fix the discrepancy before proceeding; do not edit the test file to match.

- [ ] **Step 7: Run the full suite and typecheck**

Run: `npx tsc --noEmit && npm test`
Expected: clean typecheck, all tests passing (should be 332, unchanged from before this task).

- [ ] **Step 8: Commit**

```bash
git add src/api/attestations-core.ts src/api/attestations-core.test.ts src/api/routes.attestations.ts
git commit -m "refactor: extract createAttestation/getAttestationView for reuse by the MCP server"
```

---

### Task 2: MCP server scaffold and the `check_approval` tool

This task validates the SDK integration itself on the simplest possible tool
(read-only, no side effects) before building anything more complex on top of
an untested pattern.

**Files:**
- Create: `src/mcp/server.ts`
- Test: `src/mcp/server.test.ts`

**Interfaces:**
- Consumes: `getAttestationView` (Task 1), `createAttestation` (Task 1, used by Task 3)
- Produces:
  ```ts
  export interface McpContext { db: Database; email: EmailTransport; baseUrl: string; }
  export function buildMcpServer(ctx: McpContext): McpServer;
  ```

- [ ] **Step 1: Write the failing test**

```ts
// src/mcp/server.test.ts
import { describe, it, expect, beforeEach } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { openDb, type Database } from "../db/index.js";
import * as q from "../db/queries.js";
import { createAttestation } from "../api/attestations-core.js";
import { buildMcpServer } from "./server.js";
import type { EmailTransport } from "../email/index.js";

const noopEmail: EmailTransport = { async send() {} };

async function connectedClient(db: Database) {
  const server = buildMcpServer({ db, email: noopEmail, baseUrl: "http://localhost:3000" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "test-client", version: "1.0.0" });
  await Promise.all([
    client.connect(clientTransport),
    server.connect(serverTransport),
  ]);
  return client;
}

describe("MCP server: tools/list", () => {
  it("advertises exactly check_approval at this stage of the plan", async () => {
    // Only check_approval exists after this task. request_approval and
    // wait_for_approval are added by Tasks 3 and 4; the three-tool version of
    // this assertion belongs to Task 5's real-HTTP test (see below), once all
    // three exist.
    const db = openDb(":memory:");
    const client = await connectedClient(db);
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual(["check_approval"]);
  });
});

describe("check_approval tool", () => {
  let db: Database;
  beforeEach(() => {
    db = openDb(":memory:");
    q.insertPrincipal(db, { id: "prin_1", email: "one@e.com", display_name: "One" });
  });

  it("returns the pending status and summary for a real attestation", async () => {
    const created = createAttestation(db, noopEmail, "http://localhost:3000", {
      requested_by: "agent-7", approver_ids: ["prin_1"], required_approvals: 1,
      action: {
        type: "wire_transfer", risk_tier: "high",
        payload: { amount: 2500000, currency: "USD", recipient_name: "Acme Corp", account_last4: "4821" },
      },
    });

    const client = await connectedClient(db);
    const result = await client.callTool({
      name: "check_approval",
      arguments: { attestation_id: created.attestation_id },
    });

    expect(result.isError).not.toBe(true);
    const structured = result.structuredContent as { status: string; token: string | null };
    expect(structured.status).toBe("pending");
    expect(structured.token).toBeNull();
  });

  it("returns a tool error, not a thrown exception, for an unknown attestation id", async () => {
    const client = await connectedClient(db);
    const result = await client.callTool({
      name: "check_approval",
      arguments: { attestation_id: "att_does_not_exist" },
    });
    expect(result.isError).toBe(true);
  });
});
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `npx vitest run src/mcp/server.test.ts`
Expected: FAIL — cannot resolve `./server.js`.

- [ ] **Step 3: Write `src/mcp/server.ts`**

```ts
import type { Database } from "better-sqlite3";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { getAttestationView } from "../api/attestations-core.js";
import { FailClosedError } from "../types.js";
import type { EmailTransport } from "../email/index.js";

export interface McpContext {
  db: Database;
  email: EmailTransport;
  baseUrl: string;
}

/**
 * Every tool handler below funnels a FailClosedError into an MCP tool error
 * result (`isError: true`) rather than letting it propagate as a thrown
 * protocol-level exception. An MCP client that gets an unstructured
 * connection error can't tell "your input was invalid" from "the server
 * crashed" -- a tool error keeps that distinction, matching how the REST API
 * always returns a typed JSON body rather than closing the connection.
 * Anything that is NOT a FailClosedError is rethrown: an unrecognised
 * failure should surface as a real error, not be silently downgraded to a
 * tool result the caller might mistake for an ordinary rejection.
 */
function toolError(message: string) {
  return { isError: true as const, content: [{ type: "text" as const, text: message }] };
}

export function buildMcpServer(ctx: McpContext): McpServer {
  const server = new McpServer({ name: "human-attest", version: "1.0.0" });

  server.registerTool(
    "check_approval",
    {
      title: "Check approval status",
      description: "Reads the current status of a pending or resolved attestation.",
      inputSchema: {
        attestation_id: z.string().describe("The attestation_id returned by request_approval."),
      },
    },
    async (args) => {
      try {
        const view = getAttestationView(ctx.db, args.attestation_id);
        return {
          content: [{ type: "text" as const, text: `Status: ${view.status}` }],
          structuredContent: view as unknown as Record<string, unknown>,
        };
      } catch (err) {
        if (err instanceof FailClosedError) return toolError(err.message);
        throw err;
      }
    },
  );

  return server;
}
```

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `npx vitest run src/mcp/server.test.ts`
Expected: PASS (3 tests). This proves the SDK integration itself works end to end (tool registration, `tools/list`, `tools/call`, structured content, error mapping) before Task 3 builds the more complex `request_approval` on the same pattern.

- [ ] **Step 5: Commit**

```bash
git add src/mcp/server.ts src/mcp/server.test.ts
git commit -m "feat(mcp): server scaffold and the check_approval tool"
```

---

### Task 3: `request_approval` tool

**Files:**
- Modify: `src/mcp/server.ts`
- Test: `src/mcp/server.test.ts` (append)

**Interfaces:**
- Consumes: `createAttestation` (Task 1), `q.getPrincipalByEmail` (`src/db/queries.js`)
- Produces: the `request_approval` tool, registered on the same `McpServer`

- [ ] **Step 1: Write the failing tests**

Append to `src/mcp/server.test.ts`:

```ts
describe("request_approval tool", () => {
  let db: Database;
  beforeEach(() => {
    db = openDb(":memory:");
    q.insertPrincipal(db, { id: "prin_1", email: "approver@e.com", display_name: "Approver" });
  });

  it("creates a real, pending attestation and returns its summary", async () => {
    const client = await connectedClient(db);
    const result = await client.callTool({
      name: "request_approval",
      arguments: {
        type: "wire_transfer", risk_tier: "high",
        payload: { amount: 2500000, currency: "USD", recipient_name: "Acme Corp", account_last4: "4821" },
        approver_emails: ["approver@e.com"],
      },
    });

    expect(result.isError).not.toBe(true);
    const structured = result.structuredContent as { attestation_id: string; status: string; summary: { headline: string } };
    expect(structured.status).toBe("pending");
    expect(structured.summary.headline).toBe("Wire $25,000.00 USD to Acme Corp");

    const att = q.getAttestation(db, structured.attestation_id);
    expect(att?.approver_ids).toEqual(["prin_1"]);
  });

  it("rejects closed, and creates nothing, when an approver email is not enrolled", async () => {
    const client = await connectedClient(db);
    const result = await client.callTool({
      name: "request_approval",
      arguments: {
        type: "generic", risk_tier: "low", payload: { title: "t", detail: "d" },
        approver_emails: ["nobody@e.com"],
      },
    });

    expect(result.isError).toBe(true);
    expect(db.prepare("SELECT COUNT(*) AS c FROM attestations").get()).toEqual({ c: 0 });
  });

  it("does not accept a caller-supplied display field outside the closed-world action schema", async () => {
    const client = await connectedClient(db);
    const result = await client.callTool({
      name: "request_approval",
      arguments: {
        type: "generic", risk_tier: "low",
        payload: { title: "t", detail: "d", headline: "SPOOFED DISPLAY TEXT" },
        approver_emails: ["approver@e.com"],
      },
    });
    // validateAction's closed-world check refuses any field outside the
    // type's schema -- "generic" only allows title/detail. This is the same
    // guarantee POST /v1/attestations already has; this test proves the MCP
    // entrypoint didn't quietly bypass it.
    expect(result.isError).toBe(true);
  });

  it("defaults requested_by to the connecting client's declared name", async () => {
    const server = buildMcpServer({ db, email: noopEmail, baseUrl: "http://localhost:3000" });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: "langgraph", version: "9.9.9" });
    await Promise.all([client.connect(clientTransport), server.connect(serverTransport)]);

    const result = await client.callTool({
      name: "request_approval",
      arguments: {
        type: "generic", risk_tier: "low", payload: { title: "t", detail: "d" },
        approver_emails: ["approver@e.com"],
      },
    });
    const structured = result.structuredContent as { attestation_id: string };
    const action = q.getAction(db, q.getAttestation(db, structured.attestation_id)!.action_id);
    expect(action?.requested_by).toBe("langgraph");
  });

  it("an explicit requested_by overrides the client's declared name", async () => {
    const client = await connectedClient(db);
    const result = await client.callTool({
      name: "request_approval",
      arguments: {
        type: "generic", risk_tier: "low", payload: { title: "t", detail: "d" },
        approver_emails: ["approver@e.com"], requested_by: "nightly-deploy-bot",
      },
    });
    const structured = result.structuredContent as { attestation_id: string };
    const action = q.getAction(db, q.getAttestation(db, structured.attestation_id)!.action_id);
    expect(action?.requested_by).toBe("nightly-deploy-bot");
  });
});
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `npx vitest run src/mcp/server.test.ts`
Expected: FAIL — `request_approval` tool not found (5 new failures).

- [ ] **Step 3: Add `request_approval` to `src/mcp/server.ts`**

Add the import and the resolver function above `buildMcpServer`, and register the tool inside it:

```ts
import { createAttestation, getAttestationView } from "../api/attestations-core.js";
import * as q from "../db/queries.js";
```

```ts
/**
 * Resolves each address to an enrolled principal via getPrincipalByEmail.
 *
 * Unlike POST /web/session/options (which must stay opaque about whether an
 * email is registered, because a stranger can reach it unauthenticated), the
 * caller here is whoever configured this MCP integration -- naming which
 * address failed to resolve is a real usability win for a configuration-time
 * error, not a probe surface against arbitrary third parties (design doc D5).
 */
function resolveApprovers(db: Database, emails: string[]): string[] {
  const ids: string[] = [];
  for (const email of emails) {
    const principal = q.getPrincipalByEmail(db, email);
    if (!principal) {
      throw new FailClosedError("unknown_principal", 404, `no enrolled approver with email ${email}`);
    }
    ids.push(principal.id);
  }
  return ids;
}
```

Inside `buildMcpServer`, after the `check_approval` registration:

```ts
  server.registerTool(
    "request_approval",
    {
      title: "Request human approval",
      description:
        "Ask a specific human to approve or deny a structured agent action. " +
        "Returns immediately with a pending attestation -- use wait_for_approval " +
        "or check_approval to learn the outcome. The action is limited to " +
        "{type, risk_tier, payload}: there is no free-text display field, " +
        "because what the approver sees is always rendered server-side from " +
        "this same structured payload, never supplied directly.",
      inputSchema: {
        type: z.enum(["wire_transfer", "send_email", "sign_document", "generic"])
          .describe("wire_transfer: amount/currency/recipient_name/account_last4. " +
            "send_email: to/subject/body. sign_document: document_name/document_hash. " +
            "generic: title/detail -- use this for anything else (e.g. a PR merge, an infra change)."),
        risk_tier: z.enum(["low", "medium", "high", "critical"]),
        payload: z.record(z.string(), z.unknown())
          .describe("Fields required depend on `type`; see its description."),
        approver_emails: z.array(z.string().email()).min(1)
          .describe("Email address(es) of already-enrolled Human-Attest principals."),
        requested_by: z.string().optional()
          .describe("Defaults to this MCP client's declared name."),
        required_approvals: z.number().int().min(1).optional().describe("Defaults to 1."),
        ttl_seconds: z.number().optional().describe("Defaults to 900 (15 minutes)."),
      },
    },
    async (args, extra) => {
      let approverIds: string[];
      try {
        approverIds = resolveApprovers(ctx.db, args.approver_emails);
      } catch (err) {
        if (err instanceof FailClosedError) return toolError(err.message);
        throw err;
      }

      const clientInfo = server.server.getClientVersion();
      const requestedBy = args.requested_by ?? clientInfo?.name ?? "mcp-client";

      try {
        const result = createAttestation(ctx.db, ctx.email, ctx.baseUrl, {
          requested_by: requestedBy,
          approver_ids: approverIds,
          required_approvals: args.required_approvals,
          ttl_seconds: args.ttl_seconds,
          action: { type: args.type, risk_tier: args.risk_tier, payload: args.payload },
        });
        return {
          content: [{
            type: "text" as const,
            text: `Approval requested: ${result.summary.headline}. Status: pending. ` +
              `attestation_id=${result.attestation_id}`,
          }],
          structuredContent: result as unknown as Record<string, unknown>,
        };
      } catch (err) {
        if (err instanceof FailClosedError) return toolError(err.message);
        throw err;
      }
    },
  );
```

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `npx vitest run src/mcp/server.test.ts`
Expected: PASS (8 tests total)

- [ ] **Step 5: Commit**

```bash
git add src/mcp/server.ts src/mcp/server.test.ts
git commit -m "feat(mcp): request_approval tool with email-based approver resolution"
```

---

### Task 4: `wait_for_approval` tool

**Files:**
- Modify: `src/mcp/server.ts`
- Test: `src/mcp/server.test.ts` (append)

**Interfaces:**
- Consumes: `getAttestationView` (Task 1)
- Produces: the `wait_for_approval` tool

- [ ] **Step 1: Write the failing tests**

Append to `src/mcp/server.test.ts`:

```ts
describe("wait_for_approval tool", () => {
  let db: Database;
  beforeEach(() => {
    db = openDb(":memory:");
    q.insertPrincipal(db, { id: "prin_1", email: "one@e.com", display_name: "One" });
  });

  it("returns immediately once the attestation is already resolved", async () => {
    const created = createAttestation(db, noopEmail, "http://localhost:3000", {
      requested_by: "agent-7", approver_ids: ["prin_1"],
      action: { type: "generic", risk_tier: "low", payload: { title: "t", detail: "d" } },
    });
    q.setAttestationResolved(db, created.attestation_id, "denied", null);

    const client = await connectedClient(db);
    const started = Date.now();
    const result = await client.callTool({
      name: "wait_for_approval",
      arguments: { attestation_id: created.attestation_id, timeout_seconds: 5 },
    });
    expect(Date.now() - started).toBeLessThan(1000);

    const structured = result.structuredContent as { status: string; timed_out: boolean };
    expect(structured.status).toBe("denied");
    expect(structured.timed_out).toBe(false);
  });

  it("times out with status still pending when nobody decides in time", async () => {
    const created = createAttestation(db, noopEmail, "http://localhost:3000", {
      requested_by: "agent-7", approver_ids: ["prin_1"],
      action: { type: "generic", risk_tier: "low", payload: { title: "t", detail: "d" } },
    });

    const client = await connectedClient(db);
    const result = await client.callTool({
      name: "wait_for_approval",
      arguments: { attestation_id: created.attestation_id, timeout_seconds: 1 },
    });

    const structured = result.structuredContent as { status: string; timed_out: boolean };
    expect(structured.status).toBe("pending");
    expect(structured.timed_out).toBe(true);
  }, 8000);

  it("picks up a decision recorded while it was waiting", async () => {
    const created = createAttestation(db, noopEmail, "http://localhost:3000", {
      requested_by: "agent-7", approver_ids: ["prin_1"],
      action: { type: "generic", risk_tier: "low", payload: { title: "t", detail: "d" } },
    });

    const client = await connectedClient(db);
    setTimeout(() => {
      q.setAttestationResolved(db, created.attestation_id, "approved", "tok_fake");
    }, 1200);

    const result = await client.callTool({
      name: "wait_for_approval",
      arguments: { attestation_id: created.attestation_id, timeout_seconds: 5 },
    });
    const structured = result.structuredContent as { status: string; token: string | null; timed_out: boolean };
    expect(structured.status).toBe("approved");
    expect(structured.token).toBe("tok_fake");
    expect(structured.timed_out).toBe(false);
  }, 8000);

  it("returns a tool error for an unknown attestation id, without waiting", async () => {
    const client = await connectedClient(db);
    const started = Date.now();
    const result = await client.callTool({
      name: "wait_for_approval",
      arguments: { attestation_id: "att_nope", timeout_seconds: 5 },
    });
    expect(Date.now() - started).toBeLessThan(500);
    expect(result.isError).toBe(true);
  });
});
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `npx vitest run src/mcp/server.test.ts`
Expected: FAIL — `wait_for_approval` tool not found (4 new failures).

- [ ] **Step 3: Add `wait_for_approval` to `src/mcp/server.ts`**

Add near the top of the file, alongside the other module-level constants:

```ts
const WAIT_DEFAULT_SECONDS = 300;
const WAIT_MAX_SECONDS = 3600;
const WAIT_POLL_MS = 1000;
```

Register the tool inside `buildMcpServer`, after `request_approval`:

```ts
  server.registerTool(
    "wait_for_approval",
    {
      title: "Wait for approval",
      description:
        "Polls until the attestation resolves (approved/denied/expired) or the " +
        "timeout elapses, whichever comes first. Prefer this over repeatedly " +
        "calling check_approval yourself.",
      inputSchema: {
        attestation_id: z.string(),
        timeout_seconds: z.number().int().min(1).max(WAIT_MAX_SECONDS).optional()
          .describe(`Defaults to ${WAIT_DEFAULT_SECONDS}. Capped at ${WAIT_MAX_SECONDS}.`),
      },
    },
    async (args) => {
      const timeoutMs = (args.timeout_seconds ?? WAIT_DEFAULT_SECONDS) * 1000;
      const deadline = Date.now() + timeoutMs;

      let view;
      try {
        view = getAttestationView(ctx.db, args.attestation_id);
        while (view.status === "pending" && Date.now() < deadline) {
          await new Promise((resolve) => setTimeout(resolve, WAIT_POLL_MS));
          view = getAttestationView(ctx.db, args.attestation_id);
        }
      } catch (err) {
        if (err instanceof FailClosedError) return toolError(err.message);
        throw err;
      }

      const timedOut = view.status === "pending";
      return {
        content: [{
          type: "text" as const,
          text: timedOut
            ? "Timed out while still pending."
            : `Resolved: ${view.status}.`,
        }],
        structuredContent: { status: view.status, token: view.token, timed_out: timedOut },
      };
    },
  );
```

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `npx vitest run src/mcp/server.test.ts`
Expected: PASS (12 tests total). The timeout and "picks up a decision while waiting" tests take a couple of real seconds each — that's expected, not a hang.

- [ ] **Step 5: Commit**

```bash
git add src/mcp/server.ts src/mcp/server.test.ts
git commit -m "feat(mcp): wait_for_approval tool with a bounded server-side poll"
```

---

### Task 5: Mount `/mcp` on the Fastify app

**Files:**
- Create: `src/mcp/routes.ts`
- Modify: `src/api/server.ts`
- Test: `src/mcp/routes.test.ts`

**Interfaces:**
- Consumes: `buildMcpServer` (Task 2/3/4)
- Produces: `registerMcpRoutes(app: FastifyInstance & { ctx: AppContext }): Promise<void>`

- [ ] **Step 1: Write the failing test**

```ts
// src/mcp/routes.test.ts
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { buildServer } from "../api/server.js";
import * as q from "../db/queries.js";

let app: Awaited<ReturnType<typeof buildServer>>;
let baseUrl: string;

beforeAll(async () => {
  app = await buildServer({ dbPath: ":memory:", email: { async send() {} } });
  await app.listen({ port: 0, host: "127.0.0.1" });
  const address = app.server.address();
  const port = typeof address === "object" && address ? address.port : 0;
  baseUrl = `http://127.0.0.1:${port}`;
});

afterAll(async () => {
  await app.close();
});

async function connectRealClient() {
  const client = new Client({ name: "test-client", version: "1.0.0" });
  const transport = new StreamableHTTPClientTransport(new URL(`${baseUrl}/mcp`));
  await client.connect(transport);
  return client;
}

describe("POST /mcp over a real HTTP server", () => {
  it("lists the three tools through a real Streamable HTTP round trip", async () => {
    const client = await connectRealClient();
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual(
      ["check_approval", "request_approval", "wait_for_approval"].sort(),
    );
  });

  it("calling request_approval over real HTTP actually creates a real attestation", async () => {
    q.insertPrincipal(app.ctx.db, { id: "prin_http", email: "http@e.com", display_name: "Http" });
    const client = await connectRealClient();
    const result = await client.callTool({
      name: "request_approval",
      arguments: {
        type: "generic", risk_tier: "low", payload: { title: "t", detail: "d" },
        approver_emails: ["http@e.com"],
      },
    });
    const structured = result.structuredContent as { attestation_id: string };
    expect(q.getAttestation(app.ctx.db, structured.attestation_id)).toBeDefined();
  });
});

describe("GET /mcp", () => {
  it("returns 405, since this server runs stateless with no SSE stream to attach to", async () => {
    const res = await fetch(`${baseUrl}/mcp`, { headers: { accept: "text/event-stream" } });
    expect(res.status).toBe(405);
  });
});
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `npx vitest run src/mcp/routes.test.ts`
Expected: FAIL — `/mcp` 404s (no such route yet).

- [ ] **Step 3: Write `src/mcp/routes.ts`**

**Corrected after Task 5's implementer drove real, sequential HTTP requests
against a live server**: the installed SDK does *not* allow one
`StreamableHTTPServerTransport` built in stateless mode to be reused across
requests — its `handleRequest` throws `"Stateless transport cannot be reused
across requests. Create a new transport per request."` on the second call
(`webStandardStreamableHttp.js`'s `_hasHandledRequest` guard), confirmed
directly against the installed package. A shared-instance implementation (as
originally written below) 500s on every request after the first. The fix —
build a fresh `McpServer`/transport pair per request — is the SDK's own
documented pattern for stateless mode, and preserves this task's actual
design intent (D2: no session id, no session map, no session-affinity
requirement) exactly; only the "build once, reuse" implementation detail was
wrong. Use this version:

```ts
import type { FastifyInstance } from "fastify";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { buildMcpServer } from "./server.js";
import type { AppContext } from "../api/server.js";

/**
 * Stateless mode (design doc D2): no session id, no in-memory session map
 * that could grow unbounded if a client disconnects without an explicit
 * close, and no session affinity requirement if this app is ever run behind
 * a load balancer.
 *
 * A fresh McpServer + transport is built for every request rather than one
 * shared pair built once at registration -- the installed SDK enforces this
 * in stateless mode (see the note above); building fresh instances per
 * request is its own documented pattern, not a workaround.
 */
export async function registerMcpRoutes(app: FastifyInstance & { ctx: AppContext }): Promise<void> {
  app.post("/mcp", async (req, reply) => {
    const mcpServer = buildMcpServer({ db: app.ctx.db, email: app.ctx.email, baseUrl: app.ctx.baseUrl });
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });

    // Hand the raw Node request/response to the transport and tell Fastify
    // not to touch the response itself -- the transport ends it directly
    // (streamableHttp.d.ts's handleRequest signature is built for exactly
    // this: Node's IncomingMessage/ServerResponse, with an optional
    // pre-parsed body, which req.body already is thanks to server.ts's own
    // preValidation hook normalizing it upstream of every route).
    reply.hijack();
    reply.raw.on("close", () => {
      void transport.close();
      void mcpServer.close();
    });

    await mcpServer.connect(transport);
    await transport.handleRequest(req.raw, reply.raw, req.body);
  });

  // The Streamable HTTP spec's GET is for a standalone server-initiated SSE
  // stream, which only exists in stateful (session-tracking) mode. This
  // server never issues a session id, so there is nothing for a GET to
  // attach to -- 405 says that plainly instead of the transport failing in
  // some less legible way.
  app.get("/mcp", async (_req, reply) => {
    return reply.status(405).send({
      error: "method_not_allowed",
      message: "GET /mcp is not supported; this server runs stateless with no SSE stream to attach to",
    });
  });
}
```

- [ ] **Step 4: Register it in `src/api/server.ts`**

Add the import near the other route registrations:

```ts
import { registerMcpRoutes } from "../mcp/routes.js";
```

And near the bottom of `buildServer`, alongside the other `register*Routes(app)` calls:

```ts
  registerPrincipalRoutes(app);
  registerAttestationRoutes(app);
  registerVerifyRoutes(app);
  registerWebSessionRoutes(app);
  registerWebRequestRoutes(app);
  registerHealthRoutes(app);
  await registerMcpRoutes(app);
```

(`registerMcpRoutes` is `async` for signature consistency with the other `register*Routes` functions and to leave room for future setup that needs to await something at registration time — its body has no top-level `await` itself now that `mcpServer.connect(transport)` moved inside the per-request handler, per the correction above. `buildServer` itself is already `async` and already awaits several `app.register(...)` calls above this point, so `await registerMcpRoutes(app)` is consistent with the file's existing style regardless.)

- [ ] **Step 5: Run the tests and confirm they pass**

Run: `npx vitest run src/mcp/routes.test.ts`
Expected: PASS (3 tests)

- [ ] **Step 6: Run the full suite and typecheck**

Run: `npx tsc --noEmit && npm test`
Expected: clean typecheck, all tests passing.

- [ ] **Step 7: Commit**

```bash
git add src/mcp/routes.ts src/mcp/routes.test.ts src/api/server.ts
git commit -m "feat(mcp): mount /mcp on the Fastify app via stateless Streamable HTTP"
```

---

### Task 6: Security regression through the MCP entrypoint

The spec's §6 requires proving the closed-world action schema and the
"agent never controls display text" invariant still hold when reached
through `/mcp`, not just through `/v1/attestations`. Task 3's tests already
cover the schema-rejection case at the unit level; this task adds an
end-to-end, real-HTTP proof plus an approver-isolation check.

**Files:**
- Create: `tests/security/mcp-entrypoint.test.ts`

- [ ] **Step 1: Write the tests**

```ts
// tests/security/mcp-entrypoint.test.ts
//
// The MCP server (src/mcp/server.ts) calls the exact same createAttestation
// used by POST /v1/attestations (src/api/attestations-core.ts) -- Task 1 of
// docs/superpowers/plans/2026-08-01-mcp-server.md extracted it precisely so
// the two entrypoints cannot drift. This suite proves that holds for real,
// over a real HTTP round trip, rather than trusting the shared-function
// claim on its own.
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { buildServer } from "../../src/api/server.js";
import * as q from "../../src/db/queries.js";

let app: Awaited<ReturnType<typeof buildServer>>;
let baseUrl: string;

beforeAll(async () => {
  app = await buildServer({ dbPath: ":memory:", email: { async send() {} } });
  await app.listen({ port: 0, host: "127.0.0.1" });
  const address = app.server.address();
  const port = typeof address === "object" && address ? address.port : 0;
  baseUrl = `http://127.0.0.1:${port}`;
});

afterAll(async () => {
  await app.close();
});

async function client() {
  const c = new Client({ name: "attack-client", version: "1.0.0" });
  await c.connect(new StreamableHTTPClientTransport(new URL(`${baseUrl}/mcp`)));
  return c;
}

describe("attack: smuggle display text through request_approval", () => {
  it("a caller-supplied field outside the action type's schema is refused, over real HTTP", async () => {
    q.insertPrincipal(app.ctx.db, { id: "prin_mcp1", email: "mcp1@e.com", display_name: "One" });
    const c = await client();

    const result = await c.callTool({
      name: "request_approval",
      arguments: {
        type: "wire_transfer", risk_tier: "high",
        payload: {
          amount: 100, currency: "USD", recipient_name: "Real Corp", account_last4: "0000",
          // Not part of wire_transfer's schema -- the attack this proves closed.
          headline: "Totally safe $1 refund",
        },
        approver_emails: ["mcp1@e.com"],
      },
    });

    expect(result.isError).toBe(true);
  });

  it("the rendered summary always comes from the canonical payload, never a caller-supplied string", async () => {
    q.insertPrincipal(app.ctx.db, { id: "prin_mcp2", email: "mcp2@e.com", display_name: "Two" });
    const c = await client();

    const result = await c.callTool({
      name: "request_approval",
      arguments: {
        type: "wire_transfer", risk_tier: "high",
        payload: { amount: 999999900, currency: "USD", recipient_name: "Attacker LLC", account_last4: "6666" },
        approver_emails: ["mcp2@e.com"],
      },
    });

    const structured = result.structuredContent as { summary: { headline: string } };
    // The headline is deterministically derived from amount/currency/recipient
    // by src/actions/render.ts -- proving it reflects the real payload, not
    // anything else the tool call could have smuggled in.
    expect(structured.summary.headline).toBe("Wire $9,999,999.00 USD to Attacker LLC");
  });
});

describe("attack: enumerate registered approvers via request_approval", () => {
  it("does not create an attestation, or reveal anything beyond rejection, for an unenrolled email", async () => {
    const c = await client();
    const before = (app.ctx.db.prepare("SELECT COUNT(*) AS c FROM attestations").get() as { c: number }).c;

    const result = await c.callTool({
      name: "request_approval",
      arguments: {
        type: "generic", risk_tier: "low", payload: { title: "t", detail: "d" },
        approver_emails: ["definitely-not-registered@nowhere.test"],
      },
    });

    expect(result.isError).toBe(true);
    const after = (app.ctx.db.prepare("SELECT COUNT(*) AS c FROM attestations").get() as { c: number }).c;
    expect(after).toBe(before);
  });
});

describe("check_approval / wait_for_approval never leak a purged payload", () => {
  it("summary is null through check_approval once an attestation resolves, same as GET /v1/attestations/:id", async () => {
    q.insertPrincipal(app.ctx.db, { id: "prin_mcp3", email: "mcp3@e.com", display_name: "Three" });
    const c = await client();

    const created = await c.callTool({
      name: "request_approval",
      arguments: {
        type: "generic", risk_tier: "low", payload: { title: "ZZQQX-SENTINEL", detail: "d" },
        approver_emails: ["mcp3@e.com"],
      },
    });
    const { attestation_id } = created.structuredContent as { attestation_id: string };

    q.setAttestationResolved(app.ctx.db, attestation_id, "denied", null);
    q.purgeActionPayload(app.ctx.db, q.getAttestation(app.ctx.db, attestation_id)!.action_id);

    const checked = await c.callTool({ name: "check_approval", arguments: { attestation_id } });
    const view = checked.structuredContent as { summary: unknown };
    expect(view.summary).toBeNull();
    expect(JSON.stringify(checked)).not.toContain("ZZQQX-SENTINEL");
  });
});
```

- [ ] **Step 2: Run it and confirm it fails initially, then passes**

Run: `npx vitest run tests/security/mcp-entrypoint.test.ts`
Expected: all 4 tests PASS immediately, since Tasks 1-5 already implement the behavior being proven here. This task exists to pin the property down as a named, standalone security test — not to drive new implementation. If any test fails, that is a real regression in Tasks 1-5; fix the implementation, not this test.

- [ ] **Step 3: Commit**

```bash
git add tests/security/mcp-entrypoint.test.ts
git commit -m "test(security): prove the MCP entrypoint inherits every REST-path guarantee"
```

---

### Task 7: End-to-end test — the full loop through a real MCP client

**Files:**
- Create: `tests/e2e/mcp-approval.spec.ts`
- Modify: `tests/e2e/fixtures.ts`

**Interfaces:**
- Consumes: `waitForApprovalLink`, `clickDecision` (`tests/e2e/fixtures.ts`, existing)
- Produces: `callMcpTool(baseUrl, name, args)` helper in `fixtures.ts`, for use by this spec

- [ ] **Step 1: Add an MCP client helper to `tests/e2e/fixtures.ts`**

Add near the top, with the other imports:

```ts
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
```

Add this export:

```ts
/**
 * A real MCP client, talking Streamable HTTP to the real running e2e server
 * -- the same wire protocol any MCP-compatible agent framework would use.
 */
export async function mcpClient(baseUrl: string): Promise<Client> {
  const client = new Client({ name: "e2e-test-client", version: "1.0.0" });
  await client.connect(new StreamableHTTPClientTransport(new URL(`${baseUrl}/mcp`)));
  return client;
}
```

- [ ] **Step 2: Write `tests/e2e/mcp-approval.spec.ts`**

```ts
import { test, expect } from "@playwright/test";
import {
  withVirtualAuthenticator, createPrincipal, enrolPasskey, waitForApprovalLink,
  clickDecision, mcpClient,
} from "./fixtures.js";

const BASE = "http://localhost:3000";

// The loop this whole feature exists to prove: an MCP client (standing in
// for Claude, LangGraph, or any other agent framework) calls request_approval,
// a real human approves via the real emailed link and the real SPA, and
// wait_for_approval -- called by the SAME MCP client, over the SAME
// connection -- returns the resulting verified token. Nothing here is
// mocked: the MCP tool call is real Streamable HTTP, the email is a real
// .eml written to disk, and the approval is a real WebAuthn ceremony against
// the virtual authenticator.
test("an MCP client requests approval, a human approves via email, and wait_for_approval returns a verified token", async ({ page }) => {
  await withVirtualAuthenticator(page);
  const email = `e2e-mcp-${Date.now()}@test.local`;
  const { principalId, enrolmentToken } = await createPrincipal(BASE, email);
  await enrolPasskey(page, principalId, enrolmentToken);

  const client = await mcpClient(BASE);

  const created = await client.callTool({
    name: "request_approval",
    arguments: {
      type: "wire_transfer", risk_tier: "high",
      payload: { amount: 2500000, currency: "USD", recipient_name: "Acme Corp", account_last4: "4821" },
      approver_emails: [email],
      requested_by: "e2e-mcp-agent",
    },
  });
  expect(created.isError).not.toBe(true);
  const { attestation_id } = created.structuredContent as { attestation_id: string };

  // A human approves via the real emailed link, exactly as in flow.spec.ts.
  await page.goto(await waitForApprovalLink(email));
  await clickDecision(page, "Approve with passkey");
  await expect(page.locator(".pill")).toHaveText("Approved");

  // The SAME MCP client that requested it learns the outcome.
  const waited = await client.callTool({
    name: "wait_for_approval",
    arguments: { attestation_id, timeout_seconds: 10 },
  });
  const result = waited.structuredContent as { status: string; token: string; timed_out: boolean };
  expect(result.status).toBe("approved");
  expect(result.timed_out).toBe(false);
  expect(result.token).toBeTruthy();

  // Verify it the same way any receiving system would: against the real
  // published JWKS, over the real REST API.
  const verified = await fetch(`${BASE}/v1/attestations/verify`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ token: result.token }),
  }).then((r) => r.json());
  expect(verified.valid).toBe(true);
  expect(verified.principal_id).toBe(principalId);
});

test("wait_for_approval reports timed_out: true, and a subsequent check_approval still shows pending, when nobody decides", async () => {
  const email = `e2e-mcp-timeout-${Date.now()}@test.local`;
  const { principalId } = await createPrincipal(BASE, email);

  const client = await mcpClient(BASE);
  const created = await client.callTool({
    name: "request_approval",
    arguments: {
      type: "generic", risk_tier: "low", payload: { title: "Never decided", detail: "d" },
      approver_emails: [email],
    },
  });
  const { attestation_id } = created.structuredContent as { attestation_id: string };

  const waited = await client.callTool({
    name: "wait_for_approval",
    arguments: { attestation_id, timeout_seconds: 1 },
  });
  const result = waited.structuredContent as { status: string; timed_out: boolean };
  expect(result.timed_out).toBe(true);
  expect(result.status).toBe("pending");

  const checked = await client.callTool({ name: "check_approval", arguments: { attestation_id } });
  expect((checked.structuredContent as { status: string }).status).toBe("pending");
});
```

- [ ] **Step 3: Run it**

Run: `npm run build:web && npm run e2e -- tests/e2e/mcp-approval.spec.ts`
Expected: 2 passed.

- [ ] **Step 4: Run the full e2e suite three times to check for flakiness**

Run: `npm run e2e` (three times in a row)
Expected: all specs pass, all three runs, matching the standard this project already holds itself to (the email-link rework's e2e suite required this same three-clean-runs bar before being trusted).

- [ ] **Step 5: Commit**

```bash
git add tests/e2e/mcp-approval.spec.ts tests/e2e/fixtures.ts
git commit -m "test(e2e): full MCP request_approval -> real email approval -> wait_for_approval loop"
```

---

### Task 8: Reference client script and docs

**Files:**
- Create: `demo/mcp-agent.ts`
- Modify: `README.md`, `docs/api/reference.md`, `package.json`

**Interfaces:**
- Consumes: `@modelcontextprotocol/sdk`'s `Client`/`StreamableHTTPClientTransport`, the real running server from `npm run dev`

- [ ] **Step 1: Write `demo/mcp-agent.ts`**

**Corrected after Task 8's review**: the original version of this file
omitted the `action_hash`/`payload_hash` comparison `demo/agent.ts:41`
performs before trusting a token — checking only `!verified.valid`, never
that the verified token actually names *this* action. That defeats the
entire point of a reference client whose stated purpose is proving the
correct verification pattern to integrators: a token issued for a different
action would still "verify," and the demo would wrongly print "Verified.
Executing wire transfer." The version below captures `payload_hash` from
`request_approval`'s response and checks it against `verify`'s
`action_hash`, exactly like `demo/agent.ts` already does — this is not a new
requirement, it is restoring a check the sibling reference client already
has correctly.

```ts
// The MCP equivalent of demo/agent.ts: a minimal, real reference client
// showing how an MCP-compatible agent framework would call this service --
// request_approval, then wait_for_approval, then verify the token before
// "executing" anything. Requires the real server running (`npm run dev`)
// and a principal with an enrolled passkey (see README.md).
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const BASE = "http://localhost:3000";

async function main(): Promise<void> {
  const approverEmail = process.argv[2];
  if (!approverEmail) throw new Error("usage: npm run demo:mcp -- <approver_email>");

  const client = new Client({ name: "demo-mcp-agent", version: "1.0.0" });
  await client.connect(new StreamableHTTPClientTransport(new URL(`${BASE}/mcp`)));

  console.log("Requesting approval via MCP...");
  const created = await client.callTool({
    name: "request_approval",
    arguments: {
      type: "wire_transfer", risk_tier: "high",
      payload: { amount: 2500000, currency: "USD", recipient_name: "Acme Corp", account_last4: "4821" },
      approver_emails: [approverEmail],
      requested_by: "demo-mcp-agent",
    },
  });
  if (created.isError) {
    console.error("request_approval failed:", created.content);
    process.exit(1);
  }
  const requested = created.structuredContent as {
    attestation_id: string; payload_hash: string; summary: { headline: string };
  };
  console.log(`  ${requested.summary.headline}`);
  console.log(`  An approval email has been sent to ${approverEmail}. Waiting for a decision (up to 15 minutes)...\n`);

  const waited = await client.callTool({
    name: "wait_for_approval",
    arguments: { attestation_id: requested.attestation_id, timeout_seconds: 900 },
  });
  const result = waited.structuredContent as { status: string; token: string | null; timed_out: boolean };

  if (result.timed_out) {
    console.log("Timed out waiting for a decision.");
    return;
  }
  if (result.status !== "approved") {
    console.log(`Refusing to execute: attestation ${result.status}.`);
    return;
  }

  const verified = await fetch(`${BASE}/v1/attestations/verify`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ token: result.token }),
  }).then((r) => r.json());

  if (!verified.valid || verified.action_hash !== requested.payload_hash) {
    console.log("Refusing to execute: token did not verify against this action.");
    return;
  }
  console.log("Verified. Executing wire transfer.");
}

await main();
export {};
```

- [ ] **Step 2: Add the npm script**

In `package.json`'s `"scripts"`, alongside the existing `"demo"` entry:

```json
"demo:mcp": "tsx demo/mcp-agent.ts"
```

- [ ] **Step 3: Manually verify it against the real dev server**

```bash
npm run build:web
npm run dev &
sleep 2
curl -s -X POST http://localhost:3000/v1/principals \
  -H 'content-type: application/json' \
  -d '{"email":"mcp-demo@example.com","display_name":"MCP Demo"}'
```

Enrol a passkey at the printed link (or the `.eml` in `mail/`), then in another terminal:

```bash
npm run demo:mcp -- mcp-demo@example.com
```

Approve at the printed/emailed link within the 15-minute window; confirm the script prints `Verified. Executing wire transfer.` Stop the dev server afterward (`kill %1` or Ctrl-C the backgrounded job).

- [ ] **Step 4: Document `/mcp` in `docs/api/reference.md`**

Add a new top-level section after the `## Browser API (/web/*)` section (before `## Error codes`):

```markdown
## MCP server (`/mcp`)

A Model Context Protocol server, mounted at `/mcp` on this same app, exposing
three tools for any MCP-compatible client (Claude, LangGraph, or anything
else speaking MCP). Stateless Streamable HTTP transport -- no session
tracking, no `Mcp-Session-Id` header, `GET /mcp` returns `405`.

Every tool call routes through the exact same validation, hashing,
rendering, and email-delivery logic `POST /v1/attestations` and
`GET /v1/attestations/:id` use (`src/api/attestations-core.ts`) -- the MCP
layer adds a protocol adapter, never a second implementation of anything
security-relevant. In particular, `request_approval`'s `payload` is
validated by the exact same closed-world per-type schema as the REST API:
there is no free-text display field, because what the approver sees is
always rendered server-side from this same structured payload.

### `request_approval`

| Input | Type | Notes |
|---|---|---|
| `type` | `"wire_transfer" \| "send_email" \| "sign_document" \| "generic"` | Same four types as `POST /v1/attestations`. Use `generic` (`{title, detail}`) for anything else. |
| `risk_tier` | `"low" \| "medium" \| "high" \| "critical"` | |
| `payload` | object | Fields required depend on `type` -- see `POST /v1/attestations` above. |
| `approver_emails` | `string[]`, min 1 | Resolved server-side to enrolled `principal_id`s. An address with no enrolled principal is rejected and creates nothing. |
| `requested_by` | `string`, optional | Defaults to the connecting MCP client's declared name, then `"mcp-client"`. |
| `required_approvals` | `number`, optional | Defaults to 1. |
| `ttl_seconds` | `number`, optional | Defaults to 900. |

Returns the same shape as `POST /v1/attestations`'s response body, as
`structuredContent`.

### `check_approval`

`{ attestation_id: string }` → the same shape `GET /v1/attestations/:id`
returns, as `structuredContent`. `summary` is `null` once the attestation
resolves, for the same reason it is on the REST endpoint -- the payload is
purged.

### `wait_for_approval`

`{ attestation_id: string, timeout_seconds?: number }` (default 300, max
3600) → `{ status, token, timed_out }`. Polls server-side every second.
`timed_out: true` with `status: "pending"` is a normal, non-error result --
call it again, or fall back to `check_approval` later.

Not an MCP tool for this pass: independent, offline verification of a
returned `token` still goes through `POST /v1/attestations/verify` or the
JWKS path directly -- see the [quickstart](../integration/quickstart.md).
```

- [ ] **Step 5: Add a short section to `README.md`**

After the existing "Run the demo agent" section, add:

```markdown
## Call it from an MCP client

The same server also speaks [MCP](https://modelcontextprotocol.io) at
`/mcp` -- `request_approval`, `check_approval`, `wait_for_approval`. Any
MCP-compatible agent framework can point at `http://localhost:3000/mcp`
directly; see `docs/api/reference.md`'s MCP section for the tool schemas, or
run the reference client:

```bash
npm run demo:mcp -- <approver_email>
```
```

- [ ] **Step 6: Run everything once more**

```bash
npx tsc --noEmit
npm test
npm run build:web
npm run e2e
```

Expected: clean typecheck, all unit/integration/security tests passing, e2e
suite passing. Paste the real output for each — do not summarize without
having run them.

- [ ] **Step 7: Commit**

```bash
git add demo/mcp-agent.ts package.json README.md docs/api/reference.md
git commit -m "docs: document /mcp and add a reference MCP client script"
```

---

## Post-completion addendum (final whole-branch review)

All 8 tasks above executed and passed their individual reviews exactly as
written — including every `toolError(message: string)` call site in Tasks
2-4 (lines ~451, 475, 678, 702, 860). The final whole-branch review, which
looks across tasks rather than within one, found this was nonetheless a real
gap: `toolError` never audits, and design doc §5's claim that MCP rejections
are audited "directly via the same throw sites" was never true anywhere in
this codebase — there is exactly one audit choke point (`server.ts`'s
central `setErrorHandler`), and a caught-and-returned tool error never
reaches it. Every task-scoped review was correct in isolation; none could
have seen this, since it's a property of comparing `/v1/*` and `/mcp`
side-by-side, not of either surface alone. Fixed in a single post-completion
commit (see repo history after `7ba15e8`), not by rewriting the tasks above:
`toolError` now takes `db` and writes a `q.audit(...)` row before returning,
matching the REST path's event naming. The design spec (§5) was corrected
alongside it. This addendum exists so a future reader of this plan's task
text sees the accurate final state rather than inheriting the same gap by
copying an old `toolError(message)` call site verbatim.

## Self-Review

**Spec coverage:** §2 D1→Task 5, D2→Task 5, D3→Task 1, D4→Task 3 (and re-proven in Task 6), D5→Task 3, D6→Task 3, D7→Task 4, D8→ (deliberately absent, per spec), D9→Task 5 (no auth added). §3 architecture→Tasks 1,2,5. §4 tool schemas→Tasks 2,3,4. §5 error handling→every tool handler's `toolError`/rethrow pattern, Tasks 2-4. §6 testing table→Tasks 1 (unit), 2-4 (unit, in-memory), 5 (integration, real HTTP), 6 (security), 7 (e2e). §7 non-goals→respected throughout (no new action types, no auth, no verify tool, no resources/prompts).

**Placeholder scan:** none found — every step has real, complete code.

**Type consistency:** `CreateAttestationResult`/`AttestationView` defined once in Task 1, imported and used identically in Tasks 2-6 (never redefined). `McpContext` defined in Task 2, reused by Task 5's `registerMcpRoutes`. Tool names (`request_approval`, `check_approval`, `wait_for_approval`) consistent across every task, the spec, and the docs in Task 8.
