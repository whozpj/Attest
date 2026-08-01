# Email-Link Web UI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace Web Push / PWA / iOS delivery with email links to a real React web UI where approvers decide with their passkey and browse their request history.

**Architecture:** Fastify keeps its existing `/v1/*` agent API untouched and gains a `/web/*` browser API (cookie sessions + link tokens). A new `src/email/` module delivers approval and enrolment mail through a pluggable transport (SMTP in prod, `.eml` files on disk in dev/test). A Vite-built React SPA in `web/` is served at `/`. The WebAuthn challenge binding, server-side summary rendering, and ES256 token issuance are **not modified**.

**Tech Stack:** TypeScript, Fastify 5, better-sqlite3, `@simplewebauthn/server` + `/browser`, `jose`, `nodemailer` (new), React 19 + Vite 7 (new), Vitest, Playwright.

**Spec:** `docs/superpowers/specs/2026-08-01-email-link-web-ui-design.md` — read it before starting any task.

## Global Constraints

- **Never weaken the challenge binding.** `boundHash` in `src/webauthn/authentication.ts` stays `hash({ act, att, decision })`. No task modifies `src/webauthn/`, `src/crypto/`, or `src/actions/`.
- **Never render display text from caller input.** Email bodies are built from the `RenderedSummary` produced by `src/actions/render.ts`, never from a caller-supplied string.
- **Every rejection is a `FailClosedError`** with a typed code, thrown so `server.ts`'s central error handler writes the `audit_log` row. Never write an ad-hoc audit row at a throw site.
- **Anti-enumeration parity.** A rejection must not reveal whether an email, principal, or credential exists. Distinguish causes only via `withAuditDetail` (server-side only).
- **Email is best-effort.** Sending must never throw into, or add latency to, `POST /v1/attestations`. Fire-and-forget, exactly like today's `notifyApprovers`.
- **Payload purge is sacred.** Resolved attestations expose metadata only. No task may retain rendered payload text past resolution.
- **Never run `npm install` / `npm uninstall`.** Every dependency this plan
  needs is already installed and `build:web` is already in `package.json`
  (nodemailer 9, `@types/nodemailer`, vite 8, `@vitejs/plugin-react`, react 19,
  react-dom, `@types/react`, `@types/react-dom`, react-router-dom). Multiple
  workers share one working tree, and concurrent npm writes corrupt
  `package-lock.json`. Only worker D removes packages, and only in Task D1.
  Skip any install step written into a task below — it is already done.
- **Never `git add -A` or `git add .`.** Stage only the explicit paths your
  task owns. Other workers have uncommitted work in this same tree.
- Node 20+. ESM (`"type": "module"`) — all relative imports end in `.js`.
- Test runner: `npm test` (Vitest). E2E: `npm run e2e` (Playwright).
- `src/api/routes.web.ts` must stay under ~250 lines; split into `routes.web.session.ts` / `routes.web.requests.ts` if it grows past that.

## Ownership (no two workers write the same file)

| Worker | Files |
|---|---|
| **A** | `src/email/**` |
| **B** | `src/db/**`, `src/api/routes.web*.ts`, `src/api/routes.attestations.ts`, `src/api/routes.principals.ts`, `src/api/server.ts`, `src/config.ts`, `src/types.ts` |
| **C** | `web/**`, `demo/agent.ts` |
| **D** | deletions per spec §9, `Dockerfile`, `.github/**`, `docs/**`, `README.md`, `package.json` |
| **QA** | `tests/**` |

**B depends on A's interface only** (frozen below). **C depends on B's HTTP contract only** (frozen below). Neither reads the other's source.

### Frozen interface — `src/email/index.ts` (worker A produces, B consumes)

```ts
export interface EmailMessage { to: string; subject: string; text: string; html: string; }
export interface EmailTransport { send(msg: EmailMessage): Promise<void>; }
export interface EmailConfig { smtpUrl?: string; mailFrom: string; mailDir: string; }
export function loadTransport(cfg: EmailConfig): EmailTransport;
export function renderApprovalEmail(a: {
  to: string; headline: string; fields: Array<{ label: string; value: string }>;
  requestedBy: string; expiresAt: string; linkUrl: string;
}): EmailMessage;
export function renderEnrolmentEmail(a: {
  to: string; displayName: string; linkUrl: string;
}): EmailMessage;
```

### Frozen interface — `/web/*` HTTP contract (worker B produces, C consumes)

```
POST   /web/session/options  {email}                 -> WebAuthn PublicKeyCredentialRequestOptionsJSON
POST   /web/session          {email, response}       -> 204 + Set-Cookie: ha_session
DELETE /web/session                                  -> 204
GET    /web/me                                       -> {principal_id, email, display_name}
GET    /web/requests?status=&limit=&before=          -> {items: RequestListItem[], next_before: string|null}
GET    /web/requests/:id                             -> RequestDetail
GET    /web/link/:token                              -> {attestation_id, principal_id, email}

RequestListItem = { attestation_id, type, status, requested_by, created_at,
                    resolved_at: string|null, expires_at, payload_hash,
                    my_decision: "approve"|"deny"|null }
RequestDetail   = RequestListItem & {
                    required_approvals, approvals: number,
                    summary: RenderedSummary | null,   // null once purged
                    audit: Array<{event, actor, created_at}> }
```

---

## Workstream A — Email module

### Task A1: Transport interface + file transport

**Files:**
- Create: `src/email/transport.ts`, `src/email/file.ts`
- Test: `src/email/file.test.ts`

**Interfaces:**
- Consumes: nothing
- Produces: `EmailMessage`, `EmailTransport` (types), `createFileTransport(dir: string): EmailTransport`

- [ ] **Step 1: Write the failing test**

```ts
// src/email/file.test.ts
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createFileTransport } from "./file.js";

describe("file transport", () => {
  let dir: string;
  beforeEach(() => { dir = mkdtempSync(join(tmpdir(), "ha-mail-")); });
  afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

  it("writes one .eml file per message, containing headers and both bodies", async () => {
    const t = createFileTransport(dir);
    await t.send({ to: "a@example.com", subject: "Hi", text: "plain body", html: "<p>rich body</p>" });

    const files = readdirSync(dir).filter((f) => f.endsWith(".eml"));
    expect(files).toHaveLength(1);
    const contents = readFileSync(join(dir, files[0]), "utf8");
    expect(contents).toContain("To: a@example.com");
    expect(contents).toContain("Subject: Hi");
    expect(contents).toContain("plain body");
    expect(contents).toContain("<p>rich body</p>");
  });

  it("creates the directory if it does not exist", async () => {
    const nested = join(dir, "deep", "deeper");
    await createFileTransport(nested).send({ to: "b@e.com", subject: "S", text: "t", html: "<p>h</p>" });
    expect(readdirSync(nested).filter((f) => f.endsWith(".eml"))).toHaveLength(1);
  });

  it("does not overwrite when two messages are sent in the same millisecond", async () => {
    const t = createFileTransport(dir);
    await Promise.all([
      t.send({ to: "a@e.com", subject: "One", text: "1", html: "<p>1</p>" }),
      t.send({ to: "b@e.com", subject: "Two", text: "2", html: "<p>2</p>" }),
    ]);
    expect(readdirSync(dir).filter((f) => f.endsWith(".eml"))).toHaveLength(2);
  });
});
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `npx vitest run src/email/file.test.ts`
Expected: FAIL — cannot resolve `./file.js`.

- [ ] **Step 3: Write `src/email/transport.ts`**

```ts
export interface EmailMessage {
  to: string;
  subject: string;
  text: string;
  html: string;
}

export interface EmailTransport {
  send(msg: EmailMessage): Promise<void>;
}
```

- [ ] **Step 4: Write `src/email/file.ts`**

```ts
import { mkdirSync, writeFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { join } from "node:path";
import type { EmailMessage, EmailTransport } from "./transport.js";

/**
 * Writes each message to disk as an RFC-822-ish .eml instead of sending it.
 * This is what makes the whole notification path runnable and testable with
 * no SMTP account: the e2e suite reads these files, extracts the real link,
 * and drives the real approval flow. Deliberately not a no-op "null"
 * transport -- a channel you cannot observe is a channel you cannot test.
 *
 * The filename carries a UUID rather than only a timestamp because two
 * approvers on the same attestation are mailed in the same tick, and a
 * timestamp alone collides and silently drops one.
 */
export function createFileTransport(dir: string): EmailTransport {
  return {
    async send(msg: EmailMessage): Promise<void> {
      mkdirSync(dir, { recursive: true });
      const boundary = `----ha-${randomUUID()}`;
      const eml = [
        `Date: ${new Date().toUTCString()}`,
        `To: ${msg.to}`,
        `Subject: ${msg.subject}`,
        "MIME-Version: 1.0",
        `Content-Type: multipart/alternative; boundary="${boundary}"`,
        "",
        `--${boundary}`,
        'Content-Type: text/plain; charset="utf-8"',
        "",
        msg.text,
        "",
        `--${boundary}`,
        'Content-Type: text/html; charset="utf-8"',
        "",
        msg.html,
        "",
        `--${boundary}--`,
        "",
      ].join("\r\n");
      writeFileSync(join(dir, `${Date.now()}-${randomUUID()}.eml`), eml, "utf8");
    },
  };
}
```

- [ ] **Step 5: Run tests and confirm they pass**

Run: `npx vitest run src/email/file.test.ts`
Expected: PASS (3 tests)

- [ ] **Step 6: Commit**

```bash
git add src/email/transport.ts src/email/file.ts src/email/file.test.ts
git commit -m "feat(email): transport interface and file-backed transport"
```

---

### Task A2: Templates rendered from the canonical summary

**Files:**
- Create: `src/email/templates.ts`
- Test: `src/email/templates.test.ts`

**Interfaces:**
- Consumes: `EmailMessage` from Task A1
- Produces: `renderApprovalEmail`, `renderEnrolmentEmail` (signatures in the frozen interface above)

- [ ] **Step 1: Write the failing test**

```ts
// src/email/templates.test.ts
import { describe, it, expect } from "vitest";
import { renderApprovalEmail, renderEnrolmentEmail } from "./templates.js";

const base = {
  to: "approver@acme.com",
  headline: "Wire $25,000.00 USD to Acme Corp",
  fields: [
    { label: "Amount", value: "$25,000.00 USD" },
    { label: "Recipient", value: "Acme Corp" },
  ],
  requestedBy: "agent-platform-7",
  expiresAt: "2026-08-01T12:15:00.000Z",
  linkUrl: "http://localhost:3000/a/tok123",
};

describe("renderApprovalEmail", () => {
  it("puts the server-rendered headline in the subject and both bodies", () => {
    const msg = renderApprovalEmail(base);
    expect(msg.to).toBe("approver@acme.com");
    expect(msg.subject).toContain("Wire $25,000.00 USD to Acme Corp");
    expect(msg.text).toContain("Wire $25,000.00 USD to Acme Corp");
    expect(msg.html).toContain("Wire $25,000.00 USD to Acme Corp");
  });

  it("includes every rendered field and the link in both bodies", () => {
    const msg = renderApprovalEmail(base);
    for (const body of [msg.text, msg.html]) {
      expect(body).toContain("Amount");
      expect(body).toContain("$25,000.00 USD");
      expect(body).toContain("Recipient");
      expect(body).toContain("Acme Corp");
      expect(body).toContain("http://localhost:3000/a/tok123");
    }
  });

  it("escapes HTML in rendered values so a payload string cannot inject markup", () => {
    const msg = renderApprovalEmail({
      ...base,
      headline: 'Send email to <script>alert(1)</script>',
      fields: [{ label: "To", value: '"><img src=x onerror=alert(1)>' }],
    });
    expect(msg.html).not.toContain("<script>");
    expect(msg.html).not.toContain("<img src=x");
    expect(msg.html).toContain("&lt;script&gt;");
  });

  it("states that a passkey is required, so the link alone reads as non-authorizing", () => {
    expect(renderApprovalEmail(base).text.toLowerCase()).toContain("passkey");
  });
});

describe("renderEnrolmentEmail", () => {
  it("addresses the principal and carries the enrolment link", () => {
    const msg = renderEnrolmentEmail({
      to: "new@acme.com", displayName: "New User",
      linkUrl: "http://localhost:3000/enrol?principal=prin_1&token=abc",
    });
    expect(msg.to).toBe("new@acme.com");
    expect(msg.text).toContain("New User");
    expect(msg.text).toContain("http://localhost:3000/enrol?principal=prin_1&token=abc");
    expect(msg.html).toContain("http://localhost:3000/enrol?principal=prin_1&amp;token=abc");
  });

  it("escapes the display name", () => {
    const msg = renderEnrolmentEmail({
      to: "x@e.com", displayName: "<b>Bold</b>", linkUrl: "http://localhost:3000/enrol",
    });
    expect(msg.html).not.toContain("<b>Bold</b>");
    expect(msg.html).toContain("&lt;b&gt;Bold&lt;/b&gt;");
  });
});
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `npx vitest run src/email/templates.test.ts`
Expected: FAIL — cannot resolve `./templates.js`.

- [ ] **Step 3: Write `src/email/templates.ts`**

```ts
import type { EmailMessage } from "./transport.js";

/**
 * Every interpolated value in these templates originates from
 * src/actions/render.ts's RenderedSummary -- which is itself derived from the
 * canonicalized, hashed payload, never from caller-supplied display text.
 * That is the project's central invariant (design doc §1) extended to a new
 * output medium: the agent cannot control one character the human reads.
 *
 * Escaping is still mandatory. The invariant says the agent doesn't choose
 * the *template*; it does still choose payload *values* (a recipient name, an
 * email subject), and those land inside HTML. An unescaped `recipient_name`
 * of `<script>...` would execute in whatever mail client renders it.
 */
function esc(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

const SHELL = (title: string, inner: string) => `<!doctype html>
<html><body style="margin:0;padding:24px;background:#f6f7f9;font-family:system-ui,-apple-system,'Segoe UI',sans-serif;color:#111827">
<div style="max-width:520px;margin:0 auto;background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:28px">
<div style="font-weight:650;font-size:15px;margin-bottom:18px">Human-Attest</div>
<h1 style="font-size:19px;line-height:1.35;margin:0 0 6px">${title}</h1>
${inner}
</div></body></html>`;

const BUTTON = (url: string, label: string) =>
  `<a href="${esc(url)}" style="display:inline-block;background:#4f46e5;color:#fff;text-decoration:none;padding:11px 20px;border-radius:7px;font-weight:600;font-size:14px">${esc(label)}</a>`;

export function renderApprovalEmail(a: {
  to: string;
  headline: string;
  fields: Array<{ label: string; value: string }>;
  requestedBy: string;
  expiresAt: string;
  linkUrl: string;
}): EmailMessage {
  const rows = a.fields
    .map(
      (f) =>
        `<tr><td style="padding:5px 16px 5px 0;color:#6b7280;font-size:13px">${esc(f.label)}</td>` +
        `<td style="padding:5px 0;font-size:13px;font-weight:550">${esc(f.value)}</td></tr>`,
    )
    .join("");

  const text = [
    a.headline,
    "",
    `Requested by ${a.requestedBy}.`,
    `Expires ${a.expiresAt}.`,
    "",
    ...a.fields.map((f) => `${f.label}: ${f.value}`),
    "",
    `Review this request: ${a.linkUrl}`,
    "",
    "You will confirm with your passkey. This link on its own cannot approve",
    "or deny anything -- only your authenticator can.",
  ].join("\n");

  const html = SHELL(
    esc(a.headline),
    `<p style="color:#6b7280;font-size:13px;margin:0 0 16px">Requested by ${esc(a.requestedBy)} &middot; expires ${esc(a.expiresAt)}</p>
     <table style="border-collapse:collapse;margin:0 0 22px">${rows}</table>
     <div>${BUTTON(a.linkUrl, "Review request")}</div>
     <p style="color:#6b7280;font-size:12px;margin:18px 0 0">You will confirm with your passkey. This link on its own cannot approve or deny anything &mdash; only your authenticator can.</p>`,
  );

  return { to: a.to, subject: `Approval needed: ${a.headline}`, text, html };
}

export function renderEnrolmentEmail(a: {
  to: string;
  displayName: string;
  linkUrl: string;
}): EmailMessage {
  const text = [
    `Hello ${a.displayName},`,
    "",
    "Set up your passkey so you can approve requests:",
    a.linkUrl,
    "",
    "This link is single-use and expires in 15 minutes.",
  ].join("\n");

  const html = SHELL(
    "Set up your passkey",
    `<p style="font-size:14px;margin:0 0 16px">Hello ${esc(a.displayName)}, set up your passkey so you can approve requests.</p>
     <div>${BUTTON(a.linkUrl, "Enrol passkey")}</div>
     <p style="color:#6b7280;font-size:12px;margin:18px 0 0">This link is single-use and expires in 15 minutes.</p>`,
  );

  return { to: a.to, subject: "Set up your Human-Attest passkey", text, html };
}
```

- [ ] **Step 4: Run tests and confirm they pass**

Run: `npx vitest run src/email/templates.test.ts`
Expected: PASS (6 tests)

- [ ] **Step 5: Commit**

```bash
git add src/email/templates.ts src/email/templates.test.ts
git commit -m "feat(email): approval and enrolment templates rendered from canonical summaries"
```

---

### Task A3: SMTP transport + `loadTransport` selector

**Files:**
- Create: `src/email/smtp.ts`, `src/email/index.ts`
- Test: `src/email/index.test.ts`
- Modify: `package.json` — **do not edit directly**, run the install command in Step 3 (worker D owns this file; the lockfile update is fine, a manual edit would conflict)

**Interfaces:**
- Consumes: A1's `EmailTransport`, A2's renderers
- Produces: `loadTransport(cfg: EmailConfig): EmailTransport`, and re-exports of every symbol in the frozen interface

- [ ] **Step 1: Write the failing test**

```ts
// src/email/index.test.ts
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadTransport } from "./index.js";

describe("loadTransport", () => {
  let dir: string;
  beforeEach(() => { dir = mkdtempSync(join(tmpdir(), "ha-sel-")); });
  afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

  it("uses the file transport when no smtpUrl is configured", async () => {
    const t = loadTransport({ mailFrom: "no-reply@x", mailDir: dir });
    await t.send({ to: "a@e.com", subject: "S", text: "t", html: "<p>h</p>" });
    expect(readdirSync(dir).filter((f) => f.endsWith(".eml"))).toHaveLength(1);
  });

  it("uses the file transport when smtpUrl is an empty string", async () => {
    const t = loadTransport({ smtpUrl: "", mailFrom: "no-reply@x", mailDir: dir });
    await t.send({ to: "a@e.com", subject: "S", text: "t", html: "<p>h</p>" });
    expect(readdirSync(dir).filter((f) => f.endsWith(".eml"))).toHaveLength(1);
  });

  it("returns an SMTP transport when smtpUrl is set, without connecting at construction", () => {
    const t = loadTransport({
      smtpUrl: "smtp://user:pass@127.0.0.1:2525", mailFrom: "no-reply@x", mailDir: dir,
    });
    expect(typeof t.send).toBe("function");
    expect(readdirSync(dir).filter((f) => f.endsWith(".eml"))).toHaveLength(0);
  });
});
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `npx vitest run src/email/index.test.ts`
Expected: FAIL — cannot resolve `./index.js`.

- [ ] **Step 3: Install nodemailer**

```bash
npm install nodemailer && npm install --save-dev @types/nodemailer
```

- [ ] **Step 4: Write `src/email/smtp.ts`**

```ts
import { createTransport } from "nodemailer";
import type { EmailMessage, EmailTransport } from "./transport.js";

/**
 * Constructing the nodemailer transport does not open a connection -- it
 * resolves one lazily, per send. That matters because the server builds its
 * transport at boot: a mail host that is briefly unreachable must not stop
 * the API from starting, when the only thing it degrades is a best-effort
 * notification channel.
 */
export function createSmtpTransport(url: string, from: string): EmailTransport {
  const transport = createTransport(url);
  return {
    async send(msg: EmailMessage): Promise<void> {
      await transport.sendMail({
        from, to: msg.to, subject: msg.subject, text: msg.text, html: msg.html,
      });
    },
  };
}
```

- [ ] **Step 5: Write `src/email/index.ts`**

```ts
import { createFileTransport } from "./file.js";
import { createSmtpTransport } from "./smtp.js";
import type { EmailTransport } from "./transport.js";

export type { EmailMessage, EmailTransport } from "./transport.js";
export { renderApprovalEmail, renderEnrolmentEmail } from "./templates.js";

export interface EmailConfig {
  smtpUrl?: string;
  mailFrom: string;
  mailDir: string;
}

/**
 * SMTP when configured, files on disk otherwise. The fallback is deliberately
 * a real, inspectable artifact rather than a silent no-op: a developer running
 * `npm run dev` can open the .eml and click through, and the e2e suite drives
 * the genuine flow. src/config.ts refuses to boot in production without
 * SMTP_URL, so this fallback can never be the accidental production state.
 */
export function loadTransport(cfg: EmailConfig): EmailTransport {
  if (cfg.smtpUrl && cfg.smtpUrl.length > 0) {
    return createSmtpTransport(cfg.smtpUrl, cfg.mailFrom);
  }
  return createFileTransport(cfg.mailDir);
}
```

- [ ] **Step 6: Run the whole email suite**

Run: `npx vitest run src/email/`
Expected: PASS (all 12 tests across the three files)

- [ ] **Step 7: Commit**

```bash
git add src/email package.json package-lock.json
git commit -m "feat(email): SMTP transport and environment-driven transport selection"
```

---

## Workstream B — Data model and web API

### Task B1: Schema, queries, and config for links, sessions, and login challenges

**Files:**
- Modify: `src/db/schema.sql`, `src/db/queries.ts`, `src/config.ts`
- Test: `src/db/queries.web.test.ts`, `src/config.test.ts` (append)

**Interfaces:**
- Consumes: nothing
- Produces: `insertApprovalLink`, `getApprovalLink`, `getApprovalLinkFor`, `insertSession`, `getSession`, `deleteSession`, `insertLoginChallenge`, `consumeLoginChallenge`, `getPrincipalByEmail`, `listRequestsFor`, `getAuditFor` — all in `src/db/queries.ts`; `AppConfig.smtpUrl | mailFrom | mailDir | sessionTtlHours` in `src/config.ts`

- [ ] **Step 1: Write the failing query tests**

```ts
// src/db/queries.web.test.ts
import { describe, it, expect, beforeEach } from "vitest";
import { openDb, type Database } from "./index.js";
import * as q from "./queries.js";

const iso = (msFromNow: number) => new Date(Date.now() + msFromNow).toISOString();

function seedPrincipal(db: Database, id: string, email: string) {
  q.insertPrincipal(db, { id, email, display_name: `User ${id}` });
}

function seedAttestation(db: Database, attId: string, approverIds: string[]) {
  const actionId = `act_${attId}`;
  q.insertAction(db, {
    id: actionId, requested_by: "agent-7", type: "wire_transfer",
    canonical_json: '{"amount":100}', payload_hash: `sha256:${attId}`, risk_tier: "high",
  });
  q.insertAttestation(db, {
    id: attId, action_id: actionId, required_approvals: 1,
    approver_ids: approverIds, expires_at: iso(60_000),
  });
  return actionId;
}

describe("approval links", () => {
  let db: Database;
  beforeEach(() => {
    db = openDb(":memory:");
    seedPrincipal(db, "prin_1", "one@e.com");
    seedAttestation(db, "att_1", ["prin_1"]);
  });

  it("round-trips a link token to its attestation and principal", () => {
    q.insertApprovalLink(db, { token: "tok_a", attestation_id: "att_1", principal_id: "prin_1" });
    expect(q.getApprovalLink(db, "tok_a")).toMatchObject({
      token: "tok_a", attestation_id: "att_1", principal_id: "prin_1",
    });
  });

  it("returns undefined for an unknown token", () => {
    expect(q.getApprovalLink(db, "nope")).toBeUndefined();
  });

  it("allows one link per (attestation, principal) pair", () => {
    q.insertApprovalLink(db, { token: "tok_a", attestation_id: "att_1", principal_id: "prin_1" });
    expect(() =>
      q.insertApprovalLink(db, { token: "tok_b", attestation_id: "att_1", principal_id: "prin_1" }),
    ).toThrow();
  });
});

describe("sessions", () => {
  let db: Database;
  beforeEach(() => {
    db = openDb(":memory:");
    seedPrincipal(db, "prin_1", "one@e.com");
  });

  it("round-trips a live session", () => {
    q.insertSession(db, { id: "sess_1", principal_id: "prin_1", expires_at: iso(60_000) });
    expect(q.getSession(db, "sess_1")).toMatchObject({ id: "sess_1", principal_id: "prin_1" });
  });

  it("does not return an expired session", () => {
    q.insertSession(db, { id: "sess_old", principal_id: "prin_1", expires_at: iso(-1000) });
    expect(q.getSession(db, "sess_old")).toBeUndefined();
  });

  it("deletes a session", () => {
    q.insertSession(db, { id: "sess_1", principal_id: "prin_1", expires_at: iso(60_000) });
    q.deleteSession(db, "sess_1");
    expect(q.getSession(db, "sess_1")).toBeUndefined();
  });
});

describe("login challenges", () => {
  let db: Database;
  beforeEach(() => {
    db = openDb(":memory:");
    seedPrincipal(db, "prin_1", "one@e.com");
  });

  it("consumes a valid challenge exactly once", () => {
    q.insertLoginChallenge(db, { challenge: "chal_1", principal_id: "prin_1", expires_at: iso(60_000) });
    expect(q.consumeLoginChallenge(db, "chal_1", "prin_1")).toBe(true);
    expect(q.consumeLoginChallenge(db, "chal_1", "prin_1")).toBe(false);
  });

  it("refuses an expired challenge", () => {
    q.insertLoginChallenge(db, { challenge: "chal_x", principal_id: "prin_1", expires_at: iso(-1000) });
    expect(q.consumeLoginChallenge(db, "chal_x", "prin_1")).toBe(false);
  });

  it("refuses a challenge bound to a different principal", () => {
    seedPrincipal(db, "prin_2", "two@e.com");
    q.insertLoginChallenge(db, { challenge: "chal_1", principal_id: "prin_1", expires_at: iso(60_000) });
    expect(q.consumeLoginChallenge(db, "chal_1", "prin_2")).toBe(false);
  });
});

describe("principal lookup by email", () => {
  it("finds a principal by exact email and returns undefined otherwise", () => {
    const db = openDb(":memory:");
    seedPrincipal(db, "prin_1", "one@e.com");
    expect(q.getPrincipalByEmail(db, "one@e.com")).toMatchObject({ id: "prin_1" });
    expect(q.getPrincipalByEmail(db, "missing@e.com")).toBeUndefined();
  });
});

describe("listRequestsFor", () => {
  let db: Database;
  beforeEach(() => {
    db = openDb(":memory:");
    seedPrincipal(db, "prin_1", "one@e.com");
    seedPrincipal(db, "prin_2", "two@e.com");
    seedAttestation(db, "att_mine", ["prin_1"]);
    seedAttestation(db, "att_theirs", ["prin_2"]);
  });

  it("returns only attestations naming this principal as an approver", () => {
    const rows = q.listRequestsFor(db, "prin_1", { limit: 50 });
    expect(rows.map((r) => r.attestation_id)).toEqual(["att_mine"]);
  });

  it("reports this principal's own recorded decision", () => {
    q.insertApproval(db, {
      id: "ap_1", attestation_id: "att_mine", principal_id: "prin_1",
      decision: "approve", client_data_json: "{}",
    });
    expect(q.listRequestsFor(db, "prin_1", { limit: 50 })[0].my_decision).toBe("approve");
    expect(q.listRequestsFor(db, "prin_2", { limit: 50 })[0].my_decision).toBeNull();
  });

  it("filters by status", () => {
    expect(q.listRequestsFor(db, "prin_1", { limit: 50, status: "approved" })).toHaveLength(0);
    expect(q.listRequestsFor(db, "prin_1", { limit: 50, status: "pending" })).toHaveLength(1);
  });
});
```

- [ ] **Step 2: Run and confirm it fails**

Run: `npx vitest run src/db/queries.web.test.ts`
Expected: FAIL — `q.insertApprovalLink is not a function`.

- [ ] **Step 3: Extend `src/db/schema.sql`**

Append these tables and **delete the `push_subscriptions` table definition**:

```sql
CREATE TABLE IF NOT EXISTS approval_links (
  token TEXT PRIMARY KEY,
  attestation_id TEXT NOT NULL REFERENCES attestations(id),
  principal_id TEXT NOT NULL REFERENCES principals(id),
  created_at TEXT NOT NULL,
  UNIQUE (attestation_id, principal_id)
);

CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL REFERENCES principals(id),
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS login_challenges (
  challenge TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL REFERENCES principals(id),
  expires_at TEXT NOT NULL,
  used_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_sessions_principal ON sessions(principal_id);
CREATE INDEX IF NOT EXISTS idx_links_attestation ON approval_links(attestation_id);
```

- [ ] **Step 4: Add the queries to `src/db/queries.ts`**

Delete `upsertPushSubscription`, `getPushSubscriptionsFor`, and `deletePushSubscription`. Add:

```ts
export function insertApprovalLink(
  db: Database, l: { token: string; attestation_id: string; principal_id: string },
): void {
  db.prepare(
    `INSERT INTO approval_links (token, attestation_id, principal_id, created_at)
     VALUES (?, ?, ?, ?)`,
  ).run(l.token, l.attestation_id, l.principal_id, now());
}

export function getApprovalLink(db: Database, token: string) {
  return db.prepare(`SELECT * FROM approval_links WHERE token = ?`).get(token) as
    | { token: string; attestation_id: string; principal_id: string; created_at: string }
    | undefined;
}

/**
 * Deliberately has no expiry of its own: an approval link inherits the
 * attestation's lifetime, which is the single source of truth for whether a
 * request is still live. A link to a resolved attestation still resolves, and
 * the page shows the outcome instead of a dead end -- safe precisely because
 * the payload was purged at resolution, so there is nothing left to leak.
 */
export function getApprovalLinkFor(db: Database, attestationId: string, principalId: string) {
  return db.prepare(
    `SELECT * FROM approval_links WHERE attestation_id = ? AND principal_id = ?`,
  ).get(attestationId, principalId) as
    | { token: string; attestation_id: string; principal_id: string }
    | undefined;
}

export function insertSession(
  db: Database, s: { id: string; principal_id: string; expires_at: string },
): void {
  db.prepare(
    `INSERT INTO sessions (id, principal_id, expires_at, created_at) VALUES (?, ?, ?, ?)`,
  ).run(s.id, s.principal_id, s.expires_at, now());
}

/**
 * Expiry is enforced in the WHERE clause, not by the caller. A session row
 * that has aged out is indistinguishable from one that never existed, so
 * there is no code path where a caller can forget the check and silently
 * accept a stale cookie.
 */
export function getSession(db: Database, id: string) {
  return db.prepare(`SELECT * FROM sessions WHERE id = ? AND expires_at > ?`).get(id, now()) as
    | { id: string; principal_id: string; expires_at: string }
    | undefined;
}

export function deleteSession(db: Database, id: string): void {
  db.prepare(`DELETE FROM sessions WHERE id = ?`).run(id);
}

export function insertLoginChallenge(
  db: Database, c: { challenge: string; principal_id: string; expires_at: string },
): void {
  db.prepare(
    `INSERT INTO login_challenges (challenge, principal_id, expires_at, used_at)
     VALUES (?, ?, ?, NULL)`,
  ).run(c.challenge, c.principal_id, c.expires_at);
}

/**
 * Atomic check-and-burn in one statement, mirroring consumeEnrolmentToken:
 * two requests racing on the same challenge cannot both observe it as unused.
 * Unknown, expired, already-used, and wrong-principal all return false
 * identically -- the caller collapses them into one opaque rejection.
 */
export function consumeLoginChallenge(db: Database, challenge: string, principalId: string): boolean {
  const result = db.prepare(
    `UPDATE login_challenges SET used_at = ?
     WHERE challenge = ? AND principal_id = ? AND used_at IS NULL AND expires_at > ?`,
  ).run(now(), challenge, principalId, now());
  return result.changes === 1;
}

export function getPrincipalByEmail(db: Database, email: string) {
  return db.prepare(`SELECT * FROM principals WHERE email = ?`).get(email) as
    | { id: string; email: string; display_name: string; status: string }
    | undefined;
}

export interface RequestListRow {
  attestation_id: string;
  type: string;
  status: AttestationStatus;
  requested_by: string;
  created_at: string;
  resolved_at: string | null;
  expires_at: string;
  payload_hash: string;
  my_decision: Decision | null;
}

/**
 * Membership is tested with a JSON array scan rather than `LIKE`, because
 * approver_ids is a JSON-encoded array in a TEXT column and a substring match
 * would treat "prin_1" as a member of a list containing "prin_10" -- the same
 * substring-vs-set-membership trap validateEnvelope guards against on the
 * write side.
 *
 * `before` paginates on created_at, which is stable and monotonic per row;
 * rowid breaks ties so two attestations created in the same millisecond
 * cannot cause a page boundary to skip or repeat a row.
 */
export function listRequestsFor(
  db: Database,
  principalId: string,
  opts: { limit: number; status?: AttestationStatus; before?: string },
): RequestListRow[] {
  const clauses = [
    `EXISTS (SELECT 1 FROM json_each(att.approver_ids) WHERE json_each.value = ?)`,
  ];
  const params: unknown[] = [principalId];

  if (opts.status) { clauses.push(`att.status = ?`); params.push(opts.status); }
  if (opts.before) { clauses.push(`att.created_at < ?`); params.push(opts.before); }

  params.push(principalId, opts.limit);

  return db.prepare(
    `SELECT att.id AS attestation_id, act.type AS type, att.status AS status,
            act.requested_by AS requested_by, att.created_at AS created_at,
            att.resolved_at AS resolved_at, att.expires_at AS expires_at,
            act.payload_hash AS payload_hash,
            (SELECT ap.decision FROM attestation_approvals ap
              WHERE ap.attestation_id = att.id AND ap.principal_id = ?) AS my_decision
       FROM attestations att
       JOIN actions act ON act.id = att.action_id
      WHERE ${clauses.join(" AND ")}
      ORDER BY att.created_at DESC, att.rowid DESC
      LIMIT ?`,
  ).all(...params) as RequestListRow[];
}

export function getAuditFor(db: Database, attestationId: string) {
  return db.prepare(
    `SELECT event, actor, created_at FROM audit_log
      WHERE attestation_id = ? ORDER BY id`,
  ).all(attestationId) as Array<{ event: string; actor: string | null; created_at: string }>;
}
```

- [ ] **Step 5: Run the query tests**

Run: `npx vitest run src/db/queries.web.test.ts`
Expected: PASS (13 tests)

- [ ] **Step 6: Extend `src/config.ts`**

Add to the `AppConfig` interface: `smtpUrl?: string; mailFrom: string; mailDir: string; sessionTtlHours: number;`

Add to the returned object in `loadConfig`:

```ts
    smtpUrl: env.SMTP_URL,
    mailFrom: env.MAIL_FROM ?? `no-reply@${new URL(baseUrl).hostname}`,
    mailDir: env.MAIL_DIR ?? "mail",
    sessionTtlHours: env.SESSION_TTL_HOURS ? Number(env.SESSION_TTL_HOURS) : 168,
```

Extend the production guard immediately after the existing RP_ID check:

```ts
  // Same reasoning as the RP_ID guard above: a production deployment with no
  // SMTP_URL falls back to writing .eml files into a local directory, which
  // means no approver is ever notified of anything. That failure is silent --
  // requests simply sit pending until they expire -- so it must be caught at
  // boot rather than discovered from an absence of approvals.
  if (config.nodeEnv === "production" && !config.smtpUrl) {
    throw new Error(
      "refusing to start with NODE_ENV=production and no SMTP_URL -- approval " +
      "emails would be written to disk instead of sent, and no approver would " +
      "ever be notified",
    );
  }
```

- [ ] **Step 7: Append config tests to `src/config.test.ts`**

```ts
describe("email config", () => {
  const prodBase = {
    NODE_ENV: "production", RP_ID: "attest.example.com",
    APP_BASE_URL: "https://attest.example.com",
  } as NodeJS.ProcessEnv;

  it("defaults mailFrom to no-reply at the base URL host", () => {
    expect(loadConfig({ ...prodBase, SMTP_URL: "smtp://x" }).mailFrom)
      .toBe("no-reply@attest.example.com");
  });

  it("defaults the session TTL to one week", () => {
    expect(loadConfig({ ...prodBase, SMTP_URL: "smtp://x" }).sessionTtlHours).toBe(168);
  });

  it("refuses to boot in production without SMTP_URL", () => {
    expect(() => loadConfig(prodBase)).toThrow(/SMTP_URL/);
  });

  it("allows the file transport outside production", () => {
    expect(() => loadConfig({ NODE_ENV: "development" })).not.toThrow();
  });
});
```

- [ ] **Step 8: Run the config tests**

Run: `npx vitest run src/config.test.ts`
Expected: PASS

- [ ] **Step 9: Commit**

```bash
git add src/db/schema.sql src/db/queries.ts src/db/queries.web.test.ts src/config.ts src/config.test.ts
git commit -m "feat(db): approval links, sessions, login challenges, and history queries"
```

---

### Task B2: Wire email into attestation creation and enrolment

**Files:**
- Modify: `src/api/server.ts`, `src/api/routes.attestations.ts`, `src/api/routes.principals.ts`
- Create: `src/api/notify.ts`
- Test: `src/api/notify.test.ts`

**Interfaces:**
- Consumes: A3's `loadTransport`/`renderApprovalEmail`/`renderEnrolmentEmail`, B1's `insertApprovalLink`
- Produces: `emailApprovers(...)`, `emailEnrolment(...)` in `src/api/notify.ts`; `AppContext.email: EmailTransport` replacing `AppContext.vapid`

- [ ] **Step 1: Write the failing test**

```ts
// src/api/notify.test.ts
import { describe, it, expect, beforeEach } from "vitest";
import { openDb, type Database } from "../db/index.js";
import * as q from "../db/queries.js";
import { emailApprovers } from "./notify.js";
import type { EmailMessage, EmailTransport } from "../email/index.js";

function recorder(): EmailTransport & { sent: EmailMessage[] } {
  const sent: EmailMessage[] = [];
  return { sent, async send(msg) { sent.push(msg); } };
}

function seed(db: Database) {
  q.insertPrincipal(db, { id: "prin_1", email: "one@e.com", display_name: "One" });
  q.insertPrincipal(db, { id: "prin_2", email: "two@e.com", display_name: "Two" });
  q.insertAction(db, {
    id: "act_1", requested_by: "agent-7", type: "wire_transfer",
    canonical_json: '{"amount":2500000}', payload_hash: "sha256:abc", risk_tier: "high",
  });
  q.insertAttestation(db, {
    id: "att_1", action_id: "act_1", required_approvals: 2,
    approver_ids: ["prin_1", "prin_2"], expires_at: new Date(Date.now() + 60_000).toISOString(),
  });
}

const summary = { headline: "Wire $25,000.00 USD to Acme Corp", fields: [{ label: "Amount", value: "$25,000.00 USD" }] };

describe("emailApprovers", () => {
  let db: Database;
  beforeEach(() => { db = openDb(":memory:"); seed(db); });

  it("mails every approver a link unique to them", async () => {
    const t = recorder();
    await emailApprovers(db, t, {
      attestation_id: "att_1", approverIds: ["prin_1", "prin_2"], summary,
      requestedBy: "agent-7", expiresAt: "2026-08-01T12:00:00.000Z",
      baseUrl: "http://localhost:3000",
    });

    expect(t.sent.map((m) => m.to).sort()).toEqual(["one@e.com", "two@e.com"]);
    const tokens = t.sent.map((m) => m.text.match(/\/a\/([A-Za-z0-9_-]+)/)![1]);
    expect(new Set(tokens).size).toBe(2);
    expect(q.getApprovalLink(db, tokens[0])!.principal_id).toBeTruthy();
  });

  it("persists one approval_links row per approver", async () => {
    await emailApprovers(db, recorder(), {
      attestation_id: "att_1", approverIds: ["prin_1", "prin_2"], summary,
      requestedBy: "agent-7", expiresAt: "x", baseUrl: "http://localhost:3000",
    });
    expect(q.getApprovalLinkFor(db, "att_1", "prin_1")).toBeDefined();
    expect(q.getApprovalLinkFor(db, "att_1", "prin_2")).toBeDefined();
  });

  it("never throws when the transport fails, and audits the failure", async () => {
    const failing: EmailTransport = { async send() { throw new Error("smtp down"); } };
    await expect(emailApprovers(db, failing, {
      attestation_id: "att_1", approverIds: ["prin_1"], summary,
      requestedBy: "agent-7", expiresAt: "x", baseUrl: "http://localhost:3000",
    })).resolves.toBeUndefined();

    const events = q.getAuditFor(db, "att_1").map((r) => r.event);
    expect(events).toContain("email_failed");
  });

  it("keeps mailing the remaining approvers after one fails", async () => {
    let calls = 0;
    const flaky: EmailTransport = {
      async send() { calls += 1; if (calls === 1) throw new Error("first fails"); },
    };
    await emailApprovers(db, flaky, {
      attestation_id: "att_1", approverIds: ["prin_1", "prin_2"], summary,
      requestedBy: "agent-7", expiresAt: "x", baseUrl: "http://localhost:3000",
    });
    expect(calls).toBe(2);
  });

  it("skips an approver id that is not a real principal without throwing", async () => {
    const t = recorder();
    await emailApprovers(db, t, {
      attestation_id: "att_1", approverIds: ["prin_ghost"], summary,
      requestedBy: "agent-7", expiresAt: "x", baseUrl: "http://localhost:3000",
    });
    expect(t.sent).toHaveLength(0);
  });

  it("audits a successful send", async () => {
    await emailApprovers(db, recorder(), {
      attestation_id: "att_1", approverIds: ["prin_1"], summary,
      requestedBy: "agent-7", expiresAt: "x", baseUrl: "http://localhost:3000",
    });
    expect(q.getAuditFor(db, "att_1").map((r) => r.event)).toContain("email_sent");
  });
});
```

- [ ] **Step 2: Run and confirm it fails**

Run: `npx vitest run src/api/notify.test.ts`
Expected: FAIL — cannot resolve `./notify.js`.

- [ ] **Step 3: Write `src/api/notify.ts`**

```ts
import { randomBytes } from "node:crypto";
import type { Database } from "better-sqlite3";
import * as q from "../db/queries.js";
import { renderApprovalEmail, renderEnrolmentEmail, type EmailTransport } from "../email/index.js";
import type { RenderedSummary } from "../types.js";

export interface NotifyLogger {
  warn(obj: Record<string, unknown>, msg: string): void;
}

/**
 * Best-effort, exactly like the push delivery it replaces. An approval email
 * is a notification, not the authorization -- the request is independently
 * reachable from the dashboard -- so a mail failure must never propagate into
 * POST /v1/attestations. Each approver is attempted independently: one
 * failure must not stop the rest, and this function never throws or rejects.
 *
 * The link token is minted here rather than at attestation-creation time
 * because it is meaningless without a delivery channel to carry it, and
 * because one token per approver is what makes the row unique per (att,
 * principal) -- a shared token would let one approver open another's link.
 */
export async function emailApprovers(
  db: Database,
  transport: EmailTransport,
  n: {
    attestation_id: string;
    approverIds: string[];
    summary: RenderedSummary;
    requestedBy: string;
    expiresAt: string;
    baseUrl: string;
  },
  logger?: NotifyLogger,
): Promise<void> {
  for (const principalId of n.approverIds) {
    try {
      const principal = q.getPrincipal(db, principalId);
      if (!principal) continue;

      let link = q.getApprovalLinkFor(db, n.attestation_id, principalId);
      if (!link) {
        const token = randomBytes(32).toString("base64url");
        q.insertApprovalLink(db, {
          token, attestation_id: n.attestation_id, principal_id: principalId,
        });
        link = { token, attestation_id: n.attestation_id, principal_id: principalId };
      }

      await transport.send(renderApprovalEmail({
        to: principal.email,
        headline: n.summary.headline,
        fields: n.summary.fields,
        requestedBy: n.requestedBy,
        expiresAt: n.expiresAt,
        linkUrl: `${n.baseUrl}/a/${link.token}`,
      }));

      q.audit(db, {
        attestation_id: n.attestation_id, event: "email_sent",
        actor: principalId, detail: null,
      });
    } catch (err) {
      q.audit(db, {
        attestation_id: n.attestation_id, event: "email_failed",
        actor: principalId, detail: String(err),
      });
      logger?.warn({ principal_id: principalId, err: String(err) }, "approval email failed");
    }
  }
}

/**
 * Same best-effort contract: POST /v1/principals still returns the enrolment
 * token in its response body, so a mail failure degrades convenience, never
 * the ability to enrol.
 */
export async function emailEnrolment(
  db: Database,
  transport: EmailTransport,
  n: { principalId: string; email: string; displayName: string; token: string; baseUrl: string },
  logger?: NotifyLogger,
): Promise<void> {
  try {
    await transport.send(renderEnrolmentEmail({
      to: n.email,
      displayName: n.displayName,
      linkUrl: `${n.baseUrl}/enrol?principal=${n.principalId}&token=${n.token}`,
    }));
    q.audit(db, {
      attestation_id: null, event: "email_sent", actor: n.principalId, detail: "enrolment",
    });
  } catch (err) {
    q.audit(db, {
      attestation_id: null, event: "email_failed", actor: n.principalId, detail: String(err),
    });
    logger?.warn({ principal_id: n.principalId, err: String(err) }, "enrolment email failed");
  }
}
```

- [ ] **Step 4: Run and confirm the tests pass**

Run: `npx vitest run src/api/notify.test.ts`
Expected: PASS (6 tests)

- [ ] **Step 5: Swap push for email in `src/api/server.ts`**

Replace the VAPID import and context field:

```ts
// remove: import { loadOrCreateVapidKeys, type VapidKeys } from "../push/vapid.js";
import { loadTransport, type EmailTransport } from "../email/index.js";
```

```ts
export interface AppContext {
  db: Database; kp: Keypair; email: EmailTransport; baseUrl: string;
}
```

In `buildServer`, replace the `vapid:` line with:

```ts
    email: opts.email ?? loadTransport({
      smtpUrl: cfg.smtpUrl, mailFrom: cfg.mailFrom, mailDir: cfg.mailDir,
    }),
```

Add `email?: EmailTransport` to the `opts` type so tests can inject a recorder, and hoist `const cfg = loadConfig();` above `app.ctx` (currently `loadConfig()` is only called inline for `baseUrl`). Change the static mount from `demo/public` at `/approve/` to `web/dist` at `/`, with an SPA fallback — replace `setNotFoundHandler` so that a **GET** request whose path does not start with `/v1`, `/web`, or `/.well-known` and which accepts HTML serves `web/dist/index.html` with a 200; every other unmatched route keeps today's audited 404 exactly as-is. Tighten `styleSrc` to `["'self'"]`. Delete the `registerPushRoutes` import and call.

- [ ] **Step 6: Call the email helpers from the routes**

In `src/api/routes.attestations.ts`, replace the `notifyApprovers` import and call:

```ts
import { emailApprovers } from "./notify.js";
```

```ts
    void emailApprovers(db, app.ctx.email, {
      attestation_id: attestationId,
      approverIds: envelope.approver_ids,
      summary: action.summary,
      requestedBy: envelope.requested_by,
      expiresAt: new Date(Date.now() + envelope.ttl_seconds * 1000).toISOString(),
      baseUrl: app.ctx.baseUrl,
    }, app.log);
```

Change the `approve_url` in the 201 response to `${app.ctx.baseUrl}/requests/${attestationId}`.

In `src/api/routes.principals.ts`, after `q.insertEnrolmentToken(...)` and before the 201 reply:

```ts
    void emailEnrolment(app.ctx.db, app.ctx.email, {
      principalId: id, email, displayName: display_name,
      token: enrolment_token, baseUrl: app.ctx.baseUrl,
    }, app.log);
```

- [ ] **Step 7: Run the full unit suite**

Run: `npm test`
Expected: PASS except `src/api/routes.push.test.ts` and `src/push/*.test.ts`, which worker D deletes. If any other suite fails, fix it here — that is a real regression.

- [ ] **Step 8: Commit**

```bash
git add src/api/notify.ts src/api/notify.test.ts src/api/server.ts src/api/routes.attestations.ts src/api/routes.principals.ts
git commit -m "feat(api): email approvers and enrolments, replacing web push"
```

---

### Task B3: Session sign-in endpoints

**Files:**
- Create: `src/api/routes.web.session.ts`
- Test: `src/api/routes.web.session.test.ts`

**Interfaces:**
- Consumes: B1's session and login-challenge queries
- Produces: `registerWebSessionRoutes(app)`, and `requireSession(app, req): {principal_id: string}` exported for Task B4

- [ ] **Step 1: Write the failing test**

```ts
// src/api/routes.web.session.test.ts
import { describe, it, expect, beforeEach } from "vitest";
import { buildServer } from "./server.js";
import * as q from "../db/queries.js";

async function app() {
  const a = await buildServer({ email: { async send() {} } });
  q.insertPrincipal(a.ctx.db, { id: "prin_1", email: "one@e.com", display_name: "One" });
  return a;
}

describe("POST /web/session/options", () => {
  it("returns 200 with a challenge for a registered email", async () => {
    const a = await app();
    const res = await a.inject({
      method: "POST", url: "/web/session/options", payload: { email: "one@e.com" },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json().challenge).toBeTruthy();
  });

  it("is byte-identical in shape for an unregistered email (no enumeration)", async () => {
    const a = await app();
    const known = await a.inject({
      method: "POST", url: "/web/session/options", payload: { email: "one@e.com" },
    });
    const unknown = await a.inject({
      method: "POST", url: "/web/session/options", payload: { email: "nobody@e.com" },
    });
    expect(unknown.statusCode).toBe(known.statusCode);
    expect(Object.keys(unknown.json()).sort()).toEqual(Object.keys(known.json()).sort());
    expect(unknown.json().challenge).toBeTruthy();
  });

  it("rejects a malformed body with a typed error and an audit row", async () => {
    const a = await app();
    const res = await a.inject({ method: "POST", url: "/web/session/options", payload: {} });
    expect(res.statusCode).toBe(400);
    const rows = a.ctx.db.prepare(`SELECT event FROM audit_log`).all() as Array<{ event: string }>;
    expect(rows.some((r) => r.event === "payload_invalid")).toBe(true);
  });
});

describe("POST /web/session", () => {
  it("rejects an assertion with no matching login challenge", async () => {
    const a = await app();
    const res = await a.inject({
      method: "POST", url: "/web/session",
      payload: { email: "one@e.com", response: { id: "cred_x" } },
    });
    expect(res.statusCode).toBe(401);
    expect(res.headers["set-cookie"]).toBeUndefined();
  });

  it("rejects a missing response without a raw 500", async () => {
    const a = await app();
    const res = await a.inject({
      method: "POST", url: "/web/session", payload: { email: "one@e.com" },
    });
    expect(res.statusCode).toBe(400);
  });
});

describe("GET /web/me", () => {
  it("401s with no cookie", async () => {
    const a = await app();
    expect((await a.inject({ method: "GET", url: "/web/me" })).statusCode).toBe(401);
  });

  it("401s with an expired session cookie", async () => {
    const a = await app();
    q.insertSession(a.ctx.db, {
      id: "sess_old", principal_id: "prin_1",
      expires_at: new Date(Date.now() - 1000).toISOString(),
    });
    const res = await a.inject({
      method: "GET", url: "/web/me", headers: { cookie: "ha_session=sess_old" },
    });
    expect(res.statusCode).toBe(401);
  });

  it("returns the principal for a live session", async () => {
    const a = await app();
    q.insertSession(a.ctx.db, {
      id: "sess_1", principal_id: "prin_1",
      expires_at: new Date(Date.now() + 60_000).toISOString(),
    });
    const res = await a.inject({
      method: "GET", url: "/web/me", headers: { cookie: "ha_session=sess_1" },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({ principal_id: "prin_1", email: "one@e.com" });
  });
});

describe("DELETE /web/session", () => {
  it("clears the row and the cookie", async () => {
    const a = await app();
    q.insertSession(a.ctx.db, {
      id: "sess_1", principal_id: "prin_1",
      expires_at: new Date(Date.now() + 60_000).toISOString(),
    });
    const res = await a.inject({
      method: "DELETE", url: "/web/session", headers: { cookie: "ha_session=sess_1" },
    });
    expect(res.statusCode).toBe(204);
    expect(q.getSession(a.ctx.db, "sess_1")).toBeUndefined();
  });
});
```

- [ ] **Step 2: Run and confirm it fails**

Run: `npx vitest run src/api/routes.web.session.test.ts`
Expected: FAIL — every route 404s.

- [ ] **Step 3: Write `src/api/routes.web.session.ts`**

```ts
import { randomBytes } from "node:crypto";
import {
  generateAuthenticationOptions, verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import type { FastifyInstance, FastifyRequest, FastifyReply } from "fastify";
import type { AppContext } from "./server.js";
import * as q from "../db/queries.js";
import { RP } from "../webauthn/config.js";
import { FailClosedError } from "../types.js";
import { withAuditDetail } from "../audit-detail.js";
import { loadConfig } from "../config.js";

const COOKIE = "ha_session";
const LOGIN_CHALLENGE_TTL_SECONDS = 300;

/**
 * A sign-in challenge is random and stored server-side. It is deliberately
 * NOT derived from any action -- unlike an approval challenge, which is
 * hash({act, att, decision}). That asymmetry is the security property: an
 * assertion captured during sign-in signs bytes that no approval challenge
 * can ever equal, so it can never be replayed to approve an action, and an
 * approval assertion can never be replayed to sign in. tests/security asserts
 * this directly.
 */
function newLoginChallenge(): string {
  return randomBytes(32).toString("base64url");
}

function readCookie(req: FastifyRequest, name: string): string | undefined {
  const header = req.headers.cookie;
  if (!header) return undefined;
  for (const part of header.split(";")) {
    const [k, ...rest] = part.trim().split("=");
    if (k === name) return rest.join("=");
  }
  return undefined;
}

export function requireSession(
  app: FastifyInstance & { ctx: AppContext }, req: FastifyRequest,
): { principal_id: string } {
  const id = readCookie(req, COOKIE);
  if (!id) throw new FailClosedError("no_session", 401, "sign-in required");
  const session = q.getSession(app.ctx.db, id);
  if (!session) throw new FailClosedError("session_expired", 401, "sign-in required");
  return { principal_id: session.principal_id };
}

function assertEmail(email: unknown): asserts email is string {
  if (typeof email !== "string" || email.length === 0) {
    throw new FailClosedError("payload_invalid", 400, "email is required");
  }
}

export function registerWebSessionRoutes(app: FastifyInstance & { ctx: AppContext }): void {
  const { db } = app.ctx;
  const secure = app.ctx.baseUrl.startsWith("https://");
  const ttlHours = loadConfig().sessionTtlHours;

  /**
   * Rate-limited like the other credential-adjacent unauthenticated
   * endpoints (30/min, matching /v1/attestations/:id/options).
   */
  app.post("/web/session/options", {
    config: { rateLimit: { max: 30, timeWindow: "1 minute" } },
  }, async (req) => {
    const body = req.body as { email?: unknown };
    assertEmail(body.email);

    const principal = q.getPrincipalByEmail(db, body.email);
    const creds = principal ? q.getCredentialsFor(db, principal.id) : [];

    // An unregistered email, and a registered one with no enrolled
    // credential, both get a well-formed options object with a real random
    // challenge that simply cannot be satisfied. Returning 404 or an empty
    // allowCredentials for one and not the other would turn this endpoint
    // into an account-enumeration oracle -- the same reasoning that makes
    // POST /v1/principals opaque about duplicate emails.
    const challenge = newLoginChallenge();
    if (principal && creds.length > 0) {
      q.insertLoginChallenge(db, {
        challenge, principal_id: principal.id,
        expires_at: new Date(Date.now() + LOGIN_CHALLENGE_TTL_SECONDS * 1000).toISOString(),
      });
    }

    return generateAuthenticationOptions({
      rpID: RP.id,
      challenge: Buffer.from(challenge, "base64url"),
      allowCredentials: creds.map((c) => ({ id: c.credential_id })),
      userVerification: "preferred",
    });
  });

  app.post("/web/session", {
    config: { rateLimit: { max: 30, timeWindow: "1 minute" } },
  }, async (req, reply) => {
    const body = req.body as { email?: unknown; response?: unknown };
    assertEmail(body.email);
    const response = body.response as { id?: unknown } | undefined;
    if (!response || typeof response.id !== "string") {
      throw new FailClosedError("payload_invalid", 400, "a signed assertion is required");
    }

    // One opaque rejection for every failure below, for the same
    // anti-enumeration reason as above.
    const reject = (detail: string): never => {
      throw withAuditDetail(
        new FailClosedError("login_challenge_invalid", 401, "sign-in failed"), detail,
      );
    };

    const principal = q.getPrincipalByEmail(db, body.email);
    if (!principal) reject("unknown email");
    const cred = q.getCredential(db, response.id);
    if (!cred || cred.principal_id !== principal!.id) reject("credential not bound to this principal");

    let verification;
    try {
      verification = await verifyAuthenticationResponse({
        response: body.response as never,
        expectedChallenge: (challenge) =>
          q.consumeLoginChallenge(db, challenge, principal!.id),
        expectedOrigin: RP.origin,
        expectedRPID: RP.id,
        credential: {
          id: cred!.credential_id,
          publicKey: new Uint8Array(cred!.public_key),
          counter: cred!.sign_count,
        },
      });
    } catch (err) {
      reject(`assertion rejected: ${String(err)}`);
    }
    if (!verification!.verified) reject("verified=false");

    q.updateSignCount(db, cred!.credential_id, verification!.authenticationInfo.newCounter);

    const sessionId = randomBytes(32).toString("base64url");
    q.insertSession(db, {
      id: sessionId, principal_id: principal!.id,
      expires_at: new Date(Date.now() + ttlHours * 3600 * 1000).toISOString(),
    });
    q.audit(db, {
      attestation_id: null, event: "session_created", actor: principal!.id, detail: null,
    });

    return reply
      .header("set-cookie",
        `${COOKIE}=${sessionId}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${ttlHours * 3600}` +
        (secure ? "; Secure" : ""))
      .status(204)
      .send();
  });

  app.delete("/web/session", async (req: FastifyRequest, reply: FastifyReply) => {
    const id = readCookie(req, COOKIE);
    if (id) {
      const session = q.getSession(db, id);
      q.deleteSession(db, id);
      if (session) {
        q.audit(db, {
          attestation_id: null, event: "session_ended",
          actor: session.principal_id, detail: null,
        });
      }
    }
    return reply
      .header("set-cookie", `${COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`)
      .status(204)
      .send();
  });

  app.get("/web/me", async (req) => {
    const { principal_id } = requireSession(app, req);
    const principal = q.getPrincipal(db, principal_id)!;
    return {
      principal_id, email: principal.email, display_name: principal.display_name,
    };
  });
}
```

Register it in `src/api/server.ts` alongside the other `register*Routes` calls.

- [ ] **Step 4: Run the tests**

Run: `npx vitest run src/api/routes.web.session.test.ts`
Expected: PASS (8 tests)

- [ ] **Step 5: Commit**

```bash
git add src/api/routes.web.session.ts src/api/routes.web.session.test.ts src/api/server.ts
git commit -m "feat(api): passkey sign-in, sessions, and sign-out"
```

---

### Task B4: History and link-resolution endpoints

**Files:**
- Create: `src/api/routes.web.requests.ts`
- Test: `src/api/routes.web.requests.test.ts`

**Interfaces:**
- Consumes: B1's `listRequestsFor`/`getAuditFor`/`getApprovalLink`, B3's `requireSession`
- Produces: `registerWebRequestRoutes(app)`

- [ ] **Step 1: Write the failing test**

```ts
// src/api/routes.web.requests.test.ts
import { describe, it, expect, beforeEach } from "vitest";
import { buildServer } from "./server.js";
import * as q from "../db/queries.js";

const live = () => new Date(Date.now() + 60_000).toISOString();

async function app() {
  const a = await buildServer({ email: { async send() {} } });
  const db = a.ctx.db;
  q.insertPrincipal(db, { id: "prin_1", email: "one@e.com", display_name: "One" });
  q.insertPrincipal(db, { id: "prin_2", email: "two@e.com", display_name: "Two" });
  q.insertSession(db, { id: "s1", principal_id: "prin_1", expires_at: live() });
  q.insertSession(db, { id: "s2", principal_id: "prin_2", expires_at: live() });

  q.insertAction(db, {
    id: "act_1", requested_by: "agent-7", type: "wire_transfer",
    canonical_json: '{"amount":2500000,"currency":"USD","recipient_name":"Acme Corp","account_last4":"4821"}',
    payload_hash: "sha256:abc", risk_tier: "high",
  });
  q.insertAttestation(db, {
    id: "att_1", action_id: "act_1", required_approvals: 1,
    approver_ids: ["prin_1"], expires_at: live(),
  });
  q.insertApprovalLink(db, { token: "tok_1", attestation_id: "att_1", principal_id: "prin_1" });
  return a;
}

const as1 = { cookie: "ha_session=s1" };
const as2 = { cookie: "ha_session=s2" };

describe("GET /web/requests", () => {
  it("401s without a session", async () => {
    const a = await app();
    expect((await a.inject({ method: "GET", url: "/web/requests" })).statusCode).toBe(401);
  });

  it("returns this principal's requests", async () => {
    const a = await app();
    const res = await a.inject({ method: "GET", url: "/web/requests", headers: as1 });
    expect(res.statusCode).toBe(200);
    expect(res.json().items.map((i: { attestation_id: string }) => i.attestation_id)).toEqual(["att_1"]);
  });

  it("never returns another principal's requests", async () => {
    const a = await app();
    const res = await a.inject({ method: "GET", url: "/web/requests", headers: as2 });
    expect(res.json().items).toEqual([]);
  });

  it("filters by status", async () => {
    const a = await app();
    const res = await a.inject({ method: "GET", url: "/web/requests?status=denied", headers: as1 });
    expect(res.json().items).toEqual([]);
  });

  it("rejects an unknown status value rather than ignoring it", async () => {
    const a = await app();
    const res = await a.inject({ method: "GET", url: "/web/requests?status=bogus", headers: as1 });
    expect(res.statusCode).toBe(400);
  });
});

describe("GET /web/requests/:id", () => {
  it("returns the summary while the attestation is pending", async () => {
    const a = await app();
    const res = await a.inject({ method: "GET", url: "/web/requests/att_1", headers: as1 });
    expect(res.statusCode).toBe(200);
    expect(res.json().summary.headline).toContain("Acme Corp");
    expect(Array.isArray(res.json().audit)).toBe(true);
  });

  it("returns summary: null once the payload is purged, without leaking the text", async () => {
    const a = await app();
    q.setAttestationResolved(a.ctx.db, "att_1", "approved", "tok");
    q.purgeActionPayload(a.ctx.db, "act_1");
    const res = await a.inject({ method: "GET", url: "/web/requests/att_1", headers: as1 });
    expect(res.json().summary).toBeNull();
    expect(res.payload).not.toContain("Acme Corp");
    expect(res.json().payload_hash).toBe("sha256:abc");
  });

  it("404s for an attestation this principal does not approve", async () => {
    const a = await app();
    expect((await a.inject({
      method: "GET", url: "/web/requests/att_1", headers: as2,
    })).statusCode).toBe(404);
  });
});

describe("GET /web/link/:token", () => {
  it("resolves a link token to its attestation and principal, with no session", async () => {
    const a = await app();
    const res = await a.inject({ method: "GET", url: "/web/link/tok_1" });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({ attestation_id: "att_1", principal_id: "prin_1" });
  });

  it("404s for an unknown token", async () => {
    const a = await app();
    expect((await a.inject({ method: "GET", url: "/web/link/nope" })).statusCode).toBe(404);
  });

  it("records that the link was viewed", async () => {
    const a = await app();
    await a.inject({ method: "GET", url: "/web/link/tok_1" });
    expect(q.getAuditFor(a.ctx.db, "att_1").map((r) => r.event)).toContain("approval_link_viewed");
  });
});
```

- [ ] **Step 2: Run and confirm it fails**

Run: `npx vitest run src/api/routes.web.requests.test.ts`
Expected: FAIL — routes 404.

- [ ] **Step 3: Write `src/api/routes.web.requests.ts`**

(Also add `created_at: string;` to `getAttestation`'s return type annotation in
`src/db/queries.ts` — see the note after this step.)

```ts
import type { FastifyInstance } from "fastify";
import type { AppContext } from "./server.js";
import * as q from "../db/queries.js";
import { renderSummary } from "../actions/render.js";
import { effectiveStatus } from "./state.js";
import { requireSession } from "./routes.web.session.js";
import { FailClosedError, type AttestationStatus } from "../types.js";

const STATUSES: AttestationStatus[] = ["pending", "approved", "denied", "expired"];
const MAX_LIMIT = 100;

function parseStatus(raw: unknown): AttestationStatus | undefined {
  if (raw === undefined) return undefined;
  if (typeof raw !== "string" || !STATUSES.includes(raw as AttestationStatus)) {
    throw new FailClosedError("payload_invalid", 400, "unknown status filter");
  }
  return raw as AttestationStatus;
}

export function registerWebRequestRoutes(app: FastifyInstance & { ctx: AppContext }): void {
  const { db } = app.ctx;

  app.get("/web/requests", async (req) => {
    const { principal_id } = requireSession(app, req);
    const query = req.query as { status?: unknown; limit?: unknown; before?: unknown };

    const status = parseStatus(query.status);
    const limit = Math.min(
      Number.isFinite(Number(query.limit)) && Number(query.limit) > 0 ? Number(query.limit) : 25,
      MAX_LIMIT,
    );
    const before = typeof query.before === "string" ? query.before : undefined;

    // One extra row tells us whether another page exists without a second
    // COUNT query, and without the off-by-one of reporting a next cursor for
    // an empty page.
    const rows = q.listRequestsFor(db, principal_id, { limit: limit + 1, status, before });
    const items = rows.slice(0, limit);

    return {
      items,
      next_before: rows.length > limit ? items[items.length - 1].created_at : null,
    };
  });

  app.get("/web/requests/:id", async (req) => {
    const { principal_id } = requireSession(app, req);
    const { id } = req.params as { id: string };

    const att = q.getAttestation(db, id);
    // A principal who is not an approver gets exactly what they would get for
    // an attestation that does not exist. Distinguishing the two would let a
    // signed-in user probe for the existence of other people's requests.
    if (!att || !att.approver_ids.includes(principal_id)) {
      throw new FailClosedError("unknown_attestation", 404, "unknown attestation");
    }

    // Evaluated before reading the action, so that if this is the read that
    // observes a fresh expiry, the purge it triggers is reflected in this
    // very response rather than one request later -- the same ordering
    // routes.attestations.ts's GET handler depends on.
    const status = effectiveStatus(db, id);
    const action = q.getAction(db, att.action_id)!;
    const approvals = q.getApprovals(db, id);

    return {
      attestation_id: id,
      type: action.type,
      status,
      requested_by: action.requested_by,
      created_at: att.created_at,
      resolved_at: att.resolved_at,
      expires_at: att.expires_at,
      payload_hash: action.payload_hash,
      my_decision: approvals.find((a) => a.principal_id === principal_id)?.decision ?? null,
      required_approvals: att.required_approvals,
      approvals: approvals.length,
      // Null once purged. The design doc's §7 decision: a resolved request
      // shows metadata and its audit trail, never retained payload text.
      summary: action.canonical_json
        ? renderSummary(action.type as never, action.canonical_json)
        : null,
      audit: q.getAuditFor(db, id),
    };
  });

  /**
   * The link token is a view capability, not an authorization: it resolves to
   * which request and which approver, and nothing here mutates attestation
   * state. Approving still requires the passkey ceremony on
   * /v1/attestations/:id/options + /decision.
   */
  app.get("/web/link/:token", async (req) => {
    const { token } = req.params as { token: string };
    const link = q.getApprovalLink(db, token);
    if (!link) throw new FailClosedError("unknown_link", 404, "unknown link");

    const principal = q.getPrincipal(db, link.principal_id)!;
    q.audit(db, {
      attestation_id: link.attestation_id, event: "approval_link_viewed",
      actor: link.principal_id, detail: null,
    });

    return {
      attestation_id: link.attestation_id,
      principal_id: link.principal_id,
      email: principal.email,
    };
  });
}
```

Register it in `src/api/server.ts`.

- [ ] **Step 4: Run the tests**

Run: `npx vitest run src/api/routes.web.requests.test.ts`
Expected: PASS (11 tests)

**Note on `getAttestation`:** its current return type in `src/db/queries.ts`
omits `created_at`, even though the row has the column and `SELECT *` returns
it. Add `created_at: string;` to that type annotation — without it the handler
above will not typecheck.

- [ ] **Step 4: Run the tests**

Run: `npx vitest run src/api/routes.web.requests.test.ts`
Expected: PASS (11 tests)

- [ ] **Step 5: Commit**

```bash
git add src/api/routes.web.requests.ts src/api/routes.web.requests.test.ts src/api/server.ts src/db/queries.ts
git commit -m "feat(api): request history, detail with audit trail, and link resolution"
```

---

## Workstream C — React SPA

### Task C1: Vite scaffold served by Fastify

**Files:**
- Create: `web/index.html`, `web/vite.config.ts`, `web/tsconfig.json`, `web/src/main.tsx`, `web/src/App.tsx`, `web/src/styles.css`
- Modify: `demo/agent.ts` (printed URL only)

**Interfaces:**
- Consumes: nothing
- Produces: a `web/dist` build; `npm run build:web`

- [ ] **Step 1: Install and scaffold**

```bash
npm install --save-dev vite @vitejs/plugin-react react react-dom @types/react @types/react-dom react-router-dom
```

- [ ] **Step 2: Write `web/vite.config.ts`**

```ts
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  root: __dirname,
  plugins: [react()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
    // No asset may be inlined as a data: URI or an inline <script>. The
    // server's Content-Security-Policy is scriptSrc 'self' with no
    // 'unsafe-inline', so an inlined asset would be silently blocked in the
    // browser while building and testing just fine.
    assetsInlineLimit: 0,
  },
  server: { proxy: { "/v1": "http://localhost:3000", "/web": "http://localhost:3000" } },
});
```

- [ ] **Step 3: Write the app shell**

`web/index.html`:

```html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Human-Attest</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>
```

`web/src/main.tsx`:

```tsx
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { App } from "./App.js";
import "./styles.css";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </StrictMode>,
);
```

`web/src/App.tsx` — routes for `/signin`, `/enrol`, `/requests`, `/requests/:id`, `/a/:token`, with `/` redirecting to `/requests`. Each route renders a placeholder component for now; Tasks C2–C4 fill them in.

- [ ] **Step 4: Add the build script**

Add to `package.json` scripts (coordinate with worker D, who owns the file — post the exact line in the team channel rather than editing around them):

```json
"build:web": "vite build --config web/vite.config.ts"
```

- [ ] **Step 5: Verify the build produces no inline scripts**

```bash
npm run build:web
grep -c '<script' web/dist/index.html          # expect 1
grep -o 'src="[^"]*"' web/dist/index.html      # expect a hashed /assets/*.js path
```

Expected: exactly one `<script>` tag, with an external `src` — no inline JS.

- [ ] **Step 6: Point the demo agent at the SPA**

In `demo/agent.ts`, change the printed approval URL to `${baseUrl}/requests/${attestation_id}`.

- [ ] **Step 7: Commit**

```bash
git add web demo/agent.ts package-lock.json
git commit -m "feat(web): Vite + React scaffold served as the SPA shell"
```

---

### Task C2: API client and WebAuthn helpers

**Files:**
- Create: `web/src/api.ts`, `web/src/webauthn.ts`
- Test: `web/src/api.test.ts`

**Interfaces:**
- Consumes: the frozen `/web/*` contract
- Produces: `api.*` functions and `signIn`, `enrol`, `decide` used by C3/C4

- [ ] **Step 1: Write the failing test**

```ts
// web/src/api.test.ts
import { describe, it, expect, vi, afterEach } from "vitest";
import { getRequests, ApiError } from "./api.js";

afterEach(() => { vi.unstubAllGlobals(); });

describe("api client", () => {
  it("returns the parsed body on success", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(
      JSON.stringify({ items: [], next_before: null }),
      { status: 200, headers: { "content-type": "application/json" } },
    )));
    expect(await getRequests({})).toEqual({ items: [], next_before: null });
  });

  it("throws a typed ApiError carrying the server's code", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(
      JSON.stringify({ error: "no_session", message: "sign-in required" }),
      { status: 401, headers: { "content-type": "application/json" } },
    )));
    await expect(getRequests({})).rejects.toMatchObject({ code: "no_session", status: 401 });
    await expect(getRequests({})).rejects.toBeInstanceOf(ApiError);
  });

  it("does not throw a parse error when the body is not JSON", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("<html>502</html>", { status: 502 })));
    await expect(getRequests({})).rejects.toMatchObject({ status: 502 });
  });

  it("sends credentials so the session cookie is included", async () => {
    const spy = vi.fn(async () => new Response("{}", {
      status: 200, headers: { "content-type": "application/json" },
    }));
    vi.stubGlobal("fetch", spy);
    await getRequests({});
    expect(spy.mock.calls[0][1]).toMatchObject({ credentials: "same-origin" });
  });
});
```

- [ ] **Step 2: Run and confirm it fails**

Run: `npx vitest run web/src/api.test.ts`
Expected: FAIL — cannot resolve `./api.js`.

- [ ] **Step 3: Write `web/src/api.ts`**

```ts
export class ApiError extends Error {
  constructor(public readonly status: number, public readonly code: string, message: string) {
    super(message);
    this.name = "ApiError";
  }
}

export interface RequestListItem {
  attestation_id: string;
  type: string;
  status: "pending" | "approved" | "denied" | "expired";
  requested_by: string;
  created_at: string;
  resolved_at: string | null;
  expires_at: string;
  payload_hash: string;
  my_decision: "approve" | "deny" | null;
}

export interface RenderedSummary {
  headline: string;
  fields: Array<{ label: string; value: string }>;
}

export interface RequestDetail extends RequestListItem {
  required_approvals: number;
  approvals: number;
  summary: RenderedSummary | null;
  audit: Array<{ event: string; actor: string | null; created_at: string }>;
}

/**
 * Every response shape in this app is either JSON or a failure. A non-JSON
 * body (a proxy's HTML 502, an empty 204) must surface as the status it
 * actually was, not as a JSON parse exception -- otherwise every infra
 * hiccup reaches the UI as an unreadable SyntaxError.
 */
async function call<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, { credentials: "same-origin", ...init });
  const text = await res.text();
  let body: unknown = null;
  try { body = text ? JSON.parse(text) : null; } catch { /* non-JSON */ }

  if (!res.ok) {
    const e = body as { error?: string; message?: string } | null;
    throw new ApiError(res.status, e?.error ?? "http_error", e?.message ?? `HTTP ${res.status}`);
  }
  return body as T;
}

const json = (body: unknown): RequestInit => ({
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify(body),
});

export const getMe = () =>
  call<{ principal_id: string; email: string; display_name: string }>("/web/me");

export const getRequests = (opts: { status?: string; before?: string }) => {
  const p = new URLSearchParams();
  if (opts.status) p.set("status", opts.status);
  if (opts.before) p.set("before", opts.before);
  const qs = p.toString();
  return call<{ items: RequestListItem[]; next_before: string | null }>(
    `/web/requests${qs ? `?${qs}` : ""}`,
  );
};

export const getRequest = (id: string) => call<RequestDetail>(`/web/requests/${id}`);

export const resolveLink = (token: string) =>
  call<{ attestation_id: string; principal_id: string; email: string }>(`/web/link/${token}`);

export const signInOptions = (email: string) => call<never>("/web/session/options", json({ email }));
export const signInFinish = (email: string, response: unknown) =>
  call<null>("/web/session", json({ email, response }));
export const signOut = () => call<null>("/web/session", { method: "DELETE" });

export const decisionOptions = (id: string, principal_id: string, decision: string) =>
  call<never>(`/v1/attestations/${id}/options`, json({ principal_id, decision }));
export const submitDecision = (id: string, principal_id: string, decision: string, response: unknown) =>
  call<{ status: string; token: string | null }>(
    `/v1/attestations/${id}/decision`, json({ principal_id, decision, response }),
  );

export const enrolOptions = (principal: string, token: string) =>
  call<never>(`/v1/principals/${principal}/credentials/options?token=${encodeURIComponent(token)}`,
    { method: "POST" });
export const enrolFinish = (principal: string, token: string, response: unknown) =>
  call<{ credential_id: string }>(
    `/v1/principals/${principal}/credentials?token=${encodeURIComponent(token)}`, json(response),
  );
```

- [ ] **Step 4: Write `web/src/webauthn.ts`**

```ts
import { startAuthentication, startRegistration } from "@simplewebauthn/browser";
import * as api from "./api.js";

export async function signIn(email: string): Promise<void> {
  const options = await api.signInOptions(email);
  const response = await startAuthentication({ optionsJSON: options });
  await api.signInFinish(email, response);
}

export async function enrol(principal: string, token: string): Promise<void> {
  const options = await api.enrolOptions(principal, token);
  const response = await startRegistration({ optionsJSON: options });
  await api.enrolFinish(principal, token, response);
}

/**
 * The decision is declared to the server BEFORE the ceremony, because the
 * challenge is derived from it -- hash({act, att, decision}). Approve and deny
 * therefore sign different bytes, which is what makes a captured approval
 * unusable as a denial and vice versa. Passing the wrong decision here would
 * simply fail verification, never silently record the other one.
 */
export async function decide(
  attestationId: string, principalId: string, decision: "approve" | "deny",
): Promise<{ status: string; token: string | null }> {
  const options = await api.decisionOptions(attestationId, principalId, decision);
  const response = await startAuthentication({ optionsJSON: options });
  return api.submitDecision(attestationId, principalId, decision, response);
}
```

- [ ] **Step 5: Run the tests**

Run: `npx vitest run web/src/api.test.ts`
Expected: PASS (4 tests)

- [ ] **Step 6: Commit**

```bash
git add web/src/api.ts web/src/api.test.ts web/src/webauthn.ts
git commit -m "feat(web): typed API client and WebAuthn ceremony helpers"
```

---

### Task C3: Sign-in, enrolment, and layout

**Files:**
- Create: `web/src/routes/SignIn.tsx`, `web/src/routes/Enrol.tsx`, `web/src/components/Layout.tsx`, `web/src/components/StatusPill.tsx`
- Modify: `web/src/App.tsx`, `web/src/styles.css`

**Interfaces:**
- Consumes: C2's `api` and `webauthn` modules
- Produces: `<Layout>`, `<StatusPill status=... />` used by C4

- [ ] **Step 1: Build `Layout.tsx`**

Header with the product name, the signed-in email (from `getMe`, tolerating a 401 by rendering signed-out), and a Sign out button calling `api.signOut()` then navigating to `/signin`.

- [ ] **Step 2: Build `StatusPill.tsx`**

Maps `pending | approved | denied | expired` to a coloured pill. Colours come from CSS classes in `styles.css` — **no inline `style` attributes anywhere in the app**, because `styleSrc` is `'self'` with no `'unsafe-inline'`.

- [ ] **Step 3: Build `SignIn.tsx`**

Email input, "Continue with passkey" button calling `signIn(email)`, then navigate to `/requests`. On `ApiError`, render the server's message verbatim — the server already writes deliberately opaque messages for anti-enumeration, so the UI must not add detail the server withheld.

- [ ] **Step 4: Build `Enrol.tsx`**

Reads `?principal=` and `?token=` from the query string, calls `enrol(principal, token)` on a button press, and reports success or the server's error message. Then links to `/signin`.

- [ ] **Step 5: Wire the routes in `App.tsx` and verify the build**

```bash
npm run build:web
```

Expected: build succeeds, `web/dist/assets/` contains hashed `.js` and `.css`.

- [ ] **Step 6: Commit**

```bash
git add web/src
git commit -m "feat(web): sign-in, enrolment, and shared layout"
```

---

### Task C4: Request history, detail, and the email landing page

**Files:**
- Create: `web/src/routes/Requests.tsx`, `web/src/routes/Request.tsx`, `web/src/routes/ApprovalLink.tsx`, `web/src/components/SummaryCard.tsx`, `web/src/components/AuditTrail.tsx`
- Modify: `web/src/App.tsx`, `web/src/styles.css`

- [ ] **Step 1: Build `SummaryCard.tsx`**

Takes `summary: RenderedSummary | null`. When null, renders "Details were deleted when this request resolved" and the `payload_hash` — **never** a cached copy of the text. This component is where design-doc §7 becomes visible to the user, so the copy must be honest about it rather than showing a blank.

- [ ] **Step 2: Build `Requests.tsx`**

Filter tabs (All / Pending / Approved / Denied / Expired) driven by `?status=`, a list of rows, and a "Load more" button using `next_before`. On `ApiError` with `code` of `no_session` or `session_expired`, redirect to `/signin`.

- [ ] **Step 3: Build `Request.tsx`**

Detail view: `<SummaryCard>`, status, requester, hash, approvals progress, `<AuditTrail>`, and — when the status is `pending` and `my_decision` is null — Approve and Deny buttons calling `decide(...)`. Both buttons must trigger the passkey ceremony; neither may submit on click alone. After a decision, refetch the detail rather than optimistically mutating local state, so the displayed status is always the server's.

- [ ] **Step 4: Build `ApprovalLink.tsx`**

Calls `resolveLink(token)`, then renders the same detail view. Because `/web/requests/:id` requires a session and this visitor may not have one, fetch the request through `GET /v1/attestations/:id` (which needs no session) and pass the resolved `principal_id` into `decide(...)`. On `unknown_link`, render "This link is not valid" plus a link to `/signin`.

- [ ] **Step 5: Verify the build and commit**

```bash
npm run build:web
git add web/src
git commit -m "feat(web): request history, detail with audit trail, and email landing page"
```

---

## Workstream D — Removal, build, and docs

### Task D1: Delete push, the PWA, and iOS

**Files:** deletions per spec §9

**Blocked by:** Task B2 must have landed the `notifyApprovers` → `emailApprovers` swap first, or the build breaks.

- [ ] **Step 1: Confirm nothing still imports the push modules**

```bash
grep -rn "push/send\|push/vapid\|routes.push\|notifyApprovers\|VapidKeys\|web-push" src demo tests --include=*.ts
```

Expected: no hits. If there are hits, stop — B2 has not landed. Do not proceed.

- [ ] **Step 2: Delete the files**

```bash
git rm -r src/push src/api/routes.push.ts src/api/routes.push.test.ts \
          demo/public ios tests/e2e/push-approval.spec.ts
```

- [ ] **Step 3: Remove the dependency and the VAPID key file handling**

```bash
npm uninstall web-push @types/web-push
```

Then check `keys/vapid-keys.json` is no longer read anywhere: `grep -rn "vapid" src/ --include=*.ts` must return nothing.

- [ ] **Step 4: Run the full suite**

```bash
npm test
```

Expected: PASS. Any failure here is a real regression from the deletion, not an expected casualty.

- [ ] **Step 5: Commit**

Stage explicit paths only — never `git add -A`. Other workers have uncommitted
changes in this same working tree, and `-A` would sweep their half-finished
work into your commit.

```bash
git add -u src/push src/api/routes.push.ts src/api/routes.push.test.ts \
           demo/public ios tests/e2e/push-approval.spec.ts
git add package.json package-lock.json
git commit -m "refactor: remove Web Push, the PWA, and the native iOS app"
```

---

### Task D2: Docker and CI build the SPA

**Files:** `Dockerfile`, `.dockerignore`, `.github/workflows/*.yml`, `package.json`

- [ ] **Step 1: Add the build stage to `Dockerfile`**

The image must run `npm run build:web` after `npm ci` and before the runtime stage copies files, and the runtime stage must include `web/dist`. Keep the existing non-root user and graceful-shutdown handling untouched.

- [ ] **Step 2: Add `web/dist` to `.gitignore` and keep `web/src` out of `.dockerignore`**

- [ ] **Step 3: Add the CI step**

In the workflow, add `npm run build:web` before the e2e job, since Playwright now drives the built SPA rather than static demo pages.

- [ ] **Step 4: Verify the image builds and serves the SPA**

```bash
docker build -t human-attest:test .
docker run --rm -d -p 3001:3000 --name ha-test \
  -e APP_BASE_URL=http://localhost:3001 human-attest:test
sleep 3
curl -sf http://localhost:3001/healthz
curl -s http://localhost:3001/ | grep -q '<div id="root">' && echo "SPA served"
docker rm -f ha-test
```

Expected: `/healthz` responds and the SPA shell is served at `/`.

- [ ] **Step 5: Commit**

```bash
git add Dockerfile .dockerignore .github package.json .gitignore
git commit -m "build: build the SPA in Docker and CI"
```

---

### Task D3: Rewrite the docs

**Files:** `README.md`, `docs/PRODUCTION.md`, `docs/api/reference.md`, `docs/integration/quickstart.md`, `docs/human-attest-mvp.md`

- [ ] **Step 1: `README.md`**

Rewrite the run/enrol/demo sections around email + the SPA. Replace the "Prototype limitations" bullets about push and the missing native app with the real current ones: unencrypted signing key on disk, no device-loss recovery, `SMTP_URL` required in production, and **resolved requests show metadata only because the payload is purged**.

- [ ] **Step 2: `docs/api/reference.md`**

Delete the push-subscription endpoints. Document every `/web/*` route with its auth requirement, request and response shapes, and the new error codes: `unknown_link`, `no_session`, `session_expired`, `login_challenge_invalid`.

- [ ] **Step 3: `docs/PRODUCTION.md`**

Add `SMTP_URL`, `MAIL_FROM`, `MAIL_DIR`, `SESSION_TTL_HOURS` to the env table, note the boot guard that refuses production without `SMTP_URL`, and remove the VAPID key section.

- [ ] **Step 4: `docs/human-attest-mvp.md` §9**

Replace the three push/PWA/native constraints. The headless-testing limitation is now **resolved** — say so, and say why (email lands on disk, so the e2e suite drives the real notification path).

- [ ] **Step 5: `docs/integration/quickstart.md`**

Update the walkthrough: create a principal → the enrolment email arrives (or read `mail/*.eml` locally) → enrol → the agent requests an attestation → the approval email arrives → approve → verify.

- [ ] **Step 6: Commit**

```bash
git add README.md docs
git commit -m "docs: rewrite around email delivery and the web UI"
```

---

## Workstream E — QA

### Task E1: Security suite for the new surfaces

**Files:**
- Create: `tests/security/session-approval-separation.test.ts`, `tests/security/link-token-capability.test.ts`, `tests/security/history-isolation.test.ts`

Each is a real attack test that fails if the property breaks.

- [ ] **Step 1: `session-approval-separation.test.ts`**

Prove both directions:
1. Capture a valid sign-in assertion. Submit it to `POST /v1/attestations/:id/decision`. Assert it is rejected (`binding_mismatch`) and that no `attestation_approvals` row exists.
2. Capture a valid approval assertion. Submit it to `POST /web/session`. Assert 401 and no `sessions` row.

Also assert that a login challenge is single-use: replaying the same successful sign-in payload twice yields one session, not two.

- [ ] **Step 2: `link-token-capability.test.ts`**

1. `GET /web/link/:token` never changes `attestations.status`, never inserts an `attestation_approvals` row.
2. There is no route that accepts a link token and mutates state — enumerate the registered routes and assert none outside `/web/link/:token` reads the token param.
3. A link token belonging to principal A cannot be used to decide as principal B: resolve A's link, then attempt `POST /v1/attestations/:id/decision` with `principal_id` = B. Assert rejection.

- [ ] **Step 3: `history-isolation.test.ts`**

1. `GET /web/requests` for principal B never contains an attestation naming only A.
2. `GET /web/requests/:id` for a non-approver returns exactly the same status and body as for a nonexistent id.
3. After resolution, no response from any `/web/*` route contains any substring of the original payload. Seed a payload with a distinctive sentinel (`"recipient_name": "ZZQQX-SENTINEL"`), resolve, then assert the sentinel appears in no response body and in no `audit_log.detail`.

- [ ] **Step 4: Run and commit**

```bash
npx vitest run tests/security/
git add tests/security
git commit -m "test(security): session/approval separation, link capability limits, history isolation"
```

---

### Task E2: End-to-end suite driving the real email

**Files:**
- Modify: `tests/e2e/fixtures.ts`, `tests/e2e/server.ts`, `tests/e2e/flow.spec.ts`, `tests/e2e/multi-approver.spec.ts`
- Create: `tests/e2e/email-approval.spec.ts`

- [ ] **Step 1: Add a mail helper to `fixtures.ts`**

```ts
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

/**
 * Polls the file transport's output directory for a message addressed to
 * `to`, and returns the approval link it contains. This is the whole point of
 * the file transport: the e2e suite exercises the genuine notification path
 * -- render, send, deliver, extract, click -- rather than reaching around it
 * into the database for a token the real user would never have.
 */
export async function waitForLink(
  mailDir: string, to: string, timeoutMs = 5000,
): Promise<string> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    for (const f of readdirSync(mailDir).filter((n) => n.endsWith(".eml"))) {
      const body = readFileSync(join(mailDir, f), "utf8");
      if (!body.includes(`To: ${to}`)) continue;
      const m = body.match(/https?:\/\/[^\s"<]+\/a\/[A-Za-z0-9_-]+/);
      if (m) return m[0];
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`no approval email for ${to} within ${timeoutMs}ms`);
}
```

Point `tests/e2e/server.ts` at a per-run temp `MAIL_DIR` and export it.

- [ ] **Step 2: Write `tests/e2e/email-approval.spec.ts`**

Full loop with a CDP virtual authenticator: create principal → read the enrolment email → enrol → agent creates an attestation → `waitForLink` → navigate to the link → click Approve → Face ID (virtual) → assert the page shows Approved → assert the agent's token verifies against the original action hash.

- [ ] **Step 3: Update the existing specs**

`flow.spec.ts` and `multi-approver.spec.ts` currently drive `demo/public/index.html`. Repoint them at the SPA routes. Delete assertions that referenced push. **Do not weaken any assertion about the challenge binding or the signed decision.**

- [ ] **Step 4: Run**

```bash
npm run build:web && npm run e2e
```

Expected: all specs pass.

- [ ] **Step 5: Commit**

```bash
git add tests/e2e
git commit -m "test(e2e): drive the real email delivery path end to end"
```

---

### Task E3: Full verification and review

- [ ] **Step 1: Everything green**

```bash
npx tsc --noEmit
npm test
npm run build:web
npm run e2e
```

All four must pass. Paste the real output — do not summarize.

- [ ] **Step 2: Grep for regressions against the global constraints**

```bash
# The challenge binding must be untouched
git diff main --stat -- src/webauthn src/crypto src/actions   # expect: empty

# No inline styles (CSP styleSrc is 'self')
grep -rn 'style={{' web/src                                    # expect: no hits

# No retained payload text after purge
grep -rn 'canonical_json' src/api                              # review every hit by hand
```

- [ ] **Step 3: Run the project's own review skill**

Invoke `/code-review` on the branch and address anything it finds at CONFIRMED severity.

- [ ] **Step 4: Commit any fixes**

```bash
git add -A && git commit -m "fix: address review findings"
```

---

## Self-Review

**Spec coverage:** §2 D1→C2/E1, D2→B3, D3→A1/A3, D4→D1, D5→C1, D6→B4/C4/E1, D7→B3/E1, D8→B4/E1. §4.1→A1–A3. §4.2→B1. §4.3→B3/B4. §4.4→C1–C4. §5→B2 + E2. §6→B1/B3/B4. §7→B4/C4/E1. §8→E1/E2. §9→D1. §10→B1. §12→B2. All covered.

**Type consistency:** `EmailTransport`/`EmailMessage` identical in A1, A3, B2. `RequestListItem`/`RequestDetail` identical in the frozen contract, B4, and C2. `emailApprovers` signature identical in B2's test, implementation, and call site.
