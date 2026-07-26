# Human-Attest MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a local prototype that proves a human cryptographically authorized a specific agent action, using the WebAuthn challenge as the action hash.

**Architecture:** A Fastify service over SQLite. A caller submits a structured action; the service canonicalizes it (RFC 8785), hashes it, and uses that hash as the WebAuthn authentication challenge, so the authenticator provably signs *that action*. On quorum, the service issues an ES256 JWS whose `act` claim is the action hash, verifiable offline against a published JWKS.

**Tech Stack:** TypeScript (Node 20+, ESM), Fastify, `@simplewebauthn/server` + `@simplewebauthn/browser`, `jose`, `canonicalize`, `better-sqlite3`, Vitest, Playwright.

**Spec:** [`docs/superpowers/specs/2026-07-26-human-attest-mvp-design.md`](../specs/2026-07-26-human-attest-mvp-design.md)

## Global Constraints

- Node 20+, ESM only (`"type": "module"`). No CommonJS.
- TypeScript `strict: true`. No `any` in `src/`.
- `src/types.ts` is frozen after Task 1. Changes go through the lead, never a teammate.
- All hashes are the string form `sha256:<lowercase-hex>`.
- Canonicalization is RFC 8785 (JCS). Never `JSON.stringify` for anything that gets hashed.
- **Fail closed.** Every ambiguous or failed check rejects. Never default to allow.
- Display text is never accepted from a caller. Summaries render server-side only.
- Every rejection writes an `audit_log` row.
- E2E is Chromium-only (CDP virtual authenticator).
- RP ID is `localhost`, origin `http://localhost:3000` throughout.

---

## File Structure

```
package.json, tsconfig.json, vitest.config.ts, playwright.config.ts
src/
  types.ts                  frozen contract
  crypto/canonical.ts       JCS canonicalization + hashing
  crypto/tokens.ts          ES256 keys, JWS sign/verify, JWKS
  actions/schemas.ts        per-type payload validation
  actions/render.ts         canonical JSON -> RenderedSummary
  db/schema.sql             DDL
  db/index.ts               connection + migration runner
  db/queries.ts             typed query helpers
  webauthn/registration.ts  enrolment ceremony
  webauthn/authentication.ts  approval ceremony (challenge = action hash)
  api/server.ts             Fastify wiring
  api/routes.principals.ts  enrolment routes
  api/routes.attestations.ts  create / approve / deny
  api/routes.verify.ts      verify + JWKS
  api/state.ts              state machine + quorum + purge
demo/agent.ts               reference agent
demo/public/approve.html    approval page
tests/integration/**, tests/e2e/**, tests/security/**
docs/api/**, docs/integration/**, README.md
```

---

## Task 1: Scaffolding and the frozen contract

**Owner:** Lead. No other task starts until this is committed.

**Files:**
- Create: `package.json`, `tsconfig.json`, `vitest.config.ts`, `.gitignore`, `src/types.ts`

**Interfaces:**
- Consumes: nothing
- Produces: every type in `src/types.ts`, imported by all later tasks

- [ ] **Step 1: Initialise the project**

```bash
cd CS/project
npm init -y
npm pkg set type=module
npm i fastify better-sqlite3 jose canonicalize @simplewebauthn/server @simplewebauthn/browser
npm i -D typescript @types/node @types/better-sqlite3 vitest tsx @playwright/test
```

- [ ] **Step 2: Write `tsconfig.json`**

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ES2022",
    "moduleResolution": "bundler",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "resolveJsonModule": true,
    "outDir": "dist",
    "types": ["node"]
  },
  "include": ["src", "tests", "demo"]
}
```

- [ ] **Step 3: Write `vitest.config.ts`**

```ts
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["src/**/*.test.ts", "tests/integration/**/*.test.ts", "tests/security/**/*.test.ts"],
    environment: "node",
  },
});
```

- [ ] **Step 4: Write `.gitignore`**

```
node_modules/
dist/
*.db
keys/
test-results/
```

- [ ] **Step 5: Write `src/types.ts`**

```ts
export type RiskTier = "low" | "medium" | "high" | "critical";
export type AttestationStatus = "pending" | "approved" | "denied" | "expired";
export type ActionType = "wire_transfer" | "send_email" | "sign_document" | "generic";
export type Decision = "approve" | "deny";

export interface ActionRequest {
  type: ActionType;
  payload: Record<string, unknown>;
  risk_tier: RiskTier;
}

export interface RenderedSummary {
  headline: string;
  fields: Array<{ label: string; value: string }>;
}

export interface CanonicalAction {
  type: ActionType;
  canonical_json: string;
  payload_hash: string;
  summary: RenderedSummary;
}

export interface AttestationRecord {
  id: string;
  action_id: string;
  status: AttestationStatus;
  required_approvals: number;
  approver_ids: string[];
  expires_at: string;
  resolved_at: string | null;
}

export interface AttestationToken {
  jti: string;
  sub: string;
  act: string;
  approvers: string[];
  mth: "passkey" | "passkey_multi";
  iat: number;
  exp: number;
}

export interface VerifyResult {
  valid: boolean;
  reason?: string;
  principal_id?: string;
  action_hash?: string;
  approved_at?: string;
}

export class FailClosedError extends Error {
  constructor(
    public readonly code: string,
    public readonly httpStatus: number,
    message: string,
  ) {
    super(message);
    this.name = "FailClosedError";
  }
}
```

- [ ] **Step 6: Commit**

```bash
git add package.json package-lock.json tsconfig.json vitest.config.ts .gitignore src/types.ts
git commit -m "chore: scaffold project and freeze shared types contract"
```

---

## Task 2: Canonicalization and hashing

**Owner:** Crypto Core

**Files:**
- Create: `src/crypto/canonical.ts`, `src/crypto/canonical.test.ts`

**Interfaces:**
- Consumes: nothing
- Produces: `canonicalize(value: unknown): string`, `hashCanonical(canonicalJson: string): string`, `hashPayload(payload: unknown): { canonical_json: string; payload_hash: string }`

- [ ] **Step 1: Write the failing test**

```ts
// src/crypto/canonical.test.ts
import { describe, it, expect } from "vitest";
import { canonicalize, hashCanonical, hashPayload } from "./canonical.js";

describe("canonicalize", () => {
  it("orders keys deterministically regardless of input order", () => {
    expect(canonicalize({ b: 1, a: 2 })).toBe(canonicalize({ a: 2, b: 1 }));
    expect(canonicalize({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
  });

  it("emits no insignificant whitespace", () => {
    expect(canonicalize({ a: [1, 2] })).toBe('{"a":[1,2]}');
  });

  it("orders nested keys too", () => {
    expect(canonicalize({ z: { y: 1, x: 2 } })).toBe('{"z":{"x":2,"y":1}}');
  });
});

describe("hashCanonical", () => {
  it("returns a prefixed lowercase hex sha256", () => {
    const h = hashCanonical('{"a":1}');
    expect(h).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it("is stable across calls", () => {
    expect(hashCanonical('{"a":1}')).toBe(hashCanonical('{"a":1}'));
  });
});

describe("hashPayload", () => {
  it("produces the same hash for semantically identical payloads", () => {
    const a = hashPayload({ amount: 100, currency: "USD" });
    const b = hashPayload({ currency: "USD", amount: 100 });
    expect(a.payload_hash).toBe(b.payload_hash);
  });

  it("produces different hashes when a value changes", () => {
    const a = hashPayload({ amount: 100 });
    const b = hashPayload({ amount: 101 });
    expect(a.payload_hash).not.toBe(b.payload_hash);
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run src/crypto/canonical.test.ts`
Expected: FAIL — cannot resolve `./canonical.js`

- [ ] **Step 3: Write the implementation**

```ts
// src/crypto/canonical.ts
import { createHash } from "node:crypto";
import jcs from "canonicalize";

/** RFC 8785 (JCS) canonical JSON. Never use JSON.stringify for hashed data. */
export function canonicalize(value: unknown): string {
  const out = jcs(value);
  if (out === undefined) {
    throw new Error("value is not canonicalizable");
  }
  return out;
}

export function hashCanonical(canonicalJson: string): string {
  const hex = createHash("sha256").update(canonicalJson, "utf8").digest("hex");
  return `sha256:${hex}`;
}

export function hashPayload(payload: unknown): {
  canonical_json: string;
  payload_hash: string;
} {
  const canonical_json = canonicalize(payload);
  return { canonical_json, payload_hash: hashCanonical(canonical_json) };
}

/** The 32 raw digest bytes, for use as a WebAuthn challenge. */
export function hashToBytes(payloadHash: string): Uint8Array {
  const hex = payloadHash.replace(/^sha256:/, "");
  if (!/^[0-9a-f]{64}$/.test(hex)) {
    throw new Error(`malformed hash: ${payloadHash}`);
  }
  return Uint8Array.from(Buffer.from(hex, "hex"));
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npx vitest run src/crypto/canonical.test.ts`
Expected: PASS, 7 tests

- [ ] **Step 5: Add a test for `hashToBytes` and re-run**

```ts
// append to src/crypto/canonical.test.ts
import { hashToBytes } from "./canonical.js";

describe("hashToBytes", () => {
  it("returns 32 bytes", () => {
    expect(hashToBytes(hashCanonical("{}")).length).toBe(32);
  });

  it("rejects a malformed hash", () => {
    expect(() => hashToBytes("sha256:zzz")).toThrow(/malformed hash/);
  });
});
```

Run: `npx vitest run src/crypto/canonical.test.ts`
Expected: PASS, 9 tests

- [ ] **Step 6: Commit**

```bash
git add src/crypto/canonical.ts src/crypto/canonical.test.ts
git commit -m "feat: add RFC 8785 canonicalization and action hashing"
```

---

## Task 3: Token signing and offline verification

**Owner:** Crypto Core

**Files:**
- Create: `src/crypto/tokens.ts`, `src/crypto/tokens.test.ts`

**Interfaces:**
- Consumes: `AttestationToken`, `VerifyResult`, `FailClosedError` from `src/types.ts`
- Produces: `loadOrCreateKeypair(dir: string): Promise<Keypair>`, `signAttestation(kp, claims, ttlSeconds): Promise<string>`, `verifyAttestation(jwks, token): Promise<VerifyResult>`, `publicJwks(kp): Promise<{ keys: JWK[] }>`

- [ ] **Step 1: Write the failing test**

```ts
// src/crypto/tokens.test.ts
import { describe, it, expect, beforeAll } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadOrCreateKeypair, signAttestation, verifyAttestation, publicJwks } from "./tokens.js";

let kp: Awaited<ReturnType<typeof loadOrCreateKeypair>>;
let jwks: Awaited<ReturnType<typeof publicJwks>>;

const claims = {
  jti: "att_1",
  sub: "prin_1",
  act: "sha256:" + "a".repeat(64),
  approvers: ["prin_1"],
  mth: "passkey" as const,
};

beforeAll(async () => {
  kp = await loadOrCreateKeypair(mkdtempSync(join(tmpdir(), "ha-keys-")));
  jwks = await publicJwks(kp);
});

describe("attestation tokens", () => {
  it("round-trips a valid token", async () => {
    const token = await signAttestation(kp, claims, 300);
    const result = await verifyAttestation(jwks, token);
    expect(result.valid).toBe(true);
    expect(result.action_hash).toBe(claims.act);
    expect(result.principal_id).toBe("prin_1");
  });

  it("rejects a token signed by a different key", async () => {
    const other = await loadOrCreateKeypair(mkdtempSync(join(tmpdir(), "ha-other-")));
    const forged = await signAttestation(other, claims, 300);
    const result = await verifyAttestation(jwks, forged);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("signature_invalid");
  });

  it("rejects an expired token", async () => {
    const token = await signAttestation(kp, claims, -1);
    const result = await verifyAttestation(jwks, token);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("expired");
  });

  it("rejects a tampered payload", async () => {
    const token = await signAttestation(kp, claims, 300);
    const [h, , s] = token.split(".");
    const swapped = Buffer.from(
      JSON.stringify({ ...claims, act: "sha256:" + "b".repeat(64) }),
    ).toString("base64url");
    const result = await verifyAttestation(jwks, `${h}.${swapped}.${s}`);
    expect(result.valid).toBe(false);
  });

  it("publishes a public JWKS with no private material", async () => {
    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0]).not.toHaveProperty("d");
  });

  it("reuses an existing keypair on the same directory", async () => {
    const dir = mkdtempSync(join(tmpdir(), "ha-reuse-"));
    const a = await publicJwks(await loadOrCreateKeypair(dir));
    const b = await publicJwks(await loadOrCreateKeypair(dir));
    expect(a.keys[0]).toEqual(b.keys[0]);
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run src/crypto/tokens.test.ts`
Expected: FAIL — cannot resolve `./tokens.js`

- [ ] **Step 3: Write the implementation**

```ts
// src/crypto/tokens.ts
import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import {
  generateKeyPair, exportJWK, importJWK, SignJWT, jwtVerify,
  type JWK, type KeyLike,
} from "jose";
import type { AttestationToken, VerifyResult } from "../types.js";

export interface Keypair {
  privateKey: KeyLike;
  publicJwk: JWK;
  kid: string;
}

const ALG = "ES256";

export async function loadOrCreateKeypair(dir: string): Promise<Keypair> {
  mkdirSync(dir, { recursive: true });
  const path = join(dir, "signing-key.json");

  if (existsSync(path)) {
    const stored = JSON.parse(readFileSync(path, "utf8")) as {
      privateJwk: JWK; publicJwk: JWK; kid: string;
    };
    return {
      privateKey: (await importJWK(stored.privateJwk, ALG)) as KeyLike,
      publicJwk: stored.publicJwk,
      kid: stored.kid,
    };
  }

  const { privateKey, publicKey } = await generateKeyPair(ALG, { extractable: true });
  const privateJwk = await exportJWK(privateKey);
  const publicJwk = await exportJWK(publicKey);
  const kid = `k_${Date.now()}`;
  publicJwk.kid = kid;
  publicJwk.alg = ALG;
  publicJwk.use = "sig";

  writeFileSync(path, JSON.stringify({ privateJwk, publicJwk, kid }, null, 2), { mode: 0o600 });
  return { privateKey: privateKey as KeyLike, publicJwk, kid };
}

export async function publicJwks(kp: Keypair): Promise<{ keys: JWK[] }> {
  return { keys: [kp.publicJwk] };
}

type Claims = Omit<AttestationToken, "iat" | "exp">;

export async function signAttestation(
  kp: Keypair, claims: Claims, ttlSeconds: number,
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({
    act: claims.act,
    approvers: claims.approvers,
    mth: claims.mth,
  })
    .setProtectedHeader({ alg: ALG, kid: kp.kid })
    .setJti(claims.jti)
    .setSubject(claims.sub)
    .setIssuedAt(now)
    .setExpirationTime(now + ttlSeconds)
    .sign(kp.privateKey);
}

/**
 * Offline verification. Returns a result rather than throwing: a verifier
 * answering "no" truthfully is not an error condition.
 */
export async function verifyAttestation(
  jwks: { keys: JWK[] }, token: string,
): Promise<VerifyResult> {
  try {
    const key = (await importJWK(jwks.keys[0], ALG)) as KeyLike;
    const { payload } = await jwtVerify(token, key, { algorithms: [ALG] });
    return {
      valid: true,
      principal_id: payload.sub,
      action_hash: payload.act as string,
      approved_at: new Date((payload.iat ?? 0) * 1000).toISOString(),
    };
  } catch (err) {
    const code = (err as { code?: string }).code;
    if (code === "ERR_JWT_EXPIRED") return { valid: false, reason: "expired" };
    return { valid: false, reason: "signature_invalid" };
  }
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npx vitest run src/crypto/tokens.test.ts`
Expected: PASS, 6 tests

- [ ] **Step 5: Commit**

```bash
git add src/crypto/tokens.ts src/crypto/tokens.test.ts
git commit -m "feat: add ES256 attestation signing and offline verification"
```

---

## Task 4: Action payload schemas

**Owner:** API & State

**Files:**
- Create: `src/actions/schemas.ts`, `src/actions/schemas.test.ts`

**Interfaces:**
- Consumes: `ActionType`, `ActionRequest`, `FailClosedError` from `src/types.ts`
- Produces: `validateAction(req: unknown): ActionRequest` — throws `FailClosedError("payload_invalid", 400, ...)`

- [ ] **Step 1: Write the failing test**

```ts
// src/actions/schemas.test.ts
import { describe, it, expect } from "vitest";
import { validateAction } from "./schemas.js";
import { FailClosedError } from "../types.js";

const wire = {
  type: "wire_transfer",
  risk_tier: "high",
  payload: { amount: 2500000, currency: "USD", recipient_name: "Acme Corp", account_last4: "4821" },
};

describe("validateAction", () => {
  it("accepts a well-formed wire transfer", () => {
    expect(validateAction(wire).type).toBe("wire_transfer");
  });

  it("rejects an unknown action type", () => {
    expect(() => validateAction({ ...wire, type: "launch_missiles" })).toThrow(FailClosedError);
  });

  it("rejects a missing required field", () => {
    const { amount, ...rest } = wire.payload;
    expect(() => validateAction({ ...wire, payload: rest })).toThrow(/amount/);
  });

  it("rejects a wrong-typed field", () => {
    expect(() =>
      validateAction({ ...wire, payload: { ...wire.payload, amount: "2500000" } }),
    ).toThrow(/amount/);
  });

  it("rejects caller-supplied display text", () => {
    expect(() =>
      validateAction({ ...wire, payload: { ...wire.payload, summary: "Pay $50 to Netflix" } }),
    ).toThrow(/unexpected field/);
  });

  it("rejects an invalid risk tier", () => {
    expect(() => validateAction({ ...wire, risk_tier: "whenever" })).toThrow(FailClosedError);
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run src/actions/schemas.test.ts`
Expected: FAIL — cannot resolve `./schemas.js`

- [ ] **Step 3: Write the implementation**

```ts
// src/actions/schemas.ts
import { FailClosedError, type ActionRequest, type ActionType, type RiskTier } from "../types.js";

type FieldType = "string" | "number";
interface FieldSpec { name: string; type: FieldType; }

const SCHEMAS: Record<ActionType, FieldSpec[]> = {
  wire_transfer: [
    { name: "amount", type: "number" },
    { name: "currency", type: "string" },
    { name: "recipient_name", type: "string" },
    { name: "account_last4", type: "string" },
  ],
  send_email: [
    { name: "to", type: "string" },
    { name: "subject", type: "string" },
    { name: "body", type: "string" },
  ],
  sign_document: [
    { name: "document_name", type: "string" },
    { name: "document_hash", type: "string" },
  ],
  generic: [
    { name: "title", type: "string" },
    { name: "detail", type: "string" },
  ],
};

const TIERS: RiskTier[] = ["low", "medium", "high", "critical"];

function reject(message: string): never {
  throw new FailClosedError("payload_invalid", 400, message);
}

export function validateAction(input: unknown): ActionRequest {
  if (typeof input !== "object" || input === null) reject("action must be an object");
  const req = input as Record<string, unknown>;

  const type = req.type as ActionType;
  if (!(typeof type === "string" && type in SCHEMAS)) reject(`unknown action type: ${String(type)}`);

  const risk_tier = req.risk_tier as RiskTier;
  if (!TIERS.includes(risk_tier)) reject(`invalid risk_tier: ${String(risk_tier)}`);

  const payload = req.payload;
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
    reject("payload must be an object");
  }
  const p = payload as Record<string, unknown>;
  const spec = SCHEMAS[type];

  for (const field of spec) {
    const value = p[field.name];
    if (value === undefined) reject(`missing required field: ${field.name}`);
    if (typeof value !== field.type) {
      reject(`field ${field.name} must be a ${field.type}`);
    }
  }

  // Closed-world: anything not in the schema is refused, which is what stops a
  // caller smuggling display text into the payload.
  const allowed = new Set(spec.map((f) => f.name));
  for (const key of Object.keys(p)) {
    if (!allowed.has(key)) reject(`unexpected field: ${key}`);
  }

  return { type, risk_tier, payload: p };
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npx vitest run src/actions/schemas.test.ts`
Expected: PASS, 6 tests

- [ ] **Step 5: Commit**

```bash
git add src/actions/schemas.ts src/actions/schemas.test.ts
git commit -m "feat: add closed-world action payload validation"
```

---

## Task 5: Server-side summary rendering

**Owner:** API & State

**Files:**
- Create: `src/actions/render.ts`, `src/actions/render.test.ts`

**Interfaces:**
- Consumes: `validateAction` (Task 4), `hashPayload` (Task 2), `ActionRequest`, `CanonicalAction`, `RenderedSummary`
- Produces: `renderSummary(type: ActionType, canonicalJson: string): RenderedSummary`, `prepareAction(input: unknown): CanonicalAction`

- [ ] **Step 1: Write the failing test**

```ts
// src/actions/render.test.ts
import { describe, it, expect } from "vitest";
import { prepareAction, renderSummary } from "./render.js";

const wire = {
  type: "wire_transfer",
  risk_tier: "high",
  payload: { amount: 2500000, currency: "USD", recipient_name: "Acme Corp", account_last4: "4821" },
};

describe("renderSummary", () => {
  it("formats a wire transfer headline from canonical json", () => {
    const { canonical_json } = prepareAction(wire);
    const s = renderSummary("wire_transfer", canonical_json);
    expect(s.headline).toBe("Wire $25,000.00 USD to Acme Corp");
    expect(s.fields).toContainEqual({ label: "Account", value: "••••4821" });
  });

  it("formats an email headline", () => {
    const { canonical_json } = prepareAction({
      type: "send_email", risk_tier: "low",
      payload: { to: "cfo@acme.test", subject: "Q3 numbers", body: "attached" },
    });
    expect(renderSummary("send_email", canonical_json).headline)
      .toBe("Send email to cfo@acme.test");
  });
});

describe("prepareAction", () => {
  it("derives hash and summary together", () => {
    const a = prepareAction(wire);
    expect(a.payload_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(a.summary.headline).toContain("Acme Corp");
  });

  it("renders identically for reordered payload keys", () => {
    const reordered = {
      ...wire,
      payload: { account_last4: "4821", recipient_name: "Acme Corp", currency: "USD", amount: 2500000 },
    };
    expect(prepareAction(reordered)).toEqual(prepareAction(wire));
  });

  it("refuses caller-supplied summary text", () => {
    expect(() =>
      prepareAction({ ...wire, payload: { ...wire.payload, headline: "Pay $50" } }),
    ).toThrow(/unexpected field/);
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run src/actions/render.test.ts`
Expected: FAIL — cannot resolve `./render.js`

- [ ] **Step 3: Write the implementation**

```ts
// src/actions/render.ts
import { hashPayload } from "../crypto/canonical.js";
import { validateAction } from "./schemas.js";
import type { ActionType, CanonicalAction, RenderedSummary } from "../types.js";

function money(cents: number, currency: string): string {
  const value = (cents / 100).toLocaleString("en-US", {
    minimumFractionDigits: 2, maximumFractionDigits: 2,
  });
  return `$${value} ${currency}`;
}

/**
 * Renders from canonical JSON only. There is deliberately no code path by
 * which a caller can influence this text — that binding is the product.
 */
export function renderSummary(type: ActionType, canonicalJson: string): RenderedSummary {
  const p = JSON.parse(canonicalJson) as Record<string, never>;

  switch (type) {
    case "wire_transfer":
      return {
        headline: `Wire ${money(Number(p.amount), String(p.currency))} to ${p.recipient_name}`,
        fields: [
          { label: "Amount", value: money(Number(p.amount), String(p.currency)) },
          { label: "Recipient", value: String(p.recipient_name) },
          { label: "Account", value: `••••${p.account_last4}` },
        ],
      };
    case "send_email":
      return {
        headline: `Send email to ${p.to}`,
        fields: [
          { label: "To", value: String(p.to) },
          { label: "Subject", value: String(p.subject) },
        ],
      };
    case "sign_document":
      return {
        headline: `Sign document "${p.document_name}"`,
        fields: [
          { label: "Document", value: String(p.document_name) },
          { label: "Hash", value: String(p.document_hash) },
        ],
      };
    case "generic":
      return {
        headline: String(p.title),
        fields: [{ label: "Detail", value: String(p.detail) }],
      };
  }
}

export function prepareAction(input: unknown): CanonicalAction {
  const req = validateAction(input);
  const { canonical_json, payload_hash } = hashPayload(req.payload);
  return {
    type: req.type,
    canonical_json,
    payload_hash,
    summary: renderSummary(req.type, canonical_json),
  };
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npx vitest run src/actions/render.test.ts`
Expected: PASS, 5 tests

- [ ] **Step 5: Commit**

```bash
git add src/actions/render.ts src/actions/render.test.ts
git commit -m "feat: render action summaries server-side from canonical json"
```

---

## Task 6: Database schema and queries

**Owner:** API & State

**Files:**
- Create: `src/db/schema.sql`, `src/db/index.ts`, `src/db/queries.ts`, `src/db/queries.test.ts`

**Interfaces:**
- Consumes: types from `src/types.ts`
- Produces: `openDb(path: string): Database`, and from `queries.ts`: `insertPrincipal`, `getPrincipal`, `insertCredential`, `getCredentialsFor`, `updateSignCount`, `insertAction`, `getAction`, `purgeActionPayload`, `insertAttestation`, `getAttestation`, `insertApproval`, `getApprovals`, `setAttestationResolved`, `audit`

- [ ] **Step 1: Write `src/db/schema.sql`**

```sql
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS principals (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS credentials (
  id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL REFERENCES principals(id),
  credential_id TEXT NOT NULL UNIQUE,
  public_key BLOB NOT NULL,
  sign_count INTEGER NOT NULL DEFAULT 0,
  transports TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS actions (
  id TEXT PRIMARY KEY,
  requested_by TEXT NOT NULL,
  type TEXT NOT NULL,
  canonical_json TEXT,
  payload_hash TEXT NOT NULL,
  risk_tier TEXT NOT NULL,
  created_at TEXT NOT NULL,
  purged_at TEXT
);

CREATE TABLE IF NOT EXISTS attestations (
  id TEXT PRIMARY KEY,
  action_id TEXT NOT NULL REFERENCES actions(id),
  status TEXT NOT NULL,
  required_approvals INTEGER NOT NULL,
  approver_ids TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  resolved_at TEXT,
  token TEXT
);

CREATE TABLE IF NOT EXISTS attestation_approvals (
  id TEXT PRIMARY KEY,
  attestation_id TEXT NOT NULL REFERENCES attestations(id),
  principal_id TEXT NOT NULL REFERENCES principals(id),
  decision TEXT NOT NULL,
  client_data_json TEXT NOT NULL,
  signed_at TEXT NOT NULL,
  UNIQUE (attestation_id, principal_id)
);

CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  attestation_id TEXT,
  event TEXT NOT NULL,
  actor TEXT,
  detail TEXT,
  created_at TEXT NOT NULL
);
```

- [ ] **Step 2: Write the failing test**

```ts
// src/db/queries.test.ts
import { describe, it, expect, beforeEach } from "vitest";
import { openDb } from "./index.js";
import * as q from "./queries.js";
import type { Database } from "better-sqlite3";

let db: Database;

beforeEach(() => { db = openDb(":memory:"); });

describe("principals and credentials", () => {
  it("round-trips a principal", () => {
    q.insertPrincipal(db, { id: "prin_1", email: "a@b.test", display_name: "A" });
    expect(q.getPrincipal(db, "prin_1")?.email).toBe("a@b.test");
  });

  it("stores and lists credentials for a principal", () => {
    q.insertPrincipal(db, { id: "prin_1", email: "a@b.test", display_name: "A" });
    q.insertCredential(db, {
      id: "cred_1", principal_id: "prin_1", credential_id: "abc",
      public_key: Buffer.from([1, 2, 3]), transports: "internal",
    });
    expect(q.getCredentialsFor(db, "prin_1")).toHaveLength(1);
  });

  it("rejects a duplicate credential id", () => {
    q.insertPrincipal(db, { id: "prin_1", email: "a@b.test", display_name: "A" });
    const cred = {
      id: "cred_1", principal_id: "prin_1", credential_id: "abc",
      public_key: Buffer.from([1]), transports: null,
    };
    q.insertCredential(db, cred);
    expect(() => q.insertCredential(db, { ...cred, id: "cred_2" })).toThrow();
  });
});

describe("actions", () => {
  it("purges the payload but retains the hash", () => {
    q.insertAction(db, {
      id: "act_1", requested_by: "agent", type: "wire_transfer",
      canonical_json: '{"a":1}', payload_hash: "sha256:" + "a".repeat(64), risk_tier: "high",
    });
    q.purgeActionPayload(db, "act_1");
    const row = q.getAction(db, "act_1")!;
    expect(row.canonical_json).toBeNull();
    expect(row.purged_at).not.toBeNull();
    expect(row.payload_hash).toBe("sha256:" + "a".repeat(64));
  });
});

describe("approvals", () => {
  beforeEach(() => {
    q.insertPrincipal(db, { id: "prin_1", email: "a@b.test", display_name: "A" });
    q.insertAction(db, {
      id: "act_1", requested_by: "agent", type: "generic",
      canonical_json: "{}", payload_hash: "sha256:" + "a".repeat(64), risk_tier: "low",
    });
    q.insertAttestation(db, {
      id: "att_1", action_id: "act_1", required_approvals: 1,
      approver_ids: ["prin_1"], expires_at: new Date(Date.now() + 60000).toISOString(),
    });
  });

  it("refuses two approvals from the same principal", () => {
    const a = {
      id: "ap_1", attestation_id: "att_1", principal_id: "prin_1",
      decision: "approve" as const, client_data_json: "{}",
    };
    q.insertApproval(db, a);
    expect(() => q.insertApproval(db, { ...a, id: "ap_2" })).toThrow();
  });

  it("writes audit rows", () => {
    q.audit(db, { attestation_id: "att_1", event: "binding_mismatch", actor: "prin_1", detail: null });
    const rows = db.prepare("SELECT * FROM audit_log").all();
    expect(rows).toHaveLength(1);
  });
});
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `npx vitest run src/db/queries.test.ts`
Expected: FAIL — cannot resolve `./index.js`

- [ ] **Step 4: Write `src/db/index.ts`**

```ts
import Database from "better-sqlite3";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));

export function openDb(path: string): Database.Database {
  const db = new Database(path);
  db.exec(readFileSync(join(here, "schema.sql"), "utf8"));
  return db;
}

export type { Database } from "better-sqlite3";
```

- [ ] **Step 5: Write `src/db/queries.ts`**

```ts
import type { Database } from "better-sqlite3";
import type { AttestationStatus, Decision } from "../types.js";

const now = () => new Date().toISOString();

export function insertPrincipal(
  db: Database, p: { id: string; email: string; display_name: string },
): void {
  db.prepare(
    `INSERT INTO principals (id, email, display_name, status, created_at)
     VALUES (?, ?, ?, 'active', ?)`,
  ).run(p.id, p.email, p.display_name, now());
}

export function getPrincipal(db: Database, id: string) {
  return db.prepare(`SELECT * FROM principals WHERE id = ?`).get(id) as
    | { id: string; email: string; display_name: string; status: string }
    | undefined;
}

export function insertCredential(
  db: Database,
  c: { id: string; principal_id: string; credential_id: string;
       public_key: Buffer; transports: string | null },
): void {
  db.prepare(
    `INSERT INTO credentials (id, principal_id, credential_id, public_key, sign_count, transports, created_at)
     VALUES (?, ?, ?, ?, 0, ?, ?)`,
  ).run(c.id, c.principal_id, c.credential_id, c.public_key, c.transports, now());
}

export function getCredentialsFor(db: Database, principalId: string) {
  return db.prepare(`SELECT * FROM credentials WHERE principal_id = ?`).all(principalId) as Array<{
    id: string; principal_id: string; credential_id: string;
    public_key: Buffer; sign_count: number; transports: string | null;
  }>;
}

export function getCredential(db: Database, credentialId: string) {
  return db.prepare(`SELECT * FROM credentials WHERE credential_id = ?`).get(credentialId) as
    | { id: string; principal_id: string; credential_id: string;
        public_key: Buffer; sign_count: number }
    | undefined;
}

export function updateSignCount(db: Database, credentialId: string, count: number): void {
  db.prepare(`UPDATE credentials SET sign_count = ? WHERE credential_id = ?`)
    .run(count, credentialId);
}

export function insertAction(
  db: Database,
  a: { id: string; requested_by: string; type: string; canonical_json: string;
       payload_hash: string; risk_tier: string },
): void {
  db.prepare(
    `INSERT INTO actions (id, requested_by, type, canonical_json, payload_hash, risk_tier, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
  ).run(a.id, a.requested_by, a.type, a.canonical_json, a.payload_hash, a.risk_tier, now());
}

export function getAction(db: Database, id: string) {
  return db.prepare(`SELECT * FROM actions WHERE id = ?`).get(id) as
    | { id: string; requested_by: string; type: string; canonical_json: string | null;
        payload_hash: string; risk_tier: string; purged_at: string | null }
    | undefined;
}

export function purgeActionPayload(db: Database, id: string): void {
  db.prepare(`UPDATE actions SET canonical_json = NULL, purged_at = ? WHERE id = ?`)
    .run(now(), id);
}

export function insertAttestation(
  db: Database,
  a: { id: string; action_id: string; required_approvals: number;
       approver_ids: string[]; expires_at: string },
): void {
  db.prepare(
    `INSERT INTO attestations (id, action_id, status, required_approvals, approver_ids, expires_at, created_at)
     VALUES (?, ?, 'pending', ?, ?, ?, ?)`,
  ).run(a.id, a.action_id, a.required_approvals, JSON.stringify(a.approver_ids), a.expires_at, now());
}

export function getAttestation(db: Database, id: string) {
  const row = db.prepare(`SELECT * FROM attestations WHERE id = ?`).get(id) as
    | { id: string; action_id: string; status: AttestationStatus; required_approvals: number;
        approver_ids: string; expires_at: string; resolved_at: string | null; token: string | null }
    | undefined;
  return row ? { ...row, approver_ids: JSON.parse(row.approver_ids) as string[] } : undefined;
}

export function insertApproval(
  db: Database,
  a: { id: string; attestation_id: string; principal_id: string;
       decision: Decision; client_data_json: string },
): void {
  db.prepare(
    `INSERT INTO attestation_approvals (id, attestation_id, principal_id, decision, client_data_json, signed_at)
     VALUES (?, ?, ?, ?, ?, ?)`,
  ).run(a.id, a.attestation_id, a.principal_id, a.decision, a.client_data_json, now());
}

export function getApprovals(db: Database, attestationId: string) {
  return db.prepare(`SELECT * FROM attestation_approvals WHERE attestation_id = ?`)
    .all(attestationId) as Array<{ principal_id: string; decision: Decision; signed_at: string }>;
}

export function setAttestationResolved(
  db: Database, id: string, status: AttestationStatus, token: string | null,
): void {
  db.prepare(`UPDATE attestations SET status = ?, resolved_at = ?, token = ? WHERE id = ?`)
    .run(status, now(), token, id);
}

export function audit(
  db: Database,
  e: { attestation_id: string | null; event: string; actor: string | null; detail: string | null },
): void {
  db.prepare(
    `INSERT INTO audit_log (attestation_id, event, actor, detail, created_at) VALUES (?, ?, ?, ?, ?)`,
  ).run(e.attestation_id, e.event, e.actor, e.detail, now());
}
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `npx vitest run src/db/queries.test.ts`
Expected: PASS, 6 tests

- [ ] **Step 7: Commit**

```bash
git add src/db/
git commit -m "feat: add sqlite schema and typed query helpers"
```

---

## Task 7: WebAuthn registration ceremony

**Owner:** Ceremony

**Files:**
- Create: `src/webauthn/config.ts`, `src/webauthn/registration.ts`, `src/webauthn/registration.test.ts`

**Interfaces:**
- Consumes: `src/db/queries.js`, `FailClosedError`
- Produces: `RP` config object, `beginRegistration(db, principalId)`, `finishRegistration(db, principalId, expectedChallenge, response)`

- [ ] **Step 1: Write `src/webauthn/config.ts`**

```ts
export const RP = {
  name: "Human-Attest",
  id: "localhost",
  origin: "http://localhost:3000",
} as const;
```

- [ ] **Step 2: Write the failing test**

```ts
// src/webauthn/registration.test.ts
import { describe, it, expect, beforeEach } from "vitest";
import { openDb } from "../db/index.js";
import * as q from "../db/queries.js";
import { beginRegistration } from "./registration.js";
import type { Database } from "better-sqlite3";

let db: Database;

beforeEach(() => {
  db = openDb(":memory:");
  q.insertPrincipal(db, { id: "prin_1", email: "a@b.test", display_name: "A" });
});

describe("beginRegistration", () => {
  it("returns options bound to the configured rp", async () => {
    const opts = await beginRegistration(db, "prin_1");
    expect(opts.rp.id).toBe("localhost");
    expect(opts.challenge).toBeTruthy();
  });

  it("excludes already-registered credentials", async () => {
    q.insertCredential(db, {
      id: "cred_1", principal_id: "prin_1", credential_id: "YWJj",
      public_key: Buffer.from([1]), transports: null,
    });
    const opts = await beginRegistration(db, "prin_1");
    expect(opts.excludeCredentials?.map((c) => c.id)).toContain("YWJj");
  });

  it("rejects an unknown principal", async () => {
    await expect(beginRegistration(db, "prin_missing")).rejects.toThrow(/unknown principal/);
  });
});
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `npx vitest run src/webauthn/registration.test.ts`
Expected: FAIL — cannot resolve `./registration.js`

- [ ] **Step 4: Write the implementation**

```ts
// src/webauthn/registration.ts
import {
  generateRegistrationOptions, verifyRegistrationResponse,
  type RegistrationResponseJSON,
} from "@simplewebauthn/server";
import { randomUUID } from "node:crypto";
import type { Database } from "better-sqlite3";
import * as q from "../db/queries.js";
import { FailClosedError } from "../types.js";
import { RP } from "./config.js";

export async function beginRegistration(db: Database, principalId: string) {
  const principal = q.getPrincipal(db, principalId);
  if (!principal) throw new FailClosedError("unknown_principal", 404, "unknown principal");

  const existing = q.getCredentialsFor(db, principalId);

  return generateRegistrationOptions({
    rpName: RP.name,
    rpID: RP.id,
    userName: principal.email,
    userDisplayName: principal.display_name,
    attestationType: "none",
    excludeCredentials: existing.map((c) => ({ id: c.credential_id })),
    authenticatorSelection: { residentKey: "preferred", userVerification: "preferred" },
  });
}

export async function finishRegistration(
  db: Database,
  principalId: string,
  expectedChallenge: string,
  response: RegistrationResponseJSON,
): Promise<{ credential_id: string }> {
  const verification = await verifyRegistrationResponse({
    response,
    expectedChallenge,
    expectedOrigin: RP.origin,
    expectedRPID: RP.id,
  });

  if (!verification.verified || !verification.registrationInfo) {
    q.audit(db, { attestation_id: null, event: "registration_failed", actor: principalId, detail: null });
    throw new FailClosedError("registration_failed", 400, "registration could not be verified");
  }

  const { credential } = verification.registrationInfo;

  q.insertCredential(db, {
    id: `cred_${randomUUID()}`,
    principal_id: principalId,
    credential_id: credential.id,
    public_key: Buffer.from(credential.publicKey),
    transports: response.response.transports?.join(",") ?? null,
  });

  q.audit(db, { attestation_id: null, event: "credential_registered", actor: principalId, detail: credential.id });
  return { credential_id: credential.id };
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `npx vitest run src/webauthn/registration.test.ts`
Expected: PASS, 3 tests

- [ ] **Step 6: Commit**

```bash
git add src/webauthn/config.ts src/webauthn/registration.ts src/webauthn/registration.test.ts
git commit -m "feat: add webauthn registration ceremony"
```

---

## Task 8: Authentication ceremony bound to the action hash

**Owner:** Ceremony. This is the system's central mechanism — see spec §7.

**Files:**
- Create: `src/webauthn/authentication.ts`, `src/webauthn/authentication.test.ts`

**Interfaces:**
- Consumes: `hashToBytes` (Task 2), `src/db/queries.js`, `FailClosedError`
- Produces: `beginApproval(db, principalId, payloadHash)`, `finishApproval(db, principalId, payloadHash, response)` returning `{ client_data_json: string }`

- [ ] **Step 1: Write the failing test**

```ts
// src/webauthn/authentication.test.ts
import { describe, it, expect, beforeEach } from "vitest";
import { openDb } from "../db/index.js";
import * as q from "../db/queries.js";
import { beginApproval, challengeFor } from "./authentication.js";
import { hashCanonical } from "../crypto/canonical.js";
import type { Database } from "better-sqlite3";

let db: Database;
const hash = hashCanonical('{"amount":2500000}');

beforeEach(() => {
  db = openDb(":memory:");
  q.insertPrincipal(db, { id: "prin_1", email: "a@b.test", display_name: "A" });
  q.insertCredential(db, {
    id: "cred_1", principal_id: "prin_1", credential_id: "YWJj",
    public_key: Buffer.from([1]), transports: null,
  });
});

describe("challengeFor", () => {
  it("encodes the action hash as the base64url challenge", () => {
    const hex = hash.replace("sha256:", "");
    expect(challengeFor(hash)).toBe(Buffer.from(hex, "hex").toString("base64url"));
  });

  it("differs for different actions", () => {
    expect(challengeFor(hash)).not.toBe(challengeFor(hashCanonical('{"amount":1}')));
  });
});

describe("beginApproval", () => {
  it("uses the action hash as the challenge, not a random value", async () => {
    const opts = await beginApproval(db, "prin_1", hash);
    expect(opts.challenge).toBe(challengeFor(hash));
  });

  it("is deterministic for the same action", async () => {
    const a = await beginApproval(db, "prin_1", hash);
    const b = await beginApproval(db, "prin_1", hash);
    expect(a.challenge).toBe(b.challenge);
  });

  it("restricts to the principal's own credentials", async () => {
    const opts = await beginApproval(db, "prin_1", hash);
    expect(opts.allowCredentials?.map((c) => c.id)).toEqual(["YWJj"]);
  });

  it("rejects a principal with no enrolled credential", async () => {
    q.insertPrincipal(db, { id: "prin_2", email: "c@d.test", display_name: "C" });
    await expect(beginApproval(db, "prin_2", hash)).rejects.toThrow(/no enrolled credential/);
  });

  it("rejects a malformed action hash", async () => {
    await expect(beginApproval(db, "prin_1", "sha256:nope")).rejects.toThrow(/malformed hash/);
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run src/webauthn/authentication.test.ts`
Expected: FAIL — cannot resolve `./authentication.js`

- [ ] **Step 3: Write the implementation**

```ts
// src/webauthn/authentication.ts
import {
  generateAuthenticationOptions, verifyAuthenticationResponse,
  type AuthenticationResponseJSON,
} from "@simplewebauthn/server";
import type { Database } from "better-sqlite3";
import * as q from "../db/queries.js";
import { hashToBytes } from "../crypto/canonical.js";
import { FailClosedError } from "../types.js";
import { RP } from "./config.js";

/**
 * The action hash IS the challenge. WebAuthn already signs its challenge, so
 * this is what binds the authenticator's signature to one specific action —
 * no novel cryptography required.
 */
export function challengeFor(payloadHash: string): string {
  return Buffer.from(hashToBytes(payloadHash)).toString("base64url");
}

export async function beginApproval(db: Database, principalId: string, payloadHash: string) {
  const creds = q.getCredentialsFor(db, principalId);
  if (creds.length === 0) {
    throw new FailClosedError("no_credential", 400, "principal has no enrolled credential");
  }

  return generateAuthenticationOptions({
    rpID: RP.id,
    challenge: hashToBytes(payloadHash),
    allowCredentials: creds.map((c) => ({ id: c.credential_id })),
    userVerification: "preferred",
  });
}

export async function finishApproval(
  db: Database,
  principalId: string,
  payloadHash: string,
  response: AuthenticationResponseJSON,
): Promise<{ client_data_json: string }> {
  const cred = q.getCredential(db, response.id);
  if (!cred || cred.principal_id !== principalId) {
    throw new FailClosedError("unknown_credential", 401, "credential not recognised");
  }

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge: challengeFor(payloadHash),
      expectedOrigin: RP.origin,
      expectedRPID: RP.id,
      credential: {
        id: cred.credential_id,
        publicKey: new Uint8Array(cred.public_key),
        counter: cred.sign_count,
      },
    });
  } catch {
    // A challenge mismatch lands here: the human signed a different action
    // than the one being approved. Highest-signal event in the system.
    q.audit(db, {
      attestation_id: null, event: "binding_mismatch",
      actor: principalId, detail: payloadHash,
    });
    throw new FailClosedError("binding_mismatch", 400, "signed challenge does not match action");
  }

  if (!verification.verified) {
    q.audit(db, { attestation_id: null, event: "signature_invalid", actor: principalId, detail: null });
    throw new FailClosedError("signature_invalid", 401, "signature verification failed");
  }

  const newCount = verification.authenticationInfo.newCounter;
  if (cred.sign_count > 0 && newCount > 0 && newCount <= cred.sign_count) {
    q.audit(db, {
      attestation_id: null, event: "possible_credential_clone",
      actor: principalId, detail: `stored=${cred.sign_count} presented=${newCount}`,
    });
    throw new FailClosedError("counter_regression", 401, "authenticator counter regressed");
  }
  q.updateSignCount(db, cred.credential_id, newCount);

  return {
    client_data_json: Buffer.from(response.response.clientDataJSON, "base64url").toString("utf8"),
  };
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npx vitest run src/webauthn/authentication.test.ts`
Expected: PASS, 7 tests

- [ ] **Step 5: Commit**

```bash
git add src/webauthn/authentication.ts src/webauthn/authentication.test.ts
git commit -m "feat: bind webauthn approval challenge to the action hash"
```

---

## Task 9: State machine and quorum

**Owner:** API & State

**Files:**
- Create: `src/api/state.ts`, `src/api/state.test.ts`

**Interfaces:**
- Consumes: `src/db/queries.js`, `signAttestation` (Task 3), `AttestationStatus`, `Decision`, `FailClosedError`
- Produces: `effectiveStatus(db, attestationId)`, `recordDecision(db, kp, attestationId, principalId, decision, clientDataJson)`

- [ ] **Step 1: Write the failing test**

```ts
// src/api/state.test.ts
import { describe, it, expect, beforeEach } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openDb } from "../db/index.js";
import * as q from "../db/queries.js";
import { loadOrCreateKeypair, type Keypair } from "../crypto/tokens.js";
import { effectiveStatus, recordDecision } from "./state.js";
import type { Database } from "better-sqlite3";

let db: Database;
let kp: Keypair;
const HASH = "sha256:" + "a".repeat(64);

async function seed(required: number, approvers: string[], ttlMs = 60_000) {
  db = openDb(":memory:");
  for (const id of approvers) {
    q.insertPrincipal(db, { id, email: `${id}@t.test`, display_name: id });
  }
  q.insertAction(db, {
    id: "act_1", requested_by: "agent", type: "generic",
    canonical_json: "{}", payload_hash: HASH, risk_tier: "high",
  });
  q.insertAttestation(db, {
    id: "att_1", action_id: "act_1", required_approvals: required,
    approver_ids: approvers, expires_at: new Date(Date.now() + ttlMs).toISOString(),
  });
}

beforeEach(async () => {
  kp = await loadOrCreateKeypair(mkdtempSync(join(tmpdir(), "ha-state-")));
});

describe("single-approver quorum", () => {
  it("resolves to approved and issues a token", async () => {
    await seed(1, ["prin_1"]);
    const r = await recordDecision(db, kp, "att_1", "prin_1", "approve", "{}");
    expect(r.status).toBe("approved");
    expect(r.token).toBeTruthy();
  });

  it("resolves to denied with no token", async () => {
    await seed(1, ["prin_1"]);
    const r = await recordDecision(db, kp, "att_1", "prin_1", "deny", "{}");
    expect(r.status).toBe("denied");
    expect(r.token).toBeNull();
  });
});

describe("multi-party quorum", () => {
  it("stays pending until quorum is met", async () => {
    await seed(2, ["prin_1", "prin_2"]);
    const first = await recordDecision(db, kp, "att_1", "prin_1", "approve", "{}");
    expect(first.status).toBe("pending");
    expect(first.token).toBeNull();

    const second = await recordDecision(db, kp, "att_1", "prin_2", "approve", "{}");
    expect(second.status).toBe("approved");
    expect(second.token).toBeTruthy();
  });

  it("fails closed: one denial resolves the whole attestation", async () => {
    await seed(2, ["prin_1", "prin_2"]);
    await recordDecision(db, kp, "att_1", "prin_1", "approve", "{}");
    const r = await recordDecision(db, kp, "att_1", "prin_2", "deny", "{}");
    expect(r.status).toBe("denied");
  });

  it("lists every approver in the token claims", async () => {
    await seed(2, ["prin_1", "prin_2"]);
    await recordDecision(db, kp, "att_1", "prin_1", "approve", "{}");
    const r = await recordDecision(db, kp, "att_1", "prin_2", "approve", "{}");
    const claims = JSON.parse(Buffer.from(r.token!.split(".")[1], "base64url").toString());
    expect(claims.approvers.sort()).toEqual(["prin_1", "prin_2"]);
    expect(claims.mth).toBe("passkey_multi");
  });
});

describe("rejections", () => {
  it("refuses an approver outside the approver set", async () => {
    await seed(1, ["prin_1"]);
    q.insertPrincipal(db, { id: "prin_x", email: "x@t.test", display_name: "X" });
    await expect(recordDecision(db, kp, "att_1", "prin_x", "approve", "{}"))
      .rejects.toThrow(/not an approver/);
  });

  it("refuses a decision on a terminal attestation", async () => {
    await seed(1, ["prin_1"]);
    await recordDecision(db, kp, "att_1", "prin_1", "approve", "{}");
    await expect(recordDecision(db, kp, "att_1", "prin_1", "approve", "{}"))
      .rejects.toThrow(/already resolved/);
  });

  it("refuses a decision after expiry and reports expired", async () => {
    await seed(1, ["prin_1"], -1000);
    expect(effectiveStatus(db, "att_1")).toBe("expired");
    await expect(recordDecision(db, kp, "att_1", "prin_1", "approve", "{}"))
      .rejects.toThrow(/expired/);
  });

  it("purges the payload once resolved", async () => {
    await seed(1, ["prin_1"]);
    await recordDecision(db, kp, "att_1", "prin_1", "approve", "{}");
    expect(q.getAction(db, "act_1")!.canonical_json).toBeNull();
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run src/api/state.test.ts`
Expected: FAIL — cannot resolve `./state.js`

- [ ] **Step 3: Write the implementation**

```ts
// src/api/state.ts
import { randomUUID } from "node:crypto";
import type { Database } from "better-sqlite3";
import * as q from "../db/queries.js";
import { signAttestation, type Keypair } from "../crypto/tokens.js";
import { FailClosedError, type AttestationStatus, type Decision } from "../types.js";

const TOKEN_TTL_SECONDS = 300;

/** Expiry is evaluated on read, so a prototype with no scheduler cannot serve a stale pending row. */
export function effectiveStatus(db: Database, attestationId: string): AttestationStatus {
  const att = q.getAttestation(db, attestationId);
  if (!att) throw new FailClosedError("unknown_attestation", 404, "unknown attestation");
  if (att.status !== "pending") return att.status;
  return Date.parse(att.expires_at) <= Date.now() ? "expired" : "pending";
}

export async function recordDecision(
  db: Database,
  kp: Keypair,
  attestationId: string,
  principalId: string,
  decision: Decision,
  clientDataJson: string,
): Promise<{ status: AttestationStatus; token: string | null }> {
  const att = q.getAttestation(db, attestationId)!;
  const status = effectiveStatus(db, attestationId);

  if (status === "expired") {
    q.setAttestationResolved(db, attestationId, "expired", null);
    q.audit(db, { attestation_id: attestationId, event: "decision_after_expiry", actor: principalId, detail: null });
    throw new FailClosedError("expired", 410, "attestation has expired");
  }
  if (status !== "pending") {
    q.audit(db, { attestation_id: attestationId, event: "decision_after_resolution", actor: principalId, detail: status });
    throw new FailClosedError("already_resolved", 409, `attestation already resolved: ${status}`);
  }
  if (!att.approver_ids.includes(principalId)) {
    q.audit(db, { attestation_id: attestationId, event: "unauthorised_approver", actor: principalId, detail: null });
    throw new FailClosedError("not_an_approver", 403, "principal is not an approver for this attestation");
  }

  q.insertApproval(db, {
    id: `ap_${randomUUID()}`,
    attestation_id: attestationId,
    principal_id: principalId,
    decision,
    client_data_json: clientDataJson,
  });
  q.audit(db, { attestation_id: attestationId, event: `decision_${decision}`, actor: principalId, detail: null });

  const approvals = q.getApprovals(db, attestationId);

  // Fail closed: a single dissent stops the action outright. A dissenting
  // approver is a stop signal, not a vote to be outnumbered.
  if (approvals.some((a) => a.decision === "deny")) {
    q.setAttestationResolved(db, attestationId, "denied", null);
    q.purgeActionPayload(db, att.action_id);
    return { status: "denied", token: null };
  }

  const approvers = approvals.filter((a) => a.decision === "approve").map((a) => a.principal_id);
  if (approvers.length < att.required_approvals) {
    return { status: "pending", token: null };
  }

  const action = q.getAction(db, att.action_id)!;
  const token = await signAttestation(kp, {
    jti: attestationId,
    sub: approvers[0],
    act: action.payload_hash,
    approvers,
    mth: att.required_approvals > 1 ? "passkey_multi" : "passkey",
  }, TOKEN_TTL_SECONDS);

  q.setAttestationResolved(db, attestationId, "approved", token);
  q.purgeActionPayload(db, att.action_id);
  q.audit(db, { attestation_id: attestationId, event: "attestation_approved", actor: principalId, detail: null });

  return { status: "approved", token };
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npx vitest run src/api/state.test.ts`
Expected: PASS, 10 tests

- [ ] **Step 5: Commit**

```bash
git add src/api/state.ts src/api/state.test.ts
git commit -m "feat: add attestation state machine with fail-closed quorum"
```

---

## Task 10: HTTP surface

**Owner:** API & State

**Files:**
- Create: `src/api/server.ts`, `src/api/routes.principals.ts`, `src/api/routes.attestations.ts`, `src/api/routes.verify.ts`

**Interfaces:**
- Consumes: everything from Tasks 2–9
- Produces: `buildServer(opts): Promise<FastifyInstance>` with routes
  `POST /v1/principals`, `POST /v1/principals/:id/credentials/options`,
  `POST /v1/principals/:id/credentials`, `POST /v1/attestations`,
  `GET /v1/attestations/:id`, `POST /v1/attestations/:id/options`,
  `POST /v1/attestations/:id/decision`, `POST /v1/attestations/verify`,
  `GET /.well-known/jwks.json`

- [ ] **Step 1: Write `src/api/server.ts`**

```ts
import Fastify, { type FastifyInstance } from "fastify";
import fastifyStatic from "@fastify/static";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { openDb, type Database } from "../db/index.js";
import { loadOrCreateKeypair, type Keypair } from "../crypto/tokens.js";
import { FailClosedError } from "../types.js";
import { registerPrincipalRoutes } from "./routes.principals.js";
import { registerAttestationRoutes } from "./routes.attestations.js";
import { registerVerifyRoutes } from "./routes.verify.js";

const here = dirname(fileURLToPath(import.meta.url));

export interface AppContext { db: Database; kp: Keypair; }

export async function buildServer(
  opts: { dbPath?: string; keyDir?: string } = {},
): Promise<FastifyInstance & { ctx: AppContext }> {
  const app = Fastify({ logger: false }) as FastifyInstance & { ctx: AppContext };

  app.ctx = {
    db: openDb(opts.dbPath ?? ":memory:"),
    kp: await loadOrCreateKeypair(opts.keyDir ?? join(process.cwd(), "keys")),
  };

  await app.register(fastifyStatic, {
    root: join(here, "../../demo/public"),
    prefix: "/approve/",
  });

  app.setErrorHandler((err, _req, reply) => {
    if (err instanceof FailClosedError) {
      return reply.status(err.httpStatus).send({ error: err.code, message: err.message });
    }
    return reply.status(500).send({ error: "internal_error" });
  });

  registerPrincipalRoutes(app);
  registerAttestationRoutes(app);
  registerVerifyRoutes(app);

  return app;
}
```

Install the static plugin: `npm i @fastify/static`

- [ ] **Step 2: Write `src/api/routes.principals.ts`**

```ts
import { randomUUID } from "node:crypto";
import type { FastifyInstance } from "fastify";
import type { AppContext } from "./server.js";
import * as q from "../db/queries.js";
import { beginRegistration, finishRegistration } from "../webauthn/registration.js";

const pendingChallenges = new Map<string, string>();

export function registerPrincipalRoutes(app: FastifyInstance & { ctx: AppContext }): void {
  app.post("/v1/principals", async (req, reply) => {
    const { email, display_name } = req.body as { email: string; display_name: string };
    const id = `prin_${randomUUID()}`;
    q.insertPrincipal(app.ctx.db, { id, email, display_name });
    return reply.status(201).send({ principal_id: id });
  });

  app.post("/v1/principals/:id/credentials/options", async (req) => {
    const { id } = req.params as { id: string };
    const options = await beginRegistration(app.ctx.db, id);
    pendingChallenges.set(id, options.challenge);
    return options;
  });

  app.post("/v1/principals/:id/credentials", async (req, reply) => {
    const { id } = req.params as { id: string };
    const challenge = pendingChallenges.get(id);
    if (!challenge) return reply.status(400).send({ error: "no_pending_registration" });
    pendingChallenges.delete(id);
    const result = await finishRegistration(app.ctx.db, id, challenge, req.body as never);
    return reply.status(201).send(result);
  });
}
```

- [ ] **Step 3: Write `src/api/routes.attestations.ts`**

```ts
import { randomUUID } from "node:crypto";
import type { FastifyInstance } from "fastify";
import type { AppContext } from "./server.js";
import * as q from "../db/queries.js";
import { prepareAction, renderSummary } from "../actions/render.js";
import { beginApproval, finishApproval } from "../webauthn/authentication.js";
import { effectiveStatus, recordDecision } from "./state.js";
import { FailClosedError, type Decision } from "../types.js";

export function registerAttestationRoutes(app: FastifyInstance & { ctx: AppContext }): void {
  const { db } = app.ctx;

  app.post("/v1/attestations", async (req, reply) => {
    const body = req.body as {
      action: unknown; approver_ids: string[];
      required_approvals?: number; requested_by: string; ttl_seconds?: number;
    };

    const action = prepareAction(body.action);
    const actionId = `act_${randomUUID()}`;
    q.insertAction(db, {
      id: actionId, requested_by: body.requested_by, type: action.type,
      canonical_json: action.canonical_json, payload_hash: action.payload_hash,
      risk_tier: (body.action as { risk_tier: string }).risk_tier,
    });

    const attestationId = `att_${randomUUID()}`;
    q.insertAttestation(db, {
      id: attestationId, action_id: actionId,
      required_approvals: body.required_approvals ?? 1,
      approver_ids: body.approver_ids,
      expires_at: new Date(Date.now() + (body.ttl_seconds ?? 900) * 1000).toISOString(),
    });

    return reply.status(201).send({
      attestation_id: attestationId,
      status: "pending",
      payload_hash: action.payload_hash,
      summary: action.summary,
      approve_url: `http://localhost:3000/approve/index.html?attestation=${attestationId}`,
    });
  });

  app.get("/v1/attestations/:id", async (req) => {
    const { id } = req.params as { id: string };
    const att = q.getAttestation(db, id);
    if (!att) throw new FailClosedError("unknown_attestation", 404, "unknown attestation");
    const action = q.getAction(db, att.action_id)!;
    return {
      attestation_id: id,
      status: effectiveStatus(db, id),
      payload_hash: action.payload_hash,
      required_approvals: att.required_approvals,
      approvals: q.getApprovals(db, id).length,
      summary: action.canonical_json
        ? renderSummary(action.type as never, action.canonical_json)
        : null,
      token: att.token,
    };
  });

  app.post("/v1/attestations/:id/options", async (req) => {
    const { id } = req.params as { id: string };
    const { principal_id } = req.body as { principal_id: string };
    const att = q.getAttestation(db, id);
    if (!att) throw new FailClosedError("unknown_attestation", 404, "unknown attestation");
    const action = q.getAction(db, att.action_id)!;
    return beginApproval(db, principal_id, action.payload_hash);
  });

  app.post("/v1/attestations/:id/decision", async (req) => {
    const { id } = req.params as { id: string };
    const body = req.body as { principal_id: string; decision: Decision; response?: unknown };
    const att = q.getAttestation(db, id);
    if (!att) throw new FailClosedError("unknown_attestation", 404, "unknown attestation");
    const action = q.getAction(db, att.action_id)!;

    let clientDataJson = "{}";
    if (body.decision === "approve") {
      const result = await finishApproval(
        db, body.principal_id, action.payload_hash, body.response as never,
      );
      clientDataJson = result.client_data_json;
    }

    return recordDecision(db, app.ctx.kp, id, body.principal_id, body.decision, clientDataJson);
  });
}
```

- [ ] **Step 4: Write `src/api/routes.verify.ts`**

```ts
import type { FastifyInstance } from "fastify";
import type { AppContext } from "./server.js";
import { publicJwks, verifyAttestation } from "../crypto/tokens.js";

export function registerVerifyRoutes(app: FastifyInstance & { ctx: AppContext }): void {
  app.get("/.well-known/jwks.json", async () => publicJwks(app.ctx.kp));

  // Returns 200 with valid:false on a bad token — a verifier answering
  // truthfully is not an HTTP error.
  app.post("/v1/attestations/verify", async (req) => {
    const { token } = req.body as { token: string };
    return verifyAttestation(await publicJwks(app.ctx.kp), token);
  });
}
```

- [ ] **Step 5: Add an entrypoint and start script**

```ts
// src/main.ts
import { buildServer } from "./api/server.js";

const app = await buildServer({ dbPath: "human-attest.db", keyDir: "keys" });
await app.listen({ port: 3000, host: "127.0.0.1" });
console.log("human-attest listening on http://localhost:3000");
```

```bash
npm pkg set scripts.dev="tsx src/main.ts"
npm pkg set scripts.test="vitest run"
npm pkg set scripts.e2e="playwright test"
```

- [ ] **Step 6: Verify the server boots**

Run: `npm run dev`
Expected: `human-attest listening on http://localhost:3000`. Then in another shell:

```bash
curl -s localhost:3000/.well-known/jwks.json | head -c 80
```
Expected: JSON containing `"keys"`. Stop the server.

- [ ] **Step 7: Commit**

```bash
git add src/api/ src/main.ts package.json
git commit -m "feat: add http surface for enrolment, attestation, and verification"
```

---

## Task 11: Approval page and demo agent

**Owner:** QA

**Files:**
- Create: `demo/public/index.html`, `demo/agent.ts`

**Interfaces:**
- Consumes: the HTTP surface from Task 10
- Produces: a browsable approval page at `/approve/index.html`; `npm run demo`

- [ ] **Step 1: Write the approval page**

`@simplewebauthn/browser` ships a UMD bundle, so no build step is needed — serve it from `node_modules`.

```html
<!-- demo/public/index.html -->
<!doctype html>
<meta charset="utf-8" />
<title>Approve action</title>
<style>
  body { font: 16px/1.5 Georgia, serif; max-width: 34rem; margin: 4rem auto; padding: 0 1rem; }
  h1 { font: 600 1.3rem/1.3 system-ui, sans-serif; }
  dl { display: grid; grid-template-columns: max-content 1fr; gap: .4rem 1.5rem; }
  dt { font: 600 .75rem/1.6 system-ui, sans-serif; text-transform: uppercase; color: #666; }
  button { font: 600 .9rem system-ui, sans-serif; padding: .6rem 1.2rem; margin-right: .5rem; }
  #status { margin-top: 1.5rem; font-family: ui-monospace, monospace; font-size: .85rem; }
</style>

<h1 id="headline">Loading…</h1>
<dl id="fields"></dl>
<p>
  <button id="approve">Approve</button>
  <button id="deny">Deny</button>
</p>
<p id="status"></p>

<script src="/vendor/simplewebauthn-browser.js"></script>
<script type="module">
  const params = new URLSearchParams(location.search);
  const attestationId = params.get("attestation");
  const principalId = params.get("principal");
  const status = document.getElementById("status");

  const res = await fetch(`/v1/attestations/${attestationId}`);
  const att = await res.json();

  document.getElementById("headline").textContent =
    att.summary ? att.summary.headline : `Attestation is ${att.status}`;
  document.getElementById("fields").innerHTML = (att.summary?.fields ?? [])
    .map((f) => `<dt>${f.label}</dt><dd>${f.value}</dd>`).join("");

  document.getElementById("approve").onclick = async () => {
    status.textContent = "Requesting signature…";
    const optsRes = await fetch(`/v1/attestations/${attestationId}/options`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ principal_id: principalId }),
    });
    const response = await SimpleWebAuthnBrowser.startAuthentication({
      optionsJSON: await optsRes.json(),
    });
    const decision = await fetch(`/v1/attestations/${attestationId}/decision`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ principal_id: principalId, decision: "approve", response }),
    });
    status.textContent = JSON.stringify(await decision.json());
  };

  document.getElementById("deny").onclick = async () => {
    const decision = await fetch(`/v1/attestations/${attestationId}/decision`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ principal_id: principalId, decision: "deny" }),
    });
    status.textContent = JSON.stringify(await decision.json());
  };
</script>
```

- [ ] **Step 2: Serve the browser bundle**

Add to `src/api/server.ts`, after the existing `fastifyStatic` registration:

```ts
await app.register(fastifyStatic, {
  root: join(here, "../../node_modules/@simplewebauthn/browser/dist/bundle"),
  prefix: "/vendor/",
  decorateReply: false,
});
```

Then alias the filename:

```ts
app.get("/vendor/simplewebauthn-browser.js", (_req, reply) =>
  reply.sendFile("index.umd.min.js", join(here, "../../node_modules/@simplewebauthn/browser/dist/bundle")),
);
```

- [ ] **Step 3: Write the demo agent**

```ts
// demo/agent.ts
const API = "http://localhost:3000";

async function main(): Promise<void> {
  const principalId = process.argv[2];
  if (!principalId) throw new Error("usage: npm run demo -- <principal_id>");

  const created = await fetch(`${API}/v1/attestations`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({
      requested_by: "demo-agent",
      approver_ids: [principalId],
      required_approvals: 1,
      action: {
        type: "wire_transfer",
        risk_tier: "high",
        payload: {
          amount: 2500000, currency: "USD",
          recipient_name: "Acme Corp", account_last4: "4821",
        },
      },
    }),
  }).then((r) => r.json());

  console.log(`\nAction requires human approval.`);
  console.log(`  ${created.summary.headline}`);
  console.log(`\nApprove at:\n  ${created.approve_url}&principal=${principalId}\n`);

  // Block until the human resolves it.
  for (;;) {
    const att = await fetch(`${API}/v1/attestations/${created.attestation_id}`).then((r) => r.json());
    if (att.status !== "pending") {
      if (att.status !== "approved") {
        console.log(`Refusing to execute: attestation ${att.status}.`);
        return;
      }
      const verified = await fetch(`${API}/v1/attestations/verify`, {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ token: att.token }),
      }).then((r) => r.json());

      if (!verified.valid || verified.action_hash !== created.payload_hash) {
        console.log("Refusing to execute: token did not verify against this action.");
        return;
      }
      console.log("Verified. Executing wire transfer.");
      return;
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
}

await main();
```

```bash
npm pkg set scripts.demo="tsx demo/agent.ts"
```

- [ ] **Step 4: Verify the flow manually**

Run `npm run dev`, then create a principal and enrol a passkey in the browser, then:

```bash
npm run demo -- <principal_id>
```
Expected: the agent prints the headline and an approval URL, blocks, and after you approve in the browser prints `Verified. Executing wire transfer.`

- [ ] **Step 5: Commit**

```bash
git add demo/ src/api/server.ts package.json
git commit -m "feat: add approval page and reference demo agent"
```

---

## Task 12: E2E harness with a virtual authenticator

**Owner:** QA

**Files:**
- Create: `playwright.config.ts`, `tests/e2e/fixtures.ts`, `tests/e2e/flow.spec.ts`

**Interfaces:**
- Consumes: the running server from Task 10, the page from Task 11
- Produces: `withVirtualAuthenticator(page)` fixture used by all E2E specs

- [ ] **Step 1: Write `playwright.config.ts`**

```ts
import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "tests/e2e",
  use: { baseURL: "http://localhost:3000", browserName: "chromium" },
  webServer: {
    command: "npm run dev",
    url: "http://localhost:3000/.well-known/jwks.json",
    reuseExistingServer: true,
  },
});
```

- [ ] **Step 2: Write the virtual-authenticator fixture**

Playwright has no first-class WebAuthn API; it is reached through a CDP session. Chromium only.

```ts
// tests/e2e/fixtures.ts
import type { Page } from "@playwright/test";

export async function withVirtualAuthenticator(page: Page): Promise<string> {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  return authenticatorId;
}

export async function createPrincipal(baseURL: string, email: string): Promise<string> {
  const res = await fetch(`${baseURL}/v1/principals`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ email, display_name: email }),
  });
  return (await res.json()).principal_id as string;
}
```

- [ ] **Step 3: Write the end-to-end flow test**

```ts
// tests/e2e/flow.spec.ts
import { test, expect } from "@playwright/test";
import { withVirtualAuthenticator, createPrincipal } from "./fixtures.js";

const BASE = "http://localhost:3000";

test("a human approves an action and the token verifies against it", async ({ page }) => {
  await withVirtualAuthenticator(page);
  const principalId = await createPrincipal(BASE, `e2e-${Date.now()}@test.local`);

  // Enrol a passkey through the browser so the credential is real.
  await page.goto("/approve/enrol.html?principal=" + principalId);
  await page.click("#enrol");
  await expect(page.locator("#status")).toContainText("enrolled");

  const created = await fetch(`${BASE}/v1/attestations`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({
      requested_by: "e2e", approver_ids: [principalId], required_approvals: 1,
      action: {
        type: "wire_transfer", risk_tier: "high",
        payload: { amount: 2500000, currency: "USD", recipient_name: "Acme Corp", account_last4: "4821" },
      },
    }),
  }).then((r) => r.json());

  await page.goto(`/approve/index.html?attestation=${created.attestation_id}&principal=${principalId}`);

  // The summary the human sees is rendered server-side from the payload.
  await expect(page.locator("#headline")).toHaveText("Wire $25,000.00 USD to Acme Corp");

  await page.click("#approve");
  await expect(page.locator("#status")).toContainText("approved");

  const att = await fetch(`${BASE}/v1/attestations/${created.attestation_id}`).then((r) => r.json());
  const verified = await fetch(`${BASE}/v1/attestations/verify`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ token: att.token }),
  }).then((r) => r.json());

  expect(verified.valid).toBe(true);
  expect(verified.action_hash).toBe(created.payload_hash);
});

test("a denied action issues no token", async ({ page }) => {
  await withVirtualAuthenticator(page);
  const principalId = await createPrincipal(BASE, `e2e-deny-${Date.now()}@test.local`);

  await page.goto("/approve/enrol.html?principal=" + principalId);
  await page.click("#enrol");

  const created = await fetch(`${BASE}/v1/attestations`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({
      requested_by: "e2e", approver_ids: [principalId],
      action: { type: "generic", risk_tier: "low", payload: { title: "Test", detail: "d" } },
    }),
  }).then((r) => r.json());

  await page.goto(`/approve/index.html?attestation=${created.attestation_id}&principal=${principalId}`);
  await page.click("#deny");
  await expect(page.locator("#status")).toContainText("denied");

  const att = await fetch(`${BASE}/v1/attestations/${created.attestation_id}`).then((r) => r.json());
  expect(att.token).toBeNull();
});
```

- [ ] **Step 4: Add the enrolment page the tests depend on**

```html
<!-- demo/public/enrol.html -->
<!doctype html>
<meta charset="utf-8" />
<title>Enrol passkey</title>
<button id="enrol">Enrol passkey</button>
<p id="status"></p>
<script src="/vendor/simplewebauthn-browser.js"></script>
<script type="module">
  const principalId = new URLSearchParams(location.search).get("principal");
  document.getElementById("enrol").onclick = async () => {
    const optionsJSON = await fetch(`/v1/principals/${principalId}/credentials/options`, {
      method: "POST",
    }).then((r) => r.json());
    const response = await SimpleWebAuthnBrowser.startRegistration({ optionsJSON });
    const res = await fetch(`/v1/principals/${principalId}/credentials`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify(response),
    });
    document.getElementById("status").textContent =
      res.ok ? "enrolled" : "failed";
  };
</script>
```

- [ ] **Step 5: Run the E2E suite**

Run: `npx playwright install chromium && npm run e2e`
Expected: 2 passed

- [ ] **Step 6: Commit**

```bash
git add playwright.config.ts tests/e2e/ demo/public/enrol.html
git commit -m "test: add e2e flow with cdp virtual authenticator"
```

---

## Task 13: Integration tests across module seams

**Owner:** QA

**Files:**
- Create: `tests/integration/pipeline.test.ts`

**Interfaces:**
- Consumes: `prepareAction`, `challengeFor`, `signAttestation`, `verifyAttestation`, `buildServer`
- Produces: nothing consumed downstream

- [ ] **Step 1: Write the seam tests**

```ts
// tests/integration/pipeline.test.ts
import { describe, it, expect, beforeAll } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { prepareAction } from "../../src/actions/render.js";
import { challengeFor } from "../../src/webauthn/authentication.js";
import { hashToBytes } from "../../src/crypto/canonical.js";
import { loadOrCreateKeypair, signAttestation, verifyAttestation, publicJwks } from "../../src/crypto/tokens.js";
import { buildServer } from "../../src/api/server.js";

const wire = {
  type: "wire_transfer", risk_tier: "high",
  payload: { amount: 2500000, currency: "USD", recipient_name: "Acme Corp", account_last4: "4821" },
};

describe("canonicalize -> hash -> challenge", () => {
  it("carries one hash unchanged across the seam", () => {
    const action = prepareAction(wire);
    const challenge = challengeFor(action.payload_hash);
    expect(Buffer.from(challenge, "base64url")).toEqual(Buffer.from(hashToBytes(action.payload_hash)));
  });

  it("changes the challenge when any payload field changes", () => {
    const a = challengeFor(prepareAction(wire).payload_hash);
    const b = challengeFor(prepareAction({
      ...wire, payload: { ...wire.payload, amount: 2500001 },
    }).payload_hash);
    expect(a).not.toBe(b);
  });

  it("keeps the summary and the hash derived from the same bytes", () => {
    const action = prepareAction(wire);
    expect(action.summary.headline).toContain("25,000.00");
    expect(prepareAction(wire).payload_hash).toBe(action.payload_hash);
  });
});

describe("hash -> token -> verify", () => {
  it("round-trips the action hash into the act claim", async () => {
    const kp = await loadOrCreateKeypair(mkdtempSync(join(tmpdir(), "ha-int-")));
    const action = prepareAction(wire);
    const token = await signAttestation(kp, {
      jti: "att_1", sub: "prin_1", act: action.payload_hash,
      approvers: ["prin_1"], mth: "passkey",
    }, 300);
    const result = await verifyAttestation(await publicJwks(kp), token);
    expect(result.action_hash).toBe(action.payload_hash);
  });
});

describe("http surface", () => {
  let app: Awaited<ReturnType<typeof buildServer>>;

  beforeAll(async () => {
    app = await buildServer({ dbPath: ":memory:", keyDir: mkdtempSync(join(tmpdir(), "ha-http-")) });
  });

  it("creates an attestation and returns a server-rendered summary", async () => {
    const principal = await app.inject({
      method: "POST", url: "/v1/principals",
      payload: { email: "int@test.local", display_name: "Int" },
    });
    const principalId = principal.json().principal_id;

    const res = await app.inject({
      method: "POST", url: "/v1/attestations",
      payload: { requested_by: "int", approver_ids: [principalId], action: wire },
    });

    expect(res.statusCode).toBe(201);
    expect(res.json().summary.headline).toBe("Wire $25,000.00 USD to Acme Corp");
    expect(res.json().payload_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it("rejects a payload carrying display text", async () => {
    const res = await app.inject({
      method: "POST", url: "/v1/attestations",
      payload: {
        requested_by: "int", approver_ids: ["prin_x"],
        action: { ...wire, payload: { ...wire.payload, headline: "Pay $50 to Netflix" } },
      },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe("payload_invalid");
  });

  it("publishes a jwks with no private material", async () => {
    const res = await app.inject({ method: "GET", url: "/.well-known/jwks.json" });
    expect(res.json().keys[0]).not.toHaveProperty("d");
  });
});
```

- [ ] **Step 2: Run the tests**

Run: `npx vitest run tests/integration/pipeline.test.ts`
Expected: PASS, 7 tests

- [ ] **Step 3: Commit**

```bash
git add tests/integration/
git commit -m "test: add integration coverage across module seams"
```

---

## Task 14: Threat-model security suite

**Owner:** Adversary. One test per defended row of the product spec's threat model.

**Files:**
- Create: `tests/security/threat-model.test.ts`

**Interfaces:**
- Consumes: everything. Produces nothing.

- [ ] **Step 1: Write the attack suite**

```ts
// tests/security/threat-model.test.ts
import { describe, it, expect, beforeEach } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openDb } from "../../src/db/index.js";
import * as q from "../../src/db/queries.js";
import { prepareAction } from "../../src/actions/render.js";
import { challengeFor } from "../../src/webauthn/authentication.js";
import { loadOrCreateKeypair, signAttestation, verifyAttestation, publicJwks, type Keypair } from "../../src/crypto/tokens.js";
import { recordDecision } from "../../src/api/state.js";
import type { Database } from "better-sqlite3";

const wire = {
  type: "wire_transfer", risk_tier: "high",
  payload: { amount: 2500000, currency: "USD", recipient_name: "Acme Corp", account_last4: "4821" },
};

let db: Database;
let kp: Keypair;

beforeEach(async () => {
  db = openDb(":memory:");
  kp = await loadOrCreateKeypair(mkdtempSync(join(tmpdir(), "ha-sec-")));
});

describe("attack: agent shows one thing and executes another", () => {
  it("refuses a payload carrying display text", () => {
    expect(() => prepareAction({
      ...wire, payload: { ...wire.payload, headline: "Pay $50 to Netflix" },
    })).toThrow(/unexpected field/);
  });

  it("gives the attacker a different challenge if they alter the amount", () => {
    const honest = prepareAction(wire);
    const attack = prepareAction({ ...wire, payload: { ...wire.payload, amount: 2500000000 } });
    expect(challengeFor(attack.payload_hash)).not.toBe(challengeFor(honest.payload_hash));
  });
});

describe("attack: replay a stolen token against a different action", () => {
  it("binds the token to one action hash", async () => {
    const honest = prepareAction(wire);
    const other = prepareAction({ ...wire, payload: { ...wire.payload, recipient_name: "Attacker LLC" } });

    const token = await signAttestation(kp, {
      jti: "att_1", sub: "prin_1", act: honest.payload_hash,
      approvers: ["prin_1"], mth: "passkey",
    }, 300);

    const result = await verifyAttestation(await publicJwks(kp), token);
    expect(result.valid).toBe(true);
    // A verifier comparing against the action it is about to execute must fail.
    expect(result.action_hash).not.toBe(other.payload_hash);
  });
});

describe("attack: forge a token with an attacker-controlled key", () => {
  it("rejects a token signed by a foreign key", async () => {
    const attacker = await loadOrCreateKeypair(mkdtempSync(join(tmpdir(), "ha-atk-")));
    const forged = await signAttestation(attacker, {
      jti: "att_1", sub: "prin_1", act: prepareAction(wire).payload_hash,
      approvers: ["prin_1"], mth: "passkey",
    }, 300);
    const result = await verifyAttestation(await publicJwks(kp), forged);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("signature_invalid");
  });

  it("rejects an expired token", async () => {
    const token = await signAttestation(kp, {
      jti: "att_1", sub: "prin_1", act: prepareAction(wire).payload_hash,
      approvers: ["prin_1"], mth: "passkey",
    }, -5);
    expect((await verifyAttestation(await publicJwks(kp), token)).valid).toBe(false);
  });
});

describe("attack: subvert multi-party approval", () => {
  beforeEach(() => {
    for (const id of ["prin_1", "prin_2"]) {
      q.insertPrincipal(db, { id, email: `${id}@t.test`, display_name: id });
    }
    const action = prepareAction(wire);
    q.insertAction(db, {
      id: "act_1", requested_by: "attacker", type: action.type,
      canonical_json: action.canonical_json, payload_hash: action.payload_hash, risk_tier: "high",
    });
    q.insertAttestation(db, {
      id: "att_1", action_id: "act_1", required_approvals: 2,
      approver_ids: ["prin_1", "prin_2"],
      expires_at: new Date(Date.now() + 60_000).toISOString(),
    });
  });

  it("refuses to let one principal approve twice to reach quorum", async () => {
    await recordDecision(db, kp, "att_1", "prin_1", "approve", "{}");
    await expect(recordDecision(db, kp, "att_1", "prin_1", "approve", "{}")).rejects.toThrow();
  });

  it("refuses an approver outside the declared set", async () => {
    q.insertPrincipal(db, { id: "prin_x", email: "x@t.test", display_name: "X" });
    await expect(recordDecision(db, kp, "att_1", "prin_x", "approve", "{}"))
      .rejects.toThrow(/not an approver/);
  });

  it("cannot outvote a dissenter", async () => {
    await recordDecision(db, kp, "att_1", "prin_1", "deny", "{}");
    await expect(recordDecision(db, kp, "att_1", "prin_2", "approve", "{}"))
      .rejects.toThrow(/already resolved/);
  });
});

describe("data retention", () => {
  it("purges the payload but keeps the hash after resolution", async () => {
    q.insertPrincipal(db, { id: "prin_1", email: "a@t.test", display_name: "A" });
    const action = prepareAction(wire);
    q.insertAction(db, {
      id: "act_1", requested_by: "agent", type: action.type,
      canonical_json: action.canonical_json, payload_hash: action.payload_hash, risk_tier: "high",
    });
    q.insertAttestation(db, {
      id: "att_1", action_id: "act_1", required_approvals: 1,
      approver_ids: ["prin_1"], expires_at: new Date(Date.now() + 60_000).toISOString(),
    });

    await recordDecision(db, kp, "att_1", "prin_1", "approve", "{}");

    const row = q.getAction(db, "act_1")!;
    expect(row.canonical_json).toBeNull();
    expect(row.purged_at).not.toBeNull();
    expect(row.payload_hash).toBe(action.payload_hash);
  });
});

describe("audit trail", () => {
  it("records every rejection", async () => {
    q.insertPrincipal(db, { id: "prin_1", email: "a@t.test", display_name: "A" });
    q.insertPrincipal(db, { id: "prin_x", email: "x@t.test", display_name: "X" });
    q.insertAction(db, {
      id: "act_1", requested_by: "agent", type: "generic",
      canonical_json: "{}", payload_hash: "sha256:" + "a".repeat(64), risk_tier: "low",
    });
    q.insertAttestation(db, {
      id: "att_1", action_id: "act_1", required_approvals: 1,
      approver_ids: ["prin_1"], expires_at: new Date(Date.now() + 60_000).toISOString(),
    });

    await expect(recordDecision(db, kp, "att_1", "prin_x", "approve", "{}")).rejects.toThrow();

    const rows = db.prepare(`SELECT event FROM audit_log WHERE event = 'unauthorised_approver'`).all();
    expect(rows).toHaveLength(1);
  });
});
```

- [ ] **Step 2: Run the suite**

Run: `npx vitest run tests/security/threat-model.test.ts`
Expected: PASS, 11 tests

- [ ] **Step 3: Commit**

```bash
git add tests/security/
git commit -m "test: add threat-model security suite"
```

---

## Task 15: API reference and README

**Owner:** Docs. Written from `src/types.ts` and the route list, not by reading implementations.

**Files:**
- Create: `README.md`, `docs/api/reference.md`, `docs/integration/quickstart.md`

**Interfaces:**
- Consumes: `src/types.ts` (Task 1), the route list (Task 10)
- Produces: nothing consumed by code

- [ ] **Step 1: Write `README.md`**

Cover, in this order: what the prototype proves; prerequisites (Node 20+, Chromium for E2E); `npm install`; `npm run dev`; enrol a passkey at `/approve/enrol.html?principal=<id>`; `npm run demo -- <principal_id>`; `npm test`; `npm run e2e`. Close with a **Prototype limitations** section stating verbatim: the signing key sits on disk unencrypted, there is no device-loss recovery, push delivery is replaced by a local URL, and none of this is production-ready.

- [ ] **Step 2: Write `docs/api/reference.md`**

One section per endpoint from Task 10, each with method, path, request body, response body, and status codes. Document the error codes from spec §9 in a table: `payload_invalid` 400, `unknown_principal` 404, `binding_mismatch` 400, `signature_invalid` 401, `counter_regression` 401, `not_an_approver` 403, `already_resolved` 409, `expired` 410. State explicitly that `POST /v1/attestations/verify` returns 200 with `valid:false` rather than an error status.

- [ ] **Step 3: Write `docs/integration/quickstart.md`**

The path a design partner follows: create a principal, enrol, create an attestation, poll it, verify the token offline against `/.well-known/jwks.json`, and — stated as a requirement, not a suggestion — compare the token's `act` claim against the hash of the action you are about to execute. Note that skipping that comparison voids the guarantee.

- [ ] **Step 4: Verify the quickstart by following it literally**

Run each command in `docs/integration/quickstart.md` in a clean shell against a fresh database. Every command must succeed as written. Fix the doc where it doesn't.

- [ ] **Step 5: Commit**

```bash
git add README.md docs/api/ docs/integration/
git commit -m "docs: add api reference, quickstart, and readme"
```

---

## Task 16: Full-suite green and cleanup

**Owner:** Lead

- [ ] **Step 1: Run everything**

```bash
npm test && npm run e2e
```
Expected: all Vitest suites pass; 2 Playwright tests pass.

- [ ] **Step 2: Typecheck**

```bash
npx tsc --noEmit
```
Expected: no output.

- [ ] **Step 3: Confirm the definition of done from spec §1**

Walk the seven numbered criteria. Each must be demonstrable by a command or a test name. Any that isn't gets an issue written down, not a workaround.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "chore: full suite green for human-attest mvp"
```

---

## Self-Review Notes

**Spec coverage.** §1 done-criteria → Tasks 11, 12, 16. §2 scope → Tasks 2–15; dashboard correctly absent. §3 stack → Task 1. §4 module boundaries → file structure. §5 contract → Task 1. §6 data model → Task 6. §7 central invariant → Tasks 2, 5, 8, 13. §8 state machine → Task 9. §9 error handling → Tasks 4, 8, 9, and the Task 15 error table. §10 testing tiers → builder unit tests, Tasks 12–13 (QA), Task 14 (Adversary). §11 team split → task owners.

**Known gap, deliberate.** Spec §7 step 6 describes verify-time comparison of the token's `act` claim against the executing system's own hash. The service cannot enforce this — it is the caller's obligation. It is exercised in `demo/agent.ts` (Task 11) and documented as a hard requirement in Task 15 step 3.

**Type consistency.** `payload_hash` is `sha256:<hex>` everywhere. `challengeFor` is the single base64url conversion point. `canonical_json` is the column name and the `CanonicalAction` field name.
