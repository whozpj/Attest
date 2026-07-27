// tests/security/unaudited-rejection-sweep.test.ts
//
// Structural defect class flagged by the lead: a raw exception escaping the
// route layer as a generic 500 breaks two things at once — the documented,
// typed error contract (design spec §9) and the audit trail (design spec §9:
// "Every rejection writes to audit_log"). This is the third instance of
// exactly this shape found this session (duplicate email in
// routes.principals.ts, then this). A product whose pitch is a compliance
// trail cannot have an endpoint an attacker can probe indefinitely while
// leaving zero rows behind.
//
// Two layers here:
//   1. The specific defect: POST /v1/attestations/:id/decision with a
//      missing/null `response` dereferences `response.id` inside
//      finishApproval before that function's own try/catch begins, so the
//      raw TypeError escapes the FailClosedError branch entirely and lands
//      on the server's generic `{error:"internal_error"}` 500 catch-all —
//      with no audit_log row. Written red-first: API-State is fixing the
//      route as this lands.
//   2. A systematic sweep: every route, hit with missing bodies, null
//      fields, and wrong-typed fields, must never come back as a raw,
//      untyped 500. The pattern — not the individual endpoint — is what
//      keeps recurring, so this is table-driven rather than hand-picked.
import { describe, it, expect, beforeEach } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildServer } from "../../src/api/server.js";

const wire = {
  type: "wire_transfer", risk_tier: "high",
  payload: { amount: 2500000, currency: "USD", recipient_name: "Acme Corp", account_last4: "4821" },
};

let app: Awaited<ReturnType<typeof buildServer>>;
let principalId: string;
let attestationId: string;

beforeEach(async () => {
  app = await buildServer({
    dbPath: ":memory:",
    keyDir: mkdtempSync(join(tmpdir(), "ha-sweep-")),
  });

  const principal = await app.inject({
    method: "POST", url: "/v1/principals",
    payload: { email: `sweep-${Math.random()}@test.local`, display_name: "Sweep" },
  });
  principalId = principal.json().principal_id;
  // A directly-seeded credential row is enough to drive past the
  // no_credential guard into finishApproval, which is where this defect
  // lives — the whole point is to reach the WebAuthn verification call with
  // an absent/malformed `response`, not to produce a real signature.
  app.ctx.db.prepare(
    `INSERT INTO credentials (id, principal_id, credential_id, public_key, sign_count, transports, created_at)
     VALUES (?, ?, ?, ?, 0, NULL, ?)`,
  ).run(`cred_${principalId}`, principalId, `credid_${principalId}`, Buffer.from([1, 2, 3]), new Date().toISOString());

  const attestation = await app.inject({
    method: "POST", url: "/v1/attestations",
    payload: { requested_by: "sweep", approver_ids: [principalId], action: wire },
  });
  attestationId = attestation.json().attestation_id;
});

describe("attack: an unsigned decision (missing or null response) must not crash unaudited", () => {
  for (const decision of ["approve", "deny"] as const) {
    for (const [label, response] of [
      ["response field entirely absent", undefined],
      ["response explicitly null", null],
    ] as const) {
      it(`${decision}, ${label}: exactly signature_required, one matching audit row, attestation stays pending`, async () => {
        const payload: Record<string, unknown> = { principal_id: principalId, decision };
        if (response !== undefined || label.includes("null")) payload.response = response;

        const res = await app.inject({
          method: "POST", url: `/v1/attestations/${attestationId}/decision`,
          payload,
        });

        // Byte-level, not just "some 4xx": the confirmed fixed contract
        // (src/api/routes.attestations.ts, 5f21575) is exactly this code.
        // A test asserting only "not 500" would have passed straight through
        // a fix that swapped in a different, still-unaudited 4xx.
        expect(res.statusCode).toBe(400);
        expect(res.json()).toEqual({ error: "signature_required", message: expect.any(String) });

        // The constraint that actually broke: a specific audit row must
        // exist, not merely "some" row. Checking only that the count went up
        // would pass even if the wrong event name were logged.
        const rows = app.ctx.db
          .prepare("SELECT actor FROM audit_log WHERE attestation_id = ? AND event = 'signature_required'")
          .all(attestationId) as Array<{ actor: string }>;
        expect(rows).toHaveLength(1);
        expect(rows[0].actor).toBe(principalId);

        // And the rejected attempt must not have resolved the attestation —
        // an attacker hammering this endpoint with garbage must not be able
        // to force it out of pending as a side effect of the crash.
        const check = await app.inject({ method: "GET", url: `/v1/attestations/${attestationId}` });
        expect(check.json().status).toBe("pending");
      });
    }
  }
});

// Reconciliation note (Adversary-2, this session): this describe block is
// currently RED, on 8 of its cases, and that red is real -- not a stale
// assertion left over from ca95146's attestation-id-binding change (none of
// these 8 cases touch challengeFor/beginApproval/finishApproval at all), and
// not a symptom of API-State's in-progress uncommitted work (that diff only
// touches server.ts's central handler + audit-detail.ts, adding an
// audit-event-name override -- it does not touch routes.principals.ts,
// routes.attestations.ts, or routes.verify.ts, which is where every one of
// these 8 gaps actually lives). Confirmed by reading those three route files
// directly: none of them validate a missing body before destructuring it
// (principals, attestations, options, decision, verify all throw a raw
// TypeError on `payload: undefined`), and routes.attestations.ts additionally
// never validates `approver_ids`, `requested_by`, or `ttl_seconds` before
// they reach a DB bind or `new Date(NaN).toISOString()` (a RangeError). Left
// deliberately red rather than narrowed to pass, per the same "written
// red-first" convention this file's own header describes for the specific
// finishApproval defect above -- API-State has been notified with the exact
// case list so the route-boundary validation can be extended to cover them.
describe("systematic sweep: no caller-supplied input produces a raw, untyped 500", () => {
  // Each case is (name, request). `attestationId`/`principalId` are captured
  // fresh per-test via beforeEach, so cases are built inside `getCases()`
  // and evaluated once the enclosing `it` runs — not at module load — so
  // every case sees the current test's freshly seeded ids.
  function getCases(): Array<{ name: string; method: "GET" | "POST"; url: () => string; payload?: unknown }> {
    return [
      // POST /v1/principals
      { name: "principals: completely empty body", method: "POST", url: () => "/v1/principals", payload: {} },
      { name: "principals: no body at all", method: "POST", url: () => "/v1/principals", payload: undefined },
      { name: "principals: null email", method: "POST", url: () => "/v1/principals", payload: { email: null, display_name: "x" } },
      { name: "principals: numeric email", method: "POST", url: () => "/v1/principals", payload: { email: 12345, display_name: "x" } },
      { name: "principals: array display_name", method: "POST", url: () => "/v1/principals", payload: { email: "a@b.test", display_name: ["x"] } },
      { name: "principals: extra unexpected field", method: "POST", url: () => "/v1/principals", payload: { email: "extra@b.test", display_name: "x", is_admin: true } },

      // POST /v1/principals/:id/credentials/options
      { name: "credentials/options: unknown principal id, no body", method: "POST", url: () => "/v1/principals/prin_does_not_exist/credentials/options", payload: {} },

      // POST /v1/principals/:id/credentials
      { name: "credentials: no pending challenge, empty body", method: "POST", url: () => `/v1/principals/${principalId}/credentials`, payload: {} },
      { name: "credentials: no pending challenge, no body at all", method: "POST", url: () => `/v1/principals/${principalId}/credentials`, payload: undefined },

      // POST /v1/attestations
      { name: "attestations: completely empty body", method: "POST", url: () => "/v1/attestations", payload: {} },
      { name: "attestations: no body at all", method: "POST", url: () => "/v1/attestations", payload: undefined },
      { name: "attestations: null action", method: "POST", url: () => "/v1/attestations", payload: { requested_by: "x", approver_ids: [principalId], action: null } },
      { name: "attestations: action missing payload", method: "POST", url: () => "/v1/attestations", payload: { requested_by: "x", approver_ids: [principalId], action: { type: "wire_transfer", risk_tier: "high" } } },
      { name: "attestations: missing approver_ids", method: "POST", url: () => "/v1/attestations", payload: { requested_by: "x", action: wire } },
      { name: "attestations: approver_ids wrong type (string, not array)", method: "POST", url: () => "/v1/attestations", payload: { requested_by: "x", approver_ids: "not-an-array", action: wire } },
      { name: "attestations: approver_ids null", method: "POST", url: () => "/v1/attestations", payload: { requested_by: "x", approver_ids: null, action: wire } },
      { name: "attestations: missing requested_by", method: "POST", url: () => "/v1/attestations", payload: { approver_ids: [principalId], action: wire } },
      { name: "attestations: required_approvals wrong type", method: "POST", url: () => "/v1/attestations", payload: { requested_by: "x", approver_ids: [principalId], action: wire, required_approvals: "two" } },
      { name: "attestations: ttl_seconds wrong type", method: "POST", url: () => "/v1/attestations", payload: { requested_by: "x", approver_ids: [principalId], action: wire, ttl_seconds: "soon" } },

      // GET /v1/attestations/:id
      { name: "attestations GET: garbage id", method: "GET", url: () => "/v1/attestations/not-a-real-id" },
      { name: "attestations GET: sql-injection-shaped id", method: "GET", url: () => "/v1/attestations/'; DROP TABLE actions; --" },
      { name: "attestations GET: empty-string-like id", method: "GET", url: () => "/v1/attestations/%20" },

      // POST /v1/attestations/:id/options
      { name: "options: empty body", method: "POST", url: () => `/v1/attestations/${attestationId}/options`, payload: {} },
      { name: "options: no body at all", method: "POST", url: () => `/v1/attestations/${attestationId}/options`, payload: undefined },
      { name: "options: null principal_id", method: "POST", url: () => `/v1/attestations/${attestationId}/options`, payload: { principal_id: null, decision: "approve" } },
      { name: "options: unknown principal_id", method: "POST", url: () => `/v1/attestations/${attestationId}/options`, payload: { principal_id: "prin_ghost", decision: "approve" } },
      { name: "options: decision wrong type", method: "POST", url: () => `/v1/attestations/${attestationId}/options`, payload: { principal_id: principalId, decision: 123 } },
      { name: "options: decision outside enum", method: "POST", url: () => `/v1/attestations/${attestationId}/options`, payload: { principal_id: principalId, decision: "maybe" } },
      { name: "options: unknown attestation id", method: "POST", url: () => "/v1/attestations/att_ghost/options", payload: { principal_id: principalId, decision: "approve" } },

      // POST /v1/attestations/:id/decision (beyond the dedicated describe above)
      { name: "decision: empty body", method: "POST", url: () => `/v1/attestations/${attestationId}/decision`, payload: {} },
      { name: "decision: no body at all", method: "POST", url: () => `/v1/attestations/${attestationId}/decision`, payload: undefined },
      { name: "decision: null principal_id", method: "POST", url: () => `/v1/attestations/${attestationId}/decision`, payload: { principal_id: null, decision: "approve", response: {} } },
      { name: "decision: response wrong type (string)", method: "POST", url: () => `/v1/attestations/${attestationId}/decision`, payload: { principal_id: principalId, decision: "deny", response: "not-an-object" } },
      { name: "decision: response wrong type (number)", method: "POST", url: () => `/v1/attestations/${attestationId}/decision`, payload: { principal_id: principalId, decision: "deny", response: 42 } },
      { name: "decision: response empty object", method: "POST", url: () => `/v1/attestations/${attestationId}/decision`, payload: { principal_id: principalId, decision: "deny", response: {} } },
      { name: "decision: response with extra junk fields", method: "POST", url: () => `/v1/attestations/${attestationId}/decision`, payload: { principal_id: principalId, decision: "deny", response: { id: "x", extra: "junk" } } },
      { name: "decision: unknown attestation id", method: "POST", url: () => "/v1/attestations/att_ghost/decision", payload: { principal_id: principalId, decision: "approve", response: {} } },

      // POST /v1/attestations/verify
      { name: "verify: empty body", method: "POST", url: () => "/v1/attestations/verify", payload: {} },
      { name: "verify: no body at all", method: "POST", url: () => "/v1/attestations/verify", payload: undefined },
      { name: "verify: null token", method: "POST", url: () => "/v1/attestations/verify", payload: { token: null } },
      { name: "verify: numeric token", method: "POST", url: () => "/v1/attestations/verify", payload: { token: 12345 } },
      { name: "verify: garbage string token", method: "POST", url: () => "/v1/attestations/verify", payload: { token: "not-a-jwt" } },
    ];
  }

  it("hits every route with hostile input and finds zero raw 500s", async () => {
    const failures: string[] = [];

    for (const c of getCases()) {
      // Deliberately hostile, arbitrarily-shaped payloads are the entire
      // point of this sweep, so `payload` is intentionally untyped here —
      // cast at this one boundary rather than widening the case table.
      const res = await app.inject({ method: c.method, url: c.url(), payload: c.payload as never });
      if (res.statusCode === 500) {
        failures.push(`${c.name}: got 500 ${res.body}`);
      }
    }

    expect(failures).toEqual([]);
  });
});
