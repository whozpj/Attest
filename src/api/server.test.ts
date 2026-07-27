// src/api/server.test.ts
import { describe, it, expect, beforeEach } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildServer } from "./server.js";
import { withAuditEvent, withAuditDetail } from "./audit-detail.js";
import { FailClosedError } from "../types.js";

let app: Awaited<ReturnType<typeof buildServer>>;

beforeEach(async () => {
  app = await buildServer({
    dbPath: ":memory:",
    keyDir: mkdtempSync(join(tmpdir(), "ha-server-")),
  });
});

function auditRows(): Array<{ event: string; actor: string | null; attestation_id: string | null; detail: string | null }> {
  return app.ctx.db.prepare("SELECT event, actor, attestation_id, detail FROM audit_log").all() as Array<{
    event: string; actor: string | null; attestation_id: string | null; detail: string | null;
  }>;
}

describe("every rejection writes an audit_log row, via the central error handler", () => {
  it("audits an unknown_attestation 404 on GET, with the attestation_id from the URL", async () => {
    const res = await app.inject({ method: "GET", url: "/v1/attestations/att_nonexistent" });
    expect(res.statusCode).toBe(404);
    expect(auditRows().some((r) => r.event === "unknown_attestation" && r.attestation_id === "att_nonexistent"))
      .toBe(true);
  });

  it("audits a payload_invalid rejection from action-schema validation on attestation creation", async () => {
    const res = await app.inject({
      method: "POST", url: "/v1/attestations",
      payload: {
        requested_by: "int", approver_ids: ["prin_x"],
        action: { type: "not_a_real_type", risk_tier: "low", payload: {} },
      },
    });
    expect(res.statusCode).toBe(400);
    expect(auditRows().some((r) => r.event === "payload_invalid")).toBe(true);
  });

  it("audits invalid_decision on the options route, with actor derived from principal_id and attestation_id from the URL", async () => {
    const p = await app.inject({
      method: "POST", url: "/v1/principals", payload: { email: "a@t.test", display_name: "A" },
    });
    const { principal_id } = p.json();
    const created = await app.inject({
      method: "POST", url: "/v1/attestations",
      payload: {
        requested_by: "int", approver_ids: [principal_id],
        action: { type: "generic", risk_tier: "low", payload: { title: "t", detail: "d" } },
      },
    });
    const { attestation_id } = created.json();

    const res = await app.inject({
      method: "POST", url: `/v1/attestations/${attestation_id}/options`,
      payload: { principal_id }, // no decision
    });
    expect(res.statusCode).toBe(400);
    expect(auditRows().some((r) =>
      r.event === "invalid_decision" && r.attestation_id === attestation_id && r.actor === principal_id,
    )).toBe(true);
  });

  it("audits a duplicate-email rejection on principal enrolment, with actor derived from the id param", async () => {
    const p = await app.inject({
      method: "POST", url: "/v1/principals", payload: { email: "dup@t.test", display_name: "A" },
    });
    const { principal_id } = p.json();

    const res = await app.inject({
      method: "POST", url: `/v1/principals/${principal_id}/credentials`,
      payload: {},
    });
    expect(res.statusCode).toBe(400);
    expect(auditRows().some((r) => r.event === "no_pending_registration" && r.actor === principal_id)).toBe(true);
  });

  it("audits exactly once per rejection — no duplicate row from a leftover per-throw-site call", async () => {
    const res = await app.inject({ method: "GET", url: "/v1/attestations/att_missing" });
    expect(res.statusCode).toBe(404);
    expect(auditRows().filter((r) => r.event === "unknown_attestation")).toHaveLength(1);
  });

  it("backstops an unhandled, non-FailClosedError exception: audited as internal_error, not silently dropped", async () => {
    // Registered only for this test, on this test's own fresh app instance,
    // to verify the backstop independent of which specific route happens to
    // still have an unaudited crash today (that's Finding 6's job).
    app.get("/__test/boom", async () => {
      throw new Error("kaboom");
    });

    const res = await app.inject({ method: "GET", url: "/__test/boom" });
    expect(res.statusCode).toBe(500);
    expect(res.json()).toEqual({ error: "internal_error" });
    expect(auditRows().some((r) => r.event === "internal_error" && r.detail === "kaboom")).toBe(true);
  });

  it("lets a throw site override the audit event name via withAuditEvent, writing exactly one row under that name", async () => {
    app.get("/__test/richer-signal", async () => {
      throw withAuditEvent(
        withAuditDetail(
          new FailClosedError("counter_regression", 401, "authenticator counter regressed"),
          "stored=3 presented=1",
        ),
        "possible_credential_clone",
      );
    });

    const res = await app.inject({ method: "GET", url: "/__test/richer-signal" });
    expect(res.statusCode).toBe(401);
    // The HTTP response is unaffected by either override.
    expect(res.json()).toEqual({ error: "counter_regression", message: "authenticator counter regressed" });

    const rows = auditRows();
    expect(rows.filter((r) => r.event === "counter_regression")).toHaveLength(0);
    expect(rows.filter((r) => r.event === "possible_credential_clone")).toHaveLength(1);
    expect(rows.find((r) => r.event === "possible_credential_clone")?.detail).toBe("stored=3 presented=1");
  });
});

describe("a POST with no request body at all never reaches a handler as bare `undefined`", () => {
  // Every route handler casts `req.body as {...}` and reads fields off it
  // (`body.email`, `body.decision`, ...). When no body is sent at all (no
  // Content-Type, nothing on the wire), Fastify leaves `req.body` as the bare
  // JS value `undefined` rather than an empty object — so `body.email` etc.
  // throws a raw TypeError reading a property of `undefined`, before any
  // route's own "is this field present and well-typed" check ever runs. That
  // escaped as an unaudited, untyped 500 on every route that didn't happen to
  // guard against it by accident. Normalizing a missing body to `{}` in one
  // place (rather than re-guarding every call site) means every route's
  // already-correct "field X is required" validation runs the same way it
  // does for an explicit `{}` body.
  it("POST /v1/principals with no body: same typed rejection as an explicit empty body", async () => {
    const explicit = await app.inject({ method: "POST", url: "/v1/principals", payload: {} });
    const noBody = await app.inject({ method: "POST", url: "/v1/principals" });
    expect(noBody.statusCode).toBe(explicit.statusCode);
    expect(noBody.json()).toEqual(explicit.json());
    expect(noBody.statusCode).not.toBe(500);
  });

  it("POST /v1/attestations/:id/options with no body: same typed rejection as an explicit empty body", async () => {
    const explicit = await app.inject({ method: "POST", url: "/v1/attestations/att_ghost/options", payload: {} });
    const noBody = await app.inject({ method: "POST", url: "/v1/attestations/att_ghost/options" });
    expect(noBody.statusCode).toBe(explicit.statusCode);
    expect(noBody.json()).toEqual(explicit.json());
    expect(noBody.statusCode).not.toBe(500);
  });

  it("POST /v1/attestations/:id/decision with no body: same typed rejection as an explicit empty body", async () => {
    const explicit = await app.inject({ method: "POST", url: "/v1/attestations/att_ghost/decision", payload: {} });
    const noBody = await app.inject({ method: "POST", url: "/v1/attestations/att_ghost/decision" });
    expect(noBody.statusCode).toBe(explicit.statusCode);
    expect(noBody.json()).toEqual(explicit.json());
    expect(noBody.statusCode).not.toBe(500);
  });
});
