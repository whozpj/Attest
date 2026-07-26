// src/api/routes.principals.test.ts
import { describe, it, expect, beforeEach } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildServer } from "./server.js";

let app: Awaited<ReturnType<typeof buildServer>>;

beforeEach(async () => {
  app = await buildServer({
    dbPath: ":memory:",
    keyDir: mkdtempSync(join(tmpdir(), "ha-principals-")),
  });
});

describe("POST /v1/principals fails closed", () => {
  it("rejects a missing email with the opaque principal_invalid code", async () => {
    const res = await app.inject({
      method: "POST", url: "/v1/principals",
      payload: { display_name: "No Email" },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json()).toEqual({ error: "principal_invalid", message: expect.any(String) });
  });

  it("rejects a non-string email the same way", async () => {
    const res = await app.inject({
      method: "POST", url: "/v1/principals",
      payload: { email: 12345, display_name: "Numeric Email" },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe("principal_invalid");
  });

  it("rejects a duplicate email with the same opaque code as a malformed body", async () => {
    const first = await app.inject({
      method: "POST", url: "/v1/principals",
      payload: { email: "dup@test.local", display_name: "First" },
    });
    expect(first.statusCode).toBe(201);

    const dup = await app.inject({
      method: "POST", url: "/v1/principals",
      payload: { email: "dup@test.local", display_name: "Second" },
    });
    expect(dup.statusCode).toBe(400);
    // Deliberately the same code as a malformed body: a distinct duplicate-email
    // error would be an account-enumeration vector on an enrolment endpoint.
    expect(dup.json().error).toBe("principal_invalid");
  });

  it("writes an audit_log row for a duplicate email", async () => {
    await app.inject({
      method: "POST", url: "/v1/principals",
      payload: { email: "audited@test.local", display_name: "First" },
    });
    await app.inject({
      method: "POST", url: "/v1/principals",
      payload: { email: "audited@test.local", display_name: "Second" },
    });
    const rows = app.ctx.db.prepare("SELECT * FROM audit_log").all() as Array<{ event: string }>;
    expect(rows.some((r) => r.event === "principal_invalid")).toBe(true);
  });

  it("writes an audit_log row for a malformed body", async () => {
    await app.inject({
      method: "POST", url: "/v1/principals",
      payload: { display_name: "No Email" },
    });
    const rows = app.ctx.db.prepare("SELECT * FROM audit_log").all() as Array<{ event: string }>;
    expect(rows.some((r) => r.event === "principal_invalid")).toBe(true);
  });
});

describe("POST /v1/principals/:id/credentials without a pending challenge", () => {
  it("fails closed through the standard error envelope", async () => {
    const principal = await app.inject({
      method: "POST", url: "/v1/principals",
      payload: { email: "cred@test.local", display_name: "Cred" },
    });
    const { principal_id } = principal.json();

    const res = await app.inject({
      method: "POST", url: `/v1/principals/${principal_id}/credentials`,
      payload: {},
    });
    expect(res.statusCode).toBe(400);
    expect(res.json()).toEqual({ error: "no_pending_registration", message: expect.any(String) });
  });

  it("writes an audit_log row", async () => {
    const principal = await app.inject({
      method: "POST", url: "/v1/principals",
      payload: { email: "cred2@test.local", display_name: "Cred2" },
    });
    const { principal_id } = principal.json();

    await app.inject({
      method: "POST", url: `/v1/principals/${principal_id}/credentials`,
      payload: {},
    });
    const rows = app.ctx.db.prepare("SELECT * FROM audit_log").all() as Array<{ event: string }>;
    expect(rows.some((r) => r.event === "no_pending_registration")).toBe(true);
  });
});
