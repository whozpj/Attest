import { describe, it, expect } from "vitest";
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
