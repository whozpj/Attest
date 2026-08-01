import { describe, it, expect } from "vitest";
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
