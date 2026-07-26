// src/api/routes.attestations.test.ts
import { describe, it, expect, beforeEach } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildServer } from "./server.js";

let app: Awaited<ReturnType<typeof buildServer>>;

const wire = {
  type: "wire_transfer", risk_tier: "high",
  payload: { amount: 2500000, currency: "USD", recipient_name: "Acme Corp", account_last4: "4821" },
};

beforeEach(async () => {
  app = await buildServer({
    dbPath: ":memory:",
    keyDir: mkdtempSync(join(tmpdir(), "ha-attestations-")),
  });
});

async function createPrincipalWithCredential(email: string) {
  const res = await app.inject({
    method: "POST", url: "/v1/principals",
    payload: { email, display_name: email },
  });
  const { principal_id } = res.json();
  // beginApproval only reads existing credential rows — it doesn't verify
  // anything at options time — so a directly-seeded row is enough to drive
  // the HTTP-layer wiring tests below without a real authenticator.
  app.ctx.db.prepare(
    `INSERT INTO credentials (id, principal_id, credential_id, public_key, sign_count, transports, created_at)
     VALUES (?, ?, ?, ?, 0, NULL, ?)`,
  ).run(`cred_${principal_id}`, principal_id, `credid_${principal_id}`, Buffer.from([1, 2, 3]), new Date().toISOString());
  return principal_id as string;
}

async function createAttestation(approverId: string) {
  const res = await app.inject({
    method: "POST", url: "/v1/attestations",
    payload: { requested_by: "int", approver_ids: [approverId], action: wire },
  });
  return res.json().attestation_id as string;
}

describe("POST /v1/attestations/:id/options binds the decision into the challenge", () => {
  it("rejects a missing decision", async () => {
    const principal_id = await createPrincipalWithCredential("opt-missing@test.local");
    const attestation_id = await createAttestation(principal_id);

    const res = await app.inject({
      method: "POST", url: `/v1/attestations/${attestation_id}/options`,
      payload: { principal_id },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe("invalid_decision");
  });

  it("rejects a decision outside approve/deny", async () => {
    const principal_id = await createPrincipalWithCredential("opt-bad@test.local");
    const attestation_id = await createAttestation(principal_id);

    const res = await app.inject({
      method: "POST", url: `/v1/attestations/${attestation_id}/options`,
      payload: { principal_id, decision: "maybe" },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe("invalid_decision");
  });

  it("issues a different challenge for approve than for deny on the same action", async () => {
    const principal_id = await createPrincipalWithCredential("opt-diff@test.local");
    const attestation_id = await createAttestation(principal_id);

    const approveOpts = await app.inject({
      method: "POST", url: `/v1/attestations/${attestation_id}/options`,
      payload: { principal_id, decision: "approve" },
    });
    const denyOpts = await app.inject({
      method: "POST", url: `/v1/attestations/${attestation_id}/options`,
      payload: { principal_id, decision: "deny" },
    });

    expect(approveOpts.statusCode).toBe(200);
    expect(denyOpts.statusCode).toBe(200);
    expect(approveOpts.json().challenge).not.toBe(denyOpts.json().challenge);
  });
});

describe("POST /v1/attestations/:id/decision requires a real signature for deny too", () => {
  it("rejects a missing decision", async () => {
    const principal_id = await createPrincipalWithCredential("dec-missing@test.local");
    const attestation_id = await createAttestation(principal_id);

    const res = await app.inject({
      method: "POST", url: `/v1/attestations/${attestation_id}/decision`,
      payload: { principal_id, response: { id: "whatever" } },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe("invalid_decision");
  });

  it("no longer accepts a free, unsigned deny — an unrecognised credential is rejected same as approve", async () => {
    const principal_id = await createPrincipalWithCredential("dec-deny@test.local");
    const attestation_id = await createAttestation(principal_id);

    // Before the fix, deny skipped finishApproval entirely and this would
    // have recorded a denial with clientDataJson "{}" and no verification at
    // all. Now it must go through the same credential check as approve.
    const res = await app.inject({
      method: "POST", url: `/v1/attestations/${attestation_id}/decision`,
      payload: { principal_id, decision: "deny", response: { id: "not-a-real-credential" } },
    });
    expect(res.statusCode).toBe(401);
    expect(res.json().error).toBe("unknown_credential");

    // And critically, the attestation must NOT have been resolved to denied
    // by the rejected attempt — an unauthenticated deny must not be able to
    // block a pending attestation.
    const check = await app.inject({ method: "GET", url: `/v1/attestations/${attestation_id}` });
    expect(check.json().status).toBe("pending");
  });
});

describe("GET /v1/attestations/:id on an expired attestation", () => {
  it("does not leak the summary from the very read that expires it", async () => {
    const principal = await app.inject({
      method: "POST", url: "/v1/principals",
      payload: { email: "expiry@test.local", display_name: "Expiry" },
    });
    const { principal_id } = principal.json();

    const created = await app.inject({
      method: "POST", url: "/v1/attestations",
      payload: {
        requested_by: "int", approver_ids: [principal_id], action: wire, ttl_seconds: -1,
      },
    });
    const { attestation_id } = created.json();

    // This is the FIRST read to observe the expiry — the one that must
    // trigger the purge. It must not itself return the pre-purge summary.
    const res = await app.inject({ method: "GET", url: `/v1/attestations/${attestation_id}` });
    expect(res.json().status).toBe("expired");
    expect(res.json().summary).toBeNull();

    // And the underlying row really is purged, not just hidden from this response.
    expect(app.ctx.db.prepare("SELECT canonical_json FROM actions WHERE payload_hash = ?")
      .get(res.json().payload_hash)).toEqual({ canonical_json: null });
  });
});
