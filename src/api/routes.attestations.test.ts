// src/api/routes.attestations.test.ts
import { describe, it, expect, beforeEach } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { buildServer } from "./server.js";
import { makeFakeCredential, signAssertion } from "../../tests/security/lib/webauthn-fake.js";

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

describe("POST /v1/attestations/:id/options enforces approver membership", () => {
  it("refuses a real principal with a real credential who is simply not listed as an approver", async () => {
    const outsider = await createPrincipalWithCredential("outsider@test.local");
    const approver = await createPrincipalWithCredential("real-approver@test.local");
    const attestation_id = await createAttestation(approver); // outsider is NOT in approver_ids

    const res = await app.inject({
      method: "POST", url: `/v1/attestations/${attestation_id}/options`,
      payload: { principal_id: outsider, decision: "approve" },
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe("no_credential");
    // No allowCredentials, no credential IDs, nothing beyond the opaque
    // rejection — this principal is real and does have a credential, but
    // none of that should be observable from this attestation's options call.
    expect(res.json()).not.toHaveProperty("allowCredentials");
    expect(res.json()).not.toHaveProperty("challenge");
  });

  it("gives byte-identical responses for a non-approver and a principal that doesn't exist at all", async () => {
    const approver = await createPrincipalWithCredential("real-approver-2@test.local");
    const outsider = await createPrincipalWithCredential("outsider-2@test.local");
    const attestation_id = await createAttestation(approver);

    const nonApproverRes = await app.inject({
      method: "POST", url: `/v1/attestations/${attestation_id}/options`,
      payload: { principal_id: outsider, decision: "approve" },
    });
    const unknownPrincipalRes = await app.inject({
      method: "POST", url: `/v1/attestations/${attestation_id}/options`,
      payload: { principal_id: "prin_does_not_exist", decision: "approve" },
    });

    expect(nonApproverRes.statusCode).toBe(unknownPrincipalRes.statusCode);
    expect(nonApproverRes.body).toBe(unknownPrincipalRes.body);
  });

  it("still issues real options, including allowCredentials, to an actual approver", async () => {
    const approver = await createPrincipalWithCredential("legit-approver@test.local");
    const attestation_id = await createAttestation(approver);

    const res = await app.inject({
      method: "POST", url: `/v1/attestations/${attestation_id}/options`,
      payload: { principal_id: approver, decision: "approve" },
    });

    expect(res.statusCode).toBe(200);
    expect(res.json()).toHaveProperty("challenge");
    expect(res.json().allowCredentials?.map((c: { id: string }) => c.id)).toEqual([`credid_${approver}`]);
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

async function createPrincipalWithRealCredential(email: string) {
  const res = await app.inject({
    method: "POST", url: "/v1/principals",
    payload: { email, display_name: email },
  });
  const { principal_id } = res.json();
  const cred = makeFakeCredential();
  app.ctx.db.prepare(
    `INSERT INTO credentials (id, principal_id, credential_id, public_key, sign_count, transports, created_at)
     VALUES (?, ?, ?, ?, 0, NULL, ?)`,
  ).run(`cred_${randomUUID()}`, principal_id, cred.credentialId, cred.publicKeyCose, new Date().toISOString());
  return { principal_id: principal_id as string, cred };
}

describe("POST /v1/attestations/:id/decision refuses a second decision from a principal who already decided (F4)", () => {
  it("first decision succeeds, a second genuinely-signed decision from the same principal is a typed 409, and quorum state is unaffected", async () => {
    // required_approvals: 2 keeps the attestation pending after the first
    // decision, so the second call reaches recordDecision's insertApproval
    // path instead of being turned away earlier by "already resolved" — this
    // is the case the original DB-level UNIQUE constraint crash actually hit
    // (see F4): an ordinary replayed assertion on a counter-0 authenticator.
    const first = await createPrincipalWithRealCredential("dup-decide-1@test.local");
    const second = await createPrincipalWithRealCredential("dup-decide-2@test.local");

    const createRes = await app.inject({
      method: "POST", url: "/v1/attestations",
      payload: {
        requested_by: "int", approver_ids: [first.principal_id, second.principal_id],
        required_approvals: 2, action: wire,
      },
    });
    const { attestation_id } = createRes.json();

    async function decide(cred: typeof first.cred, principalId: string, signCount: number) {
      const opts = await app.inject({
        method: "POST", url: `/v1/attestations/${attestation_id}/options`,
        payload: { principal_id: principalId, decision: "approve" },
      });
      const response = signAssertion(cred, opts.json().challenge, signCount);
      return app.inject({
        method: "POST", url: `/v1/attestations/${attestation_id}/decision`,
        payload: { principal_id: principalId, decision: "approve", response },
      });
    }

    const firstDecision = await decide(first.cred, first.principal_id, 1);
    expect(firstDecision.statusCode).toBe(200);
    expect(firstDecision.json().status).toBe("pending"); // quorum not yet met

    // A second, genuinely-valid signature (freshly signed, higher counter —
    // not a byte-for-byte replay) from the SAME principal who already decided.
    const secondDecision = await decide(first.cred, first.principal_id, 2);
    expect(secondDecision.statusCode).toBe(409);
    expect(secondDecision.json().error).toBe("already_decided");

    // The rejected duplicate must not have moved quorum state at all.
    const check = await app.inject({ method: "GET", url: `/v1/attestations/${attestation_id}` });
    expect(check.json().status).toBe("pending");
    expect(check.json().approvals).toBe(1);

    expect(auditRows().some((r) => r.event === "already_decided" && r.attestation_id === attestation_id))
      .toBe(true);
  });
});

function auditRows(): Array<{ event: string; attestation_id: string | null; actor: string | null }> {
  return app.ctx.db.prepare("SELECT event, attestation_id, actor FROM audit_log").all() as Array<{
    event: string; attestation_id: string | null; actor: string | null;
  }>;
}

describe("POST /v1/attestations/:id/decision fails closed on a missing signature, not a crash", () => {
  it("rejects a deny with no response field at all — the exact attack: attestation_id + principal_id only", async () => {
    const principal_id = await createPrincipalWithCredential("nosig-deny@test.local");
    const attestation_id = await createAttestation(principal_id);

    const res = await app.inject({
      method: "POST", url: `/v1/attestations/${attestation_id}/decision`,
      payload: { principal_id, decision: "deny" },
    });

    // Must be a typed rejection, not the raw TypeError-turned-500 that
    // `response.id` on `undefined` used to produce.
    expect(res.statusCode).toBe(400);
    expect(res.json()).toEqual({ error: "signature_required", message: expect.any(String) });

    // The requirement that actually broke: a rejection with zero trace.
    expect(auditRows().some((r) => r.event === "signature_required" && r.attestation_id === attestation_id))
      .toBe(true);

    const check = await app.inject({ method: "GET", url: `/v1/attestations/${attestation_id}` });
    expect(check.json().status).toBe("pending");
  });

  it("rejects a response that is present but malformed (no id), same opaque code as missing", async () => {
    const principal_id = await createPrincipalWithCredential("malformed-response@test.local");
    const attestation_id = await createAttestation(principal_id);

    const res = await app.inject({
      method: "POST", url: `/v1/attestations/${attestation_id}/decision`,
      payload: { principal_id, decision: "approve", response: { notAnId: true } },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe("signature_required");
    expect(auditRows().some((r) => r.event === "signature_required")).toBe(true);
  });

  it("rejects a non-object response (string) the same way", async () => {
    const principal_id = await createPrincipalWithCredential("string-response@test.local");
    const attestation_id = await createAttestation(principal_id);

    const res = await app.inject({
      method: "POST", url: `/v1/attestations/${attestation_id}/decision`,
      payload: { principal_id, decision: "approve", response: "not-an-object" },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe("signature_required");
  });
});

describe("principal_id is validated at the boundary, not assumed present", () => {
  it("POST .../decision rejects a missing principal_id with a typed error and an audit row", async () => {
    const principal_id = await createPrincipalWithCredential("missing-pid-decision@test.local");
    const attestation_id = await createAttestation(principal_id);

    const res = await app.inject({
      method: "POST", url: `/v1/attestations/${attestation_id}/decision`,
      payload: { decision: "deny", response: { id: "whatever" } },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe("payload_invalid");
    expect(auditRows().some((r) => r.event === "payload_invalid" && r.attestation_id === attestation_id))
      .toBe(true);

    const check = await app.inject({ method: "GET", url: `/v1/attestations/${attestation_id}` });
    expect(check.json().status).toBe("pending");
  });

  it("POST .../options rejects a missing principal_id with a typed error and an audit row", async () => {
    const principal_id = await createPrincipalWithCredential("missing-pid-options@test.local");
    const attestation_id = await createAttestation(principal_id);

    const res = await app.inject({
      method: "POST", url: `/v1/attestations/${attestation_id}/options`,
      payload: { decision: "approve" },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe("payload_invalid");
    expect(auditRows().some((r) => r.event === "payload_invalid" && r.attestation_id === attestation_id))
      .toBe(true);
  });
});

describe("POST /v1/attestations/:id/options on an expired attestation (F5)", () => {
  it("rejects with 410 instead of handing out a live challenge and real allowCredentials", async () => {
    const principal_id = await createPrincipalWithCredential("opt-expired@test.local");
    const created = await app.inject({
      method: "POST", url: "/v1/attestations",
      payload: {
        requested_by: "int", approver_ids: [principal_id], action: wire, ttl_seconds: -1,
      },
    });
    const { attestation_id } = created.json();

    // Left alone (never read) so it expires silently -- this /options call
    // must be the one to observe and reject it, same as GET and /decision
    // already do via effectiveStatus.
    const res = await app.inject({
      method: "POST", url: `/v1/attestations/${attestation_id}/options`,
      payload: { principal_id, decision: "approve" },
    });

    expect(res.statusCode).toBe(410);
    expect(res.json().error).toBe("expired");
    expect(res.json()).not.toHaveProperty("challenge");
    expect(res.json()).not.toHaveProperty("allowCredentials");
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

// The push-delivery test that lived here was removed with Web Push itself.
// It had become vacuous: it POSTed to /v1/principals/:id/push-subscription,
// a route that no longer exists, silently discarded the 404, and then
// asserted only that attestation creation returned 201 -- so it passed while
// testing nothing its own name claimed. The property it was really guarding,
// "a delivery failure never breaks attestation creation", now belongs to the
// email path and is covered directly in src/api/notify.test.ts ("never throws
// when the transport fails, and audits the failure", plus "keeps mailing the
// remaining approvers after one fails").

describe("POST /v1/attestations builds URLs from the server's configured baseUrl", () => {
  it("uses the configured baseUrl, not a hardcoded host", async () => {
    const customApp = await buildServer({
      dbPath: ":memory:", keyDir: mkdtempSync(join(tmpdir(), "ha-baseurl-")),
      baseUrl: "https://attest.example.com",
    });
    const principalRes = await customApp.inject({
      method: "POST", url: "/v1/principals",
      payload: { email: "baseurl@test.local", display_name: "Base URL" },
    });
    const { principal_id } = principalRes.json();
    const res = await customApp.inject({
      method: "POST", url: "/v1/attestations",
      payload: { requested_by: "int", approver_ids: [principal_id], action: wire },
    });
    expect(res.json().approve_url).toBe(
      `https://attest.example.com/requests/${res.json().attestation_id}`,
    );
  });

  it("still defaults to http://localhost:3000 when no baseUrl is passed", async () => {
    const res = await app.inject({
      method: "POST", url: "/v1/attestations",
      payload: { requested_by: "int", approver_ids: ["prin_whatever"], action: wire },
    });
    expect(res.json().approve_url).toContain("http://localhost:3000/requests/");
  });
});
