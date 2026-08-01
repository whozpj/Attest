// tests/security/duplicate-audit-rows.test.ts
//
// Permanent regression guard for a defect flagged by API-State-3 and fixed
// at a9572b7: src/webauthn/authentication.ts's counter_regression and
// binding_mismatch throw sites (and signature_invalid) used to call
// q.audit() directly, and server.ts's central error handler (cf27972) ALSO
// wrote a row for every FailClosedError reaching it through real HTTP — two
// audit_log rows for one event, silently double-counting the system's two
// highest-signal security alerts (a forged-signature attempt and a possible
// cloned credential). The fix wraps each throw with withAuditEvent /
// withAuditDetail (src/audit-detail.ts) so the throw site's own richer
// event/detail is the one row the central handler writes, not an addition
// to it.
//
// Both src/webauthn/authentication.test.ts (calls finishApproval directly)
// and this repo's other security tests exercise finishApproval below the
// HTTP boundary, so none of them would have caught this — the double-write
// only exists on the real HTTP path. This suite drives both rejections
// through buildServer + inject specifically to keep that path covered.
import { describe, it, expect, beforeEach } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildServer } from "../../src/api/server.js";
import { makeFakeCredential, signAssertion } from "./lib/webauthn-fake.js";

const wire = {
  type: "wire_transfer", risk_tier: "high",
  payload: { amount: 2500000, currency: "USD", recipient_name: "Acme Corp", account_last4: "4821" },
};

let app: Awaited<ReturnType<typeof buildServer>>;

beforeEach(async () => {
  app = await buildServer({ dbPath: ":memory:", keyDir: mkdtempSync(join(tmpdir(), "ha-dup-audit-")) });
});

async function seedPrincipalWithRealCredential(email: string) {
  const p = await app.inject({ method: "POST", url: "/v1/principals", payload: { email, display_name: email } });
  const principalId = p.json().principal_id as string;
  const cred = makeFakeCredential();
  app.ctx.db.prepare(
    `INSERT INTO credentials (id, principal_id, credential_id, public_key, sign_count, transports, created_at)
     VALUES (?, ?, ?, ?, 0, NULL, ?)`,
  ).run(`cred_${principalId}`, principalId, cred.credentialId, cred.publicKeyCose, new Date().toISOString());
  return { principalId, cred };
}

// Scoped to rejection rows. Creating an attestation now also writes a
// best-effort delivery row per approver (email_sent / email_failed, see
// src/api/notify.ts), which is attestation-scoped and entirely legitimate --
// it is not a rejection and never was one. This suite's invariant is "one
// rejection writes one row", so counting delivery rows alongside it would
// make the assertion fail for a reason that has nothing to do with the
// double-write defect it exists to guard. Everything else stays counted, so
// the "assert the count, not just the event string" property below -- the
// thing that catches a throw site and the central handler disagreeing on the
// event name -- is fully intact.
const DELIVERY_EVENTS = new Set(["email_sent", "email_failed"]);

function auditRowsFor(attestationId: string): Array<{ event: string }> {
  const rows = app.ctx.db
    .prepare("SELECT event FROM audit_log WHERE attestation_id = ?")
    .all(attestationId) as Array<{ event: string }>;
  return rows.filter((r) => !DELIVERY_EVENTS.has(r.event));
}

describe("defect: a single rejection through real HTTP writes exactly one audit_log row, not two", () => {
  it("binding_mismatch: a signature for the wrong attestation writes one row, not one from the throw site plus one from the central handler", async () => {
    const { principalId, cred } = await seedPrincipalWithRealCredential("bm@t.test");

    const attA = await app.inject({
      method: "POST", url: "/v1/attestations",
      payload: { requested_by: "agent", approver_ids: [principalId], action: wire },
    });
    const attB = await app.inject({
      method: "POST", url: "/v1/attestations",
      payload: { requested_by: "agent", approver_ids: [principalId], action: wire },
    });
    const idA = attA.json().attestation_id as string;
    const idB = attB.json().attestation_id as string;

    const optionsA = await app.inject({
      method: "POST", url: `/v1/attestations/${idA}/options`,
      payload: { principal_id: principalId, decision: "approve" },
    });
    const response = signAssertion(cred, optionsA.json().challenge, 1);

    // Submitted against B, not A -- a genuine binding_mismatch.
    const res = await app.inject({
      method: "POST", url: `/v1/attestations/${idB}/decision`,
      payload: { principal_id: principalId, decision: "approve", response },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe("binding_mismatch");

    const rows = auditRowsFor(idB);
    expect(rows).toHaveLength(1);
    expect(rows[0].event).toBe("binding_mismatch");
  });

  it("counter_regression: a replayed counter writes one row, not two under different event names", async () => {
    const { principalId, cred } = await seedPrincipalWithRealCredential("cr@t.test");

    const att = await app.inject({
      method: "POST", url: "/v1/attestations",
      payload: { requested_by: "agent", approver_ids: [principalId], action: wire },
    });
    const attestationId = att.json().attestation_id as string;

    const options1 = await app.inject({
      method: "POST", url: `/v1/attestations/${attestationId}/options`,
      payload: { principal_id: principalId, decision: "approve" },
    });
    const firstResponse = signAssertion(cred, options1.json().challenge, 1);
    const firstDecision = await app.inject({
      method: "POST", url: `/v1/attestations/${attestationId}/decision`,
      payload: { principal_id: principalId, decision: "approve", response: firstResponse },
    });
    expect(firstDecision.statusCode).toBe(200);

    // A second attestation, so the replay attempt is a fresh decision call
    // (not blocked by "already resolved") -- isolating the counter check.
    const att2 = await app.inject({
      method: "POST", url: "/v1/attestations",
      payload: { requested_by: "agent", approver_ids: [principalId], action: wire },
    });
    const attestationId2 = att2.json().attestation_id as string;
    const options2 = await app.inject({
      method: "POST", url: `/v1/attestations/${attestationId2}/options`,
      payload: { principal_id: principalId, decision: "approve" },
    });
    // Same counter (1) as the already-successful signature above -- a
    // regression relative to the credential's now-stored sign_count.
    const replayedResponse = signAssertion(cred, options2.json().challenge, 1);
    const secondDecision = await app.inject({
      method: "POST", url: `/v1/attestations/${attestationId2}/decision`,
      payload: { principal_id: principalId, decision: "approve", response: replayedResponse },
    });
    expect(secondDecision.statusCode).toBe(401);
    expect(secondDecision.json().error).toBe("counter_regression");

    // This is the case the throw site's own event name (possible_credential_clone)
    // and the central handler's err.code (counter_regression) genuinely
    // differ, so a naive "same event name twice" check would miss it --
    // asserting the *count*, not just a specific event string, is what
    // catches this.
    const rows = auditRowsFor(attestationId2);
    expect(rows).toHaveLength(1);
  });
});
