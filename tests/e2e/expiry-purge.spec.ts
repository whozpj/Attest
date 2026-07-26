import { test, expect } from "@playwright/test";

const BASE = "http://localhost:3000";

// Defect: an attestation that quietly times out -- nobody ever calls
// decision on it -- must not keep leaking its display text forever. Expiry
// is only detected on read (there is no scheduler in this prototype), so the
// very first GET after expires_at has passed must be the one that purges the
// payload, exactly as approve/deny already do. Real wire amounts and
// recipient names have no business surviving in the database past the
// window the human was given to act.
test("an attestation that quietly expires purges its payload without ever being decided", async () => {
  const created = await fetch(`${BASE}/v1/attestations`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({
      requested_by: "e2e-expiry", approver_ids: ["prin_never_approves"], required_approvals: 1,
      ttl_seconds: 1,
      action: {
        type: "wire_transfer", risk_tier: "high",
        payload: { amount: 2500000, currency: "USD", recipient_name: "Acme Corp", account_last4: "4821" },
      },
    }),
  }).then((r) => r.json());

  // Let it lapse. No one ever calls /options or /decision on it.
  await new Promise((r) => setTimeout(r, 1500));

  const att = await fetch(`${BASE}/v1/attestations/${created.attestation_id}`).then((r) => r.json());

  expect(att.status).toBe("expired");
  expect(att.summary).toBeNull();
  // The hash survives -- it's the audit trail, not display text -- even
  // though the human-readable payload behind it is gone.
  expect(att.payload_hash).toBe(created.payload_hash);
});

test("a still-pending attestation keeps its summary until it actually expires", async () => {
  const created = await fetch(`${BASE}/v1/attestations`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({
      requested_by: "e2e-expiry", approver_ids: ["prin_never_approves"], required_approvals: 1,
      ttl_seconds: 900,
      action: { type: "generic", risk_tier: "low", payload: { title: "Still pending", detail: "d" } },
    }),
  }).then((r) => r.json());

  const att = await fetch(`${BASE}/v1/attestations/${created.attestation_id}`).then((r) => r.json());
  expect(att.status).toBe("pending");
  expect(att.summary).not.toBeNull();
  expect(att.summary.headline).toBe("Still pending");
});
