import { test, expect } from "@playwright/test";
import { withVirtualAuthenticator, createPrincipal, enrolPasskey, waitForApprovalLink, clickDecision } from "./fixtures.js";

const BASE = "http://localhost:3000";

test("a human approves an action and the token verifies against it", async ({ page }) => {
  await withVirtualAuthenticator(page);
  const email = `e2e-${Date.now()}@test.local`;
  const { principalId, enrolmentToken } = await createPrincipal(BASE, email);
  await enrolPasskey(page, principalId, enrolmentToken);

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

  // The link a real approver would click out of their inbox -- see
  // email-approval.spec.ts for the version that also drives the enrolment
  // email; this spec keeps focus on the decision itself.
  await page.goto(await waitForApprovalLink(email));

  // The summary the human sees is rendered server-side from the payload.
  await expect(page.locator(".headline")).toHaveText("Wire $25,000.00 USD to Acme Corp");

  await clickDecision(page, "Approve with passkey");
  await expect(page.locator(".pill")).toHaveText("Approved");

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
  const email = `e2e-deny-${Date.now()}@test.local`;
  const { principalId, enrolmentToken } = await createPrincipal(BASE, email);
  // Deny requires a real signed assertion, same as approve, so the
  // credential must genuinely exist server-side before driving the deny
  // ceremony.
  await enrolPasskey(page, principalId, enrolmentToken);

  const created = await fetch(`${BASE}/v1/attestations`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({
      requested_by: "e2e", approver_ids: [principalId],
      action: { type: "generic", risk_tier: "low", payload: { title: "Test", detail: "d" } },
    }),
  }).then((r) => r.json());

  await page.goto(await waitForApprovalLink(email));
  await clickDecision(page, "Deny");
  await expect(page.locator(".pill")).toHaveText("Denied");

  const att = await fetch(`${BASE}/v1/attestations/${created.attestation_id}`).then((r) => r.json());
  expect(att.token).toBeNull();
});
