import { test, expect } from "@playwright/test";
import { withVirtualAuthenticator, createPrincipal } from "./fixtures.js";

const BASE = "http://localhost:3000";

test("a human approves an action and the token verifies against it", async ({ page }) => {
  await withVirtualAuthenticator(page);
  const { principalId, enrolmentToken } = await createPrincipal(BASE, `e2e-${Date.now()}@test.local`);

  // Enrol a passkey through the browser so the credential is real.
  await page.goto(`/approve/enrol.html?principal=${principalId}&token=${enrolmentToken}`);
  await page.click("#enrol");
  await expect(page.locator("#status")).toContainText("enrolled");

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

  await page.goto(`/approve/index.html?attestation=${created.attestation_id}&principal=${principalId}`);

  // The summary the human sees is rendered server-side from the payload.
  await expect(page.locator("#headline")).toHaveText("Wire $25,000.00 USD to Acme Corp");

  await page.click("#approve");
  await expect(page.locator("#status")).toContainText("approved");

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
  const { principalId, enrolmentToken } = await createPrincipal(BASE, `e2e-deny-${Date.now()}@test.local`);

  await page.goto(`/approve/enrol.html?principal=${principalId}&token=${enrolmentToken}`);
  await page.click("#enrol");
  // Deny now requires a real signed assertion, same as approve, so the
  // credential must genuinely exist server-side before we drive the deny
  // ceremony -- unlike the old bare-POST deny, this can no longer race past
  // enrolment finishing.
  await expect(page.locator("#status")).toContainText("enrolled");

  const created = await fetch(`${BASE}/v1/attestations`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({
      requested_by: "e2e", approver_ids: [principalId],
      action: { type: "generic", risk_tier: "low", payload: { title: "Test", detail: "d" } },
    }),
  }).then((r) => r.json());

  await page.goto(`/approve/index.html?attestation=${created.attestation_id}&principal=${principalId}`);
  await page.click("#deny");
  await expect(page.locator("#status")).toContainText("denied");

  const att = await fetch(`${BASE}/v1/attestations/${created.attestation_id}`).then((r) => r.json());
  expect(att.token).toBeNull();
});
