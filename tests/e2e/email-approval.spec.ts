import { test, expect } from "@playwright/test";
import { withVirtualAuthenticator, createPrincipal, waitForApprovalLink, waitForEnrolmentLink, clickDecision } from "./fixtures.js";

const BASE = "http://localhost:3000";

// The full loop this rework exists to prove: an approver receives a real
// email (written to disk by the file transport, tests/e2e/server.ts's
// MAIL_DIR), and the link inside it -- not a hand-constructed URL, not a
// database lookup, not an API response field -- is what gets them all the
// way to a verified attestation. Every other spec in this suite drives the
// same server routes more directly (constructing enrolment links from the
// API response, as any real caller may also legitimately do per
// docs/integration/quickstart.md); this one is the one place the mailed
// notification path itself is the thing under test.
test("a human enrols and approves entirely by following real emailed links", async ({ page }) => {
  await withVirtualAuthenticator(page);
  const email = `e2e-email-${Date.now()}@test.local`;
  const { principalId } = await createPrincipal(BASE, email);

  // The enrolment email createPrincipal's call just triggered.
  const enrolLink = await waitForEnrolmentLink(email);
  await page.goto(enrolLink);
  await page.getByRole("button", { name: "Enrol passkey" }).click();
  await page.getByText("Passkey enrolled").waitFor();

  const created = await fetch(`${BASE}/v1/attestations`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({
      requested_by: "e2e-email", approver_ids: [principalId], required_approvals: 1,
      action: {
        type: "wire_transfer", risk_tier: "high",
        payload: { amount: 2500000, currency: "USD", recipient_name: "Acme Corp", account_last4: "4821" },
      },
    }),
  }).then((r) => r.json());

  // The approval email that same call fired off, best-effort, to this approver.
  const approvalLink = await waitForApprovalLink(email);
  await page.goto(approvalLink);

  // The summary on the landing page is rendered server-side from the payload
  // -- unaffected by which channel carried the link here.
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
  expect(verified.principal_id).toBe(principalId);
});

// The link is a view capability, not an authorization (design doc D8): a
// second visitor who follows the SAME emailed link must not be able to
// force a decision as the principal it was addressed to just by knowing the
// token -- only a real passkey signature can. This matters more once the
// link is the primary distribution channel than it did when it was one of
// several: a forwarded or leaked email is now the realistic way a link
// reaches someone other than its intended approver.
test("visiting the approval link alone approves nothing without a passkey", async ({ page }) => {
  const email = `e2e-viewonly-${Date.now()}@test.local`;
  const { principalId } = await createPrincipal(BASE, email);

  const created = await fetch(`${BASE}/v1/attestations`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({
      requested_by: "e2e-viewonly", approver_ids: [principalId], required_approvals: 1,
      action: { type: "generic", risk_tier: "low", payload: { title: "View only", detail: "d" } },
    }),
  }).then((r) => r.json());

  const link = await waitForApprovalLink(email);
  await page.goto(link);
  await expect(page.locator(".pill")).toHaveText("Pending");

  // No credential was ever enrolled for this principal, so there is no
  // authenticator for automaticPresenceSimulation to satisfy even if a click
  // tried to start a ceremony -- but the real assertion is server-side:
  // opening the link must not itself have recorded anything.
  const att = await fetch(`${BASE}/v1/attestations/${created.attestation_id}`).then((r) => r.json());
  expect(att.status).toBe("pending");
  expect(att.approvals).toBe(0);
});
