import { test, expect } from "@playwright/test";
import { withVirtualAuthenticator, createPrincipal } from "./fixtures.js";

const BASE = "http://localhost:3000";

// The attack: an agent obtains a legitimate human signature over a benign
// action, then tries to spend that same signature on a different, malicious
// action. The signature is cryptographically valid and made by the right
// human -- it is simply over the wrong action hash, and the WebAuthn
// challenge binding alone must be enough to stop it.
test("a genuine signature over a benign action cannot approve a different, malicious action", async ({ page }) => {
  await withVirtualAuthenticator(page);
  const principalId = await createPrincipal(BASE, `e2e-mismatch-${Date.now()}@test.local`);

  await page.goto("/approve/enrol.html?principal=" + principalId);
  await page.click("#enrol");
  await expect(page.locator("#status")).toContainText("enrolled");

  // Attestation A: benign, $25,000 to Acme Corp.
  const benign = await fetch(`${BASE}/v1/attestations`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({
      requested_by: "attacker", approver_ids: [principalId], required_approvals: 1,
      action: {
        type: "wire_transfer", risk_tier: "high",
        payload: { amount: 2500000, currency: "USD", recipient_name: "Acme Corp", account_last4: "4821" },
      },
    }),
  }).then((r) => r.json());

  // Attestation B: malicious, a different payload -> a different payload_hash
  // -> a different WebAuthn challenge.
  const malicious = await fetch(`${BASE}/v1/attestations`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({
      requested_by: "attacker", approver_ids: [principalId], required_approvals: 1,
      action: {
        type: "wire_transfer", risk_tier: "high",
        payload: { amount: 2500000000, currency: "USD", recipient_name: "Attacker LLC", account_last4: "9999" },
      },
    }),
  }).then((r) => r.json());

  expect(benign.payload_hash).not.toBe(malicious.payload_hash);

  // The human genuinely signs A's challenge, from our own origin, with a
  // real WebAuthn assertion produced by the virtual authenticator.
  await page.goto(`/approve/index.html?attestation=${benign.attestation_id}&principal=${principalId}`);
  await expect(page.locator("#headline")).toHaveText("Wire $25,000.00 USD to Acme Corp");

  const response = await page.evaluate(
    async ({ attestationId, principalId }) => {
      const optsRes = await fetch(`/v1/attestations/${attestationId}/options`, {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ principal_id: principalId }),
      });
      const optionsJSON = await optsRes.json();
      // Global UMD bundle attached to window by /vendor/simplewebauthn-browser.js.
      const lib = (window as unknown as { SimpleWebAuthnBrowser: { startAuthentication: (arg: { optionsJSON: unknown }) => Promise<unknown> } }).SimpleWebAuthnBrowser;
      return lib.startAuthentication({ optionsJSON });
    },
    { attestationId: benign.attestation_id, principalId },
  );

  // The attacker tries to spend that genuine, human-signed assertion on the
  // malicious action instead of the one it was actually signed over.
  const decisionRes = await fetch(`${BASE}/v1/attestations/${malicious.attestation_id}/decision`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ principal_id: principalId, decision: "approve", response }),
  });
  const decision = await decisionRes.json();

  expect(decisionRes.status).toBe(400);
  expect(decision.error).toBe("binding_mismatch");

  // No token was minted for the malicious action; it is still pending.
  const maliciousAfter = await fetch(`${BASE}/v1/attestations/${malicious.attestation_id}`).then((r) => r.json());
  expect(maliciousAfter.status).toBe("pending");
  expect(maliciousAfter.token).toBeNull();
});
