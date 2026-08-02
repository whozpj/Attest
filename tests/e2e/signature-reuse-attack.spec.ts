import { test, expect } from "@playwright/test";
import { withVirtualAuthenticator, createPrincipal, enrolPasskey, signDecisionChallenge } from "./fixtures.js";

const BASE = "http://localhost:3000";

// The attack: an agent obtains a legitimate human signature over a benign
// action, then tries to spend that same signature on a different, malicious
// action. The signature is cryptographically valid and made by the right
// human -- it is simply over the wrong action hash, and the WebAuthn
// challenge binding alone must be enough to stop it.
test("a genuine signature over a benign action cannot approve a different, malicious action", async ({ page }) => {
  await withVirtualAuthenticator(page);
  const { principalId, enrolmentToken } = await createPrincipal(BASE, `e2e-mismatch-${Date.now()}@test.local`);
  await enrolPasskey(page, principalId, enrolmentToken);

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
  // real WebAuthn assertion produced by the virtual authenticator. Any page
  // on this origin works for this -- the ceremony is driven directly via
  // signDecisionChallenge, not through the SPA's own Approve button, since
  // the attack requires submitting the resulting signature against a
  // *different* attestation than the one it was fetched and signed for.
  await page.goto("/signin");
  const response = await signDecisionChallenge(page, BASE, benign.attestation_id, principalId, "approve");

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
