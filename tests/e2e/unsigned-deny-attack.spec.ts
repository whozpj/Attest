import { test, expect } from "@playwright/test";
import { withVirtualAuthenticator, createPrincipal } from "./fixtures.js";

const BASE = "http://localhost:3000";

// The defect: deny used to require no signature at all, so anyone who knew
// an attestation_id and a principal_id could unilaterally block a pending
// attestation -- a denial-of-service on the approval flow itself, with no
// proof a human ever made that call. Deny must now cost exactly what approve
// costs: a real WebAuthn assertion over a challenge bound to (action, "deny").
// This first test intentionally never opens a browser: the whole point of
// the old bug was that no ceremony -- and so no page -- was needed at all.
test("a bare, unsigned deny request cannot resolve a pending attestation", async () => {
  const created = await fetch(`${BASE}/v1/attestations`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({
      requested_by: "e2e", approver_ids: ["prin_someone_else"], required_approvals: 1,
      action: { type: "generic", risk_tier: "low", payload: { title: "DoS target", detail: "d" } },
    }),
  }).then((r) => r.json());

  // The exact old attack: knowing only the attestation_id and a principal_id
  // (no credential, no signature, no `response` at all).
  const decisionRes = await fetch(`${BASE}/v1/attestations/${created.attestation_id}/decision`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ principal_id: "prin_someone_else", decision: "deny" }),
  });

  expect(decisionRes.ok).toBe(false);

  const att = await fetch(`${BASE}/v1/attestations/${created.attestation_id}`).then((r) => r.json());
  expect(att.status).toBe("pending");
});

// A related, sharper variant of the same defect: even a *genuine* signature
// is only valid for the decision it was actually produced for. A real
// human's approval must not be spendable as ammunition for denying the same
// action (or vice versa) -- that's exactly what binding the decision into
// the challenge, not just the action, is for.
test("a genuine approve signature cannot be replayed as a deny on the same action", async ({ page }) => {
  await withVirtualAuthenticator(page);
  const principalId = await createPrincipal(BASE, `e2e-decision-swap-${Date.now()}@test.local`);

  await page.goto("/approve/enrol.html?principal=" + principalId);
  await page.click("#enrol");
  await expect(page.locator("#status")).toContainText("enrolled");

  const created = await fetch(`${BASE}/v1/attestations`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({
      requested_by: "e2e", approver_ids: [principalId], required_approvals: 1,
      action: { type: "generic", risk_tier: "low", payload: { title: "Decision swap", detail: "d" } },
    }),
  }).then((r) => r.json());

  // Genuinely sign the "approve" challenge for this action, from our own
  // origin, with a real assertion from the virtual authenticator.
  const response = await page.evaluate(
    async ({ attestationId, principalId }) => {
      const optsRes = await fetch(`/v1/attestations/${attestationId}/options`, {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ principal_id: principalId, decision: "approve" }),
      });
      const optionsJSON = await optsRes.json();
      // Global UMD bundle attached to window by /vendor/simplewebauthn-browser.js.
      const lib = (window as unknown as { SimpleWebAuthnBrowser: { startAuthentication: (arg: { optionsJSON: unknown }) => Promise<unknown> } }).SimpleWebAuthnBrowser;
      return lib.startAuthentication({ optionsJSON });
    },
    { attestationId: created.attestation_id, principalId },
  );

  // Try to spend that genuine approve-signature as a deny instead.
  const decisionRes = await fetch(`${BASE}/v1/attestations/${created.attestation_id}/decision`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ principal_id: principalId, decision: "deny", response }),
  });
  const decision = await decisionRes.json();

  expect(decisionRes.status).toBe(400);
  expect(decision.error).toBe("binding_mismatch");

  const att = await fetch(`${BASE}/v1/attestations/${created.attestation_id}`).then((r) => r.json());
  expect(att.status).toBe("pending");
});
