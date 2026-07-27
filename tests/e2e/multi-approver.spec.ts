import { test, expect } from "@playwright/test";
import { importJWK, jwtVerify } from "jose";
import { withVirtualAuthenticator, createPrincipal, enrolPasskey } from "./fixtures.js";

const BASE = "http://localhost:3000";

// Tier 4 (spec §1, done-criterion 6): a second flow requires two approvers
// and refuses to resolve on one. Until now this was only proven at the
// state-machine level (src/api/state.test.ts calling recordDecision
// directly with "{}" as client data) -- never through two real WebAuthn
// ceremonies with two real credentials. That gap matters here specifically:
// Tier 4 is the product's named answer to the $25M deepfake-fraud scenario,
// and the two-approver path has surface the single-approver path doesn't --
// two distinct credentials, two distinct challenges, quorum arithmetic
// across separate ceremonies.
//
// Two independent virtual authenticators live on two independent Pages in
// the same browser context (one CDP session each, via
// withVirtualAuthenticator(page)) so the two principals' credentials never
// share storage -- see the comment on enrolPasskey in ./fixtures.ts.

const wire = {
  type: "wire_transfer", risk_tier: "critical",
  payload: { amount: 2500000000, currency: "USD", recipient_name: "Acme Corp", account_last4: "4821" },
};

test("quorum genuinely requires two real approvers before a token issues", async ({ page, context }) => {
  await withVirtualAuthenticator(page);
  const page2 = await context.newPage();
  await withVirtualAuthenticator(page2);

  const { principalId: principal1, enrolmentToken: token1 } =
    await createPrincipal(BASE, `e2e-quorum-1-${Date.now()}@test.local`);
  const { principalId: principal2, enrolmentToken: token2 } =
    await createPrincipal(BASE, `e2e-quorum-2-${Date.now()}@test.local`);

  await enrolPasskey(page, principal1, token1);
  await enrolPasskey(page2, principal2, token2);

  const created = await fetch(`${BASE}/v1/attestations`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({
      requested_by: "e2e-quorum", approver_ids: [principal1, principal2], required_approvals: 2,
      action: wire,
    }),
  }).then((r) => r.json());

  // First approver signs and approves for real. Quorum (2) is not met by one.
  await page.goto(`/approve/index.html?attestation=${created.attestation_id}&principal=${principal1}`);
  await page.click("#approve");
  await expect(page.locator("#status")).toContainText("pending");

  let att = await fetch(`${BASE}/v1/attestations/${created.attestation_id}`).then((r) => r.json());
  expect(att.status).toBe("pending");
  expect(att.token).toBeNull();
  expect(att.approvals).toBe(1);

  // Second approver signs and approves for real, with their own credential
  // and their own challenge (same action, same "approve" decision -- but a
  // different keypair backing the assertion). Only now is quorum met.
  await page2.goto(`/approve/index.html?attestation=${created.attestation_id}&principal=${principal2}`);
  await page2.click("#approve");
  await expect(page2.locator("#status")).toContainText("approved");

  att = await fetch(`${BASE}/v1/attestations/${created.attestation_id}`).then((r) => r.json());
  expect(att.status).toBe("approved");
  expect(att.token).not.toBeNull();

  // The convenience verify endpoint agrees the token is valid for this action.
  const verified = await fetch(`${BASE}/v1/attestations/verify`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ token: att.token }),
  }).then((r) => r.json());
  expect(verified.valid).toBe(true);
  expect(verified.action_hash).toBe(created.payload_hash);

  // VerifyResult (src/types.ts, frozen) doesn't surface `approvers`/`mth` --
  // those live only in the signed JWT claims (AttestationToken). Decode and
  // verify the token independently, offline, against the published JWKS,
  // exactly as any third-party relying party would, to prove both
  // principals are credited and the multi-approver method marker is set.
  const jwks = await fetch(`${BASE}/.well-known/jwks.json`).then((r) => r.json());
  const key = await importJWK(jwks.keys[0], "ES256");
  const { payload } = await jwtVerify(att.token as string, key, { algorithms: ["ES256"] });

  expect(payload.approvers).toEqual(expect.arrayContaining([principal1, principal2]));
  expect((payload.approvers as string[]).length).toBe(2);
  expect(payload.mth).toBe("passkey_multi");
});

test("one real denial beats any number of real approvals", async ({ page, context }) => {
  await withVirtualAuthenticator(page);
  const page2 = await context.newPage();
  await withVirtualAuthenticator(page2);

  const { principalId: principal1, enrolmentToken: token1 } =
    await createPrincipal(BASE, `e2e-failclosed-1-${Date.now()}@test.local`);
  const { principalId: principal2, enrolmentToken: token2 } =
    await createPrincipal(BASE, `e2e-failclosed-2-${Date.now()}@test.local`);

  await enrolPasskey(page, principal1, token1);
  await enrolPasskey(page2, principal2, token2);

  const created = await fetch(`${BASE}/v1/attestations`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({
      requested_by: "e2e-failclosed", approver_ids: [principal1, principal2], required_approvals: 2,
      action: wire,
    }),
  }).then((r) => r.json());

  // First approver genuinely approves.
  await page.goto(`/approve/index.html?attestation=${created.attestation_id}&principal=${principal1}`);
  await page.click("#approve");
  await expect(page.locator("#status")).toContainText("pending");

  let att = await fetch(`${BASE}/v1/attestations/${created.attestation_id}`).then((r) => r.json());
  expect(att.status).toBe("pending");
  expect(att.approvals).toBe(1);

  // Second approver genuinely denies. Deny signs for real now, over a
  // challenge bound to (action, "deny") -- a different challenge than
  // approve's, fetched through the page's own deny button, not hand-rolled.
  await page2.goto(`/approve/index.html?attestation=${created.attestation_id}&principal=${principal2}`);
  await page2.click("#deny");
  await expect(page2.locator("#status")).toContainText("denied");

  // Fail-closed at full strength: one denial resolves the whole attestation,
  // no matter that an approval was already recorded.
  att = await fetch(`${BASE}/v1/attestations/${created.attestation_id}`).then((r) => r.json());
  expect(att.status).toBe("denied");
  expect(att.token).toBeNull();
  // The payload is purged on any terminal resolution, deny included.
  expect(att.summary).toBeNull();
});
