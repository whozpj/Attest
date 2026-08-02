import { test, expect } from "@playwright/test";
import { createPrincipal, waitForApprovalLink } from "./fixtures.js";

const BASE = "http://localhost:3000";

// Critical defect (Reviewer, this round): the closed-world validator only
// refuses extra *fields* in a payload, never constrains the *contents* of a
// legitimate string field. recipient_name (and subject/title/detail/
// document_name on other action types) is caller-controlled text that ends
// up in att.summary.fields[].value. If the approval page ever assigns that
// into innerHTML, a crafted field turns into markup -- the caller controls
// the approval page's DOM, and can make the human see one action while the
// authenticator signs the challenge for a completely different one. That is
// verbatim the threat this entire product exists to prevent (design spec
// §7.4's "no code path where the caller influences it" claim, and the
// threat-model row "agent shows the human one thing, executes another").
// Pure markup and CSS are enough; a CSP would not stop this on its own.
//
// web/src/components/SummaryCard.tsx (the SPA's replacement for the old
// hand-written approval page) interpolates every field with plain JSX
// expressions (`{f.value}`), which React always escapes -- there is no
// dangerouslySetInnerHTML anywhere in web/src (verified: `grep -rn
// dangerouslySetInnerHTML web/src` returns nothing). This test proves that
// property holds in the actual built, served page, not just by reading the
// source.
test("markup in a payload field renders as literal text, never as DOM", async ({ page }) => {
  // Never enrols a passkey -- this test only views the rendered page, so
  // enrolment_token (needed by .../credentials endpoints, not this one) is
  // unused here.
  const email = `e2e-injection-${Date.now()}@test.local`;
  const { principalId } = await createPrincipal(BASE, email);

  const maliciousRecipient = '<b id="injected">Netflix</b><script>window.__pwned = true</script>';

  const created = await fetch(`${BASE}/v1/attestations`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({
      requested_by: "e2e", approver_ids: [principalId], required_approvals: 1,
      action: {
        type: "wire_transfer", risk_tier: "high",
        payload: {
          amount: 2500000000, currency: "USD",
          recipient_name: maliciousRecipient,
          account_last4: "0000",
        },
      },
    }),
  }).then((r) => r.json());

  await page.goto(await waitForApprovalLink(email));

  // A naive assertion here (e.g. "the amount appears somewhere on the page")
  // would pass on the spoofed page too -- the spoof's whole point is to look
  // plausible. The only assertions that actually distinguish "rendered as
  // markup" from "rendered as text" are: no element from the payload was
  // created, no script executed, and the exact literal string -- angle
  // brackets and all -- is what a human would read.
  await expect(page.locator("#injected")).toHaveCount(0);
  expect(await page.evaluate(() => (window as unknown as { __pwned?: boolean }).__pwned)).toBeUndefined();

  // The headline (already textContent, unaffected by this bug) still carries
  // the real amount alongside the literal, unexecuted payload string.
  await expect(page.locator(".headline")).toHaveText(
    `Wire $25,000,000.00 USD to ${maliciousRecipient}`,
  );
  // The Recipient field (the one that used innerHTML before the fix, in the
  // now-retired hand-written approval page) shows the exact same literal
  // string, not a re-rendered DOM structure. Field order (Amount, Recipient,
  // Account) is unchanged from src/actions/render.ts, so Recipient is still
  // index 1.
  await expect(page.locator("dl.kv dd").nth(1)).toHaveText(maliciousRecipient);

  // The <dl> has the three real payload fields plus the payload-hash row
  // SummaryCard always appends (see web/src/components/SummaryCard.tsx) --
  // four of each, not three. An injected field pair (a spoofed second
  // "Amount"/"Recipient" row) would push this count past four.
  await expect(page.locator("dl.kv dt")).toHaveCount(4);
  await expect(page.locator("dl.kv dd")).toHaveCount(4);
});
