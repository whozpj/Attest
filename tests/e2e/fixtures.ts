import type { Page } from "@playwright/test";

export async function withVirtualAuthenticator(page: Page): Promise<string> {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  return authenticatorId;
}

// Finding 3 (API-State): POST /v1/principals now also returns a single-use,
// principal-bound enrolment_token that .../credentials/options and
// .../credentials both require as a ?token= query param -- principal_id
// alone used to be enough to attach a rogue authenticator to someone else's
// identity, since it's not secret (it's embedded in the enrol/approve URLs
// handed out in plain text). Every caller that goes on to actually enrol a
// passkey needs this token; a caller that only creates a principal to
// reference in approver_ids (never enrolling) can ignore it.
export async function createPrincipal(
  baseURL: string, email: string,
): Promise<{ principalId: string; enrolmentToken: string }> {
  const res = await fetch(`${baseURL}/v1/principals`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ email, display_name: email }),
  });
  const body = await res.json();
  return { principalId: body.principal_id as string, enrolmentToken: body.enrolment_token as string };
}

/**
 * Enrols a passkey for `principalId` through the real browser ceremony on
 * `page`, using the single-use enrolment_token from createPrincipal(). Each
 * Page has its own CDP session, so pairing one page with
 * `withVirtualAuthenticator(page)` per principal (rather than adding two
 * authenticators to one page) is what keeps two approvers' credentials from
 * ever sharing storage — there is no cross-page WebAuthn state to leak.
 */
export async function enrolPasskey(page: Page, principalId: string, enrolmentToken: string): Promise<void> {
  await page.goto(`/approve/enrol.html?principal=${principalId}&token=${enrolmentToken}`);
  await page.click("#enrol");
  await page.waitForFunction(() => document.getElementById("status")?.textContent?.includes("enrolled"));
}
