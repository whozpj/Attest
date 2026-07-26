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

export async function createPrincipal(baseURL: string, email: string): Promise<string> {
  const res = await fetch(`${baseURL}/v1/principals`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ email, display_name: email }),
  });
  return (await res.json()).principal_id as string;
}

/**
 * Enrols a passkey for `principalId` through the real browser ceremony on
 * `page`. Each Page has its own CDP session, so pairing one page with
 * `withVirtualAuthenticator(page)` per principal (rather than adding two
 * authenticators to one page) is what keeps two approvers' credentials from
 * ever sharing storage — there is no cross-page WebAuthn state to leak.
 */
export async function enrolPasskey(page: Page, principalId: string): Promise<void> {
  await page.goto(`/approve/enrol.html?principal=${principalId}`);
  await page.click("#enrol");
  await page.waitForFunction(() => document.getElementById("status")?.textContent?.includes("enrolled"));
}
