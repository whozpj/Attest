import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
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
  if (res.status !== 201) {
    throw new Error(`createPrincipal failed: ${res.status} ${await res.text()}`);
  }
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
 *
 * Navigates directly to /enrol with the token, the same as a caller who
 * constructs the link by hand from POST /v1/principals's response body (see
 * README.md / docs/integration/quickstart.md) — this is documented, supported
 * usage, not a workaround. email-approval.spec.ts separately proves the link
 * mailed to the principal resolves to this same page and works identically;
 * every other spec that only needs a passkey enrolled, not a test of mail
 * delivery itself, uses this faster, non-mail-dependent path instead.
 */
export async function enrolPasskey(page: Page, principalId: string, enrolmentToken: string): Promise<void> {
  await page.goto(`/enrol?principal=${principalId}&token=${enrolmentToken}`);
  await page.getByRole("button", { name: "Enrol passkey" }).click();
  await page.getByText("Passkey enrolled").waitFor();
}

// Fixed, not randomized (e.g. not mkdtempSync): the e2e webServer
// (tests/e2e/server.ts, launched by playwright.config.ts's `webServer.command`)
// runs as a separate OS process from the Playwright test workers that import
// this module, so a per-process-generated temp dir here would produce a
// different, disconnected directory than whatever the server actually wrote
// to. A literal relative path -- passed to the server via
// playwright.config.ts's `webServer.env.MAIL_DIR`, and resolved against the
// same working directory (the project root) in every process involved --
// is what lets this file read the exact directory the server wrote to.
export const MAIL_DIR = join(process.cwd(), "mail-e2e");

/**
 * Polls MAIL_DIR for a message addressed to `to` whose body contains a link
 * matching `pathPattern`, and returns that link. This is the whole point of
 * running the suite against the file email transport instead of mocking
 * delivery: it proves the real render -> send -> write-to-disk -> extract ->
 * click path works, not merely that the API accepts a hand-constructed URL.
 */
async function waitForMailLink(
  to: string, pathPattern: RegExp, timeoutMs = 8000,
): Promise<string> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    let files: string[] = [];
    try {
      files = readdirSync(MAIL_DIR).filter((f) => f.endsWith(".eml"));
    } catch {
      files = []; // directory doesn't exist yet until the first message is sent
    }
    // File names are `${Date.now()}-${uuid}.eml` (src/email/file.ts), so a
    // plain lexicographic sort orders them chronologically; newest first is
    // what a test wants if the same address happens to receive more than one
    // message before this resolves.
    files.sort().reverse();
    for (const f of files) {
      const body = readFileSync(join(MAIL_DIR, f), "utf8");
      if (!body.includes(`To: ${to}`)) continue;
      const match = body.match(pathPattern);
      if (match) return match[0];
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`no mail matching ${pathPattern} for "${to}" within ${timeoutMs}ms`);
}

/** The link from an approval-request email — `/a/<token>`, absolute. */
export const waitForApprovalLink = (to: string): Promise<string> =>
  waitForMailLink(to, /http:\/\/[^\s"<]+\/a\/[A-Za-z0-9_-]+/);

/** The link from an enrolment email — `/enrol?principal=...&token=...`, absolute. */
export const waitForEnrolmentLink = (to: string): Promise<string> =>
  waitForMailLink(to, /http:\/\/[^\s"<]+\/enrol\?[^\s"<]+/);

/**
 * A minimal, from-scratch WebAuthn authentication ceremony, run inside the
 * page via `navigator.credentials.get` against the CDP virtual authenticator
 * `withVirtualAuthenticator(page)` already installed -- and converted to the
 * exact AuthenticationResponseJSON shape `@simplewebauthn/server` expects.
 *
 * Exists because two specs (signature-reuse-attack, unsigned-deny-attack)
 * deliberately bypass the SPA's own UI to submit a genuine signature against
 * a *different* action/decision than the one it was produced for -- that is
 * the attack under test, and it can only be expressed by calling the raw
 * WebAuthn ceremony directly, not by clicking the real Approve/Deny buttons.
 * The old version of this reached for `window.SimpleWebAuthnBrowser`, a
 * global exposed by server.ts's `/vendor/simplewebauthn-browser.js` static
 * mount. That mount served demo/public/'s hand-written pages and was removed
 * along with them (the SPA imports @simplewebauthn/browser as a bundled ES
 * module instead, with nothing left on `window` for a test to reach into).
 * Re-adding that route just for tests would reintroduce production surface
 * for a testing convenience; reimplementing the handful of WebAuthn calls the
 * library would have made is a few more lines here for zero new server-side
 * surface, runs via CDP's Runtime.evaluate rather than an inserted <script>
 * tag, and is therefore unaffected by the page's own `scriptSrc: 'self'` CSP.
 */
export async function signAuthenticationChallenge(
  page: Page,
  optionsJSON: {
    challenge: string; rpId?: string; userVerification?: string;
    allowCredentials?: Array<{ id: string }>;
  },
): Promise<unknown> {
  return page.evaluate(async (opts) => {
    const b64urlToBuf = (s: string): ArrayBuffer => {
      const pad = "=".repeat((4 - (s.length % 4)) % 4);
      const raw = atob((s + pad).replace(/-/g, "+").replace(/_/g, "/"));
      const buf = new Uint8Array(raw.length);
      for (let i = 0; i < raw.length; i++) buf[i] = raw.charCodeAt(i);
      return buf.buffer;
    };
    const bufToB64url = (buf: ArrayBuffer): string => {
      const bytes = new Uint8Array(buf);
      let str = "";
      for (const b of bytes) str += String.fromCharCode(b);
      return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    };

    const credential = (await navigator.credentials.get({
      publicKey: {
        challenge: b64urlToBuf(opts.challenge),
        rpId: opts.rpId,
        userVerification: opts.userVerification as UserVerificationRequirement | undefined,
        allowCredentials: (opts.allowCredentials ?? []).map((c) => ({
          id: b64urlToBuf(c.id), type: "public-key" as const,
        })),
      },
    })) as PublicKeyCredential;
    const response = credential.response as AuthenticatorAssertionResponse;

    return {
      id: credential.id,
      rawId: bufToB64url(credential.rawId),
      type: credential.type,
      clientExtensionResults: {},
      response: {
        clientDataJSON: bufToB64url(response.clientDataJSON),
        authenticatorData: bufToB64url(response.authenticatorData),
        signature: bufToB64url(response.signature),
      },
    };
  }, optionsJSON);
}

/**
 * Clicks a decision button (Approve/Deny) and waits for the actual
 * `POST .../decision` request it triggers to complete, rather than trusting
 * a DOM assertion right after the click to have synchronized on it.
 *
 * That distinction matters concretely for a multi-approver flow: right after
 * the FIRST approver clicks Approve, the correct status is still "Pending"
 * (quorum isn't met) -- the exact same text the pill already showed before
 * the click. Playwright's `toHaveText` only genuinely retries/waits when the
 * current DOM value differs from the expected one; when the values already
 * match, it can resolve immediately, before the click's async ceremony (and
 * the decision POST it fires) has actually finished. A test asserting
 * `.pill` still says "Pending" right after that click can therefore pass
 * before the decision has landed server-side at all -- which is exactly the
 * race that produced an intermittent `att.approvals === 0` instead of `1`
 * against the real server. Gating on the network response removes the
 * ambiguity regardless of what the DOM happens to already say.
 */
export async function clickDecision(page: Page, buttonName: string): Promise<void> {
  await Promise.all([
    page.waitForResponse((res) => res.url().includes("/decision") && res.request().method() === "POST"),
    page.getByRole("button", { name: buttonName }).click(),
  ]);
}

/**
 * Fetches real `/options` for (attestationId, principalId, decision) and
 * genuinely signs the resulting challenge, all from within the page's own
 * origin (so `expectedOrigin`/`expectedRPID` checks pass exactly as they
 * would for a real browser). Used only by the two specs described above,
 * which then submit that signature against a *different* attestation or
 * decision than the one it names.
 */
export async function signDecisionChallenge(
  page: Page, base: string, attestationId: string, principalId: string, decision: "approve" | "deny",
): Promise<unknown> {
  const optionsJSON = await page.evaluate(
    async ({ base, attestationId, principalId, decision }) => {
      const res = await fetch(`${base}/v1/attestations/${attestationId}/options`, {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ principal_id: principalId, decision }),
      });
      return res.json();
    },
    { base, attestationId, principalId, decision },
  );
  return signAuthenticationChallenge(page, optionsJSON);
}
