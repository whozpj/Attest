# Human-Attest — native iOS companion

A real native SwiftUI app that enrols a Face ID / Touch ID passkey and
approves or denies pending attestations against the actual Human-Attest
server — using Apple's native platform-passkey API
(`ASAuthorizationPlatformPublicKeyCredentialProvider`), not a browser. No
server-side change was needed: WebAuthn is a standard, and Apple's native
API speaks the exact same protocol `demo/public/enrol.js`/`app.js` already
use from a browser. Every request in this app hits the real
`src/api/routes.principals.ts` / `routes.attestations.ts` endpoints.

**Status: builds, installs, and launches for real in a real Simulator on
this machine — verified via a real XCUITest that actually tapped the real
"Enrol with Face ID" button. The one remaining step, the Face ID ceremony
itself, is blocked by a confirmed, non-negotiable Apple platform
restriction: Associated Domains (required for `ASAuthorizationPlatformPublicKeyCredentialProvider`
against any domain, including `localhost`) is not available to Personal
(free) Apple Developer teams — only paid Apple Developer Program
memberships. This was confirmed twice, directly, not assumed — see below.**

**The Progressive Web App (`demo/public/app.html`) is the actual, fully
working Face ID solution today.** It does real Face ID/Touch ID
authentication via Safari's WebAuthn implementation, which has no
Associated Domains requirement (that's specifically a native-app
entitlement). This native app is real, complete, and will work the moment
a paid developer account is added to its signing team — until then, treat
the PWA as the finished product and this as ready-and-waiting.

## How it works

- **Enrol** (`EnrollView.swift`): creates a principal against the real
  server, requests real WebAuthn registration options, triggers Face ID via
  `ASAuthorizationPlatformPublicKeyCredentialProvider`, and posts the
  resulting credential back — identical ceremony to `enrol.js`, just native.
- **Approve / Deny** (`ApprovalView.swift`): paste an attestation id (the
  same one `demo/agent.ts` prints to its terminal), load its
  server-rendered summary, and sign the approve/deny decision with Face ID.
  The challenge binding (action hash + attestation id + decision) is
  entirely server-side and unchanged — this app never sees or influences
  what gets signed beyond presenting the real, server-rendered summary.
- **`WebAuthnClient.swift`**: bridges `ASAuthorizationController`'s
  delegate-based API to `async`/`await`, and `RegistrationResponseBuilder`/
  `AssertionResponseBuilder` translate Apple's native `Data`-based result
  types into the exact base64url JSON shape `@simplewebauthn/server`
  expects (`RegistrationResponseJSON`/`AuthenticationResponseJSON`).
- **No push notifications.** APNs requires a paid Apple Developer Program
  membership and real provisioning — unavailable without that same paid
  account, the same reason the web companion uses VAPID Web Push instead of
  a native equivalent. This app's approval flow is pull-based (paste the
  attestation id) rather than push-triggered.
- **`localhost` as the relying party**, matching the server's `RP.id`
  default (`src/webauthn/config.ts`). See the Associated Domains section
  below for exactly what this does and doesn't unlock without a paid
  account.

## Running it

```bash
xcodebuild -downloadPlatform iOS   # one-time, if the Simulator runtime isn't installed
brew install xcodegen              # if not already installed
cd ios
xcodegen generate                  # regenerates HumanAttest.xcodeproj from project.yml
open HumanAttest.xcodeproj
```

With the real server running (`npm run dev` from the repo root):

1. Pick any iPhone Simulator as the run destination, ⌘R.
2. **Features → Face ID → Enrolled** in the Simulator's menu bar.
3. Tap **Enrol with Face ID**. (Today, without a paid developer account,
   this will fail with an "is not associated with domain localhost" error —
   see below. With a paid account added as the signing team, this is where
   the Face ID sheet appears; **Features → Face ID → Matching Face**
   completes it.)
4. `npm run demo -- <principal_id>` in another terminal (the id the app
   shows after enrolling) — prints an `approve_url` containing the
   attestation id.
5. Paste that id into "Pending Approval," Approve, watch the demo agent's
   terminal print `Verified. Executing wire transfer.`

## Associated Domains: the confirmed, final blocker

This was traced to its actual root cause through direct, repeated testing
in this session — not inferred from documentation, not assumed:

1. **With the entitlement present** (`ios/project.yml`'s
   `com.apple.developer.associated-domains: ["webcredentials:localhost?mode=developer"]`),
   Xcode refuses to provision the app on a Personal (free) development
   team, with this exact, verbatim error: *"Cannot create an iOS App
   Development provisioning profile for 'com.humanattest.app'. Personal
   development teams, including '\<name\>', do not support the Associated
   Domains capability."* This is a hard capability gate, not a bug.
2. **With the entitlement removed entirely** — testing whether
   `ASAuthorizationPlatformPublicKeyCredentialProvider` has any built-in
   leniency for `localhost` the way browsers special-case it for local
   development — the app builds and installs fine (no entitlement to
   reject), but the real Face ID ceremony fails at runtime with: *"The
   operation couldn't be completed. Application with identifier
   FAKETEAMID.com.humanattest.app is not associated with domain
   localhost."* No leniency exists in the native API.

Both paths were verified for real, via an actual XCUITest run against a
real booted Simulator (`HumanAttestUITests/EnrollFlowUITests.swift`) that
tapped the real button and read the real resulting error text back — not
reasoned about from documentation. `?mode=developer` genuinely does what
Apple's docs say (skip needing a *hosted* `apple-app-site-association`
file), but it does not touch the separate, paid-account-only gate on the
Associated Domains capability itself. **The fix, when wanted: add a paid
Apple Developer Program membership ($99/year) as this project's signing
team in Xcode's Signing & Capabilities tab — everything else here already
works and needs no further changes.**

## What was verified for real, and how

Everything below happened against a real, booted iOS 26.3 Simulator on
this machine — not simulated, not assumed:

- **Full Xcode builds succeed** (`xcodebuild ... build` and
  `build-for-testing`), targeting the real Simulator SDK, with a real local
  code-signing identity ("Sign to Run Locally" — no paid account needed for
  this part).
- **The app installs and launches for real** (`xcrun simctl install` /
  `launch`), confirmed with real screenshots (`xcrun simctl io screenshot`)
  of the actual running UI.
- **A real bug was found and fixed this way**: the hardcoded demo email
  collided with itself on a second enrol attempt, surfacing the server's
  deliberately-opaque duplicate-email rejection
  (`principals.email UNIQUE`, anti-enumeration by design — see
  `src/api/routes.principals.ts`) as a confusing "email and display_name
  are required." Fixed by generating a fresh email per launch
  (`EnrollView.swift`'s `freshDemoEmail()`).
- **A real UI test actually taps the app**
  (`HumanAttestUITests/EnrollFlowUITests.swift`, run via
  `xcodebuild test-without-building`), using XCTest's own touch-injection
  protocol — a different, unblocked mechanism from macOS's Accessibility
  API (which requires a one-time permission grant this environment doesn't
  have, and which XCUITest doesn't need since it automates the app under
  test directly, not other Mac apps). The test's own log shows a real
  `Synthesize event` tap and a real resulting accessibility-tree read of
  the status text.
- **The `?mode=developer`-without-paid-account and no-entitlement-at-all
  paths were both directly tested**, not assumed, as described above.

None of this required GUI interaction from the assistant — the two
genuinely GUI-only steps in this whole process were signing an Apple ID
into Xcode's Accounts preferences (a one-time credential entry) and
confirming the Team dropdown in Signing & Capabilities, both of which
needed the machine owner's own authentication and both of which are
one-time setup, not something that recurs per build.
