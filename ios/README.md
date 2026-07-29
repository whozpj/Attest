# Human-Attest — native iOS companion

A real native SwiftUI app that enrols a Face ID / Touch ID passkey and
approves or denies pending attestations against the actual Human-Attest
server — using Apple's native platform-passkey API
(`ASAuthorizationPlatformPublicKeyCredentialProvider`), not a browser. No
server-side change was needed: WebAuthn is a standard, and Apple's native
API speaks the exact same protocol `demo/public/enrol.js`/`app.js` already
use from a browser. Every request in this app hits the real
`src/api/routes.principals.ts` / `routes.attestations.ts` endpoints.

## Why this exists alongside the PWA

The original build this session chose a Progressive Web App over a native
app because this build environment has no Xcode. That constraint changed —
this environment *does* have a real Xcode 26.3 install with the iOS 26.2
SDK — so this native companion was built to match. What has **not**
changed: this environment's iOS Simulator runtime is disabled (verified —
see "What was and wasn't verified" below), so this was built and compiled,
but never run on-screen, from here.

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
  membership and real provisioning — unavailable here, the same reason the
  web companion uses VAPID Web Push instead of a native equivalent. This
  app's approval flow is pull-based (paste the attestation id) rather than
  push-triggered.
- **`localhost` as the relying party, for real, via `?mode=developer`.**
  Platform passkeys normally require the RP domain to serve a real, hosted
  `apple-app-site-association` file over HTTPS — impossible for `localhost`.
  Apple's documented workaround for exactly this situation is the
  `?mode=developer` suffix on the associated-domain entry
  (`ios/project.yml`), which is honored only for debug builds launched from
  Xcode/simctl and skips that verification. This is why the app can run
  real Face ID ceremonies against `http://localhost:3000` without a real
  domain or a paid account.

## Running it (on a machine with a working Simulator)

```bash
brew install xcodegen   # if not already installed
cd ios
xcodegen generate       # regenerates HumanAttest.xcodeproj from project.yml
open HumanAttest.xcodeproj
```

Then, with the real Human-Attest server running (`npm run dev` from the
repo root, or `npx tsx src/main.ts`):

1. Build and run on an iOS Simulator (or a real device with your own Apple
   ID as a free personal-team signing identity — associated domains'
   `?mode=developer` mode works from a device debug build too, not only
   the Simulator).
2. In the Simulator: **Features → Face ID → Enrolled**, then tap Enrol —
   when the Face ID sheet appears, **Features → Face ID → Matching Face**
   completes it successfully (Non-matching Face to test a rejection).
3. In another terminal, run the real demo agent against the printed
   `principal_id`: `npm run demo -- <principal_id>` (see the repo root
   README) — it prints an `approve_url` containing the attestation id.
4. Paste that id into the app's "Pending Approval" screen, Approve with
   Face ID, and watch the agent's terminal print `Verified. Executing wire
   transfer.` — the same offline-verified proof the web/PWA demo produces,
   from a native app this time.

## What was and wasn't verified from this environment

- **Verified for real:** the Swift compiles. `xcodebuild -showdestinations`
  confirmed this environment has no usable iOS Simulator destination at all
  (Xcode reports `iOS 26.2 is not installed. Please download and install
  the platform from Xcode > Settings > Components` even though the SDK
  itself is present), so `swiftc` was invoked directly against the real
  iPhoneSimulator26.2 SDK — first `-typecheck` (clean, exit 0), then a full
  whole-module compile to object code (`swiftc -wmo -c`), producing a
  genuine 713KB `Mach-O 64-bit object arm64` file, confirmed with `file`.
  That means every API call in this app — `ASAuthorizationController`,
  `ASAuthorizationPlatformPublicKeyCredentialProvider`, every SwiftUI view,
  every `Codable` model — type-checks and compiles against Apple's real,
  current framework headers. This isn't guessed-at API usage.
- **Not verified from this environment:** actually launching the app in a
  running Simulator, tapping through the enrol/approve flow, or observing
  a real Face ID ceremony complete — the way the web/PWA companion was
  verified end-to-end with a CDP virtual authenticator earlier in this
  project. This environment's Simulator runtime doesn't come up (`xcrun
  simctl` calls hang indefinitely rather than erroring, consistent with
  Simulator support being disabled here at the platform level, not merely
  unconfigured). The steps above are exactly what would need to happen —
  and, on a machine where the Simulator actually works, should work as
  described, since the wire protocol is the same one the browser-based
  passkey flow (already proven end-to-end against this exact server) uses.
