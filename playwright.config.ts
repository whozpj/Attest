import { defineConfig } from "@playwright/test";
import { rmSync } from "node:fs";

// Cleared once per `npm run e2e` invocation, before the server even starts,
// so a previous run's leftover .eml files can never satisfy
// tests/e2e/fixtures.ts's waitForMailLink -- every run's mail directory
// starts genuinely empty, the same guarantee the throwaway in-memory DB and
// temp key dir in tests/e2e/server.ts already give the rest of the suite's
// state. Must be the identical relative path fixtures.ts's MAIL_DIR resolves
// against process.cwd(), and the identical value passed to the server below.
const MAIL_DIR = "mail-e2e";
rmSync(MAIL_DIR, { recursive: true, force: true });

export default defineConfig({
  testDir: "tests/e2e",
  use: { baseURL: "http://localhost:3000", browserName: "chromium" },
  webServer: {
    // Integration decision (lead, 2026-07-26): the plan's `npm run dev` +
    // `reuseExistingServer: true` let a stale process silently answer the
    // readiness probe with a 200 and a green e2e run would validate the
    // wrong build. Use an isolated, throwaway-DB server (tests/e2e/server.ts)
    // and never reuse whatever happens to already be on :3000.
    command: "npx tsx tests/e2e/server.ts",
    url: "http://localhost:3000/.well-known/jwks.json",
    reuseExistingServer: false,
    // Playwright merges this on top of the full inherited process.env when
    // spawning the server (node_modules/playwright/lib/runner/index.js), so
    // this only needs to add MAIL_DIR, not replicate the whole environment.
    env: { MAIL_DIR },
  },
});
