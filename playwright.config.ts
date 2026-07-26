import { defineConfig } from "@playwright/test";

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
  },
});
