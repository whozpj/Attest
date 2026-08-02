// Isolated server entrypoint for the e2e suite only. Unlike `npm run dev`
// (src/main.ts), this never touches the persistent human-attest.db / keys
// directory used for manual demoing — each e2e run gets its own throwaway
// in-memory database and temp key dir, so a test can never pass on state
// left over from a previous run.
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildServer } from "../../src/api/server.js";

const app = await buildServer({
  dbPath: ":memory:",
  keyDir: mkdtempSync(join(tmpdir(), "ha-e2e-")),
  // Measured: a full `npm run e2e` (5 parallel Playwright workers, real
  // browser navigations, real MCP client calls) drives ~165 requests against
  // the routes that share the global bucket in well under a minute -- already
  // past the production default of 100 with today's suite, before counting
  // any future spec. That's an artifact of running many workers against one
  // shared process, not a rate this app would ever see from a single real
  // client; this instance is a throwaway, never internet-facing (see the
  // module comment above). 500 keeps real headroom without touching the
  // production default itself (see buildServer's globalRateLimit option).
  globalRateLimit: { max: 500, timeWindow: "1 minute" },
});
await app.listen({ port: 3000, host: "127.0.0.1" });
console.log("human-attest e2e server listening on http://localhost:3000");
