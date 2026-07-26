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
});
await app.listen({ port: 3000, host: "127.0.0.1" });
console.log("human-attest e2e server listening on http://localhost:3000");
