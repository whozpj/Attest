import { buildServer } from "./api/server.js";
import { loadConfig } from "./config.js";

const config = loadConfig();
const app = await buildServer({
  dbPath: config.dbPath, keyDir: config.keyDir, baseUrl: config.baseUrl,
  logger: {
    level: config.nodeEnv === "production" ? "info" : "debug",
    // Fastify's default `req` serializer logs req.url INCLUDING the query
    // string. Enrolment tokens (Finding 3 in routes.principals.ts) travel as
    // ?token=... on .../credentials/options and .../credentials --
    // logging them verbatim would leak a live, unburned enrolment token to
    // anyone with log-read access, letting them register their own
    // authenticator as that approver. Strip the query string before it ever
    // reaches the log line.
    serializers: {
      req: (req) => ({ method: req.method, url: req.url.split("?")[0], remoteAddress: req.ip }),
    },
  },
  trustProxy: config.trustProxy,
});
await app.listen({ port: config.port, host: config.host });
console.log(`human-attest listening on ${config.baseUrl}`);

async function shutdown(signal: string): Promise<void> {
  app.log.info({ signal }, "shutting down");
  await app.close();
  app.ctx.db.close();
  process.exit(0);
}
process.on("SIGTERM", () => void shutdown("SIGTERM"));
process.on("SIGINT", () => void shutdown("SIGINT"));
