import { buildServer } from "./api/server.js";
import { loadConfig } from "./config.js";

const config = loadConfig();
const app = await buildServer({
  dbPath: config.dbPath, keyDir: config.keyDir, baseUrl: config.baseUrl,
  logger: { level: config.nodeEnv === "production" ? "info" : "debug" },
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
