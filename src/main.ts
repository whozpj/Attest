import { buildServer } from "./api/server.js";
import { loadConfig } from "./config.js";

const config = loadConfig();
const app = await buildServer({
  dbPath: config.dbPath, keyDir: config.keyDir, baseUrl: config.baseUrl,
});
await app.listen({ port: config.port, host: config.host });
console.log(`human-attest listening on ${config.baseUrl}`);
