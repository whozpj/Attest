import { buildServer } from "./api/server.js";

const app = await buildServer({ dbPath: "human-attest.db", keyDir: "keys" });
await app.listen({ port: 3000, host: "127.0.0.1" });
console.log("human-attest listening on http://localhost:3000");
