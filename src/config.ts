export interface AppConfig {
  nodeEnv: "development" | "production" | "test";
  port: number;
  host: string;
  baseUrl: string;
  rpId: string;
  rpOrigin: string;
  dbPath: string;
  keyDir: string;
  trustProxy: boolean;
}

/**
 * Fail closed on boot, not on the first request: a production deployment
 * still pointing RP_ID/APP_BASE_URL at localhost would silently issue tokens
 * whose WebAuthn origin/RP-ID checks can never match a real browser's real
 * origin -- every approval would fail, indistinguishably from a config typo
 * anywhere else. Refusing to start is louder and cheaper to debug.
 */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const nodeEnv = (env.NODE_ENV as AppConfig["nodeEnv"]) ?? "development";
  // Deliberately APP_BASE_URL, not BASE_URL: Vite's own tooling (which
  // Vitest embeds) reserves the bare name BASE_URL and copies it onto
  // process.env before any test file runs, so a same-named var here would
  // silently collide under `npx vitest run` (confirmed: it resolves to "/",
  // Vite's own base-path default, not this app's default) while behaving
  // correctly in production and in the e2e suite (both plain node/tsx
  // processes with no Vite involved). Prefixing it avoids the collision
  // outright instead of requiring every test file to know to work around it.
  const baseUrl = env.APP_BASE_URL ?? "http://localhost:3000";
  const config: AppConfig = {
    nodeEnv,
    port: env.PORT ? Number(env.PORT) : 3000,
    host: env.HOST ?? "127.0.0.1",
    baseUrl,
    rpId: env.RP_ID ?? "localhost",
    rpOrigin: env.RP_ORIGIN ?? baseUrl,
    dbPath: env.DB_PATH ?? "human-attest.db",
    keyDir: env.KEY_DIR ?? "keys",
    // Off by default -- @fastify/rate-limit keys on req.ip, which Fastify
    // only derives from X-Forwarded-For when trustProxy is enabled. Left
    // false, a direct-to-internet deployment (also a valid, supported
    // topology) can't have its rate limiting bypassed by a spoofed
    // X-Forwarded-For header. Set TRUST_PROXY=true only when deploying
    // behind exactly one reverse proxy you control (see docs/PRODUCTION.md).
    trustProxy: env.TRUST_PROXY === "true",
  };

  if (config.nodeEnv === "production" &&
      (config.rpId === "localhost" || config.baseUrl.includes("localhost"))) {
    throw new Error(
      "refusing to start with NODE_ENV=production while RP_ID/APP_BASE_URL still " +
      "point at localhost -- set RP_ID and APP_BASE_URL to your real domain",
    );
  }

  return config;
}
