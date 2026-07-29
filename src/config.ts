export interface AppConfig {
  nodeEnv: "development" | "production" | "test";
  port: number;
  host: string;
  baseUrl: string;
  rpId: string;
  rpOrigin: string;
  dbPath: string;
  keyDir: string;
}

/**
 * Fail closed on boot, not on the first request: a production deployment
 * still pointing RP_ID/BASE_URL at localhost would silently issue tokens
 * whose WebAuthn origin/RP-ID checks can never match a real browser's real
 * origin -- every approval would fail, indistinguishably from a config typo
 * anywhere else. Refusing to start is louder and cheaper to debug.
 */
export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const nodeEnv = (env.NODE_ENV as AppConfig["nodeEnv"]) ?? "development";
  const baseUrl = env.BASE_URL ?? "http://localhost:3000";
  const config: AppConfig = {
    nodeEnv,
    port: env.PORT ? Number(env.PORT) : 3000,
    host: env.HOST ?? "127.0.0.1",
    baseUrl,
    rpId: env.RP_ID ?? "localhost",
    rpOrigin: env.RP_ORIGIN ?? baseUrl,
    dbPath: env.DB_PATH ?? "human-attest.db",
    keyDir: env.KEY_DIR ?? "keys",
  };

  if (config.nodeEnv === "production" &&
      (config.rpId === "localhost" || config.baseUrl.includes("localhost"))) {
    throw new Error(
      "refusing to start with NODE_ENV=production while RP_ID/BASE_URL still " +
      "point at localhost -- set RP_ID and BASE_URL to your real domain",
    );
  }

  return config;
}
