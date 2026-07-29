import { describe, it, expect } from "vitest";
import { loadConfig } from "./config.js";

describe("loadConfig", () => {
  it("defaults to localhost development settings with no env vars", () => {
    const config = loadConfig({});
    expect(config).toEqual({
      nodeEnv: "development", port: 3000, host: "127.0.0.1",
      baseUrl: "http://localhost:3000", rpId: "localhost",
      rpOrigin: "http://localhost:3000", dbPath: "human-attest.db", keyDir: "keys",
    });
  });

  it("reads every value from the environment when set", () => {
    const config = loadConfig({
      NODE_ENV: "production", PORT: "8080", HOST: "0.0.0.0",
      BASE_URL: "https://attest.example.com", RP_ID: "example.com",
      RP_ORIGIN: "https://attest.example.com", DB_PATH: "/data/attest.db",
      KEY_DIR: "/secrets/keys",
    });
    expect(config).toEqual({
      nodeEnv: "production", port: 8080, host: "0.0.0.0",
      baseUrl: "https://attest.example.com", rpId: "example.com",
      rpOrigin: "https://attest.example.com", dbPath: "/data/attest.db",
      keyDir: "/secrets/keys",
    });
  });

  it("derives rpOrigin from baseUrl when RP_ORIGIN is not set", () => {
    const config = loadConfig({ BASE_URL: "https://attest.example.com" });
    expect(config.rpOrigin).toBe("https://attest.example.com");
  });

  it("refuses to start in production pointed at localhost", () => {
    expect(() => loadConfig({ NODE_ENV: "production" })).toThrow(/localhost/);
    expect(() => loadConfig({ NODE_ENV: "production", RP_ID: "example.com" })).toThrow(/localhost/);
  });

  it("allows production once both RP_ID and BASE_URL point at a real domain", () => {
    expect(() => loadConfig({
      NODE_ENV: "production", RP_ID: "example.com", BASE_URL: "https://attest.example.com",
    })).not.toThrow();
  });
});
