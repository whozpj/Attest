import { describe, it, expect } from "vitest";
import { loadConfig } from "./config.js";

describe("loadConfig", () => {
  it("defaults to localhost development settings with no env vars", () => {
    const config = loadConfig({});
    expect(config).toEqual({
      nodeEnv: "development", port: 3000, host: "127.0.0.1",
      baseUrl: "http://localhost:3000", rpId: "localhost",
      rpOrigin: "http://localhost:3000", dbPath: "human-attest.db", keyDir: "keys",
      trustProxy: false,
      smtpUrl: undefined, mailFrom: "no-reply@localhost", mailDir: "mail",
      sessionTtlHours: 168,
    });
  });

  it("reads every value from the environment when set", () => {
    const config = loadConfig({
      NODE_ENV: "production", PORT: "8080", HOST: "0.0.0.0",
      APP_BASE_URL: "https://attest.example.com", RP_ID: "example.com",
      RP_ORIGIN: "https://attest.example.com", DB_PATH: "/data/attest.db",
      KEY_DIR: "/secrets/keys", TRUST_PROXY: "true",
      SMTP_URL: "smtp://user:pass@mail.example.com:587",
      MAIL_FROM: "attest@example.com", MAIL_DIR: "/var/mail",
      SESSION_TTL_HOURS: "24",
    });
    expect(config).toEqual({
      nodeEnv: "production", port: 8080, host: "0.0.0.0",
      baseUrl: "https://attest.example.com", rpId: "example.com",
      rpOrigin: "https://attest.example.com", dbPath: "/data/attest.db",
      keyDir: "/secrets/keys", trustProxy: true,
      smtpUrl: "smtp://user:pass@mail.example.com:587",
      mailFrom: "attest@example.com", mailDir: "/var/mail",
      sessionTtlHours: 24,
    });
  });

  it("derives rpOrigin from baseUrl when RP_ORIGIN is not set", () => {
    const config = loadConfig({ APP_BASE_URL: "https://attest.example.com" });
    expect(config.rpOrigin).toBe("https://attest.example.com");
  });

  it("refuses to start in production pointed at localhost", () => {
    expect(() => loadConfig({ NODE_ENV: "production" })).toThrow(/localhost/);
    expect(() => loadConfig({ NODE_ENV: "production", RP_ID: "example.com" })).toThrow(/localhost/);
  });

  it("allows production once both RP_ID and APP_BASE_URL point at a real domain", () => {
    expect(() => loadConfig({
      NODE_ENV: "production", RP_ID: "example.com", APP_BASE_URL: "https://attest.example.com",
      SMTP_URL: "smtp://mail.example.com",
    })).not.toThrow();
  });

  it("enables trustProxy only when TRUST_PROXY=true", () => {
    expect(loadConfig({ TRUST_PROXY: "true" }).trustProxy).toBe(true);
    expect(loadConfig({}).trustProxy).toBe(false);
  });
});

describe("email config", () => {
  const prodBase = {
    NODE_ENV: "production", RP_ID: "attest.example.com",
    APP_BASE_URL: "https://attest.example.com",
  } as NodeJS.ProcessEnv;

  it("defaults mailFrom to no-reply at the base URL host", () => {
    expect(loadConfig({ ...prodBase, SMTP_URL: "smtp://x" }).mailFrom)
      .toBe("no-reply@attest.example.com");
  });

  it("defaults the session TTL to one week", () => {
    expect(loadConfig({ ...prodBase, SMTP_URL: "smtp://x" }).sessionTtlHours).toBe(168);
  });

  it("refuses to boot in production without SMTP_URL", () => {
    expect(() => loadConfig(prodBase)).toThrow(/SMTP_URL/);
  });

  it("allows the file transport outside production", () => {
    expect(() => loadConfig({ NODE_ENV: "development" })).not.toThrow();
  });
});
