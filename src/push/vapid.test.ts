import { describe, it, expect } from "vitest";
import { mkdtempSync, existsSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadOrCreateVapidKeys } from "./vapid.js";

describe("VAPID keys", () => {
  it("creates a public/private key pair", () => {
    const keys = loadOrCreateVapidKeys(mkdtempSync(join(tmpdir(), "ha-vapid-")));
    expect(typeof keys.publicKey).toBe("string");
    expect(keys.publicKey.length).toBeGreaterThan(0);
    expect(typeof keys.privateKey).toBe("string");
    expect(keys.privateKey.length).toBeGreaterThan(0);
  });

  it("reuses an existing key pair on the same directory", () => {
    const dir = mkdtempSync(join(tmpdir(), "ha-vapid-reuse-"));
    const a = loadOrCreateVapidKeys(dir);
    const b = loadOrCreateVapidKeys(dir);
    expect(b.publicKey).toBe(a.publicKey);
    expect(b.privateKey).toBe(a.privateKey);
  });

  it("generates distinct keys across different directories", () => {
    const a = loadOrCreateVapidKeys(mkdtempSync(join(tmpdir(), "ha-vapid-a-")));
    const b = loadOrCreateVapidKeys(mkdtempSync(join(tmpdir(), "ha-vapid-b-")));
    expect(a.publicKey).not.toBe(b.publicKey);
  });

  it("loads keys from VAPID_KEYS_JSON when set, without touching disk", () => {
    const dir = mkdtempSync(join(tmpdir(), "ha-vapid-envkey-"));
    process.env.VAPID_KEYS_JSON = JSON.stringify({ publicKey: "env-pub", privateKey: "env-priv" });
    try {
      const keys = loadOrCreateVapidKeys(dir);
      expect(keys).toEqual({ publicKey: "env-pub", privateKey: "env-priv" });
      expect(existsSync(join(dir, "vapid-keys.json"))).toBe(false);
    } finally {
      delete process.env.VAPID_KEYS_JSON;
    }
  });

  it("throws if VAPID_KEYS_JSON is malformed", () => {
    process.env.VAPID_KEYS_JSON = JSON.stringify({ publicKey: "" });
    try {
      expect(() => loadOrCreateVapidKeys(mkdtempSync(join(tmpdir(), "ha-vapid-bad-")))).toThrow(/malformed/);
    } finally {
      delete process.env.VAPID_KEYS_JSON;
    }
  });

  it("throws if the on-disk vapid-keys.json is malformed", () => {
    const dir = mkdtempSync(join(tmpdir(), "ha-vapid-corrupt-"));
    writeFileSync(join(dir, "vapid-keys.json"), JSON.stringify({ publicKey: "" }));
    expect(() => loadOrCreateVapidKeys(dir)).toThrow(/malformed/);
  });
});
