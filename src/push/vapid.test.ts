import { describe, it, expect } from "vitest";
import { mkdtempSync } from "node:fs";
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
});
