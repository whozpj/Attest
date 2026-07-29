import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import webpush from "web-push";

export interface VapidKeys { publicKey: string; privateKey: string; }

function assertShape(keys: unknown, source: string): asserts keys is VapidKeys {
  const k = keys as { publicKey?: unknown; privateKey?: unknown };
  if (typeof k.publicKey !== "string" || k.publicKey.length === 0 ||
      typeof k.privateKey !== "string" || k.privateKey.length === 0) {
    throw new Error(`${source} is malformed -- expected {publicKey, privateKey} non-empty strings`);
  }
}

/**
 * Same on-disk pattern as crypto/tokens.ts's loadOrCreateKeypair: generate
 * once, persist under the same keys/ directory, and reuse thereafter so
 * subscriptions registered against an old public key don't silently stop
 * verifying after a restart. VAPID_KEYS_JSON, when set, takes priority and
 * never touches disk -- the portable way to inject key material from a
 * secrets manager (AWS Secrets Manager, Vault, k8s Secrets, ...) without a
 * cloud-provider-specific SDK: every one of them can ultimately expose a
 * secret as an environment variable.
 */
export function loadOrCreateVapidKeys(dir: string): VapidKeys {
  const envKeys = process.env.VAPID_KEYS_JSON;
  if (envKeys) {
    const keys = JSON.parse(envKeys) as unknown;
    assertShape(keys, "VAPID_KEYS_JSON");
    return keys;
  }

  mkdirSync(dir, { recursive: true });
  const path = join(dir, "vapid-keys.json");

  if (existsSync(path)) {
    const keys = JSON.parse(readFileSync(path, "utf8")) as unknown;
    assertShape(keys, path);
    return keys;
  }

  const keys = webpush.generateVAPIDKeys();
  writeFileSync(path, JSON.stringify(keys, null, 2), { mode: 0o600 });
  return keys;
}
