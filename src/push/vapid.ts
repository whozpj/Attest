import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import webpush from "web-push";

export interface VapidKeys { publicKey: string; privateKey: string; }

/**
 * Same on-disk pattern as crypto/tokens.ts's loadOrCreateKeypair: generate
 * once, persist under the same keys/ directory, and reuse thereafter so
 * subscriptions registered against an old public key don't silently stop
 * verifying after a restart.
 */
export function loadOrCreateVapidKeys(dir: string): VapidKeys {
  mkdirSync(dir, { recursive: true });
  const path = join(dir, "vapid-keys.json");

  if (existsSync(path)) {
    return JSON.parse(readFileSync(path, "utf8")) as VapidKeys;
  }

  const keys = webpush.generateVAPIDKeys();
  writeFileSync(path, JSON.stringify(keys, null, 2), { mode: 0o600 });
  return keys;
}
