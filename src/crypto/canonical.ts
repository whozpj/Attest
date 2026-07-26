import { createHash } from "node:crypto";
import jcs from "canonicalize";

/** RFC 8785 (JCS) canonical JSON. Never use JSON.stringify for hashed data. */
export function canonicalize(value: unknown): string {
  const out = jcs(value);
  if (out === undefined) {
    throw new Error("value is not canonicalizable");
  }
  return out;
}

export function hashCanonical(canonicalJson: string): string {
  const hex = createHash("sha256").update(canonicalJson, "utf8").digest("hex");
  return `sha256:${hex}`;
}

export function hashPayload(payload: unknown): {
  canonical_json: string;
  payload_hash: string;
} {
  const canonical_json = canonicalize(payload);
  return { canonical_json, payload_hash: hashCanonical(canonical_json) };
}

/** The 32 raw digest bytes, for use as a WebAuthn challenge. */
export function hashToBytes(payloadHash: string): Uint8Array {
  const hex = payloadHash.replace(/^sha256:/, "");
  if (!/^[0-9a-f]{64}$/.test(hex)) {
    throw new Error(`malformed hash: ${payloadHash}`);
  }
  return Uint8Array.from(Buffer.from(hex, "hex"));
}
