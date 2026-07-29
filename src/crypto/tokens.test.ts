import { describe, it, expect, beforeAll } from "vitest";
import { mkdtempSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { exportJWK } from "jose";
import { loadOrCreateKeypair, signAttestation, verifyAttestation, publicJwks } from "./tokens.js";

let kp: Awaited<ReturnType<typeof loadOrCreateKeypair>>;
let jwks: Awaited<ReturnType<typeof publicJwks>>;

const claims = {
  jti: "att_1",
  sub: "prin_1",
  act: "sha256:" + "a".repeat(64),
  approvers: ["prin_1"],
  mth: "passkey" as const,
};

beforeAll(async () => {
  kp = await loadOrCreateKeypair(mkdtempSync(join(tmpdir(), "ha-keys-")));
  jwks = await publicJwks(kp);
});

describe("attestation tokens", () => {
  it("round-trips a valid token", async () => {
    const token = await signAttestation(kp, claims, 300);
    const result = await verifyAttestation(jwks, token);
    expect(result.valid).toBe(true);
    expect(result.action_hash).toBe(claims.act);
    expect(result.principal_id).toBe("prin_1");
  });

  it("rejects a token signed by a different key", async () => {
    const other = await loadOrCreateKeypair(mkdtempSync(join(tmpdir(), "ha-other-")));
    const forged = await signAttestation(other, claims, 300);
    const result = await verifyAttestation(jwks, forged);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("signature_invalid");
  });

  it("rejects an expired token", async () => {
    const token = await signAttestation(kp, claims, -1);
    const result = await verifyAttestation(jwks, token);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe("expired");
  });

  it("rejects a tampered payload", async () => {
    const token = await signAttestation(kp, claims, 300);
    const [h, , s] = token.split(".");
    const swapped = Buffer.from(
      JSON.stringify({ ...claims, act: "sha256:" + "b".repeat(64) }),
    ).toString("base64url");
    const result = await verifyAttestation(jwks, `${h}.${swapped}.${s}`);
    expect(result.valid).toBe(false);
  });

  it("publishes a public JWKS with no private material", async () => {
    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0]).not.toHaveProperty("d");
  });

  it("reuses an existing keypair on the same directory", async () => {
    const dir = mkdtempSync(join(tmpdir(), "ha-reuse-"));
    const a = await publicJwks(await loadOrCreateKeypair(dir));
    const b = await publicJwks(await loadOrCreateKeypair(dir));
    expect(a.keys[0]).toEqual(b.keys[0]);
  });

  it("loads a keypair from SIGNING_KEY_JSON when set, without touching disk", async () => {
    const dir = mkdtempSync(join(tmpdir(), "ha-envkey-"));
    const privateJwk = await exportJWK(kp.privateKey);
    process.env.SIGNING_KEY_JSON = JSON.stringify({ privateJwk, publicJwk: kp.publicJwk, kid: kp.kid });
    try {
      const loaded = await loadOrCreateKeypair(dir);
      expect(loaded.kid).toBe(kp.kid);
      expect(existsSync(join(dir, "signing-key.json"))).toBe(false);
    } finally {
      delete process.env.SIGNING_KEY_JSON;
    }
  });
});
