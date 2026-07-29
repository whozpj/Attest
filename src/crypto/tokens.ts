import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import {
  generateKeyPair, exportJWK, importJWK, SignJWT, jwtVerify,
  type JWK, type CryptoKey,
} from "jose";
import type { AttestationToken, VerifyResult } from "../types.js";

export interface Keypair {
  privateKey: CryptoKey;
  publicJwk: JWK;
  kid: string;
}

const ALG = "ES256";

export async function loadOrCreateKeypair(dir: string): Promise<Keypair> {
  const envKey = process.env.SIGNING_KEY_JSON;
  if (envKey) {
    const stored = JSON.parse(envKey) as { privateJwk: JWK; publicJwk: JWK; kid: string };
    return {
      privateKey: (await importJWK(stored.privateJwk, ALG)) as CryptoKey,
      publicJwk: stored.publicJwk,
      kid: stored.kid,
    };
  }

  mkdirSync(dir, { recursive: true });
  const path = join(dir, "signing-key.json");

  if (existsSync(path)) {
    const stored = JSON.parse(readFileSync(path, "utf8")) as {
      privateJwk: JWK; publicJwk: JWK; kid: string;
    };
    return {
      privateKey: (await importJWK(stored.privateJwk, ALG)) as CryptoKey,
      publicJwk: stored.publicJwk,
      kid: stored.kid,
    };
  }

  const { privateKey, publicKey } = await generateKeyPair(ALG, { extractable: true });
  const privateJwk = await exportJWK(privateKey);
  const publicJwk = await exportJWK(publicKey);
  const kid = `k_${Date.now()}`;
  publicJwk.kid = kid;
  publicJwk.alg = ALG;
  publicJwk.use = "sig";

  writeFileSync(path, JSON.stringify({ privateJwk, publicJwk, kid }, null, 2), { mode: 0o600 });
  return { privateKey, publicJwk, kid };
}

export async function publicJwks(kp: Keypair): Promise<{ keys: JWK[] }> {
  return { keys: [kp.publicJwk] };
}

type Claims = Omit<AttestationToken, "iat" | "exp">;

export async function signAttestation(
  kp: Keypair, claims: Claims, ttlSeconds: number,
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({
    act: claims.act,
    approvers: claims.approvers,
    mth: claims.mth,
  })
    .setProtectedHeader({ alg: ALG, kid: kp.kid })
    .setJti(claims.jti)
    .setSubject(claims.sub)
    .setIssuedAt(now)
    .setExpirationTime(now + ttlSeconds)
    .sign(kp.privateKey);
}

/**
 * Offline verification. Returns a result rather than throwing: a verifier
 * answering "no" truthfully is not an error condition.
 */
export async function verifyAttestation(
  jwks: { keys: JWK[] }, token: string,
): Promise<VerifyResult> {
  try {
    const key = (await importJWK(jwks.keys[0], ALG)) as CryptoKey;
    const { payload } = await jwtVerify(token, key, { algorithms: [ALG] });
    return {
      valid: true,
      principal_id: payload.sub,
      action_hash: payload.act as string,
      approved_at: new Date((payload.iat ?? 0) * 1000).toISOString(),
    };
  } catch (err) {
    const code = (err as { code?: string }).code;
    if (code === "ERR_JWT_EXPIRED") return { valid: false, reason: "expired" };
    return { valid: false, reason: "signature_invalid" };
  }
}
