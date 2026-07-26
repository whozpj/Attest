// tests/security/lib/webauthn-fake.ts
//
// A minimal software WebAuthn authenticator, used only by tests/security/**
// to produce genuine, verifiable ECDSA assertions without a browser or CDP
// virtual authenticator. This exists because some attacks in this suite need
// a real signature that src/webauthn/authentication.ts's actual verification
// path (via @simplewebauthn/server) will accept as valid — a stubbed
// public_key (e.g. Buffer.from([1,2,3])) is enough to exercise routing and
// error-shape tests, but not enough to prove or disprove a claim about what
// a *correctly signed* assertion for one challenge does when replayed
// against another.
//
// Not a general-purpose WebAuthn client: just enough of the spec (COSE key
// encoding, authenticatorData layout, ECDSA-over-authData‖clientDataHash) to
// round-trip through verifyAuthenticationResponse.
import { createHash, generateKeyPairSync, randomBytes, sign as signWithKey, type KeyObject } from "node:crypto";
import { encodeCBOR } from "@levischuck/tiny-cbor";
import { RP } from "../../../src/webauthn/config.js";

export interface FakeCredential {
  credentialId: string; // base64url, used as both `id` and `rawId`
  publicKeyCose: Buffer; // COSE_Key CBOR bytes, matches what registration would have stored
  privateKey: KeyObject;
}

/** Generates a fresh EC P-256 keypair and its COSE-encoded public key. */
export function makeFakeCredential(): FakeCredential {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = publicKey.export({ format: "jwk" }) as { x: string; y: string };
  const x = Buffer.from(jwk.x, "base64url");
  const y = Buffer.from(jwk.y, "base64url");

  // COSE_Key for an ES256 EC2 key: kty=2 (EC2), alg=-7 (ES256), crv=1 (P-256).
  // https://www.iana.org/assignments/cose/cose.xhtml
  const coseKey = new Map<number, number | Uint8Array>([
    [1, 2],
    [3, -7],
    [-1, 1],
    [-2, x],
    [-3, y],
  ]);
  const publicKeyCose = Buffer.from(encodeCBOR(coseKey as never));

  return { credentialId: randomBytes(16).toString("base64url"), publicKeyCose, privateKey };
}

/**
 * Signs a genuine WebAuthn authentication assertion over `challengeB64url` —
 * exactly the string a real authenticator would receive as
 * PublicKeyCredentialRequestOptions.challenge (already base64url, as
 * returned by beginApproval/generateAuthenticationOptions) — and returns an
 * AuthenticationResponseJSON-shaped object that
 * @simplewebauthn/server's verifyAuthenticationResponse will accept as long
 * as the challenge matches what it expects.
 */
export function signAssertion(
  cred: FakeCredential,
  challengeB64url: string,
  signCount = 1,
): {
  id: string; rawId: string; type: "public-key"; clientExtensionResults: Record<string, never>;
  response: { clientDataJSON: string; authenticatorData: string; signature: string };
} {
  const rpIdHash = createHash("sha256").update(RP.id).digest();
  const flags = Buffer.from([0x05]); // UP (0x01) + UV (0x04)
  const counter = Buffer.alloc(4);
  counter.writeUInt32BE(signCount, 0);
  const authenticatorData = Buffer.concat([rpIdHash, flags, counter]);

  const clientData = {
    type: "webauthn.get",
    challenge: challengeB64url,
    origin: RP.origin,
    crossOrigin: false,
  };
  const clientDataJSON = Buffer.from(JSON.stringify(clientData), "utf8");
  const clientDataHash = createHash("sha256").update(clientDataJSON).digest();

  // WebAuthn signs authenticatorData || SHA-256(clientDataJSON). Node's
  // default DSA encoding for crypto.sign on an EC key is DER, which is what
  // the spec (and @simplewebauthn) expects for the assertion `signature`.
  const signatureBase = Buffer.concat([authenticatorData, clientDataHash]);
  const signature = signWithKey("sha256", signatureBase, cred.privateKey);

  return {
    id: cred.credentialId,
    rawId: cred.credentialId,
    type: "public-key",
    clientExtensionResults: {},
    response: {
      clientDataJSON: clientDataJSON.toString("base64url"),
      authenticatorData: authenticatorData.toString("base64url"),
      signature: signature.toString("base64url"),
    },
  };
}
