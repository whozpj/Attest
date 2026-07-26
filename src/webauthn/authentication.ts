import {
  generateAuthenticationOptions, verifyAuthenticationResponse,
  type AuthenticationResponseJSON,
} from "@simplewebauthn/server";
import type { Database } from "better-sqlite3";
import * as q from "../db/queries.js";
import { hashToBytes } from "../crypto/canonical.js";
import { FailClosedError } from "../types.js";
import { RP } from "./config.js";

/**
 * The action hash IS the challenge. WebAuthn already signs its challenge, so
 * this is what binds the authenticator's signature to one specific action —
 * no novel cryptography required.
 */
export function challengeFor(payloadHash: string): string {
  return Buffer.from(hashToBytes(payloadHash)).toString("base64url");
}

export async function beginApproval(db: Database, principalId: string, payloadHash: string) {
  const creds = q.getCredentialsFor(db, principalId);
  if (creds.length === 0) {
    throw new FailClosedError("no_credential", 400, "principal has no enrolled credential");
  }

  return generateAuthenticationOptions({
    rpID: RP.id,
    // `.slice()` narrows to Uint8Array<ArrayBuffer>, matching the library's
    // own Uint8Array_ type (ReturnType<Uint8Array['slice']>) under strict mode.
    challenge: hashToBytes(payloadHash).slice(),
    allowCredentials: creds.map((c) => ({ id: c.credential_id })),
    userVerification: "preferred",
  });
}

export async function finishApproval(
  db: Database,
  principalId: string,
  payloadHash: string,
  response: AuthenticationResponseJSON,
): Promise<{ client_data_json: string }> {
  const cred = q.getCredential(db, response.id);
  if (!cred || cred.principal_id !== principalId) {
    throw new FailClosedError("unknown_credential", 401, "credential not recognised");
  }

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge: challengeFor(payloadHash),
      expectedOrigin: RP.origin,
      expectedRPID: RP.id,
      credential: {
        id: cred.credential_id,
        publicKey: new Uint8Array(cred.public_key),
        counter: cred.sign_count,
      },
    });
  } catch {
    // A challenge mismatch lands here: the human signed a different action
    // than the one being approved. Highest-signal event in the system.
    q.audit(db, {
      attestation_id: null, event: "binding_mismatch",
      actor: principalId, detail: payloadHash,
    });
    throw new FailClosedError("binding_mismatch", 400, "signed challenge does not match action");
  }

  if (!verification.verified) {
    q.audit(db, { attestation_id: null, event: "signature_invalid", actor: principalId, detail: null });
    throw new FailClosedError("signature_invalid", 401, "signature verification failed");
  }

  const newCount = verification.authenticationInfo.newCounter;
  if (cred.sign_count > 0 && newCount > 0 && newCount <= cred.sign_count) {
    q.audit(db, {
      attestation_id: null, event: "possible_credential_clone",
      actor: principalId, detail: `stored=${cred.sign_count} presented=${newCount}`,
    });
    throw new FailClosedError("counter_regression", 401, "authenticator counter regressed");
  }
  q.updateSignCount(db, cred.credential_id, newCount);

  return {
    client_data_json: Buffer.from(response.response.clientDataJSON, "base64url").toString("utf8"),
  };
}
