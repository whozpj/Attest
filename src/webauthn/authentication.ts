import {
  generateAuthenticationOptions, verifyAuthenticationResponse,
  type AuthenticationResponseJSON,
} from "@simplewebauthn/server";
import { isoBase64URL, parseAuthenticatorData } from "@simplewebauthn/server/helpers";
import type { Database } from "better-sqlite3";
import * as q from "../db/queries.js";
import { canonicalize, hashCanonical, hashToBytes } from "../crypto/canonical.js";
import { FailClosedError, type Decision } from "../types.js";
import { RP } from "./config.js";

/**
 * The action hash is the dominant term in the challenge's preimage, alongside
 * the decision being signed. Binding the decision in means an approve and a
 * deny for the same action sign different bytes, so an assertion captured
 * for one can never be replayed as the other — deny is no longer a free,
 * unsigned action an attacker can force on a stranger's pending attestation.
 *
 * `hashToBytes(payloadHash)` below is a pure validation call — it keeps the
 * malformed-hash rejection working, since canonicalizing a malformed string
 * would otherwise silently succeed.
 */
function boundHash(payloadHash: string, decision: Decision): string {
  hashToBytes(payloadHash);
  return hashCanonical(canonicalize({ act: payloadHash, decision }));
}

export function challengeFor(payloadHash: string, decision: Decision): string {
  return Buffer.from(hashToBytes(boundHash(payloadHash, decision))).toString("base64url");
}

export async function beginApproval(
  db: Database, principalId: string, payloadHash: string, decision: Decision,
) {
  const creds = q.getCredentialsFor(db, principalId);
  if (creds.length === 0) {
    throw new FailClosedError("no_credential", 400, "principal has no enrolled credential");
  }

  return generateAuthenticationOptions({
    rpID: RP.id,
    // `.slice()` narrows to Uint8Array<ArrayBuffer>, matching the library's
    // own Uint8Array_ type (ReturnType<Uint8Array['slice']>) under strict mode.
    challenge: hashToBytes(boundHash(payloadHash, decision)).slice(),
    allowCredentials: creds.map((c) => ({ id: c.credential_id })),
    userVerification: "preferred",
  });
}

export async function finishApproval(
  db: Database,
  principalId: string,
  payloadHash: string,
  decision: Decision,
  response: AuthenticationResponseJSON,
): Promise<{ client_data_json: string }> {
  const cred = q.getCredential(db, response.id);
  if (!cred || cred.principal_id !== principalId) {
    throw new FailClosedError("unknown_credential", 401, "credential not recognised");
  }

  let verification;
  try {
    // The counter-regression check MUST run before verifyAuthenticationResponse,
    // not after. The library throws internally on the same condition (see
    // node_modules/@simplewebauthn/server/esm/authentication/verifyAuthenticationResponse.js,
    // the `(counter > 0 || credential.counter > 0) && counter <= credential.counter`
    // check), before it ever computes `verified`. A post-hoc check on
    // `verification.authenticationInfo.newCounter` is therefore unreachable dead
    // code — every input that would trip it has already thrown into the catch
    // below and been misreported as `binding_mismatch`, silently disabling
    // cloned-credential detection (spec §9) and polluting the system's
    // highest-signal audit event with an unrelated failure mode.
    //
    // We reimplement the same regression predicate here, against the library's
    // own public parsing helpers (`parseAuthenticatorData`/`isoBase64URL` from
    // `@simplewebauthn/server/helpers`) rather than string-matching its thrown
    // Error message, which a library upgrade could change without notice.
    const presentedCount = parseAuthenticatorData(
      isoBase64URL.toBuffer(response.response.authenticatorData),
    ).counter;

    if ((presentedCount > 0 || cred.sign_count > 0) && presentedCount <= cred.sign_count) {
      q.audit(db, {
        attestation_id: null, event: "possible_credential_clone",
        actor: principalId, detail: `stored=${cred.sign_count} presented=${presentedCount}`,
      });
      throw new FailClosedError("counter_regression", 401, "authenticator counter regressed");
    }

    verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge: challengeFor(payloadHash, decision),
      expectedOrigin: RP.origin,
      expectedRPID: RP.id,
      credential: {
        id: cred.credential_id,
        publicKey: new Uint8Array(cred.public_key),
        counter: cred.sign_count,
      },
    });
  } catch (err) {
    // Our own counter-regression throw above is already typed and audited;
    // let it propagate unchanged rather than relabeling it below.
    if (err instanceof FailClosedError) throw err;

    // Everything else lands here: challenge mismatch, origin/RPID mismatch, a
    // malformed response. The human signed a different action (or a different
    // decision on the same action) than the one being recorded, or the
    // response was never a valid assertion to begin with. Highest-signal
    // event in the system.
    q.audit(db, {
      attestation_id: null, event: "binding_mismatch",
      actor: principalId, detail: `hash=${payloadHash} decision=${decision}`,
    });
    throw new FailClosedError("binding_mismatch", 400, "signed challenge does not match action");
  }

  if (!verification.verified) {
    q.audit(db, { attestation_id: null, event: "signature_invalid", actor: principalId, detail: null });
    throw new FailClosedError("signature_invalid", 401, "signature verification failed");
  }

  q.updateSignCount(db, cred.credential_id, verification.authenticationInfo.newCounter);

  return {
    client_data_json: Buffer.from(response.response.clientDataJSON, "base64url").toString("utf8"),
  };
}
