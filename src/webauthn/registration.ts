import {
  generateRegistrationOptions, verifyRegistrationResponse,
  type RegistrationResponseJSON,
} from "@simplewebauthn/server";
import { randomUUID } from "node:crypto";
import type { Database } from "better-sqlite3";
import * as q from "../db/queries.js";
import { FailClosedError } from "../types.js";
import { RP } from "./config.js";

export async function beginRegistration(db: Database, principalId: string) {
  const principal = q.getPrincipal(db, principalId);
  if (!principal) throw new FailClosedError("unknown_principal", 404, "unknown principal");

  const existing = q.getCredentialsFor(db, principalId);

  return generateRegistrationOptions({
    rpName: RP.name,
    rpID: RP.id,
    userName: principal.email,
    userDisplayName: principal.display_name,
    attestationType: "none",
    excludeCredentials: existing.map((c) => ({ id: c.credential_id })),
    authenticatorSelection: { residentKey: "preferred", userVerification: "preferred" },
  });
}

export async function finishRegistration(
  db: Database,
  principalId: string,
  expectedChallenge: string,
  response: RegistrationResponseJSON,
): Promise<{ credential_id: string }> {
  const verification = await verifyRegistrationResponse({
    response,
    expectedChallenge,
    expectedOrigin: RP.origin,
    expectedRPID: RP.id,
  });

  if (!verification.verified || !verification.registrationInfo) {
    // No direct q.audit here: the central handler in src/api/server.ts
    // already writes one row for every FailClosedError that reaches it
    // (cf27972). A duplicate call here was the exact defect fixed in
    // src/webauthn/authentication.ts (a9572b7) -- see
    // tests/security/duplicate-audit-rows.test.ts.
    throw new FailClosedError("registration_failed", 400, "registration could not be verified");
  }

  const { credential } = verification.registrationInfo;

  q.insertCredential(db, {
    id: `cred_${randomUUID()}`,
    principal_id: principalId,
    credential_id: credential.id,
    public_key: Buffer.from(credential.publicKey),
    transports: response.response.transports?.join(",") ?? null,
  });

  q.audit(db, { attestation_id: null, event: "credential_registered", actor: principalId, detail: credential.id });
  return { credential_id: credential.id };
}
