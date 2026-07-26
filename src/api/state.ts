import { randomUUID } from "node:crypto";
import type { Database } from "better-sqlite3";
import * as q from "../db/queries.js";
import { signAttestation, type Keypair } from "../crypto/tokens.js";
import { FailClosedError, type AttestationStatus, type Decision } from "../types.js";

const TOKEN_TTL_SECONDS = 300;

/** Expiry is evaluated on read, so a prototype with no scheduler cannot serve a stale pending row. */
export function effectiveStatus(db: Database, attestationId: string): AttestationStatus {
  const att = q.getAttestation(db, attestationId);
  if (!att) throw new FailClosedError("unknown_attestation", 404, "unknown attestation");
  if (att.status !== "pending") return att.status;
  return Date.parse(att.expires_at) <= Date.now() ? "expired" : "pending";
}

export async function recordDecision(
  db: Database,
  kp: Keypair,
  attestationId: string,
  principalId: string,
  decision: Decision,
  clientDataJson: string,
): Promise<{ status: AttestationStatus; token: string | null }> {
  const att = q.getAttestation(db, attestationId)!;
  const status = effectiveStatus(db, attestationId);

  if (status === "expired") {
    q.setAttestationResolved(db, attestationId, "expired", null);
    q.audit(db, { attestation_id: attestationId, event: "decision_after_expiry", actor: principalId, detail: null });
    throw new FailClosedError("expired", 410, "attestation has expired");
  }
  if (status !== "pending") {
    q.audit(db, { attestation_id: attestationId, event: "decision_after_resolution", actor: principalId, detail: status });
    throw new FailClosedError("already_resolved", 409, `attestation already resolved: ${status}`);
  }
  if (!att.approver_ids.includes(principalId)) {
    q.audit(db, { attestation_id: attestationId, event: "unauthorised_approver", actor: principalId, detail: null });
    throw new FailClosedError("not_an_approver", 403, "principal is not an approver for this attestation");
  }

  q.insertApproval(db, {
    id: `ap_${randomUUID()}`,
    attestation_id: attestationId,
    principal_id: principalId,
    decision,
    client_data_json: clientDataJson,
  });
  q.audit(db, { attestation_id: attestationId, event: `decision_${decision}`, actor: principalId, detail: null });

  const approvals = q.getApprovals(db, attestationId);

  // Fail closed: a single dissent stops the action outright. A dissenting
  // approver is a stop signal, not a vote to be outnumbered.
  if (approvals.some((a) => a.decision === "deny")) {
    q.setAttestationResolved(db, attestationId, "denied", null);
    q.purgeActionPayload(db, att.action_id);
    return { status: "denied", token: null };
  }

  const approvers = approvals.filter((a) => a.decision === "approve").map((a) => a.principal_id);
  if (approvers.length < att.required_approvals) {
    return { status: "pending", token: null };
  }

  const action = q.getAction(db, att.action_id)!;
  const token = await signAttestation(kp, {
    jti: attestationId,
    sub: approvers[0],
    act: action.payload_hash,
    approvers,
    mth: att.required_approvals > 1 ? "passkey_multi" : "passkey",
  }, TOKEN_TTL_SECONDS);

  q.setAttestationResolved(db, attestationId, "approved", token);
  q.purgeActionPayload(db, att.action_id);
  q.audit(db, { attestation_id: attestationId, event: "attestation_approved", actor: principalId, detail: null });

  return { status: "approved", token };
}
