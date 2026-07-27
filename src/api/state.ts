import { randomUUID } from "node:crypto";
import type { Database } from "better-sqlite3";
import * as q from "../db/queries.js";
import { signAttestation, type Keypair } from "../crypto/tokens.js";
import { FailClosedError, type AttestationStatus, type Decision } from "../types.js";

const TOKEN_TTL_SECONDS = 300;

/**
 * Expiry is evaluated on read, since a prototype with no scheduler cannot
 * serve a stale pending row. Detecting expiry isn't enough on its own: an
 * attestation that simply times out and is never decided would otherwise sit
 * in the database forever with its payload intact. So the first read that
 * observes expiry also resolves it and purges the payload — every path that
 * can observe "expired" ends with canonical_json gone, exactly like every
 * other terminal state (denied/approved). Later reads of an already-expired
 * row take the `att.status !== "pending"` branch and are no-ops.
 */
export function effectiveStatus(db: Database, attestationId: string): AttestationStatus {
  const att = q.getAttestation(db, attestationId);
  if (!att) throw new FailClosedError("unknown_attestation", 404, "unknown attestation");
  if (att.status !== "pending") return att.status;
  if (Date.parse(att.expires_at) > Date.now()) return "pending";

  q.setAttestationResolved(db, attestationId, "expired", null);
  q.purgeActionPayload(db, att.action_id);
  q.audit(db, { attestation_id: attestationId, event: "attestation_expired", actor: null, detail: null });
  return "expired";
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

  // effectiveStatus has already persisted an expiry transition and purged the
  // payload on first observation. Both rejections below are audited
  // centrally, in server.ts's error handler, along with every other
  // FailClosedError in the app.
  if (status === "expired") {
    throw new FailClosedError("expired", 410, "attestation has expired");
  }
  if (status !== "pending") {
    throw new FailClosedError("already_resolved", 409, `attestation already resolved: ${status}`);
  }
  if (!att.approver_ids.includes(principalId)) {
    throw new FailClosedError("not_an_approver", 403, "principal is not an approver for this attestation");
  }

  // Security control, not just tidiness: without this check, a principal who
  // already decided could submit a second, genuinely-valid signed decision
  // and hit the DB's raw UNIQUE(attestation_id, principal_id) constraint
  // instead of a typed rejection. That matters beyond the crash itself — an
  // ordinary replayed assertion (no forgery required) is reachable on any
  // authenticator whose sign_count stays at 0 across both submissions
  // (iCloud Keychain and most platform passkeys never advance the counter
  // when it's already 0 on both sides, so finishApproval's counter-regression
  // check never fires). Left unguarded, that's assertion-replay-based quorum
  // inflation: the same one real signature counted twice toward
  // required_approvals. Distinct from `already_resolved` above — that's the
  // whole attestation being terminal; this is one principal, on an
  // attestation still pending, having already cast their one decision.
  if (q.getApprovals(db, attestationId).some((a) => a.principal_id === principalId)) {
    throw new FailClosedError("already_decided", 409, "principal has already recorded a decision for this attestation");
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

  // `await` above is a yield point inside the critical section: better-sqlite3
  // is synchronous, but Fastify can serve another decision request while this
  // one is suspended signing. A concurrent denial commits immediately (no
  // await in its path), and a concurrent approval reaching quorum first can
  // commit its own token first too. Either way, "terminal is terminal" means
  // we must not blindly overwrite whatever was committed while we were away.
  // This re-check and the write below are the only remaining statements in
  // this function - no further await separates them from each other, so on a
  // single JS thread nothing can interleave between the check and the commit.
  if (effectiveStatus(db, attestationId) !== "pending") {
    const resolved = q.getAttestation(db, attestationId)!;
    q.audit(db, {
      attestation_id: attestationId, event: "stale_resolution_discarded",
      actor: principalId, detail: `computed=approved actual=${resolved.status}`,
    });
    return { status: resolved.status, token: resolved.token };
  }

  q.setAttestationResolved(db, attestationId, "approved", token);
  q.purgeActionPayload(db, att.action_id);
  q.audit(db, { attestation_id: attestationId, event: "attestation_approved", actor: principalId, detail: null });

  return { status: "approved", token };
}
