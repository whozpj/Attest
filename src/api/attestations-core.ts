import { randomUUID } from "node:crypto";
import type { Database } from "better-sqlite3";
import type { JWK } from "jose";
import * as q from "../db/queries.js";
import { prepareAction, renderSummary } from "../actions/render.js";
import { validateEnvelope } from "../actions/schemas.js";
import { effectiveStatus } from "./state.js";
import { emailApprovers } from "./notify.js";
import { verifyAttestation } from "../crypto/tokens.js";
import { FailClosedError, type AttestationStatus, type RenderedSummary, type VerifyResult } from "../types.js";
import type { EmailTransport } from "../email/index.js";

export interface CreateAttestationResult {
  attestation_id: string;
  status: "pending";
  payload_hash: string;
  summary: RenderedSummary;
  approve_url: string;
}

export interface AttestationView {
  attestation_id: string;
  status: AttestationStatus;
  payload_hash: string;
  required_approvals: number;
  approvals: number;
  summary: RenderedSummary | null;
  token: string | null;
}

export interface NotifyLogger {
  warn(obj: Record<string, unknown>, msg: string): void;
}

/**
 * Shared by POST /v1/attestations (routes.attestations.ts) and the
 * request_approval MCP tool (src/mcp/server.ts) -- extracted so the two
 * entrypoints cannot drift: a fix or a new validation rule applied to one
 * automatically applies to the other, since there is only one implementation.
 */
export function createAttestation(
  db: Database,
  email: EmailTransport,
  baseUrl: string,
  input: unknown,
  logger?: NotifyLogger,
): CreateAttestationResult {
  const envelope = validateEnvelope(input);

  const action = prepareAction(envelope.action);
  const actionId = `act_${randomUUID()}`;
  q.insertAction(db, {
    id: actionId, requested_by: envelope.requested_by, type: action.type,
    canonical_json: action.canonical_json, payload_hash: action.payload_hash,
    risk_tier: (envelope.action as { risk_tier: string }).risk_tier,
  });

  const attestationId = `att_${randomUUID()}`;
  q.insertAttestation(db, {
    id: attestationId, action_id: actionId,
    required_approvals: envelope.required_approvals,
    approver_ids: envelope.approver_ids,
    expires_at: new Date(Date.now() + envelope.ttl_seconds * 1000).toISOString(),
  });

  // Best-effort, fire-and-forget: see notify.ts -- emailApprovers never
  // throws, and a slow/blackholed mail host must never add latency to (or
  // block on) attestation creation, regardless of which entrypoint created it.
  void emailApprovers(db, email, {
    attestation_id: attestationId,
    approverIds: envelope.approver_ids,
    summary: action.summary,
    requestedBy: envelope.requested_by,
    expiresAt: new Date(Date.now() + envelope.ttl_seconds * 1000).toISOString(),
    baseUrl,
  }, logger);

  return {
    attestation_id: attestationId,
    status: "pending",
    payload_hash: action.payload_hash,
    summary: action.summary,
    approve_url: `${baseUrl}/requests/${attestationId}`,
  };
}

/** Shared by GET /v1/attestations/:id and the check_approval/wait_for_approval MCP tools. */
export function getAttestationView(db: Database, id: string): AttestationView {
  // effectiveStatus must run before the action row is read: if this is the
  // read that observes a fresh expiry, it purges canonical_json as a side
  // effect. Reading the action first would return the pre-purge summary from
  // this very response, one write later than the DB actually has it.
  const status = effectiveStatus(db, id);
  const att = q.getAttestation(db, id);
  if (!att) throw new FailClosedError("unknown_attestation", 404, "unknown attestation");
  const action = q.getAction(db, att.action_id)!;
  return {
    attestation_id: id,
    status,
    payload_hash: action.payload_hash,
    required_approvals: att.required_approvals,
    approvals: q.getApprovals(db, id).length,
    summary: action.canonical_json
      ? renderSummary(action.type as never, action.canonical_json)
      : null,
    token: att.token,
  };
}

/**
 * Shared by POST /v1/attestations/verify and the consume_approval MCP tool.
 *
 * First checks the token's signature and expiry (unchanged from before this
 * function existed). If that passes, it then atomically claims a single
 * execution against the token. That second step is what actually stops one
 * human approval from authorizing two executions: a second call with the
 * exact same, still-perfectly-valid token comes back `already_consumed`.
 */
export async function verifyAndConsumeAttestation(
  db: Database, jwks: { keys: JWK[] }, token: string,
): Promise<VerifyResult> {
  const result = await verifyAttestation(jwks, token);
  if (!result.valid) return result;

  // A valid token always carries an attestation_id (its jti claim, set by
  // signAttestation on every token this service issues). This check exists
  // only so a token that somehow lacks one fails closed instead of
  // reaching consumeAttestationToken with `undefined`.
  const attestationId = result.attestation_id;
  if (!attestationId) return { valid: false, reason: "signature_invalid" };

  const consumed = q.consumeAttestationToken(db, attestationId);
  if (consumed) return result;

  q.audit(db, {
    attestation_id: attestationId,
    event: "token_already_consumed",
    actor: null,
    detail: "verify: token already consumed",
  });
  return { valid: false, reason: "already_consumed" };
}
