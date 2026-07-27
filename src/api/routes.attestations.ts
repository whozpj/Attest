import { randomUUID } from "node:crypto";
import type { FastifyInstance } from "fastify";
import type { AppContext } from "./server.js";
import * as q from "../db/queries.js";
import { prepareAction, renderSummary } from "../actions/render.js";
import { validateEnvelope } from "../actions/schemas.js";
import { beginApproval, finishApproval } from "../webauthn/authentication.js";
import { effectiveStatus, recordDecision } from "./state.js";
import { FailClosedError, type Decision } from "../types.js";

function assertDecision(decision: unknown): asserts decision is Decision {
  if (decision !== "approve" && decision !== "deny") {
    throw new FailClosedError("invalid_decision", 400, "decision must be 'approve' or 'deny'");
  }
}

/**
 * Every caller-supplied field that a downstream helper assumes exists gets
 * validated here, at the route boundary, before it reaches that helper —
 * not because the helpers happen to crash on it today, but because relying
 * on a helper's incidental non-crashing behaviour (a query lib's undefined
 * bind decision, e.g.) is not the same thing as a documented, audited
 * rejection. A malformed request is a rejection like any other: it gets a
 * typed FailClosedError, and server.ts's central error handler gives it an
 * audit_log row the same as every other rejection in the app.
 */
function assertPrincipalId(principalId: unknown): asserts principalId is string {
  if (typeof principalId !== "string" || principalId.length === 0) {
    throw new FailClosedError("payload_invalid", 400, "principal_id is required");
  }
}

/**
 * `finishApproval` reads `response.id` unconditionally. A missing `response`
 * used to throw a raw TypeError that escaped as an unhandled 500 with zero
 * audit trail — the exact shape of failure the fail-closed and audit-log
 * constraints exist to rule out. One opaque code covers "absent" and
 * "malformed" alike, matching the enrolment-enumeration reasoning: an
 * attacker probing this endpoint should not be able to tell the two apart.
 */
function assertSignedResponse(response: unknown): asserts response is { id: string } {
  const hasId = typeof response === "object" && response !== null
    && typeof (response as { id?: unknown }).id === "string";
  if (!hasId) {
    throw new FailClosedError("signature_required", 400, "a signed assertion is required");
  }
}

export function registerAttestationRoutes(app: FastifyInstance & { ctx: AppContext }): void {
  const { db } = app.ctx;

  app.post("/v1/attestations", async (req, reply) => {
    // Validated with the same closed-world rigor validateAction applies to
    // the nested action payload — see schemas.ts's validateEnvelope for why
    // each of these checks exists (an unvalidated approver_ids, in
    // particular, can turn state.ts's set-membership check into a substring
    // match once it round-trips through JSON.stringify/JSON.parse as a
    // non-array).
    const envelope = validateEnvelope(req.body);

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

    return reply.status(201).send({
      attestation_id: attestationId,
      status: "pending",
      payload_hash: action.payload_hash,
      summary: action.summary,
      approve_url: `http://localhost:3000/approve/index.html?attestation=${attestationId}`,
    });
  });

  app.get("/v1/attestations/:id", async (req) => {
    const { id } = req.params as { id: string };
    // effectiveStatus must run before the action row is read: if this is the
    // read that observes a fresh expiry, it purges canonical_json as a side
    // effect. Reading the action first would return the pre-purge summary
    // from this very response, one write later than the DB actually has it.
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
  });

  app.post("/v1/attestations/:id/options", async (req) => {
    const { id } = req.params as { id: string };
    const body = req.body as { principal_id?: unknown; decision?: unknown };
    // The challenge is decision-specific, so the caller must declare up front
    // which action they're about to sign for — "I'm about to approve" and
    // "I'm about to deny" are bound to different challenges before the
    // ceremony even starts, which is what makes a captured deny-assertion
    // unusable as a replayed approval and vice versa.
    assertDecision(body.decision);
    assertPrincipalId(body.principal_id);
    const att = q.getAttestation(db, id);
    if (!att) throw new FailClosedError("unknown_attestation", 404, "unknown attestation");

    // A caller must be a listed approver for THIS attestation before we hand
    // out anything — including allowCredentials, which is that principal's
    // real credential IDs. Without this check, anyone who names a valid
    // approver's principal_id (not secret — we put it in approve_url
    // ourselves) could fish out their real credential ID here, then use it
    // to submit a forged, unsigned assertion that spams the system's
    // highest-signal security alert (possible_credential_clone) against a
    // real human's credential. The response is deliberately the exact same
    // code beginApproval already produces for a principal that doesn't
    // exist at all (no_credential) — a non-approver must not be
    // distinguishable from a stranger.
    if (!att.approver_ids.includes(body.principal_id)) {
      throw new FailClosedError("no_credential", 400, "principal has no enrolled credential");
    }

    const action = q.getAction(db, att.action_id)!;
    return beginApproval(db, body.principal_id, action.payload_hash, id, body.decision);
  });

  app.post("/v1/attestations/:id/decision", async (req) => {
    const { id } = req.params as { id: string };
    const body = req.body as { principal_id?: unknown; decision?: unknown; response?: unknown };
    assertDecision(body.decision);
    assertPrincipalId(body.principal_id);
    const att = q.getAttestation(db, id);
    if (!att) throw new FailClosedError("unknown_attestation", 404, "unknown attestation");
    const action = q.getAction(db, att.action_id)!;
    assertSignedResponse(body.response);

    // finishApproval runs for both decisions, unconditionally: deny requires
    // exactly the same signed proof as approve now. A decision recorded
    // without a verified signature is a decision anyone who knows the
    // attestation_id and a principal_id could force on a stranger.
    const result = await finishApproval(
      db, body.principal_id, action.payload_hash, id, body.decision, body.response as never,
    );

    return recordDecision(db, app.ctx.kp, id, body.principal_id, body.decision, result.client_data_json);
  });
}
