import { randomUUID } from "node:crypto";
import type { FastifyInstance } from "fastify";
import type { AppContext } from "./server.js";
import * as q from "../db/queries.js";
import { prepareAction, renderSummary } from "../actions/render.js";
import { beginApproval, finishApproval } from "../webauthn/authentication.js";
import { effectiveStatus, recordDecision } from "./state.js";
import { FailClosedError, type Decision } from "../types.js";

export function registerAttestationRoutes(app: FastifyInstance & { ctx: AppContext }): void {
  const { db } = app.ctx;

  app.post("/v1/attestations", async (req, reply) => {
    const body = req.body as {
      action: unknown; approver_ids: string[];
      required_approvals?: number; requested_by: string; ttl_seconds?: number;
    };

    const action = prepareAction(body.action);
    const actionId = `act_${randomUUID()}`;
    q.insertAction(db, {
      id: actionId, requested_by: body.requested_by, type: action.type,
      canonical_json: action.canonical_json, payload_hash: action.payload_hash,
      risk_tier: (body.action as { risk_tier: string }).risk_tier,
    });

    const attestationId = `att_${randomUUID()}`;
    q.insertAttestation(db, {
      id: attestationId, action_id: actionId,
      required_approvals: body.required_approvals ?? 1,
      approver_ids: body.approver_ids,
      expires_at: new Date(Date.now() + (body.ttl_seconds ?? 900) * 1000).toISOString(),
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
    const att = q.getAttestation(db, id);
    if (!att) throw new FailClosedError("unknown_attestation", 404, "unknown attestation");
    const action = q.getAction(db, att.action_id)!;
    return {
      attestation_id: id,
      status: effectiveStatus(db, id),
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
    const { principal_id } = req.body as { principal_id: string };
    const att = q.getAttestation(db, id);
    if (!att) throw new FailClosedError("unknown_attestation", 404, "unknown attestation");
    const action = q.getAction(db, att.action_id)!;
    return beginApproval(db, principal_id, action.payload_hash);
  });

  app.post("/v1/attestations/:id/decision", async (req) => {
    const { id } = req.params as { id: string };
    const body = req.body as { principal_id: string; decision: Decision; response?: unknown };
    const att = q.getAttestation(db, id);
    if (!att) throw new FailClosedError("unknown_attestation", 404, "unknown attestation");
    const action = q.getAction(db, att.action_id)!;

    let clientDataJson = "{}";
    if (body.decision === "approve") {
      const result = await finishApproval(
        db, body.principal_id, action.payload_hash, body.response as never,
      );
      clientDataJson = result.client_data_json;
    }

    return recordDecision(db, app.ctx.kp, id, body.principal_id, body.decision, clientDataJson);
  });
}
