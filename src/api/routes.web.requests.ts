import type { FastifyInstance } from "fastify";
import type { AppContext } from "./server.js";
import * as q from "../db/queries.js";
import { renderSummary } from "../actions/render.js";
import { effectiveStatus } from "./state.js";
import { requireSession } from "./routes.web.session.js";
import { FailClosedError, type AttestationStatus } from "../types.js";

const STATUSES: AttestationStatus[] = ["pending", "approved", "denied", "expired"];
const MAX_LIMIT = 100;

function parseStatus(raw: unknown): AttestationStatus | undefined {
  if (raw === undefined) return undefined;
  if (typeof raw !== "string" || !STATUSES.includes(raw as AttestationStatus)) {
    throw new FailClosedError("payload_invalid", 400, "unknown status filter");
  }
  return raw as AttestationStatus;
}

export function registerWebRequestRoutes(app: FastifyInstance & { ctx: AppContext }): void {
  const { db } = app.ctx;

  app.get("/web/requests", async (req) => {
    const { principal_id } = requireSession(app, req);
    const query = req.query as { status?: unknown; limit?: unknown; before?: unknown };

    const status = parseStatus(query.status);
    const limit = Math.min(
      Number.isFinite(Number(query.limit)) && Number(query.limit) > 0 ? Number(query.limit) : 25,
      MAX_LIMIT,
    );
    const before = typeof query.before === "string" ? query.before : undefined;

    // One extra row tells us whether another page exists without a second
    // COUNT query, and without the off-by-one of reporting a next cursor for
    // an empty page.
    const rows = q.listRequestsFor(db, principal_id, { limit: limit + 1, status, before });
    const items = rows.slice(0, limit);

    return {
      items,
      next_before: rows.length > limit ? items[items.length - 1].created_at : null,
    };
  });

  app.get("/web/requests/:id", async (req) => {
    const { principal_id } = requireSession(app, req);
    const { id } = req.params as { id: string };

    const att = q.getAttestation(db, id);
    // A principal who is not an approver gets exactly what they would get for
    // an attestation that does not exist. Distinguishing the two would let a
    // signed-in user probe for the existence of other people's requests.
    if (!att || !att.approver_ids.includes(principal_id)) {
      throw new FailClosedError("unknown_attestation", 404, "unknown attestation");
    }

    // Evaluated before reading the action, so that if this is the read that
    // observes a fresh expiry, the purge it triggers is reflected in this
    // very response rather than one request later -- the same ordering
    // routes.attestations.ts's GET handler depends on.
    const status = effectiveStatus(db, id);
    const action = q.getAction(db, att.action_id)!;
    const approvals = q.getApprovals(db, id);

    return {
      attestation_id: id,
      type: action.type,
      status,
      requested_by: action.requested_by,
      created_at: att.created_at,
      resolved_at: att.resolved_at,
      expires_at: att.expires_at,
      payload_hash: action.payload_hash,
      my_decision: approvals.find((a) => a.principal_id === principal_id)?.decision ?? null,
      required_approvals: att.required_approvals,
      approvals: approvals.length,
      // Null once purged. The design doc's §7 decision: a resolved request
      // shows metadata and its audit trail, never retained payload text.
      summary: action.canonical_json
        ? renderSummary(action.type as never, action.canonical_json)
        : null,
      audit: q.getAuditFor(db, id),
    };
  });

  /**
   * The link token is a view capability, not an authorization: it resolves to
   * which request and which approver, and nothing here mutates attestation
   * state. Approving still requires the passkey ceremony on
   * /v1/attestations/:id/options + /decision.
   */
  app.get("/web/link/:token", async (req) => {
    const { token } = req.params as { token: string };
    const link = q.getApprovalLink(db, token);
    if (!link) throw new FailClosedError("unknown_link", 404, "unknown link");

    const principal = q.getPrincipal(db, link.principal_id)!;
    q.audit(db, {
      attestation_id: link.attestation_id, event: "approval_link_viewed",
      actor: link.principal_id, detail: null,
    });

    return {
      attestation_id: link.attestation_id,
      principal_id: link.principal_id,
      email: principal.email,
    };
  });
}
