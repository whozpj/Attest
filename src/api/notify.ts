import { randomBytes } from "node:crypto";
import type { Database } from "better-sqlite3";
import * as q from "../db/queries.js";
import { renderApprovalEmail, renderEnrolmentEmail, type EmailTransport } from "../email/index.js";
import type { RenderedSummary } from "../types.js";

export interface NotifyLogger {
  warn(obj: Record<string, unknown>, msg: string): void;
}

/**
 * Best-effort, exactly like the push delivery it replaces. An approval email
 * is a notification, not the authorization -- the request is independently
 * reachable from the dashboard -- so a mail failure must never propagate into
 * POST /v1/attestations. Each approver is attempted independently: one
 * failure must not stop the rest, and this function never throws or rejects.
 *
 * The link token is minted here rather than at attestation-creation time
 * because it is meaningless without a delivery channel to carry it, and
 * because one token per approver is what makes the row unique per (att,
 * principal) -- a shared token would let one approver open another's link.
 */
export async function emailApprovers(
  db: Database,
  transport: EmailTransport,
  n: {
    attestation_id: string;
    approverIds: string[];
    summary: RenderedSummary;
    requestedBy: string;
    expiresAt: string;
    baseUrl: string;
  },
  logger?: NotifyLogger,
): Promise<void> {
  for (const principalId of n.approverIds) {
    try {
      const principal = q.getPrincipal(db, principalId);
      if (!principal) continue;

      let link = q.getApprovalLinkFor(db, n.attestation_id, principalId);
      if (!link) {
        const token = randomBytes(32).toString("base64url");
        q.insertApprovalLink(db, {
          token, attestation_id: n.attestation_id, principal_id: principalId,
        });
        link = { token, attestation_id: n.attestation_id, principal_id: principalId };
      }

      await transport.send(renderApprovalEmail({
        to: principal.email,
        headline: n.summary.headline,
        fields: n.summary.fields,
        requestedBy: n.requestedBy,
        expiresAt: n.expiresAt,
        linkUrl: `${n.baseUrl}/a/${link.token}`,
      }));

      q.audit(db, {
        attestation_id: n.attestation_id, event: "email_sent",
        actor: principalId, detail: null,
      });
    } catch (err) {
      q.audit(db, {
        attestation_id: n.attestation_id, event: "email_failed",
        actor: principalId, detail: String(err),
      });
      logger?.warn({ principal_id: principalId, err: String(err) }, "approval email failed");
    }
  }
}

/**
 * Same best-effort contract: POST /v1/principals still returns the enrolment
 * token in its response body, so a mail failure degrades convenience, never
 * the ability to enrol.
 */
export async function emailEnrolment(
  db: Database,
  transport: EmailTransport,
  n: { principalId: string; email: string; displayName: string; token: string; baseUrl: string },
  logger?: NotifyLogger,
): Promise<void> {
  try {
    await transport.send(renderEnrolmentEmail({
      to: n.email,
      displayName: n.displayName,
      linkUrl: `${n.baseUrl}/enrol?principal=${n.principalId}&token=${n.token}`,
    }));
    q.audit(db, {
      attestation_id: null, event: "email_sent", actor: n.principalId, detail: "enrolment",
    });
  } catch (err) {
    q.audit(db, {
      attestation_id: null, event: "email_failed", actor: n.principalId, detail: String(err),
    });
    logger?.warn({ principal_id: n.principalId, err: String(err) }, "enrolment email failed");
  }
}
