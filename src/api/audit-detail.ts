import { FailClosedError } from "../types.js";

const AUDIT_DETAIL = Symbol("auditDetail");

/**
 * Attaches a richer, audit-only explanation to a FailClosedError without
 * touching the frozen `message` field that becomes the HTTP response body.
 * Use this where a generic message would otherwise flatten two meaningfully
 * different causes into one opaque response (by design, for anti-enumeration
 * reasons) but the real reason is still worth having in audit_log for
 * server-side investigation.
 */
export function withAuditDetail(err: FailClosedError, detail: string): FailClosedError {
  return Object.assign(err, { [AUDIT_DETAIL]: detail });
}

export function auditDetailOf(err: unknown): string | undefined {
  if (err && typeof err === "object" && AUDIT_DETAIL in err) {
    const detail = (err as Record<typeof AUDIT_DETAIL, unknown>)[AUDIT_DETAIL];
    if (typeof detail === "string") return detail;
  }
  return undefined;
}
