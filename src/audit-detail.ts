import { FailClosedError } from "../types.js";

const AUDIT_DETAIL = Symbol("auditDetail");
const AUDIT_EVENT = Symbol("auditEvent");

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

/**
 * Overrides the audit_log event name the central handler would otherwise
 * derive from `err.code`. Use this when a throw site's own signal name
 * carries more meaning than its HTTP error code does (e.g. a rejection
 * whose code is a generic `counter_regression` but whose real significance
 * is "this looks like a cloned credential") — so that single, richer event
 * can be the one row this rejection writes, rather than the throw site
 * keeping its own separate audit() call alongside the centralized one and
 * producing two rows for one rejection.
 */
export function withAuditEvent(err: FailClosedError, event: string): FailClosedError {
  return Object.assign(err, { [AUDIT_EVENT]: event });
}

export function auditEventOf(err: unknown): string | undefined {
  if (err && typeof err === "object" && AUDIT_EVENT in err) {
    const event = (err as Record<typeof AUDIT_EVENT, unknown>)[AUDIT_EVENT];
    if (typeof event === "string") return event;
  }
  return undefined;
}
