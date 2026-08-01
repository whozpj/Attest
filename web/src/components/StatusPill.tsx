import type { AttestationStatus } from "../api.js";

const LABELS: Record<AttestationStatus, string> = {
  pending: "Pending",
  approved: "Approved",
  denied: "Denied",
  expired: "Expired",
};

/** Colour comes from a class, never a `style` prop -- styleSrc is 'self' with
 *  no 'unsafe-inline', so an inline colour would be dropped by the browser. */
export function StatusPill({ status }: { status: AttestationStatus }) {
  return <span className={`pill pill-${status}`}>{LABELS[status] ?? status}</span>;
}

const MARKS: Record<AttestationStatus, string> = {
  pending: "●",
  approved: "✓",
  denied: "✗",
  expired: "—",
};

export function StatusMark({ status }: { status: AttestationStatus }) {
  return (
    <span className={`list-mark list-mark-${status}`} aria-hidden="true">
      {MARKS[status] ?? "●"}
    </span>
  );
}
