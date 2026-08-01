import type { AuditEntry } from "../api.js";
import { formatDateTime, humanize } from "../format.js";

/**
 * The audit trail is what survives the payload purge, so on a resolved
 * request it is the substance of the page rather than a footnote. Events and
 * actors are server-chosen identifiers, never caller-supplied display text.
 */
export function AuditTrail({ entries }: { entries: AuditEntry[] }) {
  if (entries.length === 0) {
    return <p className="prose">No audit entries recorded for this request.</p>;
  }

  return (
    <ol className="audit">
      {entries.map((e, i) => (
        <li className="audit-item" key={`${e.created_at}-${e.event}-${i}`}>
          <div className="audit-rail" />
          <div className="audit-body">
            <div className="audit-event">{humanize(e.event)}</div>
            <div className="audit-meta">
              {formatDateTime(e.created_at)}
              {e.actor ? ` · ${e.actor}` : ""}
            </div>
          </div>
        </li>
      ))}
    </ol>
  );
}
