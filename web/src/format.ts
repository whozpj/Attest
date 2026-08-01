const DATE_TIME = new Intl.DateTimeFormat(undefined, {
  month: "short",
  day: "numeric",
  hour: "numeric",
  minute: "2-digit",
});

const DATE_TIME_YEAR = new Intl.DateTimeFormat(undefined, {
  year: "numeric",
  month: "short",
  day: "numeric",
  hour: "numeric",
  minute: "2-digit",
});

export function formatDateTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const sameYear = d.getFullYear() === new Date().getFullYear();
  return (sameYear ? DATE_TIME : DATE_TIME_YEAR).format(d);
}

/**
 * "in 12m" / "3h ago". Coarse on purpose: an approver needs to know whether
 * they have minutes or days, and a live-ticking countdown would imply a
 * precision the expiry check does not actually have -- the server decides
 * expiry when it next reads the row, not on a clock in this tab.
 */
export function formatRelative(iso: string): string {
  const ms = new Date(iso).getTime() - Date.now();
  if (Number.isNaN(ms)) return iso;

  const future = ms > 0;
  const mins = Math.round(Math.abs(ms) / 60_000);
  let amount: string;
  if (mins < 1) amount = "less than a minute";
  else if (mins < 60) amount = `${mins}m`;
  else if (mins < 60 * 24) amount = `${Math.round(mins / 60)}h`;
  else amount = `${Math.round(mins / (60 * 24))}d`;

  return future ? `in ${amount}` : `${amount} ago`;
}

/** `sha256:9f2a4c…e81b` — enough to eyeball against another copy without
 *  letting a 71-character string wreck a one-line list row. */
export function shortHash(hash: string): string {
  const [algo, digest] = hash.includes(":") ? hash.split(/:(.*)/s) : ["", hash];
  if (!digest || digest.length <= 14) return hash;
  const short = `${digest.slice(0, 6)}…${digest.slice(-4)}`;
  return algo ? `${algo}:${short}` : short;
}

/** `wire_transfer` -> `Wire transfer`. Action types and audit events are both
 *  snake_case identifiers chosen server-side, never caller-supplied text. */
export function humanize(identifier: string): string {
  const spaced = identifier.replace(/_/g, " ");
  return spaced.charAt(0).toUpperCase() + spaced.slice(1);
}
