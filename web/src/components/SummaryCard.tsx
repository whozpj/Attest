import { Fragment } from "react";
import type { RenderedSummary } from "../api.js";

/**
 * Design doc §7 made visible to the user.
 *
 * The server purges `canonical_json` the moment an attestation reaches a
 * terminal state, and `summary` is null forever after. That is a deliberate
 * product guarantee -- this service is not a permanent store of wire amounts
 * and recipient names -- so the null branch says exactly that, in plain words,
 * rather than rendering an empty card that reads like a bug.
 *
 * There is deliberately no client-side cache of the text to fall back on. A
 * component that stashed the summary while a request was pending and replayed
 * it after resolution would reintroduce, in the browser, precisely the
 * retention the server refuses -- and would do it invisibly.
 */
export function SummaryCard({
  summary,
  payloadHash,
}: {
  summary: RenderedSummary | null;
  payloadHash: string;
}) {
  if (!summary) {
    return (
      <section className="card card-purged">
        <h2 className="card-title">Details were deleted when this request resolved</h2>
        <p className="prose">
          Human-Attest discards the request payload as soon as a decision is final, so there is
          no copy of the amounts, names, or message bodies left to show. Only the hash of the
          exact bytes that were signed is kept — anyone holding the original action can still
          check that it matches.
        </p>
        <dl className="kv">
          <dt>Payload hash</dt>
          <dd className="mono">{payloadHash}</dd>
        </dl>
      </section>
    );
  }

  return (
    <section className="card">
      <h2 className="headline">{summary.headline}</h2>
      <dl className="kv">
        {summary.fields.map((f) => (
          <Fragment key={f.label}>
            <dt>{f.label}</dt>
            <dd>{f.value}</dd>
          </Fragment>
        ))}
        <dt>Payload hash</dt>
        <dd className="mono">{payloadHash}</dd>
      </dl>
    </section>
  );
}
