import { useCallback, useEffect, useState } from "react";
import { Link, Navigate, useSearchParams } from "react-router-dom";
import * as api from "../api.js";
import type { AttestationStatus, RequestListItem } from "../api.js";
import { Layout } from "../components/Layout.js";
import { StatusMark, StatusPill } from "../components/StatusPill.js";
import { formatDateTime, formatRelative, humanize, shortHash } from "../format.js";
import { describeError, isUnauthenticated } from "../errors.js";

const TABS: Array<{ key: string; label: string }> = [
  { key: "", label: "All" },
  { key: "pending", label: "Pending" },
  { key: "approved", label: "Approved" },
  { key: "denied", label: "Denied" },
  { key: "expired", label: "Expired" },
];

/**
 * A pending row is about time remaining; a resolved one is about what happened
 * and when. The hash rides along on resolved rows because, once the payload is
 * purged, it is the only thing left that identifies *which* action this was.
 */
function rowMeta(item: RequestListItem): string {
  if (item.status === "pending") {
    return `${item.requested_by} · expires ${formatRelative(item.expires_at)}`;
  }
  const when = item.resolved_at ?? item.expires_at;
  return `${humanize(item.status)} ${formatDateTime(when)} · ${shortHash(item.payload_hash)}`;
}

export function Requests() {
  const [params, setParams] = useSearchParams();
  const status = params.get("status") ?? "";

  const [items, setItems] = useState<RequestListItem[]>([]);
  const [nextBefore, setNextBefore] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<unknown>(null);

  useEffect(() => {
    let live = true;
    setLoading(true);
    setError(null);
    api.getRequests(status ? { status } : {}).then(
      (page) => {
        if (!live) return;
        setItems(page.items);
        setNextBefore(page.next_before);
        setLoading(false);
      },
      (err: unknown) => {
        if (!live) return;
        setError(err);
        setLoading(false);
      },
    );
    return () => {
      live = false;
    };
  }, [status]);

  const loadMore = useCallback(async () => {
    if (!nextBefore) return;
    setLoadingMore(true);
    try {
      const page = await api.getRequests({
        ...(status ? { status } : {}),
        before: nextBefore,
      });
      setItems((prev) => [...prev, ...page.items]);
      setNextBefore(page.next_before);
    } catch (err) {
      setError(err);
    } finally {
      setLoadingMore(false);
    }
  }, [nextBefore, status]);

  if (isUnauthenticated(error)) return <Navigate to="/signin" replace />;

  function selectTab(key: string) {
    setParams(key ? { status: key } : {}, { replace: true });
  }

  return (
    <Layout>
      <h1 className="h1">Requests</h1>
      <p className="sub">Everything you have been asked to decide.</p>

      <div className="tabs" role="tablist">
        {TABS.map((t) => (
          <button
            key={t.key || "all"}
            type="button"
            role="tab"
            aria-selected={status === t.key}
            className={`tab${status === t.key ? " tab-active" : ""}`}
            onClick={() => selectTab(t.key)}
          >
            {t.label}
          </button>
        ))}
      </div>

      {error ? (
        <p className="notice notice-error" role="alert">
          {describeError(error)}
        </p>
      ) : null}

      {loading ? (
        <p className="skeleton">Loading…</p>
      ) : items.length === 0 && !error ? (
        <p className="empty">
          {status ? `No ${status} requests.` : "No requests yet."}
        </p>
      ) : (
        <ul className="list">
          {items.map((item) => (
            <li className="list-row" key={item.attestation_id}>
              <Link className="list-link" to={`/requests/${item.attestation_id}`}>
                <StatusMark status={item.status as AttestationStatus} />
                <span className="list-text">
                  <span className="list-title">{humanize(item.type)}</span>
                  <span className="list-meta">{rowMeta(item)}</span>
                </span>
                <StatusPill status={item.status as AttestationStatus} />
              </Link>
            </li>
          ))}
        </ul>
      )}

      {nextBefore ? (
        <div className="more">
          <button
            type="button"
            className="btn btn-ghost"
            disabled={loadingMore}
            onClick={() => void loadMore()}
          >
            {loadingMore ? "Loading…" : "Load more"}
          </button>
        </div>
      ) : null}
    </Layout>
  );
}
