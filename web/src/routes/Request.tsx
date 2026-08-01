import { useCallback, useEffect, useState } from "react";
import { Link, Navigate, useParams } from "react-router-dom";
import * as api from "../api.js";
import type { RequestDetail } from "../api.js";
import { Layout } from "../components/Layout.js";
import { StatusPill } from "../components/StatusPill.js";
import { SummaryCard } from "../components/SummaryCard.js";
import { AuditTrail } from "../components/AuditTrail.js";
import { ApprovalMeter } from "../components/ApprovalMeter.js";
import { DecisionButtons } from "../components/DecisionButtons.js";
import { formatDateTime, formatRelative, humanize } from "../format.js";
import { describeError, isUnauthenticated } from "../errors.js";
import { useMe } from "../session.js";

export function Request() {
  const { id = "" } = useParams();
  const { me } = useMe();

  const [detail, setDetail] = useState<RequestDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);

  const load = useCallback(async () => {
    try {
      setDetail(await api.getRequest(id));
      setError(null);
    } catch (err) {
      setError(err);
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => {
    void load();
  }, [load]);

  if (isUnauthenticated(error)) return <Navigate to="/signin" replace />;

  if (loading) {
    return (
      <Layout>
        <p className="skeleton">Loading…</p>
      </Layout>
    );
  }

  if (error || !detail) {
    return (
      <Layout>
        <div className="card">
          <h1 className="h1">Request unavailable</h1>
          <p className="prose">{describeError(error)}</p>
          <Link className="btn btn-ghost" to="/requests">
            Back to all requests
          </Link>
        </div>
      </Layout>
    );
  }

  const decidable = detail.status === "pending" && detail.my_decision === null;

  return (
    <Layout>
      <p className="sub">
        <Link to="/requests">← All requests</Link>
      </p>

      <div className="card">
        <StatusPill status={detail.status} />
        <h1 className="h1">{humanize(detail.type)}</h1>
        <p className="sub">
          Requested by {detail.requested_by} · created {formatDateTime(detail.created_at)}
          {detail.status === "pending"
            ? ` · expires ${formatRelative(detail.expires_at)}`
            : detail.resolved_at
              ? ` · resolved ${formatDateTime(detail.resolved_at)}`
              : ""}
        </p>
        <ApprovalMeter approvals={detail.approvals} required={detail.required_approvals} />

        {detail.my_decision ? (
          <p className="notice notice-info">
            You {detail.my_decision === "approve" ? "approved" : "denied"} this request.
          </p>
        ) : null}

        {decidable && me ? (
          <DecisionButtons
            attestationId={detail.attestation_id}
            principalId={me.principal_id}
            onDecided={load}
          />
        ) : null}
      </div>

      <SummaryCard summary={detail.summary} payloadHash={detail.payload_hash} />

      <h2 className="h2">Audit trail</h2>
      <div className="card">
        <AuditTrail entries={detail.audit} />
      </div>
    </Layout>
  );
}
