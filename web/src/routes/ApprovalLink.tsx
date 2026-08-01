import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import * as api from "../api.js";
import type { AttestationView } from "../api.js";
import { ApiError } from "../api.js";
import { Layout } from "../components/Layout.js";
import { StatusPill } from "../components/StatusPill.js";
import { SummaryCard } from "../components/SummaryCard.js";
import { ApprovalMeter } from "../components/ApprovalMeter.js";
import { DecisionButtons } from "../components/DecisionButtons.js";
import { describeError } from "../errors.js";

interface Resolved {
  attestation_id: string;
  principal_id: string;
  email: string;
}

/**
 * The landing page for the link in an approval email.
 *
 * The link token is a view capability and nothing more (design doc §D8): it
 * reveals which attestation this is and which approver it was addressed to,
 * and then every state change still goes through the unchanged passkey
 * ceremony on /v1/attestations/:id/*. Opening the link approves nothing.
 *
 * The request itself is read through GET /v1/attestations/:id rather than
 * /web/requests/:id, because that visitor has clicked through from their inbox
 * and may well have no session. That endpoint carries no audit trail, so this
 * page shows the decision surface and points at the signed-in history for the
 * rest, rather than pretending to data it cannot see.
 */
export function ApprovalLink() {
  const { token = "" } = useParams();

  const [resolved, setResolved] = useState<Resolved | null>(null);
  const [view, setView] = useState<AttestationView | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);

  const refresh = useCallback(async (attestationId: string) => {
    setView(await api.getAttestation(attestationId));
  }, []);

  useEffect(() => {
    let live = true;
    (async () => {
      try {
        const link = await api.resolveLink(token);
        if (!live) return;
        setResolved(link);
        const att = await api.getAttestation(link.attestation_id);
        if (!live) return;
        setView(att);
      } catch (err) {
        if (live) setError(err);
      } finally {
        if (live) setLoading(false);
      }
    })();
    return () => {
      live = false;
    };
  }, [token]);

  if (loading) {
    return (
      <Layout anonymous>
        <p className="skeleton">Loading…</p>
      </Layout>
    );
  }

  if (error || !resolved || !view) {
    const unknownLink = error instanceof ApiError && error.code === "unknown_link";
    return (
      <Layout anonymous>
        <div className="page-narrow">
          <div className="card center">
            <h1 className="h1">
              {unknownLink ? "This link is not valid" : "Request unavailable"}
            </h1>
            <p className="prose">
              {unknownLink
                ? "It may have been mistyped, or it may belong to a request that was never issued to this address. Signing in shows every request you have been asked to decide."
                : describeError(error)}
            </p>
            <Link className="btn btn-primary btn-block" to="/signin">
              Sign in
            </Link>
          </div>
        </div>
      </Layout>
    );
  }

  const decidable = view.status === "pending";

  return (
    <Layout anonymous email={resolved.email}>
      <div className="card">
        <StatusPill status={view.status} />
        <h1 className="h1">Approval request</h1>
        <p className="sub">Addressed to {resolved.email}.</p>
        <ApprovalMeter approvals={view.approvals} required={view.required_approvals} />

        {decidable ? (
          <DecisionButtons
            attestationId={resolved.attestation_id}
            principalId={resolved.principal_id}
            onDecided={() => refresh(resolved.attestation_id)}
          />
        ) : (
          <p className="notice notice-info">
            This request is already {view.status}. There is nothing left to decide.
          </p>
        )}
      </div>

      <SummaryCard summary={view.summary} payloadHash={view.payload_hash} />

      <p className="note">
        <Link to={`/requests/${resolved.attestation_id}`}>
          Sign in to see the full audit trail for this request.
        </Link>
      </p>
    </Layout>
  );
}
