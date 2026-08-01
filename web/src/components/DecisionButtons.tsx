import { useState } from "react";
import type { Decision } from "../api.js";
import { decide } from "../webauthn.js";
import { describeError } from "../errors.js";

/**
 * Neither button submits anything on click alone: each one opens the passkey
 * ceremony, and the server records nothing until an assertion over
 * hash({act, att, decision}) verifies. Deny costs a signature exactly like
 * approve, because a denial stops a real action and must not be forceable by
 * whoever happens to hold the link.
 *
 * `onDecided` refetches from the server rather than patching local state, so
 * the status on screen is always the one the server actually holds -- quorum
 * may not have been reached, or another approver may have resolved it first.
 */
export function DecisionButtons({
  attestationId,
  principalId,
  onDecided,
}: {
  attestationId: string;
  principalId: string;
  onDecided: () => void | Promise<void>;
}) {
  const [busy, setBusy] = useState<Decision | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function run(decision: Decision) {
    setError(null);
    setBusy(decision);
    try {
      await decide(attestationId, principalId, decision);
      await onDecided();
    } catch (err) {
      setError(describeError(err));
    } finally {
      setBusy(null);
    }
  }

  return (
    <div>
      {error ? (
        <p className="notice notice-error" role="alert">
          {error}
        </p>
      ) : null}
      <div className="btn-row">
        <button
          type="button"
          className="btn btn-primary btn-grow"
          disabled={busy !== null}
          onClick={() => void run("approve")}
        >
          {busy === "approve" ? "Waiting for passkey…" : "Approve with passkey"}
        </button>
        <button
          type="button"
          className="btn btn-danger btn-shrink"
          disabled={busy !== null}
          onClick={() => void run("deny")}
        >
          {busy === "deny" ? "Waiting…" : "Deny"}
        </button>
      </div>
      <p className="note">
        Both buttons require your passkey. Nothing is recorded until your authenticator signs
        this exact request.
      </p>
    </div>
  );
}
