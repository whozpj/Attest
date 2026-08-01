import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Layout } from "../components/Layout.js";
import { enrol } from "../webauthn.js";
import { describeError } from "../errors.js";

export function Enrol() {
  const [params] = useSearchParams();
  const principal = params.get("principal") ?? "";
  const token = params.get("token") ?? "";

  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function run() {
    setError(null);
    setBusy(true);
    try {
      await enrol(principal, token);
      setDone(true);
    } catch (err) {
      setError(describeError(err));
    } finally {
      setBusy(false);
    }
  }

  const usable = principal !== "" && token !== "";

  return (
    <Layout anonymous>
      <div className="page-narrow">
        <div className="card center">
          <h1 className="h1">Set up your passkey</h1>
          <p className="sub">
            One ceremony now, and every future approval is a Face ID or fingerprint prompt.
          </p>

          {!usable ? (
            <p className="notice notice-error" role="alert">
              This enrolment link is incomplete. Open the link from your enrolment email
              exactly as it was sent.
            </p>
          ) : null}

          {error ? (
            <p className="notice notice-error" role="alert">
              {error}
            </p>
          ) : null}

          {done ? (
            <>
              <p className="notice notice-ok" role="status">
                Passkey enrolled. You can approve requests with it now.
              </p>
              <Link className="btn btn-primary btn-block" to="/signin">
                Go to sign in
              </Link>
            </>
          ) : (
            <button
              type="button"
              className="btn btn-primary btn-block"
              disabled={busy || !usable}
              onClick={() => void run()}
            >
              {busy ? "Waiting for passkey…" : "Enrol passkey"}
            </button>
          )}

          <p className="note">
            This link is single-use and expires 15 minutes after it was issued.
          </p>
        </div>
      </div>
    </Layout>
  );
}
