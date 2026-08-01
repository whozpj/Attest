import { useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { Layout } from "../components/Layout.js";
import { signIn } from "../webauthn.js";
import { describeError } from "../errors.js";
import { clearMe } from "../session.js";

export function SignIn() {
  const [email, setEmail] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await signIn(email.trim());
      clearMe();
      navigate("/requests", { replace: true });
    } catch (err) {
      // The server answers identically for a registered address, an
      // unregistered one, and one with no credential (design doc §4.3). The
      // UI renders its message verbatim and adds nothing: guessing at a
      // cause here would hand back exactly the enumeration signal the
      // server went out of its way not to give.
      setError(describeError(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Layout anonymous>
      <div className="page-narrow">
        <div className="card center">
          <h1 className="h1">Sign in</h1>
          <p className="sub">Your requests, past and pending.</p>

          {error ? (
            <p className="notice notice-error" role="alert">
              {error}
            </p>
          ) : null}

          <form onSubmit={onSubmit}>
            <label className="field">
              <span className="field-label">Email address</span>
              <input
                className="input"
                type="email"
                name="email"
                autoComplete="username webauthn"
                placeholder="you@example.com"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
              />
            </label>
            <button type="submit" className="btn btn-primary btn-block" disabled={busy}>
              {busy ? "Waiting for passkey…" : "Continue with passkey"}
            </button>
          </form>

          <p className="note">
            The same passkey you use to approve. No password, and no sign-in link that could
            approve anything on its own.
          </p>
        </div>
      </div>
    </Layout>
  );
}
