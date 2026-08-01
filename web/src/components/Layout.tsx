import type { ReactNode } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import * as api from "../api.js";
import { clearMe, useMe } from "../session.js";

/**
 * `anonymous` suppresses the `GET /web/me` probe on pages a signed-out
 * visitor is expected to reach -- sign-in, enrolment, and the email landing
 * page. Probing there would 401 on every load, and every 401 writes a
 * `no_session` row to audit_log; a page that is *supposed* to be visited
 * without a session should not manufacture a rejection record each time.
 *
 * `email` lets the email landing page show who the link was addressed to,
 * which it learns from GET /web/link/:token rather than from a session.
 */
export function Layout({
  children,
  anonymous = false,
  email,
}: {
  children: ReactNode;
  anonymous?: boolean;
  email?: string;
}) {
  const { me } = useMe(!anonymous);
  const navigate = useNavigate();
  const onSignIn = useLocation().pathname === "/signin";

  async function handleSignOut() {
    try {
      await api.signOut();
    } catch {
      /* Already signed out, or the server is unreachable. Either way the
         local view of the session must not survive the attempt. */
    }
    clearMe();
    navigate("/signin", { replace: true });
  }

  const shownEmail = email ?? me?.email;

  return (
    <div className="app">
      <header className="topbar">
        <div className="topbar-inner">
          <Link className="brand" to="/requests">
            Human-Attest
          </Link>
          <div className="topbar-user">
            {shownEmail ? <span className="topbar-email">{shownEmail}</span> : null}
            {me ? (
              <button type="button" className="btn-link" onClick={handleSignOut}>
                Sign out
              </button>
            ) : onSignIn ? null : (
              <Link className="btn-link" to="/signin">
                Sign in
              </Link>
            )}
          </div>
        </div>
      </header>
      <main className="page">{children}</main>
    </div>
  );
}
