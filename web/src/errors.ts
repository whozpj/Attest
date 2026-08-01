import { WebAuthnError } from "@simplewebauthn/browser";
import { ApiError } from "./api.js";

/** Codes that mean "your session is gone", per design doc §6. */
export function isUnauthenticated(err: unknown): boolean {
  return (
    err instanceof ApiError && (err.code === "no_session" || err.code === "session_expired")
  );
}

/**
 * The server writes deliberately opaque messages for anti-enumeration (design
 * doc §4.3), so an ApiError's message is rendered verbatim -- the UI must not
 * add detail the server chose to withhold, and must not guess at a cause.
 *
 * Ceremony failures are different: they never reached the server, so there is
 * no server wording to defer to, and "the prompt was dismissed" is both true
 * and the only actionable thing to say.
 */
export function describeError(err: unknown): string {
  if (err instanceof ApiError) return err.message;

  if (err instanceof WebAuthnError || err instanceof DOMException) {
    if (err.name === "NotAllowedError" || err.name === "AbortError") {
      return "The passkey prompt was dismissed or timed out. Nothing was recorded.";
    }
    if (err.name === "InvalidStateError") {
      return "This device already has a passkey enrolled for this account.";
    }
    if (err.name === "SecurityError") {
      return "This page's origin does not match the one your passkey was created for.";
    }
    return err.message || "The passkey ceremony could not be completed.";
  }

  if (err instanceof TypeError) {
    return "Could not reach the server. Check your connection and try again.";
  }
  return err instanceof Error && err.message ? err.message : "Something went wrong.";
}
