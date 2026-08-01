import { startAuthentication, startRegistration } from "@simplewebauthn/browser";
import * as api from "./api.js";
import type { Decision } from "./api.js";

export async function signIn(email: string): Promise<void> {
  const options = await api.signInOptions(email);
  const response = await startAuthentication({ optionsJSON: options });
  await api.signInFinish(email, response);
}

export async function enrol(principal: string, token: string): Promise<void> {
  const options = await api.enrolOptions(principal, token);
  const response = await startRegistration({ optionsJSON: options });
  await api.enrolFinish(principal, token, response);
}

/**
 * The decision is declared to the server BEFORE the ceremony, because the
 * challenge is derived from it -- hash({act, att, decision}). Approve and deny
 * therefore sign different bytes, which is what makes a captured approval
 * unusable as a denial and vice versa. Passing the wrong decision here would
 * simply fail verification, never silently record the other one.
 */
export async function decide(
  attestationId: string,
  principalId: string,
  decision: Decision,
): Promise<{ status: string; token: string | null }> {
  const options = await api.decisionOptions(attestationId, principalId, decision);
  const response = await startAuthentication({ optionsJSON: options });
  return api.submitDecision(attestationId, principalId, decision, response);
}
