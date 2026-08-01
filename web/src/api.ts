import type {
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
} from "@simplewebauthn/browser";

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export type AttestationStatus = "pending" | "approved" | "denied" | "expired";
export type Decision = "approve" | "deny";

export interface RequestListItem {
  attestation_id: string;
  type: string;
  status: AttestationStatus;
  requested_by: string;
  created_at: string;
  resolved_at: string | null;
  expires_at: string;
  payload_hash: string;
  my_decision: Decision | null;
}

export interface RenderedSummary {
  headline: string;
  fields: Array<{ label: string; value: string }>;
}

export interface AuditEntry {
  event: string;
  actor: string | null;
  created_at: string;
}

export interface RequestDetail extends RequestListItem {
  required_approvals: number;
  approvals: number;
  /** null once the payload was purged at resolution -- see design doc §7. */
  summary: RenderedSummary | null;
  audit: AuditEntry[];
}

/** The unchanged agent-facing view, which needs no session. */
export interface AttestationView {
  attestation_id: string;
  status: AttestationStatus;
  payload_hash: string;
  required_approvals: number;
  approvals: number;
  summary: RenderedSummary | null;
  token: string | null;
}

export interface Me {
  principal_id: string;
  email: string;
  display_name: string;
}

/**
 * Every response shape in this app is either JSON or a failure. A non-JSON
 * body (a proxy's HTML 502, an empty 204) must surface as the status it
 * actually was, not as a JSON parse exception -- otherwise every infra
 * hiccup reaches the UI as an unreadable SyntaxError.
 */
async function call<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, { credentials: "same-origin", ...init });
  const text = await res.text();
  let body: unknown = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    /* non-JSON body; the status is the only signal, and it is enough */
  }

  if (!res.ok) {
    const e = body as { error?: string; message?: string } | null;
    throw new ApiError(res.status, e?.error ?? "http_error", e?.message ?? `HTTP ${res.status}`);
  }
  return body as T;
}

const json = (body: unknown): RequestInit => ({
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify(body),
});

export const getMe = () => call<Me>("/web/me");

export const getRequests = (opts: { status?: string; before?: string }) => {
  const p = new URLSearchParams();
  if (opts.status) p.set("status", opts.status);
  if (opts.before) p.set("before", opts.before);
  const qs = p.toString();
  return call<{ items: RequestListItem[]; next_before: string | null }>(
    `/web/requests${qs ? `?${qs}` : ""}`,
  );
};

export const getRequest = (id: string) =>
  call<RequestDetail>(`/web/requests/${encodeURIComponent(id)}`);

export const resolveLink = (token: string) =>
  call<{ attestation_id: string; principal_id: string; email: string }>(
    `/web/link/${encodeURIComponent(token)}`,
  );

export const signInOptions = (email: string) =>
  call<PublicKeyCredentialRequestOptionsJSON>("/web/session/options", json({ email }));
export const signInFinish = (email: string, response: unknown) =>
  call<null>("/web/session", json({ email, response }));
export const signOut = () => call<null>("/web/session", { method: "DELETE" });

/** Unchanged /v1 surface: readable without a session, which is what the
 *  email-link landing page relies on. */
export const getAttestation = (id: string) =>
  call<AttestationView>(`/v1/attestations/${encodeURIComponent(id)}`);

export const decisionOptions = (id: string, principal_id: string, decision: Decision) =>
  call<PublicKeyCredentialRequestOptionsJSON>(
    `/v1/attestations/${encodeURIComponent(id)}/options`,
    json({ principal_id, decision }),
  );
export const submitDecision = (
  id: string,
  principal_id: string,
  decision: Decision,
  response: unknown,
) =>
  call<{ status: string; token: string | null }>(
    `/v1/attestations/${encodeURIComponent(id)}/decision`,
    json({ principal_id, decision, response }),
  );

export const enrolOptions = (principal: string, token: string) =>
  call<PublicKeyCredentialCreationOptionsJSON>(
    `/v1/principals/${encodeURIComponent(principal)}/credentials/options?token=${encodeURIComponent(token)}`,
    { method: "POST" },
  );
export const enrolFinish = (principal: string, token: string, response: unknown) =>
  call<{ credential_id: string }>(
    `/v1/principals/${encodeURIComponent(principal)}/credentials?token=${encodeURIComponent(token)}`,
    json(response),
  );
