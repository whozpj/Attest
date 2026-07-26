export type RiskTier = "low" | "medium" | "high" | "critical";
export type AttestationStatus = "pending" | "approved" | "denied" | "expired";
export type ActionType = "wire_transfer" | "send_email" | "sign_document" | "generic";
export type Decision = "approve" | "deny";

export interface ActionRequest {
  type: ActionType;
  payload: Record<string, unknown>;
  risk_tier: RiskTier;
}

export interface RenderedSummary {
  headline: string;
  fields: Array<{ label: string; value: string }>;
}

export interface CanonicalAction {
  type: ActionType;
  canonical_json: string;
  payload_hash: string;
  summary: RenderedSummary;
}

export interface AttestationRecord {
  id: string;
  action_id: string;
  status: AttestationStatus;
  required_approvals: number;
  approver_ids: string[];
  expires_at: string;
  resolved_at: string | null;
}

export interface AttestationToken {
  jti: string;
  sub: string;
  act: string;
  approvers: string[];
  mth: "passkey" | "passkey_multi";
  iat: number;
  exp: number;
}

export interface VerifyResult {
  valid: boolean;
  reason?: string;
  principal_id?: string;
  action_hash?: string;
  approved_at?: string;
}

export class FailClosedError extends Error {
  constructor(
    public readonly code: string,
    public readonly httpStatus: number,
    message: string,
  ) {
    super(message);
    this.name = "FailClosedError";
  }
}
