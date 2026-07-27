import { FailClosedError, type ActionRequest, type ActionType, type RiskTier } from "../types.js";

type FieldType = "string" | "number";
interface FieldSpec { name: string; type: FieldType; }

const SCHEMAS: Record<ActionType, FieldSpec[]> = {
  wire_transfer: [
    { name: "amount", type: "number" },
    { name: "currency", type: "string" },
    { name: "recipient_name", type: "string" },
    { name: "account_last4", type: "string" },
  ],
  send_email: [
    { name: "to", type: "string" },
    { name: "subject", type: "string" },
    { name: "body", type: "string" },
  ],
  sign_document: [
    { name: "document_name", type: "string" },
    { name: "document_hash", type: "string" },
  ],
  generic: [
    { name: "title", type: "string" },
    { name: "detail", type: "string" },
  ],
};

const TIERS: RiskTier[] = ["low", "medium", "high", "critical"];

function reject(message: string): never {
  throw new FailClosedError("payload_invalid", 400, message);
}

export function validateAction(input: unknown): ActionRequest {
  if (typeof input !== "object" || input === null) reject("action must be an object");
  const req = input as Record<string, unknown>;

  const type = req.type as ActionType;
  if (!(typeof type === "string" && type in SCHEMAS)) reject(`unknown action type: ${String(type)}`);

  const risk_tier = req.risk_tier as RiskTier;
  if (!TIERS.includes(risk_tier)) reject(`invalid risk_tier: ${String(risk_tier)}`);

  const payload = req.payload;
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
    reject("payload must be an object");
  }
  const p = payload as Record<string, unknown>;
  const spec = SCHEMAS[type];

  for (const field of spec) {
    const value = p[field.name];
    if (value === undefined) reject(`missing required field: ${field.name}`);
    if (typeof value !== field.type) {
      reject(`field ${field.name} must be a ${field.type}`);
    }
  }

  // Closed-world: anything not in the schema is refused, which is what stops a
  // caller smuggling display text into the payload.
  const allowed = new Set(spec.map((f) => f.name));
  for (const key of Object.keys(p)) {
    if (!allowed.has(key)) reject(`unexpected field: ${key}`);
  }

  return { type, risk_tier, payload: p };
}

const DEFAULT_REQUIRED_APPROVALS = 1;
const DEFAULT_TTL_SECONDS = 900;

// A generous but finite bound, not a business rule: it exists purely to keep
// `Date.now() + ttl_seconds * 1000` inside the range `Date` can represent
// (roughly +/-8.64e15 ms from the epoch). Without it, a caller-supplied
// ttl_seconds of, say, 1e15 turns `new Date(...).toISOString()` into a thrown
// RangeError ("Invalid time value") that escapes as an unaudited 500 instead
// of a typed rejection. Negative values are deliberately still allowed on the
// low end (bounded the same way) — tests rely on e.g. ttl_seconds: -1 to mint
// an attestation that is already expired the moment it's created.
const MAX_ABS_TTL_SECONDS = 315_360_000; // 10 years

export interface AttestationEnvelope {
  requested_by: string;
  approver_ids: string[];
  required_approvals: number;
  ttl_seconds: number;
  action: unknown;
}

/**
 * Validates the top-level POST /v1/attestations request body with the same
 * closed-world rigor validateAction applies to the nested action payload.
 * Every field a downstream helper (db/queries.ts, state.ts) assumes exists
 * and is well-typed is checked here, at the boundary, rather than trusted:
 *
 *   - approver_ids must be a real array of non-empty strings. Before this
 *     check, a string body (`"not-an-array"`) round-tripped through
 *     JSON.stringify/JSON.parse unchanged, and state.ts's
 *     `att.approver_ids.includes(principalId)` silently became a *substring*
 *     test on that string instead of a set-membership test on an array —
 *     turning the approver allowlist into something a crafted principal_id
 *     could partially match.
 *   - required_approvals is bounded to [1, approver_ids.length]: 0 or a
 *     negative number would make the quorum check in state.ts
 *     (`approvers.length < att.required_approvals`) pass before anyone
 *     approves anything, and a value above approver_ids.length would make
 *     quorum permanently unreachable.
 *   - requested_by must be a non-empty string; a missing one currently binds
 *     NULL into a NOT NULL column and crashes as an unaudited 500.
 */
export function validateEnvelope(input: unknown): AttestationEnvelope {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    reject("attestation request must be an object");
  }
  const req = input as Record<string, unknown>;

  const requested_by = req.requested_by;
  if (typeof requested_by !== "string" || requested_by.length === 0) {
    reject("requested_by is required and must be a non-empty string");
  }

  const approver_ids = req.approver_ids;
  if (
    !Array.isArray(approver_ids) ||
    approver_ids.length === 0 ||
    !approver_ids.every((id) => typeof id === "string" && id.length > 0)
  ) {
    reject("approver_ids is required and must be a non-empty array of non-empty strings");
  }

  const required_approvals = req.required_approvals ?? DEFAULT_REQUIRED_APPROVALS;
  if (
    typeof required_approvals !== "number" ||
    !Number.isInteger(required_approvals) ||
    required_approvals < 1 ||
    required_approvals > approver_ids.length
  ) {
    reject(`required_approvals must be an integer between 1 and ${approver_ids.length}`);
  }

  const ttl_seconds = req.ttl_seconds ?? DEFAULT_TTL_SECONDS;
  if (
    typeof ttl_seconds !== "number" ||
    !Number.isFinite(ttl_seconds) ||
    Math.abs(ttl_seconds) > MAX_ABS_TTL_SECONDS
  ) {
    reject(`ttl_seconds must be a finite number with an absolute value at most ${MAX_ABS_TTL_SECONDS}`);
  }

  return { requested_by, approver_ids, required_approvals, ttl_seconds, action: req.action };
}
