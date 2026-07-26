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
