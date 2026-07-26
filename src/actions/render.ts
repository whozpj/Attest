import { hashPayload } from "../crypto/canonical.js";
import { validateAction } from "./schemas.js";
import type { ActionType, CanonicalAction, RenderedSummary } from "../types.js";

function money(cents: number, currency: string): string {
  const value = (cents / 100).toLocaleString("en-US", {
    minimumFractionDigits: 2, maximumFractionDigits: 2,
  });
  return `$${value} ${currency}`;
}

/**
 * Renders from canonical JSON only. There is deliberately no code path by
 * which a caller can influence this text — that binding is the product.
 */
export function renderSummary(type: ActionType, canonicalJson: string): RenderedSummary {
  const p = JSON.parse(canonicalJson) as Record<string, never>;

  switch (type) {
    case "wire_transfer":
      return {
        headline: `Wire ${money(Number(p.amount), String(p.currency))} to ${p.recipient_name}`,
        fields: [
          { label: "Amount", value: money(Number(p.amount), String(p.currency)) },
          { label: "Recipient", value: String(p.recipient_name) },
          { label: "Account", value: `••••${p.account_last4}` },
        ],
      };
    case "send_email":
      return {
        headline: `Send email to ${p.to}`,
        fields: [
          { label: "To", value: String(p.to) },
          { label: "Subject", value: String(p.subject) },
        ],
      };
    case "sign_document":
      return {
        headline: `Sign document "${p.document_name}"`,
        fields: [
          { label: "Document", value: String(p.document_name) },
          { label: "Hash", value: String(p.document_hash) },
        ],
      };
    case "generic":
      return {
        headline: String(p.title),
        fields: [{ label: "Detail", value: String(p.detail) }],
      };
  }
}

export function prepareAction(input: unknown): CanonicalAction {
  const req = validateAction(input);
  const { canonical_json, payload_hash } = hashPayload(req.payload);
  return {
    type: req.type,
    canonical_json,
    payload_hash,
    summary: renderSummary(req.type, canonical_json),
  };
}
