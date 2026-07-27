// tests/security/summary-spoof.test.ts
//
// Attack found by whole-branch review (Reviewer), reproduced against
// demo/public/index.html: the closed-world payload validator
// (src/actions/schemas.ts) rejects extra *fields* — it never constrained
// the *contents* of a legitimate string field. Reviewer got the
// authenticator to sign $25,000,000 to Acme Corp while the human's screen
// read "AMOUNT $50.00 USD / RECIPIENT Netflix", by putting markup and CSS
// inside `recipient_name` and letting the approval page's unescaped
// `innerHTML` render it. No CSP stops this — it's legitimate markup in a
// legitimate field, not injected script.
//
// tests/security/threat-model.test.ts already covers the adjacent claim —
// a caller cannot smuggle a *separate* `headline` field into the payload —
// and that test is correct. This attack goes around it entirely: it never
// adds a field, it puts HTML inside the *value* of a field the schema
// already allows. QA owns the fix (escaping at the point index.html writes
// into the DOM); this file covers the layer beneath, which is not where
// the bug is but *is* the reason the bug is exploitable: the API's job is
// to canonicalize, hash, and render this content as faithful, byte-exact
// data, never to interpret it — so proving that faithfulness holds is what
// establishes the precondition the DOM-escaping fix has to defend against.
// This is a permanent regression guard, not a red-then-green fix-tracking
// test: there is nothing to fix at this layer, and there shouldn't be —
// requiring the data layer to strip or reject markup would be the wrong
// place to solve this (and would break legitimate business data that
// happens to contain "&" or "<").
import { describe, it, expect } from "vitest";
import { hashCanonical } from "../../src/crypto/canonical.js";
import { prepareAction } from "../../src/actions/render.js";

const SPOOF_RECIPIENT =
  '<span style="position:absolute;inset:0;background:#fff">AMOUNT $50.00 USD / RECIPIENT Netflix</span>Acme Corp';

describe("attack: summary spoofing via markup inside a legitimate field's value", () => {
  it("markup, quotes, and angle brackets in recipient_name pass validation and survive canonicalization byte-for-byte", () => {
    const malicious = {
      type: "wire_transfer", risk_tier: "high",
      payload: {
        amount: 2500000000, // the real amount actually being signed: $25,000,000.00
        currency: "USD",
        recipient_name: SPOOF_RECIPIENT,
        account_last4: "4821",
      },
    };

    // The closed-world schema validates field *names* and primitive
    // *types* — it has no opinion on string contents, and per the note
    // above, it shouldn't: recipient_name is legitimately free text.
    const action = prepareAction(malicious);

    // canonical_json is a JSON *document* (quotes inside the string value
    // are escaped), so compare through a parse rather than raw substring —
    // the point is byte-for-byte fidelity of the *value*, not of its
    // JSON-escaped encoding.
    const roundTripped = JSON.parse(action.canonical_json) as { recipient_name: string };
    expect(roundTripped.recipient_name).toBe(SPOOF_RECIPIENT);
    // The hash must cover the exact bytes, injected markup included — not a
    // sanitized version of them. If canonicalization silently rewrote the
    // payload, the WebAuthn challenge (derived from this hash) would no
    // longer correspond to the content anyone — human or attacker —
    // actually looked at, which would break the central invariant in a
    // different, worse way.
    expect(action.payload_hash).toBe(hashCanonical(action.canonical_json));
  });

  it("RenderedSummary carries the malicious value as plain string data, not interpreted or stripped", () => {
    const malicious = {
      type: "wire_transfer", risk_tier: "high",
      payload: {
        amount: 2500000000, currency: "USD",
        recipient_name: SPOOF_RECIPIENT, account_last4: "4821",
      },
    };
    const action = prepareAction(malicious);

    // This is the exact handoff QA's fix has to defend: by the time this
    // object reaches the approval page, the dangerous string is sitting in
    // .value/.headline verbatim. The API is not responsible for defusing
    // it — only for not lying about what it is. A future "helpful" change
    // that HTML-escaped or stripped tags *here* would itself be a defect:
    // it would mean the rendered summary no longer matches action.payload_hash
    // 1:1, and a verifier or auditor reading canonical_json later would see
    // different content than a human saw on the approval page.
    const recipientField = action.summary.fields.find((f) => f.label === "Recipient");
    expect(recipientField?.value).toBe(SPOOF_RECIPIENT);
    expect(action.summary.headline).toContain(SPOOF_RECIPIENT);

    // Sanity anchor for the actual exploit shape: the real amount that was
    // actually hashed and will actually be signed ($25,000,000.00) and the
    // attacker's spoofed narrative ("$50.00 ... Netflix") both sit in the
    // *same* string, verbatim and unmodified. That coexistence is exactly
    // what makes the DOM-layer bug exploitable — an unescaped `innerHTML`
    // renders the injected markup on top, visually hiding the true amount
    // behind the spoofed text, even though the data (and the hash) always
    // carried the real figure faithfully.
    expect(action.summary.headline).toContain("25,000,000.00");
    expect(action.summary.headline).toContain("$50.00 USD / RECIPIENT Netflix");
  });
});
