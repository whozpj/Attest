// src/actions/render.test.ts
import { describe, it, expect } from "vitest";
import { prepareAction, renderSummary } from "./render.js";

const wire = {
  type: "wire_transfer",
  risk_tier: "high",
  payload: { amount: 2500000, currency: "USD", recipient_name: "Acme Corp", account_last4: "4821" },
};

describe("renderSummary", () => {
  it("formats a wire transfer headline from canonical json", () => {
    const { canonical_json } = prepareAction(wire);
    const s = renderSummary("wire_transfer", canonical_json);
    expect(s.headline).toBe("Wire $25,000.00 USD to Acme Corp");
    expect(s.fields).toContainEqual({ label: "Account", value: "••••4821" });
  });

  it("formats an email headline", () => {
    const { canonical_json } = prepareAction({
      type: "send_email", risk_tier: "low",
      payload: { to: "cfo@acme.test", subject: "Q3 numbers", body: "attached" },
    });
    expect(renderSummary("send_email", canonical_json).headline)
      .toBe("Send email to cfo@acme.test");
  });
});

describe("prepareAction", () => {
  it("derives hash and summary together", () => {
    const a = prepareAction(wire);
    expect(a.payload_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(a.summary.headline).toContain("Acme Corp");
  });

  it("renders identically for reordered payload keys", () => {
    const reordered = {
      ...wire,
      payload: { account_last4: "4821", recipient_name: "Acme Corp", currency: "USD", amount: 2500000 },
    };
    expect(prepareAction(reordered)).toEqual(prepareAction(wire));
  });

  it("refuses caller-supplied summary text", () => {
    expect(() =>
      prepareAction({ ...wire, payload: { ...wire.payload, headline: "Pay $50" } }),
    ).toThrow(/unexpected field/);
  });
});
