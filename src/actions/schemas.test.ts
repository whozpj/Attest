// src/actions/schemas.test.ts
import { describe, it, expect } from "vitest";
import { validateAction } from "./schemas.js";
import { FailClosedError } from "../types.js";

const wire = {
  type: "wire_transfer",
  risk_tier: "high",
  payload: { amount: 2500000, currency: "USD", recipient_name: "Acme Corp", account_last4: "4821" },
};

describe("validateAction", () => {
  it("accepts a well-formed wire transfer", () => {
    expect(validateAction(wire).type).toBe("wire_transfer");
  });

  it("rejects an unknown action type", () => {
    expect(() => validateAction({ ...wire, type: "launch_missiles" })).toThrow(FailClosedError);
  });

  it("rejects a missing required field", () => {
    const { amount, ...rest } = wire.payload;
    expect(() => validateAction({ ...wire, payload: rest })).toThrow(/amount/);
  });

  it("rejects a wrong-typed field", () => {
    expect(() =>
      validateAction({ ...wire, payload: { ...wire.payload, amount: "2500000" } }),
    ).toThrow(/amount/);
  });

  it("rejects caller-supplied display text", () => {
    expect(() =>
      validateAction({ ...wire, payload: { ...wire.payload, summary: "Pay $50 to Netflix" } }),
    ).toThrow(/unexpected field/);
  });

  it("rejects an invalid risk tier", () => {
    expect(() => validateAction({ ...wire, risk_tier: "whenever" })).toThrow(FailClosedError);
  });
});
