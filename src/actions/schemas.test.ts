// src/actions/schemas.test.ts
import { describe, it, expect } from "vitest";
import { validateAction, validateEnvelope } from "./schemas.js";
import { FailClosedError } from "../types.js";

const wire = {
  type: "wire_transfer",
  risk_tier: "high",
  payload: { amount: 2500000, currency: "USD", recipient_name: "Acme Corp", account_last4: "4821" },
};

const validEnvelope = {
  requested_by: "agent-1",
  approver_ids: ["prin_a", "prin_b"],
  action: wire,
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

describe("validateEnvelope", () => {
  it("accepts a well-formed attestation request and defaults required_approvals/ttl_seconds", () => {
    const env = validateEnvelope(validEnvelope);
    expect(env.requested_by).toBe("agent-1");
    expect(env.approver_ids).toEqual(["prin_a", "prin_b"]);
    expect(env.required_approvals).toBe(1);
    expect(env.ttl_seconds).toBe(900);
  });

  it("accepts an explicit, in-bounds required_approvals", () => {
    expect(validateEnvelope({ ...validEnvelope, required_approvals: 2 }).required_approvals).toBe(2);
  });

  it("rejects a completely missing body", () => {
    expect(() => validateEnvelope(undefined)).toThrow(FailClosedError);
  });

  it("rejects a non-object body (array)", () => {
    expect(() => validateEnvelope(["not", "an", "object"])).toThrow(FailClosedError);
  });

  it("rejects a missing requested_by", () => {
    const { requested_by, ...rest } = validEnvelope;
    expect(() => validateEnvelope(rest)).toThrow(/requested_by/);
  });

  it("rejects a non-string requested_by", () => {
    expect(() => validateEnvelope({ ...validEnvelope, requested_by: 123 })).toThrow(/requested_by/);
  });

  it("rejects a missing approver_ids", () => {
    const { approver_ids, ...rest } = validEnvelope;
    expect(() => validateEnvelope(rest)).toThrow(/approver_ids/);
  });

  it("rejects approver_ids that is a string instead of an array (the substring-matching footgun)", () => {
    expect(() => validateEnvelope({ ...validEnvelope, approver_ids: "prin_a" })).toThrow(/approver_ids/);
  });

  it("rejects a null approver_ids", () => {
    expect(() => validateEnvelope({ ...validEnvelope, approver_ids: null })).toThrow(/approver_ids/);
  });

  it("rejects an empty approver_ids array", () => {
    expect(() => validateEnvelope({ ...validEnvelope, approver_ids: [] })).toThrow(/approver_ids/);
  });

  it("rejects an approver_ids array with a non-string element", () => {
    expect(() => validateEnvelope({ ...validEnvelope, approver_ids: ["prin_a", 42] })).toThrow(/approver_ids/);
  });

  it("rejects required_approvals of 0", () => {
    expect(() => validateEnvelope({ ...validEnvelope, required_approvals: 0 })).toThrow(/required_approvals/);
  });

  it("rejects a negative required_approvals", () => {
    expect(() => validateEnvelope({ ...validEnvelope, required_approvals: -5 })).toThrow(/required_approvals/);
  });

  it("rejects required_approvals greater than approver_ids.length", () => {
    expect(() => validateEnvelope({ ...validEnvelope, required_approvals: 3 })).toThrow(/required_approvals/);
  });

  it("rejects a non-integer required_approvals", () => {
    expect(() => validateEnvelope({ ...validEnvelope, required_approvals: 1.5 })).toThrow(/required_approvals/);
  });

  it("rejects a wrong-typed required_approvals", () => {
    expect(() => validateEnvelope({ ...validEnvelope, required_approvals: "two" })).toThrow(/required_approvals/);
  });

  it("rejects a wrong-typed ttl_seconds", () => {
    expect(() => validateEnvelope({ ...validEnvelope, ttl_seconds: "soon" })).toThrow(/ttl_seconds/);
  });

  it("rejects an absurdly large ttl_seconds that would overflow Date arithmetic", () => {
    expect(() => validateEnvelope({ ...validEnvelope, ttl_seconds: 1e15 })).toThrow(/ttl_seconds/);
  });

  it("still accepts a negative ttl_seconds (used deliberately to mint an already-expired attestation)", () => {
    expect(validateEnvelope({ ...validEnvelope, ttl_seconds: -1 }).ttl_seconds).toBe(-1);
  });

  it("rejects a NaN ttl_seconds", () => {
    expect(() => validateEnvelope({ ...validEnvelope, ttl_seconds: NaN })).toThrow(/ttl_seconds/);
  });
});
