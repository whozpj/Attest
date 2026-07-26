import { describe, it, expect } from "vitest";
import { canonicalize, hashCanonical, hashPayload, hashToBytes } from "./canonical.js";

describe("canonicalize", () => {
  it("orders keys deterministically regardless of input order", () => {
    expect(canonicalize({ b: 1, a: 2 })).toBe(canonicalize({ a: 2, b: 1 }));
    expect(canonicalize({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
  });

  it("emits no insignificant whitespace", () => {
    expect(canonicalize({ a: [1, 2] })).toBe('{"a":[1,2]}');
  });

  it("orders nested keys too", () => {
    expect(canonicalize({ z: { y: 1, x: 2 } })).toBe('{"z":{"x":2,"y":1}}');
  });
});

describe("hashCanonical", () => {
  it("returns a prefixed lowercase hex sha256", () => {
    const h = hashCanonical('{"a":1}');
    expect(h).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it("is stable across calls", () => {
    expect(hashCanonical('{"a":1}')).toBe(hashCanonical('{"a":1}'));
  });
});

describe("hashPayload", () => {
  it("produces the same hash for semantically identical payloads", () => {
    const a = hashPayload({ amount: 100, currency: "USD" });
    const b = hashPayload({ currency: "USD", amount: 100 });
    expect(a.payload_hash).toBe(b.payload_hash);
  });

  it("produces different hashes when a value changes", () => {
    const a = hashPayload({ amount: 100 });
    const b = hashPayload({ amount: 101 });
    expect(a.payload_hash).not.toBe(b.payload_hash);
  });
});

describe("hashToBytes", () => {
  it("returns 32 bytes", () => {
    expect(hashToBytes(hashCanonical("{}")).length).toBe(32);
  });

  it("rejects a malformed hash", () => {
    expect(() => hashToBytes("sha256:zzz")).toThrow(/malformed hash/);
  });
});
