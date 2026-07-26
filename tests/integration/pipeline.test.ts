import { describe, it, expect, beforeAll } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { prepareAction } from "../../src/actions/render.js";
import { challengeFor } from "../../src/webauthn/authentication.js";
import { hashToBytes } from "../../src/crypto/canonical.js";
import { loadOrCreateKeypair, signAttestation, verifyAttestation, publicJwks } from "../../src/crypto/tokens.js";
import { buildServer } from "../../src/api/server.js";

const wire = {
  type: "wire_transfer", risk_tier: "high",
  payload: { amount: 2500000, currency: "USD", recipient_name: "Acme Corp", account_last4: "4821" },
};

describe("canonicalize -> hash -> challenge", () => {
  it("carries one hash unchanged across the seam", () => {
    const action = prepareAction(wire);
    const challenge = challengeFor(action.payload_hash);
    expect(Buffer.from(challenge, "base64url")).toEqual(Buffer.from(hashToBytes(action.payload_hash)));
  });

  it("changes the challenge when any payload field changes", () => {
    const a = challengeFor(prepareAction(wire).payload_hash);
    const b = challengeFor(prepareAction({
      ...wire, payload: { ...wire.payload, amount: 2500001 },
    }).payload_hash);
    expect(a).not.toBe(b);
  });

  it("keeps the summary and the hash derived from the same bytes", () => {
    const action = prepareAction(wire);
    expect(action.summary.headline).toContain("25,000.00");
    expect(prepareAction(wire).payload_hash).toBe(action.payload_hash);
  });
});

describe("hash -> token -> verify", () => {
  it("round-trips the action hash into the act claim", async () => {
    const kp = await loadOrCreateKeypair(mkdtempSync(join(tmpdir(), "ha-int-")));
    const action = prepareAction(wire);
    const token = await signAttestation(kp, {
      jti: "att_1", sub: "prin_1", act: action.payload_hash,
      approvers: ["prin_1"], mth: "passkey",
    }, 300);
    const result = await verifyAttestation(await publicJwks(kp), token);
    expect(result.action_hash).toBe(action.payload_hash);
  });
});

describe("http surface", () => {
  let app: Awaited<ReturnType<typeof buildServer>>;

  beforeAll(async () => {
    app = await buildServer({ dbPath: ":memory:", keyDir: mkdtempSync(join(tmpdir(), "ha-http-")) });
  });

  it("creates an attestation and returns a server-rendered summary", async () => {
    const principal = await app.inject({
      method: "POST", url: "/v1/principals",
      payload: { email: "int@test.local", display_name: "Int" },
    });
    const principalId = principal.json().principal_id;

    const res = await app.inject({
      method: "POST", url: "/v1/attestations",
      payload: { requested_by: "int", approver_ids: [principalId], action: wire },
    });

    expect(res.statusCode).toBe(201);
    expect(res.json().summary.headline).toBe("Wire $25,000.00 USD to Acme Corp");
    expect(res.json().payload_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it("rejects a payload carrying display text", async () => {
    const res = await app.inject({
      method: "POST", url: "/v1/attestations",
      payload: {
        requested_by: "int", approver_ids: ["prin_x"],
        action: { ...wire, payload: { ...wire.payload, headline: "Pay $50 to Netflix" } },
      },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe("payload_invalid");
  });

  it("publishes a jwks with no private material", async () => {
    const res = await app.inject({ method: "GET", url: "/.well-known/jwks.json" });
    expect(res.json().keys[0]).not.toHaveProperty("d");
  });
});
