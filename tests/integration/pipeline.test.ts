import { describe, it, expect, beforeAll } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { prepareAction } from "../../src/actions/render.js";
import { challengeFor } from "../../src/webauthn/authentication.js";
import { loadOrCreateKeypair, signAttestation, verifyAttestation, publicJwks } from "../../src/crypto/tokens.js";
import { buildServer } from "../../src/api/server.js";

const wire = {
  type: "wire_transfer", risk_tier: "high",
  payload: { amount: 2500000, currency: "USD", recipient_name: "Acme Corp", account_last4: "4821" },
};

describe("canonicalize -> hash -> challenge", () => {
  // The challenge is no longer the raw payload_hash bytes -- it's derived
  // from (action hash, decision) together, so approve and deny sign
  // different bytes over the same action. payload_hash is the dominant term
  // in the preimage, not the challenge itself (spec §7).
  it("is the same challenge for the same action and the same decision", () => {
    const action = prepareAction(wire);
    expect(challengeFor(action.payload_hash, "approve"))
      .toBe(challengeFor(action.payload_hash, "approve"));
  });

  it("changes the challenge when the decision changes on the same action", () => {
    const action = prepareAction(wire);
    expect(challengeFor(action.payload_hash, "approve"))
      .not.toBe(challengeFor(action.payload_hash, "deny"));
  });

  it("changes the challenge when any payload field changes", () => {
    const a = challengeFor(prepareAction(wire).payload_hash, "approve");
    const b = challengeFor(prepareAction({
      ...wire, payload: { ...wire.payload, amount: 2500001 },
    }).payload_hash, "approve");
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

  // The unsigned-deny DoS gap (closed in f163865/5f21575) has a companion
  // e2e test (tests/e2e/unsigned-deny-attack.spec.ts) that checks the typed
  // error code over HTTP. It can't check the audit row -- that test runs
  // against a separate server process reachable only by fetch. This is the
  // in-process half: only here is app.ctx.db reachable directly, which is
  // exactly what the Global Constraint ("every rejection writes an
  // audit_log row") requires evidence of. A test that only checks the HTTP
  // response status would pass identically whether or not the audit write
  // actually happened.
  it("rejects a bare, unsigned deny with a typed error and an audit_log row", async () => {
    const principal = await app.inject({
      method: "POST", url: "/v1/principals",
      payload: { email: "deny-dos@test.local", display_name: "D" },
    });
    const principalId = principal.json().principal_id;

    const created = await app.inject({
      method: "POST", url: "/v1/attestations",
      payload: { requested_by: "int", approver_ids: [principalId], action: wire },
    });
    const attestationId = created.json().attestation_id;

    const decisionRes = await app.inject({
      method: "POST", url: `/v1/attestations/${attestationId}/decision`,
      payload: { principal_id: principalId, decision: "deny" },
    });

    expect(decisionRes.statusCode).toBe(400);
    expect(decisionRes.json().error).toBe("signature_required");

    const rows = app.ctx.db.prepare(
      `SELECT * FROM audit_log WHERE attestation_id = ? AND event = 'signature_required'`,
    ).all(attestationId);
    expect(rows.length).toBeGreaterThan(0);

    const att = await app.inject({ method: "GET", url: `/v1/attestations/${attestationId}` });
    expect(att.json().status).toBe("pending");
  });
});
