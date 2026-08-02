import { describe, it, expect, beforeAll } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildServer } from "./server.js";
import { signAttestation } from "../crypto/tokens.js";
import * as q from "../db/queries.js";

const wire = {
  type: "wire_transfer", risk_tier: "high",
  payload: { amount: 2500000, currency: "USD", recipient_name: "Acme Corp", account_last4: "4821" },
};

describe("POST /v1/attestations/verify over real HTTP", () => {
  let app: Awaited<ReturnType<typeof buildServer>>;

  beforeAll(async () => {
    app = await buildServer({ dbPath: ":memory:", keyDir: mkdtempSync(join(tmpdir(), "ha-verify-http-")) });
  });

  async function approvedToken() {
    const principal = await app.inject({
      method: "POST", url: "/v1/principals",
      payload: { email: `verify-http-${Date.now()}@test.local`, display_name: "V" },
    });
    const principalId = principal.json().principal_id;

    const created = await app.inject({
      method: "POST", url: "/v1/attestations",
      payload: { requested_by: "int", approver_ids: [principalId], action: wire },
    });
    const { attestation_id: attestationId, payload_hash: payloadHash } = created.json();

    const token = await signAttestation(app.ctx.kp, {
      jti: attestationId, sub: principalId, act: payloadHash,
      approvers: [principalId], mth: "passkey",
    }, 300);
    q.setAttestationResolved(app.ctx.db, attestationId, "approved", token);
    return token;
  }

  it("consumes a valid token on the first call", async () => {
    const token = await approvedToken();
    const res = await app.inject({ method: "POST", url: "/v1/attestations/verify", payload: { token } });
    expect(res.json().valid).toBe(true);
  });

  it("returns already_consumed on a second call with the same token", async () => {
    const token = await approvedToken();
    await app.inject({ method: "POST", url: "/v1/attestations/verify", payload: { token } });
    const second = await app.inject({ method: "POST", url: "/v1/attestations/verify", payload: { token } });
    expect(second.statusCode).toBe(200);
    expect(second.json()).toEqual({ valid: false, reason: "already_consumed" });
  });
});
