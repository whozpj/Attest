// src/api/routes.attestations.test.ts
import { describe, it, expect, beforeEach } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildServer } from "./server.js";

let app: Awaited<ReturnType<typeof buildServer>>;

const wire = {
  type: "wire_transfer", risk_tier: "high",
  payload: { amount: 2500000, currency: "USD", recipient_name: "Acme Corp", account_last4: "4821" },
};

beforeEach(async () => {
  app = await buildServer({
    dbPath: ":memory:",
    keyDir: mkdtempSync(join(tmpdir(), "ha-attestations-")),
  });
});

describe("GET /v1/attestations/:id on an expired attestation", () => {
  it("does not leak the summary from the very read that expires it", async () => {
    const principal = await app.inject({
      method: "POST", url: "/v1/principals",
      payload: { email: "expiry@test.local", display_name: "Expiry" },
    });
    const { principal_id } = principal.json();

    const created = await app.inject({
      method: "POST", url: "/v1/attestations",
      payload: {
        requested_by: "int", approver_ids: [principal_id], action: wire, ttl_seconds: -1,
      },
    });
    const { attestation_id } = created.json();

    // This is the FIRST read to observe the expiry — the one that must
    // trigger the purge. It must not itself return the pre-purge summary.
    const res = await app.inject({ method: "GET", url: `/v1/attestations/${attestation_id}` });
    expect(res.json().status).toBe("expired");
    expect(res.json().summary).toBeNull();

    // And the underlying row really is purged, not just hidden from this response.
    expect(app.ctx.db.prepare("SELECT canonical_json FROM actions WHERE payload_hash = ?")
      .get(res.json().payload_hash)).toEqual({ canonical_json: null });
  });
});
