// src/api/routes.push.test.ts
import { describe, it, expect, beforeEach } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildServer } from "./server.js";

let app: Awaited<ReturnType<typeof buildServer>>;

beforeEach(async () => {
  app = await buildServer({
    dbPath: ":memory:",
    keyDir: mkdtempSync(join(tmpdir(), "ha-push-routes-")),
  });
});

const subscription = {
  endpoint: "https://push.example/abc",
  keys: { p256dh: "p256dh-key", auth: "auth-secret" },
};

async function createPrincipal(email: string) {
  const res = await app.inject({
    method: "POST", url: "/v1/principals",
    payload: { email, display_name: email },
  });
  return res.json() as { principal_id: string; enrolment_token: string };
}

describe("GET /v1/push/vapid-public-key", () => {
  it("returns the server's VAPID public key", async () => {
    const res = await app.inject({ method: "GET", url: "/v1/push/vapid-public-key" });
    expect(res.statusCode).toBe(200);
    expect(typeof res.json().publicKey).toBe("string");
    expect(res.json().publicKey.length).toBeGreaterThan(0);
  });
});

describe("POST /v1/principals/:id/push-subscription", () => {
  it("registers a subscription given a valid, unspent enrolment token", async () => {
    const { principal_id, enrolment_token } = await createPrincipal("push-ok@test.local");
    const res = await app.inject({
      method: "POST", url: `/v1/principals/${principal_id}/push-subscription?token=${enrolment_token}`,
      payload: { subscription },
    });
    expect(res.statusCode).toBe(201);
    const rows = app.ctx.db.prepare("SELECT * FROM push_subscriptions WHERE principal_id = ?").all(principal_id);
    expect(rows).toHaveLength(1);
  });

  it("does not consume the enrolment token — /credentials/options still accepts it afterwards", async () => {
    const { principal_id, enrolment_token } = await createPrincipal("push-noconsume@test.local");
    await app.inject({
      method: "POST", url: `/v1/principals/${principal_id}/push-subscription?token=${enrolment_token}`,
      payload: { subscription },
    });
    const optionsRes = await app.inject({
      method: "POST",
      url: `/v1/principals/${principal_id}/credentials/options?token=${enrolment_token}`,
    });
    expect(optionsRes.statusCode).toBe(200);
  });

  it("rejects a missing or wrong token with the same opaque code as an unknown principal", async () => {
    const { principal_id } = await createPrincipal("push-badtoken@test.local");
    const res = await app.inject({
      method: "POST", url: `/v1/principals/${principal_id}/push-subscription?token=wrong`,
      payload: { subscription },
    });
    expect(res.statusCode).toBe(404);
    expect(res.json().error).toBe("unknown_principal");
  });

  it("rejects a malformed subscription body", async () => {
    const { principal_id, enrolment_token } = await createPrincipal("push-malformed@test.local");
    const res = await app.inject({
      method: "POST", url: `/v1/principals/${principal_id}/push-subscription?token=${enrolment_token}`,
      payload: { subscription: { endpoint: "not-https" } },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe("push_subscription_invalid");
  });

  it("writes an audit_log row for a rejected subscription", async () => {
    const { principal_id, enrolment_token } = await createPrincipal("push-audit@test.local");
    await app.inject({
      method: "POST", url: `/v1/principals/${principal_id}/push-subscription?token=${enrolment_token}`,
      payload: { subscription: {} },
    });
    const rows = app.ctx.db.prepare("SELECT * FROM audit_log").all() as Array<{ event: string }>;
    expect(rows.some((r) => r.event === "push_subscription_invalid")).toBe(true);
  });
});
