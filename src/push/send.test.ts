import { describe, it, expect, vi, beforeEach } from "vitest";
import { openDb } from "../db/index.js";
import * as q from "../db/queries.js";
import type { Database } from "better-sqlite3";

const sendNotification = vi.fn();
vi.mock("web-push", () => ({
  default: { sendNotification: (...args: unknown[]) => sendNotification(...args) },
}));

const { notifyApprovers } = await import("./send.js");

let db: Database;
const vapid = { publicKey: "pub", privateKey: "priv" };

beforeEach(() => {
  db = openDb(":memory:");
  sendNotification.mockReset();
  q.insertPrincipal(db, { id: "prin_1", email: "a@b.test", display_name: "A" });
});

describe("notifyApprovers", () => {
  it("does nothing for a principal with no subscriptions", async () => {
    await notifyApprovers(db, vapid, ["prin_1"], {
      attestation_id: "att_1", headline: "Wire $1.00",
      approveUrlBase: "http://x/approve/app.html?attestation=att_1",
    });
    expect(sendNotification).not.toHaveBeenCalled();
  });

  it("sends a push to every subscription for every approver, with a per-recipient url", async () => {
    q.upsertPushSubscription(db, {
      id: "psub_1", principal_id: "prin_1",
      endpoint: "https://push.example/a", p256dh: "k", auth: "s",
    });
    await notifyApprovers(db, vapid, ["prin_1"], {
      attestation_id: "att_1", headline: "Wire $1.00",
      approveUrlBase: "http://x/approve/app.html?attestation=att_1",
    });
    expect(sendNotification).toHaveBeenCalledTimes(1);
    const [subscription, payload, options] = sendNotification.mock.calls[0];
    expect(subscription).toEqual({ endpoint: "https://push.example/a", keys: { p256dh: "k", auth: "s" } });
    const parsed = JSON.parse(payload as string);
    expect(parsed.url).toBe("http://x/approve/app.html?attestation=att_1&principal=prin_1");
    expect(parsed.body).toBe("Wire $1.00");
    expect(parsed.attestation_id).toBe("att_1");
    expect(options.vapidDetails.publicKey).toBe("pub");
    expect(options.vapidDetails.privateKey).toBe("priv");
  });

  it("deletes a subscription the push service reports as gone (410)", async () => {
    q.upsertPushSubscription(db, {
      id: "psub_1", principal_id: "prin_1",
      endpoint: "https://push.example/gone", p256dh: "k", auth: "s",
    });
    sendNotification.mockRejectedValueOnce(Object.assign(new Error("gone"), { statusCode: 410 }));
    await notifyApprovers(db, vapid, ["prin_1"], {
      attestation_id: "att_1", headline: "x",
      approveUrlBase: "http://x/approve/app.html?attestation=att_1",
    });
    expect(q.getPushSubscriptionsFor(db, "prin_1")).toHaveLength(0);
  });

  it("does not delete a subscription on a transient failure", async () => {
    q.upsertPushSubscription(db, {
      id: "psub_1", principal_id: "prin_1",
      endpoint: "https://push.example/flaky", p256dh: "k", auth: "s",
    });
    sendNotification.mockRejectedValueOnce(Object.assign(new Error("network"), { statusCode: 500 }));
    await notifyApprovers(db, vapid, ["prin_1"], {
      attestation_id: "att_1", headline: "x",
      approveUrlBase: "http://x/approve/app.html?attestation=att_1",
    });
    expect(q.getPushSubscriptionsFor(db, "prin_1")).toHaveLength(1);
  });

  it("tries every subscription independently — one failing does not stop the others", async () => {
    q.upsertPushSubscription(db, {
      id: "psub_1", principal_id: "prin_1", endpoint: "https://push.example/bad", p256dh: "k", auth: "s",
    });
    q.upsertPushSubscription(db, {
      id: "psub_2", principal_id: "prin_1", endpoint: "https://push.example/good", p256dh: "k", auth: "s",
    });
    sendNotification.mockRejectedValueOnce(Object.assign(new Error("gone"), { statusCode: 410 }));
    sendNotification.mockResolvedValueOnce(undefined);
    await notifyApprovers(db, vapid, ["prin_1"], {
      attestation_id: "att_1", headline: "x",
      approveUrlBase: "http://x/approve/app.html?attestation=att_1",
    });
    expect(sendNotification).toHaveBeenCalledTimes(2);
  });

  it("never throws, even when every send fails", async () => {
    q.upsertPushSubscription(db, {
      id: "psub_1", principal_id: "prin_1", endpoint: "https://push.example/down", p256dh: "k", auth: "s",
    });
    sendNotification.mockRejectedValueOnce(new Error("boom"));
    await expect(notifyApprovers(db, vapid, ["prin_1"], {
      attestation_id: "att_1", headline: "x",
      approveUrlBase: "http://x/approve/app.html?attestation=att_1",
    })).resolves.toBeUndefined();
  });

  it("never throws, even when getPushSubscriptionsFor fails", async () => {
    vi.spyOn(q, "getPushSubscriptionsFor").mockImplementationOnce(() => {
      throw new Error("database error");
    });
    await expect(notifyApprovers(db, vapid, ["prin_1"], {
      attestation_id: "att_1", headline: "x",
      approveUrlBase: "http://x/approve/app.html?attestation=att_1",
    })).resolves.toBeUndefined();
  });

  it("never throws, even when deletePushSubscription fails", async () => {
    q.upsertPushSubscription(db, {
      id: "psub_1", principal_id: "prin_1",
      endpoint: "https://push.example/gone", p256dh: "k", auth: "s",
    });
    vi.spyOn(q, "deletePushSubscription").mockImplementationOnce(() => {
      throw new Error("delete failed");
    });
    sendNotification.mockRejectedValueOnce(Object.assign(new Error("gone"), { statusCode: 410 }));
    await expect(notifyApprovers(db, vapid, ["prin_1"], {
      attestation_id: "att_1", headline: "x",
      approveUrlBase: "http://x/approve/app.html?attestation=att_1",
    })).resolves.toBeUndefined();
  });
});
