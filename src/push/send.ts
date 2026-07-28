import webpush from "web-push";
import type { Database } from "better-sqlite3";
import * as q from "../db/queries.js";
import type { VapidKeys } from "./vapid.js";

const VAPID_SUBJECT = "mailto:admin@human-attest.local";

export interface PushNotice {
  attestation_id: string;
  headline: string;
  approveUrlBase: string;
}

/**
 * Best-effort push delivery. A push notification is a convenience nudge —
 * the approve_url is independently reachable regardless of whether any
 * device receives the push — so a delivery failure here must never
 * propagate to the caller (attestation creation must not fail because a
 * stale subscription exists). Each subscription is tried independently; one
 * failing must not stop the others, and this function itself never throws.
 */
export async function notifyApprovers(
  db: Database, vapid: VapidKeys, approverIds: string[], notice: PushNotice,
): Promise<void> {
  for (const principalId of approverIds) {
    try {
      const subs = q.getPushSubscriptionsFor(db, principalId);
      if (subs.length === 0) continue;

      const message = JSON.stringify({
        title: "Approval requested",
        body: notice.headline,
        attestation_id: notice.attestation_id,
        url: `${notice.approveUrlBase}&principal=${principalId}`,
      });

      for (const sub of subs) {
        try {
          await webpush.sendNotification(
            { endpoint: sub.endpoint, keys: { p256dh: sub.p256dh, auth: sub.auth } },
            message,
            { vapidDetails: { subject: VAPID_SUBJECT, publicKey: vapid.publicKey, privateKey: vapid.privateKey } },
          );
        } catch (err) {
          // 404/410 is the push service's standard signal that the
          // subscription is gone (unsubscribed, expired) — anything else is
          // treated as transient and left in place for the next attempt.
          const statusCode = (err as { statusCode?: number }).statusCode;
          if (statusCode === 404 || statusCode === 410) {
            q.deletePushSubscription(db, sub.endpoint);
          }
        }
      }
    } catch (err) {
      // Silently swallow any error (database errors, message encoding, etc.)
      // from processing this principal so we can try the next one.
    }
  }
}
