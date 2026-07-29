import type { Database } from "better-sqlite3";
import type { AttestationStatus, Decision } from "../types.js";

const now = () => new Date().toISOString();

export function insertPrincipal(
  db: Database, p: { id: string; email: string; display_name: string },
): void {
  db.prepare(
    `INSERT INTO principals (id, email, display_name, status, created_at)
     VALUES (?, ?, ?, 'active', ?)`,
  ).run(p.id, p.email, p.display_name, now());
}

export function getPrincipal(db: Database, id: string) {
  return db.prepare(`SELECT * FROM principals WHERE id = ?`).get(id) as
    | { id: string; email: string; display_name: string; status: string }
    | undefined;
}

export function insertCredential(
  db: Database,
  c: { id: string; principal_id: string; credential_id: string;
       public_key: Buffer; transports: string | null },
): void {
  db.prepare(
    `INSERT INTO credentials (id, principal_id, credential_id, public_key, sign_count, transports, created_at)
     VALUES (?, ?, ?, ?, 0, ?, ?)`,
  ).run(c.id, c.principal_id, c.credential_id, c.public_key, c.transports, now());
}

export function getCredentialsFor(db: Database, principalId: string) {
  return db.prepare(`SELECT * FROM credentials WHERE principal_id = ?`).all(principalId) as Array<{
    id: string; principal_id: string; credential_id: string;
    public_key: Buffer; sign_count: number; transports: string | null;
  }>;
}

export function getCredential(db: Database, credentialId: string) {
  return db.prepare(`SELECT * FROM credentials WHERE credential_id = ?`).get(credentialId) as
    | { id: string; principal_id: string; credential_id: string;
        public_key: Buffer; sign_count: number }
    | undefined;
}

export function updateSignCount(db: Database, credentialId: string, count: number): void {
  db.prepare(`UPDATE credentials SET sign_count = ? WHERE credential_id = ?`)
    .run(count, credentialId);
}

export function insertAction(
  db: Database,
  a: { id: string; requested_by: string; type: string; canonical_json: string;
       payload_hash: string; risk_tier: string },
): void {
  db.prepare(
    `INSERT INTO actions (id, requested_by, type, canonical_json, payload_hash, risk_tier, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
  ).run(a.id, a.requested_by, a.type, a.canonical_json, a.payload_hash, a.risk_tier, now());
}

export function getAction(db: Database, id: string) {
  return db.prepare(`SELECT * FROM actions WHERE id = ?`).get(id) as
    | { id: string; requested_by: string; type: string; canonical_json: string | null;
        payload_hash: string; risk_tier: string; purged_at: string | null }
    | undefined;
}

export function purgeActionPayload(db: Database, id: string): void {
  db.prepare(`UPDATE actions SET canonical_json = NULL, purged_at = ? WHERE id = ?`)
    .run(now(), id);
}

export function insertAttestation(
  db: Database,
  a: { id: string; action_id: string; required_approvals: number;
       approver_ids: string[]; expires_at: string },
): void {
  db.prepare(
    `INSERT INTO attestations (id, action_id, status, required_approvals, approver_ids, expires_at, created_at)
     VALUES (?, ?, 'pending', ?, ?, ?, ?)`,
  ).run(a.id, a.action_id, a.required_approvals, JSON.stringify(a.approver_ids), a.expires_at, now());
}

export function getAttestation(db: Database, id: string) {
  const row = db.prepare(`SELECT * FROM attestations WHERE id = ?`).get(id) as
    | { id: string; action_id: string; status: AttestationStatus; required_approvals: number;
        approver_ids: string; expires_at: string; resolved_at: string | null; token: string | null }
    | undefined;
  return row ? { ...row, approver_ids: JSON.parse(row.approver_ids) as string[] } : undefined;
}

export function insertApproval(
  db: Database,
  a: { id: string; attestation_id: string; principal_id: string;
       decision: Decision; client_data_json: string },
): void {
  db.prepare(
    `INSERT INTO attestation_approvals (id, attestation_id, principal_id, decision, client_data_json, signed_at)
     VALUES (?, ?, ?, ?, ?, ?)`,
  ).run(a.id, a.attestation_id, a.principal_id, a.decision, a.client_data_json, now());
}

/**
 * Ordered chronologically — who actually approved/denied first. Without an
 * explicit ORDER BY, SQLite is free to satisfy `WHERE attestation_id = ?` via
 * the UNIQUE(attestation_id, principal_id) index, which returns rows sorted
 * by `principal_id` — a column with no relationship to approval order at
 * all. `state.ts` takes `approvers[0]` as the issued token's `sub` ("primary
 * approver" per the AttestationToken contract), so that ordering bug meant
 * the token could name whichever principal happened to sort first
 * alphabetically, not whoever actually approved first.
 *
 * Ordering by `signed_at` alone is not enough: it's an ISO string with only
 * millisecond resolution, and two approvals submitted in quick succession
 * (the common case — a fast test, or two people clicking within the same
 * millisecond) can tie. `id` is `ap_${randomUUID()}` and is NOT a valid
 * tiebreak — it has no relationship to insertion order either, so a tie on
 * `signed_at` would silently reintroduce the exact bug this fixes. The
 * table has no `WITHOUT ROWID` clause, so SQLite gives it an implicit,
 * monotonically-increasing `rowid` reflecting true insertion order; that is
 * the correct tiebreak, and arguably the correct primary sort on its own.
 */
export function getApprovals(db: Database, attestationId: string) {
  return db.prepare(
    `SELECT * FROM attestation_approvals WHERE attestation_id = ? ORDER BY signed_at, rowid`,
  ).all(attestationId) as Array<{ principal_id: string; decision: Decision; signed_at: string }>;
}

export function setAttestationResolved(
  db: Database, id: string, status: AttestationStatus, token: string | null,
): void {
  db.prepare(`UPDATE attestations SET status = ?, resolved_at = ?, token = ? WHERE id = ?`)
    .run(status, now(), token, id);
}

export function insertEnrolmentToken(
  db: Database, t: { token: string; principal_id: string; expires_at: string },
): void {
  db.prepare(
    `INSERT INTO enrolment_tokens (token, principal_id, expires_at, used_at, created_at)
     VALUES (?, ?, ?, NULL, ?)`,
  ).run(t.token, t.principal_id, t.expires_at, now());
}

export function getEnrolmentToken(db: Database, token: string) {
  return db.prepare(`SELECT * FROM enrolment_tokens WHERE token = ?`).get(token) as
    | { token: string; principal_id: string; expires_at: string; used_at: string | null }
    | undefined;
}

/**
 * Atomically checks and burns a single-use enrolment token in one statement,
 * so two concurrent requests racing on the same token cannot both observe it
 * as "still valid" before either commits a consumption — the same
 * check-then-mutate race already closed for approval quorum in
 * state.ts/recordDecision. Returns whether *this* call is the one that
 * consumed it; a token that's missing, bound to a different principal,
 * expired, or already used all resolve to `false` the same way, by design —
 * the caller collapses all of them into one opaque rejection.
 */
export function consumeEnrolmentToken(db: Database, token: string, principalId: string): boolean {
  const result = db.prepare(
    `UPDATE enrolment_tokens SET used_at = ?
     WHERE token = ? AND principal_id = ? AND used_at IS NULL AND expires_at > ?`,
  ).run(now(), token, principalId, now());
  return result.changes === 1;
}

/**
 * Compensating delete for the enrolment-token race in
 * routes.principals.ts's POST /credentials handler. finishRegistration
 * (src/webauthn/registration.ts) persists the credential as an inseparable
 * part of a successful verification -- it cannot be told to verify without
 * writing. When two different, genuinely-successful ceremonies (two
 * different authenticators) race on one still-unspent enrolment token, only
 * one can win the atomic consumeEnrolmentToken call; the loser's
 * already-persisted row must be undone so it never actually attaches to the
 * principal, even though its own signature was cryptographically valid.
 * Deleting by credential_id (not the internal `id` PK) because that's the
 * only identifier finishRegistration's return value exposes.
 */
export function deleteCredential(db: Database, credentialId: string): void {
  db.prepare(`DELETE FROM credentials WHERE credential_id = ?`).run(credentialId);
}

/**
 * `endpoint` is UNIQUE per push_subscriptions. A conflict means the same
 * browser subscription is being re-registered — legitimately reachable if a
 * principal re-opens enrol.html (e.g. after clearing site data and
 * re-subscribing with the same still-cached service-worker registration) —
 * so this rebinds it rather than throwing, taking whichever principal_id
 * last proved token possession for that endpoint.
 *
 * Accepted tradeoff (production-hardening review, 2026-07-29): because
 * `endpoint` is globally unique rather than scoped per-principal, a second
 * principal who already knows a first principal's real endpoint URL could
 * re-register it to themselves, silently unsubscribing the original owner.
 * In practice this requires already knowing a high-entropy, server-generated
 * value that is never exposed to any other principal or caller -- reachable
 * only via database access or intercepting the original subscribe call, at
 * which point far worse is already possible. Impact is bounded to
 * denial-of-notification (a push message encrypted for the wrong browser's
 * keys can't be read by anyone), never disclosure, on a best-effort channel.
 * Scoping the constraint to (principal_id, endpoint) instead was considered
 * and rejected: it would let two principals coexist on one real browser
 * subscription, which cannot happen in practice (one browser, one
 * subscription, one owner) and would just mask the same re-registration
 * behavior under a different key.
 */
export function upsertPushSubscription(
  db: Database,
  s: { id: string; principal_id: string; endpoint: string; p256dh: string; auth: string },
): void {
  db.prepare(
    `INSERT INTO push_subscriptions (id, principal_id, endpoint, p256dh, auth, created_at)
     VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT(endpoint) DO UPDATE SET
       principal_id = excluded.principal_id,
       p256dh = excluded.p256dh,
       auth = excluded.auth`,
  ).run(s.id, s.principal_id, s.endpoint, s.p256dh, s.auth, now());
}

export function getPushSubscriptionsFor(db: Database, principalId: string) {
  return db.prepare(`SELECT * FROM push_subscriptions WHERE principal_id = ?`).all(principalId) as Array<{
    id: string; principal_id: string; endpoint: string; p256dh: string; auth: string;
  }>;
}

/**
 * Called when the push service itself reports the subscription is gone
 * (404/410 from a send attempt) — the standard web-push hygiene signal that
 * the browser unsubscribed or the endpoint expired, so retrying it forever
 * would just accumulate permanent failures.
 */
export function deletePushSubscription(db: Database, endpoint: string): void {
  db.prepare(`DELETE FROM push_subscriptions WHERE endpoint = ?`).run(endpoint);
}

export function audit(
  db: Database,
  e: { attestation_id: string | null; event: string; actor: string | null; detail: string | null },
): void {
  db.prepare(
    `INSERT INTO audit_log (attestation_id, event, actor, detail, created_at) VALUES (?, ?, ?, ?, ?)`,
  ).run(e.attestation_id, e.event, e.actor, e.detail, now());
}
