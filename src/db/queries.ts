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

export function getApprovals(db: Database, attestationId: string) {
  return db.prepare(`SELECT * FROM attestation_approvals WHERE attestation_id = ?`)
    .all(attestationId) as Array<{ principal_id: string; decision: Decision; signed_at: string }>;
}

export function setAttestationResolved(
  db: Database, id: string, status: AttestationStatus, token: string | null,
): void {
  db.prepare(`UPDATE attestations SET status = ?, resolved_at = ?, token = ? WHERE id = ?`)
    .run(status, now(), token, id);
}

export function audit(
  db: Database,
  e: { attestation_id: string | null; event: string; actor: string | null; detail: string | null },
): void {
  db.prepare(
    `INSERT INTO audit_log (attestation_id, event, actor, detail, created_at) VALUES (?, ?, ?, ?, ?)`,
  ).run(e.attestation_id, e.event, e.actor, e.detail, now());
}
