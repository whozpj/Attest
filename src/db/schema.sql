PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS principals (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS credentials (
  id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL REFERENCES principals(id),
  credential_id TEXT NOT NULL UNIQUE,
  public_key BLOB NOT NULL,
  sign_count INTEGER NOT NULL DEFAULT 0,
  transports TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS actions (
  id TEXT PRIMARY KEY,
  requested_by TEXT NOT NULL,
  type TEXT NOT NULL,
  canonical_json TEXT,
  payload_hash TEXT NOT NULL,
  risk_tier TEXT NOT NULL,
  created_at TEXT NOT NULL,
  purged_at TEXT
);

CREATE TABLE IF NOT EXISTS attestations (
  id TEXT PRIMARY KEY,
  action_id TEXT NOT NULL REFERENCES actions(id),
  status TEXT NOT NULL,
  required_approvals INTEGER NOT NULL,
  approver_ids TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  resolved_at TEXT,
  token TEXT
);

CREATE TABLE IF NOT EXISTS attestation_approvals (
  id TEXT PRIMARY KEY,
  attestation_id TEXT NOT NULL REFERENCES attestations(id),
  principal_id TEXT NOT NULL REFERENCES principals(id),
  decision TEXT NOT NULL,
  client_data_json TEXT NOT NULL,
  signed_at TEXT NOT NULL,
  UNIQUE (attestation_id, principal_id)
);

CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  attestation_id TEXT,
  event TEXT NOT NULL,
  actor TEXT,
  detail TEXT,
  created_at TEXT NOT NULL
);
