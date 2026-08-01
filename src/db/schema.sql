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

CREATE TABLE IF NOT EXISTS enrolment_tokens (
  token TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL REFERENCES principals(id),
  expires_at TEXT NOT NULL,
  used_at TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS push_subscriptions (
  id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL REFERENCES principals(id),
  endpoint TEXT NOT NULL UNIQUE,
  p256dh TEXT NOT NULL,
  auth TEXT NOT NULL,
  created_at TEXT NOT NULL
);

-- An approval link deliberately has no expires_at of its own: it inherits the
-- attestation's, which is the single source of truth for whether a request is
-- still live. UNIQUE (attestation_id, principal_id) is what makes a token
-- personal -- one shared token would let one approver open another's link.
CREATE TABLE IF NOT EXISTS approval_links (
  token TEXT PRIMARY KEY,
  attestation_id TEXT NOT NULL REFERENCES attestations(id),
  principal_id TEXT NOT NULL REFERENCES principals(id),
  created_at TEXT NOT NULL,
  UNIQUE (attestation_id, principal_id)
);

CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL REFERENCES principals(id),
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS login_challenges (
  challenge TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL REFERENCES principals(id),
  expires_at TEXT NOT NULL,
  used_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_sessions_principal ON sessions(principal_id);
CREATE INDEX IF NOT EXISTS idx_links_attestation ON approval_links(attestation_id);

CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  attestation_id TEXT,
  event TEXT NOT NULL,
  actor TEXT,
  detail TEXT,
  created_at TEXT NOT NULL
);
