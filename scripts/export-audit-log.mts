// Dumps audit_log to newline-delimited JSON on stdout, oldest first.
// Requires direct access to the database file -- deliberately not an HTTP
// endpoint (see the note in docs/superpowers/plans/2026-07-29-production-hardening.md,
// Task 10) so reading the audit trail needs the same access as the DB file
// itself, not a new authenticated network surface.
//
// Usage: npx tsx scripts/export-audit-log.mts <path-to-db> [--since=<ISO8601>]

import Database from "better-sqlite3";

const dbPath = process.argv[2];
if (!dbPath) {
  console.error("usage: npx tsx scripts/export-audit-log.mts <path-to-db> [--since=<ISO8601>]");
  process.exit(1);
}

const sinceArg = process.argv.find((a) => a.startsWith("--since="));
const since = sinceArg ? sinceArg.slice("--since=".length) : null;

const db = new Database(dbPath, { readonly: true });
const rows = since
  ? db.prepare("SELECT * FROM audit_log WHERE created_at >= ? ORDER BY id ASC").all(since)
  : db.prepare("SELECT * FROM audit_log ORDER BY id ASC").all();

for (const row of rows) {
  process.stdout.write(JSON.stringify(row) + "\n");
}
db.close();
