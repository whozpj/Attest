import Database from "better-sqlite3";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));

export function openDb(path: string): Database.Database {
  const db = new Database(path);
  db.exec(readFileSync(join(here, "schema.sql"), "utf8"));
  addMissingColumns(db);
  return db;
}

/**
 * `CREATE TABLE IF NOT EXISTS` above only builds tables that don't exist
 * yet -- it silently does nothing to a table that already exists but
 * predates a column schema.sql now declares. Every existing on-disk
 * database (any real deployment, or just a developer's local
 * human-attest.db from before this column existed) needs that column
 * added explicitly, once, the first time it's opened after the upgrade.
 */
function addMissingColumns(db: Database.Database): void {
  const columns = db.prepare(`PRAGMA table_info(attestations)`).all() as { name: string }[];
  const hasTokenConsumedAt = columns.some((c) => c.name === "token_consumed_at");
  if (!hasTokenConsumedAt) {
    db.exec(`ALTER TABLE attestations ADD COLUMN token_consumed_at TEXT`);
  }
}

export type { Database } from "better-sqlite3";
