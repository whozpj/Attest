import { describe, it, expect } from "vitest";
import Database from "better-sqlite3";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openDb } from "./index.js";
import * as q from "./queries.js";

describe("openDb on a pre-existing database file", () => {
  it("adds token_consumed_at to an attestations table that predates it", () => {
    // Simulates every real deployment upgrading onto this change: an
    // on-disk database created before token_consumed_at existed, where
    // `CREATE TABLE IF NOT EXISTS` alone would silently do nothing.
    const path = join(mkdtempSync(join(tmpdir(), "ha-legacy-db-")), "legacy.db");
    const legacy = new Database(path);
    legacy.exec(`
      CREATE TABLE attestations (
        id TEXT PRIMARY KEY,
        action_id TEXT NOT NULL,
        status TEXT NOT NULL,
        required_approvals INTEGER NOT NULL,
        approver_ids TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        created_at TEXT NOT NULL,
        resolved_at TEXT,
        token TEXT
      );
    `);
    legacy.close();

    const db = openDb(path);
    const columns = db.prepare(`PRAGMA table_info(attestations)`).all() as { name: string }[];
    expect(columns.some((c) => c.name === "token_consumed_at")).toBe(true);
  });

  it("consumeAttestationToken works against a freshly-migrated legacy database", () => {
    const path = join(mkdtempSync(join(tmpdir(), "ha-legacy-db-")), "legacy.db");
    const legacy = new Database(path);
    legacy.exec(`
      CREATE TABLE attestations (
        id TEXT PRIMARY KEY, action_id TEXT NOT NULL, status TEXT NOT NULL,
        required_approvals INTEGER NOT NULL, approver_ids TEXT NOT NULL,
        expires_at TEXT NOT NULL, created_at TEXT NOT NULL, resolved_at TEXT, token TEXT
      );
    `);
    legacy.prepare(
      `INSERT INTO attestations (id, action_id, status, required_approvals, approver_ids, expires_at, created_at)
       VALUES ('att_legacy', 'act_1', 'approved', 1, '[]', '2099-01-01', '2026-01-01')`,
    ).run();
    legacy.close();

    const db = openDb(path);
    expect(q.consumeAttestationToken(db, "att_legacy")).toBe(true);
    expect(q.consumeAttestationToken(db, "att_legacy")).toBe(false);
  });

  it("re-opening an already-migrated database does not error", () => {
    const path = join(mkdtempSync(join(tmpdir(), "ha-legacy-db-")), "twice.db");
    openDb(path).close();
    expect(() => openDb(path)).not.toThrow();
  });
});
