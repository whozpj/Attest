// src/webauthn/registration.test.ts
import { describe, it, expect, beforeEach } from "vitest";
import { openDb } from "../db/index.js";
import * as q from "../db/queries.js";
import { beginRegistration } from "./registration.js";
import type { Database } from "better-sqlite3";

let db: Database;

beforeEach(() => {
  db = openDb(":memory:");
  q.insertPrincipal(db, { id: "prin_1", email: "a@b.test", display_name: "A" });
});

describe("beginRegistration", () => {
  it("returns options bound to the configured rp", async () => {
    const opts = await beginRegistration(db, "prin_1");
    expect(opts.rp.id).toBe("localhost");
    expect(opts.challenge).toBeTruthy();
  });

  it("excludes already-registered credentials", async () => {
    q.insertCredential(db, {
      id: "cred_1", principal_id: "prin_1", credential_id: "YWJj",
      public_key: Buffer.from([1]), transports: null,
    });
    const opts = await beginRegistration(db, "prin_1");
    expect(opts.excludeCredentials?.map((c) => c.id)).toContain("YWJj");
  });

  it("rejects an unknown principal", async () => {
    await expect(beginRegistration(db, "prin_missing")).rejects.toThrow(/unknown principal/);
  });
});
