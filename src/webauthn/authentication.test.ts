// src/webauthn/authentication.test.ts
import { describe, it, expect, beforeEach } from "vitest";
import { openDb } from "../db/index.js";
import * as q from "../db/queries.js";
import { beginApproval, challengeFor } from "./authentication.js";
import { hashCanonical } from "../crypto/canonical.js";
import type { Database } from "better-sqlite3";

let db: Database;
const hash = hashCanonical('{"amount":2500000}');

beforeEach(() => {
  db = openDb(":memory:");
  q.insertPrincipal(db, { id: "prin_1", email: "a@b.test", display_name: "A" });
  q.insertCredential(db, {
    id: "cred_1", principal_id: "prin_1", credential_id: "YWJj",
    public_key: Buffer.from([1]), transports: null,
  });
});

describe("challengeFor", () => {
  it("is deterministic for the same action and decision", () => {
    expect(challengeFor(hash, "approve")).toBe(challengeFor(hash, "approve"));
  });

  it("differs for different actions", () => {
    expect(challengeFor(hash, "approve"))
      .not.toBe(challengeFor(hashCanonical('{"amount":1}'), "approve"));
  });

  it("differs for approve vs deny on the same action", () => {
    expect(challengeFor(hash, "approve")).not.toBe(challengeFor(hash, "deny"));
  });

  it("is identical for the same action and decision pair", () => {
    expect(challengeFor(hash, "deny")).toBe(challengeFor(hash, "deny"));
  });

  it("rejects a malformed action hash", () => {
    expect(() => challengeFor("sha256:nope", "approve")).toThrow(/malformed hash/);
  });
});

describe("beginApproval", () => {
  it("uses the bound (action, decision) hash as the challenge, not a random value", async () => {
    const opts = await beginApproval(db, "prin_1", hash, "approve");
    expect(opts.challenge).toBe(challengeFor(hash, "approve"));
  });

  it("produces a different challenge for deny than for approve on the same action", async () => {
    const approve = await beginApproval(db, "prin_1", hash, "approve");
    const deny = await beginApproval(db, "prin_1", hash, "deny");
    expect(approve.challenge).not.toBe(deny.challenge);
  });

  it("is deterministic for the same action and decision", async () => {
    const a = await beginApproval(db, "prin_1", hash, "approve");
    const b = await beginApproval(db, "prin_1", hash, "approve");
    expect(a.challenge).toBe(b.challenge);
  });

  it("restricts to the principal's own credentials", async () => {
    const opts = await beginApproval(db, "prin_1", hash, "approve");
    expect(opts.allowCredentials?.map((c) => c.id)).toEqual(["YWJj"]);
  });

  it("rejects a principal with no enrolled credential", async () => {
    q.insertPrincipal(db, { id: "prin_2", email: "c@d.test", display_name: "C" });
    await expect(beginApproval(db, "prin_2", hash, "approve")).rejects.toThrow(/no enrolled credential/);
  });

  it("rejects a malformed action hash", async () => {
    await expect(beginApproval(db, "prin_1", "sha256:nope", "approve")).rejects.toThrow(/malformed hash/);
  });
});
