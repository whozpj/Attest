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
  it("encodes the action hash as the base64url challenge", () => {
    const hex = hash.replace("sha256:", "");
    expect(challengeFor(hash)).toBe(Buffer.from(hex, "hex").toString("base64url"));
  });

  it("differs for different actions", () => {
    expect(challengeFor(hash)).not.toBe(challengeFor(hashCanonical('{"amount":1}')));
  });
});

describe("beginApproval", () => {
  it("uses the action hash as the challenge, not a random value", async () => {
    const opts = await beginApproval(db, "prin_1", hash);
    expect(opts.challenge).toBe(challengeFor(hash));
  });

  it("is deterministic for the same action", async () => {
    const a = await beginApproval(db, "prin_1", hash);
    const b = await beginApproval(db, "prin_1", hash);
    expect(a.challenge).toBe(b.challenge);
  });

  it("restricts to the principal's own credentials", async () => {
    const opts = await beginApproval(db, "prin_1", hash);
    expect(opts.allowCredentials?.map((c) => c.id)).toEqual(["YWJj"]);
  });

  it("rejects a principal with no enrolled credential", async () => {
    q.insertPrincipal(db, { id: "prin_2", email: "c@d.test", display_name: "C" });
    await expect(beginApproval(db, "prin_2", hash)).rejects.toThrow(/no enrolled credential/);
  });

  it("rejects a malformed action hash", async () => {
    await expect(beginApproval(db, "prin_1", "sha256:nope")).rejects.toThrow(/malformed hash/);
  });
});
