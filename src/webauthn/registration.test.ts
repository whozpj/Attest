// src/webauthn/registration.test.ts
import { describe, it, expect, beforeEach, vi } from "vitest";
import { openDb } from "../db/index.js";
import * as q from "../db/queries.js";
import { beginRegistration } from "./registration.js";
import type { Database } from "better-sqlite3";

// finishRegistration's failure path is exercised with a mocked
// verifyRegistrationResponse rather than a real crafted attestation --
// isolates the audit-row behavior this function owns from
// @simplewebauthn's own signature verification, which is out of scope here.
// (Reviewer-2's whole-branch review reproduced the same rejection with a
// genuine crafted `packed` attestation through the real HTTP surface; this
// unit test targets the fix at the function level.)
vi.mock("@simplewebauthn/server", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@simplewebauthn/server")>();
  return { ...actual, verifyRegistrationResponse: vi.fn() };
});

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

describe("finishRegistration", () => {
  it("does not write audit_log itself on a failed verification -- that's the central HTTP handler's job", async () => {
    // Regression test for the exact defect fixed in
    // src/webauthn/authentication.ts (a9572b7): a throw site calling
    // q.audit() directly, in addition to the central handler in
    // src/api/server.ts writing its own row for the same rejection when it
    // reaches real HTTP, produces two rows for one event. finishRegistration
    // no longer writes audit_log at all on failure -- it just throws a
    // typed FailClosedError, which is all the central handler needs.
    const { verifyRegistrationResponse } = await import("@simplewebauthn/server");
    vi.mocked(verifyRegistrationResponse).mockResolvedValue({
      verified: false, registrationInfo: undefined,
    } as never);

    const { finishRegistration } = await import("./registration.js");
    await expect(
      finishRegistration(db, "prin_1", "irrelevant-challenge", {} as never),
    ).rejects.toMatchObject({ code: "registration_failed", httpStatus: 400 });

    const rows = db.prepare("SELECT * FROM audit_log").all();
    expect(rows).toHaveLength(0);
  });
});
