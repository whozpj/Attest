// tests/security/http-surface.test.ts
//
// HTTP-level adversarial pass over the enrolment routes (src/api/routes.principals.ts).
// Scope: the account-enumeration vector on POST /v1/principals — a distinct
// duplicate-email error would let an attacker probe whether an arbitrary email
// address is already a registered principal, one HTTP request at a time. This
// isn't a row in the product spec's threat table verbatim, but it's the same
// "say why without leaking" principle the design spec states for error
// handling (§9), applied at the one endpoint where the identifier an attacker
// controls (email) is guessable, unlike the UUID principal/attestation ids
// used elsewhere. Written black-box, against the real HTTP surface via
// buildServer + inject — not against the route handler internals.
import { describe, it, expect, beforeEach } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildServer } from "../../src/api/server.js";

let app: Awaited<ReturnType<typeof buildServer>>;

beforeEach(async () => {
  app = await buildServer({
    dbPath: ":memory:",
    keyDir: mkdtempSync(join(tmpdir(), "ha-httpsec-")),
  });
});

describe("attack: enumerate registered emails via the enrolment endpoint", () => {
  it("gives a byte-identical response for a duplicate email and an unrelated malformed body", async () => {
    const first = await app.inject({
      method: "POST", url: "/v1/principals",
      payload: { email: "victim@company.test", display_name: "Victim" },
    });
    expect(first.statusCode).toBe(201);

    // Attacker probe 1: does "victim@company.test" already exist?
    const probeDuplicate = await app.inject({
      method: "POST", url: "/v1/principals",
      payload: { email: "victim@company.test", display_name: "Attacker Probe" },
    });
    // Attacker probe 2 (control): a request the attacker knows is malformed,
    // carrying no email at all.
    const probeMalformed = await app.inject({
      method: "POST", url: "/v1/principals",
      payload: { display_name: "No Email At All" },
    });

    // Same HTTP status.
    expect(probeDuplicate.statusCode).toBe(probeMalformed.statusCode);
    // Byte-identical body — not just the same `error` field, the entire
    // response, so a differently worded message on one path can't act as a
    // side channel even if some future edit keeps the error code the same.
    expect(probeDuplicate.body).toBe(probeMalformed.body);
    // Byte-identical Content-Length — the crudest possible side channel
    // (an attacker who never parses the body can still diff response sizes).
    expect(probeDuplicate.headers["content-length"]).toBe(probeMalformed.headers["content-length"]);
  });

  it("never puts the word 'duplicate' or the probed email in an HTTP-visible response", async () => {
    await app.inject({
      method: "POST", url: "/v1/principals",
      payload: { email: "secret-holder@company.test", display_name: "Holder" },
    });
    const probe = await app.inject({
      method: "POST", url: "/v1/principals",
      payload: { email: "secret-holder@company.test", display_name: "Prober" },
    });
    expect(probe.body.toLowerCase()).not.toContain("duplicate");
    expect(probe.body).not.toContain("secret-holder@company.test");
  });

  it("records the real reason server-side in audit_log without ever surfacing it over HTTP", async () => {
    await app.inject({
      method: "POST", url: "/v1/principals",
      payload: { email: "audited-only@company.test", display_name: "First" },
    });
    const probe = await app.inject({
      method: "POST", url: "/v1/principals",
      payload: { email: "audited-only@company.test", display_name: "Second" },
    });

    const rows = app.ctx.db
      .prepare(`SELECT detail FROM audit_log WHERE event = 'principal_invalid'`)
      .all() as Array<{ detail: string | null }>;
    // The server does know the real reason — it's just never handed to the caller.
    expect(rows.some((r) => (r.detail ?? "").includes("duplicate email"))).toBe(true);
    expect(probe.body).not.toContain("duplicate email");
  });

  it("does not leak a principal_id on any failure path", async () => {
    await app.inject({
      method: "POST", url: "/v1/principals",
      payload: { email: "leak-check@company.test", display_name: "First" },
    });
    const probe = await app.inject({
      method: "POST", url: "/v1/principals",
      payload: { email: "leak-check@company.test", display_name: "Second" },
    });
    expect(probe.json()).not.toHaveProperty("principal_id");
  });
});

describe("attack: probe principal existence via the credential-registration endpoint", () => {
  it("gives the same no_pending_registration response for a principal that never existed as for one that did but has no pending challenge", async () => {
    // Branch A: a principal that genuinely exists, but never called .../options.
    const real = await app.inject({
      method: "POST", url: "/v1/principals",
      payload: { email: "real@company.test", display_name: "Real" },
    });
    const { principal_id: realId } = real.json();
    const resReal = await app.inject({
      method: "POST", url: `/v1/principals/${realId}/credentials`,
      payload: {},
    });

    // Branch B: a principal id that was never created at all.
    const resFake = await app.inject({
      method: "POST", url: "/v1/principals/prin_does_not_exist/credentials",
      payload: {},
    });

    expect(resReal.statusCode).toBe(resFake.statusCode);
    expect(resReal.statusCode).toBe(400);
    expect(resReal.json()).toEqual(resFake.json());
    expect(resReal.json().error).toBe("no_pending_registration");
  });
});

describe("fail-closed error envelope: no accidental debug leakage", () => {
  it("a principal_invalid response carries exactly {error, message} — nothing else", async () => {
    const res = await app.inject({
      method: "POST", url: "/v1/principals",
      payload: { display_name: "No Email" },
    });
    expect(Object.keys(res.json()).sort()).toEqual(["error", "message"]);
  });

  it("a no_pending_registration response carries exactly {error, message} — nothing else", async () => {
    const res = await app.inject({
      method: "POST", url: "/v1/principals/prin_ghost/credentials",
      payload: {},
    });
    expect(Object.keys(res.json()).sort()).toEqual(["error", "message"]);
  });
});
