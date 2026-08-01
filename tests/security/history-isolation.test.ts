// tests/security/history-isolation.test.ts
//
// Two claims are under test here, and they fail in opposite directions.
//
// 1. Tenancy. `/web/requests` and `/web/requests/:id` are the first
//    authenticated, browsable surfaces this service has ever had. Every prior
//    read path was keyed by an unguessable id; a history list is keyed by
//    *who you are*, which is a category of bug the codebase has no prior
//    exposure to. A signed-in principal must see their own requests and
//    nothing else -- and a non-approver probing a real attestation id must be
//    indistinguishable from one probing a nonexistent one, or the endpoint
//    becomes an existence oracle for other people's requests.
//
// 2. Retention (design doc §6/D6, argued at length in §7). The README's
//    headline promise is that this is "not a permanent store of wire amounts,
//    recipient names, or email bodies." A history view is exactly the feature
//    that quietly breaks that promise, because showing a recognizable
//    headline next to a three-week-old row requires keeping the text forever.
//    The chosen answer is metadata-only after resolution.
//
// The sentinel technique below is the only honest way to test claim 2: pick a
// string that could not plausibly occur by accident, put it in the payload,
// resolve the attestation, then search everything the outside world can see.
// Asserting `summary === null` would only prove that one field was nulled;
// asserting the sentinel is *nowhere* proves the text is actually gone.
//
// Every "the sentinel is absent" assertion is paired with a control that the
// sentinel was present and reachable before resolution. Without that pairing,
// a typo in the payload would make the whole suite pass vacuously.
import { describe, it, expect, beforeEach } from "vitest";
import { randomUUID } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { FastifyInstance } from "fastify";
import { buildServer, type AppContext } from "../../src/api/server.js";
import * as q from "../../src/db/queries.js";
import type { EmailMessage, EmailTransport } from "../../src/email/index.js";
import { makeFakeCredential, type FakeCredential, signAssertion } from "./lib/webauthn-fake.js";

type App = FastifyInstance & { ctx: AppContext };

const SENTINEL = "ZZQQX-SENTINEL";

function wireTo(recipient: string) {
  return {
    type: "wire_transfer",
    risk_tier: "high",
    payload: { amount: 2500000, currency: "USD", recipient_name: recipient, account_last4: "4821" },
  };
}

function recorder(): EmailTransport & { sent: EmailMessage[] } {
  const sent: EmailMessage[] = [];
  return { sent, async send(msg) { sent.push(msg); } };
}

async function newApp(mail: EmailTransport): Promise<App> {
  return buildServer({
    dbPath: ":memory:",
    keyDir: mkdtempSync(join(tmpdir(), "ha-hist-")),
    email: mail,
  }) as Promise<App>;
}

function seedApprover(app: App, id: string, email: string): FakeCredential {
  q.insertPrincipal(app.ctx.db, { id, email, display_name: id });
  const cred = makeFakeCredential();
  q.insertCredential(app.ctx.db, {
    id: `cred_${randomUUID()}`,
    principal_id: id,
    credential_id: cred.credentialId,
    public_key: cred.publicKeyCose,
    transports: null,
  });
  return cred;
}

/** Signs in for real, through the same ceremony a browser would run. */
async function signIn(app: App, cred: FakeCredential, email: string, count = 1): Promise<string> {
  const opts = await app.inject({
    method: "POST", url: "/web/session/options", payload: { email },
  });
  const res = await app.inject({
    method: "POST",
    url: "/web/session",
    payload: { email, response: signAssertion(cred, opts.json().challenge as string, count) },
  });
  expect(res.statusCode).toBe(204);
  return (res.headers["set-cookie"] as string).split(";")[0];
}

async function createAttestation(
  app: App, approverIds: string[], action: unknown, ttlSeconds = 900,
): Promise<string> {
  const res = await app.inject({
    method: "POST",
    url: "/v1/attestations",
    payload: {
      requested_by: "agent-7",
      approver_ids: approverIds,
      required_approvals: 1,
      ttl_seconds: ttlSeconds,
      action,
    },
  });
  expect(res.statusCode).toBe(201);
  return res.json().attestation_id as string;
}

/** Runs the real approve ceremony to quorum, so the payload is genuinely purged. */
async function approve(
  app: App, attestationId: string, principalId: string, cred: FakeCredential, count = 1,
): Promise<void> {
  const opts = await app.inject({
    method: "POST",
    url: `/v1/attestations/${attestationId}/options`,
    payload: { principal_id: principalId, decision: "approve" },
  });
  const res = await app.inject({
    method: "POST",
    url: `/v1/attestations/${attestationId}/decision`,
    payload: {
      principal_id: principalId,
      decision: "approve",
      response: signAssertion(cred, opts.json().challenge as string, count),
    },
  });
  expect(res.statusCode).toBe(200);
  expect(res.json().status).toBe("approved");
}

describe("history is scoped to the signed-in principal", () => {
  let app: App;
  let credA: FakeCredential;
  let credB: FakeCredential;
  let mine: string;
  let theirs: string;

  beforeEach(async () => {
    app = await newApp(recorder());
    credA = seedApprover(app, "prin_a", "a@t.test");
    credB = seedApprover(app, "prin_b", "b@t.test");
    mine = await createAttestation(app, ["prin_a"], wireTo("Acme Corp"));
    theirs = await createAttestation(app, ["prin_b"], wireTo("Globex"));
  });

  it("lists only the requests naming this principal as an approver", async () => {
    const cookie = await signIn(app, credA, "a@t.test");
    const res = await app.inject({ method: "GET", url: "/web/requests", headers: { cookie } });

    expect(res.statusCode).toBe(200);
    expect(res.json().items.map((i: { attestation_id: string }) => i.attestation_id)).toEqual([mine]);
    expect(res.body).not.toContain(theirs);
  });

  it("shows each principal a disjoint list", async () => {
    const cookieB = await signIn(app, credB, "b@t.test");
    const res = await app.inject({ method: "GET", url: "/web/requests", headers: { cookie: cookieB } });

    expect(res.json().items.map((i: { attestation_id: string }) => i.attestation_id)).toEqual([theirs]);
    expect(res.body).not.toContain(mine);
  });

  it("does not widen the list through the status filter or the pagination cursor", async () => {
    const cookie = await signIn(app, credA, "a@t.test");

    for (const url of [
      "/web/requests?status=pending",
      "/web/requests?limit=100",
      "/web/requests?limit=100&before=2999-01-01T00:00:00.000Z",
    ]) {
      const res = await app.inject({ method: "GET", url, headers: { cookie } });
      expect(res.statusCode).toBe(200);
      expect(res.body).not.toContain(theirs);
    }
  });

  it("returns nothing at all without a session", async () => {
    expect((await app.inject({ method: "GET", url: "/web/requests" })).statusCode).toBe(401);
  });
});

describe("attack: probing for other principals' requests by id", () => {
  let app: App;
  let credA: FakeCredential;
  let theirs: string;
  let cookie: string;

  beforeEach(async () => {
    app = await newApp(recorder());
    credA = seedApprover(app, "prin_a", "a@t.test");
    seedApprover(app, "prin_b", "b@t.test");
    theirs = await createAttestation(app, ["prin_b"], wireTo("Globex"));
    cookie = await signIn(app, credA, "a@t.test");
  });

  // If these two responses differ in any observable way, a signed-in user can
  // enumerate which attestation ids exist -- and, since ids appear in
  // approve_url and in every email, that is a practical oracle rather than a
  // theoretical one.
  it("answers a real attestation the caller cannot see byte-identically to a nonexistent one", async () => {
    const real = await app.inject({
      method: "GET", url: `/web/requests/${theirs}`, headers: { cookie },
    });
    const fake = await app.inject({
      method: "GET", url: `/web/requests/att_${randomUUID()}`, headers: { cookie },
    });

    expect(real.statusCode).toBe(404);
    expect(fake.statusCode).toBe(real.statusCode);
    expect(fake.body).toBe(real.body);
    expect(fake.headers["content-type"]).toBe(real.headers["content-type"]);
    expect(fake.headers["content-length"]).toBe(real.headers["content-length"]);
  });

  it("gives the same answer for a syntactically alien id, so the id format is not an oracle either", async () => {
    const responses = await Promise.all(
      [theirs, `att_${randomUUID()}`, "not-an-id", "../../etc/passwd"].map((id) =>
        app.inject({ method: "GET", url: `/web/requests/${encodeURIComponent(id)}`, headers: { cookie } }),
      ),
    );

    for (const res of responses) {
      expect(res.statusCode).toBe(404);
      expect(res.body).toBe(responses[0].body);
    }
  });

  it("still serves the caller's own request, so the 404s above are not a blanket denial", async () => {
    const mine = await createAttestation(app, ["prin_a"], wireTo("Acme Corp"));
    const res = await app.inject({
      method: "GET", url: `/web/requests/${mine}`, headers: { cookie },
    });

    expect(res.statusCode).toBe(200);
    expect(res.json().attestation_id).toBe(mine);
  });
});

describe("resolved requests retain no payload text (design doc D6)", () => {
  let app: App;
  let mail: ReturnType<typeof recorder>;
  let credA: FakeCredential;
  let attestationId: string;
  let cookie: string;

  beforeEach(async () => {
    mail = recorder();
    app = await newApp(mail);
    credA = seedApprover(app, "prin_a", "a@t.test");
    attestationId = await createAttestation(app, ["prin_a"], wireTo(SENTINEL));
    cookie = await signIn(app, credA, "a@t.test", 1);
  });

  /** Everything the outside world can read about this attestation. */
  async function sweep(): Promise<string> {
    const urls = [
      "/web/me",
      "/web/requests",
      "/web/requests?status=approved",
      "/web/requests?status=pending",
      `/web/requests/${attestationId}`,
      `/v1/attestations/${attestationId}`,
    ];
    const bodies: string[] = [];
    for (const url of urls) {
      bodies.push((await app.inject({ method: "GET", url, headers: { cookie } })).body);
    }
    const link = q.getApprovalLinkFor(app.ctx.db, attestationId, "prin_a");
    if (link) {
      bodies.push((await app.inject({ method: "GET", url: `/web/link/${link.token}` })).body);
    }
    return bodies.join("\n");
  }

  // The control. If this ever fails, every "absent" assertion below is
  // vacuous and the suite is proving nothing.
  it("control: the sentinel IS visible while the request is pending", async () => {
    expect(await sweep()).toContain(SENTINEL);
  });

  it("is gone from every /web/* and /v1/* response body once approved", async () => {
    expect(await sweep()).toContain(SENTINEL);

    await approve(app, attestationId, "prin_a", credA, 2);

    const after = await sweep();
    expect(after).not.toContain(SENTINEL);
    expect(after).toContain(attestationId); // the metadata is still served
  });

  it("is gone once denied", async () => {
    const opts = await app.inject({
      method: "POST",
      url: `/v1/attestations/${attestationId}/options`,
      payload: { principal_id: "prin_a", decision: "deny" },
    });
    const res = await app.inject({
      method: "POST",
      url: `/v1/attestations/${attestationId}/decision`,
      payload: {
        principal_id: "prin_a", decision: "deny",
        response: signAssertion(credA, opts.json().challenge as string, 2),
      },
    });
    expect(res.json().status).toBe("denied");

    expect(await sweep()).not.toContain(SENTINEL);
  });

  it("is gone once the request simply expires undecided", async () => {
    const expiring = await createAttestation(app, ["prin_a"], wireTo(SENTINEL), -1);

    // The first read is what observes the expiry and triggers the purge.
    await app.inject({ method: "GET", url: `/v1/attestations/${expiring}` });

    const detail = await app.inject({
      method: "GET", url: `/web/requests/${expiring}`, headers: { cookie },
    });
    expect(detail.json().status).toBe("expired");
    expect(detail.body).not.toContain(SENTINEL);
    expect(detail.json().summary).toBeNull();
  });

  it("never reaches audit_log.detail, before or after resolution", async () => {
    const details = () =>
      (app.ctx.db.prepare(`SELECT detail FROM audit_log`).all() as Array<{ detail: string | null }>)
        .map((r) => r.detail ?? "")
        .join("\n");

    expect(details()).not.toContain(SENTINEL);
    await approve(app, attestationId, "prin_a", credA, 2);
    expect(details()).not.toContain(SENTINEL);

    // The audit trail is genuinely populated -- so the assertion above is
    // about the sentinel's absence, not about there being no rows to search.
    expect(q.getAuditFor(app.ctx.db, attestationId).length).toBeGreaterThan(0);
  });

  it("serves an audit trail with no detail column at all", async () => {
    await approve(app, attestationId, "prin_a", credA, 2);

    const res = await app.inject({
      method: "GET", url: `/web/requests/${attestationId}`, headers: { cookie },
    });
    const audit = res.json().audit as Array<Record<string, unknown>>;

    expect(audit.length).toBeGreaterThan(0);
    for (const row of audit) {
      expect(Object.keys(row).sort()).toEqual(["actor", "created_at", "event"]);
    }
  });

  // Broader than the task requires, and deliberately so: nulling
  // actions.canonical_json is only the retention promise if no *other* column
  // quietly kept a copy. This walks every TEXT-bearing column in the schema.
  it("survives a sweep of every text column in the database after resolution", async () => {
    await approve(app, attestationId, "prin_a", credA, 2);

    const tables = (app.ctx.db
      .prepare(`SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'`)
      .all() as Array<{ name: string }>).map((t) => t.name);
    expect(tables.length).toBeGreaterThan(0);

    const offenders: string[] = [];
    for (const table of tables) {
      for (const row of app.ctx.db.prepare(`SELECT * FROM "${table}"`).all() as Array<Record<string, unknown>>) {
        for (const [column, value] of Object.entries(row)) {
          if (typeof value === "string" && value.includes(SENTINEL)) {
            offenders.push(`${table}.${column}`);
          }
        }
      }
    }

    expect(offenders).toEqual([]);
  });

  // Not a leak, and worth pinning down so a future reader does not mistake it
  // for one: the approval email legitimately carried the summary to the
  // approver's inbox while the request was live. The retention promise is
  // about what this service stores, not about what a mail client keeps.
  it("did reach the approver's inbox while pending, which is the delivered notification and not retained state", async () => {
    expect(mail.sent.some((m) => m.text.includes(SENTINEL))).toBe(true);
  });
});
