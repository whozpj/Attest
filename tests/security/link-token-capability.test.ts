// tests/security/link-token-capability.test.ts
//
// Attack: treating the emailed approval link as an authorization rather than
// a view capability.
//
// Design doc §2/D8: "The link token is a view capability, not an
// authorization." That is the load-bearing claim behind D1 -- email is
// transport only, the passkey still authorizes. If a link token could cause
// any state change, the product's claim would silently degrade from "this
// human's authenticator signed this exact action hash" to "someone read this
// inbox," which is precisely the weaker claim the whole codebase exists to
// improve on.
//
// A token lands in an inbox, so it must be assumed compromised: inboxes are
// forwarded, backed up, synced to third parties, and read on shared devices.
// These tests therefore give the attacker the token outright and ask what
// they can do with it. The answer must be: read one pending request, and
// nothing else.
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

const wire = {
  type: "wire_transfer",
  risk_tier: "high",
  payload: { amount: 2500000, currency: "USD", recipient_name: "Acme Corp", account_last4: "4821" },
};

function recorder(): EmailTransport & { sent: EmailMessage[] } {
  const sent: EmailMessage[] = [];
  return { sent, async send(msg) { sent.push(msg); } };
}

/**
 * emailApprovers is deliberately fire-and-forget (`void` at the call site in
 * routes.attestations.ts), so the 201 can land before the last message is
 * recorded. Wait for the mail rather than assuming a microtask ordering that
 * an unrelated change could reshuffle into a flaky failure.
 */
async function waitForMail(mail: { sent: EmailMessage[] }, count: number): Promise<void> {
  for (let i = 0; i < 100 && mail.sent.length < count; i += 1) {
    await new Promise((r) => setTimeout(r, 5));
  }
  expect(mail.sent.length).toBeGreaterThanOrEqual(count);
}

async function newApp(mail: EmailTransport): Promise<App> {
  return buildServer({
    dbPath: ":memory:",
    keyDir: mkdtempSync(join(tmpdir(), "ha-link-")),
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

/** A snapshot of everything a link view is forbidden to change. */
function stateOf(app: App, attestationId: string) {
  const att = q.getAttestation(app.ctx.db, attestationId)!;
  const action = q.getAction(app.ctx.db, att.action_id)!;
  return {
    status: att.status,
    resolved_at: att.resolved_at,
    token: att.token,
    canonical_json: action.canonical_json,
    approvals: q.getApprovals(app.ctx.db, attestationId).length,
    links: (app.ctx.db.prepare(`SELECT COUNT(*) AS c FROM approval_links`).get() as { c: number }).c,
    sessions: (app.ctx.db.prepare(`SELECT COUNT(*) AS c FROM sessions`).get() as { c: number }).c,
  };
}

describe("attack: using an approval link to change state", () => {
  let app: App;
  let mail: ReturnType<typeof recorder>;
  let attestationId: string;
  let tokenA: string;

  beforeEach(async () => {
    mail = recorder();
    app = await newApp(mail);
    seedApprover(app, "prin_a", "a@t.test");
    seedApprover(app, "prin_b", "b@t.test");

    const created = await app.inject({
      method: "POST",
      url: "/v1/attestations",
      payload: {
        requested_by: "agent-7",
        approver_ids: ["prin_a", "prin_b"],
        required_approvals: 2,
        ttl_seconds: 900,
        action: wire,
      },
    });
    expect(created.statusCode).toBe(201);
    attestationId = created.json().attestation_id as string;
    await waitForMail(mail, 2);

    // Taken from the message that was actually delivered, not from the
    // database -- this is the token a real attacker would hold.
    const toA = mail.sent.find((m) => m.to === "a@t.test")!;
    tokenA = toA.text.match(/\/a\/([A-Za-z0-9_-]+)/)![1];
  });

  it("resolves the link to its request without touching attestation state", async () => {
    const before = stateOf(app, attestationId);

    const res = await app.inject({ method: "GET", url: `/web/link/${tokenA}` });

    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({
      attestation_id: attestationId, principal_id: "prin_a", email: "a@t.test",
    });
    expect(stateOf(app, attestationId)).toEqual(before);
  });

  it("stays a pure read under repetition -- the token is not consumed and nothing accumulates", async () => {
    const before = stateOf(app, attestationId);

    for (let i = 0; i < 5; i += 1) {
      expect((await app.inject({ method: "GET", url: `/web/link/${tokenA}` })).statusCode).toBe(200);
    }

    expect(stateOf(app, attestationId)).toEqual(before);
    expect(q.getApprovals(app.ctx.db, attestationId)).toHaveLength(0);
  });

  it("exposes no non-GET verb on the link route", async () => {
    const before = stateOf(app, attestationId);

    for (const method of ["POST", "PUT", "PATCH", "DELETE"] as const) {
      const res = await app.inject({ method, url: `/web/link/${tokenA}` });
      expect(res.statusCode).toBe(404);
    }

    expect(stateOf(app, attestationId)).toEqual(before);
  });

  // Enumerates the router itself rather than trusting that nobody added a
  // second token-consuming route. `:token` appearing on exactly one line, and
  // that line being a read, is the machine-checkable form of "the token is a
  // view capability".
  it("registers exactly one route that reads a :token param, and it is read-only", async () => {
    await app.ready();
    const tokenRoutes = app
      .printRoutes({ commonPrefix: false })
      .split("\n")
      .filter((line) => line.includes(":token"));

    expect(tokenRoutes).toHaveLength(1);
    expect(tokenRoutes[0]).toContain("/web/link/:token");
    expect(tokenRoutes[0]).toContain("(GET, HEAD)");
    expect(tokenRoutes[0]).not.toMatch(/POST|PUT|PATCH|DELETE/);
  });

  it("cannot be smuggled in as a session cookie", async () => {
    const asCookie = { cookie: `ha_session=${tokenA}` };

    expect((await app.inject({ method: "GET", url: "/web/me", headers: asCookie })).statusCode)
      .toBe(401);
    expect((await app.inject({ method: "GET", url: "/web/requests", headers: asCookie })).statusCode)
      .toBe(401);
    expect((await app.inject({
      method: "GET", url: `/web/requests/${attestationId}`, headers: asCookie,
    })).statusCode).toBe(401);
  });

  it("does not authorize a decision on its own -- an unsigned POST is still refused", async () => {
    const before = stateOf(app, attestationId);

    const res = await app.inject({
      method: "POST",
      url: `/v1/attestations/${attestationId}/decision`,
      headers: { cookie: `ha_session=${tokenA}` },
      payload: { principal_id: "prin_a", decision: "approve", link_token: tokenA },
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe("signature_required");
    expect(stateOf(app, attestationId)).toEqual(before);
  });

  it("returns 404 for an unknown token and changes nothing", async () => {
    const before = stateOf(app, attestationId);

    const res = await app.inject({ method: "GET", url: "/web/link/not-a-real-token" });

    expect(res.statusCode).toBe(404);
    expect(res.json().error).toBe("unknown_link");
    expect(stateOf(app, attestationId)).toEqual(before);
  });
});

describe("attack: using one approver's link to act as another approver", () => {
  let app: App;
  let mail: ReturnType<typeof recorder>;
  let credA: FakeCredential;
  let attestationId: string;
  let tokenA: string;
  let tokenB: string;

  beforeEach(async () => {
    mail = recorder();
    app = await newApp(mail);
    credA = seedApprover(app, "prin_a", "a@t.test");
    seedApprover(app, "prin_b", "b@t.test");

    const created = await app.inject({
      method: "POST",
      url: "/v1/attestations",
      payload: {
        requested_by: "agent-7",
        approver_ids: ["prin_a", "prin_b"],
        required_approvals: 2,
        ttl_seconds: 900,
        action: wire,
      },
    });
    attestationId = created.json().attestation_id as string;
    await waitForMail(mail, 2);

    tokenA = mail.sent.find((m) => m.to === "a@t.test")!.text.match(/\/a\/([A-Za-z0-9_-]+)/)![1];
    tokenB = mail.sent.find((m) => m.to === "b@t.test")!.text.match(/\/a\/([A-Za-z0-9_-]+)/)![1];
  });

  it("mails each approver a distinct token, so one inbox never carries another's link", () => {
    expect(tokenA).not.toBe(tokenB);
    expect(q.getApprovalLink(app.ctx.db, tokenA)!.principal_id).toBe("prin_a");
    expect(q.getApprovalLink(app.ctx.db, tokenB)!.principal_id).toBe("prin_b");
  });

  it("names only its own approver -- resolving A's link reveals nothing about B", async () => {
    const body = (await app.inject({ method: "GET", url: `/web/link/${tokenA}` })).body;

    expect(Object.keys(JSON.parse(body)).sort())
      .toEqual(["attestation_id", "email", "principal_id"]);
    expect(body).not.toContain("prin_b");
    expect(body).not.toContain("b@t.test");
  });

  it("cannot be used to record a decision as the other principal", async () => {
    const before = stateOf(app, attestationId);

    // The attacker holds A's link and A's mailbox but not B's authenticator.
    // The strongest thing they can present is a genuine assertion from A's
    // key, declared as B.
    const opts = await app.inject({
      method: "POST",
      url: `/v1/attestations/${attestationId}/options`,
      payload: { principal_id: "prin_a", decision: "approve" },
    });
    const assertion = signAssertion(credA, opts.json().challenge as string);

    const res = await app.inject({
      method: "POST",
      url: `/v1/attestations/${attestationId}/decision`,
      payload: { principal_id: "prin_b", decision: "approve", response: assertion },
    });

    expect(res.statusCode).toBe(401);
    expect(res.json().error).toBe("unknown_credential");
    expect(q.getApprovals(app.ctx.db, attestationId)).toHaveLength(0);
    expect(stateOf(app, attestationId)).toEqual(before);
  });

  it("cannot be used to deny as the other principal either", async () => {
    const opts = await app.inject({
      method: "POST",
      url: `/v1/attestations/${attestationId}/options`,
      payload: { principal_id: "prin_a", decision: "deny" },
    });
    const assertion = signAssertion(credA, opts.json().challenge as string);

    const res = await app.inject({
      method: "POST",
      url: `/v1/attestations/${attestationId}/decision`,
      payload: { principal_id: "prin_b", decision: "deny", response: assertion },
    });

    expect(res.statusCode).toBe(401);
    expect(q.getAttestation(app.ctx.db, attestationId)!.status).toBe("pending");
    expect(q.getApprovals(app.ctx.db, attestationId)).toHaveLength(0);
  });

  it("leaves A's own quorum contribution intact -- the guard is on identity, not on the link", async () => {
    // Control: with A's own principal_id, the very same ceremony succeeds.
    // So the rejections above are about impersonating B, not about the flow
    // being broken.
    const opts = await app.inject({
      method: "POST",
      url: `/v1/attestations/${attestationId}/options`,
      payload: { principal_id: "prin_a", decision: "approve" },
    });
    const res = await app.inject({
      method: "POST",
      url: `/v1/attestations/${attestationId}/decision`,
      payload: {
        principal_id: "prin_a", decision: "approve",
        response: signAssertion(credA, opts.json().challenge as string),
      },
    });

    expect(res.statusCode).toBe(200);
    expect(res.json().status).toBe("pending"); // quorum is 2
    expect(q.getApprovals(app.ctx.db, attestationId)).toHaveLength(1);
  });
});
