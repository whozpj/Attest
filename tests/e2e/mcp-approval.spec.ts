import { test, expect } from "@playwright/test";
import {
  withVirtualAuthenticator, createPrincipal, enrolPasskey, waitForApprovalLink,
  clickDecision, mcpClient,
} from "./fixtures.js";

const BASE = "http://localhost:3000";

// The loop this whole feature exists to prove: an MCP client (standing in
// for Claude, LangGraph, or any other agent framework) calls request_approval,
// a real human approves via the real emailed link and the real SPA, and
// wait_for_approval -- called by the SAME MCP client, over the SAME
// connection -- returns the resulting verified token. Nothing here is
// mocked: the MCP tool call is real Streamable HTTP, the email is a real
// .eml written to disk, and the approval is a real WebAuthn ceremony against
// the virtual authenticator.
test("an MCP client requests approval, a human approves via email, and wait_for_approval returns a verified token", async ({ page }) => {
  await withVirtualAuthenticator(page);
  const email = `e2e-mcp-${Date.now()}@test.local`;
  const { principalId, enrolmentToken } = await createPrincipal(BASE, email);
  await enrolPasskey(page, principalId, enrolmentToken);

  const client = await mcpClient(BASE);

  const created = await client.callTool({
    name: "request_approval",
    arguments: {
      type: "wire_transfer", risk_tier: "high",
      payload: { amount: 2500000, currency: "USD", recipient_name: "Acme Corp", account_last4: "4821" },
      approver_emails: [email],
      requested_by: "e2e-mcp-agent",
    },
  });
  expect(created.isError).not.toBe(true);
  const { attestation_id } = created.structuredContent as { attestation_id: string };

  // A human approves via the real emailed link, exactly as in flow.spec.ts.
  await page.goto(await waitForApprovalLink(email));
  await clickDecision(page, "Approve with passkey");
  await expect(page.locator(".pill")).toHaveText("Approved");

  // The SAME MCP client that requested it learns the outcome.
  const waited = await client.callTool({
    name: "wait_for_approval",
    arguments: { attestation_id, timeout_seconds: 10 },
  });
  const result = waited.structuredContent as { status: string; token: string; timed_out: boolean };
  expect(result.status).toBe("approved");
  expect(result.timed_out).toBe(false);
  expect(result.token).toBeTruthy();

  // Verify it the same way any receiving system would: against the real
  // published JWKS, over the real REST API.
  const verified = await fetch(`${BASE}/v1/attestations/verify`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ token: result.token }),
  }).then((r) => r.json());
  expect(verified.valid).toBe(true);
  expect(verified.principal_id).toBe(principalId);
});

test("wait_for_approval reports timed_out: true, and a subsequent check_approval still shows pending, when nobody decides", async () => {
  const email = `e2e-mcp-timeout-${Date.now()}@test.local`;
  const { principalId } = await createPrincipal(BASE, email);

  const client = await mcpClient(BASE);
  const created = await client.callTool({
    name: "request_approval",
    arguments: {
      type: "generic", risk_tier: "low", payload: { title: "Never decided", detail: "d" },
      approver_emails: [email],
    },
  });
  const { attestation_id } = created.structuredContent as { attestation_id: string };

  const waited = await client.callTool({
    name: "wait_for_approval",
    arguments: { attestation_id, timeout_seconds: 1 },
  });
  const result = waited.structuredContent as { status: string; timed_out: boolean };
  expect(result.timed_out).toBe(true);
  expect(result.status).toBe("pending");

  const checked = await client.callTool({ name: "check_approval", arguments: { attestation_id } });
  expect((checked.structuredContent as { status: string }).status).toBe("pending");
});
