// The MCP equivalent of demo/agent.ts: a minimal, real reference client
// showing how an MCP-compatible agent framework would call this service --
// request_approval, then wait_for_approval, then consume_approval right
// before "executing" anything. Requires the real server running
// (`npm run dev`) and a principal with an enrolled passkey (see README.md).
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const BASE = "http://localhost:3000";

async function main(): Promise<void> {
  const approverEmail = process.argv[2];
  if (!approverEmail) throw new Error("usage: npm run demo:mcp -- <approver_email>");

  const client = new Client({ name: "demo-mcp-agent", version: "1.0.0" });
  await client.connect(new StreamableHTTPClientTransport(new URL(`${BASE}/mcp`)));

  console.log("Requesting approval via MCP...");
  const created = await client.callTool({
    name: "request_approval",
    arguments: {
      type: "wire_transfer", risk_tier: "high",
      payload: { amount: 2500000, currency: "USD", recipient_name: "Acme Corp", account_last4: "4821" },
      approver_emails: [approverEmail],
      requested_by: "demo-mcp-agent",
    },
  });
  if (created.isError) {
    console.error("request_approval failed:", created.content);
    process.exit(1);
  }
  const requested = created.structuredContent as {
    attestation_id: string; payload_hash: string; summary: { headline: string };
  };
  console.log(`  ${requested.summary.headline}`);
  console.log(`  An approval email has been sent to ${approverEmail}. Waiting for a decision (up to 15 minutes)...\n`);

  const waited = await client.callTool({
    name: "wait_for_approval",
    arguments: { attestation_id: requested.attestation_id, timeout_seconds: 900 },
  });
  if (waited.isError) {
    console.error("wait_for_approval failed:", waited.content);
    process.exit(1);
  }
  const result = waited.structuredContent as { status: string; token: string | null; timed_out: boolean };

  if (result.timed_out) {
    console.log("Timed out waiting for a decision.");
    return;
  }
  if (result.status !== "approved") {
    console.log(`Refusing to execute: attestation ${result.status}.`);
    return;
  }

  const consumed = await client.callTool({
    name: "consume_approval",
    arguments: { token: result.token },
  });
  if (consumed.isError) {
    console.log("Refusing to execute: could not consume the token.", consumed.structuredContent);
    return;
  }
  const verified = consumed.structuredContent as { valid: boolean; action_hash: string };

  if (!verified.valid || verified.action_hash !== requested.payload_hash) {
    console.log("Refusing to execute: token did not verify against this action.");
    return;
  }
  console.log("Consumed. Executing wire transfer.");
  console.log("(A second consume_approval call on this same token would now fail with already_consumed.)");
}

await main();
export {};
