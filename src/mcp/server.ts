import type { Database } from "better-sqlite3";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { getAttestationView } from "../api/attestations-core.js";
import { FailClosedError } from "../types.js";
import type { EmailTransport } from "../email/index.js";

export interface McpContext {
  db: Database;
  email: EmailTransport;
  baseUrl: string;
}

/**
 * Every tool handler below funnels a FailClosedError into an MCP tool error
 * result (`isError: true`) rather than letting it propagate as a thrown
 * protocol-level exception. An MCP client that gets an unstructured
 * connection error can't tell "your input was invalid" from "the server
 * crashed" -- a tool error keeps that distinction, matching how the REST API
 * always returns a typed JSON body rather than closing the connection.
 * Anything that is NOT a FailClosedError is rethrown: an unrecognised
 * failure should surface as a real error, not be silently downgraded to a
 * tool result the caller might mistake for an ordinary rejection.
 */
function toolError(message: string) {
  return { isError: true as const, content: [{ type: "text" as const, text: message }] };
}

export function buildMcpServer(ctx: McpContext): McpServer {
  const server = new McpServer({ name: "human-attest", version: "1.0.0" });

  server.registerTool(
    "check_approval",
    {
      title: "Check approval status",
      description: "Reads the current status of a pending or resolved attestation.",
      inputSchema: {
        attestation_id: z.string().describe("The attestation_id returned by request_approval."),
      },
    },
    async (args) => {
      try {
        const view = getAttestationView(ctx.db, args.attestation_id);
        return {
          content: [{ type: "text" as const, text: `Status: ${view.status}` }],
          structuredContent: view as unknown as Record<string, unknown>,
        };
      } catch (err) {
        if (err instanceof FailClosedError) return toolError(err.message);
        throw err;
      }
    },
  );

  return server;
}
