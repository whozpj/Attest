import type { Database } from "better-sqlite3";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { createAttestation, getAttestationView } from "../api/attestations-core.js";
import * as q from "../db/queries.js";
import { FailClosedError } from "../types.js";
import type { EmailTransport } from "../email/index.js";

export interface McpContext {
  db: Database;
  email: EmailTransport;
  baseUrl: string;
}

const WAIT_DEFAULT_SECONDS = 300;
const WAIT_MAX_SECONDS = 3600;
const WAIT_POLL_MS = 1000;

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
 *
 * Unlike a REST rejection, a tool error never throws, so it never reaches
 * server.ts's central setErrorHandler -- the only other place q.audit gets
 * called for a rejection. This is the one place that gap gets closed for
 * /mcp, which (like /v1/*) requires no caller authentication.
 */
function toolError(db: Database, err: FailClosedError, toolName: string) {
  q.audit(db, {
    attestation_id: null,
    event: err.code,
    actor: null,
    detail: `${toolName}: ${err.message}`,
  });
  return {
    isError: true as const,
    content: [{ type: "text" as const, text: err.message }],
    structuredContent: { error: err.code, message: err.message },
  };
}

/**
 * Resolves each address to an enrolled principal via getPrincipalByEmail.
 *
 * Unlike POST /web/session/options (which must stay opaque about whether an
 * email is registered, because a stranger can reach it unauthenticated), the
 * caller here is whoever configured this MCP integration -- naming which
 * address failed to resolve is a real usability win for a configuration-time
 * error, not a probe surface against arbitrary third parties (design doc D5).
 */
function resolveApprovers(db: Database, emails: string[]): string[] {
  const ids: string[] = [];
  for (const email of new Set(emails)) {
    const principal = q.getPrincipalByEmail(db, email);
    if (!principal) {
      throw new FailClosedError("unknown_principal", 404, `no enrolled approver with email ${email}`);
    }
    ids.push(principal.id);
  }
  return ids;
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
        if (err instanceof FailClosedError) return toolError(ctx.db, err, "check_approval");
        throw err;
      }
    },
  );

  server.registerTool(
    "request_approval",
    {
      title: "Request human approval",
      description:
        "Ask a specific human to approve or deny a structured agent action. " +
        "Returns immediately with a pending attestation -- use wait_for_approval " +
        "or check_approval to learn the outcome. The action is limited to " +
        "{type, risk_tier, payload}: there is no free-text display field, " +
        "because what the approver sees is always rendered server-side from " +
        "this same structured payload, never supplied directly.",
      inputSchema: {
        type: z.enum(["wire_transfer", "send_email", "sign_document", "generic"])
          .describe(
            "wire_transfer: amount (INTEGER CENTS, not dollars -- $47,500.00 is " +
              "4750000, not 47500)/currency (ISO 4217, e.g. \"USD\")/recipient_name/" +
              "account_last4 (string, e.g. \"7734\"). " +
              "send_email: to/subject/body. sign_document: document_name/document_hash. " +
              "generic: title/detail -- use this for anything else (e.g. a PR merge, an infra change).",
          ),
        risk_tier: z.enum(["low", "medium", "high", "critical"]),
        payload: z.record(z.string(), z.unknown())
          .describe(
            "Fields required depend on `type` (see its description) -- ONLY those " +
              "fields, exactly, or the request is rejected closed with " +
              "\"unexpected field: <name>\"; there is no free-text/reason/note field on " +
              "any type. After calling this tool, always re-read the returned " +
              "`summary.headline` and confirm it states the amount/recipient you " +
              "intended before calling wait_for_approval -- the server renders that " +
              "summary from exactly the payload you sent, so a wrong or misunderstood " +
              "field (most commonly: dollars instead of cents) is visible there before " +
              "any human ever sees the request, and a human should never be asked to " +
              "approve a request you haven't confirmed reads correctly yourself.",
          ),
        approver_emails: z.array(z.string().email()).min(1)
          .describe("Email address(es) of already-enrolled Human-Attest principals."),
        requested_by: z.string().optional()
          .describe("Defaults to this MCP client's declared name."),
        required_approvals: z.number().int().min(1).optional().describe("Defaults to 1."),
        ttl_seconds: z.number().optional().describe("Defaults to 900 (15 minutes)."),
      },
    },
    async (args, extra) => {
      let approverIds: string[];
      try {
        approverIds = resolveApprovers(ctx.db, args.approver_emails);
      } catch (err) {
        if (err instanceof FailClosedError) return toolError(ctx.db, err, "request_approval");
        throw err;
      }

      const clientInfo = server.server.getClientVersion();
      const requestedBy = args.requested_by ?? clientInfo?.name ?? "mcp-client";

      try {
        const result = createAttestation(ctx.db, ctx.email, ctx.baseUrl, {
          requested_by: requestedBy,
          approver_ids: approverIds,
          required_approvals: args.required_approvals,
          ttl_seconds: args.ttl_seconds,
          action: { type: args.type, risk_tier: args.risk_tier, payload: args.payload },
        });
        return {
          content: [{
            type: "text" as const,
            text: `Approval requested: ${result.summary.headline}. Status: pending. ` +
              `attestation_id=${result.attestation_id}`,
          }],
          structuredContent: result as unknown as Record<string, unknown>,
        };
      } catch (err) {
        if (err instanceof FailClosedError) return toolError(ctx.db, err, "request_approval");
        throw err;
      }
    },
  );

  server.registerTool(
    "wait_for_approval",
    {
      title: "Wait for approval",
      description:
        "Polls until the attestation resolves (approved/denied/expired) or the " +
        "timeout elapses, whichever comes first. Prefer this over repeatedly " +
        "calling check_approval yourself.",
      inputSchema: {
        attestation_id: z.string(),
        timeout_seconds: z.number().int().min(1).max(WAIT_MAX_SECONDS).optional()
          .describe(`Defaults to ${WAIT_DEFAULT_SECONDS}. Capped at ${WAIT_MAX_SECONDS}.`),
      },
    },
    async (args, extra) => {
      const timeoutMs = (args.timeout_seconds ?? WAIT_DEFAULT_SECONDS) * 1000;
      const deadline = Date.now() + timeoutMs;

      let view;
      try {
        view = getAttestationView(ctx.db, args.attestation_id);
        while (view.status === "pending" && Date.now() < deadline && !extra.signal.aborted) {
          await new Promise((resolve) => setTimeout(resolve, WAIT_POLL_MS));
          view = getAttestationView(ctx.db, args.attestation_id);
        }
      } catch (err) {
        if (err instanceof FailClosedError) return toolError(ctx.db, err, "wait_for_approval");
        throw err;
      }

      const timedOut = view.status === "pending";
      return {
        content: [{
          type: "text" as const,
          text: timedOut
            ? "Timed out while still pending."
            : `Resolved: ${view.status}.`,
        }],
        structuredContent: { status: view.status, token: view.token, timed_out: timedOut },
      };
    },
  );

  return server;
}
