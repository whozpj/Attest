import type { FastifyInstance } from "fastify";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { buildMcpServer } from "./server.js";
import type { AppContext } from "../api/server.js";

/**
 * Stateless mode (design doc D2): no session id, no in-memory session map
 * that could grow unbounded if a client disconnects without an explicit
 * close, and no session affinity requirement if this app is ever run behind
 * a load balancer.
 *
 * A fresh McpServer + transport is built for every request rather than one
 * shared pair built once at registration. The installed SDK's
 * StreamableHTTPServerTransport enforces this: in stateless mode
 * (sessionIdGenerator: undefined) it throws "Stateless transport cannot be
 * reused across requests" the second time handleRequest is called on the
 * same instance (webStandardStreamableHttp.js's handleRequest, guarded by
 * `_hasHandledRequest`) -- confirmed by driving a real two-request sequence
 * against a shared instance, which 500'd on request two. Building fresh
 * instances per request is the SDK's own documented pattern for stateless
 * mode.
 */
export async function registerMcpRoutes(app: FastifyInstance & { ctx: AppContext }): Promise<void> {
  app.post("/mcp", async (req, reply) => {
    const mcpServer = buildMcpServer({ db: app.ctx.db, email: app.ctx.email, baseUrl: app.ctx.baseUrl });
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });

    // Hand the raw Node request/response to the transport and tell Fastify
    // not to touch the response itself -- the transport ends it directly
    // (streamableHttp.d.ts's handleRequest signature is built for exactly
    // this: Node's IncomingMessage/ServerResponse, with an optional
    // pre-parsed body, which req.body already is thanks to server.ts's own
    // preValidation hook normalizing it upstream of every route).
    reply.hijack();
    reply.raw.on("close", () => {
      void transport.close();
      void mcpServer.close();
    });

    await mcpServer.connect(transport);
    await transport.handleRequest(req.raw, reply.raw, req.body);
  });

  // The Streamable HTTP spec's GET is for a standalone server-initiated SSE
  // stream, which only exists in stateful (session-tracking) mode. This
  // server never issues a session id, so there is nothing for a GET to
  // attach to -- 405 says that plainly instead of the transport failing in
  // some less legible way.
  app.get("/mcp", async (_req, reply) => {
    return reply.status(405).send({
      error: "method_not_allowed",
      message: "GET /mcp is not supported; this server runs stateless with no SSE stream to attach to",
    });
  });
}
