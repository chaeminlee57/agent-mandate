// MCP server that gives any MCP-capable agent (Claude Desktop, Claude Code, ...) a verified human
// behind it. The private key lives in ~/.agent-mandate/agent.json and never leaves this machine.
//
// Tools:
//   request_mandate    ask the person for a scoped, revocable mandate at a site
//   check_mandate      see whether they approved it (or wait for them)
//   agent_fetch        call the site as this agent; a token and DPoP proof are attached for you
//   wait_for_approval  after a 402 step_up_required, wait while the person approves one purchase
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { AgentClient } from "../agent/client.ts";

const agent = await AgentClient.load();
const server = new McpServer({ name: "agent-mandate", version: "0.1.0" });
const text = (t: string) => ({ content: [{ type: "text" as const, text: t }] });
const fail = (e: unknown) => ({ ...text(`Error: ${(e as Error).message}`), isError: true });

server.registerTool(
  "request_mandate",
  {
    title: "Request a mandate",
    description:
      "Ask the user for permission to act for them at a website, with a spending budget. Returns a link the user must open to " +
      "sign in with ID.me and approve with a passkey. Share the link with the user, then call check_mandate.",
    inputSchema: {
      site: z.string().describe("Website origin, e.g. http://localhost:4200"),
      purpose: z.string().describe("One sentence the user will see explaining why you need this"),
      max_total_usd: z.number().positive().describe("Total budget you're asking for"),
      per_purchase_limit_usd: z.number().positive().optional().describe("Largest single purchase without asking again"),
      days: z.number().int().min(1).max(90).optional().describe("How long the mandate should last (default 7)"),
    },
  },
  async (a) => {
    try {
      const r = await agent.requestMandate({ site: a.site, purpose: a.purpose, maxTotalUsd: a.max_total_usd, perPurchaseUsd: a.per_purchase_limit_usd, days: a.days });
      return text(
        `Ask the user to open this link and approve: ${r.approve_url}\n` +
        `${r.site.name} will learn: ${r.site.requested_claims.join(", ")} (optional: ${Object.keys(r.site.optional_claims ?? {}).join(", ") || "none"}).\n` +
        `Agent key fingerprint the user will see: ${agent.keyFingerprint}`,
      );
    } catch (e) { return fail(e); }
  },
);

server.registerTool(
  "check_mandate",
  {
    title: "Check a mandate",
    description: "Check whether the user approved the mandate for a site. Set wait_seconds to wait for them.",
    inputSchema: { site: z.string(), wait_seconds: z.number().int().min(0).max(300).optional() },
  },
  async (a) => {
    try {
      const rec = a.wait_seconds ? await agent.waitForMandate(a.site, a.wait_seconds * 1000) : await agent.refresh(a.site);
      return text(`Mandate for ${rec.site}: ${rec.status}${rec.mandate_id ? ` (${rec.mandate_id})` : ""}`);
    } catch (e) { return fail(e); }
  },
);

server.registerTool(
  "agent_fetch",
  {
    title: "Call a site as a verified agent",
    description:
      "Make an HTTP request to a site you hold a mandate for. Authentication is attached automatically. For purchases, pass a " +
      "stable idempotency_key and reuse it if you retry. If the response is 402 step_up_required, give the user the approval_url, " +
      "call wait_for_approval, then repeat the same request with approval_id set.",
    inputSchema: {
      url: z.string(),
      method: z.enum(["GET", "POST", "PUT", "DELETE"]).optional(),
      body: z.record(z.string(), z.any()).optional(),
      idempotency_key: z.string().optional(),
      approval_id: z.string().optional(),
    },
  },
  async (a) => {
    try {
      const headers: Record<string, string> = {};
      if (a.idempotency_key) headers["idempotency-key"] = a.idempotency_key;
      if (a.approval_id) headers["agent-approval"] = a.approval_id;
      const r = await agent.fetch(a.url, { method: a.method, body: a.body, headers });
      return text(`HTTP ${r.status}\n${JSON.stringify(r.body, null, 2)}`);
    } catch (e) { return fail(e); }
  },
);

server.registerTool(
  "wait_for_approval",
  {
    title: "Wait for a one-time approval",
    description: "After a 402 step_up_required, wait until the user approves or denies that one purchase.",
    inputSchema: { site: z.string(), approval_id: z.string(), wait_seconds: z.number().int().min(1).max(300).optional() },
  },
  async (a) => {
    try {
      return text(`Approval ${a.approval_id}: ${await agent.waitForApproval(a.site, a.approval_id, (a.wait_seconds ?? 120) * 1000)}`);
    } catch (e) { return fail(e); }
  },
);

await server.connect(new StdioServerTransport());
