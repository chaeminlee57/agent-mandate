// Demo Store: a fake shop (a "relying party") that lets AI agents buy on a person's behalf,
// using the verifier package. This is what any website would add to accept agent mandates.
import { Hono } from "hono";
import { serve } from "@hono/node-server";
import { html } from "hono/html";
import { DATA_DIR, DEMO_STORE_API_KEY, MANDATE_URL, STORE_URL, port } from "../../shared/config.ts";
import { randomId } from "../../shared/crypto.ts";
import { now, openDb } from "../../shared/db.ts";
import { ago, page, THEMES, usd } from "../../shared/ui.ts";
import { agentMandate, authorizeTransaction, createVerifier, type AgentMandate } from "../../packages/verifier/index.ts";

const PRODUCTS = [
  { sku: "cable-usbc", name: "USB-C cable, 2 m", price_cents: 1900 },
  { sku: "lamp-desk", name: "Desk lamp", price_cents: 4500 },
  { sku: "kb-mech", name: "Mechanical keyboard", price_cents: 8900 },
  { sku: "hp-anc", name: "Noise-cancelling headphones", price_cents: 34900 },
];
const VETERAN_DISCOUNT = 0.1;

const db = openDb(DATA_DIR, "store.db", `
CREATE TABLE IF NOT EXISTS orders (
  id TEXT PRIMARY KEY, reference TEXT UNIQUE NOT NULL, mandate_id TEXT NOT NULL, subject TEXT NOT NULL, agent_name TEXT NOT NULL,
  claims_json TEXT NOT NULL, items_json TEXT NOT NULL, total_cents INTEGER NOT NULL, discount_cents INTEGER NOT NULL,
  approval_id TEXT, created_at INTEGER NOT NULL);`);

const verifier = createVerifier({ issuer: MANDATE_URL, audience: STORE_URL, publicOrigin: STORE_URL });
const app = new Hono<{ Variables: { agentMandate: AgentMandate } }>();

// Agents discover what this site needs before asking a person for a mandate.
app.get("/.well-known/agent-access", (c) =>
  c.json({
    site: STORE_URL,
    name: "Demo Store",
    accepted_issuers: [MANDATE_URL],
    requested_claims: ["verified_human", "over_18"],
    optional_claims: { veteran: `${VETERAN_DISCOUNT * 100}% veteran discount`, student: "no effect" },
    endpoints: { products: `${STORE_URL}/api/products`, checkout: `${STORE_URL}/api/agent/checkout`, whoami: `${STORE_URL}/api/agent/whoami` },
  }),
);

app.get("/api/products", (c) => c.json({ products: PRODUCTS.map((p) => ({ ...p, price_usd: p.price_cents / 100 })) }));

app.use("/api/agent/*", agentMandate(verifier));

app.get("/api/agent/whoami", (c) => {
  const m = c.get("agentMandate");
  return c.json({ subject: m.subject, agent: m.agent, claims: m.claims, limits: m.authorization, token_expires_at: m.expiresAt });
});

app.post("/api/agent/checkout", async (c) => {
  const m = c.get("agentMandate");
  const idempotencyKey = c.req.header("idempotency-key");
  if (!idempotencyKey) return c.json({ error: "invalid_request", error_description: "send an Idempotency-Key header and reuse it on retries" }, 400);
  const body = await c.req.json().catch(() => ({}));
  const items = (Array.isArray(body.items) ? body.items : []).map((i: { sku: string; qty?: number }) => ({
    product: PRODUCTS.find((p) => p.sku === i.sku), qty: Math.max(1, Math.min(10, Number(i.qty ?? 1))),
  }));
  if (!items.length || items.some((i: { product?: unknown }) => !i.product)) return c.json({ error: "invalid_request", error_description: "unknown or empty items" }, 400);
  if (!m.claims.verified_human || !m.claims.over_18) return c.json({ error: "insufficient_claims", error_description: "this store needs a verified adult" }, 403);

  const subtotal = items.reduce((s: number, i: any) => s + i.product.price_cents * i.qty, 0);
  const discount = m.claims.veteran ? Math.round(subtotal * VETERAN_DISCOUNT) : 0;
  const total = subtotal - discount;
  const description = items.map((i: any) => `${i.qty > 1 ? `${i.qty} × ` : ""}${i.product.name}`).join(", ");
  // Scoped to the mandate, like the issuer's ledger: two agents working for the same person must not share keys.
  const reference = `order:${m.mandateId}:${idempotencyKey}`;

  const prior = db.prepare("SELECT * FROM orders WHERE reference = ?").get(reference) as { id: string } | undefined;
  const txn = await authorizeTransaction(MANDATE_URL, DEMO_STORE_API_KEY, {
    mandate_id: m.mandateId, amount_usd: total / 100, description, reference, approval_id: c.req.header("agent-approval") || undefined,
  });

  if (txn.status === "step_up_required") {
    c.header("WWW-Authenticate", `AgentMandate error="step_up_required", approval_id="${txn.approval_id}", approval_url="${txn.approval_url}"`);
    return c.json({
      error: "step_up_required", reason: txn.reason, approval_id: txn.approval_id, approval_url: txn.approval_url, amount_usd: total / 100,
      next: "Ask the person to approve at approval_url, then repeat this request with the same Idempotency-Key and the header Agent-Approval: <approval_id>.",
    }, 402);
  }
  if (txn.status === "denied") return c.json({ error: "mandate_denied", reason: txn.reason }, 403);

  // Two retries racing each other both get here; only one inserts, and both answer with that order.
  const newId = randomId("ord", 8);
  if (!prior)
    db.prepare(`INSERT INTO orders (id, reference, mandate_id, subject, agent_name, claims_json, items_json, total_cents, discount_cents, approval_id, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(reference) DO NOTHING`)
      .run(newId, reference, m.mandateId, m.subject, m.agent.name, JSON.stringify(m.claims),
        JSON.stringify(items.map((i: any) => ({ sku: i.product.sku, qty: i.qty }))), total, discount, c.req.header("agent-approval") || null, now());
  const orderId = (db.prepare("SELECT id FROM orders WHERE reference = ?").get(reference) as { id: string }).id;
  return c.json({
    order_id: orderId, description, subtotal_usd: subtotal / 100, discount_usd: discount / 100, total_usd: total / 100,
    discount_reason: discount ? "veteran (verified by ID.me)" : null, budget_remaining_usd: txn.remaining_usd,
  }, orderId === newId ? 201 : 200);
});

// The human view of the shop: products, and what agents have bought here.
app.get("/", (c) => {
  const orders = db.prepare("SELECT * FROM orders ORDER BY created_at DESC LIMIT 20").all() as any[];
  return c.html(page(THEMES.store, "Shop", html`
    <h1>Demo Store</h1>
    <p class="muted">Agents can shop here if a verified adult stands behind them. Verified veterans get ${VETERAN_DISCOUNT * 100}% off.</p>
    ${PRODUCTS.map((p) => html`<div class="row"><span>${p.name}</span><span>${usd(p.price_cents)}</span></div>`)}
    <h2>Orders placed by agents</h2>
    ${orders.length ? orders.map((o) => {
      const claims = Object.keys(JSON.parse(o.claims_json));
      return html`<div class="panel" data-order="${o.id}">
        <div class="row"><strong>${usd(o.total_cents)}</strong><span class="small muted">${ago(o.created_at)}</span></div>
        <div class="small">Placed by ${o.agent_name} for customer <span class="mono">${o.subject}</span></div>
        <div class="small muted">Verified: ${claims.join(", ")}${o.discount_cents ? html` · veteran discount ${usd(o.discount_cents)}` : ""}${o.approval_id ? " · approved by the customer one time" : ""}</div>
      </div>`;
    }) : html`<p class="muted">No agent orders yet.</p>`}
    <p class="small muted">The store never learns the customer's name. It sees a verified yes or no for each fact, plus an ID that's only valid here.</p>`));
});

serve({ fetch: app.fetch, port: port(STORE_URL) }, () => console.log(`demo store     ${STORE_URL}`));
