// Machine-facing endpoints of the mandate service.
//   Agents authenticate with a DPoP proof signed by their own key (no passwords, no shared secrets).
//   Websites (relying parties) authenticate with an API key issued when they register.
import { Hono, type Context } from "hono";
import { SignJWT } from "jose";
import { APPROVAL_TTL_SECONDS, MANDATE_URL, TOKEN_TTL_SECONDS } from "../../shared/config.ts";
import { sha256hex } from "../../shared/crypto.ts";
import { now, tx } from "../../shared/db.ts";
import { DpopError, verifyDpopProof, DPOP_ALGS } from "../../packages/verifier/dpop.ts";
import {
  audit, autoSpentCents, db, getMandate, liveStatus, newId, pairwiseSub, replay, signingKey, type MandateRow,
} from "./context.ts";

export const api = new Hono();

const agentIdFor = (jkt: string) => `agent_${jkt.slice(0, 16)}`;

/** Verify the caller's DPoP proof for this exact request and return its key thumbprint. */
async function agentKey(c: Context) {
  const url = `${MANDATE_URL}${new URL(c.req.url).pathname}`;
  return verifyDpopProof(c.req.header("dpop"), { method: c.req.method, url, replay });
}

function dpopFailure(c: Context, e: unknown) {
  if (!(e instanceof DpopError)) throw e;
  c.header("WWW-Authenticate", `DPoP error="invalid_dpop_proof", algs="${DPOP_ALGS.join(" ")}"`);
  return c.json({ error: "invalid_dpop_proof", error_description: e.message }, 401);
}

type RP = { origin: string; name: string; requested_claims: string; optional_claims: string };
function relyingParty(c: Context): RP | undefined {
  const key = c.req.header("authorization")?.replace(/^Bearer /, "");
  if (!key) return undefined;
  return db.prepare("SELECT * FROM relying_parties WHERE api_key_hash = ?").get(sha256hex(key)) as RP | undefined;
}

// ---------- discovery ----------

api.get("/.well-known/agent-mandate", (c) =>
  c.json({
    issuer: MANDATE_URL,
    jwks_uri: `${MANDATE_URL}/.well-known/jwks.json`,
    mandate_request_endpoint: `${MANDATE_URL}/api/mandate-requests`,
    token_endpoint: `${MANDATE_URL}/api/token`,
    transaction_authorize_endpoint: `${MANDATE_URL}/api/transactions/authorize`,
    token_type: "mandate+jwt",
    dpop_signing_alg_values_supported: DPOP_ALGS,
    claims_supported: ["verified_human", "over_18", "over_21", "veteran", "student"],
  }),
);

api.get("/.well-known/jwks.json", (c) => c.json({ keys: [signingKey.publicJwk] }));

// ---------- agent endpoints ----------

// An agent asks a person for a mandate. The person approves it in the portal.
api.post("/api/mandate-requests", async (c) => {
  let proof;
  try { proof = await agentKey(c); } catch (e) { return dpopFailure(c, e); }
  const b = await c.req.json().catch(() => ({}));
  let audience = "";
  try { audience = typeof b.audience === "string" ? new URL(b.audience).origin : ""; } catch {}
  const rp = db.prepare("SELECT origin FROM relying_parties WHERE origin = ?").get(audience);
  if (!rp) return c.json({ error: "unknown_audience", error_description: `${audience || "audience"} is not a registered site` }, 400);
  const maxTotal = Number(b.max_total_usd), perPurchase = Number(b.per_purchase_limit_usd ?? b.max_total_usd), days = Number(b.days ?? 7);
  if (!(maxTotal > 0 && maxTotal <= 10_000) || !(perPurchase > 0 && perPurchase <= maxTotal) || !(days >= 1 && days <= 90))
    return c.json({ error: "invalid_request", error_description: "need 0 < per_purchase_limit_usd <= max_total_usd <= 10000 and 1 <= days <= 90" }, 400);

  const name = String(b.agent_name ?? "AI agent").slice(0, 60);
  // A key keeps the name it first asked with, so an agent can't rename itself after a person approved it.
  db.prepare("INSERT INTO agents (jkt, jwk_json, name, created_at) VALUES (?, ?, ?, ?) ON CONFLICT(jkt) DO NOTHING")
    .run(proof.jkt, JSON.stringify(proof.jwk), name, now());
  const id = newId("mreq");
  const proposal = { max_total_usd: maxTotal, per_purchase_limit_usd: perPurchase, days };
  db.prepare("INSERT INTO mandate_requests (id, agent_jkt, audience, purpose, proposal_json, status, created_at) VALUES (?, ?, ?, ?, ?, 'pending', ?)")
    .run(id, proof.jkt, audience, String(b.purpose ?? "").slice(0, 200), JSON.stringify(proposal), now());
  return c.json({ request_id: id, status: "pending", approve_url: `${MANDATE_URL}/approve/${id}`, poll_url: `${MANDATE_URL}/api/mandate-requests/${id}` }, 201);
});

api.get("/api/mandate-requests/:id", async (c) => {
  let proof;
  try { proof = await agentKey(c); } catch (e) { return dpopFailure(c, e); }
  const r = db.prepare("SELECT * FROM mandate_requests WHERE id = ? AND agent_jkt = ?").get(c.req.param("id"), proof.jkt) as
    | { id: string; status: string; mandate_id: string | null; audience: string } | undefined;
  if (!r) return c.json({ error: "not_found" }, 404);
  const m = r.mandate_id ? getMandate(r.mandate_id) : undefined;
  return c.json({ request_id: r.id, status: r.status, mandate_id: r.mandate_id, audience: r.audience, expires_at: m?.expires_at });
});

// Exchange a live mandate for a short-lived token bound to the agent's key.
api.post("/api/token", async (c) => {
  let proof;
  try { proof = await agentKey(c); } catch (e) { return dpopFailure(c, e); }
  const b = await c.req.json().catch(() => ({}));
  const m = getMandate(String(b.mandate_id ?? ""));
  if (!m || m.agent_jkt !== proof.jkt) return c.json({ error: "invalid_grant", error_description: "no such mandate for this agent key" }, 400);
  const status = liveStatus(m);
  if (status !== "active") return c.json({ error: "invalid_grant", error_description: `mandate is ${status}` }, 400);

  const agent = db.prepare("SELECT name FROM agents WHERE jkt = ?").get(m.agent_jkt) as { name: string };
  const exp = Math.min(now() + TOKEN_TTL_SECONDS, m.expires_at);
  const token = await new SignJWT({
    act: { sub: agentIdFor(m.agent_jkt), name: agent.name },
    claims: JSON.parse(m.claims_json),
    authorization_details: [{ type: "purchase", max_total_usd: m.max_total_cents / 100, per_purchase_limit_usd: m.per_purchase_cents / 100 }],
    mandate_id: m.id,
    cnf: { jkt: m.agent_jkt },
  })
    .setProtectedHeader({ alg: "ES256", kid: signingKey.kid, typ: "mandate+jwt" })
    .setIssuer(MANDATE_URL)
    .setAudience(m.audience)
    .setSubject(pairwiseSub(m.user_id, m.audience))
    .setIssuedAt()
    .setExpirationTime(exp)
    .setJti(newId("tok"))
    .sign(signingKey.privateKey);
  return c.json({ access_token: token, token_type: "DPoP", expires_in: exp - now() });
});

api.get("/api/approvals/:id", async (c) => {
  let proof;
  try { proof = await agentKey(c); } catch (e) { return dpopFailure(c, e); }
  const a = db.prepare("SELECT a.id, a.status FROM approvals a JOIN mandates m ON m.id = a.mandate_id WHERE a.id = ? AND m.agent_jkt = ?")
    .get(c.req.param("id"), proof.jkt) as { id: string; status: string } | undefined;
  if (!a) return c.json({ error: "not_found" }, 404);
  return c.json({ approval_id: a.id, status: a.status });
});

// ---------- relying-party endpoints ----------

// The one online check: debit the spend ledger atomically, or ask the person to step up.
api.post("/api/transactions/authorize", async (c) => {
  const rp = relyingParty(c);
  if (!rp) return c.json({ error: "invalid_client" }, 401);
  const b = await c.req.json().catch(() => ({}));
  const m = getMandate(String(b.mandate_id ?? ""));
  if (!m || m.audience !== rp.origin) return c.json({ status: "denied", reason: "unknown mandate" }, 403);
  const amount = Math.round(Number(b.amount_usd) * 100);
  const description = String(b.description ?? "").slice(0, 200);
  const reference = String(b.reference ?? "");
  if (!(amount > 0) || !reference) return c.json({ error: "invalid_request", error_description: "amount_usd and reference are required" }, 400);

  const result = tx(db, () => decide(m, amount, description, reference, b.approval_id ? String(b.approval_id) : undefined));
  if (result.status === "approved" && !result.replayed)
    audit("purchase", { amount_cents: amount, description, site: rp.name, approval_id: result.approval_id ?? null }, { userId: m.user_id, mandateId: m.id });
  if (result.status === "step_up_required" && result.created)
    audit("step_up_requested", { amount_cents: amount, description, reason: result.reason }, { userId: m.user_id, mandateId: m.id });
  if (result.status === "denied") audit("purchase_denied", { amount_cents: amount, description, reason: result.reason }, { userId: m.user_id, mandateId: m.id });

  const code = result.status === "approved" ? 200 : result.status === "step_up_required" ? 402 : 403;
  const { created: _c, approval_id: _a, replayed: _r, ...body } = result as Record<string, unknown>;
  if (result.status === "step_up_required") body.approval_id = result.approval_id;
  return c.json(body, code);
});

type Decision =
  | { status: "approved"; transaction_id: string; remaining_usd: number; approval_id?: string; replayed?: boolean }
  | { status: "step_up_required"; approval_id: string; approval_url: string; reason: string; created: boolean }
  | { status: "denied"; reason: string };

function decide(m: MandateRow, amount: number, description: string, reference: string, approvalId?: string): Decision {
  const remaining = () => (m.max_total_cents - autoSpentCents(m.id)) / 100;
  const status = liveStatus(m);
  if (status !== "active") return { status: "denied", reason: `mandate is ${status}` };

  // Idempotent retry: the same reference never charges twice.
  const prior = db.prepare("SELECT id, amount_cents, description FROM ledger WHERE mandate_id = ? AND reference = ?").get(m.id, reference) as
    | { id: string; amount_cents: number; description: string } | undefined;
  if (prior) {
    if (prior.amount_cents !== amount || prior.description !== description) return { status: "denied", reason: "reference reused for a different purchase" };
    return { status: "approved", transaction_id: prior.id, remaining_usd: remaining(), replayed: true };
  }

  if (approvalId) {
    const a = db.prepare("SELECT * FROM approvals WHERE id = ? AND mandate_id = ?").get(approvalId, m.id) as
      | { id: string; amount_cents: number; description: string; reference: string; status: string; created_at: number } | undefined;
    // The approval covers one exact purchase: the amount and description the person saw, the same reference, used once, within a day.
    if (!a || a.amount_cents !== amount || a.description !== description || a.reference !== reference)
      return { status: "denied", reason: "approval does not match this purchase" };
    if (a.status !== "approved") return { status: "denied", reason: `approval is ${a.status}` };
    if (a.created_at < now() - APPROVAL_TTL_SECONDS) return { status: "denied", reason: "approval expired" };
    const id = newId("txn");
    db.prepare("INSERT INTO ledger (id, mandate_id, amount_cents, description, reference, approval_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .run(id, m.id, amount, description, reference, a.id, now());
    db.prepare("UPDATE approvals SET status = 'used', used_at = ? WHERE id = ?").run(now(), a.id);
    return { status: "approved", transaction_id: id, remaining_usd: remaining(), approval_id: a.id };
  }

  const left = m.max_total_cents - autoSpentCents(m.id);
  const reason =
    amount > m.per_purchase_cents ? `over the ${m.per_purchase_cents / 100} USD per-purchase limit`
    : amount > left ? `over the remaining ${left / 100} USD of the ${m.max_total_cents / 100} USD budget`
    : null;
  if (reason) {
    const existing = db.prepare("SELECT id FROM approvals WHERE mandate_id = ? AND reference = ? AND amount_cents = ? AND description = ? AND status = 'pending' AND created_at >= ?")
      .get(m.id, reference, amount, description, now() - APPROVAL_TTL_SECONDS) as { id: string } | undefined;
    const id = existing?.id ?? newId("appr");
    if (!existing)
      db.prepare("INSERT INTO approvals (id, mandate_id, amount_cents, description, reference, reason, status, created_at) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)")
        .run(id, m.id, amount, description, reference, reason, now());
    return { status: "step_up_required", approval_id: id, approval_url: `${MANDATE_URL}/approvals/${id}`, reason, created: !existing };
  }

  const id = newId("txn");
  db.prepare("INSERT INTO ledger (id, mandate_id, amount_cents, description, reference, approval_id, created_at) VALUES (?, ?, ?, ?, ?, NULL, ?)")
    .run(id, m.id, amount, description, reference, now());
  return { status: "approved", transaction_id: id, remaining_usd: remaining() };
}

api.get("/api/mandates/:id/status", (c) => {
  const rp = relyingParty(c);
  if (!rp) return c.json({ error: "invalid_client" }, 401);
  const m = getMandate(c.req.param("id"));
  if (!m || m.audience !== rp.origin) return c.json({ error: "not_found" }, 404);
  return c.json({ mandate_id: m.id, status: liveStatus(m), expires_at: m.expires_at });
});
