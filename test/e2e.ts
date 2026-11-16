// End-to-end story, fully automated: the human side runs in headless Chromium with a virtual
// passkey authenticator; the agent side uses the same AgentClient the MCP server uses.
// It starts its own copies of all three services on ports 4500-4700 with a throwaway data dir.
//
//   npm run e2e            (add SCREENSHOTS=1 to save docs/screenshots/*.png)
import { spawn, type ChildProcess } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert/strict";
import { chromium, type Page } from "playwright";
import { SignJWT, generateKeyPair, exportJWK } from "jose";
import { randomUUID } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { createServer } from "node:http";

const IDP = "http://localhost:4500", MANDATE = "http://localhost:4600", STORE = "http://localhost:4700";
const tmp = mkdtempSync(join(tmpdir(), "agent-mandate-e2e-"));
const env = { ...process.env, IDP_URL: IDP, MANDATE_URL: MANDATE, STORE_URL: STORE, AGENT_MANDATE_DATA: join(tmp, "data"), AGENT_MANDATE_HOME: join(tmp, "agent") };
process.env.AGENT_MANDATE_HOME = env.AGENT_MANDATE_HOME;
const shots = process.env.SCREENSHOTS ? new URL("../docs/screenshots/", import.meta.url).pathname : null;
if (shots) mkdirSync(shots, { recursive: true });

const procs: ChildProcess[] = [];
for (const f of ["apps/mock-idme/server.ts", "apps/mandate/server.ts", "apps/store/server.ts"]) {
  const p = spawn(process.execPath, ["--no-warnings", f], { env, stdio: ["ignore", "ignore", "inherit"] });
  procs.push(p);
}
const cleanup = () => { procs.forEach((p) => p.kill()); rmSync(tmp, { recursive: true, force: true }); };
process.on("exit", cleanup);

async function up(url: string) {
  for (let i = 0; i < 50; i++) {
    try { if ((await fetch(url)).ok) return; } catch {}
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`${url} did not start`);
}
await Promise.all([up(`${IDP}/.well-known/openid-configuration`), up(`${MANDATE}/.well-known/jwks.json`), up(`${STORE}/api/products`)]);

const { AgentClient } = await import("../packages/agent/client.ts");
const agent = await AgentClient.load({ name: "Claude Desktop", issuers: [MANDATE] });

let step = 0;
const ok = (msg: string) => console.log(`  ✓ ${++step}. ${msg}`);
const shot = async (page: Page, name: string) => { if (shots) await page.screenshot({ path: join(shots, `${name}.png`), fullPage: true }); };

const browser = await chromium.launch();
const ctx = await browser.newContext({ viewport: { width: 900, height: 900 }, deviceScaleFactor: 2 });
const page = await ctx.newPage();
const cdp = await ctx.newCDPSession(page);
await cdp.send("WebAuthn.enable");
await cdp.send("WebAuthn.addVirtualAuthenticator", {
  options: { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
});

try {
  console.log("Agent mandates, end to end\n");

  // 1. The agent asks for a mandate.
  const req = await agent.requestMandate({ site: STORE, purpose: "Buy desk gear for your new apartment", maxTotalUsd: 150, perPurchaseUsd: 100, days: 7 });
  assert.match(req.approve_url, /\/approve\/mreq_/);
  ok(`agent asked for a $150 mandate and got an approval link`);

  // 2. The person signs in with (mock) ID.me, adds a passkey, reviews, and approves.
  await page.goto(req.approve_url);
  await page.waitForURL(`${IDP}/oauth/authorize**`);
  await shot(page, "1-idme-login");
  await page.click('button[data-persona="idme_test_jordan"]');
  await page.waitForURL(`${MANDATE}/passkey/setup**`);
  await page.click("#reg");
  await page.waitForURL(req.approve_url);
  await page.check('input[name=claim][value=veteran]');
  await shot(page, "2-consent");
  await page.click("#approve");
  await page.waitForURL(`${MANDATE}/?flash=granted`);
  ok("person signed in via ID.me, created a passkey, shared veteran status, and approved with the passkey");

  const rec = await agent.waitForMandate(STORE, 5000);
  assert.equal(rec.status, "approved");
  ok("agent sees the mandate is approved");

  // 3. The site sees a verified human, but no name.
  const who = await agent.fetch(`${STORE}/api/agent/whoami`);
  assert.equal(who.status, 200);
  assert.equal(who.body.claims.verified_human, true);
  assert.equal(who.body.claims.veteran, true);
  assert.match(who.body.subject, /^pw_/);
  assert.ok(!JSON.stringify(who.body).includes("Jordan"));
  ok(`store sees a verified veteran adult as ${who.body.subject}, with no name attached`);

  // 4. A normal purchase inside the limits.
  const kb = await agent.fetch(`${STORE}/api/agent/checkout`, { method: "POST", body: { items: [{ sku: "kb-mech" }] }, headers: { "idempotency-key": "order-1" } });
  assert.equal(kb.status, 201);
  assert.equal(kb.body.total_usd, 80.1);
  ok(`bought a keyboard for $${kb.body.total_usd} (veteran discount applied), $${kb.body.budget_remaining_usd} left`);

  const again = await agent.fetch(`${STORE}/api/agent/checkout`, { method: "POST", body: { items: [{ sku: "kb-mech" }] }, headers: { "idempotency-key": "order-1" } });
  assert.equal(again.status, 200);
  assert.equal(again.body.order_id, kb.body.order_id);
  ok("retrying with the same Idempotency-Key returns the same order and doesn't charge twice");

  // 5. Over the limit: step-up approval on the person's device.
  const hp = await agent.fetch(`${STORE}/api/agent/checkout`, { method: "POST", body: { items: [{ sku: "hp-anc" }] }, headers: { "idempotency-key": "order-2" } });
  assert.equal(hp.status, 402);
  assert.equal(hp.body.error, "step_up_required");
  ok(`$${hp.body.amount_usd} headphones → 402 step_up_required (${hp.body.reason})`);

  await page.goto(hp.body.approval_url);
  await shot(page, "3-step-up");
  await page.click("#approve");
  await page.waitForSelector("text=This purchase was approved");
  assert.equal(await agent.waitForApproval(STORE, hp.body.approval_id, 5000), "approved");
  const hp2 = await agent.fetch(`${STORE}/api/agent/checkout`, { method: "POST", body: { items: [{ sku: "hp-anc" }] }, headers: { "idempotency-key": "order-2", "agent-approval": hp.body.approval_id } });
  assert.equal(hp2.status, 201);
  ok("person approved that one purchase with the passkey; the agent's retry went through");

  const reuse = await agent.fetch(`${STORE}/api/agent/checkout`, { method: "POST", body: { items: [{ sku: "hp-anc" }] }, headers: { "idempotency-key": "order-3", "agent-approval": hp.body.approval_id } });
  assert.equal(reuse.status, 403);
  ok(`reusing that approval for a second pair is refused (${reuse.body.reason})`);

  // 6. Stolen-token attacks.
  const token = await agent.token(STORE);
  const url = `${STORE}/api/agent/whoami`;
  const noProof = await fetch(url, { headers: { authorization: `DPoP ${token}` } });
  assert.equal(noProof.status, 401);
  const { privateKey } = await generateKeyPair("ES256", { extractable: true });
  const { d, ...attackerJwk } = await exportJWK(privateKey);
  const forged = await new SignJWT({ htm: "GET", htu: url, ath: (await import("../packages/verifier/dpop.ts")).tokenHash(token) })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: attackerJwk }).setIssuedAt().setJti(randomUUID()).sign(privateKey);
  const wrongKey = await fetch(url, { headers: { authorization: `DPoP ${token}`, dpop: forged } });
  assert.equal(wrongKey.status, 401);
  assert.match((await wrongKey.json()).error_description, /different key/);
  const proof = await agent.proof("GET", url, token);
  assert.equal((await fetch(url, { headers: { authorization: `DPoP ${token}`, dpop: proof } })).status, 200);
  assert.equal((await fetch(url, { headers: { authorization: `DPoP ${token}`, dpop: proof } })).status, 401);
  const otherSite = await agent.proof("GET", `${MANDATE}/api/agent/whoami`, token);
  assert.equal((await fetch(url, { headers: { authorization: `DPoP ${token}`, dpop: otherSite } })).status, 401);
  ok("a stolen token fails without the agent's key, with an attacker's key, with a replayed proof, and with a proof made for another URL");

  // 7. The dashboard, the store's view, then revoke.
  await page.goto(`${MANDATE}/`);
  await shot(page, "4-dashboard");
  const storePage = await ctx.newPage();
  await storePage.goto(`${STORE}/`);
  await shot(storePage, "5-store-orders");
  await page.click(`[data-mandate="${rec.mandate_id}"] button.danger`);
  await page.waitForURL(`${MANDATE}/?flash=revoked`);
  await shot(page, "6-revoked");
  const after = await agent.fetch(`${STORE}/api/agent/checkout`, { method: "POST", body: { items: [{ sku: "cable-usbc" }] }, headers: { "idempotency-key": "order-4" } });
  assert.equal(after.status, 403);
  await assert.rejects(() => fetch(`${MANDATE}/api/token`).then(() => (agent as any).issuerCall("POST", `${MANDATE}/api/token`, { mandate_id: rec.mandate_id })), /revoked/);
  ok("after one click on Revoke, purchases are refused and no new tokens are issued");

  // 8. Edge cases: second agent, swapped cart, copied session cookie, login CSRF, look-alike issuer.
  const agent2 = await AgentClient.load({ home: join(tmp, "agent2"), name: "Shopping agent", issuers: [MANDATE] });
  const req2 = await agent2.requestMandate({ site: STORE, purpose: "Restock desk gear", maxTotalUsd: 100 });
  await page.goto(req2.approve_url);
  await page.click("#approve");
  await page.waitForURL(`${MANDATE}/?flash=granted`);
  await agent2.waitForMandate(STORE, 5000);
  const kb2 = await agent2.fetch(`${STORE}/api/agent/checkout`, { method: "POST", body: { items: [{ sku: "kb-mech" }] }, headers: { "idempotency-key": "order-1" } });
  assert.equal(kb2.status, 201);
  assert.notEqual(kb2.body.order_id, kb.body.order_id);
  ok("a second agent for the same person that reuses an Idempotency-Key gets its own order, not the first agent's");

  const twoKeyboards = { items: [{ sku: "kb-mech", qty: 2 }] }, samePriceOtherCart = { items: [{ sku: "cable-usbc", qty: 7 }, { sku: "lamp-desk" }] };
  const big = await agent2.fetch(`${STORE}/api/agent/checkout`, { method: "POST", body: twoKeyboards, headers: { "idempotency-key": "order-6" } });
  assert.equal(big.status, 402);
  await page.goto(big.body.approval_url);
  await page.click("#approve");
  await page.waitForSelector("text=This purchase was approved");
  const swapped = await agent2.fetch(`${STORE}/api/agent/checkout`, { method: "POST", body: samePriceOtherCart, headers: { "idempotency-key": "order-6", "agent-approval": big.body.approval_id } });
  assert.equal(swapped.status, 403);
  const asApproved = await agent2.fetch(`${STORE}/api/agent/checkout`, { method: "POST", body: twoKeyboards, headers: { "idempotency-key": "order-6", "agent-approval": big.body.approval_id } });
  assert.equal(asApproved.status, 201);
  ok(`an approval covers the cart the person saw: a different cart at the same $${big.body.amount_usd} is refused, the approved one goes through`);

  const db = new DatabaseSync(join(env.AGENT_MANDATE_DATA, "mandate.db"));
  const ageSessions = (seconds: number) => db.prepare("UPDATE sessions SET created_at = created_at - ?").run(seconds);
  const sessionCookie = (await ctx.cookies(MANDATE)).find((c) => c.name === "am_session")!.value;
  const asCopier = (path: string, method = "GET") => fetch(`${MANDATE}${path}`, { method, headers: { cookie: `am_session=${sessionCookie}` } });
  ageSessions(3600);
  assert.match(await (await asCopier("/")).text(), /Active mandates/);
  assert.equal((await asCopier("/webauthn/register/options", "POST")).status, 403);
  ageSessions(8 * 3600);
  assert.doesNotMatch(await (await asCopier("/")).text(), /Active mandates/);
  ok("a session cookie copied an hour after sign-in can see the dashboard but can't add a passkey, and stops working after 8 hours");

  const startLogin = async (returnTo = "/") => {
    const login = await fetch(`${MANDATE}/login?return_to=${encodeURIComponent(returnTo)}`, { redirect: "manual" });
    const authz = new URL(login.headers.get("location")!);
    const form = new URLSearchParams({ sub: "idme_test_casey" });
    for (const k of ["redirect_uri", "state", "nonce", "code_challenge"]) form.set(k, authz.searchParams.get(k) ?? "");
    const decided = await fetch(`${IDP}/oauth/authorize/decide`, { method: "POST", body: form, redirect: "manual" });
    return { callback: decided.headers.get("location")!, stateCookie: login.headers.get("set-cookie")!.split(";")[0] };
  };
  const elsewhere = await startLogin();
  assert.equal((await fetch(elsewhere.callback, { redirect: "manual" })).status, 400);
  const offsite = await startLogin("//evil.example/");
  const landed = await fetch(offsite.callback, { redirect: "manual", headers: { cookie: offsite.stateCookie } });
  assert.equal(landed.headers.get("location"), "/");
  const badRedirect = new URL(`${IDP}/oauth/authorize`);
  for (const [k, v] of Object.entries({ client_id: "agent-mandate-dev", response_type: "code", code_challenge: "x", code_challenge_method: "S256", redirect_uri: "https://evil.example/cb" }))
    badRedirect.searchParams.set(k, v);
  assert.equal((await fetch(badRedirect)).status, 400);
  ok("a sign-in started in one browser can't be finished in another, return_to can't leave the site, and codes only go to the registered redirect URI");

  const lookalike = createServer((_, res) => res.end(JSON.stringify({ name: "Fake shop", accepted_issuers: ["https://id-me-verify.example"], requested_claims: [] })));
  await new Promise<void>((r) => lookalike.listen(4800, r));
  await assert.rejects(() => agent.requestMandate({ site: "http://localhost:4800", purpose: "x", maxTotalUsd: 10 }), /only uses/);
  lookalike.close();
  ok("the agent only uses the issuer it was configured with, so a site can't get it to hand the person a look-alike sign-in link");

  console.log(`\nAll ${step} checks passed.${shots ? ` Screenshots in docs/screenshots/.` : ""}`);
} catch (e) {
  await shot(page, "failure");
  console.error("\nFAILED:", e);
  process.exitCode = 1;
} finally {
  await browser.close();
  cleanup();
  process.exit();
}
