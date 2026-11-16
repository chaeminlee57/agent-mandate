// Human-facing side of the mandate service: sign in with ID.me, register a passkey, approve or
// deny an agent's request, approve one-off purchases over the limit, and watch or revoke mandates.
import { Hono, type Context } from "hono";
import { getCookie, setCookie, deleteCookie } from "hono/cookie";
import { html, raw } from "hono/html";
import { readFileSync } from "node:fs";
import { createRemoteJWKSet, jwtVerify } from "jose";
import {
  generateAuthenticationOptions, generateRegistrationOptions, verifyAuthenticationResponse, verifyRegistrationResponse,
} from "@simplewebauthn/server";
import { APPROVAL_TTL_SECONDS, MANDATE_URL, OIDC } from "../../shared/config.ts";
import { b64url, randomId, sha256b64url } from "../../shared/crypto.ts";
import { now, tx } from "../../shared/db.ts";
import { ago, page, THEMES, usd } from "../../shared/ui.ts";
import {
  audit, autoSpentCents, availableClaims, db, getMandate, liveStatus, newId, totalSpentCents, type Attributes, type MandateRow, type User,
} from "./context.ts";

export const portal = new Hono();
const T = THEMES.mandate;
const rpID = new URL(MANDATE_URL).hostname;
const idpKeys = createRemoteJWKSet(new URL(OIDC.jwksUrl));
const webauthnJs = readFileSync(new URL("../../node_modules/@simplewebauthn/browser/dist/bundle/index.umd.min.js", import.meta.url), "utf8");
const CLAIM_LABELS: Record<string, string> = {
  verified_human: "Is a real, ID-verified person", over_18: "Is over 18", over_21: "Is over 21", veteran: "Is a U.S. veteran", student: "Is a student",
};

// ---------- sessions ----------

const SESSION_SECONDS = 8 * 3600;
// Adding a passkey needs an ID.me sign-in this recent, so a session cookie copied later can't enroll the copier's own passkey.
const PASSKEY_ENROLL_SECONDS = 600;

/** Only paths on this site: "/approve/x" yes; "//evil.example", "/\evil.example", "https://...", or anything with spaces or quotes no. */
const safeReturnTo = (v: string | undefined) => (v && /^\/(?![/\\])[^\x00-\x20<>"'\\]*$/.test(v) ? v : "/");

type Session = { sid: string; user: User; attrs: Attributes; hasPasskey: boolean; signedInAt: number };
function session(c: Context): Session | undefined {
  const sid = getCookie(c, "am_session");
  if (!sid) return undefined;
  const row = db.prepare("SELECT u.*, s.created_at AS signed_in_at FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id = ? AND s.created_at > ?")
    .get(sid, now() - SESSION_SECONDS) as (User & { signed_in_at: number }) | undefined;
  if (!row) return undefined;
  const { signed_in_at, ...user } = row;
  const hasPasskey = !!db.prepare("SELECT 1 FROM passkeys WHERE user_id = ?").get(user.id);
  return { sid, user, attrs: JSON.parse(user.attributes_json), hasPasskey, signedInAt: signed_in_at };
}
const canEnrollPasskey = (s: Session) => s.signedInAt > now() - PASSKEY_ENROLL_SECONDS;

/** Pages that need a verified sign-in and a passkey send the person through both first. */
function requireUser(c: Context): Session | Response {
  const s = session(c);
  const here = new URL(c.req.url).pathname;
  if (!s) return c.redirect(`/login?return_to=${encodeURIComponent(here)}`);
  if (!s.hasPasskey) return c.redirect(`/passkey/setup?return_to=${encodeURIComponent(here)}`);
  return s;
}

const signedInBar = (s?: Session) =>
  s ? html`<form method="post" action="/logout" style="display:inline"><span class="note">${s.user.name}</span> <button class="ghost" style="padding:4px 10px;font-size:13px">Sign out</button></form>` : "";

portal.get("/static/webauthn.js", (c) => c.body(webauthnJs, 200, { "content-type": "text/javascript" }));

// ---------- sign in with ID.me (OIDC authorization code + PKCE) ----------

portal.get("/login", (c) => {
  const state = randomId("st"), verifier = b64url(crypto.getRandomValues(new Uint8Array(32))), nonce = randomId("n");
  const returnTo = safeReturnTo(c.req.query("return_to"));
  db.prepare("INSERT INTO oidc_states (state, verifier, nonce, return_to, created_at) VALUES (?, ?, ?, ?, ?)").run(state, verifier, nonce, returnTo, now());
  // Bind this sign-in to this browser, so a callback URL made in someone else's browser can't sign this one in (login CSRF).
  setCookie(c, "am_oidc_state", state, { httpOnly: true, sameSite: "Lax", path: "/oauth/callback", maxAge: 600 });
  const u = new URL(OIDC.authorizeUrl);
  for (const [k, v] of Object.entries({
    client_id: OIDC.clientId, redirect_uri: OIDC.redirectUri, response_type: "code", scope: OIDC.scope,
    state, nonce, code_challenge: sha256b64url(verifier), code_challenge_method: "S256",
    // Ask the identity provider to re-authenticate the person if their own session is older than this, and report when they did.
    max_age: String(PASSKEY_ENROLL_SECONDS),
  })) u.searchParams.set(k, v);
  return c.redirect(u.toString());
});

portal.get("/oauth/callback", async (c) => {
  const { code, state } = c.req.query();
  const browserState = getCookie(c, "am_oidc_state");
  deleteCookie(c, "am_oidc_state", { path: "/oauth/callback" });
  const st = db.prepare("SELECT * FROM oidc_states WHERE state = ? AND created_at >= ?").get(state ?? "", now() - 600) as
    | { verifier: string; nonce: string; return_to: string; created_at: number } | undefined;
  db.prepare("DELETE FROM oidc_states WHERE state = ? OR created_at < ?").run(state ?? "", now() - 600);
  if (!st || !code || browserState !== state) return c.text("Sign-in expired. Start again.", 400);

  const tokenRes = await fetch(OIDC.tokenUrl, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code", code, redirect_uri: OIDC.redirectUri,
      client_id: OIDC.clientId, client_secret: OIDC.clientSecret, code_verifier: st.verifier,
    }),
  });
  if (!tokenRes.ok) return c.text(`Identity provider refused the code: ${await tokenRes.text()}`, 502);
  const tokens = (await tokenRes.json()) as { access_token: string; id_token: string };
  const { payload } = await jwtVerify(tokens.id_token, idpKeys, { issuer: OIDC.issuer, audience: OIDC.clientId });
  if (payload.nonce !== st.nonce) return c.text("nonce mismatch", 400);

  const attrsRes = await fetch(OIDC.attributesUrl, { headers: { authorization: `Bearer ${tokens.access_token}` } });
  if (!attrsRes.ok) return c.text(`Identity provider refused the attributes request (${attrsRes.status}).`, 502);
  const raw =(await attrsRes.json()) as { attributes: { handle: string; value: string }[]; status: { group: string; subgroups?: string[]; verified: boolean }[] };
  const attr = (h: string) => raw.attributes.find((a) => a.handle === h)?.value;
  const attrs: Attributes = {
    verified: !!raw.status.find((s) => s.group === "identity")?.verified,
    birth_date: attr("birth_date"),
    groups: raw.status.filter((s) => s.verified).flatMap((s) =>
      s.group === "military" && s.subgroups?.some((g) => /veteran/i.test(g)) ? ["veteran"] : s.group === "student" ? ["student"] : []),
  };
  const name = [attr("fname"), attr("lname")].filter(Boolean).join(" ") || "ID.me member";
  const existing = db.prepare("SELECT id FROM users WHERE idp_sub = ?").get(String(payload.sub)) as { id: string } | undefined;
  const userId = existing?.id ?? newId("usr");
  db.prepare(`INSERT INTO users (id, idp_sub, name, email, attributes_json, created_at) VALUES (?, ?, ?, ?, ?, ?)
              ON CONFLICT(idp_sub) DO UPDATE SET name = excluded.name, email = excluded.email, attributes_json = excluded.attributes_json`)
    .run(userId, String(payload.sub), name, attr("email") ?? null, JSON.stringify(attrs), now());
  // The session counts from when the identity provider last authenticated the person (auth_time), not from this redirect.
  // An ID.me session that is still open could otherwise make an old sign-in look new. Without auth_time, fall back to now.
  const authTime = typeof payload.auth_time === "number" && payload.auth_time <= now() + 60 ? payload.auth_time : now();
  const sid = randomId("ses", 24);
  db.prepare("INSERT INTO sessions (id, user_id, created_at) VALUES (?, ?, ?)").run(sid, userId, authTime);
  setCookie(c, "am_session", sid, { httpOnly: true, sameSite: "Lax", path: "/", maxAge: SESSION_SECONDS });
  audit("signed_in", { via: "ID.me", verified: attrs.verified }, { userId });
  return c.redirect(st.return_to);
});

portal.post("/logout", (c) => {
  const sid = getCookie(c, "am_session");
  if (sid) db.prepare("DELETE FROM sessions WHERE id = ?").run(sid);
  deleteCookie(c, "am_session", { path: "/" });
  return c.redirect("/");
});

// ---------- passkeys ----------

portal.get("/passkey/setup", (c) => {
  const s = session(c);
  const returnTo = safeReturnTo(c.req.query("return_to"));
  // No session, or a sign-in too old to add a passkey: sign in with ID.me again, then come back.
  if (!s || !canEnrollPasskey(s)) return c.redirect(`/login?return_to=${encodeURIComponent(returnTo)}`);
  return c.html(page(T, "Add a passkey", html`
    <h1>Add a passkey</h1>
    <p>Agents can ask, but only you can say yes. Every approval in this portal is signed with a passkey on this device, like Face ID or Touch ID, so a stolen session cookie can't approve anything.</p>
    <div class="actions"><button id="reg">Create passkey</button></div><p class="err" id="err"></p>
    <script>
      document.getElementById('reg').onclick = async () => {
        try {
          const opts = await (await fetch('/webauthn/register/options', { method: 'POST' })).json();
          const att = await SimpleWebAuthnBrowser.startRegistration({ optionsJSON: opts });
          const r = await (await fetch('/webauthn/register/verify', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(att) })).json();
          if (!r.ok) throw new Error(r.error || 'could not save passkey');
          location.href = ${raw(JSON.stringify(returnTo).replace(/</g, "\\u003c"))};
        } catch (e) { document.getElementById('err').textContent = e.message; }
      };
    </script>`, { right: signedInBar(s), scripts: ["/static/webauthn.js"] }));
});

function saveChallenge(sid: string, purpose: string, challenge: string) {
  db.prepare("INSERT INTO webauthn_challenges (session_id, purpose, challenge, created_at) VALUES (?, ?, ?, ?) ON CONFLICT(session_id, purpose) DO UPDATE SET challenge = excluded.challenge, created_at = excluded.created_at")
    .run(sid, purpose, challenge, now());
}
function takeChallenge(sid: string, purpose: string): string | undefined {
  const row = db.prepare("SELECT challenge, created_at FROM webauthn_challenges WHERE session_id = ? AND purpose = ?").get(sid, purpose) as { challenge: string; created_at: number } | undefined;
  db.prepare("DELETE FROM webauthn_challenges WHERE session_id = ? AND purpose = ?").run(sid, purpose);
  return row && row.created_at > now() - 300 ? row.challenge : undefined;
}

portal.post("/webauthn/register/options", async (c) => {
  const s = session(c);
  if (!s) return c.json({ error: "signed out" }, 401);
  if (!canEnrollPasskey(s)) return c.json({ error: "sign in with ID.me again to add a passkey" }, 403);
  const existing = db.prepare("SELECT credential_id FROM passkeys WHERE user_id = ?").all(s.user.id) as { credential_id: string }[];
  const opts = await generateRegistrationOptions({
    rpName: "Agent Mandates", rpID, userName: s.user.email || s.user.name, userDisplayName: s.user.name,
    userID: new TextEncoder().encode(s.user.id),
    excludeCredentials: existing.map((p) => ({ id: p.credential_id })),
    authenticatorSelection: { residentKey: "preferred", userVerification: "required" },
  });
  saveChallenge(s.sid, "register", opts.challenge);
  return c.json(opts);
});

portal.post("/webauthn/register/verify", async (c) => {
  const s = session(c);
  if (!s) return c.json({ ok: false, error: "signed out" }, 401);
  if (!canEnrollPasskey(s)) return c.json({ ok: false, error: "sign in with ID.me again to add a passkey" }, 403);
  const expectedChallenge = takeChallenge(s.sid, "register");
  if (!expectedChallenge) return c.json({ ok: false, error: "challenge expired" }, 400);
  try {
    const v = await verifyRegistrationResponse({ response: await c.req.json(), expectedChallenge, expectedOrigin: MANDATE_URL, expectedRPID: rpID, requireUserVerification: true });
    if (!v.verified) return c.json({ ok: false, error: "not verified" }, 400);
    const cred = v.registrationInfo.credential;
    db.prepare("INSERT INTO passkeys (credential_id, user_id, public_key, counter, transports, created_at) VALUES (?, ?, ?, ?, ?, ?)")
      .run(cred.id, s.user.id, cred.publicKey, cred.counter, JSON.stringify(cred.transports ?? []), now());
    audit("passkey_added", {}, { userId: s.user.id });
    return c.json({ ok: true });
  } catch (e) {
    return c.json({ ok: false, error: (e as Error).message }, 400);
  }
});

portal.post("/webauthn/auth/options", async (c) => {
  const s = session(c);
  if (!s) return c.json({ error: "signed out" }, 401);
  const { purpose } = await c.req.json();
  const creds = db.prepare("SELECT credential_id, transports FROM passkeys WHERE user_id = ?").all(s.user.id) as { credential_id: string; transports: string }[];
  const opts = await generateAuthenticationOptions({
    rpID, userVerification: "required",
    allowCredentials: creds.map((p) => ({ id: p.credential_id, transports: JSON.parse(p.transports) })),
  });
  saveChallenge(s.sid, String(purpose), opts.challenge);
  return c.json(opts);
});

/** Check a passkey assertion made for one specific purpose (one consent or one purchase). */
async function verifyPasskey(s: Session, purpose: string, response: any): Promise<boolean> {
  const expectedChallenge = takeChallenge(s.sid, purpose);
  if (!expectedChallenge || !response?.id) return false;
  const pk = db.prepare("SELECT * FROM passkeys WHERE credential_id = ? AND user_id = ?").get(response.id, s.user.id) as
    | { credential_id: string; public_key: Uint8Array; counter: number; transports: string } | undefined;
  if (!pk) return false;
  try {
    const v = await verifyAuthenticationResponse({
      response, expectedChallenge, expectedOrigin: MANDATE_URL, expectedRPID: rpID, requireUserVerification: true,
      credential: { id: pk.credential_id, publicKey: new Uint8Array(pk.public_key), counter: pk.counter, transports: JSON.parse(pk.transports) },
    });
    if (v.verified) db.prepare("UPDATE passkeys SET counter = ? WHERE credential_id = ?").run(v.authenticationInfo.newCounter, pk.credential_id);
    return v.verified;
  } catch {
    return false;
  }
}

// Small client helper: get a challenge for this purpose, sign it with the passkey, post the result.
const passkeyScript = html`<script>
async function signAndSend(purpose, url, body) {
  const err = document.getElementById('err'); err.textContent = '';
  try {
    let assertion = null;
    if (body.decision === 'approve') {
      const opts = await (await fetch('/webauthn/auth/options', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ purpose }) })).json();
      assertion = await SimpleWebAuthnBrowser.startAuthentication({ optionsJSON: opts });
    }
    const r = await (await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ ...body, assertion }) })).json();
    if (!r.ok) throw new Error(r.error || 'something went wrong');
    location.href = r.redirect;
  } catch (e) { err.textContent = e.message; }
}
</script>`;

// ---------- consent: an agent asks for a mandate ----------

type RequestRow = { id: string; agent_jkt: string; audience: string; purpose: string; proposal_json: string; status: string; mandate_id: string | null; created_at: number };

function loadRequest(id: string) {
  const r = db.prepare("SELECT * FROM mandate_requests WHERE id = ?").get(id) as RequestRow | undefined;
  if (!r) return undefined;
  const agent = db.prepare("SELECT name FROM agents WHERE jkt = ?").get(r.agent_jkt) as { name: string };
  const rp = db.prepare("SELECT * FROM relying_parties WHERE origin = ?").get(r.audience) as { name: string; requested_claims: string; optional_claims: string };
  return { r, agent, rp, proposal: JSON.parse(r.proposal_json) as { max_total_usd: number; per_purchase_limit_usd: number; days: number } };
}

const fingerprint = (jkt: string) => jkt.slice(0, 12).match(/.{1,4}/g)!.join("-");

portal.get("/approve/:id", (c) => {
  const s = requireUser(c);
  if (s instanceof Response) return s;
  const loaded = loadRequest(c.req.param("id"));
  if (!loaded) return c.html(page(T, "Not found", html`<h1>That request doesn't exist</h1>`), 404);
  const { r, agent, rp, proposal } = loaded;
  const status = r.status === "pending" && r.created_at < now() - APPROVAL_TTL_SECONDS ? "expired" : r.status;
  if (status !== "pending")
    return c.html(page(T, "Already decided", html`<h1>This request was already ${status}</h1><p><a href="/">Back to your mandates</a></p>`, { right: signedInBar(s) }));

  const have = availableClaims(s.attrs);
  const required: string[] = JSON.parse(rp.requested_claims), optional: string[] = JSON.parse(rp.optional_claims);
  const missing = required.filter((k) => !have[k]);
  return c.html(page(T, "Approve agent", html`
    <h1>${agent.name} wants to act for you at ${rp.name}</h1>
    <p class="muted">${r.purpose || "No reason given."}</p>
    <div class="panel">
      <div class="row"><span class="k">Agent</span><span class="v">${agent.name} · key <span class="mono">${fingerprint(r.agent_jkt)}</span></span></div>
      <div class="row"><span class="k">Website</span><span class="v">${rp.name} · <span class="mono">${r.audience}</span></span></div>
    </div>
    <h2>What ${rp.name} learns about you</h2>
    <p class="small muted">Only yes-or-no facts. Not your name, birthday, or email. The site gets an ID for you that no other site can match.</p>
    ${required.map((k) => html`<label class="check"><input type="checkbox" checked disabled> ${CLAIM_LABELS[k] ?? k} ${have[k] ? "" : html`<span class="pill bad">you don't have this</span>`}</label>`)}
    ${optional.filter((k) => have[k]).map((k) => html`<label class="check"><input type="checkbox" name="claim" value="${k}"> ${CLAIM_LABELS[k] ?? k} <span class="small muted">(optional, may unlock discounts)</span></label>`)}
    <h2>Limits</h2>
    <div class="row"><span class="k">Total budget (USD)</span><input type="number" id="max" min="1" max="10000" value="${proposal.max_total_usd}"></div>
    <div class="row"><span class="k">Most for one purchase (USD)</span><input type="number" id="per" min="1" max="10000" value="${proposal.per_purchase_limit_usd}"></div>
    <div class="row"><span class="k">Expires after (days)</span><input type="number" id="days" min="1" max="90" value="${proposal.days}"></div>
    <p class="small muted">Anything over these limits comes back to you for a one-time approval. You can revoke this at any time.</p>
    ${missing.length
      ? html`<p class="err">${rp.name} requires facts your ID.me account can't confirm, so this can't be approved.</p>
             <div class="actions"><button class="ghost" id="deny">Deny</button></div>`
      : html`<div class="actions"><button id="approve">Approve with passkey</button><button class="ghost" id="deny">Deny</button></div>`}
    <p class="err" id="err"></p>
    ${passkeyScript}
    <script>
      const send = (decision) => signAndSend('consent:${r.id}', '/approve/${r.id}', {
        decision,
        claims: [...document.querySelectorAll('input[name=claim]:checked')].map((x) => x.value),
        max_total_usd: Number(document.getElementById('max').value),
        per_purchase_limit_usd: Number(document.getElementById('per').value),
        days: Number(document.getElementById('days').value),
      });
      document.getElementById('approve')?.addEventListener('click', () => send('approve'));
      document.getElementById('deny').addEventListener('click', () => send('deny'));
    </script>`, { right: signedInBar(s), scripts: ["/static/webauthn.js"] }));
});

portal.post("/approve/:id", async (c) => {
  const s = session(c);
  if (!s) return c.json({ ok: false, error: "signed out" }, 401);
  const loaded = loadRequest(c.req.param("id"));
  if (!loaded || loaded.r.status !== "pending" || loaded.r.created_at < now() - APPROVAL_TTL_SECONDS)
    return c.json({ ok: false, error: "request is no longer pending" }, 400);
  const { r, rp } = loaded;
  const b = await c.req.json();

  if (b.decision !== "approve") {
    db.prepare("UPDATE mandate_requests SET status = 'denied' WHERE id = ? AND status = 'pending'").run(r.id);
    audit("mandate_denied", { site: rp.name }, { userId: s.user.id });
    return c.json({ ok: true, redirect: "/?flash=denied" });
  }
  if (!(await verifyPasskey(s, `consent:${r.id}`, b.assertion))) return c.json({ ok: false, error: "passkey check failed" }, 403);

  const have = availableClaims(s.attrs);
  const required: string[] = JSON.parse(rp.requested_claims), optional: string[] = JSON.parse(rp.optional_claims);
  if (required.some((k) => !have[k])) return c.json({ ok: false, error: "missing required facts" }, 400);
  const chosen = (Array.isArray(b.claims) ? b.claims : []).filter((k: string) => optional.includes(k) && have[k]);
  const claims = Object.fromEntries([...required, ...chosen].map((k) => [k, true]));
  const maxTotal = Math.round(Number(b.max_total_usd) * 100), per = Math.round(Number(b.per_purchase_limit_usd) * 100), days = Number(b.days);
  if (!(maxTotal > 0 && maxTotal <= 1_000_000 && per > 0 && per <= maxTotal && days >= 1 && days <= 90))
    return c.json({ ok: false, error: "limits are out of range" }, 400);

  const mandateId = newId("md");
  // Claim the request inside the transaction: if two approvals race (two tabs, two people), only one creates a mandate.
  const granted = tx(db, () => {
    const claimed = db.prepare("UPDATE mandate_requests SET status = 'approved', mandate_id = ? WHERE id = ? AND status = 'pending'").run(mandateId, r.id);
    if (claimed.changes !== 1) return false;
    db.prepare(`INSERT INTO mandates (id, user_id, agent_jkt, audience, purpose, claims_json, max_total_cents, per_purchase_cents, status, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)`)
      .run(mandateId, s.user.id, r.agent_jkt, r.audience, r.purpose, JSON.stringify(claims), maxTotal, per, now(), now() + days * 86400);
    return true;
  });
  if (!granted) return c.json({ ok: false, error: "request is no longer pending" }, 400);
  audit("mandate_granted", { site: rp.name, max_total_cents: maxTotal, per_purchase_cents: per, days, claims: Object.keys(claims) }, { userId: s.user.id, mandateId });
  return c.json({ ok: true, redirect: "/?flash=granted" });
});

// ---------- step-up: approve one purchase over the limit ----------

type ApprovalRow = { id: string; mandate_id: string; amount_cents: number; description: string; reason: string; status: string; created_at: number };

portal.get("/approvals/:id", (c) => {
  const s = requireUser(c);
  if (s instanceof Response) return s;
  const a = db.prepare("SELECT * FROM approvals WHERE id = ?").get(c.req.param("id")) as ApprovalRow | undefined;
  const m = a && getMandate(a.mandate_id);
  if (!a || !m || m.user_id !== s.user.id) return c.html(page(T, "Not found", html`<h1>That approval doesn't exist</h1>`), 404);
  const agent = db.prepare("SELECT name FROM agents WHERE jkt = ?").get(m.agent_jkt) as { name: string };
  const rp = db.prepare("SELECT name FROM relying_parties WHERE origin = ?").get(m.audience) as { name: string };
  const decided = a.status !== "pending";
  return c.html(page(T, "Approve purchase", html`
    <h1>${decided ? `This purchase was ${a.status === "used" ? "approved" : a.status}` : `Approve one purchase for ${agent.name}?`}</h1>
    <div class="panel">
      <div class="row"><span class="k">Amount</span><span class="v"><strong>${usd(a.amount_cents)}</strong></span></div>
      <div class="row"><span class="k">For</span><span class="v">${a.description}</span></div>
      <div class="row"><span class="k">At</span><span class="v">${rp.name}</span></div>
      <div class="row"><span class="k">Why you're being asked</span><span class="v">${a.reason}</span></div>
    </div>
    <p class="small muted">Approving covers this one purchase, at this amount, once. It doesn't raise your limits.</p>
    ${decided ? html`<p><a href="/">Back to your mandates</a></p>` : html`
      <div class="actions"><button id="approve">Approve with passkey</button><button class="ghost" id="deny">Deny</button></div>
      <p class="err" id="err"></p>${passkeyScript}
      <script>
        document.getElementById('approve').onclick = () => signAndSend('purchase:${a.id}', '/approvals/${a.id}', { decision: 'approve' });
        document.getElementById('deny').onclick = () => signAndSend('purchase:${a.id}', '/approvals/${a.id}', { decision: 'deny' });
      </script>`}`, { right: signedInBar(s), scripts: ["/static/webauthn.js"] }));
});

portal.post("/approvals/:id", async (c) => {
  const s = session(c);
  if (!s) return c.json({ ok: false, error: "signed out" }, 401);
  const a = db.prepare("SELECT * FROM approvals WHERE id = ?").get(c.req.param("id")) as ApprovalRow | undefined;
  const m = a && getMandate(a.mandate_id);
  if (!a || !m || m.user_id !== s.user.id) return c.json({ ok: false, error: "not found" }, 404);
  if (a.status !== "pending") return c.json({ ok: false, error: `already ${a.status}` }, 400);
  if (a.created_at < now() - APPROVAL_TTL_SECONDS) return c.json({ ok: false, error: "this request expired; ask the agent to try the purchase again" }, 400);
  const b = await c.req.json();
  if (b.decision === "approve" && !(await verifyPasskey(s, `purchase:${a.id}`, b.assertion)))
    return c.json({ ok: false, error: "passkey check failed" }, 403);
  const status = b.decision === "approve" ? "approved" : "denied";
  db.prepare("UPDATE approvals SET status = ?, decided_at = ? WHERE id = ? AND status = 'pending'").run(status, now(), a.id);
  audit(`step_up_${status}`, { amount_cents: a.amount_cents, description: a.description }, { userId: s.user.id, mandateId: m.id });
  return c.json({ ok: true, redirect: `/approvals/${a.id}` });
});

// ---------- revoke ----------

portal.post("/mandates/:id/revoke", (c) => {
  const s = session(c);
  const origin = c.req.header("origin");
  if (!s || (origin && origin !== MANDATE_URL)) return c.text("forbidden", 403);
  const m = getMandate(c.req.param("id"));
  if (!m || m.user_id !== s.user.id) return c.text("not found", 404);
  db.prepare("UPDATE mandates SET status = 'revoked', revoked_at = ? WHERE id = ? AND status = 'active'").run(now(), m.id);
  db.prepare("UPDATE approvals SET status = 'denied', decided_at = ? WHERE mandate_id = ? AND status = 'pending'").run(now(), m.id);
  audit("mandate_revoked", {}, { userId: s.user.id, mandateId: m.id });
  return c.redirect("/?flash=revoked");
});

// ---------- dashboard ----------

const EVENT_TEXT: Record<string, (d: any) => string> = {
  signed_in: () => "Signed in with ID.me",
  passkey_added: () => "Added a passkey",
  mandate_granted: (d) => `Granted a mandate at ${d.site}: ${usd(d.max_total_cents)} budget for ${d.days} days`,
  mandate_denied: (d) => `Denied an agent at ${d.site}`,
  mandate_revoked: () => "Revoked a mandate",
  purchase: (d) => `Agent bought "${d.description}" for ${usd(d.amount_cents)}${d.approval_id ? " (you approved it)" : ""}`,
  purchase_denied: (d) => `Blocked a ${usd(d.amount_cents)} purchase: ${d.reason}`,
  step_up_requested: (d) => `Agent asked to spend ${usd(d.amount_cents)} on "${d.description}"`,
  step_up_approved: (d) => `You approved ${usd(d.amount_cents)} for "${d.description}"`,
  step_up_denied: (d) => `You denied ${usd(d.amount_cents)} for "${d.description}"`,
};

function mandateCard(m: MandateRow) {
  const agent = db.prepare("SELECT name FROM agents WHERE jkt = ?").get(m.agent_jkt) as { name: string };
  const rp = db.prepare("SELECT name FROM relying_parties WHERE origin = ?").get(m.audience) as { name: string };
  const status = liveStatus(m), spent = autoSpentCents(m.id), total = totalSpentCents(m.id);
  const pct = Math.min(100, Math.round((spent / m.max_total_cents) * 100));
  const days = Math.max(0, Math.ceil((m.expires_at - now()) / 86400));
  return html`<div class="panel" data-mandate="${m.id}">
    <div class="row"><strong>${agent.name} at ${rp.name}</strong>
      <span class="pill ${status === "active" ? "" : status === "revoked" ? "bad" : "off"}">${status}</span></div>
    ${m.purpose ? html`<p class="small muted">${m.purpose}</p>` : ""}
    <div class="bar"><i style="width:${pct}%"></i></div>
    <div class="small muted">${usd(spent)} of ${usd(m.max_total_cents)} budget used${total > spent ? html` · ${usd(total - spent)} more approved one by one` : ""} · up to ${usd(m.per_purchase_cents)} per purchase</div>
    <div class="small muted">Shares: ${Object.keys(JSON.parse(m.claims_json)).map((k) => CLAIM_LABELS[k] ?? k).join(", ")} · agent key <span class="mono">${fingerprint(m.agent_jkt)}</span>
      ${status === "active" ? ` · ${days} day${days === 1 ? "" : "s"} left` : ""}</div>
    ${status === "active" ? html`<form method="post" action="/mandates/${m.id}/revoke" class="actions"><button class="danger">Revoke</button></form>` : ""}
  </div>`;
}

portal.get("/", (c) => {
  const s = session(c);
  if (!s) {
    return c.html(page(T, "Home", html`
      <h1>Let AI agents act for you, on your terms</h1>
      <p>Sign in with ID.me once. Then any agent you approve can prove to a website that a real, verified person is behind it, with the limits you set, and you can cut it off with one click.</p>
      <div class="actions"><a class="btn" href="/login">Sign in with ID.me</a></div>`));
  }
  const flash = { granted: "Mandate granted. The agent can start now.", denied: "Request denied.", revoked: "Revoked. The agent can't spend another cent." }[c.req.query("flash") ?? ""];
  const mandates = db.prepare("SELECT * FROM mandates WHERE user_id = ? ORDER BY created_at DESC").all(s.user.id) as MandateRow[];
  const active = mandates.filter((m) => liveStatus(m) === "active"), past = mandates.filter((m) => liveStatus(m) !== "active");
  const pending = db.prepare(`SELECT a.* FROM approvals a JOIN mandates m ON m.id = a.mandate_id WHERE m.user_id = ? AND a.status = 'pending' ORDER BY a.created_at DESC`).all(s.user.id) as ApprovalRow[];
  const events = db.prepare("SELECT * FROM audit WHERE user_id = ? ORDER BY id DESC LIMIT 25").all(s.user.id) as { type: string; detail_json: string; created_at: number }[];
  const have = availableClaims(s.attrs);
  return c.html(page(T, "Your mandates", html`
    ${flash ? html`<div class="panel"><strong>${flash}</strong></div>` : ""}
    <h1>${s.user.name}</h1>
    <p>${have.verified_human ? html`<span class="pill">ID.me verified</span>` : html`<span class="pill off">Not verified</span>`}
       ${have.veteran ? html` <span class="pill">Veteran</span>` : ""}${have.student ? html` <span class="pill">Student</span>` : ""}</p>
    ${pending.length ? html`<h2>Waiting for you</h2>${pending.map((a) => html`<div class="panel"><div class="row"><span>${a.description} · <strong>${usd(a.amount_cents)}</strong></span><a class="btn" href="/approvals/${a.id}">Review</a></div><div class="small muted">${a.reason}</div></div>`)}` : ""}
    <h2>Active mandates</h2>
    ${active.length ? active.map(mandateCard) : html`<p class="muted">None yet. When an agent asks for one, you'll get a link to approve it here.</p>`}
    ${past.length ? html`<h2>Past mandates</h2>${past.map(mandateCard)}` : ""}
    <h2>Activity</h2>
    ${events.map((e) => html`<div class="row small"><span>${(EVENT_TEXT[e.type] ?? ((_: unknown) => e.type))(JSON.parse(e.detail_json))}</span><span class="muted">${ago(e.created_at)}</span></div>`)}
  `, { right: signedInBar(s) }));
});
