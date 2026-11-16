// The agent side: holds the agent's private key, asks people for mandates, swaps a mandate for
// short-lived tokens, and signs every request with a DPoP proof. The MCP server and the demo
// script both use this, so Claude and the scripted demo behave the same way.
import { calculateJwkThumbprint, exportJWK, generateKeyPair, importJWK, SignJWT, type JWK, type CryptoKey } from "jose";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import { tokenHash } from "../verifier/dpop.ts";

type MandateRecord = { site: string; issuer: string; mandate_id?: string; request_id: string; status: string; approve_url: string };
type State = { private_jwk: JWK; jkt: string; mandates: Record<string, MandateRecord> };

export type AgentResponse = { status: number; body: any; headers: Record<string, string> };

/** True if url parses and is on exactly this origin. */
const isOn = (url: unknown, origin: string) => {
  try { return new URL(String(url)).origin === origin; } catch { return false; }
};

export class AgentClient {
  private key!: CryptoKey;
  private publicJwk!: JWK;
  private tokens = new Map<string, { token: string; exp: number }>();
  private file: string;
  state: State;
  name: string;
  /** Mandate issuers this agent will use. A site can name any issuer, so the agent only follows the ones configured here. */
  issuers: string[];
  private constructor(file: string, state: State, name: string, issuers: string[]) {
    this.file = file;
    this.state = state;
    this.name = name;
    this.issuers = issuers;
  }

  /** Load the agent's identity from disk, creating a fresh key pair the first time. */
  static async load(opts: { home?: string; name?: string; issuers?: string[] } = {}) {
    const home = opts.home ?? process.env.AGENT_MANDATE_HOME ?? join(homedir(), ".agent-mandate");
    mkdirSync(home, { recursive: true, mode: 0o700 });
    const file = join(home, "agent.json");
    let state: State;
    if (existsSync(file)) {
      state = JSON.parse(readFileSync(file, "utf8"));
    } else {
      const { privateKey } = await generateKeyPair("ES256", { extractable: true });
      const private_jwk = await exportJWK(privateKey);
      const { d, ...pub } = private_jwk;
      state = { private_jwk, jkt: await calculateJwkThumbprint(pub, "sha256"), mandates: {} };
      writeFileSync(file, JSON.stringify(state, null, 2), { mode: 0o600 });
    }
    const issuers = (opts.issuers ?? (process.env.AGENT_MANDATE_ISSUERS ?? "http://localhost:4100").split(",")).map((u) => new URL(u.trim()).origin);
    const client = new AgentClient(file, state, opts.name ?? process.env.AGENT_NAME ?? "Claude", issuers);
    client.key = (await importJWK(state.private_jwk, "ES256")) as CryptoKey;
    const { d, ...pub } = state.private_jwk;
    client.publicJwk = pub;
    return client;
  }

  private save() {
    writeFileSync(this.file, JSON.stringify(this.state, null, 2), { mode: 0o600 });
  }

  get keyFingerprint() {
    return this.state.jkt.slice(0, 12).match(/.{1,4}/g)!.join("-");
  }

  /** A DPoP proof for one request: method + URL + fresh jti, plus a hash of the token if any. */
  async proof(method: string, url: string, accessToken?: string) {
    const u = new URL(url);
    return new SignJWT({ htm: method.toUpperCase(), htu: `${u.origin}${u.pathname}`, ...(accessToken ? { ath: tokenHash(accessToken) } : {}) })
      .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: this.publicJwk })
      .setIssuedAt()
      .setJti(randomUUID())
      .sign(this.key);
  }

  private async issuerCall(method: string, url: string, body?: unknown) {
    const res = await fetch(url, {
      method,
      headers: { dpop: await this.proof(method, url), ...(body ? { "content-type": "application/json" } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
    const json = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(`${json.error ?? res.status}: ${json.error_description ?? json.reason ?? res.statusText}`);
    return json;
  }

  /** What a site needs, and which mandate issuer it trusts. */
  async discover(site: string) {
    const origin = new URL(site).origin;
    const res = await fetch(`${origin}/.well-known/agent-access`);
    if (!res.ok) throw new Error(`${origin} does not accept agent mandates (no /.well-known/agent-access)`);
    return { origin, ...(await res.json()) } as { origin: string; name: string; accepted_issuers: string[]; requested_claims: string[]; optional_claims: Record<string, string>; endpoints: Record<string, string> };
  }

  /** Ask a person for a mandate. Returns the link they need to open. */
  async requestMandate(opts: { site: string; purpose: string; maxTotalUsd: number; perPurchaseUsd?: number; days?: number }) {
    const site = await this.discover(opts.site);
    const issuer = (site.accepted_issuers ?? []).map((u) => { try { return new URL(u).origin; } catch { return ""; } }).find((u) => this.issuers.includes(u));
    if (!issuer)
      throw new Error(`${site.origin} accepts mandates from ${(site.accepted_issuers ?? []).join(", ") || "no issuer"}, and this agent only uses ${this.issuers.join(", ")}`);
    const r = await this.issuerCall("POST", `${issuer}/api/mandate-requests`, {
      agent_name: this.name, audience: site.origin, purpose: opts.purpose,
      max_total_usd: opts.maxTotalUsd, per_purchase_limit_usd: opts.perPurchaseUsd ?? opts.maxTotalUsd, days: opts.days ?? 7,
    });
    if (!isOn(r.approve_url, issuer)) throw new Error(`the issuer returned an approval link that is not on ${issuer}`);
    this.state.mandates[site.origin] = { site: site.origin, issuer, request_id: r.request_id, status: "pending", approve_url: r.approve_url };
    this.save();
    return { site, approve_url: r.approve_url as string, request_id: r.request_id as string };
  }

  /** Check whether the person approved the pending request for a site. */
  async refresh(site: string) {
    const rec = this.record(site);
    const r = await this.issuerCall("GET", `${rec.issuer}/api/mandate-requests/${rec.request_id}`);
    rec.status = r.status;
    if (r.mandate_id) rec.mandate_id = r.mandate_id;
    this.save();
    return rec;
  }

  async waitForMandate(site: string, timeoutMs = 120_000) {
    const until = Date.now() + timeoutMs;
    while (Date.now() < until) {
      const rec = await this.refresh(site);
      if (rec.status !== "pending") return rec;
      await new Promise((r) => setTimeout(r, 1500));
    }
    return this.record(site);
  }

  record(site: string) {
    const rec = this.state.mandates[new URL(site).origin];
    if (!rec) throw new Error(`no mandate for ${new URL(site).origin}. Call request_mandate first.`);
    return rec;
  }

  /** A short-lived token for a site, fetched from the issuer and cached until just before expiry. */
  async token(site: string) {
    const rec = this.record(site);
    if (!rec.mandate_id) throw new Error(`the mandate for ${rec.site} is ${rec.status}, not approved`);
    const cached = this.tokens.get(rec.site);
    if (cached && cached.exp > Date.now() + 30_000) return cached.token;
    const r = await this.issuerCall("POST", `${rec.issuer}/api/token`, { mandate_id: rec.mandate_id });
    this.tokens.set(rec.site, { token: r.access_token, exp: Date.now() + r.expires_in * 1000 });
    return r.access_token as string;
  }

  /** Call a site as this agent: mandate token + a fresh DPoP proof on every request. */
  async fetch(url: string, opts: { method?: string; body?: unknown; headers?: Record<string, string> } = {}): Promise<AgentResponse> {
    const method = (opts.method ?? "GET").toUpperCase();
    const token = await this.token(url);
    const res = await fetch(url, {
      method,
      headers: {
        authorization: `DPoP ${token}`,
        dpop: await this.proof(method, url, token),
        ...(opts.body ? { "content-type": "application/json" } : {}),
        ...opts.headers,
      },
      body: opts.body ? JSON.stringify(opts.body) : undefined,
    });
    const body = await res.json().catch(() => null);
    // A site's 402 carries a link for the person to open. Pass it on only if it points at this mandate's issuer.
    if (body && typeof body === "object" && "approval_url" in body && !isOn(body.approval_url, this.record(url).issuer)) {
      body.approval_url = null;
      body.agent_warning = `the site sent an approval link that is not on ${this.record(url).issuer}; it was removed and should not be shown to the person`;
    }
    return { status: res.status, body, headers: Object.fromEntries(res.headers) };
  }

  async approvalStatus(site: string, approvalId: string) {
    const rec = this.record(site);
    return (await this.issuerCall("GET", `${rec.issuer}/api/approvals/${approvalId}`)).status as string;
  }

  async waitForApproval(site: string, approvalId: string, timeoutMs = 120_000) {
    const until = Date.now() + timeoutMs;
    while (Date.now() < until) {
      const s = await this.approvalStatus(site, approvalId);
      if (s !== "pending") return s;
      await new Promise((r) => setTimeout(r, 1500));
    }
    return "pending";
  }
}
