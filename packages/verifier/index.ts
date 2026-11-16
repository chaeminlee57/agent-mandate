// @agent-mandate/verifier: the drop-in check a website runs on every request an AI agent makes.
//
//   const verifier = createVerifier({ issuer, audience: "https://shop.example" });
//   app.use("/api/agent/*", agentMandate(verifier));
//   app.post("/api/agent/checkout", (c) => { const m = c.get("agentMandate"); ... });
//
// It checks, with no network call after the issuer's keys are cached:
//   1. the mandate token's signature, issuer, audience (this site), and expiry
//   2. the DPoP proof: signed by the key the token is bound to (cnf.jkt), for this exact method
//      and URL, fresh, never seen before, and tied to this token (ath)
// Limits that depend on history (like "$150 total") cannot be checked offline, so money moves
// through the issuer's transaction endpoint instead. See authorizeTransaction() below.
import { createRemoteJWKSet, jwtVerify, type JWTVerifyGetKey } from "jose";
import type { MiddlewareHandler } from "hono";
import { DpopError, MemoryReplayCache, verifyDpopProof, DPOP_ALGS, type ReplayCache } from "./dpop.ts";

export { MemoryReplayCache, type ReplayCache } from "./dpop.ts";

export type AgentMandate = {
  mandateId: string;
  /** Pairwise subject: stable for this person on this site, different on every other site. */
  subject: string;
  agent: { id: string; name: string };
  claims: Record<string, boolean | number | string>;
  authorization: { type: string; max_total_usd?: number; per_purchase_limit_usd?: number; [k: string]: unknown }[];
  issuer: string;
  expiresAt: number;
  token: string;
};

export type VerifyResult =
  | { ok: true; mandate: AgentMandate }
  | { ok: false; status: 401 | 400; error: string; description: string };

export type VerifierOptions = {
  issuer: string;
  /** This website's origin, exactly as it appears in the token's aud claim. */
  audience: string;
  /** Defaults to `${issuer}/.well-known/jwks.json`. */
  jwks?: JWTVerifyGetKey;
  replay?: ReplayCache;
  /** Public origin used to rebuild the request URL for the htu check (needed behind proxies). */
  publicOrigin?: string;
};

export function createVerifier(opts: VerifierOptions) {
  const jwks = opts.jwks ?? createRemoteJWKSet(new URL(`${opts.issuer}/.well-known/jwks.json`));
  const replay = opts.replay ?? new MemoryReplayCache();

  async function verify(req: { method: string; url: string; authorization?: string; dpop?: string }): Promise<VerifyResult> {
    const fail = (description: string, error = "invalid_token", status: 401 | 400 = 401): VerifyResult => ({
      ok: false, status, error, description,
    });
    const auth = req.authorization ?? "";
    if (!auth.startsWith("DPoP ")) return fail("expected Authorization: DPoP <mandate token>", "invalid_request");
    const token = auth.slice(5).trim();

    let payload;
    try {
      ({ payload } = await jwtVerify(token, jwks, {
        issuer: opts.issuer,
        audience: opts.audience,
        typ: "mandate+jwt",
        algorithms: ["ES256"],
        clockTolerance: 5,
      }));
    } catch (e) {
      return fail(`mandate token rejected: ${(e as Error).message}`);
    }
    const cnf = payload.cnf as { jkt?: string } | undefined;
    if (!cnf?.jkt) return fail("mandate token is not bound to a key");

    const url = opts.publicOrigin ? new URL(new URL(req.url).pathname, opts.publicOrigin).toString() : req.url;
    try {
      const proof = await verifyDpopProof(req.dpop, { method: req.method, url, accessToken: token, replay });
      if (proof.jkt !== cnf.jkt) return fail("DPoP proof was signed by a different key than the token is bound to");
    } catch (e) {
      if (e instanceof DpopError) return fail(e.message, "invalid_dpop_proof");
      throw e;
    }

    const act = payload.act as { sub: string; name?: string };
    return {
      ok: true,
      mandate: {
        mandateId: String(payload.mandate_id),
        subject: String(payload.sub),
        agent: { id: act?.sub, name: act?.name ?? "agent" },
        claims: (payload.claims ?? {}) as AgentMandate["claims"],
        authorization: (payload.authorization_details ?? []) as AgentMandate["authorization"],
        issuer: String(payload.iss),
        expiresAt: Number(payload.exp),
        token,
      },
    };
  }

  return { verify, issuer: opts.issuer, audience: opts.audience };
}

export type Verifier = ReturnType<typeof createVerifier>;

/** Hono middleware. Puts the verified mandate on c.get("agentMandate") or answers 401. */
export function agentMandate(verifier: Verifier): MiddlewareHandler<{ Variables: { agentMandate: AgentMandate } }> {
  return async (c, next) => {
    const result = await verifier.verify({
      method: c.req.method,
      url: c.req.url,
      authorization: c.req.header("authorization"),
      dpop: c.req.header("dpop"),
    });
    if (!result.ok) {
      c.header(
        "WWW-Authenticate",
        `DPoP error="${result.error}", error_description="${result.description.replace(/"/g, "'")}", algs="${DPOP_ALGS.join(" ")}"`,
      );
      return c.json({ error: result.error, error_description: result.description }, result.status);
    }
    c.set("agentMandate", result.mandate);
    await next();
  };
}

export type TxnResult =
  | { status: "approved"; transaction_id: string; remaining_usd: number }
  | { status: "step_up_required"; approval_id: string; approval_url: string; reason: string }
  | { status: "denied"; reason: string };

/**
 * Ask the issuer to approve a purchase against the mandate's limits. The issuer holds the spend
 * ledger, so this is the one online call. Pass the same `reference` on retries: it is idempotent.
 */
export async function authorizeTransaction(
  issuer: string,
  apiKey: string,
  body: { mandate_id: string; amount_usd: number; description: string; reference: string; approval_id?: string },
): Promise<TxnResult> {
  const res = await fetch(`${issuer}/api/transactions/authorize`, {
    method: "POST",
    headers: { authorization: `Bearer ${apiKey}`, "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok && res.status !== 402 && res.status !== 403)
    throw new Error(`issuer returned ${res.status}: ${await res.text()}`);
  return (await res.json()) as TxnResult;
}
