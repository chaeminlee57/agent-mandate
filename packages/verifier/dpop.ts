// DPoP proof checking (RFC 9449). A DPoP proof is a tiny JWT the agent signs with its own private
// key for every request. It names the HTTP method and URL, carries a unique ID, and (when a token
// is attached) a hash of that token. Checking it proves the caller holds the key the token is bound
// to, so a token copied out of a log or a proxy is useless on its own.
import { calculateJwkThumbprint, decodeProtectedHeader, importJWK, jwtVerify, type JWK } from "jose";
import { createHash } from "node:crypto";

export const DPOP_ALGS = ["ES256", "EdDSA"];

export interface ReplayCache {
  /** Returns false if this key was already seen (a replay); otherwise remembers it until expiresAt. */
  checkAndStore(key: string, expiresAtSec: number): boolean | Promise<boolean>;
}

/** In-memory replay cache. Fine for one process; use Redis (SET NX EX) when you run several. */
export class MemoryReplayCache implements ReplayCache {
  private seen = new Map<string, number>();
  checkAndStore(key: string, expiresAtSec: number) {
    const now = Date.now() / 1000;
    if (this.seen.size > 10_000) for (const [k, exp] of this.seen) if (exp < now) this.seen.delete(k);
    const prev = this.seen.get(key);
    if (prev && prev > now) return false;
    this.seen.set(key, expiresAtSec);
    return true;
  }
}

export class DpopError extends Error {}

/** Strip query and fragment, as RFC 9449 says to compare htu without them. */
export const normalizeHtu = (url: string) => {
  const u = new URL(url);
  return `${u.origin}${u.pathname}`;
};

export const tokenHash = (token: string) => createHash("sha256").update(token).digest("base64url");

export type VerifiedProof = { jwk: JWK; jkt: string; jti: string };

export async function verifyDpopProof(
  proof: string | undefined,
  opts: { method: string; url: string; accessToken?: string; replay: ReplayCache; maxAgeSec?: number },
): Promise<VerifiedProof> {
  if (!proof) throw new DpopError("missing DPoP proof header");
  let header;
  try {
    header = decodeProtectedHeader(proof);
  } catch {
    throw new DpopError("DPoP proof is not a JWT");
  }
  if (header.typ !== "dpop+jwt") throw new DpopError("DPoP proof must have typ dpop+jwt");
  if (!header.alg || !DPOP_ALGS.includes(header.alg)) throw new DpopError("unsupported DPoP alg");
  const jwk = header.jwk as JWK | undefined;
  if (!jwk || "d" in jwk) throw new DpopError("DPoP proof must carry a public jwk");

  const key = await importJWK(jwk, header.alg);
  const maxAge = opts.maxAgeSec ?? 60;
  let payload;
  try {
    ({ payload } = await jwtVerify(proof, key, { typ: "dpop+jwt", maxTokenAge: `${maxAge}s`, clockTolerance: 5 }));
  } catch (e) {
    throw new DpopError(`DPoP proof rejected: ${(e as Error).message}`);
  }
  if (payload.htm !== opts.method.toUpperCase()) throw new DpopError("DPoP htm does not match the request method");
  if (typeof payload.htu !== "string" || normalizeHtu(payload.htu) !== normalizeHtu(opts.url))
    throw new DpopError("DPoP htu does not match the request URL");
  if (typeof payload.jti !== "string" || payload.jti.length < 8) throw new DpopError("DPoP proof needs a jti");
  if (opts.accessToken !== undefined && payload.ath !== tokenHash(opts.accessToken))
    throw new DpopError("DPoP ath does not match the access token");

  const jkt = await calculateJwkThumbprint(jwk, "sha256");
  const fresh = await opts.replay.checkAndStore(`${jkt}:${payload.jti}`, (payload.iat ?? 0) + maxAge + 5);
  if (!fresh) throw new DpopError("DPoP proof was already used (replay)");
  return { jwk, jkt, jti: payload.jti };
}
