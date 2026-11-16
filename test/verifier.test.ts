// Unit tests for the website-side verifier. No servers: a local issuer key signs tokens and the
// verifier reads it from an in-memory key set.
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { calculateJwkThumbprint, createLocalJWKSet, exportJWK, generateKeyPair, SignJWT, type CryptoKey, type JWK } from "jose";
import { createVerifier } from "../packages/verifier/index.ts";
import { tokenHash } from "../packages/verifier/dpop.ts";

const ISS = "https://issuer.test", AUD = "https://shop.test", URL_ = `${AUD}/api/agent/checkout`;
const issuer = await generateKeyPair("ES256");
const issuerJwk = { ...(await exportJWK(issuer.publicKey)), kid: "k1", alg: "ES256" };
const verifier = createVerifier({ issuer: ISS, audience: AUD, jwks: createLocalJWKSet({ keys: [issuerJwk] }) });

async function agentKey() {
  const { privateKey, publicKey } = await generateKeyPair("ES256");
  const jwk = await exportJWK(publicKey);
  return { privateKey, jwk, jkt: await calculateJwkThumbprint(jwk) };
}
const alice = await agentKey();

function mandateToken(over: { aud?: string; exp?: number; jkt?: string; iss?: string; typ?: string } = {}) {
  return new SignJWT({ act: { sub: "agent_1", name: "Claude" }, claims: { verified_human: true }, mandate_id: "md_1", cnf: { jkt: over.jkt ?? alice.jkt } })
    .setProtectedHeader({ alg: "ES256", kid: "k1", typ: over.typ ?? "mandate+jwt" })
    .setIssuer(over.iss ?? ISS).setAudience(over.aud ?? AUD).setSubject("pw_abc").setIssuedAt()
    .setExpirationTime(over.exp ?? Math.floor(Date.now() / 1000) + 600).sign(issuer.privateKey);
}
function proof(key: { privateKey: CryptoKey; jwk: JWK }, token: string, over: { htm?: string; htu?: string; ath?: string | null; iat?: number } = {}) {
  const claims: Record<string, unknown> = { htm: over.htm ?? "POST", htu: over.htu ?? URL_ };
  if (over.ath !== null) claims.ath = over.ath ?? tokenHash(token);
  return new SignJWT(claims).setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: key.jwk })
    .setIssuedAt(over.iat ?? Math.floor(Date.now() / 1000)).setJti(randomUUID()).sign(key.privateKey);
}
const check = async (token: string, dpop?: string, method = "POST", url = URL_) =>
  verifier.verify({ method, url, authorization: `DPoP ${token}`, dpop });

test("accepts a valid token with a matching proof", async () => {
  const t = await mandateToken();
  const r = await check(t, await proof(alice, t));
  assert.equal(r.ok, true);
  if (r.ok) assert.equal(r.mandate.subject, "pw_abc");
});

test("rejects a token without a proof", async () => {
  const t = await mandateToken();
  const r = await check(t);
  assert.equal(r.ok, false);
});

test("rejects a proof from a different key (stolen token)", async () => {
  const t = await mandateToken();
  const mallory = await agentKey();
  const r = await check(t, await proof(mallory, t));
  assert.ok(!r.ok && /different key/.test(r.description));
});

test("rejects a replayed proof", async () => {
  const t = await mandateToken();
  const p = await proof(alice, t);
  assert.equal((await check(t, p)).ok, true);
  const r = await check(t, p);
  assert.ok(!r.ok && /replay/.test(r.description));
});

test("rejects a proof for another method or URL", async () => {
  const t = await mandateToken();
  assert.equal((await check(t, await proof(alice, t, { htm: "GET" }))).ok, false);
  assert.equal((await check(t, await proof(alice, t, { htu: `${AUD}/api/agent/refund` }))).ok, false);
});

test("rejects a proof not tied to this token (missing or wrong ath)", async () => {
  const t = await mandateToken();
  assert.equal((await check(t, await proof(alice, t, { ath: null }))).ok, false);
  assert.equal((await check(t, await proof(alice, t, { ath: tokenHash("other") }))).ok, false);
});

test("rejects a stale proof", async () => {
  const t = await mandateToken();
  const r = await check(t, await proof(alice, t, { iat: Math.floor(Date.now() / 1000) - 300 }));
  assert.equal(r.ok, false);
});

test("rejects tokens for another site, from another issuer, expired, or of the wrong type", async () => {
  for (const t of [
    await mandateToken({ aud: "https://other.test" }),
    await mandateToken({ iss: "https://evil.test" }),
    await mandateToken({ exp: Math.floor(Date.now() / 1000) - 60 }),
    await mandateToken({ typ: "JWT" }),
  ]) assert.equal((await check(t, await proof(alice, t))).ok, false);
});

test("rejects a token signed by an unknown key", async () => {
  const rogue = await generateKeyPair("ES256");
  const t = await new SignJWT({ cnf: { jkt: alice.jkt } }).setProtectedHeader({ alg: "ES256", kid: "k1", typ: "mandate+jwt" })
    .setIssuer(ISS).setAudience(AUD).setSubject("pw_x").setIssuedAt().setExpirationTime("10m").sign(rogue.privateKey);
  assert.equal((await check(t, await proof(alice, t))).ok, false);
});
