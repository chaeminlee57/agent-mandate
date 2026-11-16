// Shared state for the mandate service: database, signing key, and the domain helpers the
// portal pages and the APIs both use.
import { DATA_DIR, DEMO_STORE_API_KEY, STORE_URL } from "../../shared/config.ts";
import { hmacb64url, loadOrCreateSecret, loadOrCreateSigningKey, randomId, sha256hex } from "../../shared/crypto.ts";
import { now, openDb } from "../../shared/db.ts";
import { MemoryReplayCache } from "../../packages/verifier/dpop.ts";

const schema = `
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY, idp_sub TEXT UNIQUE NOT NULL, name TEXT NOT NULL, email TEXT,
  attributes_json TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS oidc_states (state TEXT PRIMARY KEY, verifier TEXT NOT NULL, nonce TEXT NOT NULL, return_to TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS passkeys (
  credential_id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), public_key BLOB NOT NULL,
  counter INTEGER NOT NULL, transports TEXT, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS webauthn_challenges (session_id TEXT NOT NULL, purpose TEXT NOT NULL, challenge TEXT NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY (session_id, purpose));
CREATE TABLE IF NOT EXISTS agents (jkt TEXT PRIMARY KEY, jwk_json TEXT NOT NULL, name TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS relying_parties (
  origin TEXT PRIMARY KEY, name TEXT NOT NULL, api_key_hash TEXT NOT NULL,
  requested_claims TEXT NOT NULL, optional_claims TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS mandate_requests (
  id TEXT PRIMARY KEY, agent_jkt TEXT NOT NULL REFERENCES agents(jkt), audience TEXT NOT NULL REFERENCES relying_parties(origin),
  purpose TEXT NOT NULL, proposal_json TEXT NOT NULL, status TEXT NOT NULL, mandate_id TEXT, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS mandates (
  id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), agent_jkt TEXT NOT NULL REFERENCES agents(jkt),
  audience TEXT NOT NULL REFERENCES relying_parties(origin), purpose TEXT NOT NULL,
  claims_json TEXT NOT NULL, max_total_cents INTEGER NOT NULL, per_purchase_cents INTEGER NOT NULL,
  status TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, revoked_at INTEGER);
CREATE TABLE IF NOT EXISTS ledger (
  id TEXT PRIMARY KEY, mandate_id TEXT NOT NULL REFERENCES mandates(id), amount_cents INTEGER NOT NULL,
  description TEXT NOT NULL, reference TEXT NOT NULL, approval_id TEXT, created_at INTEGER NOT NULL,
  UNIQUE (mandate_id, reference));
CREATE TABLE IF NOT EXISTS approvals (
  id TEXT PRIMARY KEY, mandate_id TEXT NOT NULL REFERENCES mandates(id), amount_cents INTEGER NOT NULL,
  description TEXT NOT NULL, reference TEXT NOT NULL, reason TEXT NOT NULL, status TEXT NOT NULL,
  created_at INTEGER NOT NULL, decided_at INTEGER, used_at INTEGER);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT, mandate_id TEXT, type TEXT NOT NULL,
  detail_json TEXT NOT NULL, created_at INTEGER NOT NULL);
`;

export const db = openDb(DATA_DIR, "mandate.db", schema);
export const signingKey = await loadOrCreateSigningKey(DATA_DIR, "mandate-signing");
const pairwiseSecret = loadOrCreateSecret(DATA_DIR, "pairwise");
export const replay = new MemoryReplayCache();

// Seed the demo store as a registered relying party (dev value from shared/config.ts).
db.prepare(
  `INSERT INTO relying_parties (origin, name, api_key_hash, requested_claims, optional_claims) VALUES (?, ?, ?, ?, ?)
   ON CONFLICT(origin) DO UPDATE SET api_key_hash = excluded.api_key_hash`,
).run(STORE_URL, "Demo Store", sha256hex(DEMO_STORE_API_KEY), JSON.stringify(["verified_human", "over_18"]), JSON.stringify(["veteran", "student"]));

/** Pairwise subject: the same person gets a different, unlinkable ID at every website. */
export const pairwiseSub = (userId: string, audience: string) => `pw_${hmacb64url(pairwiseSecret, `${userId}|${audience}`).slice(0, 22)}`;

export function audit(type: string, detail: Record<string, unknown>, ids: { userId?: string; mandateId?: string } = {}) {
  db.prepare("INSERT INTO audit (user_id, mandate_id, type, detail_json, created_at) VALUES (?, ?, ?, ?, ?)").run(
    ids.userId ?? null, ids.mandateId ?? null, type, JSON.stringify(detail), now(),
  );
}

export type User = { id: string; idp_sub: string; name: string; email: string; attributes_json: string };
export type Attributes = { verified: boolean; birth_date?: string; groups: string[] };

/** Turn the identity provider's attributes into the claims a person can choose to share. */
export function availableClaims(attrs: Attributes): Record<string, boolean> {
  const age = attrs.birth_date ? ageOn(attrs.birth_date, new Date()) : 0;
  return {
    verified_human: attrs.verified,
    over_18: attrs.verified && age >= 18,
    over_21: attrs.verified && age >= 21,
    veteran: attrs.groups.includes("veteran"),
    student: attrs.groups.includes("student"),
  };
}

function ageOn(birth: string, d: Date) {
  const b = new Date(birth + "T00:00:00Z");
  let age = d.getUTCFullYear() - b.getUTCFullYear();
  if (d.getUTCMonth() < b.getUTCMonth() || (d.getUTCMonth() === b.getUTCMonth() && d.getUTCDate() < b.getUTCDate())) age--;
  return age;
}

export type MandateRow = {
  id: string; user_id: string; agent_jkt: string; audience: string; purpose: string; claims_json: string;
  max_total_cents: number; per_purchase_cents: number; status: string; created_at: number; expires_at: number; revoked_at: number | null;
};

export const getMandate = (id: string) => db.prepare("SELECT * FROM mandates WHERE id = ?").get(id) as MandateRow | undefined;

/** Spending that counts against the cap. Purchases the person approved one by one do not. */
export const autoSpentCents = (mandateId: string) =>
  Number((db.prepare("SELECT COALESCE(SUM(amount_cents),0) AS s FROM ledger WHERE mandate_id = ? AND approval_id IS NULL").get(mandateId) as { s: number }).s);
export const totalSpentCents = (mandateId: string) =>
  Number((db.prepare("SELECT COALESCE(SUM(amount_cents),0) AS s FROM ledger WHERE mandate_id = ?").get(mandateId) as { s: number }).s);

/** A mandate is usable only while active and unexpired. Expiry is applied lazily here. */
export function liveStatus(m: MandateRow): "active" | "revoked" | "expired" {
  if (m.status === "revoked") return "revoked";
  if (m.expires_at <= now()) return "expired";
  return "active";
}

export const newId = randomId;
