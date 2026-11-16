import { createHash, createHmac, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { exportJWK, generateKeyPair, importJWK, type JWK, type CryptoKey } from "jose";

export const b64url = (buf: Buffer | Uint8Array) => Buffer.from(buf).toString("base64url");
export const sha256b64url = (s: string) => b64url(createHash("sha256").update(s).digest());
export const sha256hex = (s: string) => createHash("sha256").update(s).digest("hex");
export const hmacb64url = (key: string, s: string) => b64url(createHmac("sha256", key).update(s).digest());
export const randomId = (prefix: string, bytes = 12) => `${prefix}_${b64url(randomBytes(bytes))}`;

export type SigningKey = { privateKey: CryptoKey; publicJwk: JWK; kid: string };

/** Load an ES256 signing key from disk, creating it on first run. */
export async function loadOrCreateSigningKey(dir: string, name: string): Promise<SigningKey> {
  mkdirSync(dir, { recursive: true });
  const file = join(dir, `${name}.jwk.json`);
  let privateJwk: JWK;
  if (existsSync(file)) {
    privateJwk = JSON.parse(readFileSync(file, "utf8"));
  } else {
    const { privateKey } = await generateKeyPair("ES256", { extractable: true });
    privateJwk = { ...(await exportJWK(privateKey)), kid: randomId("key", 6), alg: "ES256" };
    writeFileSync(file, JSON.stringify(privateJwk), { mode: 0o600 });
  }
  const { d, ...publicJwk } = privateJwk;
  return {
    privateKey: (await importJWK(privateJwk, "ES256")) as CryptoKey,
    publicJwk: { ...publicJwk, use: "sig" },
    kid: privateJwk.kid!,
  };
}

/** Load or create a random secret (used for pairwise subject IDs). */
export function loadOrCreateSecret(dir: string, name: string): string {
  mkdirSync(dir, { recursive: true });
  const file = join(dir, `${name}.secret`);
  if (existsSync(file)) return readFileSync(file, "utf8").trim();
  const secret = b64url(randomBytes(32));
  writeFileSync(file, secret, { mode: 0o600 });
  return secret;
}
