// One place for every URL and port. Override any of them with environment variables.
const env = process.env;

export const IDP_URL = env.IDP_URL ?? "http://localhost:4000";
export const MANDATE_URL = env.MANDATE_URL ?? "http://localhost:4100";
export const STORE_URL = env.STORE_URL ?? "http://localhost:4200";

export const port = (url: string) => Number(new URL(url).port || 80);

// OIDC client settings for the identity provider. The defaults point at the local mock.
// To use the real ID.me sandbox, set these from your ID.me developer app (see README).
export const OIDC = {
  authorizeUrl: env.IDME_AUTHORIZE_URL ?? `${IDP_URL}/oauth/authorize`,
  tokenUrl: env.IDME_TOKEN_URL ?? `${IDP_URL}/oauth/token`,
  attributesUrl: env.IDME_ATTRIBUTES_URL ?? `${IDP_URL}/api/public/v3/attributes.json`,
  jwksUrl: env.IDME_JWKS_URL ?? `${IDP_URL}/oidc/.well-known/jwks`,
  issuer: env.IDME_ISSUER ?? IDP_URL,
  clientId: env.IDME_CLIENT_ID ?? "agent-mandate-dev",
  clientSecret: env.IDME_CLIENT_SECRET ?? "dev-secret-not-for-production",
  scope: env.IDME_SCOPE ?? "openid military student",
  redirectUri: `${MANDATE_URL}/oauth/callback`,
};

// Dev-only API key the demo store uses to call the mandate service. Seeded on startup.
export const DEMO_STORE_API_KEY = env.DEMO_STORE_API_KEY ?? "rp_dev_demo_store_key";

export const TOKEN_TTL_SECONDS = 600; // mandate tokens live 10 minutes
export const APPROVAL_TTL_SECONDS = 86400; // mandate requests and one-off purchase approvals must be used within a day
export const DATA_DIR = env.AGENT_MANDATE_DATA ?? new URL("../data/", import.meta.url).pathname;
