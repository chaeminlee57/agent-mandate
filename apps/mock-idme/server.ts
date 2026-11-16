// A small OpenID Connect provider that stands in for the ID.me sandbox during local development.
// It speaks the same protocol the mandate service uses with the real thing: authorization code
// flow with PKCE, a signed id_token, and an attributes endpoint shaped like ID.me's.
import { Hono } from "hono";
import { serve } from "@hono/node-server";
import { html } from "hono/html";
import { SignJWT } from "jose";
import { DATA_DIR, IDP_URL, OIDC, port } from "../../shared/config.ts";
import { loadOrCreateSigningKey, randomId, sha256b64url } from "../../shared/crypto.ts";
import { page, THEMES } from "../../shared/ui.ts";

type Persona = {
  sub: string;
  fname: string;
  lname: string;
  email: string;
  birth_date: string;
  verified: boolean;
  groups: { group: string; subgroups: string[] }[];
};

// Test identities, like the sandbox's test users. None of these are real people.
export const PERSONAS: Persona[] = [
  {
    sub: "idme_test_jordan",
    fname: "Jordan",
    lname: "Rivera",
    email: "jordan.rivera@example.test",
    birth_date: "1990-04-12",
    verified: true,
    groups: [{ group: "military", subgroups: ["Veteran"] }],
  },
  {
    sub: "idme_test_sam",
    fname: "Sam",
    lname: "Okafor",
    email: "sam.okafor@example.test",
    birth_date: "2007-09-30",
    verified: true,
    groups: [{ group: "student", subgroups: ["Undergraduate"] }],
  },
  {
    sub: "idme_test_casey",
    fname: "Casey",
    lname: "Nguyen",
    email: "casey.nguyen@example.test",
    birth_date: "1985-01-20",
    verified: false,
    groups: [],
  },
];

const key = await loadOrCreateSigningKey(DATA_DIR, "mock-idme-signing");
const codes = new Map<string, { sub: string; nonce: string; challenge: string; redirectUri: string; authTime: number; exp: number }>();
const accessTokens = new Map<string, { sub: string; exp: number }>();

const app = new Hono();

app.get("/.well-known/openid-configuration", (c) =>
  c.json({
    issuer: IDP_URL,
    authorization_endpoint: `${IDP_URL}/oauth/authorize`,
    token_endpoint: `${IDP_URL}/oauth/token`,
    jwks_uri: `${IDP_URL}/oidc/.well-known/jwks`,
    response_types_supported: ["code"],
    code_challenge_methods_supported: ["S256"],
    id_token_signing_alg_values_supported: ["ES256"],
  }),
);

app.get("/oidc/.well-known/jwks", (c) => c.json({ keys: [key.publicJwk] }));

app.get("/oauth/authorize", (c) => {
  const q = c.req.query();
  if (q.client_id !== OIDC.clientId) return c.text("unknown client_id", 400);
  if (q.redirect_uri !== OIDC.redirectUri) return c.text("redirect_uri is not registered for this client", 400);
  if (q.response_type !== "code" || q.code_challenge_method !== "S256" || !q.code_challenge)
    return c.text("this provider requires response_type=code with PKCE (S256)", 400);
  const hidden = ["redirect_uri", "state", "nonce", "code_challenge"]
    .map((k) => html`<input type="hidden" name="${k}" value="${q[k] ?? ""}">`);
  return c.html(
    page(
      THEMES.idp,
      "Sign in",
      html`<h1>Choose a test identity</h1>
        <p class="muted">This page replaces the ID.me login and identity proofing steps. Pick who you are for this session.</p>
        ${PERSONAS.map(
          (p) => html`<form method="post" action="/oauth/authorize/decide" class="panel">
            ${hidden}<input type="hidden" name="sub" value="${p.sub}">
            <div class="row"><strong>${p.fname} ${p.lname}</strong>
              <span>${p.verified ? html`<span class="pill">IAL2 verified</span>` : html`<span class="pill off">Not verified</span>`}
              ${p.groups.map((g) => html` <span class="pill">${g.subgroups[0]}</span>`)}</span></div>
            <div class="small muted">Born ${p.birth_date} · ${p.email}</div>
            <div class="actions"><button type="submit" data-persona="${p.sub}">Continue as ${p.fname}</button></div>
          </form>`,
        )}`,
    ),
  );
});

app.post("/oauth/authorize/decide", async (c) => {
  const f = await c.req.parseBody();
  const persona = PERSONAS.find((p) => p.sub === f.sub);
  if (!persona) return c.text("unknown persona", 400);
  // Codes only ever go to the registered redirect URI, even if someone posts this form directly.
  if (f.redirect_uri !== OIDC.redirectUri) return c.text("redirect_uri is not registered for this client", 400);
  const code = randomId("code");
  codes.set(code, {
    sub: persona.sub,
    nonce: String(f.nonce ?? ""),
    challenge: String(f.code_challenge),
    redirectUri: String(f.redirect_uri),
    authTime: Math.floor(Date.now() / 1000), // this mock has no session of its own, so every sign-in is a fresh one
    exp: Date.now() + 60_000,
  });
  const to = new URL(String(f.redirect_uri));
  to.searchParams.set("code", code);
  to.searchParams.set("state", String(f.state ?? ""));
  return c.redirect(to.toString(), 302);
});

app.post("/oauth/token", async (c) => {
  const f = await c.req.parseBody();
  const entry = codes.get(String(f.code));
  codes.delete(String(f.code)); // codes are single use
  if (f.client_id !== OIDC.clientId || f.client_secret !== OIDC.clientSecret)
    return c.json({ error: "invalid_client" }, 401);
  if (!entry || entry.exp < Date.now() || entry.redirectUri !== f.redirect_uri)
    return c.json({ error: "invalid_grant" }, 400);
  if (sha256b64url(String(f.code_verifier ?? "")) !== entry.challenge)
    return c.json({ error: "invalid_grant", error_description: "PKCE check failed" }, 400);
  const persona = PERSONAS.find((p) => p.sub === entry.sub)!;
  const accessToken = randomId("at", 24);
  accessTokens.set(accessToken, { sub: persona.sub, exp: Date.now() + 300_000 });
  const idToken = await new SignJWT({ nonce: entry.nonce, email: persona.email, auth_time: entry.authTime })
    .setProtectedHeader({ alg: "ES256", kid: key.kid })
    .setIssuer(IDP_URL)
    .setAudience(OIDC.clientId)
    .setSubject(persona.sub)
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(key.privateKey);
  return c.json({ access_token: accessToken, token_type: "Bearer", expires_in: 300, id_token: idToken });
});

// Shaped like ID.me's attributes endpoint: a list of attributes and a list of verified groups.
app.get("/api/public/v3/attributes.json", (c) => {
  const token = c.req.header("authorization")?.replace(/^Bearer /, "") ?? "";
  const entry = accessTokens.get(token);
  if (!entry || entry.exp < Date.now()) return c.json({ error: "invalid_token" }, 401);
  const p = PERSONAS.find((x) => x.sub === entry.sub)!;
  return c.json({
    attributes: [
      { handle: "fname", name: "First Name", value: p.fname },
      { handle: "lname", name: "Last Name", value: p.lname },
      { handle: "email", name: "Email", value: p.email },
      { handle: "birth_date", name: "Birth Date", value: p.birth_date },
      { handle: "uuid", name: "Unique Identifier", value: p.sub },
    ],
    status: [
      { group: "identity", subgroups: ["IAL2"], verified: p.verified },
      ...p.groups.map((g) => ({ ...g, verified: true })),
    ],
  });
});

serve({ fetch: app.fetch, port: port(IDP_URL) }, () => console.log(`mock ID.me     ${IDP_URL}`));
