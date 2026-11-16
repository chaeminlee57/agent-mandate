// The mandate service: issues key-bound, scoped, revocable mandates for AI agents on behalf of
// people who signed in with ID.me. See README.md for the full design.
import { Hono } from "hono";
import { serve } from "@hono/node-server";
import { MANDATE_URL, port } from "../../shared/config.ts";
import { api } from "./api.ts";
import { portal } from "./portal.ts";

const app = new Hono();
// No page here may be framed by another site, so the passkey buttons can't be clickjacked.
app.use("*", async (c, next) => {
  await next();
  c.header("X-Frame-Options", "DENY");
  c.header("Content-Security-Policy", "frame-ancestors 'none'");
});
app.route("/", api);
app.route("/", portal);
app.onError((err, c) => {
  console.error(err);
  return c.json({ error: "server_error", error_description: err.message }, 500);
});

serve({ fetch: app.fetch, port: port(MANDATE_URL) }, () => console.log(`mandate service ${MANDATE_URL}`));
