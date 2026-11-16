// Interactive walkthrough. Run `npm run dev` in one terminal and this in another.
// The script plays the agent; you play the person in the browser when it hands you a link.
import { AgentClient } from "../packages/agent/client.ts";
import { DATA_DIR, MANDATE_URL, STORE_URL } from "../shared/config.ts";
import { join } from "node:path";
import { createInterface } from "node:readline/promises";

const agent = await AgentClient.load({ home: join(DATA_DIR, "demo-agent"), name: "Claude", issuers: [MANDATE_URL] });
const rl = createInterface({ input: process.stdin, output: process.stdout });
const say = (s: string) => console.log(`\n\x1b[1m${s}\x1b[0m`);
const show = (r: { status: number; body: unknown }) => console.log(`  HTTP ${r.status}`, JSON.stringify(r.body, null, 2).replace(/\n/g, "\n  "));
const pause = () => rl.question("  (press enter to continue) ");
const checkout = (sku: string, key: string, approval?: string) =>
  agent.fetch(`${STORE_URL}/api/agent/checkout`, { method: "POST", body: { items: [{ sku }] }, headers: { "idempotency-key": key, ...(approval ? { "agent-approval": approval } : {}) } });

say(`Agent key fingerprint: ${agent.keyFingerprint}`);
say("1. Claude asks you for a mandate at the Demo Store");
const req = await agent.requestMandate({ site: STORE_URL, purpose: "Buy desk gear for your new apartment", maxTotalUsd: 150, perPurchaseUsd: 100, days: 7 });
console.log(`  Open this link, sign in, and approve:\n  ${req.approve_url}`);
const rec = await agent.waitForMandate(STORE_URL, 600_000);
console.log(`  Mandate ${rec.status}: ${rec.mandate_id ?? ""}`);
if (rec.status !== "approved") process.exit(1);

say("2. The store sees a verified human, not a name");
show(await agent.fetch(`${STORE_URL}/api/agent/whoami`));
await pause();

const run = Date.now().toString(36);
say("3. A purchase inside your limits goes straight through");
show(await checkout("kb-mech", `${run}-1`));
await pause();

say("4. Something over the limit comes back to you");
const big = await checkout("hp-anc", `${run}-2`);
show(big);
if (big.status === 402) {
  console.log(`\n  Approve it here: ${big.body.approval_url}`);
  const s = await agent.waitForApproval(STORE_URL, big.body.approval_id, 600_000);
  console.log(`  You ${s} it. Retrying with the approval...`);
  show(await checkout("hp-anc", `${run}-2`, big.body.approval_id));
}
await pause();

say("5. A stolen token is useless without the agent's key");
const token = await agent.token(STORE_URL);
const stolen = await fetch(`${STORE_URL}/api/agent/whoami`, { headers: { authorization: `DPoP ${token}` } });
console.log(`  HTTP ${stolen.status}`, await stolen.text());
await pause();

say("6. Now revoke the mandate in the portal, then press enter");
await pause();
show(await checkout("cable-usbc", `${run}-3`));
rl.close();
