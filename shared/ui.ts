import { html, raw } from "hono/html";

export type Theme = { app: string; accent: string; tint: string; note?: string };

export const THEMES = {
  idp: { app: "Mock ID.me", accent: "#4a5568", tint: "#eef1f5", note: "Local stand-in for the ID.me sandbox" },
  mandate: { app: "Agent Mandates", accent: "#0f6e56", tint: "#e6f4ef" },
  store: { app: "Demo Store", accent: "#b4501f", tint: "#fbefe8", note: "A fake shop that accepts agent mandates" },
} satisfies Record<string, Theme>;

const css = (t: Theme) => `
:root{--accent:${t.accent};--tint:${t.tint};--text:#1d1f23;--muted:#62666d;--line:#e3e5e8;--bg:#fafaf9;--danger:#b42318}
@media (prefers-color-scheme:dark){:root{--text:#ecedee;--muted:#a1a5ab;--line:#2c2f33;--bg:#141518;--tint:color-mix(in srgb,${t.accent} 22%,#141518)}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:16px/1.6 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
header{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:14px 20px;border-bottom:1px solid var(--line)}
.brand{font-weight:600;color:var(--accent);text-decoration:none}.note{color:var(--muted);font-size:13px}
main{max-width:760px;margin:0 auto;padding:28px 20px 64px}
h1{font-size:26px;line-height:1.25;margin:0 0 8px}h2{font-size:18px;margin:32px 0 10px}
p{margin:0 0 12px}.muted{color:var(--muted)}.small{font-size:14px}
.panel{background:var(--tint);border-radius:12px;padding:18px 20px;margin:16px 0}
.row{display:flex;justify-content:space-between;align-items:baseline;gap:16px;padding:10px 0}
.row+.row{margin-top:2px}.k{color:var(--muted);font-size:14px}.v{text-align:right}
button,.btn{font:inherit;font-weight:600;border:0;border-radius:8px;padding:10px 16px;cursor:pointer;background:var(--accent);color:#fff;text-decoration:none;display:inline-block}
button.ghost,.btn.ghost{background:transparent;color:var(--accent);box-shadow:inset 0 0 0 1px var(--accent)}
button.danger{background:transparent;color:var(--danger);box-shadow:inset 0 0 0 1px var(--danger)}
.actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:18px}
input[type=number],input[type=text]{font:inherit;padding:8px 10px;border:1px solid var(--line);border-radius:8px;background:transparent;color:inherit;width:120px}
label.check{display:flex;gap:10px;align-items:center;padding:6px 0}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px}
.pill{display:inline-block;font-size:12px;font-weight:600;padding:2px 8px;border-radius:99px;background:var(--tint);color:var(--accent)}
.pill.off{color:var(--muted);background:transparent;box-shadow:inset 0 0 0 1px var(--line)}
.pill.bad{color:var(--danger);background:transparent;box-shadow:inset 0 0 0 1px var(--danger)}
.item{padding:14px 0}.item+.item{border-top:0}
.err{color:var(--danger);font-size:14px;margin-top:10px;min-height:1em}
.bar{height:8px;border-radius:99px;background:var(--line);overflow:hidden;margin:6px 0 2px}.bar>i{display:block;height:100%;background:var(--accent)}
`;

export function page(t: Theme, title: string, body: unknown, opts: { right?: unknown; scripts?: string[] } = {}) {
  return html`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title} · ${t.app}</title><style>${raw(css(t))}</style></head>
<body><header><div><a class="brand" href="/">${t.app}</a>${t.note ? html` <span class="note">· ${t.note}</span>` : ""}</div><div>${opts.right ?? ""}</div></header>
<main>${body}</main>
${raw((opts.scripts ?? []).map((s) => `<script src="${s}"></script>`).join(""))}
</body></html>`;
}

export const usd = (cents: number) =>
  (cents / 100).toLocaleString("en-US", { style: "currency", currency: "USD" });

export const ago = (unix: number) => {
  const s = Math.max(1, Math.floor(Date.now() / 1000) - unix);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
};
