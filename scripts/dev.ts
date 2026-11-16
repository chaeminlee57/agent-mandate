// Start the mock ID.me, the mandate service, and the demo store together.
import { spawn } from "node:child_process";

const apps = [
  ["idp", "apps/mock-idme/server.ts"],
  ["mandate", "apps/mandate/server.ts"],
  ["store", "apps/store/server.ts"],
] as const;

const children = apps.map(([name, file]) => {
  const child = spawn(process.execPath, ["--no-warnings", file], { stdio: ["ignore", "pipe", "pipe"], env: process.env });
  const tag = `[${name}]`.padEnd(10);
  for (const stream of [child.stdout, child.stderr])
    stream.on("data", (d: Buffer) => d.toString().trimEnd().split("\n").forEach((l) => console.log(tag, l)));
  child.on("exit", (code) => { console.log(tag, `exited (${code})`); process.exitCode = code ?? 1; });
  return child;
});

const stop = () => { children.forEach((c) => c.kill()); process.exit(); };
process.on("SIGINT", stop);
process.on("SIGTERM", stop);
