/**
 * Black Duck MCP smoke tests (read-only by default).
 */
import { BlackDuckClient } from "../dist/client.js";
import { loadConfig } from "../dist/config.js";

const config = loadConfig();
const client = new BlackDuckClient(config);
const out = { ok: true, tests: [] as { name: string; status: string; preview?: string; error?: string }[] };

async function run(name: string, fn: () => Promise<unknown>) {
  try {
    const result = await fn();
    const s = JSON.stringify(result);
    out.tests.push({ name, status: "ok", preview: s.length > 500 ? `${s.slice(0, 500)}...` : s });
  } catch (err) {
    out.ok = false;
    out.tests.push({ name, status: "fail", error: err instanceof Error ? err.message : String(err) });
  }
}

await run("blackduck_current_user", () => client.get("/api/current-user"));
await run("blackduck_list_projects", () => client.get("/api/projects", { limit: 3, offset: 0 }));

console.log(JSON.stringify(out, null, 2));
process.exit(out.ok ? 0 : 1);
