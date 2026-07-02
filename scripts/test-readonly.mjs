import { BlackDuckClient } from "../dist/client.js";

const baseUrl = process.env.BLACKDUCK_URL;
const token = process.env.BLACKDUCK_API_TOKEN || process.env.BLACKDUCK_TOKEN;

if (!baseUrl || !token) {
  console.error("Missing BLACKDUCK_URL or BLACKDUCK_API_TOKEN/BLACKDUCK_TOKEN");
  process.exit(1);
}

const client = new BlackDuckClient(baseUrl, token);
const out = { ok: true, tests: [] };

async function run(name, fn) {
  try {
    const result = await fn();
    out.tests.push({ name, status: "ok", preview: summarize(result) });
  } catch (err) {
    out.ok = false;
    out.tests.push({ name, status: "fail", error: err instanceof Error ? err.message : String(err) });
  }
}

function summarize(data) {
  const s = JSON.stringify(data);
  return s.length > 500 ? `${s.slice(0, 500)}...` : s;
}

await run("blackduck_current_user", () => client.get("/api/current-user"));
await run("blackduck_list_projects", () =>
  client.get("/api/projects", { limit: 3, offset: 0 }),
);

console.log(JSON.stringify(out, null, 2));
process.exit(out.ok ? 0 : 1);
