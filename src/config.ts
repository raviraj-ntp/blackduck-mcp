export type BlackDuckConfig = {
  url: string;
  apiToken: string;
  verifySsl: boolean;
  writeEnabled: boolean;
};

function envFlag(name: string, defaultValue = false): boolean {
  const v = process.env[name];
  if (v === undefined || v.trim() === "") return defaultValue;
  const normalized = v.trim().toLowerCase();
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  return ["1", "true", "yes", "on"].includes(normalized);
}

export function loadConfig(): BlackDuckConfig {
  const url = process.env.BLACKDUCK_URL;
  const apiToken = process.env.BLACKDUCK_API_TOKEN ?? process.env.BLACKDUCK_TOKEN;
  if (!url) throw new Error("Missing required environment variable: BLACKDUCK_URL");
  if (!apiToken) {
    throw new Error("Missing required environment variable: BLACKDUCK_API_TOKEN (or BLACKDUCK_TOKEN)");
  }
  return {
    url: url.replace(/\/+$/, ""),
    apiToken,
    verifySsl: !envFlag("BLACKDUCK_NO_SSL_VERIFY"),
    // Optional — omitted or "false" both mean read-only writes (dry-run still works).
    writeEnabled: envFlag("BLACKDUCK_WRITE_ENABLED", false),
  };
}
