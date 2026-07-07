# Black Duck MCP

Local **read-only** MCP server for **Synopsys Black Duck** — 8 tools for projects, versions, components, and security data.

- Runs on **your machine**
- **npm:** `@raviraj87/blackduck-mcp` — https://www.npmjs.com/package/@raviraj87/blackduck-mcp
- **GitHub:** https://github.com/raviraj-ntp/blackduck-mcp

---

## Quick start (npm — recommended)

Edit `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "blackduck": {
      "command": "npx",
      "args": ["-y", "@raviraj87/blackduck-mcp"],
      "env": {
        "BLACKDUCK_URL": "https://blackduck.example.com",
        "BLACKDUCK_API_TOKEN": "your-api-token"
      }
    }
  }
}
```

Restart Cursor. Ask: *"Use blackduck_health"*.

## Install from source (optional)

```bash
git clone https://github.com/raviraj-ntp/blackduck-mcp.git
cd blackduck-mcp
npm install
npm run build
```

Use `"command": "node"`, `"args": ["<<YOUR_CLONE_PATH>>/blackduck-mcp/dist/index.js"]` in `mcp.json`.

---

## What you customize on each machine

| What | Where | Notes |
|------|--------|-------|
| Server | `mcp.json` | **npm:** `npx` + `@raviraj87/blackduck-mcp` — **or** `node` + clone path |
| `BLACKDUCK_URL` | `env` | Base URL only — no `/api/...` |
| `BLACKDUCK_API_TOKEN` | `env` | From Black Duck UI |

---

## Get a Black Duck API token

1. Log in to Black Duck
2. User profile → **Access tokens** → create token
3. Set as `BLACKDUCK_API_TOKEN`

---

## Cursor setup

**npm (recommended):**

```json
{
  "mcpServers": {
    "blackduck": {
      "command": "npx",
      "args": ["-y", "@raviraj87/blackduck-mcp"],
      "env": {
        "BLACKDUCK_URL": "https://blackduck.example.com",
        "BLACKDUCK_API_TOKEN": "your-api-token"
      }
    }
  }
}
```

**From source:**

```json
"command": "node",
"args": ["<<YOUR_CLONE_PATH>>/blackduck-mcp/dist/index.js"]
```

Restart Cursor. Check **Settings → MCP** for 8 tools.

### URL format

```
✅ https://blackduck.example.com
❌ https://blackduck.example.com/api/projects
```

Auth: server exchanges your API token for a bearer token at startup (you only set `BLACKDUCK_API_TOKEN`).

---

## Verify

**Terminal:**

```bash
export BLACKDUCK_URL=https://blackduck.example.com
export BLACKDUCK_API_TOKEN=your-token
npm run test:readonly
```

**In Cursor:** *"List Black Duck projects with blackduck_list_projects"*

---

## Using tools

Typical flow:

1. `blackduck_list_projects` → project ID
2. `blackduck_get_project_versions` → version ID
3. `blackduck_list_project_components` → BOM / risk filters
4. `blackduck_api_get` → anything else (vulnerabilities, etc.)

| Tool | Purpose |
|------|---------|
| `blackduck_health` | Connectivity check |
| `blackduck_current_user` | Who am I |
| `blackduck_list_projects` | List projects (`limit`, `offset`, `q`) |
| `blackduck_get_project_versions` | Versions for a project |
| `blackduck_list_project_components` | BOM for project+version (`filter[]`, `sort`) |
| `blackduck_list_components` | Components by version ID |
| `blackduck_get_matched_files` | Matched files from API path |
| `blackduck_api_get` | Generic GET escape hatch |

---

## npm scripts

| Command | Purpose |
|---------|---------|
| `npm install` | Install dependencies |
| `npm run build` | Build `dist/` |
| `npm run dev` | Run with `tsx` (no build) |
| `npm run test:readonly` | Smoke test |

---

## Security

- Never commit `BLACKDUCK_API_TOKEN`.
- Read-only tools only — no create/update/delete.

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| Missing env variable | Add `BLACKDUCK_URL` and `BLACKDUCK_API_TOKEN` to `mcp.json` |
| 401 Unauthorized | Regenerate token |
| Empty project list | Check base URL and token permissions |
| Tools missing | Fix `args` path; `npm run build`; restart Cursor |

---

## Publishing (maintainers)

Repo: https://github.com/raviraj-ntp/blackduck-mcp · npm: `@raviraj87/blackduck-mcp`

```bash
git status
npm run build
git push origin main

npm whoami    # raviraj87
npm version patch    # required before republish
npm publish --access public
# 2FA: npm publish --access public --otp=XXXXXX
```

New GitHub repo: `gh repo create raviraj-ntp/blackduck-mcp --public --source=. --remote=origin --push`  
Remote (HTTPS): `https://github.com/raviraj-ntp/blackduck-mcp.git`
