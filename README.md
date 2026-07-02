# Black Duck MCP

A local **Model Context Protocol (MCP) server** that lets AI assistants (Cursor, Claude Desktop, etc.) query **Synopsys Black Duck** for projects, versions, components, and security data.

**Read-only** — this server does not create, modify, or delete anything in Black Duck.

This repository is **standalone** — clone or publish this folder by itself.

**License:** MIT

---

## Table of contents

- [What does this do?](#what-does-this-do)
- [Who is this for?](#who-is-this-for)
- [How it works](#how-it-works)
- [Prerequisites](#prerequisites)
- [Installation (step by step)](#installation-step-by-step)
- [Getting a Black Duck API token](#getting-a-black-duck-api-token)
- [Configuration](#configuration)
- [Connect to Cursor](#connect-to-cursor)
- [Verify it works](#verify-it-works)
- [Using the tools](#using-the-tools)
- [Tool reference](#tool-reference)
- [npm scripts](#npm-scripts)
- [Security](#security)
- [Troubleshooting](#troubleshooting)
- [Project layout](#project-layout)
- [Publishing](#publishing)

---

## What does this do?

Black Duck tracks open-source components and security risk in your software. This MCP server exposes **8 read-only tools** so an AI can:

- List projects and versions
- Inspect bill-of-materials (BOM) components
- Query matched files and vulnerabilities (via generic GET)
- Verify API connectivity

Instead of the AI guessing Black Duck REST paths, it calls tools like `blackduck_list_projects` and `blackduck_list_project_components`.

---

## Who is this for?

- Security engineers reviewing component risk with AI assistance
- Developers using **Cursor** who need Black Duck data in context
- Teams that want read-only, safe access to Black Duck from chat

---

## How it works

```
┌─────────────┐    stdio     ┌────────────────┐    HTTPS    ┌─────────────┐
│ Cursor / AI │ ◄──────────► │ blackduck-mcp  │ ◄─────────► │ Black Duck  │
│   client    │  (local)     │ (this server)  │  (your net) │ (your org)  │
└─────────────┘              └────────────────┘             └─────────────┘
```

1. Cursor starts the server locally.
2. You ask about projects, components, or vulnerabilities.
3. The server calls Black Duck with your API token.
4. JSON results go back to the AI.

All credentials stay on your machine.

---

## Prerequisites

| Requirement | Details |
|-------------|---------|
| **Node.js 20+** | `node --version` |
| **Black Duck** | Synopsys Black Duck Hub (on-prem or hosted) |
| **API token** | See below |
| **Network** | Reach `BLACKDUCK_URL` from your machine |

---

## Installation (step by step)

### 1. Clone and build

```bash
git clone https://github.com/ravi-netapp/blackduck-mcp.git
cd blackduck-mcp
npm install
npm run build
```

### 2. Get an API token

See [Getting a Black Duck API token](#getting-a-black-duck-api-token).

### 3. Configure Cursor

See [Connect to Cursor](#connect-to-cursor).

---

## Getting a Black Duck API token

Steps vary slightly by Black Duck version; typically:

1. Log in to Black Duck in your browser.
2. Open your **user profile** or **access tokens** settings.
3. Create a new **API access token**.
4. Copy the token — set it as `BLACKDUCK_API_TOKEN`.

Your Black Duck admin can confirm the exact menu path for your deployment.

---

## Configuration

### Environment variables

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `BLACKDUCK_URL` | **Yes** | Base URL of your Black Duck server | `https://blackduck.example.com` |
| `BLACKDUCK_API_TOKEN` | **Yes** | API access token | (from Black Duck UI) |

**URL format:** Use the host only — no `/api/...` path, no trailing slash.

```
✅ https://blackduck.example.com
❌ https://blackduck.example.com/api/projects
```

Authentication header sent by this server:

```
Authorization: token <BLACKDUCK_API_TOKEN>
```

### Local env file (optional)

```bash
cp .env.example .env.local
# Edit values — .env.local is gitignored
export BLACKDUCK_URL=https://blackduck.example.com
export BLACKDUCK_API_TOKEN=your-token
```

---

## Connect to Cursor

### 1. Edit MCP config

Open `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "blackduck": {
      "command": "node",
      "args": ["/absolute/path/to/blackduck-mcp/dist/index.js"],
      "env": {
        "BLACKDUCK_URL": "https://blackduck.example.com",
        "BLACKDUCK_API_TOKEN": "your-api-token"
      }
    }
  }
}
```

Replace `/absolute/path/to/blackduck-mcp` with your actual clone path.

### 2. Restart Cursor

Quit and reopen. **Settings → MCP** should list `blackduck` with 8 tools.

### Dev mode (optional)

```json
"command": "npx",
"args": ["tsx", "/absolute/path/to/blackduck-mcp/src/index.ts"]
```

---

## Verify it works

### Terminal smoke test

```bash
export BLACKDUCK_URL=https://blackduck.example.com
export BLACKDUCK_API_TOKEN=your-token
npm run build
npm run test:readonly
```

Expect `"ok": true` in the JSON output.

### In Cursor

Ask:

> Use `blackduck_health` to verify Black Duck connectivity.

> List my Black Duck projects with `blackduck_list_projects`.

---

## Using the tools

### Typical workflow

1. **`blackduck_list_projects`** — find project names and IDs
2. **`blackduck_get_project_versions`** — pick a version ID for a project
3. **`blackduck_list_project_components`** — inspect BOM / security filters
4. **`blackduck_api_get`** — anything else (vulnerabilities, policies, etc.)

### Pagination

List tools support `limit` and `offset`:

```json
{ "limit": 25, "offset": 0 }
```

Increase `offset` to page through large result sets.

### Filtering components

`blackduck_list_project_components` accepts repeated filters:

```json
{
  "projectId": "abc-123",
  "versionId": "def-456",
  "filter": ["securityRisk:high", "licenseRisk:medium"],
  "sort": "securityRisk DESC"
}
```

### Example prompts in Cursor

| You ask | Tool the AI may use |
|---------|---------------------|
| "What Black Duck projects exist?" | `blackduck_list_projects` |
| "Components in project X version Y" | `blackduck_list_project_components` |
| "High-risk components in release 2.0" | `blackduck_list_project_components` with filters |
| "Vulnerabilities for this version" | `blackduck_api_get` with vulnerabilities path |

---

## Tool reference

| Tool | What it does | Main parameters |
|------|--------------|-----------------|
| `blackduck_health` | Quick connectivity check (calls current-user API) | — |
| `blackduck_current_user` | Show who the token authenticates as | — |
| `blackduck_list_projects` | List all projects you can access | `limit`, `offset`, `q` (search) |
| `blackduck_get_project_versions` | Versions under one project | `projectId`, `limit`, `offset` |
| `blackduck_list_project_components` | BOM components for a project version | `projectId`, `versionId`, `filter[]`, `sort` |
| `blackduck_list_components` | Components by global version ID | `versionId`, `limit`, `offset` |
| `blackduck_get_matched_files` | Files matched to a component | `matchedFilesPathOrUrl` from API response |
| `blackduck_api_get` | **Escape hatch** — any GET endpoint | `path`, `limit`, `offset`, `q`, `sort`, `filter[]` |

### Example tool inputs

**List first 10 projects:**

```json
{ "limit": 10, "offset": 0 }
```

**Search projects by name:**

```json
{ "q": "name:my-app" }
```

**High-security-risk components:**

```json
{
  "projectId": "abc123",
  "versionId": "def456",
  "filter": ["securityRisk:high"],
  "limit": 50
}
```

**Vulnerabilities via generic GET:**

```json
{
  "path": "/api/projects/abc123/versions/def456/vulnerabilities",
  "limit": 100
}
```

**Matched files (path from a prior API response):**

```json
{
  "matchedFilesPathOrUrl": "/api/components/xyz/matched-files",
  "limit": 100
}
```

---

## npm scripts

| Command | When to use |
|---------|-------------|
| `npm install` | First time setup |
| `npm run build` | Compile TypeScript → `dist/` |
| `npm run start` | Run server manually |
| `npm run dev` | Development without building |
| `npm run typecheck` | Verify types only |
| `npm run test:readonly` | Smoke test against live Black Duck |

---

## Security

- **Never commit** `BLACKDUCK_API_TOKEN` to git.
- `.env.local` is gitignored — use it for local secrets.
- **Read-only tools only** — no write/delete operations exposed.
- Use a token with **read** scope appropriate for your role.
- Traffic goes directly from your machine to your Black Duck instance.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `Missing required environment variable` | Env not in `mcp.json` | Add `BLACKDUCK_URL` and `BLACKDUCK_API_TOKEN` |
| 401 Unauthorized | Invalid or expired token | Regenerate token in Black Duck |
| Empty project list | Wrong URL or no access | Verify base URL; check token permissions |
| SSL errors | Corporate proxy/cert | May need Node cert config for your org |
| Tools not in Cursor | Server not starting | Check absolute path; run `npm run build`; restart Cursor |
| `Cannot find module` | Not built | Run `npm install && npm run build` |

---

## Project layout

```
blackduck-mcp/
├── src/
│   ├── index.ts       # MCP tool registrations
│   └── client.ts      # Black Duck HTTP client
├── scripts/
│   └── test-readonly.mjs
├── .env.example
├── package.json
├── LICENSE
├── PUBLISHING.md
└── dist/              # Built output (npm run build; gitignored)
```

---

## Publishing

This folder is a complete GitHub repository. See [PUBLISHING.md](./PUBLISHING.md).
