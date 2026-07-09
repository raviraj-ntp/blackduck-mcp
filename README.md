# Black Duck MCP

Local MCP server for **Synopsys Black Duck** — vulnerability triage, BOM inspection, policy compliance, and remediation (30+ tools).

- Runs on **your machine**
- **npm:** `@raviraj87/blackduck-mcp`
- **GitHub:** https://github.com/raviraj-ntp/blackduck-mcp

---

## Quick start

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

---

## Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `BLACKDUCK_URL` | Yes | Base URL only — no `/api/...` |
| `BLACKDUCK_API_TOKEN` | Yes | API token from Black Duck UI |
| `BLACKDUCK_NO_SSL_VERIFY` | No | Set `true` to skip TLS verification |
| `BLACKDUCK_WRITE_ENABLED` | No | Omit entirely for read-only (default). Set `true` only when you need live writes with `dryRun: false` |

Write tools default to **dry-run preview**. Omitting `BLACKDUCK_WRITE_ENABLED` is safe — the server starts normally and write tools preview changes without applying them. Set `BLACKDUCK_WRITE_ENABLED=true` and `dryRun: false` only when you intend to modify Black Duck.

---

## Tools (v1.1)

### Health & discovery
| Tool | Purpose |
|------|---------|
| `blackduck_health` | Connectivity check |
| `blackduck_current_user` | Authenticated user |
| `blackduck_list_projects` | Search/list projects |
| `blackduck_list_versions` | Versions by project **name** |
| `blackduck_resolve_project_version` | Name → IDs |
| `blackduck_get_project_versions` | Versions by project **ID** (legacy) |

### Vulnerabilities
| Tool | Purpose |
|------|---------|
| `blackduck_get_vulnerabilities` | Full CVE details + upgrade guidance |
| `blackduck_get_vulnerability_summary` | Severity counts + top 10 |
| `blackduck_get_component_detail` | Deep-dive one component |
| `blackduck_search_cve` | Find components by CVE |

### Policy & BOM
| Tool | Purpose |
|------|---------|
| `blackduck_get_policy_violations` | Violations with rule details |
| `blackduck_get_version_policy_status` | Quick policy status |
| `blackduck_list_bom_components` | Full BOM with filters |
| `blackduck_get_component_origins` | Match type (Maven/NPM/snippet) |
| `blackduck_get_bom_component_files` | Files that triggered match |
| `blackduck_get_snippet_matches` | All snippet detections |
| `blackduck_find_bad_mappings` | Flag suspicious mappings |
| `blackduck_list_scans` | Code locations / scan status |
| `blackduck_search_kb_component` | KB component search |

### Write / remediation
| Tool | Purpose |
|------|---------|
| `blackduck_set_component_usage` | Dev Tool / Excluded / etc. |
| `blackduck_set_component_license` | Fix license on BOM entry |
| `blackduck_set_component_version` | Point to KB version |
| `blackduck_bulk_mark_reviewed` | Clear review-policy violations |
| `blackduck_ignore_snippet` | False-positive snippet |
| `blackduck_update_package_json` | Patch local package.json from BD guidance |

### Escape hatches
| Tool | Purpose |
|------|---------|
| `blackduck_api_get` | Any GET endpoint |
| `blackduck_api_put` | Any PUT endpoint (write-gated) |
| `blackduck_list_project_components` | BOM by project+version ID |
| `blackduck_list_components` | Components by version ID |
| `blackduck_get_matched_files` | Matched-files URL/path |

---

## Typical workflow

1. `blackduck_list_projects` → pick project name
2. `blackduck_list_versions` → pick version
3. `blackduck_get_vulnerability_summary` → posture overview
4. `blackduck_get_vulnerabilities` → CVEs + upgrade guidance
5. `blackduck_update_package_json` (dry_run) → proposed fixes
6. `blackduck_bulk_mark_reviewed` → clear review policies after triage

---

## Verify

```bash
export BLACKDUCK_URL=https://blackduck.example.com
export BLACKDUCK_API_TOKEN=your-token
npm run build
npm run test:readonly
```

---

## License

MIT — Copyright © 2026 Ravi Raj
