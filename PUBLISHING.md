# Publishing this repository

This is a **standalone** repository. It has no dependency on sibling MCP projects.

## Before you push

```bash
git status
```

Must **not** be committed (in `.gitignore`): `node_modules/`, `dist/`, `.env`, `.env.local`, API tokens.

## GitHub CLI (recommended)

```bash
brew install gh
gh auth login

git init
git add .
git commit -m "Initial commit: Black Duck MCP server"
gh repo create blackduck-mcp --public --source=. --remote=origin --push
```

## Without GitHub CLI

1. Create empty repo `blackduck-mcp` on GitHub.
2. From this directory:

```bash
git init
git add .
git commit -m "Initial commit: Black Duck MCP server"
git branch -M main
git remote add origin git@github.com:ravi-netapp/blackduck-mcp.git
git push -u origin main
```

## After publishing

- `npm install && npm run build` in the clone
- Update Cursor `mcp.json` with the new path
- Topics: `mcp`, `blackduck`, `security`, `cursor`
