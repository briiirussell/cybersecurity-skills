# MCP client (MC1–MC3)

Loaded from `agent-supply-chain-audit` Step 4. Read-only.

The editor that talks to those servers is part of the same supply chain. VS Code 1.145.3 (10 November 2026) fixes a
cluster where the editor trusted an MCP server, an install link, or a workspace file and ran a command with the
user's permissions. None are reported exploited in the wild, and none are in CISA KEV. Forks (Cursor, Windsurf,
VSCodium, and others) get the fixes only when they ship a rebased build. Which forks have done so was not confirmed
on 2026-11-11; check each vendor's release notes.

**MC1 — client version.** List each editor that loads MCP servers, and its version:

```bash
code --version 2>/dev/null | head -1
cursor --version 2>/dev/null | head -1
windsurf --version 2>/dev/null | head -1
codium --version 2>/dev/null | head -1
# macOS app bundles, when the CLIs are not on PATH
defaults read "/Applications/Visual Studio Code.app/Contents/Info" CFBundleShortVersionString 2>/dev/null
```

- VS Code below 1.145.3 (affects 1.145.2 and older) → finding **high**. Patch. The highest is CVE-2026-120779 (CNA CVSS 9.6, E:U): MCP elicitation notification text could become a command link ([GHSA-66hq-jw93-462h](https://github.com/microsoft/vscode/security/advisories/GHSA-66hq-jw93-462h)). The same release also fixes CVE-2026-114171 (install-link RCE, CVSS 8.8), CVE-2026-119983 (legacy SSE RCE, CVSS 8.8), CVE-2026-119985 (network workspace trust bypass, CVSS 8.3), and CVE-2026-120780 (serve-web downgrade, CVSS 8.3).
- A fork → **needs_validation** until that vendor's release notes name the upstream VS Code version or the fix it includes. Record the fork version and the upstream base it reports.

**MC2 — legacy SSE transport.** CVE-2026-119983 is in the legacy SSE transport. Flag entries that use `"type": "sse"` or an `/sse` URL. Suggest Streamable HTTP, or turning the server off until the client is patched. On a client below 1.145.3 this is part of the MC1 high. On a patched client it is a hardening note.

```bash
rg -n '"type"\s*:\s*"sse"|/sse["/]' .vscode/mcp.json .cursor/mcp.json ~/.cursor/mcp.json "$HOME/Library/Application Support/Code/User/mcp.json" 2>/dev/null
```

**MC3 — install links and network workspaces.** Anti-patterns, recorded as hardening notes unless a link was already approved:
- Approving a one-click MCP install link without reading the displayed command and inputs (CVE-2026-114171).
- Opening an HTTP(S) workspace file from an untrusted source (CVE-2026-119985). Workspace settings can name MCP servers that start a process.
