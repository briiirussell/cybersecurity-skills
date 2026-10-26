# Agent extension locations — where to look, per agent

Paths move between releases. Treat this as a starting list, glob for anything nearby, and record what you actually
found rather than what this table predicts. `~` is the user's home directory; "project" means the repo root and,
where the agent walks up the tree, every parent and nested directory too.

## Claude Code

| Scope | Path | What it is | Runs code? |
|---|---|---|---|
| Project | `CLAUDE.md`, `CLAUDE.local.md`, `.claude/CLAUDE.md`, nested `**/CLAUDE.md` | Instruction files loaded into context | No, but they steer every tool call |
| Project | `.claude/settings.json`, `.claude/settings.local.json` | Permissions, `defaultMode`, hooks, `env`, `apiKeyHelper`, `statusLine`, MCP enablement | **Yes** (hooks, helper keys) |
| Project | `.claude/skills/*/SKILL.md` (+ `scripts/`, `references/`) | Project skills | Bundled scripts can |
| Project | `.claude/commands/**/*.md`, `.claude/agents/*.md` | Slash commands, subagents (can carry their own `allowed-tools`) | Via the tools they pre-approve |
| Project | `.mcp.json` | Project MCP servers (`command`/`args`/`env`, or `url`/`headers`) | **Yes** |
| Plugin | `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json`, `hooks/hooks.json`, plugin `skills/`, `commands/`, `agents/`, `.mcp.json` | Plugin manifest and everything it bundles | **Yes** |
| User | `~/.claude/CLAUDE.md`, `~/.claude/settings.json` | User-wide instructions and settings | **Yes** (hooks) |
| User | `~/.claude/skills/`, `~/.claude/commands/`, `~/.claude/agents/` | User-level extensions, active in every project | Via scripts / tools |
| User | `~/.claude/plugins/` (installed plugins, `marketplaces/`, marketplace and install registries) | Installed plugins and the marketplaces they came from | **Yes** |
| User | `~/.claude.json` | User and per-project `mcpServers`, approval state | **Yes** |
| User | `~/.claude/projects/*/memory/` (where present) | Persistent memory files reloaded into later sessions | No, but a persistence target (MP1) |
| Managed | macOS `/Library/Application Support/ClaudeCode/`, Linux `/etc/claude-code/` (`managed-settings.json`, `managed-mcp.json`) | Org-enforced settings; override user and project | **Yes** |
| Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` (Windows `%APPDATA%\Claude\`) | Claude Desktop MCP servers; desktop extension bundles carry their own `manifest.json` | **Yes** |

## Cross-agent skill folders

| Scope | Path | Notes |
|---|---|---|
| Project | `.agents/skills/*/SKILL.md` | Where `npx skills add` installs for agents that read the shared folder. This catalog installs here. |
| Project / user | `AGENTS.md` (root and nested), `~/.codex/AGENTS.md` | Read by Codex, Cursor, Copilot, Gemini (when configured) and others |

## Cursor

| Scope | Path | Runs code? |
|---|---|---|
| Project | `.cursor/rules/*.mdc` (frontmatter `alwaysApply`, `globs`), legacy `.cursorrules` | No — instructions |
| Project | `.cursor/mcp.json` | **Yes** |
| Project | `.cursor/hooks.json` (where present), `.cursor/commands/` | **Yes** (hooks) |
| User | `~/.cursor/mcp.json`, `~/.cursor/hooks.json` | **Yes** |
| User | User Rules and auto-run / allowlist settings live in the app's settings UI | Ask the user to export or screenshot |
| User | `~/.cursor/extensions/` | VS Code-style extensions — a separate, larger supply chain |

## Codex (OpenAI)

| Scope | Path | Runs code? |
|---|---|---|
| Project / user | `AGENTS.md`, `AGENTS.override.md`, `~/.codex/AGENTS.md` | No — instructions |
| User | `~/.codex/config.toml` — `[mcp_servers.<name>]` (`command`, `args`, `env`), `approval_policy`, `sandbox_mode`, `[shell_environment_policy]`; project `.codex/config.toml` where supported | **Yes** |
| User | `~/.codex/prompts/*.md`, `~/.codex/skills/` (recent versions) | Via the tools they invoke |

## Gemini CLI

| Scope | Path | Runs code? |
|---|---|---|
| Project / user | `GEMINI.md` (root, ancestors, nested), `~/.gemini/GEMINI.md`, or whatever `contextFileName` points at | No — instructions |
| Project / user | `.gemini/settings.json`, `~/.gemini/settings.json` — `mcpServers`, tool allow/exclude lists, auto-approve settings | **Yes** |
| Project / user | `.gemini/commands/*.toml`, `~/.gemini/commands/` | Via shell-injection syntax in prompts |
| User | `~/.gemini/extensions/*/gemini-extension.json` — bundles MCP servers, context files and commands | **Yes** |

## GitHub Copilot (VS Code and the coding agent)

| Scope | Path | Runs code? |
|---|---|---|
| Project | `.github/copilot-instructions.md`, `.github/instructions/*.instructions.md` | No — instructions |
| Project | `.github/prompts/*.prompt.md`, `.github/chatmodes/*.chatmode.md`, `.github/agents/*.agent.md` | Via the tools they list |
| Project | `.vscode/mcp.json` | **Yes** |
| User | VS Code user `settings.json` — `mcp` servers, tool auto-approve settings | **Yes** |
| Repo settings | Coding-agent MCP config (repo Settings UI) and `.github/workflows/copilot-setup-steps.yml` | **Yes**, in CI |

## Others worth a glob

Windsurf (`.windsurfrules`, `.windsurf/rules/`, `~/.codeium/windsurf/mcp_config.json`), Cline / Roo (`.clinerules`,
`.roo/`), Continue (`~/.continue/config.*`), Zed (`settings.json` `context_servers`). Same checks apply.

## One-shot discovery

Project scope (hidden and gitignored files included, `node_modules` skipped):

```bash
rg --files --hidden -uu -g '!node_modules' -g '!.git' \
  -g '{CLAUDE,AGENTS,GEMINI}.md' -g 'CLAUDE.local.md' -g 'AGENTS.override.md' -g 'SKILL.md' \
  -g '.mcp.json' -g 'mcp.json' -g 'mcp_config.json' -g 'claude_desktop_config.json' \
  -g '.cursorrules' -g '.windsurfrules' -g '.clinerules' -g '*.mdc' \
  -g 'copilot-instructions.md' -g '*.instructions.md' -g '*.prompt.md' -g '*.chatmode.md' -g '*.agent.md' \
  -g 'settings.json' -g 'settings.local.json' -g 'hooks.json' -g 'plugin.json' -g 'marketplace.json' \
  -g 'gemini-extension.json' -g 'config.toml'
```

Portable fallback:

```bash
find . -path ./node_modules -prune -o -path ./.git -prune -o -type f \( \
  -name 'CLAUDE.md' -o -name 'CLAUDE.local.md' -o -name 'AGENTS.md' -o -name 'GEMINI.md' -o -name 'SKILL.md' \
  -o -name '.mcp.json' -o -name 'mcp.json' -o -name '*.mdc' -o -name '.cursorrules' \
  -o -name 'copilot-instructions.md' -o -name '*.instructions.md' -o -name '*.prompt.md' \
  -o -name 'settings.json' -o -name 'settings.local.json' -o -name 'hooks.json' \
  -o -name 'plugin.json' -o -name 'marketplace.json' -o -name 'gemini-extension.json' \) -print
```

User scope: run the same `rg --files` against `~/.claude ~/.claude.json ~/.cursor ~/.codex ~/.gemini` (and the
Desktop / managed paths above), skipping transcript and cache folders (`~/.claude/projects/*/*.jsonl`,
`~/.codex/sessions`, `~/.gemini/tmp`) — those are a `secrets-audit` concern, not extensions.

## Recording the pin

For every item, record where it came from and what version is installed:

| Source | What counts as a pin |
|---|---|
| Git-installed skill / plugin / marketplace | A commit SHA (a tag is movable; a branch is not a pin) |
| `npx` / `bunx` / `pnpm dlx` MCP server | `pkg@1.2.3` exact version, ideally with a lockfile or integrity hash |
| `uvx` / `uv tool run` / `pip` | `pkg==1.2.3` |
| Docker MCP server | `image@sha256:…` (a numeric tag is weaker; `latest` or no tag is unpinned) |
| Remote (`url`) MCP server | Cannot be pinned — the vendor can change tools at any time; record it as such |
| Hand-written / vendored file | Note the commit it was last changed in (`git log -1 --format=%H -- <path>`) |
