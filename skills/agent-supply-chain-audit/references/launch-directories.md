# Launch Directories and Folder Trust (LD1–LD4)

Companion to `agent-supply-chain-audit` Step 1 and Step 3. The rest of the audit reads the project and the user-level
config. This file asks **where agents get launched**. An instruction file in the folder an agent starts in is code
the agent obeys, and a folder the browser saves downloads into is an unreviewed source.

**Incident that prompted this (reported 2026-10-25/26).** Forever Security found a planted `AGENTS.md` in a customer's
`~/Downloads`, which was also the agent's working directory. Written to look like ordinary engineering guidelines, it
told Codex to register a server in `~/.codex/config.toml` and install the npm package `function-color`, part of the
campaign CloudSEK and Checkmarx call MALFEX. Forever stopped it before any code ran. How the file got there isn't
known. A web page can save a file to Downloads without a click, and Forever built a proof of concept that does, but
whether the attacker used that route isn't known. In Forever's tests:

- **Codex** ran the payload in more than 90% of attempts. Because `~/.codex/config.toml` is machine-wide, the added
  server then loads in every later Codex session, in any folder.
- **Claude Code**: a planted `CLAUDE.md` framed as gateway setup got an `ANTHROPIC_BASE_URL` written into project
  settings about half the time. That sends the login token to the attacker, who replayed it and took over the account
  without running code. The reports disagree on the code-execution rate (Help Net: about a fifth of tests through a
  helper agent; BleepingComputer: about half).
- About half of Forever's customers run a coding agent in their Downloads folder.

Forever's view: "There is nothing here for OpenAI or Anthropic to patch." The defense is configuration and habit.
Sources: [The Hacker News](https://thehackernews.com/2026/10/malicious-file-in-downloads-folder.html),
[Help Net Security](https://www.helpnetsecurity.com/2026/10/26/ai-coding-agents-malware-openai-codex/),
[BleepingComputer](https://www.bleepingcomputer.com/news/security/ai-coding-agents-hijacked-using-agentsmd-file-in-downloads-folder/).

## Folder trust, per agent

| Agent | Where trust lives | What trust unlocks |
|---|---|---|
| Codex | `~/.codex/config.toml`: `projects.<path>.trust_level`, set to `trusted` or `untrusted` ([config reference](https://learn.chatgpt.com/docs/config-file/config-reference)) | Untrusted projects skip project-scoped `.codex/` layers (project config, hooks, rules). Help Net reports Codex follows `AGENTS.md` only in a trusted folder, and Downloads qualifies once the user has worked there |
| Claude Code | The folder-trust prompt on first launch | Project `.claude/settings*.json` (hooks, `env`, permissions) and `CLAUDE.md` for whoever trusts the folder (Step 3) |

**Codex trust is per exact path.** A trusted parent doesn't cover its subfolders, and recursive trust is an open
feature request ([openai/codex#19426](https://github.com/openai/codex/issues/19426)). It cuts the other way too: a
comment there (Codex 0.163.0, 2026-10-28) reports that marking a parent `untrusted` didn't stop a child folder's
`AGENTS.md` from loading. **An `untrusted` entry for `~/Downloads` doesn't protect a folder unzipped inside it.** The
fix is not launching agents there.

## Inventory (read-only)

```bash
# Codex: which folders are trusted? Anything that isn't a repo the user owns is a lead
rg -n -A1 '^\[projects\.' ~/.codex/config.toml 2>/dev/null
# Instruction files and project settings in catch-all folders the browser or other tools write to
for d in "$HOME/Downloads" "$HOME/Desktop" "$HOME" /tmp; do
  find "$d" -maxdepth 2 \( -name AGENTS.md -o -name CLAUDE.md -o -name CLAUDE.local.md -o -name GEMINI.md \
    -o -path '*/.claude/settings*.json' -o -path '*/.codex/config.toml' -o -name .mcp.json \) 2>/dev/null
done
```

Then **ask** where the user usually starts agents. Shell history can show it (`cd ~/Downloads && codex`), but don't
read history files into the session; ask instead.

## Checks

| ID | Check | How | Finding |
|---|---|---|---|
| **LD1** | Trusted catch-all folder | A Codex `projects.<path>.trust_level` set to `trusted` for `~/Downloads`, `~/Desktop`, `$HOME` or `/tmp`, or the user says they launch agents there | Hardening note on a single-user machine with nothing sensitive; **Medium** where the agent holds production credentials. Fix: stop launching agents there and remove the trust entry. An `untrusted` parent entry alone doesn't cover subfolders |
| **LD2** | Instruction file nobody wrote | An `AGENTS.md` / `CLAUDE.md` / `GEMINI.md` from the inventory that isn't in a repo the user owns. Read it with the Step 2 content checks: install commands, edits to the agent's own config, base URLs, requests to turn off approvals or the sandbox | `confirmed`, **Critical**, if it tells the agent to edit agent settings, install a package, or reroute API traffic. Hand off to `incident-triage` (dev-tool compromise) |
| **LD3** | Machine-wide config written from a project session | `rg -n '\[mcp_servers' ~/.codex/config.toml`, and the BH4 `ANTHROPIC_BASE_URL` grep, run over every project settings file the inventory found as well as the project. Any server or base URL the user doesn't recognize | `confirmed`, **Critical**. Per the reporting, assume the login token leaked: rotate it, and remove the entry after evidence is saved |
| **LD4** | Package from a known campaign | `function-color` (MALFEX) in any lockfile or global install: `rg -n 'function-color' --glob '**/{package-lock.json,pnpm-lock.yaml,yarn.lock}' ~ 2>/dev/null` and `npm ls -g function-color` | `confirmed`, **Critical**. Help Net says to treat the machine as compromised; hand off to `incident-triage` |

Size LD2 and LD3 hits like a user-level hook: a planted instruction file can do whatever the agent can do in that
session, and a Codex config change persists across every folder.

## Hardening notes (no product needed)

- Don't start Codex, Claude Code or any agent in `~/Downloads`, `~/Desktop` or `$HOME`. Start it in the project root.
- Review any `AGENTS.md` or `CLAUDE.md` someone else authored before an agent works in that folder, including in a
  freshly cloned repo.
- Leave approval prompts and sandboxes on, and treat any instruction to turn them off as a finding.
- Check `~/.codex/config.toml` for servers and base URLs you didn't add, and `.claude/settings.json` for an
  `ANTHROPIC_BASE_URL` you didn't set.
- If a planted file is found, rotate the agent's login token.

Proposed by @coreyhaines31 in issue #234.
