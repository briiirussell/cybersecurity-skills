# Bundled Browser Runtimes (RT1)

Companion to `agent-supply-chain-audit` Step 1 and Step 4. The audit already checks how each extension is pinned. This
file checks what an extension **launches**. Browser-automation MCP servers and CLIs bring a full Chromium, and that
browser:

- runs attacker-controlled content by design (every page the agent visits),
- is downloaded once and never updates itself,
- can run with the macOS Accessibility permission of the app that launched it,
- and stays frozen longer the better RP1 is followed, because pinning the server also pins its Chromium.

## Recognize browser-launching extensions

| Extension | How to recognize it | Where its browser lives |
|---|---|---|
| `@playwright/mcp` and anything on `playwright` / `playwright-core` | `command` / `args` mention `playwright`; `package.json` dependencies | `~/Library/Caches/ms-playwright/chromium-<rev>` (macOS), `~/.cache/ms-playwright` (Linux), or `PLAYWRIGHT_BROWSERS_PATH` |
| Puppeteer-based servers | Dependencies on `puppeteer` / `puppeteer-core` | `~/.cache/puppeteer/chrome/<platform>-<version>`, or the `cacheDirectory` config |
| `agent-browser` (CLI and skill) | `agent-browser` in skills, commands or allowed Bash | Its own Chrome for Testing download, or an existing Chrome, Brave, Playwright or Puppeteer install. `--executable-path` / `AGENT_BROWSER_EXECUTABLE_PATH` / `~/.agent-browser/config.json` set it explicitly |
| `chrome-devtools-mcp` | MCP `args` | The installed Chrome by default, which updates itself. Old only when `--executablePath` points at a cached build or `--channel` pins one |
| Skills or plugins that say "run `npx playwright install`" or similar | Grep their SKILL.md and commands | As Playwright |
| Computer-use and desktop-control servers | Tool names such as `screenshot`, `click`, `type_text` | No browser, but they **hold Accessibility themselves**. Record it: it's the permission an escaped browser would use |
| Remote browser services (Browserbase, hosted Playwright) | A `url` server, or an API key for the service | Not on this machine. Out of scope for RT1; the vendor's patch cadence is a `third_party_dependency` condition, not a finding |

```bash
M=".mcp.json .cursor/mcp.json .vscode/mcp.json $HOME/.claude.json $HOME/.cursor/mcp.json $HOME/.gemini/settings.json"
rg -n -i 'playwright|puppeteer|agent-browser|chrome-devtools-mcp|browserbase|stagehand|chromium|executablePath|executable-path|--channel' $M \
  "$HOME/Library/Application Support/Claude/claude_desktop_config.json" $HOME/.codex/config.toml 2>/dev/null
rg -l -i 'playwright|puppeteer|agent-browser|chromium' ~/.claude/skills .claude/skills ~/.claude/plugins .agents/skills 2>/dev/null
```

Record the result in the inventory's **Runtime** column: `—`, `node`, `python`, `chromium <version>`,
`system Chrome`, or `electron <version>`.

## RT1 — the bundled browser is behind

Find the Chromium version each browser-launching extension actually starts. The inventory loop in `personal-opsec`
(`references/local-checks.md`, "Agent browser runtimes") reads every cached build's version without running it. Compare
against Chrome for Testing stable:
`https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions.json` (`.channels.Stable.version`).

| State | Verdict and severity |
|---|---|
| Below the fix for a **known-exploited or sandbox-escape** Chromium CVE, browses arbitrary or untrusted URLs (research, scraping, following links, prompt-driven navigation), **and** launched from an app with Accessibility | `confirmed`, **High**, condition `third_party_dependency` |
| Same, untrusted URLs, no Accessibility in the chain | `confirmed`, **Medium** |
| Same, only loads localhost or the user's own previews | `confirmed`, **Low** |
| More than 2 majors behind stable, no specific CVE | `needs_validation`. Blocker: "which renderer CVEs fixed since `<version>` are public". Settle it from the Chrome release notes for each major in between |

Whether the launching app holds Accessibility comes from `personal-opsec` C7, or from asking the user. Listing TCC
grants needs Full Disk Access, so don't try to read them.

**Evidence:** the binary path, its version, the CVE if any, the extension that launches it, and the launching app.
Save the inventory output under `<audit dir>/evidence/` and point `location` at it.

## Pinning and runtime age together (RP1 and RT1)

For a browser-launching extension, a pin needs an update budget:

> Pin the package (RP1) **and** give it a runtime age budget (RT1). A pinned browser server is a commitment to update
> it on purpose. Once its bundled Chromium is more than one major behind stable, bumping the pin is a security update,
> not a feature change.

Record the pin date in the inventory, so the next audit can see how old the pin is. Following RP1 to the letter
without this leaves the most exposed component, a browser running untrusted content, permanently out of date.

## Settings that pick the browser binary (BH4)

`PLAYWRIGHT_BROWSERS_PATH`, `PUPPETEER_EXECUTABLE_PATH`, `AGENT_BROWSER_EXECUTABLE_PATH`, and `--executablePath` /
`--executable-path` in MCP `args` redirect which binary runs. In an `env` block of settings or MCP config, treat them
like the other BH4 rerouting keys: record the target path and check its version under RT1. A path into the repo, `/tmp`
or another writable shared folder is a separate finding: anyone who can write there can swap the binary.

## Fixing

Hand the update to the tool's own updater (the table in `personal-opsec`'s local checks), delete old builds, and
restart sessions, since a running browser keeps the old binary in memory. For the fleet response when a Chrome CVE
lands across repos, CI images and production renderers, use `patch-sweep`.

## Sources

- Chrome for Testing availability JSON (`googlechromelabs.github.io/chrome-for-testing`)
- Playwright "Browsers" docs (cache paths, `PLAYWRIGHT_BROWSERS_PATH`); Puppeteer configuration docs (`cacheDirectory`);
  agent-browser README (browser detection, `--executable-path`)
- Example of the bug class: CVE-2026-106378, a macOS GPU-process sandbox escape fixed in Chrome 155
  ([pwn.ai write-up](https://pwn.ai/blog/chrome-escape))
- Proposed by @coreyhaines31 in issue #218
