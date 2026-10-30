# Personal OpSec — Local Read-Only Checks by OS

Every command here only reports state. None changes a setting. Run what applies, report the one-line result of each, and map it to the control ID in `SKILL.md`. Commands not in the skill's `allowed-tools` will prompt for permission — that's expected; explain what each does before running it.

## macOS

| Control | Command | What "good" looks like |
|---|---|---|
| OS currency | `sw_vers` | Current or previous major macOS with recent point updates |
| K5 disk encryption | `fdesetup status` | `FileVault is On.` |
| Inbound firewall | `/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate` | `Firewall is enabled. (State = 1)` (hardening note if off) |
| Stealth mode | `/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode` | `Firewall stealth mode is on` (hardening note) |
| Gatekeeper | `spctl --status` | `assessments enabled` |
| SIP | `csrutil status` | `System Integrity Protection status: enabled.` |
| K14 DNS | `scutil --dns` | Resolvers belong to the chosen filtering/private provider, or a DoH/DoT configuration profile is installed (System Settings → Privacy & Security → Profiles — ask the user) |
| K1 PM CLI | `which op bw lpass keepassxc-cli` | At least one present (presence ≠ configured) |
| C5 GitHub token | `gh auth status` | Token stored in the system keyring, not a plaintext file; scopes no broader than needed |

Apps (Glob, no shell): `/Applications/*.app` — look for the password manager, Signal, the chosen browser, VPN client, outbound firewall (Little Snitch, LuLu), clipboard managers.

## Windows (PowerShell; some need an elevated prompt — ask before elevating)

| Control | Command | Good |
|---|---|---|
| OS currency | `Get-ComputerInfo -Property OsName, OsVersion` | Supported release with current updates |
| K5 disk encryption | `manage-bde -status` (elevated) or `Get-BitLockerVolume` | OS volume `Protection On`, `Fully Encrypted` |
| Firewall | `Get-NetFirewallProfile \| Select Name, Enabled` | All profiles `True` |
| Defender / Smart App Control | `Get-MpComputerStatus \| Select AntivirusEnabled, RealTimeProtectionEnabled` | Both `True` (or another AV is managing) |
| K14 DNS | `Get-DnsClientServerAddress -AddressFamily IPv4` | Resolvers match the chosen provider |
| K1 PM CLI | `Get-Command op, bw -ErrorAction SilentlyContinue` | Present |

## Linux

| Control | Command | Good |
|---|---|---|
| K5 disk encryption | `lsblk -o NAME,TYPE,FSTYPE,MOUNTPOINT` | Root (and home) sit on a `crypt` device / `crypto_LUKS` partition |
| Firewall | `ufw status` or `nft list ruleset` (may need sudo — ask) | Default-deny inbound |
| K14 DNS | `resolvectl status` | Upstream resolvers / DoT match the chosen provider |
| K1 PM CLI | `which op bw keepassxc-cli` | Present |

## AI-agent layer (all OSes)

Existence and permissions only — never open these files.

```text
Glob:   ~/.aws/credentials  ~/.aws/config  ~/.config/gh/hosts.yml  ~/.npmrc  ~/.netrc
        ~/.docker/config.json  ~/.pypirc  ~/.kube/config  ~/.ssh/id_*
        ~/.config/gcloud/application_default_credentials.json
        ~/.claude.json  ~/.claude/settings.json  ~/.cursor/mcp.json
        ~/Library/Application Support/Claude/claude_desktop_config.json
        <projects dir>/**/.env*  <projects dir>/**/.mcp.json
ls -l:  each credential-file hit — flag anything group/world readable (should be -rw------- / 600)
Grep:   output_mode=count only
        pattern (sk-ant-|sk_live_|ghp_|github_pat_|AKIA|xox[baprs]-)
        files   ~/.zshrc ~/.bashrc ~/.zprofile ~/.zsh_history ~/.bash_history and the MCP config files
Grep:   output_mode=count, pattern sso_session|sso_start_url, file ~/.aws/config   (SSO in use = better)
```

Portable equivalent for the user to run themselves, still count-only:

```bash
grep -cE '(sk-ant-|sk_live_|ghp_|github_pat_|AKIA|xox[baprs]-)' ~/.zshrc ~/.zsh_history 2>/dev/null
```

A non-zero count is enough to raise the finding. Don't open the file to "confirm" — the user can rotate and clean it.

## Agent browser runtimes (C7)

Every Chromium that an agent tool downloaded, with its version, oldest first. On macOS the version comes from the
app bundle (`defaults read`, which runs nothing). A headless shell or a Linux `chrome` has no bundle, so its version
needs `--version`, which runs the binary; that call prompts.

```bash
for r in "$HOME/Library/Caches/ms-playwright" "$HOME/.cache/ms-playwright" "${PLAYWRIGHT_BROWSERS_PATH:-}" \
         "$HOME/.cache/puppeteer" "$HOME/.agent-browser" "$HOME/Library/Caches/Cypress" "$HOME/.cache/Cypress" \
         "$HOME/.cache/selenium"; do
  [ -n "$r" ] && [ -d "$r" ] || continue
  find "$r" -maxdepth 5 \( -name "*.app" -o -name chrome -o -name chrome-headless-shell -o -name headless_shell \) -prune 2>/dev/null |
  while read -r p; do
    if [ -d "$p" ]; then v=$(defaults read "$p/Contents/Info" CFBundleShortVersionString 2>/dev/null)
    else v=$("$p" --version 2>/dev/null | grep -Eo '[0-9]+(\.[0-9]+){3}'); fi
    printf '%s\t%s\n' "${v:-unknown}" "$p"
  done
done | sort -t. -k1,1n
# Current Chrome for Testing stable (what a fresh `playwright install` would pull)
curl -s https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions.json | jq -r .channels.Stable.version
```

- Playwright's WebKit build shows up as `Playwright.app` with version `1.0`; skip it, it isn't Chromium.
- Puppeteer puts the version in the folder name (`~/.cache/puppeteer/chrome/mac_arm-<version>/`), so the folder list
  is enough.
- agent-browser can use its own download, or an existing Chrome, Brave, Playwright or Puppeteer install. Its docs
  don't say where the download goes, so the loop searches `~/.agent-browser`; check `~/.agent-browser/config.json`
  and `AGENT_BROWSER_EXECUTABLE_PATH` for an explicit path.
- **Project-local browsers** the loop misses: Glob `**/node_modules/playwright-core/.local-browsers/*` (installed with
  `PLAYWRIGHT_BROWSERS_PATH=0`) and `**/node_modules/puppeteer*/.local-chromium/*` (old Puppeteer). These come back on
  every `npm ci` at whatever version the lockfile pins, so the fix belongs to `dependency-audit`.
- Windows: `%USERPROFILE%\AppData\Local\ms-playwright` and `%USERPROFILE%\.cache\puppeteer`. Read the version from
  the folder name, or from the `chrome.exe` file properties.

Which builds are running right now (an old build that's live is worse than one on disk):

```bash
pgrep -fl 'Chrome for Testing|chrome-headless-shell|Chromium' | awk '{print $2}' | sort | uniq -c
```

**Accessibility, Input Monitoring and Screen Recording grants.** Listing them needs Full Disk Access, so from a normal
shell the TCC database query fails with `authorization denied`. **Ask** the user to open System Settings → Privacy &
Security → Accessibility (then Input Monitoring and Screen Recording) and read out what's enabled. Don't ask them to
grant Full Disk Access for the audit; that widens the very access this control is about. The apps that matter are
the ones that launch browsers: Terminal, iTerm, Warp, Ghostty, Cursor, VS Code, Windsurf, Zed, the Claude desktop
app, Raycast or Alfred, and any automation helper.

### Updating each runtime

| Tool | Update | Clean old builds |
|---|---|---|
| Playwright | Upgrade `playwright` / `@playwright/test` in the project, then `npx playwright install chromium` | Playwright removes builds no installed version needs (unless `PLAYWRIGHT_SKIP_BROWSER_GC=1`). `npx playwright uninstall --all` removes every Playwright browser |
| Puppeteer | Upgrade `puppeteer`, then `npx puppeteer browsers install chrome` | `npx @puppeteer/browsers clear` |
| agent-browser | `agent-browser upgrade` (detects npm, Homebrew or Cargo), then `agent-browser install` | `agent-browser doctor --fix` can reinstall Chrome; delete older downloads once sessions are closed |
| `@playwright/mcp` and other MCP browser servers | Pin a current version in the MCP config, then run its install step | As Playwright |
| `chrome-devtools-mcp` | Uses the installed Chrome by default, which updates itself. Check `--executablePath` / `--channel` in the MCP config | — |

A running browser keeps the old binary in memory, so restart its sessions after updating. Closing sessions can
interrupt other agents that are running, so the user does that, not the audit.
