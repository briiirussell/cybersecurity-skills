# IDE Extensions (EX1–EX6)

Companion to `agent-supply-chain-audit` Step 1 and Step 4. IDE extensions are a larger supply chain than MCP servers,
and a more trusted one. Every extension runs in the extension host with the user's full privileges. It can read every
open repo and `.env` file and start processes, and it usually activates when the IDE opens. Auto-update turns a
marketplace compromise into same-day code execution on every developer machine that has the extension.

**Incident that prompted this (2026-10-29):** malicious `Anthropic.claude-code` 2.1.312 and 2.1.313 in **Cursor's**
extension marketplace, for about 11 hours (02:27–13:35 PT). Code prepended to `extension.js` collected host details
and the *names* of credential-looking environment variables, added an attacker SSH key, tried to turn on SSH, opened a
reverse SSH tunnel, and set up persistence. It was not built by Anthropic. Source:
[Cursor's security notice](https://cursor.com/blog/claude-code-extension-security-notice), updated 2026-10-30 11:30 PT.
Cursor lists both versions as malicious; Threat Landscape's analysis names only 2.1.313. Go with the vendor notice.
IOCs and the response playbook are in `incident-triage` (dev-tool compromise).

The lesson for this audit: **the same "official" extension id can be a different build in a different marketplace.**
Pinning by name isn't enough.

## Inventory

| IDE | Extensions folder | Marketplace it pulls from |
|---|---|---|
| Cursor | `~/.cursor/extensions/` | Cursor's own marketplace |
| VS Code | `~/.vscode/extensions/` | Visual Studio Marketplace |
| VS Code Insiders | `~/.vscode-insiders/extensions/` | Visual Studio Marketplace |
| Windsurf | `~/.windsurf/extensions/` | Open VSX by default |
| VSCodium | `~/.vscode-oss/extensions/` | Open VSX |
| Remote, WSL and SSH sessions | `~/.vscode-server/extensions/`, `~/.cursor-server/extensions/` **on the remote host** | As the local IDE |
| JetBrains | `~/Library/Application Support/JetBrains/<IDE>/plugins/` (macOS); `META-INF/plugin.xml` per plugin | JetBrains Marketplace |

Each extensions folder has an `extensions.json` registry. Read it without starting the IDE:

```bash
for d in ~/.cursor ~/.vscode ~/.vscode-insiders ~/.windsurf ~/.vscode-oss; do
  f="$d/extensions/extensions.json"; [ -f "$f" ] || continue
  jq -r --arg ide "$(basename "$d")" '.[] | [$ide, .identifier.id, .version, (.metadata.source // "-"),
    (.metadata.publisherDisplayName // "-"), ((.metadata.installedTimestamp // 0) / 1000 | todate)] | @tsv' "$f"
done
# Every version folder on disk, including old ones the registry no longer lists
ls ~/.cursor/extensions ~/.vscode/extensions 2>/dev/null | grep -v '^extensions.json$'
```

`metadata.source` is `gallery` for a marketplace install and `vsix` for a manually installed package. **Inventory every
version folder**, not just the registry's current entry. IDEs keep previous versions on disk after an update, so a
malicious build can still be there after the IDE moved on. `cursor --list-extensions --show-versions` and
`code --list-extensions --show-versions` give the same list but start the IDE's CLI, so they prompt.

Record per extension: **id**, **version** (and every older folder), **IDE and marketplace**, **publisher**, **install
time**, **source** (`gallery` / `vsix`), **auto-update on?**, and **what it can run**. For every extension, "what it can
run" is the user's full access.

## Checks

| ID | Check | How | Finding |
|---|---|---|---|
| **EX1** | Known-bad version on disk | Match id and version, across every version folder, against vendor notices. Start with `anthropic.claude-code` 2.1.312 and 2.1.313 (Cursor). Compare the `extension.js` hash with the published IOC | `confirmed`, **Critical**. Hand off to `incident-triage` now, before cleaning anything |
| **EX2** | Auto-update on for high-privilege extensions | `extensions.autoUpdate` and `extensions.autoCheckUpdates` in the IDE's user `settings.json` (`~/Library/Application Support/<Code\|Cursor>/User/settings.json` on macOS). Unset means on | Hardening note for low-reach extensions. **Medium** for agent or AI extensions on a machine that holds production credentials. Turning updates off without someone reviewing them just leaves old versions, so pair it with a review cadence |
| **EX3** | Marketplace divergence | Is the extension installed from a different marketplace than the publisher's main one (Cursor or Open VSX vs the Visual Studio Marketplace)? | Note. Get first-party agent integrations from the vendor's own channel. For Claude Code, that's the CLI from npm or the native installer, which installs its IDE integration |
| **EX4** | Prepended or obfuscated activation code | Read the start of `dist/extension.js` or `out/extension.js` (the first few KB). Look for code before the bundler banner, `child_process`, `authorized_keys`, `launchctl`, `schtasks`, `ssh -R`, `/beacon`, long base64 blobs. The patterns in [content-checks.md](content-checks.md) apply | `confirmed` if present. Size it as EX1 |
| **EX5** | Unverified publisher or typosquat | Publisher id isn't the vendor's, a near-miss name, few installs, published recently | `needs_validation` |
| **EX6** | No extension policy | Is there a reviewed allowlist (VS Code `extensions.allowed`, managed settings or MDM) and a recommended list in `.vscode/extensions.json`? | Hardening note, feeding the team's policy |

Don't run or activate an extension to test it, and don't uninstall one during the audit. An EX1 or EX4 hit is
evidence for `incident-triage`, which decides when to clean up.

## Severity

Size extension findings like a **user-level hook that runs every time the IDE opens**: an EX1 or EX4 hit is Critical.
An unreviewed high-privilege extension on auto-update, on a machine with production access, is Medium. Fingerprint:
`agent-supply-chain-audit:EX1:<ide>:<extension id>@<version>` (for example
`agent-supply-chain-audit:EX1:cursor:anthropic.claude-code@2.1.313`). User-level paths go in `findings.user.json`.

## Sources

- [Cursor security notice](https://cursor.com/blog/claude-code-extension-security-notice) (affected versions, window,
  IOCs, remediation scripts)
- [Threat Landscape analysis](https://threatlandscape.io/blog/trojanized-claude-code-extension-2-1-313-ssh-backdoor);
  [BleepingComputer](https://www.bleepingcomputer.com/news/security/malicious-claude-code-extension-on-cursor-planted-ssh-backdoors/)
- VS Code docs: extension auto-update settings and `extensions.allowed`
- Proposed by @coreyhaines31 in issue #222
