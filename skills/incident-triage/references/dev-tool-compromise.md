# Compromised Developer Machine (Dev-Tool Compromise)

Companion to `incident-triage`, for when a developer tool turns out to have been malicious: an IDE extension, an MCP
server, an npm `postinstall` script, a skill or a plugin. These compromises use a small set of persistence and access
patterns that generic triage doesn't look for: an attacker SSH key, a reverse tunnel, a user-level LaunchAgent or
scheduled task named after a vendor, a hidden script in `~/.config`.

The playbook comes first; this incident's IOCs follow. When a new incident lands, add a dated IOC section rather than
editing the playbook.

## 1. Is this machine in scope?

1. **Was the bad component installed during the window?** For an extension: the version folders on disk and the
   install time in `extensions.json` (`agent-supply-chain-audit`, IDE extensions). For npm: the lockfile, and the
   `~/.npm/_cacache` index times.
2. **Did it activate?** Was the IDE opened with the extension enabled? Most extensions activate when the IDE starts.
3. **Do any IOCs match?** Check the vendor's indicators (section 5). Cursor's rule for its incident: if the attacker
   key is present, the machine is affected.

## 2. Contain, before cleaning

Each step changes the machine: name it, and get the incident lead's or owner's go-ahead.

- **Cut the attacker's access.** Take the machine off the network, or block the command-and-control address at the
  host firewall.
- **Collect evidence before removing anything** (section 3). Uninstalling the extension isn't enough: the persistence
  runs on its own (Cursor), and removing files first destroys what scoping needs.
- **Rotate from a different, clean machine.** Everything the affected machine could reach: GitHub tokens and SSH keys,
  cloud credentials, `.env` secrets in open repos, npm or PyPI publish tokens, browser sessions. When a payload sends
  only the *names* of credential variables, the values weren't taken, but the attacker now knows which credentials to
  go after. Rotate those first (`secrets-audit`).

## 3. Evidence and IOC sweep (read-only)

**macOS and Linux**

```bash
# SSH backdoor: an attacker key in authorized_keys
grep -n '<key comment from the IOC list>' ~/.ssh/authorized_keys 2>/dev/null
ssh-keygen -lf ~/.ssh/authorized_keys 2>/dev/null        # fingerprints, to compare with the published one
ls -la ~/.ssh/                                            # a laptop with any authorized_keys file is itself a lead
# Persistence
ls -la ~/Library/LaunchAgents/                            # com.apple.* labels in a USER LaunchAgents folder are suspicious
launchctl list | grep -i -E 'sysmon|com\.apple\.'
defaults read ~/Library/LaunchAgents/<label>.plist 2>/dev/null
crontab -l 2>/dev/null | grep -n '@reboot'
systemctl --user list-unit-files 2>/dev/null
# Remote access turned on?
sudo systemsetup -getremotelogin                          # macOS, needs admin: ask
systemctl is-active sshd ssh 2>/dev/null                  # Linux
# A live tunnel or beacon
ps -axo pid,ppid,lstart,command | grep -E 'ssh .*-R|autossh' | grep -v grep
lsof -nPi | grep -E '<IOC address>|:<IOC port>'
```

**Windows (PowerShell)**

```powershell
Select-String -Path "$HOME\.ssh\authorized_keys","C:\ProgramData\ssh\administrators_authorized_keys" -Pattern '<key comment>' -ErrorAction SilentlyContinue
Get-ScheduledTask -TaskName '<task name>' -ErrorAction SilentlyContinue | Format-List *
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" -ErrorAction SilentlyContinue
Get-WindowsCapability -Online -Name OpenSSH.Server* | Select-Object Name, State
Get-Service sshd -ErrorAction SilentlyContinue
Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match '-R .*localhost:22' } | Select-Object ProcessId, CommandLine
```

**Network and EDR:** outbound connections to the IOC address and ports. Save every command's output under
`<incident dir>/evidence/` with the time it ran.

## 4. Scope beyond the one machine

- **Fleet:** which other machines installed the component? Use MDM software inventory, `extensions.json` across
  managed devices, or ask each developer to run the check and report only "found" or "not found".
- **A reverse tunnel means inbound access** if it came up and something was listening on the forwarded port. If the
  tunnel connected to a running SSH server, the attacker had a shell on the machine. Treat every repo, credential and
  session on it as exposed, and check the git history of repos pushed from it after the install time.
- **Downstream:** did anyone push code, publish a package or deploy from the machine after the install? Hand that to
  `cicd-security` and `patch-sweep`.

## 5. Eradicate and recover (hand-off notes)

- Run the vendor's remediation script, if there is one, as the vendor says. Treat a non-zero exit as "not clean".
- **Rebuild** when the attacker may have had interactive access. Cursor says to assess whether to rebuild; analysts
  recommend rebuilding whenever the backdoor had any chance of interactive access.
- Put remote access back the way it was: turn Remote Login off again if it was off before
  (`sudo systemsetup -setremotelogin off`), and remove the OpenSSH Server capability on Windows if it wasn't there.
- Update or remove the component, and check the version you move to against the vendor notice.

---

## IOCs: malicious `Anthropic.claude-code` in Cursor's marketplace (2026-10-29)

Source of truth: [Cursor's security notice](https://cursor.com/blog/claude-code-extension-security-notice), updated
2026-10-30 11:30 PT ("We updated the IOCs and clarified affected versions"). Supporting analysis:
[Threat Landscape](https://threatlandscape.io/blog/trojanized-claude-code-extension-2-1-313-ssh-backdoor) and
[BleepingComputer](https://www.bleepingcomputer.com/news/security/malicious-claude-code-extension-on-cursor-planted-ssh-backdoors/).
Re-read the notice before relying on this list; vendors update IOCs.

**What and when.** `Anthropic.claude-code` versions **2.1.312 and 2.1.313** from Cursor's extension marketplace, for
Windows and macOS, available from about 02:27 to 13:35 PT on October 29, 2026. Not built by Anthropic. Sources
disagree on 2.1.312: Cursor lists it as malicious, Threat Landscape calls it clean. Use Cursor's list. Cursor's IOCs
include Linux artifacts too. Cursor says the attacker's server no longer works; its host took it down.

**What it did.** A block of code prepended to `extension.js` ran on activation. It collected the hostname, user, OS,
home and working directories, git email, public IP, and the **names** (not values) of environment variables
containing KEY, TOKEN, SECRET, PASS, AWS or GCP. It appended an attacker SSH key to `authorized_keys`, tried to turn on
the SSH server, opened a reverse SSH tunnel, and set up persistence. Per Cursor, turning on SSH failed unless Cursor
ran with admin rights, because of bugs in the malicious code. So the tunnel led to a shell only where an SSH server was
already running.

| Kind | Indicator |
|---|---|
| Network | `134[.]209[.]82[.]225`: reverse SSH as user `tunnel` on TCP 22, and HTTP POST to port 8099 `/beacon`. Also a loopback beacon to `127.0.0.1:8099/beacon`. Lookups to `ifconfig.me` / `api.ipify.org` aren't an indicator on their own |
| SSH key | Comment `svc-telemetry` in `authorized_keys` (Windows: also `C:\ProgramData\ssh\administrators_authorized_keys`); fingerprint `SHA256:0Z6R+DF64Do2nwQic8a7kkfDLNNk4IiK+2U2Rci4htk`. Reverse-tunnel key fingerprint `SHA256:KOAU57+ZG6u3MG4WwzPzPX2O5YEe9qdOC1Bl+6MVyDQ` |
| Files (macOS, Linux) | `~/.config/.smt`, `~/.config/.smtk`; `$TMPDIR/.stk_<10 hex>` (macOS), `/tmp/.stk_<10 hex>` (Linux) |
| Files (Windows) | `%USERPROFILE%\.config\smt.cmd`, `%USERPROFILE%\.config\smtk`, `%TEMP%\.stk_<10 hex>` |
| Persistence | macOS LaunchAgent `~/Library/LaunchAgents/com.apple.sysmond.plist` (label `com.apple.sysmond`); Windows scheduled task `SysMon`, fallback `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\sysmon.cmd`; Linux cron `@reboot /bin/sh "<HOME>/.config/.smt"` |
| `extension.js` | SHA-256 `ecb58cb29078d9646ad1dcdbe51526f2d9cfea06be5fb2ab183e8ecc3ab6bf15` (both versions and platforms) |
| VSIX | 2.1.312 darwin-arm64 `fcbb327e38e61c4fec795e0d0591f52cd1014b813d20a5912104953c3a17c364`, win32-x64 `3de1722901165769893bef57c72594e9a54459faa23f3091b136b79966edd081`; 2.1.313 darwin-arm64 `80402fdcad8799285fd93044976973ca000da7995fb93363f819bb8e4f84ee6c`, win32-x64 `6786ec90cbd45949695bd7805c9fbb26cfc91bc5fc897de0183d9bcb9cb21731` |

Quick check on macOS:

```bash
grep -qs svc-telemetry ~/.ssh/authorized_keys && echo "AFFECTED: attacker key present"
ls -d ~/.cursor/extensions/anthropic.claude-code-2.1.31[23]-* 2>/dev/null
shasum -a 256 ~/.cursor/extensions/anthropic.claude-code-2.1.31[23]-*/dist/extension.js 2>/dev/null
ls ~/Library/LaunchAgents/com.apple.sysmond.plist ~/.config/.smt ~/.config/.smtk 2>/dev/null
```

**Remediation (Cursor).** `remediate-macos.sh` runs as the affected user, not root (`bash remediate-macos.sh`).
`remediate-windows.ps1` runs from PowerShell opened as Administrator
(`powershell -ExecutionPolicy Bypass -File .\remediate-windows.ps1`). Both exit non-zero if anything remains. Cursor
also says to isolate affected hosts, search telemetry for the IOCs, rotate credentials and sessions from a trusted
system, and assess whether to rebuild. Threat Landscape says to confirm the installed version is 2.1.314 or later;
Cursor doesn't name a fixed version. The npm package and the Visual Studio Marketplace build were not reported as
affected.
