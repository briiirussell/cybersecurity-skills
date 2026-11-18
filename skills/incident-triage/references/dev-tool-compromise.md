# Compromised Developer Machine (Dev-Tool Compromise)

Companion to `incident-triage`, for when a developer tool turns out to have been malicious: an IDE extension, an MCP
server, an npm `postinstall` script, a skill or a plugin. These compromises use a small set of persistence and access
patterns that generic triage doesn't look for: an attacker SSH key, a reverse tunnel, a user-level LaunchAgent or
scheduled task named after a vendor, a hidden script in `~/.config`.

The playbook comes first; this incident's IOCs follow. When a new incident lands, add a dated IOC section rather than
editing the playbook.

If the parent was a trusted coding agent (`claude`, Cursor, Codex, or the ChatGPT app) rather than a malicious
extension, do not close on that parent. Follow "When a coding agent ran it" in `SKILL.md`, then use the persistence
sweep below.

## 1. Is this machine in scope?

1. **Was the bad component installed during the window?** For an extension: the version folders on disk and the
   install time in `extensions.json` (`agent-supply-chain-audit`, IDE extensions). For npm: the lockfile, and the
   `~/.npm/_cacache` index times.
2. **Did it activate?** Was the IDE opened with the extension enabled? Most extensions activate when the IDE starts.
3. **Do any IOCs match?** Check the vendor's indicators (section 5). Cursor's rule for its incident: if the attacker
   key is present, the machine is affected.

Two more ways onto the same machine, from Binance's 2026-11-03 preliminary report (reported, not re-proven here;
the four items that report leaves out stay left out — see `agent-supply-chain-audit` IN1–IN4):

1. **Tampered installer.** Ask which installer was run around the first suspicious activity. Check `brew tap` and the
   Homebrew remote (IN2), and review `~/Library/LaunchAgents` as section 3 already does. An agent or CLI whose
   install source cannot be shown is critical.
2. **Interview "homework" repo.** Ask whether the user cloned or unzipped a repository from a recruiter or
   interviewer in the last 90 days. If they did, on the work machine, treat the machine as compromised and rotate
   everything reachable from it. Binance's report says its endpoint protection missed the malware, so "no alert" is
   not a clean result.

**Web-to-agent session (exposure, not an IOC list).** In agent session transcripts, look for prompts the user did
not type, especially ones that say they are away from the keyboard and ask to install or run something. Do not grep
for the wording of any one report. Also look for a global package install, a new LaunchAgent or scheduled task, and
a new `authorized_keys` entry that line up with a session the user was not at the keyboard for. Reuse the checks in
sections 3 and 5. The prompting report is ThisBash (Forever Security, 2026-11-04; The Register, 2026-11-05): an
extension that can run on the agent's web origin could drive a remote-control feature such as Claude Dispatch. No
CVE and no reported exploitation. The claim that Claude Code Remote Control and Cowork web sessions share the design
is vendor-unconfirmed. Inventory and reduce it with `agent-supply-chain-audit` WB1–WB4. Re-check that claim when
Forever Security publishes its follow-up.

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
- **Committed agent config.** List every repo the compromised identity (the person, their SSH keys, their tokens)
  could push to. In each, look for new or changed agent config since the first suspicious activity: `.claude/`,
  `.mcp.json`, `CLAUDE.md`, `AGENTS.md`, `.cursor/`, `.gemini/settings.json`, `.github/copilot-instructions.md`. A
  hook or command that downloads and runs something runs on every developer who opens the repo in an agent. The
  read-only history commands are `agent-supply-chain-audit` CC2 (its `references/change-control.md`). Tell
  developers not to open those repos in an agent until they are checked. Revert the change through a reviewed pull
  request, and treat any machine that opened the repo since the change as in scope (section 1).
- **AI-named tokens and apps.** Review PATs, OAuth apps, GitHub Apps and SSH or deploy keys created
  since the first suspicious activity. Weigh names that look like an AI tool (Copilot, Claude, Codex, Cursor) the same
  as any other new token: a familiar name is camouflage, not a reason to skip it. Revoke what nobody can account for,
  from a clean machine (`secrets-audit`; `log-watch` for the org audit log). Rotate before anyone reopens those repos
  in an agent.
- Prompting report: GTIG's AI Threat Tracker (2026-11-16) describes a suspected DPRK cluster, MIDNIGHT NEPTUNE, that
  pivoted into internal repos, modified `.claude/settings.json` so starting Claude Code downloaded the SOMBERMEME
  backdoor, and hid its lateral movement with GitHub PATs named after Microsoft Copilot. Vendor
  research, not re-verified. GTIG gives no hook contents. Checked 2026-11-18 against
  [GTIG](https://cloud.google.com/blog/topics/threat-intelligence/agentic-threat-activity-crosses-a-significant-threshold/).

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

---

## IOCs: stolen GitHub write tokens pushing a CI secret stealer (wfx, 2026-11)

A stolen maintainer or bot token, used the way that account already writes. Not a GitHub Actions vulnerability, and
no CVE. Sources, both read 2026-11-15: [StepSecurity, 2026-11-12](https://www.stepsecurity.io/blog/wfx-phantom-the-github-actions-secret-stealer)
and [Aikido, 2026-11-12](https://www.aikido.dev/blog/compromised-github-accounts-push-ci-secret-stealer-to-tens-of-thousands-of-repositories).
Re-read them before relying on this list. StepSecurity says the exfil channel changed during the campaign: HTTP at
the start, Telegram as a backup from 01:10 UTC on November 12, and Telegram-only from about 05:30 UTC that day.
Blocking the November 10 addresses does not cover the later copies.

**What and when.** Starting about 12:45 UTC on 2026-11-10, valid write tokens for real developer and bot accounts
opened a probe pull request and, where the token and the repo allowed it, pushed a CI secret stealer, then reverted
within about a minute and deleted the run and its logs. Aikido reports 4,837 compromised accounts and probe pull
requests in 61,764 repositories, and that the payload ran in at least 1,806 repositories. The same post also says
at least 1,835 repositories had credentials exfiltrated. StepSecurity counted more than 63,000 probe pull requests
by 07:40 UTC on November 12, and said new ones were still appearing. How the tokens were obtained is **unknown**.
Some tokens were issued to the Fly.io GitHub App (`fly-io`, app id 34557): 173 probe pull requests from 19 accounts.
StepSecurity reports no evidence of a Fly.io infrastructure breach. Most of the campaign used other credentials,
such as PATs.

**What it did, for scoping.** It collects the job's secrets (including ones the workflow file never names, because
it reads runner memory), uses the job's OIDC token to open cloud sessions, and tries to leave access behind a
rotation. The four places to look, as StepSecurity described them: an existing workflow, a shell script CI already
runs, a new workflow on a throwaway branch, and a hidden script plus a `package.json` hook (`postinstall` most
often). Anyone who ran `npm install` on a poisoned commit locally ran that hook too.

Search before cleaning. A hit on the probe means the opening account's token is stolen, even if nothing else ran.

1. Pull requests titled `docs: dependency audit notes`, from branch `wfx-docs`, adding `docs/wfx-audit.md`. The
   probe file's git blob in the copies StepSecurity checked is `ee6e5addfe591923fc385553cb66cf0d25634a6b`.
2. Commits since 2026-11-10 with messages `ci: refresh build cache`, `ci: restore`, `ci: cleanup`,
   `chore: add ci helper`, `chore: add dependency audit workflow`, and `chore: initial commit` in an empty
   repository just before the workflow. Paths: `.ci-[a-z0-9]{6}.sh`, `.github/workflows/build-audit-*.yml`,
   branches `chore/[a-z0-9]{8}` and `ci-check-[0-9]{4}`.
3. **Gap check.** A missing run number right after one of those commits means the stealer likely ran and the run
   was deleted. drunomics/nuxtjs-drupal-ce went from run 1963 to 1965; run 1964 was the injected commit
   (StepSecurity).

   ```bash
   gh run list -R OWNER/REPO -L 200 --json number,createdAt --jq 'sort_by(.number) | .[].number' \
     | awk 'NR>1 && $1!=prev+1 {print "gap after #" prev} {prev=$1}'
   ```

4. If it ran: rotate every secret the job could reach, not only the ones the workflow names, plus publishing
   tokens and cloud credentials the job's OIDC token could assume. Then remove persistence, because rotation
   alone does not. Look for AWS role trust policies with `"Principal": {"AWS": "*"}`, IAM access keys created
   since 2026-11-10, CloudTrail sessions named `wfx-*` (`AssumeRoleWithWebIdentity` or `AssumeRole`, then
   `CreateAccessKey` or `UpdateAssumeRolePolicy`), and Azure federated identity credentials named `wfx-ci-*`.
   Also review GCP `GenerateAccessToken` and `SignJwt` through the GitHub workload-identity pool, and Vault or
   Kubernetes logins that presented a `token.actions.githubusercontent.com` token. Delete leftover `wfx-docs` and
   `chore/*` branches and close the probe pull requests. Name each cloud change and get the incident lead's
   go-ahead before it runs.
5. Revoke that account's PATs, OAuth grants, GitHub App grants, and SSH keys, and sign out its
   sessions. For a bot, decide whether it still needs permission to bypass branch protection. Rotate credentials
   for anyone who ran `npm install` on a poisoned commit. What the token could reach in CI, as a configuration
   question, is `cicd-security` check `compromised-writer`.

| Kind | Indicator |
|---|---|
| Network | `194[.]150[.]166[.]244:8080/exfil`, `18[.]143[.]168[.]96:8080/exfil`, `153[.]75[.]82[.]159:8080/exfil`. Later copies send only to `api.telegram.org` `sendDocument`, chat `-1004340163187`, bot ids `8708988906`, `9196217635`, `9180059428`, `8902935164`, `8876515636` (StepSecurity, 2026-11-12) |
| Callback tokens | `b42d70a7aab9140ca19e8249`, `15f44heehnax8jdf41yx`, sent as `t=` on the upload. Search strings, not credentials of yours |
| Pull request | Title `docs: dependency audit notes`; body `Routine dependency audit notes`; branch `wfx-docs`; file `docs/wfx-audit.md` |
| Commit messages | `ci: refresh build cache`, `ci: restore`, `ci: cleanup`, `chore: add ci helper`, `chore: add dependency audit workflow` |
| Branches and files | `wfx-docs`; `chore/[a-z0-9]{8}`; `ci-check-[0-9]{4}`; `.ci-[a-z0-9]{6}.sh`; `.github/workflows/build-audit-[a-z0-9]{6}.yml` |
| Content markers | Step names `Pass runtime` and `Restore cache` or `Run audit`; `WF_CALLBACK`, `WF_CTOKEN`, `WF_EXFIL_`, `WF_TG_BOTS`; staging directory `.wfx-`; log lines `memscan_files`, `archive_bytes`, `deliver_retry` |
| Cloud persistence | Azure federated credentials named `wfx-ci-*`; AWS trust `"Principal": {"AWS": "*"}`; AWS session names `wfx-*` |
| Packages | Packagist `digitalelvis/neuronai-studio` `3.14.3` (the hook runs under `npm install` in the package directory, not under `composer install`; StepSecurity says pin `3.14.2` or earlier). Go `github.com/onuragtas/docker-env` `v1.0.278` and `v1.0.280`, and `github.com/vkuznet/gocurl` `v0.0.0-20261111095532-8d5aad0cb0da`: the stealer is in a workflow file only, and Go builds do not run workflow files. Block the versions anyway |

File hashes are a weak detector. StepSecurity examined copies that do not share a hash, because each one embeds the
target repository and random names. Aikido published one sample,
`89695abb392d5cfd4972672961e644bb46baa98aa1ed7173c2a2816c762735cf`. A match is a hit. A miss is not a clearance.

Some repositories in this wave were also in the October GhostAction wave. Aikido treats the two as distinct
campaigns. An account that was compromised in October is worth checking for this one too.
