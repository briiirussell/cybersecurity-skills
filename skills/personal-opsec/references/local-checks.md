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
