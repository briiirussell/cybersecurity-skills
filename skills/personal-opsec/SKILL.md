---
name: personal-opsec
description: "Audit one person's own security setup — the founder or operator who holds the keys to the stack — and produce a prioritized gap report. Walks Karpathy's 15-control digital security checklist, adds account-recovery, SIM-swap, registrar, and hardware-key checks, and covers the AI-agent era: tokens your coding agents can read, MCP server trust, inbox-assistant prompt injection, clipboard exposure. Use when the user mentions 'personal opsec,' 'personal security audit,' 'secure my own accounts,' 'founder security,' 'Karpathy security checklist,' 'am I secure,' 'hardware key,' 'YubiKey,' 'SIM swap,' 'port-out PIN,' 'FileVault,' 'BitLocker,' 'password manager,' 'recovery codes,' 'registrar lock,' 'what can my AI agent see,' 'API keys on my laptop,' 'MCP trust,' or wants to harden their own accounts and machine."
allowed-tools: Read, Grep, Glob, Bash(fdesetup status:*), Bash(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate:*), Bash(/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode:*), Bash(scutil --dns:*), Bash(spctl --status:*), Bash(csrutil status:*), Bash(sw_vers:*), Bash(which:*), Bash(ls -l:*), Bash(gh auth status:*), Bash(whois:*), Bash(manage-bde -status:*), Bash(lsblk:*), Bash(resolvectl status:*)
---

# Personal OpSec — Audit One Operator's Own Security Setup

Every other skill in this catalog audits an organization, a codebase, or infrastructure. This one audits **a person**: the founder, solo operator, or small-team admin whose laptop, email, phone number, and password manager are the real root of trust for the whole stack. If their email falls to a SIM swap, it doesn't matter how good the IAM policies are.

**This is not security-awareness or phishing training.** No quizzes, no "think before you click" content. The agent checks the person's actual state — on the local machine where it can, by asking where it can't — and produces a prioritized gap report in the same finding/disposition vocabulary as the audit skills, ready for `finding-triage`.

The baseline is Karpathy's 15-control list (via Andrej Karpathy's digital security checklist), plus the operator-critical items it skips and the AI-agent layer it predates. Products named below are examples of a control, not endorsements; any tool that provides the control counts.

Cross-references: `secrets-audit` for API keys and tokens on disk that coding agents can read; `agent-supply-chain-audit` for MCP server and agent-extension trust; `prompt-injection` for personal and inbox assistants that read untrusted mail; `iam-audit` for the org-level MFA and access policy this person administers; `breach-patterns` for the phishing and account-takeover patterns behind these controls; `finding-triage` for dispositions on each gap; `osint-recon` if the user wants to see what's public about *themselves*.

## Consent and scope (before anything else)

- **Only the person being audited runs this, on their own accounts and their own machine.** Confirm that at the start. If the user asks to audit a co-founder, employee, partner, or anyone else, stop: that person runs it themselves, with their own consent. Refuse to profile, enumerate, or assess someone else's personal security, accounts, devices, or exposure without their explicit consent — that's surveillance or pre-attack recon, not opsec.
- On a work machine managed by an employer, local checks are fine, but don't attempt to read or change MDM/EDR configuration.
- **Read-only.** The agent never changes a setting, enables a feature, installs anything, or logs into an account. It reports; the user fixes.
- **Never read secret values.** The agent doing this audit is itself an AI agent with file access — exactly the exposure Part C measures. Check existence, file permissions, and match *counts*; never print a token, key, recovery code, or password into the transcript. If the user pastes one, tell them to rotate it.

## How evidence turns into verdicts

| Evidence | Verdict | Notes |
|---|---|---|
| Agent ran a read-only check and the control is absent/off | `confirmed` | Severity assigned; disposition later |
| Agent ran a check and the control is present | `rejected` | Record the control and where it was observed (e.g. `fdesetup status` → "FileVault is On") so re-runs don't re-raise |
| User reports state the agent can't check (MFA type on an account, carrier PIN) | `needs_validation` | `blockers[]` = why the agent can't see it; `validation_plan` = the exact settings page or step the user checks. User says "yes, I have it" → still needs_validation until they've looked, then confirmed/rejected |
| Privacy-preference control with no account-takeover or data-loss path | **Hardening note** | Not a finding, no severity, reported separately |

Severity follows the shared calibration: impact is what an attacker gets (email takeover, prod credentials, money movement), likelihood is how exposed the gap is. `overall ≤ impact`. Fingerprints are stable and look like `personal-opsec:<control>:<gap>` — e.g. `personal-opsec:k05-disk-encryption:off`, `personal-opsec:x01-carrier-port-pin:missing` — never including dates or severity.

## Workflow

1. Confirm consent and scope (above). Ask which OS, which phone carrier/country, and which accounts are "crown jewels" (primary email, GitHub, cloud console, registrar/DNS, bank/Stripe, password manager).
2. Run the local checks in one pass (below). Report what you ran.
3. Walk Part A, B, C. For anything not checkable, ask a short, specific question — batch them, don't interrogate one at a time.
4. Build the gap report (Output Format), prioritized P0/P1/P2, and hand confirmed findings to `finding-triage` for disposition.

### Local checks (read-only)

macOS — run these; each is pre-approved and changes nothing:

```bash
sw_vers                                                          # OS version (old major = missing security updates)
fdesetup status                                                  # K5: FileVault on/off
/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate # inbound firewall
/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode
spctl --status                                                   # Gatekeeper: "assessments enabled"
csrutil status                                                   # System Integrity Protection
scutil --dns                                                     # K14: which resolvers are in use
which op bw lpass keepassxc-cli                                  # K1: password-manager CLIs present
gh auth status                                                   # C5: GitHub token scopes and where it's stored
```

Use Glob (no Bash needed) for installed apps: `/Applications/{1Password,Bitwarden,Signal,Brave Browser,Mullvad VPN,Little Snitch,LuLu,NextDNS}*.app`. Presence of an app isn't proof it's configured — it moves a control from "missing" to "ask how it's set up".

Windows and Linux equivalents (`manage-bde -status`, `Get-BitLockerVolume`, `lsblk`, `resolvectl status`, firewall state) are in [references/local-checks.md](references/local-checks.md).

## Part A — Karpathy's 15 controls

Via Andrej Karpathy's digital security checklist. "Tier" says whether a gap becomes a finding or a hardening note for an operator.

| # | Control (example tools) | How the agent checks | If missing |
|---|---|---|---|
| K1 | Password manager, unique password per account (1Password, Bitwarden) | `which op bw …`, Glob for app; **ask** whether the vault's reuse/breach report is clean and whether crown-jewel accounts are in it | Finding — high if crown-jewel passwords are reused |
| K2 | Hardware security keys, 2–3 enrolled, stored separately (YubiKey, Titan; passkeys are an acceptable phishing-resistant step) | **Ask** per crown-jewel account: which second factors are enrolled (SMS / TOTP / passkey / hardware key), how many keys, where the spare lives | Finding — high for primary email or GitHub with SMS/TOTP only; medium with one key and no spare |
| K3 | Biometric/strong unlock on password manager and critical apps | **Ask**: PM unlock method and auto-lock timeout; phone banking/email app lock | Finding low; hardening note if PM auto-locks quickly |
| K4 | Security-question answers are random, stored in the PM | **Ask** which accounts still use security questions and whether answers are real facts | Finding medium where it's a recovery path for a crown-jewel account; else hardening note |
| K5 | Full-disk encryption (FileVault, BitLocker, LUKS) | `fdesetup status` / `manage-bde -status` / `lsblk` | Finding — high on a laptop holding prod credentials |
| K6 | Minimize smart-home devices | **Ask**: are IoT devices on the same network as the work laptop? | Hardening note; finding low only if IoT shares a flat network with a machine that has prod access |
| K7 | Signal with disappearing messages | Glob for Signal; **ask** what channel is used for sensitive ops talk | Hardening note. (Credentials shared over SMS/Slack DMs are a `secrets-audit` matter, not this one) |
| K8 | Privacy-focused browser (Brave, or hardened Firefox) | Glob for apps; **ask** default browser and extension count | Hardening note. Browser *extensions* with "read all sites" on the admin browser profile → finding medium (they see sessions) |
| K9 | Private default search engine | **Ask** | Hardening note |
| K10 | Virtual cards for online purchases (Privacy.com and similar) | **Ask** | Hardening note (limits card-fraud blast radius) |
| K11 | Virtual mailing address | **Ask** — matters more if home address is on public business filings | Hardening note; flag to `osint-recon` if the user wants to check their own exposure |
| K12 | Type addresses instead of clicking email links; remote images off | **Ask** mail client and whether remote content loads | Hardening note — the stronger control is K2 (phishing-resistant MFA makes a clicked link far less costly) |
| K13 | Selective VPN on untrusted networks (Mullvad and similar) | Glob/`which mullvad`; **ask** when it's used | Hardening note |
| K14 | DNS-level blocking (NextDNS and similar) | `scutil --dns` / `resolvectl status`: look for the provider's resolvers or a DoH/DoT profile | Hardening note |
| K15 | Outbound network monitoring (Little Snitch, LuLu) | Glob for app; macOS firewall state as the inbound counterpart | Hardening note — but on a machine running coding agents and MCP servers, outbound visibility is how you'd notice exfiltration; say so |

Additional local signals from the checks: firewall off → hardening note (laptops are rarely directly reachable); Gatekeeper or SIP disabled → finding medium (unsigned code runs freely on the machine holding the keys); OS a major version or more behind with no updates → finding medium.

## Part B — Operator-critical items the list skips

These are the account-takeover paths that actually hit founders. Keep them in every run.

| # | Control | How to check | If missing |
|---|---|---|---|
| X1 | **SIM-swap / port-out protection** — carrier port-out PIN or number lock (names vary by carrier: "SIM protection", "Number Lock", "account lock") | **Ask**; validation plan = the carrier's account security page | Finding — high if the number is a recovery factor for any crown-jewel account |
| X2 | **SMS removed as a recovery factor** on primary email, GitHub, cloud console, registrar, password manager | **Ask** per account | Finding — high (SMS recovery undoes a hardware key) |
| X3 | **Recovery codes stored offline**, not only inside the password manager they'd be needed to recover | **Ask** where GitHub/Google/AWS-root/PM recovery codes and the PM emergency kit live | Finding medium — if lost with the PM, recovery depends on support tickets |
| X4 | **Registrar and DNS account lock** — transfer lock on the domain, registrar account on hardware-key MFA, registry lock for high-value domains, DNS provider (Cloudflare, Route 53) account on hardware-key MFA | `whois <their-domain>` → look for `clientTransferProhibited`; **ask** about registrar/DNS account MFA | Finding — high: whoever controls DNS controls email, so password resets, so everything |
| X5 | **Hardware-key MFA on GitHub and cloud consoles** (AWS root and IAM Identity Center, GCP, Azure, Vercel, Supabase, Stripe) | `gh auth status` for token posture; **ask** for MFA type per console. AWS root: `aws iam get-account-summary` → `AccountMFAEnabled` if the user runs it | Finding — high for GitHub (push = prod) and AWS root; hand org-wide enforcement to `iam-audit` |
| X6 | **Primary email is the strongest account** — it resets everything else | Covered by K2/X2 on that account; **ask** whether any crown-jewel account recovers to a weaker secondary email | Finding high if a crown-jewel account recovers to a weaker mailbox |

## Part C — The AI-agent-era layer

Coding agents, MCP servers, and inbox assistants run with the operator's file access and credentials. Karpathy's list predates this; for an operator it's now one of the largest exposures.

**C1 — Tokens and keys an agent can read.** Anything in the home directory is readable by any agent you run there. Check existence and permissions only — **never Read these files**:

- Glob for: `~/.aws/credentials`, `~/.config/gh/hosts.yml`, `~/.npmrc`, `~/.netrc`, `~/.docker/config.json`, `~/.pypirc`, `~/.kube/config`, `~/.config/gcloud/application_default_credentials.json`, `~/.ssh/id_*`, `**/.env*` under the user's projects directory
- `ls -l` on each hit: world/group-readable credential files → finding
- Grep with **count output only** (never content) for exported secrets in shell startup files and history: pattern `(sk-ant-|sk_live_|ghp_|github_pat_|AKIA|xox[baprs]-)` against `~/.zshrc`, `~/.bashrc`, `~/.zprofile`, `~/.zsh_history`, `~/.bash_history`
- Finding severity by what the token unlocks: a live production cloud key or a GitHub token with `repo`/`admin:org` in a plaintext file → high; secrets in shell history → medium (rotate, then clear). Hand the cleanup and rotation to `secrets-audit`.

**C2 — MCP servers and agent extensions.** Inventory what's connected and what each can reach. Check config files (Grep for server names and `command`/`url` keys only; count, don't print, any `env` values): `~/.claude.json`, `~/.claude/settings.json`, project `.mcp.json`, `~/.cursor/mcp.json`, `~/Library/Application Support/Claude/claude_desktop_config.json`, VS Code `mcp.json`. For each server, ask: who publishes it, is it pinned to a version, what credentials does it hold, can it send data out (HTTP, email, Slack)? A server that can both read private data and reach the network is an exfiltration path. Secrets inline in MCP config → finding (C1 rules). The trust review itself → `agent-supply-chain-audit`.

**C3 — Agent permission modes.** **Ask** (or Grep `~/.claude/settings.json` for `permissions`/`defaultMode`): does any agent run with auto-approve / bypass-permissions / unscoped shell on the machine that holds prod credentials? Finding medium–high depending on C1: a no-prompt agent plus plaintext admin keys means any prompt injection it reads can act with those keys.

**C4 — Personal and inbox assistants.** **Ask** which assistants read email, calendar, docs, or messages, and what they can *do*: send, forward, reply, delete, share files, create filters. Inbound email is attacker-controlled input; an assistant that reads it and can send mail or share a Drive file is an indirect-prompt-injection exfiltration path. Draft-only/read-only is the safe shape. Send/forward/share capability with no human confirmation → finding medium–high. Testing and design → `prompt-injection`.

**C5 — Long-lived vs scoped, short-lived tokens.** From `gh auth status` and **asking**: classic GitHub PATs with broad scopes and no expiry, long-lived AWS IAM user keys instead of SSO/Identity Center sessions (`~/.aws/config` with `sso_session` entries is the better state — Grep count), Stripe secret keys instead of restricted keys, provider API keys with no spend limit. Prefer fine-grained tokens with expiry, SSO sessions, restricted keys. Long-lived admin-scoped token on the laptop → finding medium; with no expiry and org admin scope → high.

**C6 — Clipboard and screen exposure.** Glob for clipboard-history managers (Maccy, Paste, Raycast/Alfred clipboard history); **ask** whether the password manager clears the clipboard and whether clipboard history excludes it. Agents with screen or clipboard access (computer-use tools, screen-recording assistants) see whatever is copied. Secrets persisting in clipboard history that agents or sync can read → finding low–medium; hardening note if the PM is excluded and clears in ≤90 s.

## Prioritization

- **P0 — this week.** Any confirmed/needs_validation gap that gives account takeover of a crown-jewel account or prod access: SMS-only or SMS-recoverable primary email/GitHub/registrar, no carrier port-out PIN when the number is a recovery factor, no disk encryption on a laptop with prod keys, plaintext admin tokens readable by a no-prompt agent, inbox assistant that can send/share without confirmation.
- **P1 — this month.** Single hardware key with no spare, recovery codes only in the PM, broad long-lived tokens, MCP servers with network + private-data reach, Gatekeeper/SIP off, stale OS.
- **P2 — when convenient.** Remaining low findings.
- **Hardening notes** — privacy preferences (K6–K14 mostly). Listed, never ranked against findings.

Order within a tier by blast radius: primary email → password manager → registrar/DNS → GitHub → cloud root → payments → everything else.

## Output Format

```markdown
# Personal OpSec Gap Report
## Person: [self — consent confirmed] · Date: [date] · OS: [..] · Crown-jewel accounts: [..]
## Local checks run: [commands + one-line result each]

### Summary
P0: X · P1: X · P2: X · Needs validation: X · Hardening notes: X

### Findings
| Priority | Fingerprint | Control | Verdict | Severity | Evidence | Fix (specific steps) | Disposition |
|---|---|---|---|---|---|---|---|
| P0 | personal-opsec:x02-sms-recovery:primary-email | X2 | confirmed | high | User checked Google account → recovery phone set | Remove recovery phone; enroll 2 hardware keys; store recovery codes offline | — |

### Needs validation
| Fingerprint | Control | Blockers | Validation plan (where to look) |
|---|---|---|---|

### Rejected (control present — kept so re-runs don't re-raise)
| Fingerprint | Control | Observed by | Where |
|---|---|---|---|

### Hardening notes (not findings)
- [K9] Default search engine is [..]; a private engine reduces query profiling. No account-takeover path.

### Hand-offs
- secrets-audit: [C1 items to rotate/clean]
- agent-supply-chain-audit: [C2 servers to review]
- prompt-injection: [C4 assistants]
- iam-audit: [X5 org-wide enforcement]
- finding-triage: every confirmed finding, for disposition
```

Dispositions use the shared vocabulary: `Fixed`, `Deferred`, `Accepted Risk`, `Mitigated (platform/config)`, `Requires major migration`, or `False Positive`. A personal `Accepted Risk` (e.g. "I'm keeping SMS on my bank because it offers nothing else") still gets a one-line reason and a re-evaluation date. Re-run quarterly or after a new device, a new phone number, or a new agent/MCP setup; rejected records carry over.

## Boundaries

- Audit only the consenting person running it, on their own accounts and devices. Refuse requests to assess, profile, or enumerate another person's accounts, devices, MFA setup, phone carrier, address, or exposure without that person's explicit consent — including "just checking my partner's / employee's / co-founder's setup."
- Read-only. No setting changes, no installs, no logins, no enrollment on the user's behalf.
- Never print or store secret values, recovery codes, or passwords. Counts and file metadata only. If one is exposed in the session, the fix is rotation.
- Not security-awareness or phishing training content. Don't generate quizzes, simulated phishing, or generic tips divorced from the person's actual state.
- Vendor names are examples of a control, not endorsements; accept any tool that provides the control.
- This doesn't replace org controls. Org-wide MFA enforcement, SSO, and access reviews belong in `iam-audit`.

## References

- Andrej Karpathy's digital security checklist (15 controls), as circulated in Ole Lehmann's "stay secure in the age of AI agents" post — paraphrased, not reprinted
- CISA — Implementing Phishing-Resistant MFA (fact sheet)
- NIST SP 800-63B — Digital Identity Guidelines: Authentication (restrictions on SMS/PSTN authenticators)
- FIDO Alliance — passkeys and security keys
- FTC / FCC consumer guidance on SIM-swap and port-out fraud
- ICANN — EPP status codes (`clientTransferProhibited`, registry lock)
- OWASP Top 10 for LLM Applications — LLM01 Prompt Injection, LLM06 Excessive Agency
