# secrets-audit

> Find leaked secrets in source code, Git history, build artifacts, and infrastructure — and audit the secrets-management posture preventing future leaks. Use when the user mentions 'secrets audit,' 'secret scanning,' 'leaked credentials,' 'API key in code,' 'gitleaks,' 'trufflehog,' 'betterleaks,' 'git history scan,' 'secrets management,' 'vault audit,' 'rotation policy,' 'AWS Secrets Manager,' 'HashiCorp Vault,' 'Doppler,' '1Password Secrets Automation,' 'sealed-secrets,' 'External Secrets Operator,' 'secrets in MCP config,' 'API key in Claude transcript,' 'is this key public,' or needs to find or prevent credential exposure.

# Secrets Audit — Credential Exposure and Secrets-Management Review

Two halves: (1) find secrets that have already leaked into source, history, or artifacts, and (2) audit the secrets-management posture that determines whether future leaks happen.

Most secret leaks aren't "we forgot to redact" — they're "we never had a system, so every developer made up their own approach." This skill covers both the cleanup and the prevention.

Cross-references: `dependency-audit` (CI-related secrets risk in build-time exposure), `iam-audit` (workload identity federation as the alternative to long-lived keys), `owasp-audit` A04:2025 Cryptographic Failures (hard-coded secrets found during an app review), `agent-supply-chain-audit` (the skills, hooks, and MCP servers that sit next to these agent configs and can read them), `incident-triage` and `threat-hunting` (the exfiltration-collector domains below as egress indicators), `scanner-pipeline` (gitleaks / trufflehog across full history and a whole fleet of repos, on a schedule), `personal-opsec` (the operator's own machine, where agent tokens and pasted secrets actually live), `cicd-security` (which workflows and forks can reach CI secrets).

## Authorization

Scan only repositories, CI systems and machines the user owns or is authorized to audit. Never print a full secret: give the type, location, and prefix plus last four. Checking that a key is live ("Verify it's live" below) uses the key, so ask first. That includes scanners that verify: trufflehog checks every candidate with its provider unless you pass `--no-verification`, so no secret scanner is pre-approved. Ask, use the provider's read-only identity call, and never use a found credential to read data. Rotation and history rewrites are the owner's call and always prompt.

## Part 1 — Find leaked secrets

### Provider key prefixes (high-confidence patterns)

The most useful first sweep is grep against known provider key prefixes. False positives are low and matches are almost always real.

These list matching files (`-l`) or counts (`-c`) rather than printing the match, so the secret isn't copied into your terminal scrollback or an agent transcript. Use the masked `rg` below when you need to tell keys apart.

```bash
# Stripe
grep -rlE "(sk_live_|sk_test_|rk_live_|whsec_)[A-Za-z0-9]{20,}" . \
  --include="*.{js,ts,jsx,tsx,py,rb,go,java,php,sh,env,yml,yaml,json}"

# AWS access keys
grep -rlE "(AKIA|ASIA)[A-Z0-9]{16}" .

# AWS secret keys (40 chars, base64-y). High FP rate: lockfile integrity hashes match too. Counts per file first
grep -rcE "[A-Za-z0-9/+=]{40}" . --include="*.env*" --include="*.json" | grep -v ':0$'

# GitHub
grep -rlE "gh[pousr]_[A-Za-z0-9]{36}" .

# Google Cloud API key + service-account JSON
grep -rlE "AIza[A-Za-z0-9_-]{35}" .
grep -rln '"type": "service_account"' . --include="*.json"

# Slack
grep -rlE "xox[baprs]-[A-Za-z0-9-]+" .

# OpenAI / Anthropic
grep -rlE "sk-[A-Za-z0-9]{32,}" .
grep -rlE "sk-ant-[A-Za-z0-9_-]{90,}" .

# Generic high-entropy values in env files: variable names and line numbers, value masked to first/last 4
grep -rnE "^[A-Z_]+=[A-Za-z0-9/+=]{32,}$" . --include="*.env*" | sed -E 's/=(.{4}).*(.{4})$/=\1…\2/'
```

For full repo coverage, use `git ls-files` to scope to tracked files and avoid `node_modules`:

```bash
git ls-files | xargs grep -lE 'sk_live_|ghp_|AKIA[A-Z0-9]{16}|sk-ant-|AIza[A-Za-z0-9_-]{35}' 2>/dev/null
```

**Running these inside an AI agent session?** Every match the agent prints is written into that session's transcript
(see the agent section below), which creates a new copy of the secret. List files (`-l`) or counts (`-c`), or mask the
value to prefix + last 4 when you need to tell keys apart:

```bash
rg -o -r '$1…$2' '(sk_live_|rk_live_|sk-ant-|ghp_|github_pat_|AKIA|xox[baprs]-|AIza)[A-Za-z0-9_-]{8,}([A-Za-z0-9]{4})' .
```

### Confirm the key type before rating it

A prefix match tells you the provider, not the authority. Several providers issue keys that are public by design, and
the same prefix can cover both. Before rating, establish what kind of key it is and what it can do — the severity
follows the authority, not the match ([references/severity-calibration.md](references/severity-calibration.md)).

| Provider | Publishable (meant for clients) | Restricted / scoped | Secret (full authority) |
|---|---|---|---|
| Google | `AIza…` browser / Maps / Firebase keys — fine when application restrictions (referrer, app, IP) and API restrictions are set | Same `AIza…` prefix with API restrictions; check which APIs it can call in Cloud Console → Credentials | An unrestricted `AIza…` key on a project with billable or data-bearing APIs enabled (Maps, Generative Language / Gemini) acts like a secret; service-account JSON always is |
| Stripe | `pk_live_` / `pk_test_` — public, not a finding | `rk_live_` — rate by the permissions set on that key in the Dashboard | `sk_live_` — full account; `sk_test_` is test-mode only (lower); `whsec_` lets an attacker forge webhooks, rate by what the handler does |
| Supabase | `anon` JWT / `sb_publishable_…` — public; exposure is about RLS, which is an authorization finding (`owasp-audit` / `api-audit`), not a secret | — | `service_role` JWT / `sb_secret_…` — bypasses RLS entirely |
| Firebase | Web config (`apiKey`, `authDomain`, `projectId`, `appId`) — identifiers, not secrets; the risk lives in Security Rules and App Check | — | Admin SDK service-account JSON, CI deploy tokens |
| Others | Mapbox `pk.`, Algolia search-only key, Sentry DSN, PostHog `phc_` | — | Mapbox `sk.`, Algolia admin key, PostHog `phx_` personal key |

Decode a Supabase key's JWT payload locally (the middle segment, base64) to read its `role` — that doesn't use the key.
A publishable key with correct restrictions is `rejected` (name the restriction and where it's configured). A
publishable key missing its restrictions is a finding only when you can trace the abuse (billing, quota exhaustion,
data the enabled API returns); otherwise it's a hardening note.

### Tooling

Start with Betterleaks. Commands, the v1/v2 flag differences, safety rules and report fields are in
[references/betterleaks.md](references/betterleaks.md). In short: detection only and redacted, with the report written
to a file, never printed. The default scan is pre-approved, and checking liveness prompts.

| Tool | Use |
|---|---|
| `betterleaks git . --validate=false --analyze=false --redact -o .security/out/betterleaks.json` | Default. Full history, fewer generic-secret false positives, value fingerprints that dedupe. After asking, `-v` checks liveness and `-a` adds identity and permissions |
| `gitleaks git --redact` | Fast, low FP, run as pre-commit and in CI; supports custom rules. Keep it where the repo already has a `.gitleaks.toml` or hook |
| `trufflehog git file://. --no-verification` | Detection only. Without the flag it checks each candidate with its provider (high confidence, but it uses the key): ask first |
| `detect-secrets scan` | Yelp's tool; good baseline file workflow |
| GitHub Secret Scanning | Free for public repos; covers most providers automatically; pushes get blocked at push time when enabled with push protection |
| GitLab Secret Detection | Similar, built-in to CI |
| GitGuardian / Doppler / Spectral | Commercial; add organizational dashboards and historical analysis |

### Git history (the part people forget)

A secret deleted in the latest commit is still in history — `git log -p`, `git log -S<secret>`, and any fork or local clone all have it.

```bash
# Search every commit for a pattern
git log -p -S "sk_live_" --all

# Search only deleted lines
git log -p --all | grep -E "^-.*sk_live_"

# Trufflehog historical scan
trufflehog git file://. --since-commit=<first-commit> --no-verification

# Git history rewrite — destructive, coordinate first
git filter-repo --invert-paths --path config/secrets.yml
# or
bfg --delete-files secrets.yml
```

**Critical caveat:** rewriting history requires every developer to re-clone, every fork is still exposed, and the secret should be considered compromised regardless. Always rotate first, history-rewrite second.

### Build artifacts and other forgotten places

Secrets leak in places that aren't `.env` files:

- **Docker images** — `docker history <image>` shows every `ENV` line; `--build-arg SECRET=...` ends up in layers
- **CI environment** — secrets logged by `set -x`, `console.log(process.env)`, error stack traces, debug output
- **Frontend bundles** — `NEXT_PUBLIC_*` / `VITE_*` / `REACT_APP_*` env vars are shipped to the browser; grep the bundled JS
- **Crash reports** — Sentry / Datadog / Bugsnag capturing `process.env` snapshots
- **Logs** — application logs shipped to a SIEM that has weaker access controls than the app
- **Backups** — `pg_dump` of a table that includes user-stored API keys
- **Public S3 / blob storage** — `.env` accidentally uploaded
- **Documentation** — README.md examples with real keys instead of placeholders
- **Slack / Notion / Linear** — pasted in a DM "to test," never rotated
- **Browser localStorage / cookies** — captured in shared screenshots or session replays
- **AI coding agent configs and transcripts** — see below; now one of the most common places keys sit in plaintext

### AI coding agent configs and transcripts

Agents need tokens for their MCP servers and helpers, and developers paste keys into chat to "just test it". Both end
up in plaintext files that are rarely gitignored deliberately and are often synced or backed up.

| Location | What leaks |
|---|---|
| `.mcp.json`, `~/.claude.json` (user and per-project `mcpServers`) | `env` and `headers` blocks with literal tokens |
| `.cursor/mcp.json`, `~/.cursor/mcp.json`, `.vscode/mcp.json` | Same, for Cursor and VS Code / Copilot |
| `~/Library/Application Support/Claude/claude_desktop_config.json` (Windows `%APPDATA%\Claude\`) | Claude Desktop MCP `env` blocks |
| `.claude/settings.json`, `.claude/settings.local.json`, `~/.claude/settings.json` | `env` blocks; `apiKeyHelper` / `awsCredentialExport` commands that print a credential (and run a shell command — see `agent-supply-chain-audit`) |
| `~/.codex/config.toml`, `~/.codex/auth.json` | `[mcp_servers.<name>.env]` tables; the Codex login / API key |
| `~/.gemini/settings.json`, `.gemini/settings.json`, `.gemini/.env`, `~/.gemini/.env` | `mcpServers` `env`; Gemini API keys |
| `~/.claude/projects/**/*.jsonl` (plus `~/.claude/history.jsonl`, shell snapshots, file history where present) | Session transcripts: every pasted key, every `cat .env`, every secret a tool printed |
| `~/.codex/sessions/**/*.jsonl`, `~/.codex/history.jsonl`, `~/.gemini/tmp/` | Codex and Gemini session logs and checkpoints |
| Cursor / VS Code `User/workspaceStorage/*/state.vscdb` and chat-session folders | Chat history in SQLite / JSON |
| Dotfiles repos and backups (Time Machine, iCloud, a `~/.claude` checked into `dotfiles`) | Copies of all of the above |

```bash
# MCP env / headers: any value that isn't a ${VAR} reference is a literal secret candidate
rg -n -A10 '"(env|headers)"\s*:' .mcp.json .cursor/mcp.json .vscode/mcp.json ~/.claude.json ~/.cursor/mcp.json \
  ~/.gemini/settings.json "$HOME/Library/Application Support/Claude/claude_desktop_config.json" 2>/dev/null \
  | rg -o -r '$1$2 = <literal>' '^(\S+?[:-]\d+[:-]).*?"([A-Za-z0-9_]+)"\s*:\s*"[^"$]{12,}"'   # key names only, values masked
rg -n '\[mcp_servers\.[^]]+\.env\]|^\s*env\s*=\s*\{' ~/.codex/config.toml   # then read the table in an editor, not into the session
# Agent settings: env blocks and credential helpers
rg -n '"(env|apiKeyHelper|awsCredentialExport|awsAuthRefresh|otelHeadersHelper)"\s*:' \
  .claude/settings.json .claude/settings.local.json ~/.claude/settings.json
# Transcripts and logs: counts per file only — printing a match copies it into this session's transcript
rg -c -e 'sk-ant-' -e 'sk_live_' -e 'rk_live_' -e 'ghp_' -e 'github_pat_' -e 'AKIA[A-Z0-9]{16}' -e 'xox[baprs]-' \
  -e 'AIza[A-Za-z0-9_-]{35}' -e '-----BEGIN [A-Z ]*PRIVATE KEY' -e 'service_role' \
  ~/.claude/projects ~/.claude/history.jsonl ~/.codex/sessions ~/.gemini/tmp 2>/dev/null
rg -a -c -e 'sk-ant-' -e 'sk_live_' -e 'ghp_' -e 'AKIA[A-Z0-9]{16}' \
  "$HOME/Library/Application Support/Cursor/User/workspaceStorage" 2>/dev/null
# Are any of these tracked?
git ls-files | rg '(^|/)(\.mcp\.json|mcp\.json|mcp_config\.json|settings\.local\.json|claude_desktop_config\.json|auth\.json|\.env)$'
```

For a key found in a transcript: rotate it (the transcript is a copy you can't recall from backups), then delete or scrub
the session file. Shorten retention where the agent supports it (Claude Code `cleanupPeriodDays`).

### Exfiltration collectors — egress indicators

Malicious skills, hooks, and packages ship stolen secrets to free collectors and tunnels. Seeing one of these in a
config, hook command, skill, bundled script, or package is a strong candidate for exfiltration; seeing one in egress
logs or DNS is an indicator for `incident-triage` (scope a live incident) and `threat-hunting` (sweep for it). Some
have legitimate uses — a team Slack webhook in CI notifications — so confirm what is sent.

| Kind | Domains / URL shapes |
|---|---|
| Chat webhooks | `discord.com/api/webhooks/`, `discordapp.com/api/webhooks/`, `api.telegram.org/bot`, `hooks.slack.com/services/` (and `/workflows/`, `/triggers/`) |
| Request collectors | `webhook.site`, `requestbin` / `*.m.pipedream.net`, `requestcatcher.com`, `beeceptor.com`, `pipedream.net` |
| OAST / interaction | `interact.sh`, `*.oast.pro` / `.live` / `.site` / `.online` / `.fun` / `.me`, `burpcollaborator.net`, `oastify.com` |
| Tunnels | `*.ngrok.io`, `*.ngrok-free.app`, `*.ngrok.app`, `*.trycloudflare.com`, `loca.lt`, `serveo.net` |
| Paste / drop | `pastebin.com`, `transfer.sh`, `paste.ee`, `0x0.st` |

```bash
rg -n -i 'discord(app)?\.com/api/webhooks|api\.telegram\.org/bot|hooks\.slack\.com/(services|workflows|triggers)|webhook\.site|requestbin|pipedream\.net|requestcatcher\.com|beeceptor\.com|interact\.sh|oast\.(pro|live|site|online|fun|me)|burpcollaborator\.net|oastify\.com|ngrok(-free)?\.(io|app|dev)|trycloudflare\.com|loca\.lt|serveo\.net|pastebin\.com|transfer\.sh|paste\.ee|0x0\.st' .
```

A Slack or Discord webhook URL is itself a secret (anyone holding it can post to that channel) — report it under both
headings.

### Triaging a found secret

When you find a leaked secret:

1. **Identify the key type** — publishable, restricted, or secret, and what it can reach (see "Confirm the key type before rating it")
2. **Verify it's live** — ask first. If the rule can validate (`betterleaks config show ids --validation`), re-scan the file that holds it with `-v` ([references/betterleaks.md](references/betterleaks.md#commands)). Otherwise use the provider's read-only identity call (`aws sts get-caller-identity`, `stripe balance retrieve`, `curl -H "Authorization: Bearer $TOKEN" ...`). Don't assume; some leaked keys are already revoked or were sandbox-only. `unknown` is not `invalid`: record it as `needs_validation`
3. **Determine exposure window** — first commit it appeared in, when the repo went public, when CI logs were retained from
4. **Determine blast radius** — what does this key access? What can be done with it? For rules that support analysis (`config show ids --analysis`), the same re-scan with `-a` returns the identity, account and permissions; copy them into the evidence, redacted. Otherwise check by hand: IAM permissions, Stripe live vs test, GitHub `repo` vs `admin:org`
5. **Rotate immediately** — generate a new key, deploy it, then revoke the old one (revoke-first breaks prod). Then confirm the old key is dead: re-run the `-v` scan where it was found and expect `invalid`. Never use a scanner's `revoke` command; revocation is the owner's step
6. **Audit for use** — provider audit logs (CloudTrail, GitHub audit log, Stripe events) for any activity from the leaked credential
7. **Then clean** — remove from current code, then optionally history-rewrite (low priority once rotated)
8. **Document** — incident report, even if rotation was clean; recurrence patterns surface trends

## Part 2 — Audit secrets-management posture

### The hierarchy of secret storage (worst → best)

| Tier | Pattern | When acceptable |
|---|---|---|
| ❌ | Hardcoded in source | Never |
| ❌ | Hardcoded in image / build artifact | Never |
| ❌ | Plaintext in shared docs / Slack | Never |
| ⚠️ | `.env` file in repo (even with .gitignore — easy to leak via push, backup, archive) | Bootstrap only; flagged in audit |
| ⚠️ | Environment variables (only) | Acceptable for ephemeral dev; weak for prod (visible in /proc, crash dumps, logs) |
| 🟢 | Secrets manager pulled at deploy time | Standard for most apps |
| 🟢 | Workload identity federation (no stored secret at all) | Best where supported |

### Cloud-provider secrets managers

- **AWS Secrets Manager / Parameter Store (SecureString)** — integrate via IAM-scoped IRSA / task role / Lambda role
- **GCP Secret Manager** — bind via Workload Identity to GSA, GSA pulls secret
- **Azure Key Vault** — pull via managed identity
- **Doppler / Infisical / 1Password Secrets Automation** — cross-cloud, developer-friendly

### Audit checklist

- **No secrets in Git history** (run gitleaks --all)
- **No `.env` committed** — `.gitignore` covers `.env*` (with care for `.env.example`)
- **Agent configs in `.gitignore`, or `${ENV}` references only** — `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `.claude/settings.local.json`, `.gemini/.env` are either untracked (`git check-ignore -v <file>`) or hold only variable references (`${VAR}` in Claude Code `.mcp.json`, `${env:VAR}` in Cursor, `${input:…}` prompts in VS Code); agent transcript retention is set and transcripts aren't in dotfile repos or unencrypted backups
- **Secrets fetched at runtime, not embedded at build** — image rebuild is not required to rotate
- **IAM scoped to the secret** — service A can read secret A, not secret B
- **Rotation cadence** — defined per secret class (admin: 30d, service: 90d, customer-shared: per breach response)
- **Rotation is automated** — if a human runs a script every 90 days, rotation will eventually drift
- **Access logged** — every Get / Decrypt call is in an audit trail
- **No long-lived cloud keys for workloads** — workload identity federation everywhere it's supported (see `iam-audit`)
- **Break-glass procedure** — when the secrets manager is down, how do critical services come up? (Usually: cached on disk encrypted, with strict re-fetch on restart)
- **Cross-environment isolation** — staging cannot read prod secrets, ever (different KMS keys, different IAM)

### Common findings

- **Rotation never tested** — secret stores configured, never actually rotated; first attempt breaks prod
- **`.env.local` shipped to staging** — environment-specific dev secrets cross the boundary
- **CI secrets accessible from PRs from forks** — GitHub's default behavior was previously dangerous; verify `pull_request_target` and secret accessibility → `cicd-security` (fork secrets, pwn requests)
- **Build args used for secrets** — `--build-arg AWS_SECRET=...` ends up in image history (use `--secret`/BuildKit instead)
- **Logging frameworks dump `process.env`** on unhandled exception — Sentry / Datadog / Bugsnag scrub config required
- **Secret stored in K8s as plain Secret** without etcd encryption — base64 is encoding, not encryption (see `container-audit`)
- **OAuth client secrets in mobile apps** — public clients can't hold secrets; PKCE is the answer

## Output Format

Write `findings.json` first, validate it, then render the markdown report from it — the prose never changes a verdict
or severity. Record shape and the validate / SARIF-export commands are in
[references/findings-format.md](references/findings-format.md); run
`node references/validate-findings.mjs findings.json` ([references/validate-findings.mjs](references/validate-findings.mjs)) and fix every error before writing prose.

- **Never put a secret value in `findings.json`** (or the report). Redact to prefix + last 4 — `sk_live_…9f2c` — in
  titles and evidence descriptions.
- **Fingerprint:** `secrets-audit/<provider>-<key type>/<file>/<variable>`, the form in `findings-format.md`, e.g.
  `secrets-audit/stripe-secret-key/config/payments.ts/STRIPE_SECRET_KEY`. When the value has no variable name (an
  inline literal, a URL with credentials), use the enclosing symbol, or `last4-<last 4>` if there's none:
  `secrets-audit/github-pat/scripts/deploy.sh/last4-9f2c`. No line numbers.
- Scanner data (detector, validation result, identity, permissions, value fingerprint) goes in `ext`; the keys are in
  [references/betterleaks.md](references/betterleaks.md#verdicts-and-ext-keys).
- `skill: "secrets-audit"`. Run each candidate through the refutation pass in
  [references/verification.md](references/verification.md), and rate with
  [references/severity-calibration.md](references/severity-calibration.md) (key types are in its section 6).
  - `confirmed`: verified live (`reproduced: true` when you made the provider check), or a secret-class key whose
    authority you established. Severity follows the key type and blast radius. A hard-coded fallback secret in code
    (`process.env.JWT_SECRET || "changeme"`) is also `confirmed`. Rate it as if the default is live, add a
    `system_configuration` condition, and cap confidence at medium ("Unsafe shipped defaults" in `verification.md`).
  - `needs_validation`: you can't settle it without the owner, for example whether a found key is still active.
    Record the blockers and the exact check they should run.
  - `rejected`: revoked, a placeholder, publishable with correct restrictions, or a vendor's published example
    value. `ruled_out_by` names what rules it out. `location` is where that's configured, or for an inert value the
    line that holds it.
- Locations are repo-relative. A key that exists only in history uses the path as it was, with the commit in the
  evidence description. Keys found in user-level agent files (`~/.claude`, `~/.codex`, …) go in a separate
  `findings.user.json` with paths relative to `$HOME`.

```markdown
# Secrets Audit Report
## Scope: [repos / environments / managers covered]
## Date: [date]

### Live leaked secrets found
| Provider | Key type (publishable / restricted / secret) | Redacted value | Location | First seen (commit / date) | Verified live? | Rotation status |
|---|---|---|---|---|---|---|

### Needs validation
| Provider | Location | Blocker | Check for the owner to run |
|---|---|---|---|

### Hardening notes (not findings)
- [e.g. publishable key without referrer restriction and no traced abuse; transcript retention unset]

### Rejected (do not re-raise)
| Fingerprint | Location | Ruled out by |
|---|---|---|

### Secrets-management posture
| Category | Status | Notes |
|---|---|---|

### Recommendations
| Priority | Item | Owner | Deadline |
|---|---|---|---|
```

Dispositions for confirmed findings: Fixed / Deferred / Accepted Risk / Mitigated (platform/config) / Requires major migration (see `owasp-audit`). A rotated-and-revoked key is Fixed even if history still holds it.

## Boundaries

- Only audit repositories, CI systems, and infrastructure the user has authorization for
- Never use a found secret to access the provider — verify it's live with a minimal API call (account info, not data extraction); do not pivot
- For history rewrite operations: never proceed without explicit confirmation and a coordinated developer-notification plan
- Refuse to help collect or weaponize leaked secrets found in other people's repos
- If the audit surfaces credentials belonging to a third party (vendor, employee personal accounts), notify and rotate; don't quietly fix

## References

- OWASP Cheat Sheet: Secrets Management
- NIST SP 800-57 (Recommendation for Key Management)
- GitGuardian "State of Secrets Sprawl" annual reports — useful for industry context
- `betterleaks`, `gitleaks`, `trufflehog`, `detect-secrets` documentation
- GitHub Secret Scanning + Push Protection documentation
- HashiCorp Vault Architecture / Best Practices
- AWS Secrets Manager Best Practices
- "Twelve-Factor App" — Config principles
- NVIDIA SkillSpector (Apache-2.0) — agent-config access (AS2) and command-running settings keys (BH4) rules, and its credential-exfiltration webhook signatures: [repo](https://github.com/NVIDIA/SkillSpector)

## Reference files

This skill links to supporting files under `references/`. They are not inlined in this adapter; open them on GitHub (or in `skills/secrets-audit/references/` if you have the repo checked out):

- [references/betterleaks.md](https://github.com/briiirussell/cybersecurity-skills/blob/main/skills/secrets-audit/references/betterleaks.md)
- [references/findings-format.md](https://github.com/briiirussell/cybersecurity-skills/blob/main/skills/secrets-audit/references/findings-format.md)
- [references/findings.schema.json](https://github.com/briiirussell/cybersecurity-skills/blob/main/skills/secrets-audit/references/findings.schema.json)
- [references/severity-calibration.md](https://github.com/briiirussell/cybersecurity-skills/blob/main/skills/secrets-audit/references/severity-calibration.md)
- [references/to-sarif.mjs](https://github.com/briiirussell/cybersecurity-skills/blob/main/skills/secrets-audit/references/to-sarif.mjs)
- [references/validate-findings.mjs](https://github.com/briiirussell/cybersecurity-skills/blob/main/skills/secrets-audit/references/validate-findings.mjs)
- [references/verification.md](https://github.com/briiirussell/cybersecurity-skills/blob/main/skills/secrets-audit/references/verification.md)
