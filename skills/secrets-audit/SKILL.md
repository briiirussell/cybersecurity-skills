---
name: secrets-audit
description: "Find leaked secrets in source code, Git history, build artifacts, and infrastructure — and audit the secrets-management posture preventing future leaks. Use when the user mentions 'secrets audit,' 'secret scanning,' 'leaked credentials,' 'API key in code,' 'gitleaks,' 'trufflehog,' 'git history scan,' 'secrets management,' 'vault audit,' 'rotation policy,' 'AWS Secrets Manager,' 'HashiCorp Vault,' 'Doppler,' '1Password Secrets Automation,' 'sealed-secrets,' 'External Secrets Operator,' or needs to find or prevent credential exposure."
allowed-tools: Bash, Read, Write, Grep, Glob, WebSearch
---

# Secrets Audit — Credential Exposure and Secrets-Management Review

Two halves: (1) find secrets that have already leaked into source, history, or artifacts, and (2) audit the secrets-management posture that determines whether future leaks happen.

Most secret leaks aren't "we forgot to redact" — they're "we never had a system, so every developer made up their own approach." This skill covers both the cleanup and the prevention.

Cross-references: `dependency-audit` (CI-related secrets risk in build-time exposure), `iam-audit` (workload identity federation as the alternative to long-lived keys), `owasp-audit` A02 (in-source secret patterns).

## Part 1 — Find leaked secrets

### Provider key prefixes (high-confidence patterns)

The most useful first sweep is grep against known provider key prefixes. False positives are low and matches are almost always real.

```bash
# Stripe
grep -rE "(sk_live_|sk_test_|rk_live_|whsec_)[A-Za-z0-9]{20,}" . \
  --include="*.{js,ts,jsx,tsx,py,rb,go,java,php,sh,env,yml,yaml,json}"

# AWS access keys
grep -rE "(AKIA|ASIA)[A-Z0-9]{16}" .

# AWS secret keys (40 chars, base64-y) — high FP rate, use with caution
grep -rE "[A-Za-z0-9/+=]{40}" . --include="*.env*" --include="*.json"

# GitHub
grep -rE "gh[pousr]_[A-Za-z0-9]{36}" .

# Google Cloud API key + service-account JSON
grep -rE "AIza[A-Za-z0-9_-]{35}" .
grep -rln '"type": "service_account"' . --include="*.json"

# Slack
grep -rE "xox[baprs]-[A-Za-z0-9-]+" .

# OpenAI / Anthropic
grep -rE "sk-[A-Za-z0-9]{32,}" .
grep -rE "sk-ant-[A-Za-z0-9_-]{90,}" .

# Generic high-entropy strings in env files
grep -rE "^[A-Z_]+=[A-Za-z0-9/+=]{32,}$" . --include="*.env*"
```

For full repo coverage, use `git ls-files` to scope to tracked files and avoid `node_modules`:

```bash
git ls-files | xargs grep -lE 'sk_live_|ghp_|AKIA[A-Z0-9]{16}|sk-ant-|AIza[A-Za-z0-9_-]{35}' 2>/dev/null
```

### Tooling

| Tool | Use |
|---|---|
| `gitleaks detect` | Fast, low FP, run as pre-commit and in CI; supports custom rules |
| `trufflehog git file://.` | Verifies findings against the real API (high confidence) |
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
trufflehog git file://. --since-commit=<first-commit>

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

### Triaging a found secret

When you find a leaked secret:

1. **Verify it's live** — use the provider's verification (`aws sts get-caller-identity`, `stripe balance retrieve`, `curl -H "Authorization: Bearer $TOKEN" ...`) — don't assume; some leaked keys are already revoked or were sandbox-only
2. **Determine exposure window** — first commit it appeared in, when the repo went public, when CI logs were retained from
3. **Determine blast radius** — what does this key access? What can be done with it? IAM permissions, Stripe live vs test, GitHub `repo` vs `admin:org`
4. **Rotate immediately** — generate a new key, deploy it, then revoke the old one (revoke-first breaks prod)
5. **Audit for use** — provider audit logs (CloudTrail, GitHub audit log, Stripe events) for any activity from the leaked credential
6. **Then clean** — remove from current code, then optionally history-rewrite (low priority once rotated)
7. **Document** — incident report, even if rotation was clean; recurrence patterns surface trends

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
- **CI secrets accessible from PRs from forks** — GitHub's default behavior was previously dangerous; verify `pull_request_target` and secret accessibility
- **Build args used for secrets** — `--build-arg AWS_SECRET=...` ends up in image history (use `--secret`/BuildKit instead)
- **Logging frameworks dump `process.env`** on unhandled exception — Sentry / Datadog / Bugsnag scrub config required
- **Secret stored in K8s as plain Secret** without etcd encryption — base64 is encoding, not encryption (see `container-audit`)
- **OAuth client secrets in mobile apps** — public clients can't hold secrets; PKCE is the answer

## Output Format

```markdown
# Secrets Audit Report
## Scope: [repos / environments / managers covered]
## Date: [date]

### Live leaked secrets found
| Provider | Location | First seen (commit / date) | Verified live? | Rotation status |
|---|---|---|---|---|

### Secrets-management posture
| Category | Status | Notes |
|---|---|---|

### Recommendations
| Priority | Item | Owner | Deadline |
|---|---|---|---|
```

Disposition rule (Fixed / Deferred / Accepted Risk) per `owasp-audit`.

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
- `gitleaks`, `trufflehog`, `detect-secrets` documentation
- GitHub Secret Scanning + Push Protection documentation
- HashiCorp Vault Architecture / Best Practices
- AWS Secrets Manager Best Practices
- "Twelve-Factor App" — Config principles
