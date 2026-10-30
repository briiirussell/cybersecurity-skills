# scanner-pipeline

> Set up and run deterministic security scanners across a repo or a whole fleet of repos — gitleaks, trufflehog, semgrep, osv-scanner, trivy, checkov, Brakeman, govulncheck, Supabase advisors, and (guarded) nuclei/ZAP — then normalize their output to findings.json or SARIF, dedupe, suppress with expiry, schedule in CI, and hand findings to fix agents. Use when the user mentions 'run scanners,' 'security scanning pipeline,' 'set up gitleaks,' 'semgrep in CI,' 'osv-scanner,' 'trivy fs,' 'SARIF,' 'code scanning,' 'scan all my repos,' 'security-scan workflow,' 'weekly security scan,' 'Supabase RLS advisor,' 'dedupe scanner findings,' 'suppression file,' 'stop asking Claude to hack my app,' or wants tools, not an agent, to find the bugs.

# Scanner Pipeline — Run the Real Tools, Normalize, Hand Off

Stop asking the agent to hack your app. Have it pick the right deterministic scanner for each layer, run it non-interactively, merge the output into one format, and route each finding to a fix agent. Scanners find the same thing every time; an agent review finds it when it happens to look.

Field evidence from a 45-app sweep in October 2026 (`patch-sweep`). An agent-led review eventually found all of these; a scanner would have flagged each one on the first run:
- **10 Supabase tables with RLS disabled**, readable and writable with the public anon key — including 472k inbound email bodies. Supabase's own security advisor reports this as `rls_disabled_in_public`.
- **An always-true RLS policy**: `csr.collection_id = csr.collection_id`. A custom semgrep rule over migrations catches it (below).
- **Separate `npm audit`, `pnpm audit`, and `bundle-audit` runs per repo**, where one `osv-scanner` pass covers every lockfile.

**This skill orchestrates.** Interpreting a tool's findings in depth stays with the layer skill: `secrets-audit`, `dependency-audit`, `container-audit`, `cloud-audit`, `owasp-audit`. Active exploitation is `web-pentest` / `red-team-engagement`.

**Why `Write` is pre-approved:** this skill's main output is files — the `scanner-pipeline.md` plan, a `.github/workflows/security-scan.yml`, and scanner configs. It writes only those, and only inside the target repo. Live-app scanners (`nuclei`, `zap`) are deliberately not pre-approved; they always prompt.

Cross-references: `finding-triage` (ranking and disposition), `secrets-audit`, `dependency-audit`, `container-audit`, `cloud-audit` (Supabase advisors, PaaS), `web-pentest` (authorization for live scans), `cicd-security` (SHA-pinned Actions, workflow hardening; zizmor / actionlint results), `patch-sweep` (fleet CVE response), `log-watch`.

## Authorization

Before running anything, confirm:
1. **Repos:** the user owns or is authorized to scan each one. For fleet mode, the owners/orgs to enumerate.
2. **Live targets:** only domains the user owns **and names explicitly** in this conversation. Not "whatever the repo deploys to" — the user says the hostnames.
3. **Where results go:** local files only, GitHub code scanning, or issues. Secret findings never go into a public issue.

Refuse to: run live scanners (nuclei, ZAP, Burp) against hosts the user doesn't own or didn't name; scan third-party or shared hosts (a shared Supabase/Vercel/Heroku hostname, a CDN, an API you call); run ZAP active scan or nuclei intrusive templates without the `web-pentest` authorization step; print secret values anywhere.

## 1. Detect the stack and pick tools per layer

Read the repo first: lockfiles, `Dockerfile`, `*.tf`, `supabase/`, `Gemfile`, `go.mod`, `.github/workflows/`. Then pick one tool per layer, preferring multi-ecosystem tools over per-package-manager ones.

| Layer | Primary | Stack-specific add-ons | Fallback |
|---|---|---|---|
| Secrets | `gitleaks git` (full history) | `trufflehog git --only-verified` for live verification | — |
| Code (SAST) | `semgrep scan` | Brakeman (Rails), gosec (Go), CodeQL (if GHAS), custom semgrep rules (below) | — |
| Dependencies | `osv-scanner scan source -r .` (npm, pnpm, yarn, Bundler, pip, Go, Cargo, Composer, Maven in one pass) | `bundle-audit` (Rails), `govulncheck` (Go, call-graph reachability), `pip-audit` | `npm audit` / `pnpm audit --prod` / `yarn audit` |
| Infra / IaC / containers | `trivy fs --scanners vuln,misconfig,secret .` | `checkov -d .` (Terraform, CloudFormation, k8s, Actions), `trivy image <img>` | — |
| Database (Supabase) | Supabase security advisor (`supabase db advisors`, or Management API `GET /v1/projects/{ref}/advisors/security`) | `supabase db lint` (plpgsql_check: function errors, not RLS), semgrep rule over `supabase/migrations/` | `pg_policies` / `pg_tables.rowsecurity` query |
| Live app (guarded) | ZAP baseline (passive) | nuclei with `-rl` | — |

Commands, non-interactive, one output file per tool under `.security/out/`:

```bash
mkdir -p .security/out
# Secrets — full history, values redacted
gitleaks git . --redact --report-format sarif --report-path .security/out/gitleaks.sarif
trufflehog git file://. --only-verified --json --no-update | jq -c 'del(.Raw, .RawV2)' > .security/out/trufflehog.jsonl
# Code
semgrep scan --config p/default --config .semgrep/ --metrics=off --sarif --output .security/out/semgrep.sarif
# Dependencies (all lockfiles at once)
osv-scanner scan source -r . --format sarif --output .security/out/osv.sarif
# Infra / IaC / container files
trivy fs --scanners vuln,misconfig,secret --format sarif --output .security/out/trivy.sarif .
checkov -d . -o sarif --output-file-path .security/out/
# Rails
bundle-audit check --update
brakeman --no-pager -f sarif -o .security/out/brakeman.sarif
# Go
govulncheck -format sarif ./... > .security/out/govulncheck.sarif
gosec -fmt sarif -out .security/out/gosec.sarif ./...
# Supabase (check flags with `supabase db advisors --help` for your CLI version)
supabase db advisors --linked
curl -s -H "Authorization: Bearer $SUPABASE_ACCESS_TOKEN" \
  "https://api.supabase.com/v1/projects/<ref>/advisors/security" > .security/out/supabase-advisors.json
```

Add `.security/out/` to `.gitignore`. Flag versions differ between tool majors (gitleaks 8.19+ uses `git`/`dir` subcommands; osv-scanner v2 uses `scan source`); run `<tool> --help` once and adjust rather than guessing.

### Custom rule: always-true RLS policy

The motivating bug: `using (csr.collection_id = csr.collection_id)` compares a column with itself, so the policy passes for every row. The author meant the outer table's column. Semgrep has no first-class SQL parser, so use generic mode: `pattern-inside: create policy ... ;` plus a regex that backreferences the left-hand side. Full rule file (self-comparison, literal `true`, and public tables to cross-check for RLS): [references/semgrep/supabase-rls.yml](references/semgrep/supabase-rls.yml). Copy it into the repo's `.semgrep/` so the CI workflow picks it up. To write a rule like this from a confirmed finding, with tests, see `variant-analysis`.

```bash
semgrep scan --metrics=off --config .semgrep/supabase-rls.yml supabase/migrations/
# quick check without semgrep (PCRE backreference)
rg -nP '(?i)\b([a-z_][a-z0-9_]*\.[a-z_][a-z0-9_]*)\s*=\s*\1\b' supabase/migrations/
# portable: BSD and GNU grep -E accept \1 in practice (ugrep aliased as grep does not; use /usr/bin/grep)
grep -rEni '([a-z_][a-z0-9_]*\.[a-z_][a-z0-9_]*)[[:space:]]*=[[:space:]]*\1([^a-z0-9_]|$)' supabase/migrations/
```

Pair it with the RLS-disabled check, which needs the database, not the source:
```sql
select schemaname, tablename from pg_tables
where schemaname = 'public' and rowsecurity = false;
```

## 2. Secrets, done carefully

- **Scan full history, not HEAD.** `gitleaks git` walks every commit; `gitleaks dir` only sees the working tree. A secret deleted last year is still in every clone.
- **Verified means live.** `trufflehog --only-verified` checks each candidate against the provider's API. That sends the found key to its provider, which uses it, so trufflehog isn't pre-approved: the run prompts, and the user says yes to the check. A verified hit is **P0**: record it as `confirmed`, and **rotate before you clean history**. Rewriting history first leaves a live key in every fork and clone while you work. Hand rotation to `secrets-audit`.
- **Never print values.** Use `--redact` for gitleaks; strip `Raw`/`RawV2` from trufflehog JSON. Reports, issues, PR comments, and agent hand-offs name the detector, file, commit, and a hash of the value — never the value. Fingerprint secrets as `secret:<detector>:<sha256(value)[:12]>` so the same key in five files dedupes to one finding.
- **Unverified hits** are `needs_validation`, not noise: the provider may not support verification, or the key may be for an internal system.

## 3. Live-app scanning guardrails

Live scanning sends traffic to a running system. Follow `web-pentest`'s authorization step first; this section only sets the rate and order.

1. **Only hostnames the user owns and named.** Never the platform's shared domain root, a CDN, an auth provider, or a third-party API the app calls. Use `-u https://app.example.com`, never a wildcard or a list scraped from DNS.
2. **Passive before active.** ZAP baseline spiders and reports passively:
   ```bash
   docker run --rm -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t https://app.example.com -J zap.json
   ```
   Active scan (`zap-full-scan.py`) only after the user confirms, ideally on a staging copy.
3. **Low rate.** `nuclei -u https://app.example.com -rl 10 -c 5 -severity medium,high,critical -exclude-tags intrusive,dos,fuzz -jsonl -o nuclei.jsonl`. Raise only with the user's go-ahead.
4. **Stop on signs of harm:** 5xx spikes, rate-limit responses, account lockouts. Report and pause.

## 4. Normalize the output

Every tool speaks a different format. Convert all of them to the repo's findings format, then export SARIF once. Format, fields, and validator: [references/findings-format.md](references/findings-format.md); validate with [references/validate-findings.mjs](references/validate-findings.mjs); export with [references/to-sarif.mjs](references/to-sarif.mjs).

**Import rules:**
- A scanner hit enters as `verdict: "needs_validation"`, with `blockers: ["scanner result, not yet triaged"]` and a `validation_plan` naming the exact re-run command. The tool's own severity goes in `evidence[].description`; the record gets a real `severity` only when `finding-triage` confirms it. Exception: a verified live secret is `confirmed` on import.
- `skill: "scanner-pipeline"`, plus the tool name and rule id in `evidence`.
- `cwe` from the rule's metadata (semgrep, Brakeman, gosec, checkov all carry one). For dependency advisories use the advisory's CWE if present, otherwise leave it empty — don't guess.
- `confidence`: static-only results cap at `medium`. Verified secrets and reachability-confirmed `govulncheck` results can be `high`.

**Dedupe across tools** by fingerprint — a stable root-cause id with no line numbers, severity, or verdict:

| Kind | Fingerprint | Collapses |
|---|---|---|
| Dependency | `dep:<ecosystem>:<package>:<canonical-id>` (CVE if one exists, else GHSA, else OSV id) | osv-scanner + trivy + npm audit + Dependabot on the same advisory |
| Secret | `secret:<detector>:<sha256(value)[:12]>` | gitleaks + trufflehog + trivy on the same key, across files and commits |
| Code | `sast:<cwe>:<file>:<enclosing function or route>` | semgrep + CodeQL + Brakeman on the same sink |
| IaC | `iac:<resource address>:<check family>` | trivy misconfig + checkov on the same resource |
| Database | `db:<project>:<schema.table>:<lint name>` | advisor + custom semgrep rule on the same table |

Keep every tool's evidence on the merged record; the fix agent needs it.

**Suppression file** — `.security/suppressions.yml`, one entry per fingerprint:
```yaml
- fingerprint: dep:npm:next:CVE-2026-XXXXX
  tool: osv-scanner
  reason: "Static export; no server runtime. Advisory requires Server Actions."
  owner: "@jdoe"
  added: 2026-10-26
  expires: 2027-01-24      # max 90 days; expired entries resurface the finding
```
Rules: every entry has a reason, owner, and expiry (90 days max); expired entries are ignored and the finding comes back; the agent proposes suppressions but the user approves each one. Mirror entries into native ignore files only where the tool supports a reason and expiry — `osv-scanner.toml` `[[IgnoredVulns]]` with `ignoreUntil` and `reason`, `.trivyignore` with `exp:YYYY-MM-DD` — and keep `suppressions.yml` as the source of truth. Suppressed findings go into findings.json as `rejected` with `ruled_out_by` pointing at the suppression entry, so re-runs don't re-raise them.

## 5. Fleet mode

```bash
gh repo list <owner> --limit 1000 --source --no-archived --json nameWithOwner,defaultBranchRef,pushedAt
```
`--source` drops forks; `--no-archived` drops archived repos. Repeat per owner/org. For each repo: shallow-clone the **production branch** (from `patch-sweep` Step 2 if you have it; default branch otherwise) — except for secrets, which need full history (`git clone --filter=blob:none` is enough for gitleaks). Run the per-repo pipeline in parallel (a handful at a time), writing `.security/out/<repo>/`. Then roll up:

```markdown
| repo | layer | tool | sev | finding | status |
|---|---|---|---|---|---|
| acme/api | db | supabase advisor | (tool: ERROR) | rls_disabled_in_public: public.inbound_emails | needs_validation |
| acme/api | secrets | trufflehog | P0 | verified Stripe live key in commit a1b2c3d (value hash 3f9e…) | confirmed — rotate |
| acme/web | deps | osv-scanner | (tool: CRITICAL) | next 15.5.10 — CVE-2026-XXXXX | needs_validation |
```
`sev` shows the tool's label in parentheses until `finding-triage` sets a real severity. Sort P0 secrets first, then by tool severity.

## 6. CI and schedule

Scaffold [references/security-scan.yml](references/security-scan.yml) into the repo as `.github/workflows/security-scan.yml`. It:
- runs gitleaks, osv-scanner, and semgrep on every PR (gitleaks over the PR's commits; semgrep diff-aware against the base);
- runs a **weekly full scan** (full git history, all rules) and on `workflow_dispatch`;
- can be called from other repos with `workflow_call`, so one copy serves a fleet;
- uploads SARIF to GitHub code scanning when available (public repos, or private with GitHub Advanced Security) and always keeps SARIF as a workflow artifact otherwise;
- pins every Action to a full commit SHA and every container image to a digest (`cicd-security`). The SHAs in the template were looked up from the upstream release tags on 2026-10-26; update them with Dependabot or Renovate, not by switching to tags.

When code scanning isn't available, open or update one issue per fingerprint (title = fingerprint, body = evidence without secret values) instead of dumping SARIF into a comment.

## 7. Hand-off to fixes

1. **Triage first.** Every `needs_validation` record goes to `finding-triage` for verdict, severity, and disposition. P0 verified secrets skip the queue to rotation.
2. **One finding per fix agent.** Give it the merged record: fingerprint, every tool's evidence, the exact re-run command, and the owning layer skill to consult. Not the whole board.
3. **Confirm by re-running the specific tool** on the fix branch — the same command, same config — and record the before/after. The finding closes only when that tool no longer reports the fingerprint.
4. **Never edit scanner config to make a finding disappear.** No deleting rules, no narrowing paths, no adding a suppression from inside a fix agent. A fix agent that thinks a finding is a false positive reports it back for a suppression the user approves.

## Output Format

Write `scanner-pipeline.md` at the repo root (or one per fleet):

```markdown
# Scanner Pipeline — [repo or fleet] — [date]

## Stack detected
[languages, package managers, frameworks, IaC, Supabase y/n, live targets named by user]

## Tools per layer
| layer | tool | version | command | output |
|---|---|---|---|---|

## Schedule
- PR: gitleaks (PR commits), osv-scanner, semgrep (diff-aware)
- Weekly: full history + all layers, [day/time UTC]
- Results: code scanning / artifact + issues

## Suppression policy
`.security/suppressions.yml`; reason + owner + expiry ≤ 90 days; user approves each entry.

## First run
- findings.json: [N] records ([c] confirmed, [n] needs_validation, [r] rejected)
- Roll-up board: [table above]

## Hand-off
[fingerprints sent to finding-triage; P0 secrets sent to rotation]
```

Optional scaffolds: `.github/workflows/security-scan.yml`, `.gitleaks.toml` (extend the default config with org-specific rules), `.semgrep/` (custom rules such as the RLS rule), `osv-scanner.toml`.

## Boundaries

- Orchestration only. Deep interpretation lives in the layer skills.
- No active exploitation. A scanner hit that needs proving goes to `web-pentest` with its authorization step.
- Live scans: owned and named hosts only, passive first, low rate.
- Never print, commit, or post secret values.
- Never weaken a scanner's config to pass CI.

## References

- [gitleaks](https://github.com/gitleaks/gitleaks), [trufflehog](https://github.com/trufflesecurity/trufflehog), [semgrep](https://semgrep.dev/docs/), [osv-scanner](https://google.github.io/osv-scanner/), [trivy](https://trivy.dev/), [checkov](https://www.checkov.io/), [Brakeman](https://brakemanscanner.org/), [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck), [ZAP baseline](https://www.zaproxy.org/docs/docker/baseline-scan/), [nuclei](https://docs.projectdiscovery.io/tools/nuclei/)
- [Supabase database advisors](https://supabase.com/docs/guides/database/database-advisors) and [Splinter](https://github.com/supabase/splinter); [`supabase db lint`](https://supabase.com/docs/reference/cli/supabase-db-lint)
- [GitHub — uploading SARIF](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/uploading-a-sarif-file-to-github)
- Idea source: @neilsuperduper, 2026-10-25 (paraphrased) — run real tools per layer and hand their findings to agents to fix; issue #84

## Reference files

This skill links to supporting files under `references/`. They are not inlined in this adapter; open them on GitHub (or in `skills/scanner-pipeline/references/` if you have the repo checked out):

- [references/findings-format.md](https://github.com/briiirussell/cybersecurity-skills/blob/main/skills/scanner-pipeline/references/findings-format.md)
- [references/findings.schema.json](https://github.com/briiirussell/cybersecurity-skills/blob/main/skills/scanner-pipeline/references/findings.schema.json)
- [references/security-scan.yml](https://github.com/briiirussell/cybersecurity-skills/blob/main/skills/scanner-pipeline/references/security-scan.yml)
- [references/semgrep/supabase-rls.yml](https://github.com/briiirussell/cybersecurity-skills/blob/main/skills/scanner-pipeline/references/semgrep/supabase-rls.yml)
- [references/to-sarif.mjs](https://github.com/briiirussell/cybersecurity-skills/blob/main/skills/scanner-pipeline/references/to-sarif.mjs)
- [references/validate-findings.mjs](https://github.com/briiirussell/cybersecurity-skills/blob/main/skills/scanner-pipeline/references/validate-findings.mjs)
