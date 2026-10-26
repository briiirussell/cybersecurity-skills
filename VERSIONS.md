# Cybersecurity Skills Versions

Current versions of all skills. Agents can compare against local versions to check for updates.

| Skill | Version | Last Updated |
|-------|---------|--------------|
| agent-supply-chain-audit | 1.0.1 | 2026-10-26 |
| ai-risk-management | 1.0.2 | 2026-10-26 |
| api-audit | 1.1.1 | 2026-10-26 |
| breach-patterns | 1.0.2 | 2026-10-26 |
| business-logic-testing | 1.0.0 | 2026-10-26 |
| cloud-audit | 1.1.1 | 2026-10-26 |
| container-audit | 1.0.1 | 2026-10-26 |
| crypto-audit | 1.0.1 | 2026-10-26 |
| csf-mapping | 1.0.1 | 2026-10-26 |
| dependency-audit | 1.2.1 | 2026-10-26 |
| disk-forensics | 1.0.1 | 2026-10-26 |
| finding-triage | 1.1.1 | 2026-10-26 |
| hipaa-audit | 1.0.1 | 2026-10-26 |
| iam-audit | 1.0.2 | 2026-10-26 |
| incident-triage | 1.0.4 | 2026-10-26 |
| log-watch | 1.0.0 | 2026-10-26 |
| mobile-audit | 1.0.1 | 2026-10-26 |
| osint-recon | 1.0.1 | 2026-10-26 |
| owasp-audit | 1.2.1 | 2026-10-26 |
| patch-sweep | 1.0.1 | 2026-10-26 |
| pci-audit | 1.0.1 | 2026-10-26 |
| personal-opsec | 1.0.0 | 2026-10-26 |
| privacy-engineering | 1.0.1 | 2026-10-26 |
| prompt-injection | 1.1.1 | 2026-10-26 |
| recon | 1.0.1 | 2026-10-26 |
| red-team-engagement | 1.0.1 | 2026-10-26 |
| scanner-pipeline | 1.0.1 | 2026-10-26 |
| secrets-audit | 1.1.1 | 2026-10-26 |
| security-comms | 1.0.1 | 2026-10-26 |
| siem-detection | 1.0.2 | 2026-10-26 |
| soc-operations | 1.0.2 | 2026-10-26 |
| threat-hunting | 1.0.3 | 2026-10-26 |
| threat-modeling | 1.0.1 | 2026-10-26 |
| vuln-research | 1.0.1 | 2026-10-26 |
| web-pentest | 1.1.1 | 2026-10-26 |

## Recent Changes

### 1.19.4 (2026-10-26)

CI fix: code scanning raised every baselined SkillSpector match (221 intentional examples) as an open alert. GitHub ignores the `kind: external` suppressions SkillSpector writes for baselined results. Repo tooling only; no skill content changes.

**Fixed**

- `.github/scripts/merge-sarif.mjs` drops results that SkillSpector already suppressed via `.skillspector-baseline.yaml`, and records how many it dropped in the run's properties. Code scanning now shows only real, unbaselined findings, and those still fail the scan job first. Uploading the clean run closes the 221 stale alerts on `development` and the open PRs.

### 1.19.3 (2026-10-26)

CI fix: the SkillSpector scan passed, but uploading its SARIF to GitHub code scanning failed with "more runs than allowed (35 > 20)". Repo tooling only; no skill content changes.

**Fixed**

- `.github/scripts/merge-sarif.mjs` now folds every per-skill scan into one SARIF run. Paths are still rewritten to `skills/<skill>/…`. Rules are de-duplicated by id, and the indexes pointing to rules and files are remapped. The catalog can now grow past 20 skills without breaking the upload.

### 1.19.2 (2026-10-26)

Tightens two pre-approvals that were broader than they looked. Found in the 1.19.1 SkillSpector triage. (#65)

**Fixed**

- **patch-sweep** (1.0.1): removed `Bash(git branch:*)`. The prefix also matched `git branch -D` / `-m`, and the skill never needed it. Branch inspection goes through `git ls-remote` and `git log`, which are still pre-approved.
- **scanner-pipeline** (1.0.1):
  - `osv-scanner:*` is narrowed to `osv-scanner scan:*`, so `osv-scanner fix` (which rewrites lockfiles) now prompts.
  - `trivy:*` is narrowed to `trivy fs` / `image` / `config`.
  - `semgrep` and `pip-audit` are no longer pre-approved. Both have a file-rewriting flag (`--autofix` / `--fix`), and a prefix rule can't exclude a trailing flag, so they now prompt each time.
- `docs/security-scanning.md`: table rows updated to match.

### 1.19.1 (2026-10-26)

Repo trust: CI, lint, and a SkillSpector scan on every PR. Repo tooling only; no skill content changes.

**Added**

- **`.github/workflows/ci.yml`**: runs on PRs and pushes to `development` and `main`. Every action is pinned to a full commit SHA, and permissions are kept to the minimum. (#69)
  - **Skill lint** (`scripts/lint-skills.mjs`, no dependencies). Fails when:
    - `name` doesn't match the folder
    - the description is outside 200–1024 characters
    - `SKILL.md` is 500 lines or more
    - a cross-referenced skill or relative link doesn't resolve
    - `allowed-tools` pairs `WebFetch` with unscoped `Bash`

    It also warns when two skills share a trigger phrase.
  - **Adapter drift:** rebuilds the adapters and shared reference copies, and fails if the committed copies are stale.
  - **Tests:** `npm test` (Node 22).
  - **SkillSpector:** NVIDIA [SkillSpector](https://github.com/NVIDIA/SkillSpector), pinned commit, `--no-llm`, one skill at a time. The tool rejects `--baseline` on recursive scans and reports paths relative to each skill. SARIF is merged and uploaded to code scanning.
- **`.skillspector-baseline.yaml`**: 117 narrow rules, each with a written reason. They cover all 221 current matches, every one of them an intentional example. A security skill has to name `~/.aws/credentials`, show an injection payload, and grep for collector domains. A `*` skill wildcard is only allowed for files copied from `shared/`. `node .github/scripts/skillspector-baseline.mjs --check` validates the file.
- **`docs/security-scanning.md`**: the CI checks, how the baseline works, how to scan this repo yourself before installing, and the full allowed-tools before → after table from 1.19.0 with a reason per skill.
- **README:** CI badge, a "Security scanning" section, build and test commands, and how `shared/` copies work.

**Changed**

- `CLAUDE.md` and `CONTRIBUTING.md`: directory tree and commands now cover `shared/` + `manifest.json` ("edit shared/, never the copies"), `npm test`, the lint, and the baseline check. The contributor checklist points at the CI jobs.

### 1.19.0 (2026-10-26)

**Heads up: this may change how skills feel to use.** `allowed-tools` in a Claude Code skill lists tools that run **without a permission prompt** while the skill is active. It is not an access list or a ceiling. Before this version, 26 of 29 skills pre-approved plain `Bash`, 24 pre-approved `Write`, and 5 paired `Bash` with `WebFetch`. That last combination gives attacker-controlled web content a path to the shell with no prompt in between. Nothing is removed from what a skill *can* do. Commands that used to run silently now ask first, unless they're read-only and listed below. If you relied on the old pre-approvals for unattended runs, add the specific commands to your own permission settings. Credit: NVIDIA [SkillSpector](https://github.com/NVIDIA/SkillSpector) rule LP3. (#65)

**Changed**

- **No skill pairs `WebFetch` with unscoped `Bash` anymore.** `recon` and `osint-recon` keep only `whois` / `dig`. `vuln-research` keeps only read-only package queries (`npm ls`, `pip show`, `bundle info`, `go list`). `breach-patterns` and `web-pentest` pre-approve no shell at all; every active test against a target prompts.
- **Bash removed** (the skill runs no commands, or its commands hit a live target and should prompt): ai-risk-management, api-audit, breach-patterns, crypto-audit, csf-mapping, finding-triage, hipaa-audit, mobile-audit, pci-audit, privacy-engineering, prompt-injection, red-team-engagement, siem-detection, threat-hunting, web-pentest.
- **Bash scoped to read-only commands:**
  - cloud-audit and iam-audit: documented `aws` / `gcloud` / `az` read calls
  - container-audit: `trivy image|config`, `kube-bench run`
  - dependency-audit: exact `npm audit` / `pnpm audit --prod` rules so `audit fix` always prompts; plus `npm ls`, `pnpm why`, `yarn why`, `yarn npm audit`, `osv-scanner scan`, `govulncheck`, `bundle audit`, `composer audit`, `dotnet list package`, `trivy fs|image`
  - disk-forensics: `file`, `sha256sum`, `fdisk -l`, `mmls`, `fsstat`, `fls`, `icat`, `strings`
  - incident-triage: `ps`, `netstat`, `lsof`, `who`
  - owasp-audit: exact `npm audit` rules
  - secrets-audit: `trufflehog git`
- **`Write` dropped everywhere** except the skills whose main output is a file: siem-detection (rule files), scanner-pipeline (plan + workflow) and log-watch (plan). Edits still work; they just prompt.
- The new 1.5.0–1.10.0 skills already shipped with scoped grants. agent-supply-chain-audit only pre-approves `skillspector scan --no-llm`, because LLM mode sends file contents to a provider.
- `CLAUDE.md` and `templates/skill-template.md` now describe `allowed-tools` correctly. The template default is `Read, Grep, Glob`.
- Note: the Cursor and Codex adapters carry no tool restrictions at all. Those agents use their own permission settings.

All 29 pre-existing skills get a patch bump. The full before → after table with a reason per skill ships in `docs/security-scanning.md` in 1.19.1.

### 1.18.0 (2026-10-26)

cloud-audit adds a PaaS section. Many small teams have no AWS account at all: production is a Vercel team, a few Heroku apps and a Render service. Every check here comes from a real October 2026 fleet sweep.

**Changed**

- **cloud-audit** (1.1.0). New section **"PaaS (Vercel / Netlify / Heroku / Render / Railway / Fly)"**, with read-only CLI/API commands for each check (#83):
  1. **Stale manual production deploys.** One client site was serving a 96-day-old `vercel deploy --prod` from a laptop while `main` held only a README. Compare the deploy's source, age and commit against the head of the production branch.
  2. **Silently broken git deploys.** For example, an Ignored Build Step running `git diff` while `.vercelignore` excluded `.git`, or a second project still linked to an old org.
  3. **Legacy projects still serving old code** on `*.vercel.app` after their domains moved.
  4. **Duplicate projects per repo**, each carrying its own copy of env vars and secrets.
  5. **Preview and production exposure.** Is deployment protection on? Can `*.vercel.app` addresses bypass the WAF in front of the custom domain? Do preview env vars point at production databases?
  6. **The build queue as an availability risk** during an emergency patch.
  7. **Heroku specifics:** stack and libvips version, runtime pin vs what's actually running, `pg:backups` schedule and restore test, live keys in review-app config vars.
  8. **Repo security defaults:** Dependabot alerts, secret scanning, push protection, branch protection. They were off on 142 repos in one account.
  - New finding type: **"Production not reproducible from source (manual deploy / branch mismatch)"**.
  - Netlify, Render, Railway and Fly versions of the checks live in `references/paas.md`. Supabase RLS advisors are covered too.
  - Cross-references to `patch-sweep` and `scanner-pipeline`. The disposition list now matches the shared set.
- README: cloud-audit row updated.

### 1.17.0 (2026-10-26)

web-pentest gets a combined white-box + black-box mode and a paired-evidence rule for every PoC.

**Changed**

- **web-pentest** (1.1.0)
  - **New section: "Combined white-box + black-box mode".** When you have both the source and a running instance, build a Target Map linking code handlers to live endpoints, along with their shared auth and config. Prioritization runs both ways: code findings guide live testing, and anomalies seen live decide which code gets read first. The authorization check still applies to the live target. owasp-audit points here. (#76)
  - **Paired evidence.** A validated finding shows the attack request next to its baseline or control: unauthenticated vs authenticated, benign vs payload, owner vs non-owner. IDOR / BOLA findings must show owner and non-owner requests that are identical except for the token. Single-request PoCs no longer count as validated. (#76)
  - **Phase 8 (business logic)** is kept and now hands off to `business-logic-testing` for invariants, state-machine abuse and dynamic race proofs. (#74)
  - The report uses the shared verdicts (`confirmed` / `needs_validation` / `rejected`) and severity calibration. Ideas paraphrased from [Strix](https://github.com/usestrix/strix) (Apache-2.0); its never-refuse posture is not adopted.
- README: web-pentest row updated.

### 1.16.0 (2026-10-26)

prompt-injection now catches instructions a human reviewer can't see but the model reads, and MCP tool poisoning.

**Changed**

- **prompt-injection** (1.1.0)
  - **New Step 3: inspect instruction-bearing content for concealment.** Applies to system prompts, RAG corpora, tool and MCP manifests, and agent instruction files. Copy-paste patterns in both `rg` and portable `grep` for:
    - invisible characters (zero-width, bidi overrides, word joiners, BOM, soft hyphen, and the Unicode tag block)
    - directive keywords hidden in HTML or `[//]: #` comments
    - long whitespace runs that push text out of view
    - `data:text/...;base64,` payloads

    The old Steps 3–7 are now 4–8. (#70)
  - **MCP tool poisoning:** injection inside parameter descriptions, a tool's description not matching its behaviour, pinning and diffing tool definitions after approval (rug pulls), and Unicode deception in tool names. (#70)
  - Anti-refusal phrasing added to the indirect-injection patterns. New output category: **Hidden Instruction / Tool Poisoning**. NVIDIA [SkillSpector](https://github.com/NVIDIA/SkillSpector) (Apache-2.0) added to References. (#70)
  - **Hardening notes are no longer findings.** "Low — defense-in-depth improvements" moves out of the findings list into a "Hardening notes (not findings)" section, with severity per `references/severity-calibration.md`. (#63)
  - Cross-references to `agent-supply-chain-audit`, `log-watch` and `personal-opsec`.
- README: prompt-injection row updated.

### 1.15.0 (2026-10-26)

secrets-audit now covers AI agent configs and transcripts, which have become one of the most common places secrets leak. It also checks key type before rating a find.

**Changed**

- **secrets-audit** (1.1.0)
  - **AI agent locations** (#73):
    - `env` blocks in `.mcp.json`, `.cursor/mcp.json` and `claude_desktop_config.json`
    - `.claude/settings.local.json`, including `apiKeyHelper`, which runs a shell command
    - agent session transcripts such as `~/.claude/projects/**/*.jsonl`, where secrets get pasted
    - the Cursor, Codex and Gemini equivalents

    The transcript greps only list files, count matches or mask values, so running them from an agent doesn't copy secrets into a fresh transcript. New checklist item: agent configs are gitignored or contain only `${ENV}` references.
  - **Exfiltration collectors as egress indicators:** Discord, Telegram and Slack webhooks, webhook.site, requestbin / pipedream, ngrok, interactsh and similar. Cross-referenced from incident-triage and threat-hunting. (#73)
  - **Key-type check before rating.** Publishable, restricted and secret keys are different findings (Google `AIza…` browser keys, Stripe `pk_` / `rk_` / `sk_`, Supabase anon vs service_role, Firebase config). A public identifier called a key is not a secret. (#63)
  - **findings.json** is written and validated, with secret values redacted to prefix + last 4. (#64)
  - Cross-references to `agent-supply-chain-audit`, `scanner-pipeline` and `personal-opsec`.
- `incident-triage` (1.0.3), `threat-hunting` (1.0.2): cross-references to secrets-audit's collector-domain list for egress checks.
- README: secrets-audit row updated.

### 1.14.0 (2026-10-26)

dependency-audit gets field feedback from a 45-app CVE sweep (October 2026), CI/release trust handoffs, and package-source redirection checks.

**Changed**

- **dependency-audit** (1.2.0)
  - **Step 0: audit the branch that's actually deployed.** Confirm the production branch, plus the deployed package in a monorepo, and the package manager before running anything. In one real repo, `main` held only a README. (#81)
  - **Fixing safely**, from the sweep, in `references/fixing-safely.md` (#81):
    - `pnpm audit --fix` writes open-ended `>=` overrides that force major jumps. Rewrite them to same-major ranges.
    - In-range re-resolves can create duplicate singleton packages. A real case: two copies of `prosemirror-model` broke a live editor while install, lint and build all passed.
    - When a fix is blocked, name the intermediate package that pins the vulnerable version rather than reporting "no fix available".
    - Fixes can raise the Node `engines` floor.
    - pnpm and yarn need their own audit commands. `npm audit` in a pnpm repo fails silently.
    - New "Verify after fixing" checklist: singleton dupes, engines floor, clean `--frozen-lockfile` / `npm ci`, and a preview smoke test of the features those packages power.
  - **Runtimes** (#81):
    - Every pin has to move together (`.ruby-version`, Gemfile `ruby`, lockfile, Dockerfile `ARG`, CI image, buildpack; `.nvmrc`, `.node-version`, `engines`, platform setting).
    - Ruby gotchas: `--conservative` still jumping shared deps, the tighten-resolve-restore pin trick, Brakeman being latest-only, patch-level Rails breaking specs.
    - "No in-place fix exists" is separated from in-range fixes.
    - Platform mitigations count as compensating controls.
  - **New dispositions:** `Mitigated (platform/config)` and `Requires major migration (est. effort)`. (#81)
  - **CI and release trust handoffs** in `references/ci-release.md`, plus a Step 5b summary (#71):
    - Ten patterns, each with a grep: `workflow_run` / `pull_request_target` restoring artifacts or caches into privileged jobs, cache keys that PRs can write, missing or `write-all` `permissions:` combined with a reachable privileged step, OIDC `id-token: write` and the cloud trust-policy subject, release jobs promoting by tag instead of digest, a checksum fetched from the same origin as the artifact, and more.
    - New rule next to the CVE table: a mutable or known-vulnerable dependency is not a finding by itself. Show who can influence resolution and what boundary follows.
    - Facts that only exist on the hosting platform go to `needs_validation`.
    - Paraphrased from Cloudflare's [SUPPLY-CHAIN-AND-RELEASE.md](https://github.com/cloudflare/security-audit-skill/blob/main/skills/security-audit/SUPPLY-CHAIN-AND-RELEASE.md) (MIT).
  - **Agent extensions and source redirection** (#72):
    - The inventory now includes `.mcp.json` / `.cursor/mcp.json` server commands, installed skills and plugin marketplaces.
    - A per-ecosystem table of package-source redirection (npm, Yarn, pip/uv, Poetry, Maven/Gradle, Cargo, including env-var and CLI forms) in `references/source-redirection.md`.
    - Greps for unpinned `npx -y` / `uvx` / `docker run`, and a check for `.pyc` files with no matching source.
    - New risk row: "Agent extension (unpinned / unreviewed)".
  - **findings.json** is written and validated before the prose (#64). Diff / lockfile-scoped review mode (#67).
  - Cross-references to `patch-sweep`, `scanner-pipeline`, `agent-supply-chain-audit` and cloud-audit "PaaS".
- README: dependency-audit row updated.

### 1.13.0 (2026-10-26)

api-audit gets a much deeper GraphQL playbook, a paired-evidence rule, and the same verify-then-report workflow owasp-audit adopted in 1.12.0.

**Changed**

- **api-audit** (1.1.0)
  - **GraphQL playbook** in `references/graphql.md`, paraphrased from [Strix](https://github.com/usestrix/strix) (Apache-2.0) (#75):
    - schema inference when introspection is off (field suggestions, "Expected one of" enum leaks, existence oracles)
    - an aliased owned-vs-foreign IDOR comparison in a single request
    - child resolvers that assume the parent checked auth
    - Relay `node(id:)` global-ID swaps
    - federation `_entities` / `_service{sdl}`
    - `@defer` / `@stream` leaks
    - subscriptions authorized only at the handshake
    - persisted-query replay
    - `@oneOf` coercion
    - cursor tampering
    - alias/batch rate-limit bypass
    - fragment-split WAF evasion
  - **Paired evidence.** A validated finding shows the attack request next to its baseline. BOLA / BOPLA / BFLA must show owner vs non-owner requests that are byte-identical except for the token. (#76)
  - **Recon first + coverage ledger.** An API entry surface is a REST route, GraphQL operation or resolver, gRPC method, webhook or websocket channel. There's a coverage critic before the report, and partial reports say so. (#68)
  - **Verify every finding** using the three verdicts. "Potential" is retired for `needs_validation` with blockers and a plan, and there's a "Rejected (do not re-raise)" section. (#62)
  - **Severity calibration and hardening notes.** CORS and header issues are findings only with a traced impact. (#63)
  - **findings.json** is written and validated before the prose. (#64)
  - **Diff / PR-scoped mode** for API changes. (#67)
  - Cross-reference to `business-logic-testing` for invariant and race testing of API flows. Existing API1–API10 checklist kept as is.
- README: api-audit row updated.

### 1.12.0 (2026-10-26)

owasp-audit adopts the full audit workflow: recon first, per-finding verification, coverage tracking, machine-readable findings, run profiles and diff mode. Most of these ideas come from a deep dive into [cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill) (MIT) and [Strix](https://github.com/usestrix/strix) (Apache-2.0). Everything is paraphrased and cited.

**Changed**

- **owasp-audit** (1.2.0). New workflow: Scope → Recon → run profile / mode → category checklist → Verify every finding → coverage critic → `findings.json` → report.
  - **Recon first.** Write a short `architecture.md` covering principals, entry surfaces, trust boundaries with the `file:line` of each control, and sinks. Then build a `coverage.json` ledger per surface × boundary × attack class. "Clean" now requires reviewed paths and a check that was actually run, so "A01 clean" can no longer hide routes nobody read. (#68)
  - **Verify every finding.** A separate refutation pass re-reads each cited `file:line`, names the strongest control on the path, and returns one verdict:
    - `confirmed`: carries severity.
    - `needs_validation`: lists blockers plus a check the owner can run. Replaces the old "Potential" label.
    - `rejected`: names the control and its location. These are kept so re-runs don't raise them again.

    A "does NOT rule out" list blocks lazy rejections, and moving a verdict up needs a fresh verifier. (#62)
  - **Severity calibration.** Headers, CORS and cookie flags count as findings only when there's a traced impact. A new "Hardening notes (not findings)" section, and an anti-patterns list (checklist deviations presented as vulns; self-impact presented as crossing a boundary). The A05 `curl -I` checks become needs-validation items. (#63)
  - **findings.json first.** Write and validate `findings.json` (plus `coverage.json`), then render the markdown from it. Prose never changes a verdict or severity. SARIF export for code scanning. (#64)
  - **Run profiles and orchestration.** Quick / standard / deep profiles change breadth, never the evidence bar, and the report header names the profile. For large codebases, a coordinator splits the work across subagent hunters (including a Wildcard and an "Obvious things" hunter), with a sequential fallback for agents that can't run subagents. Re-runs carry findings forward by fingerprint and never re-raise a rejected claim. (#77)
  - **Diff / PR-scoped mode.** In scope: what the change introduces, old weaknesses it newly reaches, helpers it weakens (checked across sibling call sites), controls it removes, and assumptions it breaks. Unrelated old bugs are noted, not filed. The PR description is treated as untrusted. Reports are labeled "diff-scoped (partial)", and there's an optional CI recipe. (#67)
  - **Inbound webhook patterns**, from a real Codex second-model review (`references/webhooks-and-parsers.md`) (#82):
    - Multipart field-index amplification: a 78-byte request expanded to about 5 MB of JSON. Comes with a parser-limits table per framework.
    - Unauthenticated inbound webhooks that trigger paid work. Comes with a provider signature table and the raw-body requirement.
    - Parser errors thrown outside the error boundary, hiding attack traffic from monitoring.
  - When both the source and a running instance are available, the skill points to web-pentest's "Combined white-box + black-box mode". A04 race patterns cross-reference `business-logic-testing` for proving them live. (#76, #74)
  - All existing checklist content is kept. The long tables and payload sets moved to `references/checklist-details.md`. The Second-Opinion Pass is kept as the post-fix review.
- README: owasp-audit row updated.

### 1.11.0 (2026-10-26)

finding-triage gets severity calibration and structured input. This is the first skill to adopt the shared findings foundation from 1.4.0.

**Changed**

- **finding-triage** (1.1.0)
  - **Step 2: the boundary + result gate.** A finding must name six things: the lower-trust principal, the input it controls, the intended control, the boundary crossed, the affected principal or resource, and a concrete observed result. Missing any one makes it a hardening note or a needs-validation item. (#63)
  - **Step 3: severity calibration.**
    - Severity anchors: high fully defeats an explicit control with real consequences; medium only weakens one.
    - `overall ≤ demonstrated impact`.
    - An over-rating list: self-XSS, missing headers, a lone open redirect, "could matter if chained", anything that already needs admin.
    - A High/Critical acceptance checklist.
    - The SLA column is kept separate from severity.
    - Full detail in `references/severity-calibration.md`. (#63)
  - **Defense-in-depth is no longer Low.** A gap where another layer already stops the attack is now a **Hardening note**, outside the findings list. (#63)
  - **Verdict vocabulary:** accepts `confirmed` / `needs_validation` / `rejected` from any audit skill. Severity applies only to `confirmed`. (#62)
  - **Structured input:** accepts a `findings.json` record by fingerprint, using the shared schema and validator now shipped in `references/`. (#64)
  - **New dispositions:** `Mitigated (platform/config)` and `Requires major migration`, alongside Fixed / Deferred / Accepted Risk / False Positive. These came from the October 2026 field sweep (#81).
- README: finding-triage row updated.

### 1.10.0 (2026-10-26)

New skill: **personal-opsec**. Every other skill in the catalog is aimed at an org or a codebase. This one covers the individual: the founder or operator who holds the keys, and who is usually the easiest way in.

**Added**

- **personal-opsec** (1.0.0). An agent-run audit of one person's setup, not a static checklist.
  - **Karpathy's 15 controls** (via Andrej Karpathy's digital security checklist). The agent checks current state on the local machine where it can, using read-only commands: disk encryption, firewall, DNS resolver, password manager CLI, registrar lock via `whois`. It asks the user about the rest.
  - **Operator-critical additions:** account recovery paths, SIM-swap protection and carrier port-out PIN, recovery codes stored offline, registrar and DNS account lock, hardware-key MFA on GitHub and cloud consoles.
  - **The AI-agent-era layer:**
    - tokens and API keys your coding agents can read (→ `secrets-audit`)
    - MCP server trust and what a connected agent could exfiltrate (→ `agent-supply-chain-audit`)
    - prompt injection of personal and inbox assistants (→ `prompt-injection`)
    - clipboard exposure
    - scoped, short-lived tokens over long-lived ones
  - **Output:** a prioritized gap report in the catalog's finding vocabulary, handed to `finding-triage`. Privacy-preference items that don't lead to account takeover are reported as hardening notes, not findings.
  - This is explicitly not security-awareness or phishing training. It refuses to audit someone else's personal security without their consent. (#61)

**Changed**

- `iam-audit` (1.0.1), `breach-patterns` (1.0.1), `agent-supply-chain-audit` (1.0.1): cross-references to personal-opsec.
- README: added to Design & Governance, the skill table, crossovers, and Where to start.

### 1.9.0 (2026-10-26)

New skill: **log-watch**. It sets up scheduled, agent-driven log review and paging for small teams that have no SIEM and no security staff, but do have logs.

**Added**

- **log-watch** (1.0.0).
  - **Inventory the logs you already have** and map each source to the detections it can support: Vercel, Heroku, Render, Sentry, Supabase / Neon / Postgres auth tables, Stripe, Cloudflare, CloudTrail, the GitHub audit log.
  - **Ten starter detections**, each with a signal, threshold and severity, plus example queries: credential stuffing, new admin/owner grants, API key creation, 401/403/404 spikes on admin/`.env`/`.git` paths, bad webhook signatures, unusual export volume, impossible travel, Stripe refund/dispute spikes, CloudTrail root logins and IAM changes, and egress to collector domains.
  - **Two-stage pipeline.** A deterministic filter or cheap classifier first, then a strong model reviews only flagged events alongside the previous run's state. A cost table converts events/min → tokens/day → $/month.
  - **Schedule and state:** cron agent, GitHub Actions schedule or Vercel cron. A checkpoint, a dedupe key per alert, and a suppression list with expiry, so the same issue doesn't page every 5 minutes.
  - **Paging** to Slack, Pushover, PagerDuty or email, with a "why this fired" summary and raw event links.
  - **Logs are untrusted input.** User agents, paths, emails and error text are attacker-controlled, so the reviewing agent gets read-only credentials, log content is fenced as data, and log text never picks an action. Rule-based hits always page; the model can raise their severity but never silence them.
  - **Detection only:** no auto-blocking. Hands off to `incident-triage`, and to `siem-detection` / `soc-operations` when the team outgrows it.
  - Optional scaffold: a GitHub Actions workflow plus a runner in `references/scaffold.md`. (#79)

**Changed**

- `siem-detection` (1.0.1), `soc-operations` (1.0.1), `incident-triage` (1.0.2): cross-references to log-watch.
- README: added to Detect & Respond, the skill table, crossovers, and Where to start.

### 1.8.0 (2026-10-26)

New skill: **scanner-pipeline**. The idea: stop asking an agent to hack your own app. Have it set up real scanners for each layer, then pass their findings to agents to fix.

**Added**

- **scanner-pipeline** (1.0.0).
  - **Pick tools by stack and layer:**
    - secrets: gitleaks, trufflehog
    - code: semgrep, codeql
    - dependencies: osv-scanner (one multi-ecosystem pass is preferred over per-package-manager audits), pip-audit, bundle-audit, govulncheck
    - infrastructure: trivy, checkov
    - Supabase advisors for apps backed by Supabase
    - live app: ZAP baseline, then nuclei, and only on domains the user owns and names
  - **Secrets in full git history.** A verified live secret is P0: rotate it before cleaning history, and never print the value.
  - **Normalize findings** to SARIF or the shared `findings.json`, dedupe across tools, and keep a suppression file where every entry needs a reason and an expiry.
  - **Fleet mode** across `gh repo list`, skipping forks and archived repos, with a roll-up board.
  - **CI template** in `references/security-scan.yml`, with actions pinned to commit SHAs and images pinned to digests: gitleaks, osv-scanner and semgrep on PRs, a weekly full scan, and SARIF upload.
  - **A semgrep rule** in `references/semgrep/supabase-rls.yml` for always-true RLS policies (`x = x`, `using (true)`). It's based on a real bug that exposed 472k email bodies.
  - **Hand-off:** findings go to `finding-triage`, each fix agent gets one finding, the same tool is re-run to confirm the fix, and the agent never edits scanner config to make a finding disappear.
  - Live scanners (nuclei, ZAP) are deliberately not pre-approved and always prompt. (#84)

**Fixed**

- `build-adapters.mjs`: files in nested `references/` folders are now listed in the Cursor/Codex adapters. The appended section is renamed "Reference files" so it no longer clashes with a skill's own "References" heading.

**Changed**

- README: added to AppSec & Supply Chain, the skill table, crossovers, and Where to start.

### 1.7.0 (2026-10-26)

New skill: **patch-sweep**. It came out of a real October 2026 sweep: about 45 apps (Heroku Rails, Render, and around 39 Vercel Next.js projects) responding to a wave of Ruby, Node, PHP, Rails/libvips and Next.js advisories. Most of the real work happened outside any single `npm audit`.

**Added**

- **patch-sweep** (1.0.0). Fleet-wide CVE response.
  - **Inventory:** map each repo to its platform project and the domains it actually serves. Flag legacy projects still serving `*.vercel.app`, projects with no custom domain, and duplicate projects built from the same repo.
  - **Production branch:** find the branch each project really deploys from. Don't assume it's the default.
  - **Stale deploys:** detect stale manual deploys and broken git deploys, which need an owner decision rather than a merge.
  - **Affectedness:** check the runtime, the dependency, and whether the vulnerable code path is used. Read every pin file, call out EOL lines that won't get a fix, and note managed runtimes that patch themselves.
  - **Mitigate before patching**, e.g. `VIPS_BLOCK_UNTRUSTED`.
  - **Patch procedure per app:** hotfix branch from production, in-range fixes only, lint/typecheck/build, preview check, merge, confirm production returns 200, sync back.
  - **Delegation:** about 6 repos per agent, watch for build queues, and repos owned by clients or other maintainers get PRs, never merges.
  - **Prevention:** turn on Dependabot alerts across the fleet.
  - **Output:** a status board with one row per app, plus "not shipped, and why" and "needs a major-version upgrade". Pre-approved commands are read-only inventory only. (#80)

**Changed**

- README: added to AppSec & Supply Chain, the skill table, crossovers, and Where to start.

### 1.6.0 (2026-10-26)

New skill: **business-logic-testing**. Business logic and race conditions are the bugs scanners can't find, and until now the catalog covered them only thinly (web-pentest Phase 8 was eight one-line bullets).

**Added**

- **business-logic-testing** (1.0.0).
  - **Invariants first:** conservation of value, uniqueness, monotonicity, exclusivity. Then an Actor × Action × Resource matrix.
  - **State-machine abuse:** skip, reorder or replay steps, and limit-slicing.
  - **Numeric issues:** float vs decimal, rounding, cross-currency refund arbitrage, negative amounts. Also stale feature gates and roles, and gaps in event-driven sagas.
  - **Concurrency methodology** in `references/concurrency.md`: HTTP/2 single-packet and last-byte sync, connection warming, idempotency keys scoped to a path instead of a principal, cache-before-commit, lost updates, Redis locks without NX/EX or fencing tokens, READ COMMITTED anomalies, upsert races.
  - **Validation and false positives per class.** Example of a validated race: one request is denied, N concurrent ones succeed, and durable state proves it. Truly idempotent operations and visual-only glitches don't count.
  - **Authorization:** concurrency testing against production money flows needs explicit written scope. Staging or test mode is preferred, request counts are capped, and third parties are never targeted. Pre-approved tools are read-only, so live requests always prompt.
  - Uses the shared verdicts and `findings.json`. Methodology paraphrased from [Strix](https://github.com/usestrix/strix) (Apache-2.0). Strix's never-refuse posture is explicitly not adopted. (#74)

**Changed**

- README: added to Offensive & Recon, the skill table and crossovers. The links from owasp-audit, api-audit and web-pentest come with those skills' own versions.

### 1.5.0 (2026-10-26)

New skill: **agent-supply-chain-audit**. Coding-agent extensions are now a supply-chain surface that runs with your privileges and almost no review. NVIDIA's SkillSpector cites research finding vulnerabilities in about a quarter of 31k published skills, with about 5% likely malicious.

**Added**

- **agent-supply-chain-audit** (1.0.0). Audits the skills, plugins, marketplaces, hooks, settings, MCP servers, and instruction files (`CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.cursor/rules`, `copilot-instructions.md`) that Claude Code, Cursor, Codex, Gemini CLI and Copilot load, at both project and user level.
  - Inventory with source and pin for every extension.
  - Content checks, each with a grep and the matching SkillSpector rule ID: hidden instructions, invisible Unicode, agent snooping, exfiltration wording, anti-refusal language, `curl | bash`, shipped `.pyc` files, persistence writes.
  - Hooks and settings review: `defaultMode`, `permissions.allow`, `apiKeyHelper`, hooks that call out to the network.
  - MCP pinning and tool-definition diffing to catch rug pulls.
  - Optional SkillSpector pass. Only `--no-llm` is pre-approved, because LLM mode sends file contents to a provider.
  - Read-only. Output is an inventory table plus findings in the shared `findings.json` format, with a SAFE / CAUTION / DO NOT INSTALL verdict per item. (#66)

**Changed**

- `ai-risk-management` (1.0.1): new "AI coding agents and extensions" row in the AI inventory, pointing to agent-supply-chain-audit.
- `incident-triage` (1.0.1), `threat-hunting` (1.0.1): cross-references to agent-supply-chain-audit.
- README: added to the AI Security family, the skill table, crossovers, and Where to start.

### 1.4.0 (2026-10-26)

Findings foundation. No skill content changes in this version. It adds the shared machinery that the audit skills adopt one at a time in the versions that follow.

**Added**

- `shared/findings.schema.json` + `shared/validate-findings.mjs`: a machine-readable `findings.json` with stable root-cause `fingerprint`s and three verdicts (`confirmed` / `needs_validation` / `rejected`). The validator has no dependencies and exits non-zero on bad input. It enforces sort order, no duplicates, safe repo-relative paths, a trace that runs entrypoint → sink, `overall ≤ impact`, severity only on `confirmed`, blockers + plan on `needs_validation`, a named control on `rejected`, and `high` confidence only when reproduced. Schema structure adapted from [cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill) (MIT). (#64)
- `shared/to-sarif.mjs`: findings.json → SARIF 2.1.0 for GitHub code scanning. Fingerprint → `partialFingerprints`, trace → `codeFlows`, severity → `security-severity`. (#64)
- `shared/coverage.schema.json` + `shared/validate-coverage.mjs`: a coverage ledger per surface × trust boundary × attack class. `covered` requires reviewed paths and a check. (#68)
- `shared/severity-calibration.md`: the boundary + result gate, severity anchors, the `overall ≤ demonstrated impact` rule, the over-rating list, the High/Critical checklist, and hardening notes ≠ findings. (#63)
- `shared/verification.md`, `recon-and-coverage.md`, `orchestration.md`, `diff-review.md`: the per-finding refutation pass, recon-first + coverage critic, coordinator/hunter orchestration with quick / standard / deep run profiles and re-run carry-forward, and diff / PR-scoped review. (#62, #67, #68, #77)
- `shared/manifest.json`: declares which skills receive a copy of each shared file. `scripts/build-adapters.mjs` now copies shared files into `skills/<skill>/references/`, because `npx skills` installs one folder at a time. Cursor/Codex adapters gain a References section linking those files. It's empty in this version; each skill adds itself when it starts using a file.
- `npm test`: a zero-dependency `node:test` suite (53 tests) for the validators, SARIF export and the build. Needs Node ≥ 21.

**Decided (#78):** live probing stays allowed when it's authorized and non-destructive, e.g. checking whether a leaked key is live or running `curl -I` against your own origin. A check that wasn't actually run is recorded as `needs_validation`, never as confirmed or clean.

### 1.3.0 (2026-05-26)

Compliance and governance release. **Six new skills**, taking the catalog from 23 → 29 skills across seven families (added: Compliance & Privacy). Catalog audited end to end before tag: all 29 skills pass mechanical checks; content audit found no fatigue, no pattern reuse, all cross-references resolve.

**New skills:**

- **security-comms** — Translate security work for non-security audiences. Seven audience archetypes (board / executive / engineering leadership / individual engineers / customer success / customers / procurement-legal-compliance), two-mode workflow (draft from technical input / review a draft), six templates (board update, executive memo, customer disclosure draft, post-mortem narrative, audit-findings-for-engineering, sales-engineering FAQ). Closes the gap every other skill produces — namely, the technical output that has to land with a non-security audience.
- **privacy-engineering** — GDPR / CCPA / CPRA / LGPD / PIPEDA technical implementation. Eight engineering practices (data classification, minimization, lawful basis, consent management, DSAR pipeline with full deletion fan-out across DBs / caches / search / analytics / vendors, vendor / sub-processor management, breach-notification engineering hooks, DPIA inputs). Concrete grep patterns for PII leakage in code and analytics SDK initializations.
- **ai-risk-management** — NIST AI Risk Management Framework (RMF) 1.0 + EU AI Act. Broader than prompt-injection (which is the security slice). Four-function workflow (Govern / Map / Measure / Manage with inventory as prereq), evaluation categories with concrete tooling per category (Fairlearn, AIF360, What-If Tool, Aequitas, SHAP, LIME, HELM, MMLU), regulatory layer covering EU AI Act risk tiers, US federal patchwork, state laws.
- **red-team-engagement** — Authorized adversary emulation methodology. Distinct from web-pentest (technique-focused). Multi-week, objective-based, often assumed-breach. Carries the heaviest authorization gating in the catalog: seven required checks before any planning, explicit refusal language, RoE document with twelve specific sections, and a Boundaries section with eight separate refusal categories.
- **pci-audit** — PCI DSS v4.0 audit. Leads with scope determination (the single most-leveraged variable). Engineering-relevant requirements (Req 3 storage of CHD with PAN regex patterns by brand; Req 4 transmission; Req 6 cross-ref to owasp-audit / api-audit / vuln-research / dependency-audit; Req 7-8 cross-ref iam-audit; Req 10 cross-ref siem-detection; Req 11 cross-ref dependency-audit / web-pentest / red-team-engagement; Req 12 cross-ref incident-triage).
- **hipaa-audit** — HIPAA Security / Privacy / Breach Notification / HITECH. Three safeguard categories (Administrative / Physical / Technical) with §164.308 / §164.310 / §164.312 citations. 18 identifiers, BA chain-of-liability, minimum-necessary at the query / API level, 60-day breach notification timing by recipient, encryption-as-safe-harbor framing.

**Existing skills updated (back-references added):**

- `incident-triage` — added cross-refs to security-comms (stakeholder / customer notifications), privacy-engineering / hipaa-audit / pci-audit (regulatory clock determination), ai-risk-management (AI-specific incident classes)
- `finding-triage` — added cross-ref to security-comms (translating dispositions for non-security audiences)
- `breach-patterns` — added cross-refs to hipaa-audit / pci-audit / privacy-engineering for regulatory implications
- `prompt-injection` — added cross-ref to ai-risk-management for the broader governance frame

**README:**

- Skill-map diagram expanded from six → seven families with the new Compliance & Privacy family
- Skills table includes all 29 entries
- "Where to start" section expanded with new contexts: working under a specific regulation, translating security work upward / outward

**Repo state:**

- 50+ PRs since v1.0.0; 7 PRs in this release cycle (#54–#60)
- main + development synced
- Plugin metadata (`marketplace.json`, `plugin.json`) at 1.3.0
- npx skills and Claude plugin marketplace install paths verified

**Audit pre-release confirmation:**

A comprehensive content + mechanical audit ran before the v1.3.0 tag. Mechanical checks (build, naming, JSON validity, npx enumeration, adapter sync, description length, line count) all clean. Content audit specifically checked for fatigue / pattern-reuse risk after six skills in one stretch — none found. pci-audit and hipaa-audit are demonstrably distinct skills, not the same template with different acronyms. security-comms is the strongest new addition. red-team-engagement carries the heaviest and most appropriate authorization framing in the entire catalog.

### 1.2.2 (2026-05-26)

Audit-driven polish patch. Full mechanical + content audit of all 23 skills landed with one substantive fix and six minor cross-reference / description improvements.

**Mechanical audit results (all clean):**
- Build script succeeds for all 23 skills
- Every skill's `name` field matches its directory name
- Every description in the 200-1024 character target range
- Every adapter file (Cursor `.mdc`, Codex `.md`) generated and in sync
- `.claude-plugin/{marketplace,plugin}.json` JSON valid
- `npx skills add briiirussell/cybersecurity-skills --list` enumerates all 23
- All skills under 500 lines (largest: `owasp-audit` at 365)

**Content fixes:**

- **`siem-detection`** — stripped four stale "future" / "coming in this release" qualifiers that referenced `soc-operations`, `threat-hunting`, and `breach-patterns` as forthcoming. All three skills now exist (since v1.2.0), so the cross-references are now correct and live.
- **`incident-triage`** — added an explicit cross-references block. The skill predates the detect/respond family; every adjacent skill referenced back into it, but it referenced none of them. Now points at `siem-detection` (the rule that fired), `disk-forensics` (deeper analysis), `breach-patterns` (post-incident pattern extraction), `soc-operations` (the ops layer above).
- **`prompt-injection`** — added cross-references to `threat-modeling` (design-time AI risk), `owasp-audit` (output-rendering XSS overlap), and `api-audit` (LLM tool / MCP server API surface). The skill was an island; it now sits in the family.
- **`cloud-audit`** — added explicit cross-references pointing IAM deep-dive at `iam-audit`, K8s posture at `container-audit`, secrets hygiene at `secrets-audit`. Also added a disposition-rule pointer to `owasp-audit`'s three-disposition Report Format.
- **`recon`** and **`osint-recon`** — added bidirectional cross-references. recon now references osint-recon and web-pentest; osint-recon now references recon, breach-patterns, and incident-triage. The passive→active and OSINT→active pairings are now explicit.
- **`disk-forensics`** — added an explicit `## Authorization Check` section (previously folded into Boundaries only) covering lawful basis, chain of custody, and privacy scope. Expanded description with more trigger phrases ("timeline analysis," "memory forensics," "volatility," "plaso," "log2timeline," "artifact analysis," "chain of custody").
- **`owasp-audit`** — broadened description from 311 to 757 characters with the full OWASP Top 10 category list and additional trigger phrases ("appsec review," "secure code review," "IDOR," "SQL injection," "XSS," "SSRF," etc.). The anchor skill of the catalog deserves the pushy invocation.

**No skill content was added or removed.** All changes are descriptive / cross-reference improvements that make the catalog feel like one connected family instead of 23 independent files.

Plugin metadata (`marketplace.json`, `plugin.json`) bumped to 1.2.2.

### 1.2.1 (2026-05-26)

Documentation patch — no skill content changes.

- README opening rewritten to make audience inclusive. Previous framing positioned the skills as "for security engineers and red/blue teamers"; v1.2.1 explicitly welcomes developers shipping safer code without a dedicated security team, and founders / ops folks / small-team operators securing stacks they can't afford a CISO for.
- New **Where to start** section maps user context to recommended starting skills — reviewing your own code, securing cloud infrastructure, responding to incidents, building a security program from scratch, closing the loop on a single finding.
- Honest note about offensive skills (`recon`, `osint-recon`, `web-pentest`) requiring more security context and explicit authorization — these stay opt-in for users with the right footing.
- Contributing language broadened — field feedback is welcome from every level of expertise, not just practitioners.

This patch reflects the project's actual reach: while security professionals are still the majority of users, the skills are designed to be usable end-to-end by anyone whose AI agent needs to do security work. The technical depth is in the skills; the explanations are in the agent's output.

Plugin metadata (`marketplace.json`, `plugin.json`) bumped to 1.2.1 to keep release and bundle aligned.

### 1.2.0 (2026-05-26)

Major expansion. **Fifteen new skills** added, growing the repo from 8 → 23 skills across six families. Repo is now installable via `npx skills` and the Claude Code plugin marketplace.

**New skills:**

- **api-audit** — OWASP API Security Top 10 (2023). BOLA, mass assignment, BFLA, sister-route gaps, GraphQL introspection, webhook signature verification.
- **breach-patterns** — Preemptive hardening from public breach disclosures. Ten patterns catalogued (Capital One, SolarWinds, LastPass, Okta Lapsus$, Snowflake, MOVEit, Codecov, Twitter insider, Equifax, Uber).
- **container-audit** — Docker + Kubernetes security. Dockerfile, pod security, RBAC, NetworkPolicy, secrets, image policy, runtime detection.
- **crypto-audit** — Cryptography implementation review. Deeper than owasp-audit A02 — algorithm/mode choice, KDF parameters, IV/nonce handling, signature verification ordering, randomness, TLS posture, key lifecycle.
- **csf-mapping** — NIST CSF 2.0 governance frame. Subcategory mapping, current/target tiers, prioritized roadmap. Translates technical findings into board language.
- **finding-triage** — Single-finding disposition workflow. Closes the loop on every audit skill. Four templates (Fix / Defer / Accept Risk / False Positive) with required-field enforcement.
- **iam-audit** — Consultant-style IAM. Three modes (audit / design / migrate) covering cloud IAM (AWS/GCP/Azure), identity providers (Okta/Entra/Auth0/Workspace), and application authorization (RBAC/ABAC/ReBAC).
- **mobile-audit** — iOS + Android against OWASP MASVS / MASTG. Storage, crypto, network (cert pinning), auth (biometrics, OAuth), platform (deeplinks, IPC), code, resilience.
- **secrets-audit** — Find leaked secrets (code, Git history, build artifacts, CI, frontend bundles) + audit secrets-management posture (rotation, scope, workload identity federation).
- **siem-detection** — Detection engineering. Log source → ATT&CK coverage mapping, Sigma rule authoring, FP tuning lifecycle, detection-as-code Git+CI workflow.
- **soc-operations** — Build / run / improve a SOC. Staffing math, runbook structure, escalation criteria, KPIs (MTTD / MTTR / FP rate), alert-fatigue tuning loop.
- **threat-hunting** — Proactive, hypothesis-driven hunts. PEAK framework, ATT&CK-driven hunt catalog, every hunt produces a rule / dead-end doc / coverage gap.
- **threat-modeling** — Pre-implementation security design. STRIDE-per-element + abuse cases, Shostack four-question frame, data flow diagrams with trust boundaries.
- **vuln-research** — CVE deep-dive. Pull canonical sources (NVD / vendor / GHSA / CISA KEV / EPSS), reachability analysis, exploitation availability check, patch / mitigate / accept-risk decision.
- **web-pentest** — Live web application testing. OWASP WSTG-structured, nine phases from config through business logic. Heavy authorization-check + boundaries because most dual-use skill in the family.

**Distribution:**

- `npx skills add briiirussell/cybersecurity-skills` — works out of the box (vercel-labs/skills)
- `/plugin marketplace add briiirussell/cybersecurity-skills` — Claude Code plugin marketplace via new `.claude-plugin/` scaffold (marketplace.json + plugin.json)

**README and docs:**

- Updated skill-map diagram showing the six families and cross-references
- Six install methods documented in priority order (npx, plugin marketplace, manual, Cursor, Codex, submodule)

**Repo health:** main + development synced, all 50 PRs in this release cycle merged, no open issues or PRs.

### 1.1.0 (2026-05-26)

Field-feedback release. Thirteen PRs (#21–#33) closing every open issue from real-world audits — owasp-audit grew from 163 → 365 lines, dependency-audit from 235 → 281 lines, both still well under the 500-line guideline.

**owasp-audit additions:**

- **A01:** auth-check ordering (404/400/401 ordering as state-enumeration leak), IDOR via foreign keys in mutation payloads, framework RPC surface enumeration (server actions, tRPC, GraphQL, Remix), open-redirect control-byte rejection (extends PR #20)
- **A02:** full provider key prefix list (Stripe, GitHub, AWS, GCP, Slack, OpenAI/Anthropic, Vercel), bcrypt cost ≥ 12, VERIFY_PEER managed-service caveat with three-option remediation ladder, config-file extensions (.yml / .yaml / .toml / .json) in grep sweep, type coercion in cryptographic-verification paths (parseInt → NaN defeating freshness checks)
- **A03:** full JSON-LD JSON.stringify breakout pattern (replaces "typically safe" parenthetical), Rails ERB sinks + Rails JSON-LD idiom, SVG upload as stored XSS, regex-sanitizer anti-pattern with [/\s] / cross-namespace / CSP-backstop requirements, sanitize on write AND on render with backfill migration
- **A04:** configured-but-not-loaded check, multi-tenant webhook signature N-way matching DoS, rate-limit key fallback as lockout vector, fire-and-forget background jobs lose request-scoped auth, sister-route audit, external-resource-create TOCTOU with billing implications, worker-queue atomic claim
- **A05:** Rails admin-engine mounts gated on Rails.env.production? (PgHero / Sidekiq::Web / Flipper / Mission Control leak in staging), source-tree hygiene (macOS sync-conflict duplicates), Next.js next.config.ts headers() rule merging, auth middleware that doesn't exempt bearer/HMAC routes, bearer-token compare with unset env interpolation, API routes returning HTML 302 instead of JSON 401, framework header locations, baseline header values table, concurrent-execution races on paid endpoints
- **A06:** cross-reference to dependency-audit, npm prod/dev triage
- **A07:** Devise :validatable enforcement, NextAuth v5 / Auth.js footguns (AUTH_SECRET fallthrough, credentials rate-limit, account enumeration, JWT-strategy adapter no-op)
- **A08:** external-resource overwrite without state check, external side-effects before durable DB state (reserve-then-act)
- **A09:** silent-catch anti-pattern, unauthenticated email to user-supplied address (phishing vector against sender reputation)
- **A10:** image-optimizer-as-proxy (next/image, Nuxt, SvelteKit), expanded SSRF bypass matrix (decimal/hex/octal IPv4, IPv4-mapped IPv6, trailing-dot, cloud metadata, CGNAT, link-local IPv6)
- **New section:** Second-Opinion Pass — adversarial second-pass review of the report and the fix branch, plus verify-against-library-internals rule
- **Verify Fixes:** canonical XSS payload bank for sanitizer-config verification
- **Report Format:** three-disposition rule (Fixed / Deferred / Accepted Risk) with required fields, per-category Clean / N/A states, enriched Verification field requiring concrete adversarial input

**dependency-audit additions:**

- **Step 1:** package manifest edge cases (optionalDependencies, overrides used to silence, monorepos, engines)
- **Step 2:** `npm audit --omit=dev` for prod-vs-dev triage, `--force` downgrade footgun warning, "when audit fix cannot resolve" subsection
- **Step 3:** advisory-freshness methodology (cross-ref GitHub Advisories before consulting hardcoded patterns)
- **Next.js:** server-only import detection
- **Express / Node:** new Serverless / edge runtime subsection (in-memory Map rate-limit is per-instance, x-forwarded-for trust, unbounded collections)
- **Step 4 lockfile/CI:** concrete grep commands replacing prose checklist
- **Output:** "Where reachable" column added to the CVE table (runtime / build-only / dev-only)

All thirteen field-feedback issues from @coreyhaines31 closed in this release. Acknowledgements in the GitHub Release.

### 1.0.0 (2026-05-26)

First tagged release. Eight skills covering AppSec, offensive recon, detect-and-respond, cloud, and AI security:

- **owasp-audit** — Source-code audit against OWASP Top 10 (2021). Category-by-category checklist, grep patterns, remediation guidance, report template.
- **dependency-audit** — Dependency, framework, runtime, and toolchain audit. CVE lookups, supply chain risk, security anti-patterns.
- **prompt-injection** — Audit AI features / LLM integrations / agents for prompt injection, privilege escalation, and authorization bypass.
- **recon** — Structured attack surface enumeration for authorized pentests, bug bounty, and CTF.
- **osint-recon** — Open source intelligence gathering and correlation for authorized investigations.
- **incident-triage** — NIST SP 800-61 incident response triage.
- **disk-forensics** — Disk image analysis, evidence recovery, timeline reconstruction.
- **cloud-audit** — AWS / GCP / Azure misconfiguration and IAM audit.

Also includes:

- Build script (`scripts/build-adapters.mjs`) for Cursor `.mdc` and Codex `.md` outputs
- Skill template (`templates/skill-template.md`)
- `CLAUDE.md` with skill format spec and writing guidance
- `CONTRIBUTING.md` with full workflow
- README modeled on the AI-skills ecosystem standard

Repo workflow established:

- `main` — stable, tagged releases
- `development` — integration branch
- `feature/<name>` — per-change branches, merged into `development`, then `development` → `main` at release cut
