# Cybersecurity Skills Versions

Current versions of all skills. Agents can compare against local versions to check for updates.

| Skill | Version | Last Updated |
|-------|---------|--------------|
| agent-supply-chain-audit | 1.0.0 | 2026-10-26 |
| ai-risk-management | 1.0.1 | 2026-10-26 |
| api-audit | 1.0.0 | 2026-05-26 |
| breach-patterns | 1.0.0 | 2026-05-26 |
| business-logic-testing | 1.0.0 | 2026-10-26 |
| cloud-audit | 1.0.0 | 2026-05-26 |
| container-audit | 1.0.0 | 2026-05-26 |
| crypto-audit | 1.0.0 | 2026-05-26 |
| csf-mapping | 1.0.0 | 2026-05-26 |
| dependency-audit | 1.1.0 | 2026-05-26 |
| disk-forensics | 1.0.0 | 2026-05-26 |
| finding-triage | 1.0.0 | 2026-05-26 |
| hipaa-audit | 1.0.0 | 2026-05-26 |
| iam-audit | 1.0.0 | 2026-05-26 |
| incident-triage | 1.0.1 | 2026-10-26 |
| mobile-audit | 1.0.0 | 2026-05-26 |
| osint-recon | 1.0.0 | 2026-05-26 |
| owasp-audit | 1.1.0 | 2026-05-26 |
| pci-audit | 1.0.0 | 2026-05-26 |
| privacy-engineering | 1.0.0 | 2026-05-26 |
| prompt-injection | 1.0.0 | 2026-05-26 |
| recon | 1.0.0 | 2026-05-26 |
| red-team-engagement | 1.0.0 | 2026-05-26 |
| secrets-audit | 1.0.0 | 2026-05-26 |
| security-comms | 1.0.0 | 2026-05-26 |
| siem-detection | 1.0.0 | 2026-05-26 |
| soc-operations | 1.0.0 | 2026-05-26 |
| threat-hunting | 1.0.1 | 2026-10-26 |
| threat-modeling | 1.0.0 | 2026-05-26 |
| vuln-research | 1.0.0 | 2026-05-26 |
| web-pentest | 1.0.0 | 2026-05-26 |

## Recent Changes

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
