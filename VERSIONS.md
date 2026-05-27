# Cybersecurity Skills Versions

Current versions of all skills. Agents can compare against local versions to check for updates.

| Skill | Version | Last Updated |
|-------|---------|--------------|
| api-audit | 1.0.0 | 2026-05-26 |
| breach-patterns | 1.0.0 | 2026-05-26 |
| cloud-audit | 1.0.0 | 2026-05-26 |
| container-audit | 1.0.0 | 2026-05-26 |
| crypto-audit | 1.0.0 | 2026-05-26 |
| csf-mapping | 1.0.0 | 2026-05-26 |
| dependency-audit | 1.1.0 | 2026-05-26 |
| disk-forensics | 1.0.0 | 2026-05-26 |
| finding-triage | 1.0.0 | 2026-05-26 |
| iam-audit | 1.0.0 | 2026-05-26 |
| incident-triage | 1.0.0 | 2026-05-26 |
| mobile-audit | 1.0.0 | 2026-05-26 |
| osint-recon | 1.0.0 | 2026-05-26 |
| owasp-audit | 1.1.0 | 2026-05-26 |
| prompt-injection | 1.0.0 | 2026-05-26 |
| recon | 1.0.0 | 2026-05-26 |
| secrets-audit | 1.0.0 | 2026-05-26 |
| siem-detection | 1.0.0 | 2026-05-26 |
| soc-operations | 1.0.0 | 2026-05-26 |
| threat-hunting | 1.0.0 | 2026-05-26 |
| threat-modeling | 1.0.0 | 2026-05-26 |
| vuln-research | 1.0.0 | 2026-05-26 |
| web-pentest | 1.0.0 | 2026-05-26 |

## Recent Changes

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
