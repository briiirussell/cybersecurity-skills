# Cybersecurity Skills for AI Agents

[![CI](https://github.com/briiirussell/cybersecurity-skills/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/briiirussell/cybersecurity-skills/actions/workflows/ci.yml)

A collection of cybersecurity skills for AI coding agents. The AI does the heavy lifting; you bring the context about your stack and your priorities.

**Built to be useful at every experience level:**

- **Security engineers and pentesters** running formal audits — concrete grep patterns, OWASP / NIST / ATT&CK alignment, report templates that pass auditor review
- **Developers** shipping safer code without a dedicated security team to lean on — security work that fits into a normal sprint, plain-English explanations of why each finding matters
- **Founders, ops folks, and small-team operators** securing a stack they can't afford a CISO for — guided, opinionated playbooks for the most common security work, with the audit skill explaining what it found and why
- **Red / blue / purple teams** running real engagements — offensive recon, web pentest, threat hunting, detection engineering, SOC operations

You do not need to be a security expert to use these skills. The skills are written so the AI agent can run them end-to-end and explain the findings in language any technical reader can follow. If you can describe what you have and what you want to know about it, the agent can do the work.

Skills are authored as Claude Code [`SKILL.md` files](https://code.claude.com/docs/en/skills) (the canonical format) and built into adapters for Cursor and Codex. Installable via [`npx skills`](https://github.com/vercel-labs/skills) or the Claude Code plugin marketplace.

Built by [Bri Russell](https://github.com/briiirussell). I run real audits with these skills, then bring the gaps I find back into the skill itself — so each version is a little less opinion and a little more evidence.

**Contributions welcome!** Field feedback is the most valuable contribution — whether you're a security engineer who hit a gap during an audit, a developer whose AI agent missed something obvious, or a founder who used a skill and got an answer that wasn't quite right. [Open a PR](#contributing) or [open an issue](https://github.com/briiirussell/cybersecurity-skills/issues) — every level of expertise produces useful signal.

## Where to start

Not every skill is for every user on day one. A good starting point by context:

- **Reviewing your own code or product:** start with `owasp-audit` for the source-code sweep, then `api-audit` if you have API endpoints, then `dependency-audit` for the CVE pass
- **A CVE wave just dropped and you run many apps:** `patch-sweep` to work out which apps are affected and ship fixes across the fleet, with `dependency-audit` for each project
- **Want deterministic scanners in CI instead of asking an agent to "hack" your app:** `scanner-pipeline` picks the tools per layer, wires them into CI, and routes findings to `finding-triage`
- **Securing cloud / infrastructure:** start with `cloud-audit` (AWS / GCP / Azure misconfig), then `iam-audit` if you manage identities, then `container-audit` if you run Docker / Kubernetes
- **Responding to "something happened":** `incident-triage` for the immediate response, `disk-forensics` if you need to analyze a system afterward, `security-comms` to draft the stakeholder / customer communications
- **No SIEM, no security staff, but you have logs:** `log-watch` sets up a scheduled agent that reads the logs you already have (Vercel, Heroku, Sentry, Supabase, Stripe, CloudTrail, GitHub) and pages someone when it matters
- **You are the security team (founder / solo operator):** `personal-opsec` audits your own accounts, devices and AI-agent setup first — the person holding the keys is usually the softest target
- **Building a security program from scratch:** `csf-mapping` for the governance frame, `threat-modeling` before new features, `breach-patterns` to learn from public incidents
- **Working under a specific regulation:** `privacy-engineering` for GDPR / CCPA / similar privacy laws, `hipaa-audit` for ePHI, `pci-audit` for payment cards, `ai-risk-management` for AI features
- **Running AI coding agents with skills, plugins, or MCP servers:** `agent-supply-chain-audit` before you install or trust them — including this catalog
- **Closing the loop on findings:** `finding-triage` for any single finding from any source — gives you a defensible disposition with the right ticket fields
- **Translating security work upward or outward:** `security-comms` for board / exec / customer / engineering / sales-engineering deliverables

The offensive skills (`recon`, `osint-recon`, `web-pentest`, `red-team-engagement`) require explicit authorization for the target and assume more security context. They open with an authorization check and will refuse anything ambiguous. `red-team-engagement` in particular carries the strongest refusal posture in the catalog and will refuse to plan anything against systems the user cannot demonstrate authorization for.

## What are Skills?

Skills are markdown files that give AI agents specialized knowledge and workflows for specific tasks. Drop them into your project and your agent recognizes when you're working on a security task and applies the right methodology — OWASP categories, NIST IR steps, MITRE ATT&CK references, the actual grep patterns that surface the bug.

The goal isn't to replace a security engineer — or to pretend you have one if you don't. It's to give the agent enough structure that the first pass is useful, the report format is consistent, and the obvious stuff stops slipping through. For teams without dedicated security headcount, that closes a real gap. For teams with security engineers, it lets them spend their time on the work the AI can't do.

## How Skills Work Together

The skills are organized into seven families. Most security work crosses families — an OWASP audit surfaces a dependency question, an incident kicks off an OSINT trail, cloud findings overlap with appsec, and findings have to be translated for the audience that hears them. Skills cross-reference each other where that's true; `finding-triage`, `security-comms`, and `csf-mapping` orchestrate across the whole map.

```
                    ┌──────────────────────────────────────────┐
                    │          Cybersecurity Skill Map         │
                    └──────────────────────┬───────────────────┘
                                           │
  ┌──────────┬──────────┬──────────┬───────┴────┬─────────┬──────────┬───────────┐
  ▼          ▼          ▼          ▼            ▼         ▼          ▼           ▼
┌──────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌──────┐ ┌─────────┐ ┌──────────┐
│AppSec│ │Offens. │ │Detect &│ │Cloud & │ │ AI   │ │Design & │ │Complianc │
│& Sup │ │& Recon │ │Respond │ │ Infra  │ │Secur.│ │Governnce│ │& Privacy │
├──────┤ ├────────┤ ├────────┤ ├────────┤ ├──────┤ ├─────────┤ ├──────────┤
│owasp-│ │recon   │ │incid-  │ │cloud-  │ │promp-│ │threat-  │ │privacy-  │
│ audit│ │osint-  │ │ triage │ │ audit  │ │ inj. │ │ modeling│ │ engineer-│
│api-  │ │ recon  │ │disk-   │ │contain-│ │ai-   │ │vuln-    │ │ ing      │
│ audit│ │web-    │ │ forens.│ │ audit  │ │ risk-│ │ research│ │pci-audit │
│depen-│ │ pentest│ │siem-   │ │iam-aud-│ │ mgmt │ │finding- │ │hipaa-    │
│ audit│ │red-    │ │ detect.│ │ it     │ │agent-│ │ triage  │ │ audit    │
│secre-│ │ team-  │ │soc-    │ │        │ │supply│ │csf-     │ │          │
│ audit│ │ engage-│ │ ops    │ │        │ │-chain│ │ mapping │ │          │
│crypt-│ │ ment   │ │threat- │ │        │ │-audit│ │security-│ │          │
│ audit│ │business│ │ hunting│ │        │ │      │ │ comms   │ │          │
│mobile│ │-logic- │ │breach- │ │        │ │      │ │personal-│ │          │
│-audit│ │-testing│ │patterns│ │        │ │      │ │ opsec   │ │          │
│patch-│ │        │ │log-    │ │        │ │      │ │         │ │          │
│ sweep│ │        │ │ watch  │ │        │ │      │ │         │ │          │
│scan- │ │        │ │        │ │        │ │      │ │         │ │          │
│ner-  │ │        │ │        │ │        │ │      │ │         │ │          │
│pipe- │ │        │ │        │ │        │ │      │ │         │ │          │
│line  │ │        │ │        │ │        │ │      │ │         │ │          │
│cicd- │ │        │ │        │ │        │ │      │ │         │ │          │
│ sec. │ │        │ │        │ │        │ │      │ │         │ │          │
└──┬───┘ └───┬────┘ └───┬────┘ └───┬────┘ └──┬───┘ └────┬────┘ └────┬─────┘
   │         │          │          │         │           │            │
   └─────────┴────┬─────┴──────────┴─────────┴───────────┴────────────┘
                  │
   Common crossovers:
     owasp-audit ↔ api-audit ↔ dependency-audit ↔ vuln-research
     web-pentest ↔ recon ↔ osint-recon ↔ red-team-engagement
     siem-detection → threat-hunting → incident-triage → disk-forensics
     cloud-audit ↔ container-audit ↔ iam-audit ↔ secrets-audit
     threat-modeling → owasp-audit / api-audit (pre-implementation → code)
     prompt-injection ⇆ ai-risk-management (security slice ⇆ whole lifecycle)
     privacy-engineering ⇆ hipaa-audit / pci-audit (engineering ⇆ regulatory)
     agent-supply-chain-audit ⇆ dependency-audit / secrets-audit (agent extensions are supply chain too)
     owasp-audit (source-side race patterns) → business-logic-testing (prove it live) ← web-pentest
     dependency-audit (one project) → patch-sweep (the whole fleet)
     scanner-pipeline → finding-triage → fix agents (tools find it, agents fix it)
     log-watch → siem-detection / soc-operations (outgrow it) → incident-triage (it's real)
     personal-opsec → iam-audit / secrets-audit / agent-supply-chain-audit (the person → the org → the agents)
     dependency-audit → cicd-security ← agent-supply-chain-audit (the pipeline is supply chain too)
     dependency-audit → cicd-security ← agent-supply-chain-audit (the pipeline is supply chain too)
     breach-patterns → every audit skill (what to check)
     finding-triage ← every audit skill (closes the loop on any finding)
     security-comms ← every skill (translates output for non-security audience)
     csf-mapping ← every skill (rolls evidence into governance frame)
```

## Available Skills

<!-- SKILLS:START -->
| Skill | What it does |
|-------|--------------|
| [agent-supply-chain-audit](skills/agent-supply-chain-audit/) | Audit what your AI coding agents load and trust — skills, plugins, hooks, settings, MCP servers, `CLAUDE.md` / `AGENTS.md` / `.cursor/rules`. Hidden instructions, invisible Unicode, agent snooping, unpinned MCP servers (rug pulls), exfil hooks. Covers Claude Code, Cursor, Codex, Gemini CLI, Copilot. |
| [ai-risk-management](skills/ai-risk-management/) | NIST AI Risk Management Framework + EU AI Act — model lifecycle governance, fairness, robustness, transparency, monitoring, third-party model risk. Broader than prompt-injection. |
| [api-audit](skills/api-audit/) | OWASP API Security Top 10 (2023) — REST / GraphQL / RPC endpoint audit. BOLA, mass assignment, BFLA, rate-limit, webhook signature, plus a deep GraphQL playbook (schema inference with introspection off, aliased owned-vs-foreign IDOR, resolver cascade, Relay node swap, federation `_entities`, subscriptions, persisted queries). Paired owner-vs-non-owner evidence, verification pass, coverage ledger, findings.json. [Example run](examples/api-audit/report.md). |
| [breach-patterns](skills/breach-patterns/) | Preemptive hardening — read public breach disclosures, extract the audit question each one implies, check your stack. Capital One / LastPass / Okta / Snowflake / MOVEit / Codecov / Equifax / Uber. |
| [business-logic-testing](skills/business-logic-testing/) | The bugs scanners can't find — invariant-first testing (conservation of value, uniqueness, monotonicity, exclusivity), Actor × Action × Resource matrix, state-machine abuse, limit-slicing, and race conditions proven dynamically (HTTP/2 single-packet, idempotency-key scope, cache-before-commit). Explicit written scope required for money flows. |
| [cicd-security](skills/cicd-security/) | GitHub Actions, GitLab CI and CircleCI review — pwn requests (`pull_request_target` / `workflow_run`), expression injection, token permissions, SHA pinning, OIDC trust subjects, self-hosted runners, fork secrets, cache and artifact trust, and AI agents in CI that read issue or PR text while holding a write token. zizmor and actionlint run read-only. Writes findings.json (confirmed / needs validation / rejected), with SARIF export. |
| [cloud-audit](skills/cloud-audit/) | AWS / GCP / Azure infrastructure misconfiguration, excessive IAM, public exposure, compliance gaps — plus PaaS (Vercel / Netlify / Heroku / Render / Railway / Fly): stale manual production deploys, silently broken git deploys, legacy projects still serving old code, preview exposure, repo security defaults. Writes findings.json (confirmed / needs validation / rejected), with SARIF export. |
| [container-audit](skills/container-audit/) | Docker + Kubernetes audit. Dockerfile, base images, pod security, RBAC, NetworkPolicy, secrets, image policy, runtime. Writes findings.json (confirmed / needs validation / rejected), with SARIF export. |
| [crypto-audit](skills/crypto-audit/) | Cryptography implementation review — algorithm/mode choice, KDF parameters, IV/nonce handling, authenticated encryption, signature verification, randomness, TLS posture, key lifecycle. Deeper than owasp-audit A02. Writes findings.json (confirmed / needs validation / rejected), with SARIF export. |
| [csf-mapping](skills/csf-mapping/) | NIST CSF 2.0 posture assessment — Govern / Identify / Protect / Detect / Respond / Recover. Subcategory mapping, current/target tiers, prioritized roadmap. Translates technical findings into governance language. |
| [dependency-audit](skills/dependency-audit/) | Dependencies, frameworks, runtimes, toolchain — CVEs, security anti-patterns, supply chain risk. Fixing safely (pnpm override traps, duplicate singletons, engines floor, runtime pins that must move together), CI/release trust handoffs (cache/artifact poisoning, OIDC, digest promotion), package-source redirection, agent-extension pinning. [Example run](examples/dependency-audit/report.md). |
| [disk-forensics](skills/disk-forensics/) | Disk image analysis, evidence recovery, timeline reconstruction. Explicit Authorization Check covering lawful basis, chain of custody, privacy scope. |
| [finding-triage](skills/finding-triage/) | Single-finding disposition workflow — accepts any source (or a findings.json record by fingerprint) and the confirmed / needs-validation / rejected verdicts. Boundary + result gate, severity capped at demonstrated impact, hardening notes kept out of findings. Fixed / Deferred / Accepted Risk / Mitigated (platform/config) / Requires major migration / False Positive, with ticket-ready writeups. Closes the loop on every audit skill. [Example run](examples/finding-triage/report.md). |
| [hipaa-audit](skills/hipaa-audit/) | HIPAA Security / Privacy / Breach Notification — three safeguard categories, 18 identifiers, BAA chain-of-liability, minimum-necessary, 60-day breach clock, encryption-as-safe-harbor. Writes findings.json (confirmed / needs validation / rejected), with SARIF export. |
| [iam-audit](skills/iam-audit/) | Consultant-style IAM — audit / design / migrate. Cloud IAM (AWS/GCP/Azure), identity providers (Okta/Entra/Auth0/Workspace), application authorization (RBAC/ABAC/ReBAC), workload identity, JIT access, break-glass. Writes findings.json (confirmed / needs validation / rejected), with SARIF export. |
| [incident-triage](skills/incident-triage/) | Security incident triage following NIST SP 800-61. |
| [log-watch](skills/log-watch/) | Scheduled agent log review + paging for small teams without a SIEM — inventory the logs you already have, starter detections with thresholds (credential stuffing, new admin grants, key creation, .env/.git probing, bad webhook signatures, export spikes, CloudTrail root/IAM), a cheap-filter → strong-model pipeline with a monthly cost table, dedupe + suppression, paging. Detection only; logs treated as untrusted input. |
| [mobile-audit](skills/mobile-audit/) | iOS + Android audit against OWASP MASVS / MASTG — storage, crypto, network, auth, platform IPC, code, resilience. Writes findings.json (confirmed / needs validation / rejected), with SARIF export. |
| [osint-recon](skills/osint-recon/) | Open source intelligence gathering and correlation. |
| [owasp-audit](skills/owasp-audit/) | Source-code audit against OWASP Top 10:2025 — recon first (architecture + coverage ledger), category checklist with grep patterns, a per-finding refutation pass (confirmed / needs validation / rejected), coverage critic, findings.json → report. Quick / standard / deep run profiles, subagent orchestration, re-runs by fingerprint, diff / PR-scoped mode, inbound-webhook and parser-limit patterns. [Example run](examples/owasp-audit/report.md). |
| [patch-sweep](skills/patch-sweep/) | Fleet-wide CVE response across many apps and deploy platforms — map repos → platform projects → live domains, find each project's real production branch, catch stale manual deploys, decide affectedness (runtime + dependency + code path), mitigate before patching, ship and confirm prod. Output: one status board row per app. |
| [pci-audit](skills/pci-audit/) | PCI DSS v4.0.1 — scope determination first, then Req 3 (CHD storage) / 4 (transmission) / 6 (secure SDLC) / 7-8 (access) / 10 (logging) / 11 (testing) / 12 (program). Writes findings.json (confirmed / needs validation / rejected), with SARIF export. |
| [personal-opsec](skills/personal-opsec/) | Audit one person's own security setup — the founder or operator holding the keys. Walks Karpathy's 15-step checklist with read-only local checks where possible (disk encryption, firewall, DNS), adds operator-critical items (account recovery, SIM-swap / port-out PIN, registrar lock, hardware-key MFA), and the AI-agent-era layer (tokens your agents can read, MCP trust, inbox-agent prompt injection). Not awareness training. |
| [privacy-engineering](skills/privacy-engineering/) | GDPR / CCPA / CPRA / LGPD / PIPEDA technical implementation — data classification, minimization, consent, the DSAR pipeline (access / deletion / portability with full vendor fan-out), DPIA inputs. Writes findings.json (confirmed / needs validation / rejected), with SARIF export. |
| [prompt-injection](skills/prompt-injection/) | AI features / LLM integrations / agents — direct and indirect prompt injection, privilege escalation, authorization bypass, plus concealment checks (invisible Unicode, comment-hidden directives, whitespace padding, base64 data URIs) and MCP tool poisoning (parameter-description injection, description vs behaviour mismatch, rug-pull pinning, Unicode tool names). Writes findings.json (confirmed / needs validation / rejected), with SARIF export. |
| [recon](skills/recon/) | Structured attack surface enumeration for authorized pentests, bug bounty, CTF. |
| [red-team-engagement](skills/red-team-engagement/) | Authorized adversary emulation methodology — distinct from web-pentest. Multi-week, objective-based, assumed-breach. Heaviest authorization framing in the catalog. |
| [scanner-pipeline](skills/scanner-pipeline/) | Set up and run real scanners per layer (gitleaks / trufflehog, semgrep, osv-scanner, trivy / checkov, Supabase advisors, ZAP / nuclei on domains you own), normalize to SARIF or findings.json, dedupe, suppress with reason + expiry, schedule in CI, and hand one finding at a time to fix agents. Works across a fleet of repos. |
| [secrets-audit](skills/secrets-audit/) | Find leaked secrets (code, Git history, build artifacts, CI, frontend bundles, AI agent configs and session transcripts) + audit secrets-management posture (rotation, scope, workload identity). Confirms key type (publishable vs restricted vs secret) before rating; findings.json with values redacted; exfil collector-domain list for egress hunting. [Example run](examples/secrets-audit/report.md). |
| [security-comms](skills/security-comms/) | Translate security work for non-security audiences — board, executive, engineering, customer success, customers, legal, procurement. Seven audience archetypes, six templates (incident comms, post-mortem, breach disclosure, etc.). |
| [siem-detection](skills/siem-detection/) | SIEM detection engineering — log source coverage, Sigma rule authoring, MITRE ATT&CK mapping, FP tuning, detection-as-code. |
| [soc-operations](skills/soc-operations/) | Build / run / improve a SOC — alert prioritization, runbook authoring, escalation criteria, on-call structure, KPIs (MTTD / MTTR / FP rate), alert-fatigue tuning loop. |
| [threat-hunting](skills/threat-hunting/) | Proactive, hypothesis-driven adversary detection — PEAK framework, ATT&CK-driven hunt catalog, every hunt produces an artifact (rule, dead-end doc, or coverage gap). |
| [threat-modeling](skills/threat-modeling/) | Pre-implementation security design — STRIDE per element + abuse cases, data flow diagrams with trust boundaries, four-question Shostack frame. |
| [vuln-research](skills/vuln-research/) | CVE deep-dive — pull canonical sources, confirm versions, reachability analysis, check public PoCs / CISA KEV / EPSS, decide patch / mitigate / accept-risk. |
| [web-pentest](skills/web-pentest/) | Live web application pentest against an authorized target — OWASP WSTG-structured, nine phases from config through business logic. Combined white-box + black-box mode (code ↔ endpoint Target Map) when you have source too; every PoC carries paired baseline-vs-attack evidence. Writes findings.json (confirmed / needs validation / rejected), with SARIF export. |
<!-- SKILLS:END -->

Want to see the output first? [`examples/`](examples/) has real runs of five audit skills against a small vulnerable app.

Every offensive skill enforces an authorization check before doing anything; every skill refuses destructive or unauthorized use. Details in [Ethics & Authorization](#ethics--authorization).

## Installation

### Option 1: `npx skills` (recommended)

The [vercel-labs/skills](https://github.com/vercel-labs/skills) installer reads the canonical `skills/` directory directly:

```bash
# List available skills
npx skills add briiirussell/cybersecurity-skills --list

# Install all skills
npx skills add briiirussell/cybersecurity-skills

# Install specific skills
npx skills add briiirussell/cybersecurity-skills --skill owasp-audit api-audit
```

Installs to your `.agents/skills/` directory with a symlink into `.claude/skills/` for Claude Code compatibility.

### Option 2: Claude Code plugin marketplace

```bash
/plugin install cybersecurity-skills --marketplace briiirussell/cybersecurity-skills
```

That's one step on Claude Code 2.1.275 or later. On older versions, add the marketplace first:

```bash
/plugin marketplace add briiirussell/cybersecurity-skills
/plugin install cybersecurity-skills
```

The plugin also ships one subagent, `finding-verifier`. Audit skills hand it one candidate finding at a time, and it tries to disprove the finding in a fresh, read-only context. Cursor and Codex don't get the subagent; they follow the same steps from `verification.md`.

### Option 3: Claude Code (project-level, manual)

```bash
git clone https://github.com/briiirussell/cybersecurity-skills.git
cp -r cybersecurity-skills/skills/owasp-audit .claude/skills/
```

Trigger naturally ("run an OWASP audit on this codebase") or invoke directly with `/owasp-audit`.

### Option 4: Claude Code (personal, all projects)

```bash
cp -r cybersecurity-skills/skills/owasp-audit ~/.claude/skills/
```

### Option 5: Cursor

```bash
cp adapters/cursor/owasp-audit.mdc .cursor/rules/
```

### Option 6: Codex

```bash
cp adapters/codex/owasp-audit.md <your-codex-config-dir>/
```

### Option 7: Git submodule (easy updates)

```bash
git submodule add https://github.com/briiirussell/cybersecurity-skills.git .agents/cybersecurity-skills
```

Then reference skills from `.agents/cybersecurity-skills/skills/`.

## Building Adapters

After creating or modifying a skill, regenerate the Cursor + Codex adapters:

```bash
node scripts/build-adapters.mjs   # adapters + shared reference copies
node scripts/lint-skills.mjs      # frontmatter, size, cross-reference and link lint
npm test                          # findings / coverage validators, SARIF export, build (Node ≥ 21, no dependencies)
```

Files in `shared/` (the `findings.json` schema and validator, severity calibration, verification and coverage guides) are copied into each skill's `references/` folder according to `shared/manifest.json`, because `npx skills` installs one skill folder at a time. Edit `shared/`, never the copies.

## Creating a New Skill

1. Copy `templates/skill-template.md` to `skills/<your-skill>/SKILL.md`
2. Fill in the frontmatter (`name`, `description`, `allowed-tools`)
3. Write instructions in imperative form, under 500 lines
4. Add trigger prompts in `evals/triggers/<your-skill>.json` (see [`evals/README.md`](evals/README.md))
5. Run the build script to generate adapters, then `npm run check`

Format details and writing guidance live in [`CLAUDE.md`](CLAUDE.md). Full contribution flow in [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Security scanning

Every PR is linted and scanned with [NVIDIA SkillSpector](https://github.com/NVIDIA/SkillSpector) (static mode, pinned version). Intentional example payloads — a security skill has to name `~/.aws/credentials` and show what an injection looks like — are suppressed by narrow, reasoned rules in [`.skillspector-baseline.yaml`](.skillspector-baseline.yaml). Scan it yourself before installing:

    skillspector scan https://github.com/briiirussell/cybersecurity-skills --recursive --no-llm

Our baseline is never applied to your scan; SkillSpector only uses an author-shipped baseline for a single skill with `--use-shipped-baseline`. `allowed-tools` lists tools pre-approved to run **without a prompt** in Claude Code — it is not a sandbox — and the Cursor / Codex adapters carry no tool restrictions at all. Details: [docs/security-scanning.md](docs/security-scanning.md). You can also point `agent-supply-chain-audit` at this repo.

Found a way a skill could lead an agent to do something unsafe, like an over-broad grant or an instruction that skips the authorization check? Please report it privately. [SECURITY.md](SECURITY.md) has what's in scope and how.

## Ethics & Authorization

These skills are for **authorized security testing, CTF competitions, security research, and defensive use only**. Every offensive skill (`recon`, `osint-recon`, `web-pentest`, etc.) opens with an authorization check and refuses destructive techniques, mass targeting, supply-chain compromise, or evasion patterns intended for malicious use.

If you're using these against a system you don't own or have explicit written authorization to test, you are using them wrong. Don't.

## Versioning

This repo follows [semantic versioning](https://semver.org/). See [`VERSIONS.md`](VERSIONS.md) for the full changelog and [GitHub Releases](https://github.com/briiirussell/cybersecurity-skills/releases) for release notes.

- **MAJOR** (X.0.0) — Breaking changes: skill renames, removals, or frontmatter changes that break existing installs
- **MINOR** (1.X.0) — New skill, or substantive expansion of an existing one
- **PATCH** (1.0.X) — Content fixes, grep-pattern updates, small additions

Every new skill and every skill improvement ships as its own version, one PR each, so each skill's version in `VERSIONS.md` tells you exactly what changed and when.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). The short version: field feedback (PRs or issues with concrete patterns from a real audit) is the highest-signal contribution. If a skill missed something in your audit, that's exactly what I want to know. Open a [field report](https://github.com/briiirussell/cybersecurity-skills/issues/new?template=field-report.yml). If one found something real, I'd love a [trophy case](https://github.com/briiirussell/cybersecurity-skills/issues/new?template=trophy-case.yml) entry.

## License

MIT — see [`LICENSE`](LICENSE).
