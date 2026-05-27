# Cybersecurity Skills for AI Agents

A collection of cybersecurity skills for AI coding agents. Built for developers, security engineers, and red/blue teamers who want their AI assistant to handle real security work — source-code audits, dependency triage, cloud and container review, IAM design, incident response, threat hunting, detection engineering, and governance mapping.

Skills are authored as Claude Code [`SKILL.md` files](https://code.claude.com/docs/en/skills) (the canonical format) and built into adapters for Cursor and Codex. Installable via [`npx skills`](https://github.com/vercel-labs/skills) or the Claude Code plugin marketplace.

Built by [Bri Russell](https://github.com/briiirussell). I run real audits with these skills, then bring the gaps I find back into the skill itself — so each version is a little less opinion and a little more evidence.

**Contributions welcome!** Found a gap during an audit, or have a new skill to add? [Open a PR](#contributing) or [open an issue](https://github.com/briiirussell/cybersecurity-skills/issues) — field feedback is the most valuable thing you can send.

## What are Skills?

Skills are markdown files that give AI agents specialized knowledge and workflows for specific tasks. Drop them into your project and your agent recognizes when you're working on a security task and applies the right methodology — OWASP categories, NIST IR steps, MITRE ATT&CK references, the actual grep patterns that surface the bug.

The goal isn't to replace a security engineer. It's to give the agent enough structure that the first pass is useful, the report format is consistent, and the obvious stuff stops slipping through.

## How Skills Work Together

The skills are organized into six families. Most security work crosses families — an OWASP audit surfaces a dependency question, an incident kicks off an OSINT trail, cloud findings overlap with appsec. Skills cross-reference each other where that's true; `finding-triage` and `csf-mapping` orchestrate across the whole map.

```
                  ┌────────────────────────────────────────────┐
                  │            Cybersecurity Skill Map         │
                  └──────────────────────┬─────────────────────┘
                                         │
   ┌──────────────┬──────────────┬───────┴───────┬──────────────┬───────────────┐
   ▼              ▼              ▼               ▼              ▼               ▼
┌────────┐  ┌──────────┐  ┌────────────┐  ┌────────────┐  ┌──────────┐  ┌────────────┐
│ AppSec │  │Offensive │  │  Detect &  │  │  Cloud &   │  │   AI     │  │  Design &  │
│& Supply│  │ & Recon  │  │  Respond   │  │   Infra    │  │ Security │  │ Governance │
├────────┤  ├──────────┤  ├────────────┤  ├────────────┤  ├──────────┤  ├────────────┤
│owasp-  │  │recon     │  │incident-   │  │cloud-      │  │prompt-   │  │threat-     │
│ audit  │  │osint-    │  │ triage     │  │ audit      │  │ injection│  │ modeling   │
│api-    │  │ recon    │  │disk-       │  │container-  │  │          │  │vuln-       │
│ audit  │  │web-      │  │ forensics  │  │ audit      │  │          │  │ research   │
│depend- │  │ pentest  │  │siem-       │  │iam-audit   │  │          │  │finding-    │
│ audit  │  │          │  │ detection  │  │            │  │          │  │ triage     │
│secrets-│  │          │  │soc-        │  │            │  │          │  │csf-mapping │
│ audit  │  │          │  │ operations │  │            │  │          │  │            │
│crypto- │  │          │  │threat-     │  │            │  │          │  │            │
│ audit  │  │          │  │ hunting    │  │            │  │          │  │            │
│mobile- │  │          │  │breach-     │  │            │  │          │  │            │
│ audit  │  │          │  │ patterns   │  │            │  │          │  │            │
└───┬────┘  └────┬─────┘  └─────┬──────┘  └─────┬──────┘  └────┬─────┘  └─────┬──────┘
    │            │              │               │              │              │
    └────────────┴───────┬──────┴───────────────┴──────────────┴──────────────┘
                         │
        Common crossovers:
          owasp-audit ↔ api-audit ↔ dependency-audit ↔ vuln-research
          web-pentest ↔ recon ↔ osint-recon ↔ owasp-audit
          siem-detection → threat-hunting → incident-triage → disk-forensics
          cloud-audit ↔ container-audit ↔ iam-audit ↔ secrets-audit
          threat-modeling → owasp-audit / api-audit (pre-implementation → code)
          breach-patterns → every audit skill (what to check)
          finding-triage ← every skill (closes the loop on any finding)
          csf-mapping ← every skill (rolls evidence into governance frame)
```

## Available Skills

<!-- SKILLS:START -->
| Skill | What it does |
|-------|--------------|
| [api-audit](skills/api-audit/) | OWASP API Security Top 10 (2023) — REST / GraphQL / RPC endpoint audit. BOLA, mass assignment, BFLA, rate-limit, GraphQL introspection, webhook signature. |
| [breach-patterns](skills/breach-patterns/) | Preemptive hardening — read public breach disclosures, extract the audit question each one implies, check your stack. Capital One / LastPass / Okta / Snowflake / MOVEit / Codecov / Equifax / Uber. |
| [cloud-audit](skills/cloud-audit/) | AWS / GCP / Azure infrastructure misconfiguration, excessive IAM, public exposure, compliance gaps. |
| [container-audit](skills/container-audit/) | Docker + Kubernetes audit. Dockerfile, base images, pod security, RBAC, NetworkPolicy, secrets, image policy, runtime. |
| [crypto-audit](skills/crypto-audit/) | Cryptography implementation review — algorithm/mode choice, KDF parameters, IV/nonce handling, authenticated encryption, signature verification, randomness, TLS posture, key lifecycle. Deeper than owasp-audit A02. |
| [csf-mapping](skills/csf-mapping/) | NIST CSF 2.0 posture assessment — Govern / Identify / Protect / Detect / Respond / Recover. Subcategory mapping, current/target tiers, prioritized roadmap. Translates technical findings into governance language. |
| [dependency-audit](skills/dependency-audit/) | Dependencies, frameworks, runtimes, toolchain — CVEs, security anti-patterns, supply chain risk. |
| [disk-forensics](skills/disk-forensics/) | Disk image analysis, evidence recovery, timeline reconstruction. |
| [finding-triage](skills/finding-triage/) | Single-finding disposition workflow — Fixed / Deferred / Accepted Risk / False Positive, with ticket-ready writeup templates and required-field enforcement. Closes the loop on every audit skill. |
| [iam-audit](skills/iam-audit/) | Consultant-style IAM — audit / design / migrate. Cloud IAM (AWS/GCP/Azure), identity providers (Okta/Entra/Auth0/Workspace), application authorization (RBAC/ABAC/ReBAC), workload identity, JIT access, break-glass. |
| [incident-triage](skills/incident-triage/) | Security incident triage following NIST SP 800-61. |
| [mobile-audit](skills/mobile-audit/) | iOS + Android audit against OWASP MASVS / MASTG — storage, crypto, network, auth, platform IPC, code, resilience. |
| [osint-recon](skills/osint-recon/) | Open source intelligence gathering and correlation. |
| [owasp-audit](skills/owasp-audit/) | Source-code audit against OWASP Top 10 (2021) — category checklist, grep patterns, runtime verification, Second-Opinion Pass, three-disposition reporting. |
| [prompt-injection](skills/prompt-injection/) | AI features / LLM integrations / agents — prompt injection, privilege escalation, authorization bypass. |
| [recon](skills/recon/) | Structured attack surface enumeration for authorized pentests, bug bounty, CTF. |
| [secrets-audit](skills/secrets-audit/) | Find leaked secrets (code, Git history, build artifacts, CI, frontend bundles) + audit secrets-management posture (rotation, scope, workload identity). |
| [siem-detection](skills/siem-detection/) | SIEM detection engineering — log source coverage, Sigma rule authoring, MITRE ATT&CK mapping, FP tuning, detection-as-code. |
| [soc-operations](skills/soc-operations/) | Build / run / improve a SOC — alert prioritization, runbook authoring, escalation criteria, on-call structure, KPIs (MTTD / MTTR / FP rate), alert-fatigue tuning loop. |
| [threat-hunting](skills/threat-hunting/) | Proactive, hypothesis-driven adversary detection — PEAK framework, ATT&CK-driven hunt catalog, every hunt produces an artifact (rule, dead-end doc, or coverage gap). |
| [threat-modeling](skills/threat-modeling/) | Pre-implementation security design — STRIDE per element + abuse cases, data flow diagrams with trust boundaries, four-question Shostack frame. |
| [vuln-research](skills/vuln-research/) | CVE deep-dive — pull canonical sources, confirm versions, reachability analysis, check public PoCs / CISA KEV / EPSS, decide patch / mitigate / accept-risk. |
| [web-pentest](skills/web-pentest/) | Live web application pentest against an authorized target — OWASP WSTG-structured, nine phases from config through business logic. |
<!-- SKILLS:END -->

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
/plugin marketplace add briiirussell/cybersecurity-skills
/plugin install cybersecurity-skills
```

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
node scripts/build-adapters.mjs
```

## Creating a New Skill

1. Copy `templates/skill-template.md` to `skills/<your-skill>/SKILL.md`
2. Fill in the frontmatter (`name`, `description`, `allowed-tools`)
3. Write instructions in imperative form, under 500 lines
4. Run the build script to generate adapters

Format details and writing guidance live in [`CLAUDE.md`](CLAUDE.md). Full contribution flow in [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Ethics & Authorization

These skills are for **authorized security testing, CTF competitions, security research, and defensive use only**. Every offensive skill (`recon`, `osint-recon`, `web-pentest`, etc.) opens with an authorization check and refuses destructive techniques, mass targeting, supply-chain compromise, or evasion patterns intended for malicious use.

If you're using these against a system you don't own or have explicit written authorization to test, you are using them wrong. Don't.

## Versioning

This repo follows [semantic versioning](https://semver.org/). See [`VERSIONS.md`](VERSIONS.md) for the full changelog and [GitHub Releases](https://github.com/briiirussell/cybersecurity-skills/releases) for release notes.

- **MAJOR** (X.0.0) — Breaking changes: skill renames, removals, or frontmatter changes that break existing installs
- **MINOR** (1.X.0) — New skill, or substantive expansion of an existing one
- **PATCH** (1.0.X) — Content fixes, grep-pattern updates, small additions

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). The short version: field feedback (PRs or issues with concrete patterns from a real audit) is the highest-signal contribution. If a skill missed something in your audit, that's exactly what I want to know.

## License

MIT — see [`LICENSE`](LICENSE).
