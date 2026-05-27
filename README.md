# Cybersecurity Skills for AI Agents

A collection of cybersecurity skills for AI coding agents. Built for developers, security engineers, and red/blue teamers who want their AI assistant to handle real security work — source-code audits, dependency triage, cloud config review, incident response, OSINT, and AI/LLM security.

Skills are authored as Claude Code [`SKILL.md` files](https://code.claude.com/docs/en/skills) (the canonical format) and built into adapters for Cursor and Codex. Works with any agent that supports the skill spec.

Built by [Bri Russell](https://github.com/briiirussell). I run real audits with these skills, then bring the gaps I find back into the skill itself — so each version is a little less opinion and a little more evidence.

**Contributions welcome!** Found a gap during an audit, or have a new skill to add? [Open a PR](#contributing) or [open an issue](https://github.com/briiirussell/cybersecurity-skills/issues) — field feedback is the most valuable thing you can send.

## What are Skills?

Skills are markdown files that give AI agents specialized knowledge and workflows for specific tasks. Drop them into your project and your agent recognizes when you're working on a security task and applies the right methodology — OWASP categories, NIST IR steps, MITRE ATT&CK references, the actual grep patterns that surface the bug.

The goal isn't to replace a security engineer. It's to give the agent enough structure that the first pass is useful, the report format is consistent, and the obvious stuff stops slipping through.

## How Skills Work Together

Skills are organized into five families. Most security work touches more than one — an OWASP audit usually surfaces a dependency question, an incident often kicks off an OSINT trail, cloud findings overlap with appsec. The skills cross-reference each other where that's true.

```
                    ┌──────────────────────────────────────┐
                    │       Cybersecurity Skill Map        │
                    └──────────────────┬───────────────────┘
                                       │
       ┌───────────────┬───────────────┼───────────────┬───────────────┐
       ▼               ▼               ▼               ▼               ▼
  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐
  │  AppSec  │   │ Offensive│   │ Detect & │   │  Cloud   │   │    AI    │
  │ & Supply │   │  & Recon │   │ Respond  │   │   & IaC  │   │ Security │
  ├──────────┤   ├──────────┤   ├──────────┤   ├──────────┤   ├──────────┤
  │owasp-    │   │recon     │   │incident- │   │cloud-    │   │prompt-   │
  │ audit    │   │osint-    │   │ triage   │   │ audit    │   │ injection│
  │dependency│   │ recon    │   │disk-     │   │          │   │          │
  │ -audit   │   │          │   │ forensics│   │          │   │          │
  └────┬─────┘   └────┬─────┘   └────┬─────┘   └────┬─────┘   └────┬─────┘
       │              │               │              │              │
       └──────────────┴───────┬───────┴──────────────┴──────────────┘
                              │
          Common crossovers:
            owasp-audit ↔ dependency-audit ↔ prompt-injection
            recon ↔ osint-recon ↔ owasp-audit (target appsec)
            incident-triage → disk-forensics, osint-recon (attribution)
            cloud-audit ↔ owasp-audit (IaC + app boundary)
```

## Available Skills

<!-- SKILLS:START -->
| Skill | What it does |
|-------|--------------|
| [cloud-audit](skills/cloud-audit/) | Audit AWS / GCP / Azure infrastructure for misconfigurations, excessive IAM permissions, public exposure, and compliance gaps. |
| [dependency-audit](skills/dependency-audit/) | Audit dependencies, frameworks, language runtimes, and dev tools for known CVEs, security anti-patterns, and supply chain risk. |
| [disk-forensics](skills/disk-forensics/) | Analyze disk images and file systems to recover evidence, reconstruct timelines, and identify artifacts for investigations or CTF. |
| [incident-triage](skills/incident-triage/) | Rapid triage and initial response to security incidents following NIST SP 800-61 methodology. |
| [osint-recon](skills/osint-recon/) | Gather and correlate open source intelligence from public sources for authorized investigations and threat intel. |
| [owasp-audit](skills/owasp-audit/) | Audit application source code against the OWASP Top 10 (2021) — category by category, with concrete grep patterns and remediation guidance. |
| [prompt-injection](skills/prompt-injection/) | Audit applications with AI features, LLM integrations, or agents for prompt injection, privilege escalation, and authorization bypass. |
| [recon](skills/recon/) | Structured reconnaissance and attack surface enumeration for authorized pentests, bug bounty, and CTF. |
<!-- SKILLS:END -->

Each skill enforces an authorization check before doing anything offensive, and refuses destructive or unauthorized use. Details in [Ethics & Authorization](#ethics--authorization).

## Installation

### Option 1: Claude Code (project-level)

Copy the skill directory into your project:

```bash
git clone https://github.com/briiirussell/cybersecurity-skills.git
cp -r cybersecurity-skills/skills/owasp-audit .claude/skills/
```

Then trigger naturally ("run an OWASP audit on this codebase") or invoke directly with `/owasp-audit`.

### Option 2: Claude Code (personal, all projects)

```bash
cp -r cybersecurity-skills/skills/owasp-audit ~/.claude/skills/
```

### Option 3: Cursor

```bash
cp adapters/cursor/owasp-audit.mdc .cursor/rules/
```

### Option 4: Codex

```bash
cp adapters/codex/owasp-audit.md <your-codex-config-dir>/
```

### Option 5: Clone everything

```bash
git clone https://github.com/briiirussell/cybersecurity-skills.git
cp -r cybersecurity-skills/skills/* .claude/skills/
```

### Option 6: Git submodule (easy updates)

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

These skills are for **authorized security testing, CTF competitions, security research, and defensive use only**. Every offensive skill (`recon`, `osint-recon`, etc.) opens with an authorization check and the skill itself will refuse destructive techniques, mass targeting, supply-chain compromise, or evasion patterns intended for malicious use.

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
