# Cybersecurity Skills for AI Agents

A curated collection of cybersecurity skill prompts compatible with multiple AI coding agents.

## What is this?

Pre-built cybersecurity skills that give AI coding agents specialized knowledge for security tasks — pentesting, OSINT, forensics, incident response, and more.

Skills are authored as Claude Code [`SKILL.md` files](https://code.claude.com/docs/en/skills) (the canonical format) and adapted for other agents via a build script:

- **Claude Code** — copy skill directories into `.claude/skills/`
- **Cursor** — use generated `.mdc` rule files from `adapters/cursor/`
- **Codex** — use generated instruction files from `adapters/codex/`

## Skills

| Skill | What it does |
|-------|-------------|
| `recon` | Attack surface enumeration and reconnaissance for pentests, bug bounty, CTF |
| `owasp-audit` | Source code security audit against OWASP Top 10 (2021) |
| `osint-recon` | Open source intelligence gathering and correlation |
| `disk-forensics` | Disk image analysis, evidence recovery, timeline reconstruction |
| `incident-triage` | Security incident triage following NIST SP 800-61 |
| `cloud-audit` | AWS/GCP/Azure misconfiguration and IAM auditing |

## Quick Start

### Claude Code

Copy a skill directory into your project or personal skills:

```bash
# Project-level
cp -r skills/owasp-audit .claude/skills/

# Personal (available in all projects)
cp -r skills/owasp-audit ~/.claude/skills/
```

Then use it naturally ("run an OWASP audit on my code") or invoke directly (`/owasp-audit`).

### Cursor

Copy rule files into your project:

```bash
cp adapters/cursor/owasp-audit.mdc .cursor/rules/
```

### Codex

Copy instruction files into your Codex configuration:

```bash
cp adapters/codex/owasp-audit.md <your-codex-config-dir>/
```

## Building Adapters

After creating or modifying skills, regenerate the adapter files:

```bash
node scripts/build-adapters.mjs
```

## Creating New Skills

1. Copy `templates/skill-template.md` to `skills/<your-skill>/SKILL.md`
2. Fill in the frontmatter (`name`, `description`, `allowed-tools`)
3. Write instructions in imperative form (under 500 lines)
4. Run the build script to generate adapters

See `CLAUDE.md` for the full format specification.

## Ethics & Authorization

All skills are designed for **authorized security testing, CTF competitions, security research, and defensive use cases only**. Every skill includes an authorization check and built-in guardrails that refuse destructive, malicious, or unauthorized use.

## License

MIT
