# CLAUDE.md

## Project Overview

**Cybersecurity Skills** is a collection of cybersecurity skill prompts for AI coding agents. Skills are authored as Claude Code `SKILL.md` files (the canonical format) and adapted for Cursor and Codex via a build script.

## Supported Agents

| Agent | Format | Location |
|-------|--------|----------|
| Claude Code | `SKILL.md` (canonical) | `skills/<skill-name>/SKILL.md` — copy to `.claude/skills/` |
| Cursor | `.mdc` rule files | `adapters/cursor/` |
| Codex | Instruction `.md` | `adapters/codex/` |

## Directory Structure

```
skills/
├── recon/SKILL.md
├── owasp-audit/SKILL.md
├── disk-forensics/SKILL.md
├── osint-recon/SKILL.md
├── incident-triage/SKILL.md
└── cloud-audit/SKILL.md
adapters/
├── cursor/          # Generated .mdc files
└── codex/           # Generated .md files
templates/
└── skill-template.md
scripts/
└── build-adapters.mjs
```

## Skill Format (Claude Code SKILL.md)

Every skill follows the [Anthropic skill creator guidelines](https://code.claude.com/docs/en/skills):

```yaml
---
name: skill-name                    # Lowercase, hyphens, max 64 chars
description: "What it does and when to use it. 200-1024 chars. Include trigger phrases."
allowed-tools: Bash, Read, Write    # Tools the skill can use
---
```

**Frontmatter fields:**
- `name` — Slug used for `/skill-name` invocation. Lowercase + hyphens only.
- `description` — Explains WHAT the skill does and WHEN to use it. Claude uses this to decide automatic invocation. Be "pushy" to combat undertriggering.
- `allowed-tools` — Comma-separated list of tools the skill can access.
- `disable-model-invocation` — Set `true` for manual-only skills (e.g., deploy).
- `user-invocable` — Set `false` for background knowledge only.

**Content guidelines:**
- Use imperative form ("Run this command", "Check for X")
- Keep SKILL.md under 500 lines
- Move reference material to separate files if needed
- Define output formats explicitly

## Build Commands

```bash
node scripts/build-adapters.mjs    # Generate Cursor + Codex adapters from SKILL.md files
```

## Creating a New Skill

1. Create `skills/<skill-name>/SKILL.md` using `templates/skill-template.md`
2. Use proper frontmatter (`name`, `description`, `allowed-tools`)
3. Write instructions in imperative form
4. Run `node scripts/build-adapters.mjs` to generate adapters
5. Test the skill in Claude Code by copying to `.claude/skills/`

## Guidelines

- All skills must include an authorization check before taking action
- Skills should refuse destructive or malicious use cases
- Focus on educational value and professional security workflows
- Keep descriptions "pushy" — include all relevant trigger phrases so the skill activates when needed
