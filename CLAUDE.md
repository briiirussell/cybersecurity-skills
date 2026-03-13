# CLAUDE.md

## Project Overview

**Cybersecurity Skills** is a collection of AI-agent-compatible cybersecurity skill prompts. Skills are authored in a canonical markdown format and can be adapted for multiple AI coding agents.

## Supported Agents

| Agent | Adapter Format | Directory |
|-------|---------------|-----------|
| Claude Code | `.md` skill files | `adapters/claude-code/` |
| Cursor | `.mdc` rule files | `adapters/cursor/` |
| Codex | Instruction files | `adapters/codex/` |

## Directory Structure

```
skills/           # Canonical skill definitions (source of truth)
adapters/         # Generated/adapted files per agent platform
templates/        # Templates for authoring new skills
scripts/          # Build scripts for generating adapters
```

## Skill Authoring

All skills are authored in `skills/<domain>/<skill-name>.md` using the canonical template in `templates/skill-template.md`. Each skill file contains:

1. **Metadata** (YAML frontmatter): name, domain, triggers, tools needed
2. **System prompt**: The core instruction set
3. **Examples**: Sample invocations and expected behavior
4. **Tool requirements**: What tools/capabilities the skill needs

## Build Commands

```bash
node scripts/build-adapters.mjs    # Generate all adapter files from canonical skills
```

## Domains

| Domain | Directory | Coverage |
|--------|-----------|----------|
| Pentesting | `skills/pentesting/` | Recon, exploitation, post-exploitation, reporting |
| OSINT | `skills/osint/` | Open source intelligence gathering and analysis |
| Forensics | `skills/forensics/` | Disk, memory, network forensics and evidence handling |
| Reverse Engineering | `skills/reverse-engineering/` | Binary analysis, disassembly, decompilation |
| Network Security | `skills/network-security/` | Traffic analysis, firewall rules, IDS/IPS |
| Web App Security | `skills/web-app-security/` | OWASP Top 10, API security, code review |
| Cloud Security | `skills/cloud-security/` | AWS/GCP/Azure hardening, IAM, misconfigurations |
| Cryptography | `skills/cryptography/` | Cipher analysis, protocol review, implementation audits |
| Malware Analysis | `skills/malware-analysis/` | Static/dynamic analysis, sandboxing, indicators |
| Incident Response | `skills/incident-response/` | Triage, containment, eradication, recovery |
| Social Engineering | `skills/social-engineering/` | Phishing analysis, awareness training, pretexting defense |

## Guidelines

- All skills must include clear **authorization context** (pentesting engagements, CTF, security research, defensive use)
- Skills should refuse destructive or malicious use cases
- Focus on educational value and professional security workflows
- Test skills across all three agent platforms before merging
