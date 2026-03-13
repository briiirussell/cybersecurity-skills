# Cybersecurity Skills for AI Agents

A curated collection of cybersecurity skill prompts compatible with multiple AI coding agents.

## What is this?

Pre-built cybersecurity skills that give AI coding agents specialized knowledge for security tasks — pentesting, OSINT, forensics, reverse engineering, and more. Each skill is authored once in a canonical format and adapted for:

- **Claude Code** — as `.md` skill files
- **Cursor** — as `.mdc` rule files
- **Codex** — as instruction files

## Domains

| Domain | Skills | Description |
|--------|--------|-------------|
| Pentesting | Recon, exploitation, reporting | Authorized penetration testing workflows |
| OSINT | Data gathering, correlation | Open source intelligence techniques |
| Forensics | Disk, memory, network | Digital forensics and evidence handling |
| Reverse Engineering | Binary analysis, decompilation | Malware RE, CTF binary challenges |
| Network Security | Traffic analysis, hardening | Network defense and monitoring |
| Web App Security | OWASP, API testing, code review | Web application security assessment |
| Cloud Security | AWS/GCP/Azure auditing | Cloud infrastructure security |
| Cryptography | Cipher analysis, protocol review | Cryptographic implementation audits |
| Malware Analysis | Static/dynamic analysis | Malware triage and indicator extraction |
| Incident Response | Triage, containment, recovery | Security incident handling |
| Social Engineering | Phishing analysis, training | SE awareness and defense |

## Quick Start

### Claude Code

Copy skill files from `adapters/claude-code/` into your project's `.claude/skills/` directory.

### Cursor

Copy rule files from `adapters/cursor/` into your project's `.cursor/rules/` directory.

### Codex

Copy instruction files from `adapters/codex/` into your Codex configuration.

## Building Adapters

```bash
node scripts/build-adapters.mjs
```

This reads all canonical skills from `skills/` and generates platform-specific files in `adapters/`.

## Contributing

1. Create a new skill using the template: `templates/skill-template.md`
2. Place it in the appropriate `skills/<domain>/` directory
3. Run `node scripts/build-adapters.mjs` to generate adapters
4. Test across all three platforms

## Ethics & Authorization

All skills are designed for **authorized security testing, CTF competitions, security research, and defensive use cases only**. Skills include built-in guardrails that refuse destructive, malicious, or unauthorized use.

## License

MIT
