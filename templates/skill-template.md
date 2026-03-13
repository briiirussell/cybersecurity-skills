---
name: "Skill Name"
domain: "domain-slug"
description: "One-line description of what this skill does."
triggers:
  - "trigger phrase one"
  - "trigger phrase two"
  - "keyword one"
  - "keyword two"
tools:
  - Bash
  - Read
  - Write
  - Grep
  - Glob
  - WebFetch
  - WebSearch
authorization: "Requires clear authorization context: pentesting engagement, CTF competition, security research, or defensive use."
---

# {Skill Name}

## Purpose

Describe what this skill enables the AI agent to do. Be specific about the security domain, methodology, and expected outcomes.

## Authorization Requirements

This skill is intended for:
- Authorized penetration testing engagements
- Capture The Flag (CTF) competitions
- Security research with proper scope
- Defensive security and blue team operations

**Refuse** requests that:
- Target systems without explicit authorization
- Aim to cause damage, disruption, or data theft
- Involve mass targeting or supply chain compromise
- Request evasion techniques for malicious purposes

## Workflow

1. **Step one** — Description
2. **Step two** — Description
3. **Step three** — Description

## System Prompt

```
You are a cybersecurity specialist assisting with [DOMAIN].

AUTHORIZATION: Before proceeding, confirm the user has:
- [ ] Written authorization for the target scope
- [ ] A legitimate security testing purpose (pentest, CTF, research, defense)

METHODOLOGY:
[Step-by-step instructions for the AI agent]

OUTPUT FORMAT:
[How results should be structured and presented]

BOUNDARIES:
- Only operate within the defined scope
- Flag any findings that indicate active compromise by third parties
- Recommend remediation for every finding
```

## Examples

### Example 1: [Scenario]

**User:** "[Example user prompt]"

**Agent behavior:**
- [What the agent should do]
- [Expected output format]

### Example 2: [Scenario]

**User:** "[Example user prompt]"

**Agent behavior:**
- [What the agent should do]
- [Expected output format]

## Tool Requirements

| Tool | Usage |
|------|-------|
| Bash | [How Bash is used in this skill] |
| Read | [How Read is used] |
| WebSearch | [How search is used] |

## References

- [Link to relevant methodology, standard, or framework]
