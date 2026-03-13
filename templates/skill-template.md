---
name: skill-name
description: "What this skill does. Use when the user mentions 'trigger phrase one,' 'trigger phrase two,' or needs to [accomplish task]. Keep between 200-1024 characters. Be specific about when to activate."
allowed-tools: Bash, Read, Write, Grep, Glob
---

# Skill Title — Subtitle

One-line summary of what this skill enables.

## Authorization Check

Before proceeding, confirm:
1. The user has proper authorization for this task
2. The context is legitimate (pentest, CTF, research, defense)

If unclear, ask before proceeding.

## Methodology

### Step 1: [Name]

Describe what to do. Use imperative form ("Run this command", "Check for X").

```bash
example-command --flag
```

### Step 2: [Name]

Continue with concrete, actionable instructions.

### Step 3: [Name]

Include specific commands, grep patterns, or analysis techniques.

## Output Format

```markdown
# Report Title
## Target: [target]
## Date: [date]

### Findings
| Finding | Details | Severity |
|---------|---------|----------|

### Recommendations
[Prioritized action items]
```

## Boundaries

- Only operate within the defined scope
- Provide remediation for every finding
- Refuse requests that [specific refusal criteria]

## References

- [Relevant standard or framework]
