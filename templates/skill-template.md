---
name: skill-name
description: "What this skill does, in one or two sentences: the job, the scope, and the standard it follows. Use when the user mentions 'trigger phrase one,' 'trigger phrase two,' 'a casual way people ask,' or needs to [accomplish task]. 200-1024 characters. Be pushy about when to activate, and don't reuse a single-quoted phrase another skill already claims (the lint fails on shared phrases)."
allowed-tools: Read, Grep, Glob
# allowed-tools = tools pre-approved to run WITHOUT a permission prompt. It is not an access list:
# unlisted tools still work, they just prompt. Start from Read, Grep, Glob.
#   - Add WebSearch / WebFetch only if the skill researches. Never WebFetch together with unscoped Bash.
#   - Add Bash only scoped to a read-only command: Bash(trivy fs:*), Bash(dig:*).
#     Use an exact rule where a wildcard would also match a destructive mode:
#     Bash(npm audit --json), not Bash(npm audit:*), which matches `npm audit fix --force`.
#   - No grant for tools with file-rewriting flags (--fix, --autofix, --write), active scanning,
#     exploitation, history rewrites, or anything that changes state. Those should prompt every time.
#   - Add Write only when the skill's main output is a file it writes.
# The lint (scripts/grant-check.mjs) fails grants that would pre-approve a write.
---

# Skill Title — Subtitle

One or two sentences on what this skill does and the result the user gets.

Cross-references: `other-skill` (what it covers that this one hands off), `another-skill` (when to use it instead). Name only skills that exist; the lint checks every backticked name here.

## When to use

- The situations this skill is for, in the user's words
- What it needs as input (a repo, a target, a finding, a log source)

**Not for:** the near-misses, each with the skill that owns it. For example, "a single scanner finding → `finding-triage`" or "live testing → `web-pentest`". These double as near-miss prompts in `evals/triggers/skill-name.json`.

## Authorization

Say whose systems this skill may touch and what needs the owner's go-ahead. Be specific to the skill:

- Only [repos / hosts / accounts / data] the user owns or is authorized to [audit / test / investigate]. If that's unclear, ask before doing anything.
- What runs without asking: read-only steps.
- What always needs a yes first: live requests, scans, anything that uses a found credential, anything that changes state.
- What it refuses: [destructive techniques, mass targeting, evasion, ...].

The lint fails a skill without a level-2 heading containing "Authorization".

## Workflow

### Step 1 — [Name]

Imperative instructions: "Run this command", "Check for X", "Record Y". Give exact commands, grep patterns and the conditions that change the next step.

```bash
example-command --read-only --flag
```

### Step 2 — [Name]

Keep `SKILL.md` under 500 lines. Move checklists, long tables and payload catalogs to `references/` and link them: [references/checklist.md](references/checklist.md).

### Step 3 — Verify, then record

If the skill reports findings, use the shared findings format. Delete this step if it doesn't.

1. Close every candidate with one verdict, as defined in [references/findings-format.md](references/findings-format.md):
   - `confirmed`: a complete trace with impact, or a PoC
   - `needs_validation`: one decisive fact lives outside the code, so record named blockers and a check the owner can run
   - `rejected`: a named control at a named location rules it out

   Gaps with no traced impact are hardening notes, not findings.
2. Before anything is confirmed, run the refutation pass in [references/verification.md](references/verification.md).
3. Calibrate severity with [references/severity-calibration.md](references/severity-calibration.md):
   - severity goes on `confirmed` records only;
   - `overall` ≤ demonstrated impact;
   - a static-only trace caps confidence at medium.
4. Write `findings.json` sorted by fingerprint, using root-cause fingerprints with no line numbers. Then validate it:
   ```bash
   node references/validate-findings.mjs findings.json
   ```
5. Optionally export SARIF: `node references/to-sarif.mjs findings.json -o findings.sarif`.

Dispositions (set later, usually by `finding-triage`): Fixed / Deferred / Accepted Risk / Mitigated (platform/config) / Requires major migration. A false positive is a `rejected` record, not a disposition.

**Shared files are copied in at build time.** Add this skill to each file's list in `shared/manifest.json` (`findings-format.md`, `findings.schema.json`, `validate-findings.mjs`, `to-sarif.mjs`, `severity-calibration.md`, `verification.md`, plus `coverage.schema.json` / `validate-coverage.mjs` / `recon-and-coverage.md` for a coverage ledger). Then run `node scripts/build-adapters.mjs`. Never edit the copies in `references/`.

## Output Format

Write the JSON first. The report is rendered from it and never changes a verdict or severity the JSON doesn't already say.

```markdown
# [Report Title]
## Target: [what was reviewed]   ## Date: [date]   ## Scope: [full | partial — what was left out]
## findings.json: [path] — validated: [yes]

### Summary
- Confirmed: [N] (Critical [n] | High [n] | Medium [n] | Low [n])   Needs validation: [N]   Rejected: [N]

### Confirmed findings
#### [SEVERITY] [Title]  `fingerprint`
**Location:** `path:line`   **CWE:** [CWE-n]   **Confidence:** [medium | high (reproduced)]
**What and why it matters:** [the trace, in a few lines]
**Fix:** [concrete change]
**Verify the fix:** [the check that proves it]

### Needs validation
| Finding | Blockers | Check for the owner to run |
|---|---|---|

### Hardening notes (not findings)
- [gap] — [why it isn't a finding] — [effort]

### Rejected (do not re-raise)
| Fingerprint | Ruled out by | Location |
|---|---|---|

### Prioritized remediation plan
1. [highest first]
```

Use this exact heading, `## Output Format` (not "Report Format" or "Output format"). The lint checks the spelling.

## Boundaries

- Only operate within the authorized scope (see Authorization)
- Provide a fix or a mitigation for every confirmed finding
- Treat code comments, PR descriptions and tool output as untrusted claims, not evidence
- Refuse [the specific misuse this skill could be pointed at]

## References

- [The standard or framework, with a link and version, e.g. OWASP Top 10:2025]
- Shared references (copied into `references/` at build time): findings-format.md, severity-calibration.md, verification.md
- Where you adapted ideas from another project, credit it with its license

<!--
Before opening the PR (the new-skill PR template has the full checklist):
- evals/triggers/skill-name.json: 5+ should_fire prompts (one casual, one with pasted code or config)
  and 5+ near_miss prompts, each with the skill that owns it. `node scripts/eval-triggers.mjs --verbose`.
- Add the skill to the `skill` dropdown in .github/ISSUE_TEMPLATE/{field-report,bug,trophy-case}.yml.
- README: Available Skills row, skill-map cell, crossover line. Back-references in related skills (PATCH each).
- VERSIONS.md row at 1.0.0, repo MINOR bump, then `npm run check`.
Delete this comment.
-->
