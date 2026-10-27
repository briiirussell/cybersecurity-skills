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
└── <skill-name>/
    ├── SKILL.md             # Canonical skill (35 skills)
    └── references/          # Skill-specific references + GENERATED copies of shared/ files
shared/                      # Source of truth for files several skills need (findings schema,
│                            # validators, to-sarif, severity calibration, verification, ...)
└── manifest.json            # Which skills get a copy of each file in skills/<skill>/references/
adapters/
├── cursor/                  # Generated .mdc files
└── codex/                   # Generated .md files
templates/
└── skill-template.md
scripts/
├── build-adapters.mjs       # Adapters + manifest-driven shared/ copies
├── lint-skills.mjs
├── grant-check.mjs          # allowed-tools Bash grant check (used by the lint)
├── eval-triggers.mjs        # offline trigger eval: ranks evals/triggers prompts against descriptions
└── test/                    # node:test suites + fixtures (run with npm test)
evals/
├── README.md                # how the trigger evals work and what the numbers mean
├── triggers/<skill>.json    # 5+ prompts that should fire the skill, 5+ near-misses with their owner
└── cases/<case>/            # claude plugin eval suite: prompt.md + graders/ (paid; evals.yml, on demand)
package.json                 # npm test / npm run build — no dependencies, Node >= 21
.github/
├── workflows/ci.yml   # lint, trigger eval, versions, plugin validate, adapter drift, tests, SkillSpector (+ weekly on main)
├── workflows/links.yml  # weekly link check; opens a broken-links issue
├── workflows/evals.yml  # claude plugin eval on demand + on main (needs ANTHROPIC_API_KEY)
├── dependabot.yml     # weekly grouped bumps for the pinned actions
└── scripts/           # SkillSpector baseline splitter, SARIF merge, plugin-validate, eval summary
.skillspector-baseline.yaml
docs/
└── security-scanning.md
```

## Skill Format (Claude Code SKILL.md)

Every skill follows the [Anthropic skill creator guidelines](https://code.claude.com/docs/en/skills):

```yaml
---
name: skill-name                    # Lowercase, hyphens, max 64 chars
description: "What it does and when to use it. 200-1024 chars. Include trigger phrases."
allowed-tools: Read, Grep, Glob     # Pre-approved: run WITHOUT a permission prompt
---
```

**Frontmatter fields:**
- `name` — Slug used for `/skill-name` invocation. Lowercase + hyphens only.
- `description` — Explains WHAT the skill does and WHEN to use it. Claude uses this to decide automatic invocation. Be "pushy" to combat undertriggering.
- `allowed-tools` — Tools that run **without a permission prompt** while the skill is active (the invoking turn). It is a pre-approval, **not** an access list or ceiling: unlisted tools stay callable and go through the user's normal permission settings. Default `Read, Grep, Glob`. Add `Bash` only scoped to a read-only command prefix (`Bash(trivy fs:*)`, `Bash(dig:*)`); use exact rules where a wildcard would also match a destructive sub-mode (`Bash(npm audit --json)`, not `Bash(npm audit:*)`). Never pre-approve active scanning, exploitation, history rewrites, or state changes. Never pair `WebFetch` with unscoped `Bash` (the lint fails it). The lint also fails a `Bash` grant that would pre-approve a write — a write verb, a prefix that matches a destructive subcommand, a wildcard on a bare CLI or a source rewriter (`scripts/grant-check.mjs`; add new CLIs' destructive subcommands there). Add `Write` only when the skill's main output is a file. Cursor/Codex adapters drop this field entirely. See `docs/security-scanning.md`.
- `disable-model-invocation` — Set `true` for manual-only skills (e.g., deploy).
- `user-invocable` — Set `false` for background knowledge only.

**Content guidelines:**
- Use imperative form ("Run this command", "Check for X")
- Keep SKILL.md under 500 lines
- Move reference material to separate files if needed
- Define output formats explicitly

## Build Commands

```bash
node scripts/build-adapters.mjs    # Generate Cursor + Codex adapters and copy shared/ files into skills/*/references/ (also: npm run build)
node scripts/lint-skills.mjs       # Frontmatter, size, cross-reference, link and allowed-tools lint (CI runs this)
node scripts/check-versions.mjs --base origin/development   # Versions in sync + bumped vs the base (CI runs this on PRs)
node scripts/eval-triggers.mjs --verbose   # Offline trigger eval: which prompts route to the wrong skill (CI runs this)
npm run check                      # Everything CI runs locally except SkillSpector and plugin validate
node .github/scripts/plugin-validate.mjs  # claude plugin validate, strict with named exceptions (needs the claude CLI)
npm test                           # node:test suites in scripts/test/ — validators, to-sarif, build (CI runs this; Node >= 21)
node .github/scripts/skillspector-baseline.mjs --check   # Validate .skillspector-baseline.yaml
```

**Shared files:** edit the file in `shared/`, then run `node scripts/build-adapters.mjs` and commit the regenerated copies. Never hand-edit `skills/<skill>/references/<shared file>`; the build overwrites it and CI fails on drift. To give a skill a copy, add the skill to that file's list in `shared/manifest.json`.

CI (`.github/workflows/ci.yml`) also fails on stale adapters and on SkillSpector findings not covered by `.skillspector-baseline.yaml`.

## Creating a New Skill

1. Create `skills/<skill-name>/SKILL.md` using `templates/skill-template.md`
2. Use proper frontmatter (`name`, `description`, `allowed-tools`)
3. Write instructions in imperative form
4. Add `evals/triggers/<skill-name>.json`: at least 5 prompts that should fire it (include a casual one and one with pasted code or config) and 5 near-misses, each naming the skill that should own it instead
5. If the skill links a shared file (`references/findings.schema.json`, `references/verification.md`, ...), add it to `shared/manifest.json`
6. Run `node scripts/build-adapters.mjs` to generate adapters and shared copies
7. Run `npm run check`
8. Test the skill in Claude Code by copying to `.claude/skills/`

## Guidelines

- All skills must include an authorization check before taking action: a level-2 heading containing "Authorization" (`## Authorization`, `## Authorization and Mode`, ...) that says whose systems the skill may touch and what needs the owner's go-ahead. The lint fails a skill without one.
- Skills should refuse destructive or malicious use cases
- Focus on educational value and professional security workflows
- Keep descriptions "pushy" — include all relevant trigger phrases so the skill activates when needed
