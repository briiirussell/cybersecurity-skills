# Contributing

Thanks for your interest in contributing. The highest-signal contribution to this repo is **field feedback** — concrete patterns from a real audit, with the false-negative (or false-positive) that surfaced them. That's how each skill gets sharper over time.

## What to contribute

- **Field feedback issues** — "I ran `owasp-audit` against a Next.js + Drizzle app and it missed X. Here's the pattern and a suggested grep." Open an [issue](https://github.com/briiirussell/cybersecurity-skills/issues/new) with the framework, the missing pattern, and (if you have it) a concrete code shape it should match against.
- **PRs that close a feedback gap** — Take an open issue, add the bullet/grep/section to the relevant `SKILL.md`, regenerate adapters, open a PR referencing the issue.
- **New skills** — A new skill should cover a distinct domain (not a re-slice of an existing one). Check the [skill map](README.md#how-skills-work-together) first to make sure it fits.
- **Adapter fixes** — Cursor / Codex output bugs, build script improvements.

## Workflow

This repo uses a `main` + `development` model:

- `main` — Stable. What's tagged in releases.
- `development` — Integration branch. Feature branches merge here first.
- `feature/<name>` — Your branch for a specific change.

### Step by step

1. **Fork the repo** (or branch directly if you have push access)
2. **Branch from `development`**:
   ```bash
   git checkout development
   git pull
   git checkout -b feature/your-change
   ```
3. **Make your changes** — keep the scope tight; one logical change per PR
4. **Regenerate adapters** if you touched any `SKILL.md`:
   ```bash
   node scripts/build-adapters.mjs
   ```
5. **Commit and push**
6. **Open a PR into `development`** — not `main`. The release cut promotes `development` → `main`.

## Adding a new skill

### 1. Create the directory

```bash
mkdir -p skills/your-skill-name
```

### 2. Write `SKILL.md`

Start from the template:

```bash
cp templates/skill-template.md skills/your-skill-name/SKILL.md
```

Required frontmatter:

```yaml
---
name: your-skill-name
description: "What it does and when to use it. Include trigger phrases agents will see in user prompts. 200–1024 chars."
allowed-tools: Bash, Read, Write, Grep, Glob, WebSearch
---
```

### 3. Naming rules

- Directory and `name` field: lowercase, hyphens only (e.g., `cloud-audit`, not `Cloud_Audit`)
- Both must match exactly
- Description: lead with what it does, then list trigger phrases. Be "pushy" — agents under-trigger when descriptions are thin.

### 4. Structure

```
skills/your-skill-name/
├── SKILL.md           # Required — main instructions
├── references/        # Optional — detailed reference material
├── scripts/           # Optional — helper scripts
└── assets/            # Optional — templates, fixtures
```

### 5. Writing the instructions

- **Imperative form** — "Check for X" / "Run Y" / "Report findings as Z"
- **Under 500 lines** in `SKILL.md` — offload depth to `references/`
- **Define the output format** explicitly — agents drift without a template
- **Include an authorization check** for any offensive skill — it should refuse if the user can't confirm authorization
- **Anti-pattern bullets > prose** — `OWASP A01: missing role check on /api/admin/*` beats a paragraph about access control

### 6. Build

```bash
node scripts/build-adapters.mjs
```

This regenerates `adapters/cursor/your-skill-name.mdc` and `adapters/codex/your-skill-name.md`.

### 7. Test locally

```bash
cp -r skills/your-skill-name ~/.claude/skills/
```

Run a real scenario against it. Iterate until the output is what you'd want to read first thing on a Monday.

## PR checklist

- [ ] Branched from `development`
- [ ] `name` matches directory name
- [ ] `description` is pushy and lists trigger phrases
- [ ] `SKILL.md` is under 500 lines
- [ ] Adapters regenerated (`node scripts/build-adapters.mjs`)
- [ ] Tested against a real scenario, not just a synthetic one
- [ ] No secrets, credentials, or proprietary data in examples
- [ ] If closing an issue, PR description references `Closes #N`

## Questions

Open an issue with the `question` label, or comment on an open issue if it's related.
