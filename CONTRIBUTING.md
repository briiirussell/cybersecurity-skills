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
4. **Regenerate adapters and shared copies** if you touched any `SKILL.md` or anything in `shared/`:
   ```bash
   node scripts/build-adapters.mjs
   ```
   Files in `shared/` are copied into `skills/<skill>/references/` per `shared/manifest.json`. Edit `shared/`, never the copies.
5. **Run the checks CI runs**:
   ```bash
   npm run check   # lint, baseline, versions, trigger eval, adapter drift, tests (Node >= 21, no dependencies)
   ```
6. **Commit and push**
7. **Open a PR into `development`** — not `main`. The release cut promotes `development` → `main`.

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
allowed-tools: Read, Grep, Glob
---
```

`allowed-tools` lists tools that run **without a permission prompt** while the skill is active. It is a pre-approval, not an access list: unlisted tools still work, they just prompt. Keep it tight:

- Start from `Read, Grep, Glob`. Add `WebSearch` / `WebFetch` if the skill researches.
- Add `Bash` only scoped to a read-only command, e.g. `Bash(trivy fs:*)`, `Bash(dig:*)`. If a wildcard would also match a destructive sub-mode, use an exact rule (`Bash(npm audit --json)`, not `Bash(npm audit:*)`, which matches `npm audit fix --force`). `grep`, `cat`, `ls` and read-only `git` already run without prompts.
- Never pre-approve active scanning or exploitation of a target, history rewrites, or anything that changes state — the user should confirm those each time.
- Never combine `WebFetch` with unscoped `Bash` — CI fails it.
- Add `Write` only if the skill's main output is a file it writes.

Cursor and Codex adapters carry no tool restrictions at all. See [docs/security-scanning.md](docs/security-scanning.md).

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

### 6. Build and lint

```bash
node scripts/build-adapters.mjs
node scripts/lint-skills.mjs
```

The build regenerates `adapters/cursor/your-skill-name.mdc` and `adapters/codex/your-skill-name.md`, and copies the `shared/` files listed for your skill in `shared/manifest.json` into `skills/your-skill-name/references/`. To link a shared file (e.g. `references/findings.schema.json`), add your skill to that file's list in the manifest first. The lint checks frontmatter, size, cross-references, links and `allowed-tools`.

### 7. Add trigger prompts

Create `evals/triggers/your-skill-name.json`:

```json
{
  "skill": "your-skill-name",
  "should_fire": ["five or more prompts a real user would type, casual ones and one with pasted code or config"],
  "near_miss": [{ "prompt": "a prompt that sounds close but belongs elsewhere", "owner": "other-skill" }]
}
```

Write the prompts the way people actually ask, not by copying phrases from your description. `node scripts/eval-triggers.mjs --verbose` ranks every prompt against every description and lists the ones that land on the wrong skill. It's a cheap proxy for routing, so a miss is a hint to sharpen a description, not proof the model will misroute. See [evals/README.md](evals/README.md).

### 8. Test locally

```bash
cp -r skills/your-skill-name ~/.claude/skills/
```

Run a real scenario against it. Iterate until the output is what you'd want to read first thing on a Monday.

## PR checklist

CI (`.github/workflows/ci.yml`) runs on every PR into `development` or `main` and enforces the first group automatically. Run the commands locally first.

Enforced by CI:

- [ ] Skill lint passes — `node scripts/lint-skills.mjs` (`name` matches directory, `description` 200–1024 chars, `SKILL.md` under 500 lines, an `## Authorization` section, cross-referenced skills exist, relative links resolve, no `WebFetch` + unscoped `Bash`, no `Bash` grant whose prefix also matches a destructive subcommand)
- [ ] Adapters and shared copies regenerated and committed — `node scripts/build-adapters.mjs` leaves no diff; shared content edited in `shared/`, not in `skills/*/references/` copies
- [ ] Versions bumped — repo version in `.claude-plugin/plugin.json` and `marketplace.json`, a `### X.Y.Z (date)` entry in `VERSIONS.md`, and the row of every skill you changed (fix = PATCH, improvement = MINOR, new skill = 1.0.0). `node scripts/check-versions.mjs --base origin/development` checks this
- [ ] Trigger prompts added or updated — `evals/triggers/<skill>.json` (5+ should-fire, 5+ near-misses with an `owner`); `node scripts/eval-triggers.mjs --verbose` shows which prompts land on the wrong skill. If you edited a description, check you didn't steal another skill's prompts
- [ ] `npm run check` passes (lint, baseline check, version check, trigger eval, adapter drift, tests — the CI checks that need no extra tools)
- [ ] Tests pass — `npm test` (add or update a test in `scripts/test/` if you changed a validator, `to-sarif.mjs`, or the build)
- [ ] SkillSpector scan is clean — any new finding is fixed, or covered by a narrow rule **with a reason** in `.skillspector-baseline.yaml` (see [docs/security-scanning.md](docs/security-scanning.md))

Reviewed by a human:

- [ ] Branched from `development`
- [ ] `description` is pushy and lists trigger phrases and none of them is already claimed by another skill (the lint fails on shared phrases)
- [ ] `allowed-tools` is minimal: no unscoped `Bash`, `Write` only if the skill writes a file
- [ ] Tested against a real scenario, not just a synthetic one
- [ ] No secrets, credentials, or proprietary data in examples
- [ ] If closing an issue, PR description references `Closes #N`

## Questions

Open an issue with the `question` label, or comment on an open issue if it's related.
