## New skill: `skill-name`

What it does, who it's for, and why no existing skill covers it.

Closes #

## The skill

- [ ] `skills/<name>/SKILL.md` from `templates/skill-template.md`: `name` matches the folder, `description` is 200–1024 chars and pushy, and no trigger phrase is already claimed by another skill
- [ ] Has a `## Authorization` section saying whose systems it may touch and what needs the owner's go-ahead
- [ ] `allowed-tools` is minimal: `Read, Grep, Glob`, plus only scoped read-only `Bash(...)` or exact rules. `Write` only if the main output is a file. No `WebFetch` with unscoped `Bash`
- [ ] `SKILL.md` is under 500 lines, with depth moved to `references/`
- [ ] If it reports findings: it uses `references/findings-format.md` (verdicts, dispositions, severity calibration, verification), and its shared files are listed in `shared/manifest.json`

## Wiring it in

- [ ] `evals/triggers/<name>.json`: 5+ should-fire prompts (one casual, one with pasted code or config) and 5+ near-misses with an `owner`
- [ ] README: an Available Skills row, a skill-map cell, a crossover line, and a "Where to start" bullet if it fits
- [ ] Back-references in related skills' cross-references, each a PATCH bump on that skill's row
- [ ] `node scripts/build-adapters.mjs` run and the adapters and shared copies committed

## Versions

- [ ] Repo MINOR bump in `plugin.json` and `marketplace.json`, and a `### X.Y.0 (date)` entry in `VERSIONS.md`
- [ ] New `VERSIONS.md` row at `1.0.0`

## Checks

- [ ] `npm run check` passes (lint, baseline, versions, trigger eval, adapter drift, tests)
- [ ] SkillSpector is clean, or each intentional example match has a narrow rule **with a reason** in `.skillspector-baseline.yaml`
- [ ] Tried on a real scenario, not just a synthetic one. What was it?
- [ ] No secrets, credentials, or proprietary data in examples
