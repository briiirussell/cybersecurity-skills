## Skill update: `skill-name`

What changed, and what prompted it (field report, framework update, false positive, ...).

Closes #

## Change

- [ ] One skill per PR. Other skills are touched only for cross-reference back-links (PATCH bumps on their rows)
- [ ] Still has its `## Authorization` section, still under 500 lines, and links resolve
- [ ] `allowed-tools` changes, if any, stay read-only and scoped. Say why each new grant can't write or destroy anything
- [ ] Shared content edited in `shared/`, not in a `skills/*/references/` copy
- [ ] If the `description` changed: `node scripts/eval-triggers.mjs --verbose` shows it didn't start stealing another skill's prompts, and `evals/triggers/<skill>.json` is updated for any new triggers

## Versions

- [ ] Skill row bumped in `VERSIONS.md`: fix or cross-reference = PATCH, improvement = MINOR
- [ ] Repo version bumped to match (skill improvement = repo MINOR, fix = repo PATCH), with a `### X.Y.Z (date)` entry

## Checks

- [ ] `node scripts/build-adapters.mjs` run and the result committed
- [ ] `npm run check` passes
- [ ] SkillSpector is clean, or new intentional matches have a narrow baseline rule with a reason
- [ ] Tried on a real scenario. What was it?
