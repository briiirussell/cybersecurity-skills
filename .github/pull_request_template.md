<!--
Adding a skill or changing one? Swap this body for the matching checklist:
  new skill:     add ?template=new-skill.md to the PR URL (or copy .github/PULL_REQUEST_TEMPLATE/new-skill.md)
  skill update:  ?template=skill-update.md
Everything else (tooling, docs, CI) can use this one.
-->

## What and why

Closes #

## Checklist

- [ ] Branched from `development`, PR targets `development`
- [ ] One version for this PR: repo version bumped in `.claude-plugin/plugin.json` and `marketplace.json`, with a `### X.Y.Z (date)` entry in `VERSIONS.md` (tooling or docs = PATCH)
- [ ] `npm run check` passes
- [ ] Tests added or updated in `scripts/test/` if a script, validator or the build changed
- [ ] No secrets, credentials, or proprietary data
