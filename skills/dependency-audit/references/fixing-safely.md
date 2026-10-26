# Fixing Safely — Package-Manager, Runtime, and Framework Traps

Companion to `dependency-audit` Steps 2–3. Every trap below was hit in a real multi-app CVE sweep (Rails on Heroku, Next.js on Vercel with npm, pnpm, and yarn v1). Several of them passed `npm audit`, lint, and the build, and only broke at runtime. Read this before you push a patch PR.

## 1. Use the audit command that matches the lockfile

| Lockfile | Audit command | Notes |
|---|---|---|
| `package-lock.json` | `npm audit --omit=dev --json` | Compare with and without `--omit=dev` |
| `pnpm-lock.yaml` | `pnpm audit --prod --json` | Use the pnpm major that matches `lockfileVersion` / `packageManager` (run via `corepack`) |
| `yarn.lock` (v1) | `yarn audit --groups dependencies --json` | v1 output is NDJSON, one advisory per line |
| `yarn.lock` (Berry, v2+) | `yarn npm audit --environment production --recursive --json` | `--recursive` includes transitives |
| `bun.lock` / `bun.lockb` | `bun audit` (recent bun) or audit an exported npm lockfile | |

`npm audit` in a pnpm or yarn repo has no `package-lock.json` to read. Depending on the npm version it either errors out or reports on a tree it resolved itself, which is not what ships. Neither result is an audit. Check `packageManager` in `package.json` and which lockfile is committed before running anything.

## 2. `pnpm audit --fix` writes open-ended `>=` overrides

`pnpm audit --fix` adds an override per advisory in the form `pkg@<patched: >=patched` to `pnpm-workspace.yaml` (pnpm 10+) or `package.json` `pnpm.overrides`. An open `>=` lets the resolver pick the newest major. In practice that meant dozens of overrides forcing nanoid 3→5, zod 3→4, and deepmerge-ts 7→8 onto parents that were never tested against them.

After `--fix`:

```bash
# List the overrides it wrote
grep -nE '>=' pnpm-workspace.yaml package.json
```

- Rewrite each override to a same-major range: `nanoid@<3.3.8: ^3.3.8`, not `>=3.3.8`.
- Better, where possible: drop the override and update the vulnerable package within its declared range (`pnpm update <pkg>` / `pnpm update -r <pkg>`).
- Keep the overrides that remain few and commented with the advisory ID, so someone can remove them later.

The same applies to npm `overrides` and yarn `resolutions` that you write by hand. Pin to the patched release line, not "anything newer".

## 3. In-range re-resolves can duplicate singleton packages

Some packages have to be loaded exactly once per process or bundle. If a re-resolve moves one consumer to a new patch of a singleton while another consumer stays on the old one, you get two copies. Install, lint, type-check, and build all still pass. The failure shows up at runtime. Example: `prosemirror-view` moved to `prosemirror-model@1.25.12` while TipTap stayed on `1.25.4`, and typing in the editor threw `RangeError: ... multiple versions of prosemirror-model were loaded`.

Packages to check (not exhaustive): `react`, `react-dom`, `prosemirror-model`, `prosemirror-state`, `prosemirror-view`, `prosemirror-transform`, `@tiptap/pm`, `yjs`, `graphql`, `styled-components`, `@emotion/react`, `@emotion/styled`, `@emotion/cache`, `@apollo/client`, `zod` when schemas cross package boundaries, and any package that uses `instanceof` checks or a module-level registry.

```bash
npm ls <pkg> --all          # npm: more than one version line = duplicate
pnpm why <pkg> -r           # pnpm
yarn why <pkg>              # yarn v1 and Berry

# Quick sweep of the usual suspects
for p in react react-dom prosemirror-model prosemirror-view @tiptap/pm yjs graphql styled-components @emotion/react; do
  echo "== $p"; npm ls "$p" --all 2>/dev/null | grep -oE "$p@[0-9][^ ]*" | sort -u
done
```

Fix by deduplicating (`npm dedupe`, `pnpm dedupe`, `yarn-deduplicate` for v1), by updating every consumer together, or with a same-major override that forces one version.

## 4. Exact pins in intermediate packages block the fix

When `audit fix` can't move a transitive package, find out why before reporting "no fix available". Usually an intermediate package pins it exactly (`"zod": "3.22.4"`, not `^3.22.4`).

```bash
npm ls <vuln-pkg> --all               # read the chain from root to the vulnerable copy
npm view <parent>@<ver> dependencies  # look for exact versions with no ^ or ~
pnpm why <vuln-pkg> -r
yarn why <vuln-pkg>
```

Examples from the sweep: `@vercel/blob` → `@vercel/cli-config` pinning `zod` exactly; a UI kit pinning vulnerable copies of `npm`, `undici`, and `zod@3`, where `--force` would have swapped in a breaking 0.x release of the kit.

Report it as: **"Blocked by exact pin in `<parent>@<ver>`"**, then recommend one of:
- a **scoped** override that only applies under that parent: npm `"overrides": { "<parent>": { "<vuln-pkg>": "^x.y.z" } }`, pnpm `"<parent>><vuln-pkg>": "^x.y.z"`, yarn `"resolutions": { "<parent>/<vuln-pkg>": "^x.y.z" }`. Test the parent's features afterward.
- an upstream issue or PR against the parent, linked in the report.
- reachability analysis (SKILL.md Step 2) if neither is acceptable yet.

## 5. Fixes can raise the Node `engines` floor

A patched transitive can require a newer Node than the repo runs. Example: `eslint-visitor-keys@5` needs `^22.13`, while `.nvmrc` said `22.11`. yarn v1 hard-fails the install on an engines mismatch. npm and pnpm warn by default, and fail only with `engine-strict`.

```bash
# What the repo says it runs
cat .nvmrc .node-version 2>/dev/null; node -e 'console.log(require("./package.json").engines)'

# Highest engines.node requirements in the installed tree (npm lockfile v2/v3)
node -e 'const l=require("./package-lock.json").packages;for(const[k,v]of Object.entries(l))if(v.engines&&v.engines.node)console.log(v.engines.node.padEnd(24),k)' | sort -V | tail -20
# pnpm-lock.yaml records engines per package: grep -nA1 "engines:" pnpm-lock.yaml. yarn v1 does not, so check the install output.
```

If the new floor is above the deployed runtime, either bump the runtime (and move every pin, see §6) or pick a fix version that doesn't raise the floor.

## 6. Runtime upgrades have to move every pin together

A runtime bump that misses one pin keeps the vulnerable runtime running in that environment, often production. Grep for all of them in one pass:

**Ruby:**
- `.ruby-version`, `.tool-versions`
- `Gemfile` `ruby "x.y.z"`
- `Gemfile.lock` `RUBY VERSION` section (run `bundle update --ruby` or re-lock)
- `Dockerfile` `ARG RUBY_VERSION` / `FROM ruby:x.y`
- CI image or `ruby/setup-ruby` `ruby-version:`
- Buildpack / stack (Heroku stack, `app.json`, `project.toml`)

**Node:**
- `.nvmrc`, `.node-version`, `.tool-versions`
- `package.json` `engines.node` and `packageManager`
- `Dockerfile` `FROM node:x`
- CI `actions/setup-node` `node-version:`
- Platform setting (Vercel project Node version, Heroku `engines`, Netlify `NODE_VERSION`). Platform settings are not in the repo, so mark them `needs_validation` with the console or CLI command to check.

```bash
grep -rnE "ruby[-_ ]?version|^ruby |RUBY VERSION|FROM ruby:|node[-_ ]?version|FROM node:|\"node\":|nvmrc" \
  --include="*" -I . 2>/dev/null | grep -vE "node_modules|vendor/|\.git/" | head -50
```

## 7. Ruby gotchas

- **`bundle update --conservative <gem>` can still jump a shared dependency a major version.** In the sweep, `json` went 2→3, which dropped `quirks_mode`. `httparty` still passes it, so the app broke at runtime. Check `git diff Gemfile.lock` for any major change you didn't ask for, and constrain it (`gem "json", "~> 2.21"`).
- **Pin without a permanent Gemfile change:** tighten the constraint in the Gemfile, run `bundle lock` / `bundle update <gem> --conservative`, then restore the original constraint. Bundler keeps the locked version as long as it still satisfies the Gemfile. Commit only the `Gemfile.lock` change.
- **Brakeman fails CI when it isn't the latest release** (its version check). Expect a red CI on the patch PR and bump Brakeman in the same PR rather than treating it as a regression.
- **Patch-level Rails releases can break specs.** One Rails 8.1 patch release changed how `column_exists?` compares boolean defaults and broke a migration spec. Run the full suite on every framework bump, including patch releases, and read the release notes before calling a failure unrelated.
- Run `bundle audit update && bundle audit check` (the advisory DB goes stale) and `bundle exec rails about` to confirm the version actually loaded.

## 8. When no in-place fix exists

Some advisories have no fix on the release line you're on:
- the framework line is out of support (for example, older Next.js majors that get no backports for a critical RCE, where the fix exists only on the current majors)
- the runtime line is EOL (for example, a Ruby minor that no longer receives security fixes)

Don't list these next to in-range fixes as if they were one command away. Give the confirmed finding the disposition **`Requires major migration`** with:
- the minimum fixed version on each supported line
- an effort estimate (S / M / L, plus the main breaking changes from the upgrade guide)
- interim compensating controls (WAF rule, feature disabled, route blocked), if any
- a target date and owner

## 9. Platform and config mitigations as compensating controls

Sometimes the right response is a platform or config change, not a package change. Give it the disposition **`Mitigated (platform/config)`** and record what makes the mitigation real:
- **Config flags with version prerequisites.** For example, libvips' `VIPS_BLOCK_UNTRUSTED=1` blocks the untrusted loaders that several image-processing advisories go through, but it only exists in libvips ≥ 8.13. Confirm the runtime's libvips version (for example `vips --version`, or the platform stack's package list) before you count it. A flag on a version that ignores it mitigates nothing.
- **Managed runtimes that patch themselves.** Some PaaS platforms roll Node or other runtime patch releases on their own (Vercel's managed Node, for example). An advisory against the runtime may need no repo change. Confirm the platform's current runtime version and changelog, and record it as `needs_validation` until you have.
- **Feature disabled or route unreachable** in production config (the vulnerable loader or endpoint is turned off).

Every mitigation needs: the control, where it's set (file, env var, or platform setting), the version prerequisite, and how to verify it in the deployed environment. Re-evaluate when the mitigation changes (stack upgrade, env var removed). See `cloud-audit` "PaaS" for platform-specific checks.

## 10. Audit the branch that's actually deployed

Before auditing, confirm what ships:
- the production branch (Vercel/Netlify production branch, Heroku pipeline, the branch the deploy workflow triggers on). In the sweep, one repo's `main` held only a README and production deployed from another branch.
- for monorepos, which package or app is deployed, and its own lockfile or workspace slice
- the commit currently in production (platform deploy history), when it differs from the branch head

```bash
git branch -r --sort=-committerdate | head
grep -rnE "branches:|on:\s*push" .github/workflows/*.y*ml 2>/dev/null
cat vercel.json netlify.toml app.json Procfile 2>/dev/null | head -50
```

If you can't confirm the deployed branch from the repo, mark it `needs_validation` and say which branch you audited. For fleet-wide patching across many repos, see `patch-sweep`.

## Verify after fixing

Run this before calling a patch PR done. Each item caught a real breakage in the sweep.

- [ ] **Advisory resolved:** re-run the matching audit command (§1) and confirm the advisory is gone, not suppressed.
- [ ] **No downgrades or surprise majors:** `git diff` the lockfile and scan for major-version changes you didn't intend (`--force`, `>=` overrides, `--conservative` jumps).
- [ ] **No duplicate singletons:** `npm ls` / `pnpm why` / `yarn why` for the packages in §3.
- [ ] **Engines floor still met:** new lockfile entries' `engines.node` vs `.nvmrc` / `.node-version` / `engines` / platform setting (§5).
- [ ] **Clean frozen install:** delete `node_modules` and run `npm ci`, `pnpm install --frozen-lockfile`, `yarn install --frozen-lockfile` (v1), or `yarn install --immutable` (Berry). For Ruby, `bundle install` with `BUNDLE_FROZEN=true`.
- [ ] **Runtime pins consistent** if the runtime moved (§6).
- [ ] **Full test suite**, not only build and lint. For framework bumps, read the release notes for behaviour changes (§7).
- [ ] **Preview smoke test** of the features the changed packages power: the editor for prosemirror/TipTap/yjs, image upload for sharp/libvips, auth for auth libraries, GraphQL queries for graphql/apollo. Watch the browser console and server logs, not only the page render.
- [ ] **Overrides documented:** every remaining override or resolution has a comment or tracking issue naming the advisory, so it can be removed later.
