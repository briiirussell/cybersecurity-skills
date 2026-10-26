# patch-sweep

> Respond to a CVE wave across a whole portfolio of apps at once: inventory every repo and the platform project and domain it actually serves, find the real production branch, spot stale manual deploys, decide which apps are affected, mitigate, patch, ship, and confirm production. Use when the user mentions 'patch sweep,' 'patch all my apps,' 'fleet-wide CVE,' 'are any of my apps affected,' 'Next.js RCE across all projects,' 'Rails CVE on all our Heroku apps,' 'patch every repo,' 'CVE wave,' 'security release across the fleet,' 'which of our sites run the vulnerable version,' 'mass dependency update,' or has more than a handful of apps to patch against the same advisories.

# Patch Sweep — Fleet-Wide CVE Response

`dependency-audit` patches one project. This skill runs the response when a batch of advisories lands and you have 10, 40, or 100 apps across Vercel, Heroku, Render, Netlify, Fly, or Railway, split between a personal account, an agency org, and client repos.

Most of the real work in a sweep is outside `npm audit`: knowing which repo serves which domain, which branch production actually builds from, which production deploys no merge will ever replace, and which apps aren't affected at all. Get the map right first. Patching the wrong branch of the wrong repo is the most common way a sweep "finishes" with vulnerable code still live.

Cross-references:
- `dependency-audit` — the per-project audit and fix procedure (in-range fixes, pnpm/yarn traps, duplicate singletons, engines floor, runtime pins). This skill calls it once per affected app.
- `cloud-audit` "PaaS" section — platform posture: stale manual deploys, broken git deploys, legacy projects, preview exposure, repo security defaults.
- `scanner-pipeline` — run osv-scanner / trivy once per repo instead of separate per-package-manager audits, and keep it running weekly afterward.
- `finding-triage` — rank the leftovers that can't be patched in range.
- `security-comms` — client and stakeholder notices, especially for client repos you can only PR.
- `vuln-research` — when an advisory's affected range or code path is unclear.

## Authorization — confirm before touching anything

Ask the user, and write the answers at the top of the board:

1. **Which accounts are in scope?** List each GitHub owner/org and each platform team/account. Only repos and platform accounts the user controls are in scope for merges and deploys.
2. **Which repos belong to someone else?** Client repos, repos owned by another maintainer, and anything where the user is a collaborator rather than the owner. These get a **PR assigned to the owner, never a push or merge**, even if the user's token has write access.
3. **Who can approve an owner decision?** Stale manual deploys, legacy projects, and duplicate projects need someone to decide. Name that person per account.
4. **Is a production deploy allowed today?** Some clients have change windows or freeze periods.

Refuse to: push to or merge into a repo the user doesn't own without that owner's explicit approval in the user's own message; deploy to a platform account the user doesn't control; delete projects, domains, or deployments as part of the sweep (that's an owner decision, recorded as an action); disable deployment protection, branch protection, or CI checks to make a patch land faster.

The listed `allowed-tools` are read-only inventory commands. Every merge, `vercel deploy`, `git push`, `heroku config:set`, and `gh api -X PUT` prompts on purpose.

## Step 1 — Inventory and mapping

Build one row per **deployed app**, not per repo. A repo can feed several projects; a project can outlive its repo.

**Repos** (per owner/org; skip forks and archived repos):
```bash
gh repo list <owner> --limit 1000 --source --no-archived \
  --json nameWithOwner,defaultBranchRef,isPrivate,pushedAt,viewerPermission
```
`viewerPermission` tells you whether you're `ADMIN`, `WRITE`, or below. It does not tell you whether the repo is yours to merge into; ownership comes from the authorization step.

**Vercel** (per team; repeat with `--scope <team>`):
```bash
vercel project ls --format json --scope <team>
vercel project inspect <project> --scope <team>
vercel domains ls --scope <team>
vercel api /v9/projects/<project> --scope <team>           # link.org/repo, link.productionBranch, commandForIgnoringBuildStep
vercel api /v9/projects/<project>/domains --scope <team>   # every domain attached to the project, incl. *.vercel.app
```

**Heroku:**
```bash
heroku apps --all --json          # includes team apps
heroku domains -a <app>
heroku apps:info -a <app> --json  # stack, region, git url
```
Heroku doesn't record a "source repo" unless the GitHub integration or a pipeline is set up; check `heroku pipelines:info <pipeline>` or the dashboard's Deploy tab, and ask when it isn't there.

**Render** (API; token from the dashboard):
```bash
curl -s -H "Authorization: Bearer $RENDER_API_KEY" "https://api.render.com/v1/services?limit=100"
# per service: repo, branch, autoDeployTrigger, serviceDetails.runtime
curl -s -H "Authorization: Bearer $RENDER_API_KEY" "https://api.render.com/v1/services/<id>/custom-domains"
```

**Netlify / Fly / Railway:** `netlify sites:list --json`, `fly apps list` + `fly certs list -a <app>`, `railway list` / the dashboard. Same columns.

Flag these as you go; each is a row in the board with an owner action:

| Flag | How to spot it | Why it matters |
|---|---|---|
| **Legacy project still serving** | Project's only domains are `*.vercel.app` / `*.herokuapp.com` / `*.onrender.com`, and the custom domain now lives on another project or repo | Old, unpatched code is still reachable at a public URL. Patch, protect, or delete — owner's call |
| **No custom domain** | No domain other than the platform default | May not really be live. Confirm with the owner before spending a patch cycle on it; protect or delete if it's dead |
| **Duplicate project per repo** | Two projects (often in two teams) with the same `link.repo` | Both build on every push, both hold env vars and secrets; only one serves the domain. The other is attack surface |
| **Repo with no project** | Repo appears in `gh repo list` but in no platform listing | Might deploy somewhere you didn't list (Netlify, a VPS, a client's account). Ask |

Sources: `vercel project ls` and `vercel project inspect` per the [Vercel CLI docs](https://vercel.com/docs/cli/project); `vercel api` per [vercel.com/docs/cli/api](https://vercel.com/docs/cli/api); Render services API per [api-docs.render.com](https://api-docs.render.com/reference/list-services).

## Step 2 — Find the production branch for each project

Don't assume the default branch. Read it from the platform:

- **Vercel:** `link.productionBranch` from `vercel api /v9/projects/<project>`.
- **Render:** `branch` on the service.
- **Heroku:** the branch set for automatic deploys in the GitHub integration (dashboard → Deploy), or whatever CI pushes to `heroku main`. If production moves by `git push heroku`, the source of truth is whoever last pushed — see Step 3.
- **Monorepos:** also record the project's root directory (`rootDirectory` on Vercel, `rootDir` on Render). The deployed package is what you audit, not the repo root.

Cases that come up in real sweeps:
- `main` holds only a README while the app lives on `development`.
- The production branch is set to `development` on purpose, and `main` is stale.
- A client monorepo deploys from `cf-development` or another non-obvious branch.

Then confirm production actually matches that branch: compare the production deployment's commit with the branch HEAD.
```bash
vercel ls <project> --prod --scope <team>          # latest production deployments
vercel inspect <production-url> --scope <team>     # source, target, created
git ls-remote origin refs/heads/<prod-branch>      # branch HEAD sha
```

## Step 3 — Detect stale and manual deploys

A merge only fixes production if production is built from git. Check each project:

- **Manual production deploy.** The current production deployment came from the CLI (`source: "cli"` on Vercel's deployments API: `vercel api "/v6/deployments?projectId=<id>&target=production&limit=5"`), not from git. A 96-day-old `vercel deploy --prod` from someone else's laptop will not change when you merge. On Heroku, `heroku releases -a <app>` shows who deployed and how; a release that isn't from the GitHub integration or your CI is the equivalent.
- **Git deploys that always fail.** Look at the last 10–20 git-triggered deployments. If they're all `ERROR`, production has only been moving through manual deploys. Typical causes: an Ignored Build Step that runs `git diff HEAD^ HEAD` while `.vercelignore` excludes `.git` (`.vercelignore` applies to git builds too), or a project still git-linked to the repo's old org.
- **Production commit not on the production branch.** The deployed sha isn't reachable from the branch: someone deployed a local branch.

Each of these is an **owner decision, not a merge**. Record the options in the board's owner-action column: redeploy from git after fixing the build, adopt the manual deploy's code into the branch, or retire the project. Don't run `vercel deploy --prod` over someone else's manual deploy to "fix" it — you'd be replacing code you haven't seen with code they haven't approved.

## Step 4 — Is each app affected?

An app is affected only if all three line up: **vulnerable runtime or dependency version + the vulnerable component is present + the vulnerable code path is used.** Write down which of the three rules it out when an app is not affected.

**Runtime versions — read every file that pins them.** They often disagree; the one the platform actually uses wins.

| Runtime | Pin locations |
|---|---|
| Ruby | `.ruby-version`, Gemfile `ruby` line, `Gemfile.lock` `RUBY VERSION`, Dockerfile `ARG RUBY_VERSION`, CI image, buildpack / stack |
| Node | `.nvmrc`, `.node-version`, `package.json` `engines.node`, Dockerfile `FROM node:`, CI `node-version`, platform setting (Vercel project Node.js version, Heroku `engines`) |
| Python | `.python-version`, `runtime.txt`, `pyproject.toml` `requires-python`, Dockerfile, CI |
| PHP | `composer.json` `require.php`, Dockerfile, platform runtime setting |

**Dependency versions:** read the lockfile on the production branch, not `package.json` ranges. One `osv-scanner scan source -r .` covers npm, pnpm, yarn, Bundler, pip, and Composer lockfiles in a single pass (see `scanner-pipeline`).

**Special cases:**
- **EOL lines get no fix.** Ruby 3.2, Next.js 13/14 for the 2026 RCEs, any Node major past end-of-life. These go straight to "needs a major-version upgrade" with an effort estimate; don't list them beside in-range fixes.
- **Managed runtimes that patch themselves.** Vercel applies Node patch releases to its managed runtime; Heroku and Render images get OS-level updates on rebuild. An advisory in the runtime may need only a redeploy or no action. Confirm what the platform's docs or changelog say for that release before marking it.
- **Code path not used.** A static Vite or Astro site isn't affected by Next.js server advisories. An app without libvips (no Active Storage variants, no `image_processing` with vips) isn't affected by a libvips RCE. A Next.js app with no Server Actions or middleware may sit outside a specific advisory's preconditions — read the advisory's exact conditions (`vuln-research`).

Mark each row `affected` / `not affected (reason)` / `unknown (what's needed)`. Unknown rows don't get skipped; they get an owner action.

## Step 5 — Mitigate before patching

Patching 40 apps takes days. A platform or env-level compensating control can take minutes. Look for one per advisory and apply it first, on apps the user controls:

- **Env-var kill switch.** Example: `VIPS_BLOCK_UNTRUSTED=1` blocks libvips' untrusted loaders for the Active Storage + libvips RCE. It needs libvips ≥ 8.13; check the stack image (Heroku-24 ships 8.15.1; `heroku run --no-tty "vips --version" -a <app>` to confirm). Setting a config var restarts dynos — say so before running it.
- **WAF / firewall rule** at the platform or CDN that blocks the exploit's request shape (Vercel Firewall custom rule, Cloudflare WAF managed rule for the CVE).
- **Turn off the vulnerable feature** behind a flag until the patch ships.
- **Deployment protection** on legacy or preview URLs that would otherwise serve vulnerable code publicly.

Record mitigations with disposition `Mitigated (platform/config)` on the board. A mitigation doesn't close the row — the patch still ships — but it changes how urgent the remaining rows are.

## Step 6 — Patch procedure per app

For each affected app the user owns. For other owners' repos, do the same up to the PR, then stop (Step 7).

1. **Hotfix branch from the production branch** (from Step 2), not from the default branch: `git switch -c hotfix/<cve-or-date> origin/<prod-branch>`.
2. **In-range fixes only.** Use `dependency-audit` Step 2's procedure. Anything that needs a major bump goes to its own PR and the "needs a major-version upgrade" section. Never `npm audit fix --force` in a sweep.
3. **Move every runtime pin together** when the fix is a runtime bump (the table in Step 4). Missing one file means the deploy keeps the vulnerable runtime.
4. **Run lint, typecheck, and build** locally or in CI. Then `dependency-audit`'s verify-after-fixing checks (duplicate singletons, engines floor, clean `npm ci` / `--frozen-lockfile`).
5. **Verify the preview:** the deployment reaches Ready (`vercel inspect <preview-url> --wait`), and key routes return 200 (`curl -s -o /dev/null -w '%{http_code}\n' <preview-url>/<route>` for the homepage, login, and one route that exercises the patched package). If deployment protection is on, use a protection bypass the owner set up rather than turning protection off.
6. **Merge** the PR into the production branch.
7. **Confirm production:** the new production deployment's commit is the merge commit, it's Ready, and the custom domain (not just the `*.vercel.app` URL) returns 200.
8. **Sync back.** Merge the production branch into `development` (or whatever the integration branch is) so the next release doesn't regress the patch.
9. **If the sync conflicts with unrelated work** on `development`, don't resolve someone else's feature conflicts. Cherry-pick just the patch commits onto `development` instead: `git cherry-pick <patch-sha>...`.

Re-run the scanner from Step 4 against the merged branch and record crit/high before → after.

## Step 7 — Delegation and parallelism

- **Batch about 6 repos per agent.** Give each agent the board rows for its repos (prod branch, platform project, affected advisories, owner rules) so it doesn't redo Steps 1–4. Agents report back in board-row format.
- **Watch the build queue.** A team with one concurrent build serializes every preview; on one Vercel team, previews waited 30–60 minutes. Stagger pushes by team, prioritize internet-facing and highest-severity apps first, and tell the user if an on-demand concurrency increase would help. Don't use CLI production deploys to skip the queue unless the owner chooses that path.
- **Client repos and other maintainers' repos get a PR, not a merge.** Open it against their production branch, assign or request review from the owner, link the advisory, and list what you verified on the preview. Record "PR open, awaiting <owner>" on the board. `security-comms` drafts the notice that goes with it.
- **One owner at a time per repo.** Don't let two agents touch the same repo; the second one's lockfile changes will conflict.

## Step 8 — Prevention

Before closing the sweep, turn on the controls that would have made the next one smaller, on repos the user owns:

```bash
# Dependabot alerts: 204 = on, 404 = off
gh api repos/<owner>/<repo>/vulnerability-alerts --silent && echo on || echo off
# enable (prompts; one repo at a time or in a reviewed loop)
gh api -X PUT repos/<owner>/<repo>/vulnerability-alerts
# secret scanning / push protection status
gh api repos/<owner>/<repo> --jq '.security_and_analysis'
```

Run it over every non-fork, non-archived repo from Step 1. In one real account and org, 142 repos had alerts off. Also:
- Schedule `scanner-pipeline`'s weekly scan on every production repo.
- Fix or retire every stale manual deploy and legacy project found in Step 3 (`cloud-audit` PaaS).
- Write down each project's production branch in its README so the next sweep starts at Step 4.

## Output Format

```markdown
# Patch Sweep — [advisory set] — [date]

**Scope:** [GitHub owners/orgs] · [platform teams/accounts] · **Owner-only repos (PR, no merge):** [list]
**Advisories:** [CVE / GHSA ids, fixed versions]
**Mitigations applied:** [e.g., VIPS_BLOCK_UNTRUSTED=1 on 5 Heroku apps, 2026-10-22]

## Status board

| repo | platform/project | domain | prod branch | runtime/framework old→new | crit/high before→after | merged? | prod 200? | leftover (needs major) | owner action |
|---|---|---|---|---|---|---|---|---|---|
| acme/site | vercel/acme-site | acme.com | development | next 15.5.10→15.5.24 | 2/3→0/0 | yes | yes | — | — |
| client/app | vercel/client-app | client.com | cf-development | next 14.2.3→14.2.3 | 1/2→1/0 | PR #41 | — | next 14→15.5.24 | client to review PR, schedule Next 15 upgrade |
| acme/old-site | vercel/acme-old | acme-old.vercel.app | main | next 13.4→— | 3/4→3/4 | no | — | next 13→16 | legacy project, no custom domain: owner to delete or protect |

## Not shipped, and why
- [repo] — [manual prod deploy by X, 96 days old; owner decision needed] / [git deploys failing: Ignored Build Step + .vercelignore] / [client PR awaiting review] / [build queue] / [not affected: static site]

## Needs a major-version upgrade
- [repo] — [Next 13 → 15.5.24+ / 16.4.3; Ruby 3.2 → 3.3.13+] — est. effort [S/M/L] — disposition `Requires major migration` — mitigation in place: [yes/no]

## Prevention
- Dependabot alerts enabled on [N] repos ([M] were off)
- Weekly scanner-pipeline scheduled on [N] repos
```

Dispositions on the board use the shared set: `Fixed`, `Deferred`, `Accepted Risk`, `Mitigated (platform/config)`, `Requires major migration`, plus `False Positive` for "not affected" rows where a scanner claimed otherwise.

## Boundaries

- Only repos and platform accounts the user controls get merges and deploys. Everything else is a PR with the owner assigned.
- Never overwrite another person's manual production deploy, delete a project or domain, or disable a protection to finish the sweep. Record the owner action instead.
- No major-version upgrades inside the sweep; they get their own PR.
- Never print secret values from env vars or config vars while inventorying. List keys, not values.
- Don't probe domains to decide whether they're live beyond a plain GET of the user's own URLs. No scanning of hosts the user doesn't own.

## References

- Vercel CLI: [`vercel list`](https://vercel.com/docs/cli/list), [`vercel inspect`](https://vercel.com/docs/cli/inspect), [`vercel project`](https://vercel.com/docs/cli/project), [`vercel api`](https://vercel.com/docs/cli/api)
- [Render API — list services](https://api-docs.render.com/reference/list-services)
- [GitHub REST — vulnerability alerts](https://docs.github.com/en/rest/repos/repos#check-if-vulnerability-alerts-are-enabled-for-a-repository)
- Field source: a ~45-app sweep, October 2026 (5 Heroku Rails apps, 1 Render app, ~39 Vercel Next.js apps), issue #80