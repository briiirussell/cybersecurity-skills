# PaaS checks — Render, Netlify, Fly, Railway

Companion to the "PaaS (Vercel / Netlify / Heroku / Render / Railway / Fly)" section of `cloud-audit`. Same eight checks; these are the per-platform commands for the platforms not spelled out there. All read-only. Never print env var values — list names.

CLI flags drift between versions. Run `<cli> <command> --help` once before scripting against it.

Save the output that backs a finding to `<audit dir>/evidence/<platform>-<command>-<app>.json` (pretty-printed, values redacted) and point the record's `location` and `evidence[]` at that file and line, as in `cloud-audit`'s "Verify, then record" step. Fingerprints use the platform as the provider: `cloud-audit/manual-prod-deploy/render/<team>/<service>`.

## Render (REST API)

Create an API key in the dashboard (Account Settings → API Keys) and keep it in an env var.

```bash
H="Authorization: Bearer $RENDER_API_KEY"
# Inventory: repo, branch, autoDeployTrigger, runtime, suspended
curl -s -H "$H" "https://api.render.com/v1/services?limit=100" \
  | jq '.[].service | {id, name, type, repo, branch, autoDeployTrigger, rootDir, runtime: .serviceDetails.runtime, suspended}'
# Checks 1, 2: how production got there, and whether git deploys fail
curl -s -H "$H" "https://api.render.com/v1/services/<id>/deploys?limit=20" \
  | jq '.[].deploy | {status, trigger, commit: .commit.id, createdAt}'
# Check 3: custom domains per service
curl -s -H "$H" "https://api.render.com/v1/services/<id>/custom-domains"
# env var names only
curl -s -H "$H" "https://api.render.com/v1/services/<id>/env-vars" | jq -r '.[].envVar.key'
```
- `trigger: "manual"` or `"api"` on the live deploy, with `autoDeployTrigger: "off"`, is the Render form of a manual production deploy. Compare `commit.id` with the branch HEAD.
- A run of `build_failed` with `trigger: "new_commit"` means git deploys are broken.
- `autoDeploy` is deprecated in favor of `autoDeployTrigger` (`commit`, `checksPass`, `off`).

## Netlify

```bash
netlify sites:list --json | jq '.[] | {id, name, url, custom_domain, repo: .build_settings.repo_url, branch: .build_settings.repo_branch}'
netlify api listSiteDeploys --data '{"site_id": "<id>"}' \
  | jq '.[] | {state, context, branch, commit_ref, created_at, manual_deploy}' | head -60
netlify env:list --json | jq -r 'keys[]'      # inside a linked site dir; names only
```
- Check 1: the published deploy has `manual_deploy: true`, or its `commit_ref` isn't the branch HEAD.
- Check 3: sites with no `custom_domain` that still serve `*.netlify.app`.
- Check 5: deploy-preview and branch-deploy contexts in `netlify.toml` that inherit production env vars; site protection (password / team login) on previews.

## Fly.io

```bash
fly apps list
fly releases -a <app>              # version, status, user, date; image ref
fly status -a <app>                # image, machines, region
fly certs list -a <app>            # custom domains; none = only <app>.fly.dev
fly secrets list -a <app>          # names and digests, not values
```
- Fly deploys from the CLI by default (`fly deploy`), so "manual deploy" is normal. The check is whether the deployed image was built from the production branch: look for a CI workflow that runs `fly deploy` on that branch, and compare the release's image label or build time with the last merge.

## Railway

```bash
railway list          # projects you can see
railway status        # linked project, environment, service
railway variables     # prints VALUES — use the dashboard to list names instead; never save this output to evidence
```
- The service's Settings → Source shows repo, branch, and "Wait for CI"; Deployments shows each deploy's trigger and commit. Railway's public API is GraphQL (`https://backboard.railway.com/graphql/v2`) if you need to script it.
- Check 3: services with only a `*.up.railway.app` domain.

## Repo defaults (all platforms)

Same as check 8 in the main section: `gh api repos/<o>/<r>/vulnerability-alerts`, `gh api repos/<o>/<r> --jq .security_and_analysis`, branch protection or rulesets on the production branch.
