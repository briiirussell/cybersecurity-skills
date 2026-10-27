# CI/CD check catalog

Companion to `cicd-security` Step 4. For each class: what to grep, when it's a finding, the shapes that are safe, and
the fix. Greps assume GitHub Actions and the repo root as the working directory. `rg` first, then a portable
`grep -E` (macOS grep has no `-P`). In the markdown tables, `\|` is escaping; type a plain `|` in the shell.

```bash
WF=.github/workflows
```

A grep hit is a candidate. Close it with the trace in SKILL.md Step 6: who triggers it, what carries the input, what
the sink holds.

## Contents

- [Attacker-controlled contexts](#attacker-controlled-contexts)
- [1. pwn-request](#1-pwn-request) · [2. script-injection](#2-script-injection) · [3. excessive-permissions](#3-excessive-permissions)
- [4. unpinned-action](#4-unpinned-action) · [5. oidc-trust](#5-oidc-trust) · [6. self-hosted-runner](#6-self-hosted-runner)
- [7. fork-secrets](#7-fork-secrets) · [8. cache-poisoning](#8-cache-poisoning) · [9. artifact-trust](#9-artifact-trust)
- [10. comment-command](#10-comment-command) · [11. unprotected-publish](#11-unprotected-publish)
- [zizmor audit map](#zizmor-audit-map) · [Platform facts](#platform-facts) · [Safe shapes](#safe-shapes-do-not-raise)

## Attacker-controlled contexts

Text an outsider can set, on the triggers they can reach. Expanding any of these with `${{ }}` into a script is
injection.

| Context | Set by |
|---|---|
| `github.event.issue.title`, `.issue.body` | Anyone who opens an issue |
| `github.event.pull_request.title`, `.body`, `.head.ref`, `.head.label`, `.head.repo.default_branch` | Fork PR author |
| `github.head_ref` | Fork PR author (branch names can hold `$(…)`, backticks and `;`) |
| `github.event.comment.body`, `.review.body`, `.review_comment.body` | Anyone who can comment |
| `github.event.discussion.title`, `.body` | Anyone who can open a discussion |
| `github.event.head_commit.message`, `.author.name`, `.author.email`; `github.event.commits.*.message`, `.author.*` | Commit author (fork, or anyone whose commit gets pushed) |
| `github.event.pages.*.page_name` | Wiki editors |
| `github.event.workflow_run.head_branch`, `.head_commit.message`, `.head_commit.author.*`, `.display_title` | Whoever triggered the upstream run |
| `steps.*.outputs.*`, `needs.*.outputs.*`, `env.*` | Whatever filled them: trace back |
| `inputs.*` on `workflow_dispatch` | Users with write access: usually not an outsider path |

Not attacker text: `github.event.pull_request.number`, `.id`, SHAs, `github.repository`, `github.repository_owner`,
`secrets.*`, `github.run_id`.

## 1. pwn-request

`pull_request_target` and `workflow_run` run in the base repository with secrets and the base token. The problem is
what they then run.

```bash
rg -l 'pull_request_target|workflow_run' $WF | xargs rg -n -A4 'actions/checkout'
rg -n 'ref:\s*\$\{\{\s*(github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref|github\.event\.workflow_run\.head_(sha|branch))|refs/pull/' $WF
# portable
grep -lE 'pull_request_target|workflow_run' $WF/*.y*ml | xargs grep -nE -A4 'actions/checkout'
grep -rnE 'ref:[[:space:]]*\$\{\{[[:space:]]*(github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref|github\.event\.workflow_run\.head_(sha|branch))|refs/pull/' $WF
```

Also catch checkouts done by hand: `git fetch origin pull/…/head`, `gh pr checkout`, `git checkout ${{ … }}`.

**Finding when** code from the checked-out PR runs in a job that holds a write scope, a secret, OIDC, or a persistent
runner. Execution includes: build and test commands, package installs (`npm install`/`ci`, `pip install .`, `bundle
install` with a PR Gemfile), `make`, scripts in the tree, `uses: ./…` local actions, pre-commit hooks, linters that
load PR config files that run code (`eslint.config.js`, `conftest.py`), and an AI agent that loads PR-controlled
`CLAUDE.md`/settings (see `ai-agents-in-ci.md`).

**Not a finding:** a checkout into a subdirectory that nothing executes (read as data, e.g. diffed or linted with
pinned tools and config from the base branch); `pull_request_target` used only for labeling or commenting with
nothing from the PR evaluated.

**Fix:** move the untrusted work to `pull_request` (read-only, no secrets); if privileged follow-up is needed, a
separate `workflow_run` workflow that treats the first run's output as data (section 9). Label gating ("safe to
test") is a stopgap: a new push after the label lands runs unreviewed code; gate on the reviewed SHA if it must stay.

Note the 2025-12-08 change: `pull_request_target` now always runs the default branch's workflow file. A vulnerable
workflow left on a release branch no longer runs; one on the default branch still does.

## 2. script-injection

```bash
rg -n '\$\{\{\s*(github\.head_ref|github\.event\.(issue|pull_request|comment|review|review_comment|discussion|head_commit|commits|pages|workflow_run)\b[^}]*)\}\}' $WF .github/actions
# portable
grep -rnE '\$\{\{[[:space:]]*(github\.head_ref|github\.event\.(issue|pull_request|comment|review|review_comment|discussion|head_commit|commits|pages|workflow_run)[.[])' $WF .github/actions
```

Then read each hit's context. It's a sink when the expression sits in:

- a `run:` block (any shell, including `pwsh` and `python` via `shell:`);
- `actions/github-script`'s `script:` input (evaluated as JavaScript);
- a composite action's `run:` that receives it as an input (`${{ inputs.title }}`): trace the caller;
- a line that writes to `$GITHUB_ENV`, `$GITHUB_PATH` or `$GITHUB_OUTPUT`, which lets the value set `LD_PRELOAD`,
  `NODE_OPTIONS`, `BASH_ENV` or `PATH` for every later step (zizmor `github-env`).

Not a sink: `if:` conditions, most `with:` inputs (passed as strings, unless the action itself evals them), job-level
`env:` values that are then used quoted.

**Finding when** the trigger is reachable by an outsider (section "Attacker-controlled contexts") and the job holds
anything. `workflow_dispatch` inputs and `push`-only workflows on protected branches need write access: hardening note.

**Fix:**

```yaml
- env:
    TITLE: ${{ github.event.issue.title }}
  run: echo "Title: $TITLE"     # quoted variable, no ${{ }} in the script
```

## 3. excessive-permissions

```bash
for f in $WF/*.y*ml; do grep -qE '^permissions:' "$f" || echo "no top-level permissions: $f"; done
rg -n 'permissions:\s*write-all|^\s+(contents|packages|actions|id-token|pull-requests|issues|deployments|attestations|security-events|statuses|checks):\s*write' $WF
rg -n -B2 -A3 'actions/checkout' $WF | rg -n 'persist-credentials'
# portable
grep -nE 'permissions:[[:space:]]*write-all|^[[:space:]]+(contents|packages|actions|id-token|pull-requests|issues|deployments|attestations|security-events|statuses|checks):[[:space:]]*write' $WF/*.y*ml
```

A job's effective scopes: its own `permissions:`, else the workflow's, else the repo/org default
(`default_workflow_permissions`, a platform fact). Write scopes that matter most: `contents` (push code, create
releases, move tags), `actions` (edit or re-run workflows, caches), `packages`, `id-token`, `pull-requests` with
`can_approve_pull_request_reviews` on (the token can approve PRs).

**Finding when** a lower-trust actor reaches a step that can use the scope (sections 1, 2, 10, 12). Missing least
privilege without that path is a hardening note: recommend `permissions: {}` or `contents: read` at the top and
per-job grants.

`actions/checkout` stores the token in `.git/config` unless `persist-credentials: false`. That matters when a later
step uploads the workspace as an artifact (zizmor `artipacked`) or runs PR code.

## 4. unpinned-action

```bash
rg -n 'uses:\s*[^.\s#][^@\s]*@' $WF .github/actions | rg -v '@[0-9a-f]{40}(\s|$)'
rg -n 'uses:\s*docker://' $WF .github/actions | rg -v '@sha256:'
# portable
grep -rnE 'uses:[[:space:]]*[^.[:space:]#][^@[:space:]]*@' $WF .github/actions | grep -vE '@[0-9a-f]{40}([[:space:]]|$)'
```

Separate first-party (`actions/*`, `github/*`), the org's own actions, and third-party. A 40-hex SHA with a version
comment (`@<sha> # v4.2.2`) is the target shape; Dependabot and Renovate keep it updated.

**Finding when** a third-party tag or branch ref runs in a job that holds secrets, a write scope, OIDC, or publish
rights. Rate likelihood on the upstream: a single-maintainer action with broad adoption is a known target
(tj-actions/changed-files, CVE-2025-30066, March 2025). In a read-only job with no secrets it's a hardening note.

Also check, with the online zizmor run: `impostor-commit` (the SHA exists only in a fork network, so it isn't the
upstream's code), `ref-confusion` (a tag and branch share a name), `known-vulnerable-actions`, `archived-uses`. The
repo or org can enforce SHA pinning in the allowed-actions policy (`sha_pinning_required`, since August 2025).

## 5. oidc-trust

```bash
rg -n 'id-token:\s*write|configure-aws-credentials|role-to-assume|google-github-actions/auth|workload_identity_provider|azure/login' $WF
rg -n 'token\.actions\.githubusercontent\.com(:sub|/sub)?|attribute_condition|assertion\.(sub|repository|repository_owner|ref)|federated_identity_credential|subject\s*=' \
  -g '*.tf' -g '*.json' -g '*.y*ml' -g '*.ts' -g '*.py' . | rg -v node_modules
rg -n 'repo:[^"'"'"'\s]*\*' -g '*.tf' -g '*.json' -g '*.y*ml' .
# portable
grep -rnE 'token\.actions\.githubusercontent\.com|attribute_condition|federated_identity_credential' --include='*.tf' --include='*.json' --include='*.y*ml' . | grep -v node_modules
```

| Cloud | Look at | Too broad | Good |
|---|---|---|---|
| AWS | `Condition` on `token.actions.githubusercontent.com:sub` (and `:aud` = `sts.amazonaws.com`) | `StringLike` `repo:org/*`, `repo:org/repo:*`, `repo:*`; only `aud` checked (older roles; AWS now refuses new ones without `sub`) | `StringEquals` `repo:org/repo:environment:prod` or `repo:org/repo:ref:refs/heads/main` |
| GCP | Provider `attribute_condition` and the `principalSet` bound on the service account | Only `assertion.repository_owner == 'org'`; binding the whole pool | Condition on `assertion.repository` plus `assertion.ref` or environment; bind `principalSet://…/attribute.repository/org/repo` |
| Azure | Federated credential `subject` (or a claims-matching expression) | `repo:org/repo:pull_request`; wildcard expressions | `repo:org/repo:environment:prod` |

If the repo or org customizes the subject claim (`actions/oidc/customization/sub`), the subject the cloud sees
differs from the default `repo:…:ref:…` shape. Read the template before judging a policy.

**Finding when** a workflow a lower-trust actor can run (any branch, `pull_request`, another repo in the org) can
satisfy the condition and the role can do something that matters. Hand the role's permissions to `iam-audit`. Trust
policies that live only in the cloud account are `needs_validation` with the read command (see Platform facts).

## 6. self-hosted-runner

```bash
rg -n 'runs-on:' $WF | rg -v 'ubuntu-|windows-|macos-'
```

Custom labels (`[self-hosted, linux]`, `gpu`, `build-xl`) are usually self-hosted, but larger GitHub-hosted runners
also have custom names: confirm with the runners API.

**Finding when** the repo is public (or fork PRs run on private), a job reachable from fork PRs, comments or
`pull_request_target` runs on it, and the runner isn't ephemeral. The next job on that machine inherits what the
previous one left: files, credentials in the home directory, Docker images, background processes. On public repos
GitHub's guidance is not to use self-hosted runners at all, unless they're ephemeral and isolated.

## 7. fork-secrets

```bash
rg -n 'secrets:\s*inherit|toJSON\(secrets\)|\$\{\{\s*secrets\.' $WF
```

- `pull_request` from a fork gets no secrets and a read-only token on public repos. On private and internal repos the
  "Send write tokens / Send secrets to workflows from fork pull requests" settings change that: a platform fact.
- Dependabot-triggered runs get Dependabot secrets, not Actions secrets.
- `secrets: inherit` hands every secret to the called workflow; with a reusable workflow that runs PR code, that's the
  path. `toJSON(secrets)` puts every secret into one value (zizmor `overprovisioned-secrets`).
- Secrets used outside an `environment:` can't be gated by reviewers (zizmor `secrets-outside-env`, auditor persona).

**Finding when** a secret is in scope of a step that runs untrusted code or text (sections 1, 2, 12). A secret that
already appeared in a log or artifact goes to `secrets-audit` for rotation.

## 8. cache-poisoning

```bash
rg -n 'actions/cache(/save|/restore)?@|restore-keys:|cache:\s*['"'"'"]?(npm|yarn|pnpm|pip|poetry|gradle|maven|go)|key:.*(head_ref|github\.event\.pull_request)' $WF
# portable
grep -nE 'actions/cache(/save|/restore)?@|restore-keys:|cache:[[:space:]]*.?(npm|yarn|pnpm|pip|poetry|gradle|maven|go)' $WF/*.y*ml
```

Caches are scoped by branch, and a run can read caches from its own branch and the default branch. A
`pull_request_target` run executes in the default branch's scope, so a cache it writes is visible to later default
branch runs, including releases. Shapes that matter: cache writes in `pull_request_target`/`issue_comment` jobs that
also run untrusted code; broad `restore-keys:` prefixes; keys derived from attacker text; a release job that restores
anything. Ultralytics (December 2024) was a `pull_request_target` injection that poisoned a cache a later release
restored before publishing to PyPI.

**Fix:** release and publish jobs build without restoring caches (`setup-*` without `cache:`, no `actions/cache`), or
from keys no untrusted run can write.

## 9. artifact-trust

```bash
rg -l 'workflow_run' $WF | xargs rg -n 'download-artifact|action-download-artifact|gh run download|run-id:|unzip|tar x'
```

**Finding when** the downloaded content (from a run a fork can trigger) is executed, extracted into the workspace
where later steps run things, deployed, published, or used unquoted in a shell (a "PR number" file containing
`1; …`). Treat it as data: extract to `${{ runner.temp }}`, validate the shape (`^[0-9]+$` for a PR number), never
run it. Release jobs that download artifacts by name from another workflow should check the run's `head_sha` and
`event` before using them; artifact identity across releases is `dependency-audit` territory (digests, attestations).

## 10. comment-command

```bash
rg -l 'issue_comment|pull_request_review_comment' $WF | xargs rg -n "author_association|contains\(.*comment\.body|startsWith\(.*comment\.body|github\.actor|getCollaboratorPermissionLevel"
rg -n "github\.actor\s*==|github\.triggering_actor|user\.login\s*==\s*'.*\[bot\]'" $WF
```

- A `/deploy` or `/test` command must check the commenter (`author_association` in `OWNER`/`MEMBER`/`COLLABORATOR`,
  or a permission API call) **before** any privileged step, and then check out the reviewed SHA, not the branch head.
- `github.actor` is whoever caused the latest event, which can differ from the PR author: a bot check on it can be
  satisfied by triggering a re-run (zizmor `bot-conditions`). Compare `github.event.pull_request.user.login` instead.
- Comment-triggered runs on PRs execute the default branch's workflow; any PR checkout inside is section 1.

## 11. unprotected-publish

```bash
rg -n 'npm publish|pnpm publish|yarn npm publish|twine upload|uv publish|poetry publish|cargo publish|gem push|docker push|gh release create|goreleaser' $WF
rg -n 'NPM_TOKEN|NODE_AUTH_TOKEN|PYPI_(API_)?TOKEN|CARGO_REGISTRY_TOKEN|GEM_HOST_API_KEY|environment:' $WF
```

Check: which refs reach the publish job (tag pushes from anyone with write, any branch), whether an `environment:`
with required reviewers or a deployment-branch rule sits in front, and whether a long-lived token is used where
trusted publishing (OIDC to npm, PyPI, RubyGems, crates.io) is available (zizmor `use-trusted-publishing`). Who can
push tags is a ruleset fact.

## zizmor audit map

zizmor result → class here. Every result still needs the trace.

| zizmor audit | Class |
|---|---|
| `dangerous-triggers` | `pwn-request` candidate (the trigger alone is not a finding) |
| `template-injection` | `script-injection` (or `agent-prompt-injection` when the sink is an agent's `prompt`) |
| `github-env` | `script-injection` |
| `excessive-permissions`, `undocumented-permissions` | `excessive-permissions` (the second is hardening) |
| `artipacked` | `excessive-permissions` (token on disk) or `artifact-trust` |
| `unpinned-uses`, `unpinned-images`, `impostor-commit`, `ref-confusion`, `stale-action-refs`, `known-vulnerable-actions`, `archived-uses`, `typosquat-uses`, `ref-version-mismatch` | `unpinned-action` |
| `self-hosted-runner` (pedantic) | `self-hosted-runner` |
| `secrets-inherit`, `overprovisioned-secrets`, `secrets-outside-env`, `unredacted-secrets` | `fork-secrets` |
| `cache-poisoning` | `cache-poisoning` |
| `bot-conditions`, `unsound-condition`, `unsound-contains` | `comment-command` |
| `use-trusted-publishing` | `unprotected-publish` |
| `insecure-commands`, `hardcoded-container-credentials`, `obfuscation`, `adhoc-packages`, `unpinned-tools`, `dependabot-execution` | Read and classify; often hardening |
| `anonymous-definition`, `concurrency-limits`, `misfeature`, `superfluous-actions`, `dependabot-cooldown` | Hardening notes |

## Platform facts

Reads that prompt (`gh api` can write with other flags, so it isn't pre-approved). Record the command and its output,
redacted, under `<audit dir>/evidence/` and point `evidence[]` at it.

```bash
gh api repos/OWNER/REPO --jq '{visibility, default_branch, fork}'
gh api repos/OWNER/REPO/actions/permissions/workflow
gh api repos/OWNER/REPO/actions/permissions
gh api repos/OWNER/REPO/actions/permissions/fork-pr-contributor-approval    # public repos: approval policy for fork runs
gh api repos/OWNER/REPO/actions/runners
gh api orgs/ORG/actions/runner-groups --jq '.runner_groups[] | {name, visibility, allows_public_repositories}'
gh api repos/OWNER/REPO/actions/oidc/customization/sub
gh api repos/OWNER/REPO/environments
gh api repos/OWNER/REPO/rulesets
# cloud side
aws iam get-role --role-name ROLE --query Role.AssumeRolePolicyDocument
gcloud iam workload-identity-pools providers describe PROVIDER --workload-identity-pool=POOL --location=global --format='value(attributeCondition)'
az ad app federated-credential list --id APP_ID --query '[].{name:name, subject:subject}'
```

If an endpoint returns 404 on the user's plan or GitHub version, use the Settings → Actions page instead and say so
in the evidence description.

## Safe shapes (do not raise)

| Shape | Why |
|---|---|
| `pull_request_target` with no checkout of PR code and no PR text in scripts | Runs only base-branch code |
| `${{ github.event.pull_request.number }}`, SHAs, `github.repository` in `run:` | Not free text |
| `${{ }}` in `if:` or passed via `env:` and used as `"$VAR"` | Not pasted into the script |
| `${{ secrets.X }}` in `with:` | Not an injection; still count it in "secrets in scope" |
| Third-party action pinned to a full SHA that exists in the upstream repo | Immutable |
| `pull_request` (not `_target`) from forks on a public repo | No secrets, read-only token |
| Agent action with the default write-access gate and no PR checkout at the root | Outsiders can't trigger it |

## Sources

GitHub Security Lab "Keeping your GitHub Actions and workflows secure" parts 1 and 2; GitHub Docs security hardening;
zizmor audit documentation (MIT); Sentry `gha-security-review` (Apache-2.0) for the outsider threat model and
safe-shape list. All paraphrased; greps written for this repo.
