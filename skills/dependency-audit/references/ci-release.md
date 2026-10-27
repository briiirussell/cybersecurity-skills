# CI and Release Trust Handoffs

Companion to `dependency-audit` Step 5b. Handoffs 1–4, 7 and 8 are now reviewed by `cicd-security`, which has the fuller checks; they stay listed here so a dependency review can spot them and hand off. Most real build-pipeline compromises don't need a vulnerable package. They go through a handoff: a lower-trust job writes something (a cache, an artifact, a tag, a checksum) that a higher-trust job later restores, executes, signs, or ships. This file lists the handoffs to check, a grep for each, and the evidence a finding needs.

Approach adapted (paraphrased) from Cloudflare's security-audit-skill `SUPPLY-CHAIN-AND-RELEASE.md` (MIT).

## Principles

1. **CI configuration is authorization code.** A workflow file decides who can run what, with which credentials, against which targets. Review it with the same rigour as an access-control check in the application.
2. **A mutable or known-vulnerable dependency is not a finding by itself.** Show three things: who can influence what gets resolved (a fork PR author, a package maintainer, anyone who can push a tag), which build consumes it, and which execution or release boundary comes next (secrets in scope, a publish step, a deploy). Without all three it is a hardening note or a `needs_validation` item.
3. **Least privilege missing on its own is hardening.** `permissions: write-all` with no reachable privileged step is a hardening note. It becomes a finding only when a lower-trust actor can reach a step that uses the extra privilege.
4. **Integrity has to come from somewhere independent.** A checksum or signature downloaded from the same place as the artifact proves nothing if that place is compromised.
5. **Name the lower-trust actor and prove artifact identity across the handoff.** "The release job uses an artifact" is not a finding. "A fork PR's `pull_request` run uploads `dist`, and the `workflow_run` release job downloads `dist` by name and publishes it with `NPM_TOKEN`" is.

## Where platform-only facts go

Some facts that decide exploitability exist only on the hosting platform, not in the repo:
- branch and tag protection / rulesets, required reviews, who can push tags
- the default `GITHUB_TOKEN` permission setting (org or repo level)
- whether fork PR workflows need approval to run
- runner type (GitHub-hosted vs self-hosted, ephemeral vs persistent)
- environment protection rules and required reviewers
- the cloud-side OIDC trust policy, when it isn't in this repo's IaC

Don't guess these. Record the candidate as `needs_validation` with `blockers[]` naming the missing fact and a `validation_plan` the owner can run, for example:

```bash
gh api repos/{owner}/{repo}/branches/{branch}/protection
gh api repos/{owner}/{repo}/rulesets
gh api repos/{owner}/{repo}/actions/permissions/workflow      # default token perms
gh api repos/{owner}/{repo}/environments
gh api repos/{owner}/{repo}/actions/runners                   # self-hosted runners
aws iam get-role --role-name <role> --query Role.AssumeRolePolicyDocument
```

## Patterns

All greps assume GitHub Actions. Adapt the paths for GitLab (`.gitlab-ci.yml`), CircleCI (`.circleci/config.yml`), and Buildkite.

```bash
WF=".github/workflows"
```

### 1. Privileged workflow restores artifacts or caches from an untrusted run

`workflow_run` and `pull_request_target` run in the base repo's context, with secrets and a write-capable token. If they download an artifact or restore a cache that a fork PR's `pull_request` run produced, and then execute or publish it, the fork author controls what runs with secrets.

```bash
grep -lE "workflow_run|pull_request_target" $WF/*.y*ml \
  | xargs grep -nE "actions/download-artifact|action-download-artifact|gh run download|actions/cache(/restore)?@|run-id:"
```

Finding when: the triggering run can come from a fork or untrusted branch, and the restored content is executed (`npm run`, `make`, unzip-then-run), deployed, or published in a job with secrets or write permissions. Treat artifact contents as untrusted data: extract outside the workspace, validate, never execute.

### 2. Cache keys an untrusted run can write

Caches restored by privileged jobs are a poisoning target. Risky shapes: a cache written from a `pull_request_target` job (base-branch scope, so later default-branch runs restore it); broad `restore-keys:` prefixes that fall back to any cache with the same prefix; keys built from attacker-controlled input (branch name, PR title); the same key used by a PR job and a release job.

```bash
grep -nE "actions/cache(/save|/restore)?@|restore-keys:|key:.*github\.(head_ref|event\.pull_request)|cache:\s*['\"]?(npm|yarn|pnpm|pip|poetry|gradle|maven)" $WF/*.y*ml
```

`actions/setup-node`, `setup-python`, `setup-java` and similar with `cache:` use the same cache store. Finding when: an untrusted run can write a key that a release, deploy, or secret-holding job later restores and executes. Release jobs should build without restoring caches, or with a key no untrusted run can write.

### 3. Missing or broad `permissions:` combined with a reachable privileged step

```bash
# Workflows with no permissions block at all (inherit the repo/org default)
grep -L "permissions:" $WF/*.y*ml
# Broad grants
grep -nE "permissions:\s*write-all|^\s+(contents|packages|actions|id-token|pull-requests|deployments|attestations|security-events):\s*write" $WF/*.y*ml
```

Then check what an untrusted actor can reach in that job: script injection via `${{ github.event.* }}` in `run:`, checkout and build of PR code, a third-party action that is not SHA-pinned. Missing `permissions:` alone is a hardening note. If the workflow relies on the platform default and you can't see it, the default is a `needs_validation` blocker (see above).

### 4. OIDC `id-token: write` and the cloud trust-policy subject

`id-token: write` lets the job mint a token that a cloud role trusts. What matters is the trust policy's subject condition. A wildcard such as `repo:org/*`, or `repo:org/repo:*`, or a policy that checks only `aud`, lets any branch, any PR workflow, or any repo in the org assume the role.

```bash
# Which jobs can mint tokens, and for what
grep -nE "id-token:\s*write|configure-aws-credentials|google-github-actions/auth|azure/login|role-to-assume|workload_identity_provider" $WF/*.y*ml
# Trust policies in IaC (Terraform, CloudFormation, JSON policies)
grep -rnE "token\.actions\.githubusercontent\.com(:sub|:aud|/sub)?|attribute_condition|assertion\.(repository|ref|sub)|subject_claim|federated_credential" \
  --include="*.tf" --include="*.json" --include="*.y*ml" --include="*.ts" . | grep -v node_modules
# Wildcard subjects
grep -rnE "repo:[^\"' ]*\*" --include="*.tf" --include="*.json" --include="*.y*ml" . | grep -v node_modules
```

Good: the subject is pinned to a repo plus a protected ref or environment (`repo:org/repo:environment:production` or `:ref:refs/heads/main`). Finding when: a lower-trust workflow (PR, any branch) can satisfy the condition and the role grants something meaningful. Trust policies that live only in the cloud account go to `needs_validation`. Hand role-permission review to `iam-audit` / `cloud-audit`.

### 5. Promotion or release by tag or name instead of digest

If the job that tests or scans an image is not the job that ships it, the two must agree on identity by digest. A mutable tag (`:latest`, `:main`, `:v1`) or an artifact name can be re-pointed between the two steps.

```bash
grep -nE "docker (pull|tag|push)|crane (copy|tag|cp)|skopeo copy|oras (pull|copy)|kubectl set image|helm (upgrade|install)|gh release (download|upload)|image:\s" $WF/*.y*ml \
  | grep -v "@sha256:"
# Deploy manifests referencing images by tag
grep -rnE "image:\s*\S+:\S+" --include="*.y*ml" k8s/ deploy/ charts/ 2>/dev/null | grep -v "@sha256:"
```

Finding when: someone with lower trust than the release job can push to that tag, artifact name, or registry path between build and promotion. Fix: carry the digest from the build job's output, promote with `image@sha256:...`, and verify attestations before deploy.

### 6. Checksum or signature from the same origin as the artifact

```bash
grep -rnE "(curl|wget|Invoke-WebRequest)[^|]*(\.sha(256|512)|checksums?\.txt|\.sig|\.asc|SHA256SUMS)" $WF Dockerfile* scripts/ 2>/dev/null
grep -rnE "(curl|wget)[^|]*\|\s*(sudo\s+)?(ba|z)?sh" $WF Dockerfile* scripts/ *.sh 2>/dev/null
```

A `.sha256` fetched from the same release page or bucket as the binary only detects corruption, not tampering. Independent integrity means a checksum pinned in the repo, a signature checked against a key or identity pinned in the repo (`cosign verify --certificate-identity ...`, `gpg` with a pinned fingerprint), or a provenance attestation verified against the expected builder. `curl | sh` has no integrity check at all.

### 7. Publish steps without a protected identity

```bash
grep -nE "npm publish|pnpm publish|yarn npm publish|twine upload|uv publish|poetry publish|cargo publish|gem push|docker push|gh release create|goreleaser" $WF/*.y*ml
grep -nE "NPM_TOKEN|NODE_AUTH_TOKEN|PYPI_(API_)?TOKEN|CARGO_REGISTRY_TOKEN|GEM_HOST_API_KEY|environment:" $WF/*.y*ml
```

Check: does the publish job run only from a protected ref or tag, behind an `environment:` with reviewers? Does it use a long-lived token where trusted publishing (OIDC to npm, PyPI, RubyGems, crates.io) is available? Is provenance (`npm publish --provenance`, SLSA attestations) generated? Who can push the tag that triggers it? That last one is a platform fact, so route it to `needs_validation`.

### 8. Self-hosted runners reachable from untrusted PRs

```bash
grep -nE "runs-on:.*self-hosted|runs-on:\s*\[.*self-hosted" $WF/*.y*ml
```

A persistent self-hosted runner that runs fork PR code can be left with a backdoor that the next privileged job inherits. Whether the repo is public, whether fork runs need approval, and whether the runner is ephemeral are platform facts, so they go to `needs_validation`.

### 9. Build-context inclusion

What goes into a build is part of the release. `COPY . .` without a `.dockerignore` ships `.git`, `.env`, and local credentials into image layers. Package `files` / `.npmignore` gaps ship source maps, tests, or secrets in the published tarball.

```bash
ls .dockerignore 2>/dev/null || echo "no .dockerignore"
grep -nE "^\s*(COPY|ADD)\s+\.\s" Dockerfile* 2>/dev/null
npm pack --dry-run 2>/dev/null | head -60     # what the published package actually contains
```

### 10. Unpinned tools that generate or build shipped code

Code generators, bundler plugins, and build tools fetched unpinned at build time (`npx some-codegen`, `pip install tool` without a version, `go run pkg@latest`) let whoever controls the latest version of that tool write the code you ship.

```bash
grep -rnE "npx\s+(-y\s+)?[a-z@][^ @]*(\s|$)|go run\s+\S+@latest|pip install\s+[a-zA-Z][^=<> ]*(\s|$)" $WF scripts/ package.json Makefile 2>/dev/null
```

Pin the version (and for actions, the commit SHA). This overlaps with the existing unpinned-actions check in SKILL.md Step 5.

## Reporting

Each confirmed CI/release finding should state:
- **Lower-trust actor:** who can influence the input (fork PR author, any contributor with push, a third-party action maintainer, a package maintainer)
- **Handoff:** the job, trigger, and object (artifact name, cache key, tag) that crosses the boundary, with file and line
- **Privileged consumer:** the job that restores or executes it, and what it holds (secrets, token permissions, OIDC role, publish rights)
- **Boundary crossed:** code execution with secrets, a package publish, a production deploy, a cloud role
- **Platform facts assumed** and whether each was verified. Unverified ones make the record `needs_validation`.

Score severity with [severity-calibration.md](severity-calibration.md). Credential exposure and publish rights usually set impact. The platform settings above usually set likelihood.

## Sources

- Cloudflare security-audit-skill, [`SUPPLY-CHAIN-AND-RELEASE.md`](https://github.com/cloudflare/security-audit-skill/blob/main/skills/security-audit/SUPPLY-CHAIN-AND-RELEASE.md) (MIT). Principles and attack classes paraphrased; greps written for this repo.
- GitHub Docs: "Security hardening for GitHub Actions", "About security hardening with OpenID Connect", "Caching dependencies to speed up workflows"
- SLSA build track, [slsa.dev](https://slsa.dev)
