# GitLab CI and CircleCI equivalents

Same questions as for GitHub Actions: who can start a pipeline, what text and code they control, and what the job
holds. Fingerprints use the config file: `cicd-security/<class>/.gitlab-ci.yml/<job>`,
`cicd-security/<class>/.circleci/config.yml/<job>`; set `ext.platform` to `gitlab-ci` or `circleci`.

## GitLab CI

| Class | GitLab shape | Where to look |
|---|---|---|
| `pwn-request` | Merge request pipelines from forks run in the **fork's** project by default (no parent secrets). A maintainer clicking "Run pipeline" on a fork MR runs it in the **parent** project with its variables: the fork's code with the parent's secrets | Project → CI/CD settings; MR pipeline history. Treat "run fork MR pipelines in the parent" as a review step, like a label gate |
| `script-injection` | Predefined variables with outsider text expanded in `script:` without quoting: `$CI_MERGE_REQUEST_TITLE`, `$CI_MERGE_REQUEST_DESCRIPTION`, `$CI_COMMIT_MESSAGE`, `$CI_COMMIT_TITLE`, `$CI_COMMIT_BRANCH`, `$CI_COMMIT_REF_NAME`, `$CI_MERGE_REQUEST_SOURCE_BRANCH_NAME` | `rg -n 'CI_(MERGE_REQUEST_(TITLE\|DESCRIPTION\|SOURCE_BRANCH_NAME)\|COMMIT_(MESSAGE\|TITLE\|DESCRIPTION\|BRANCH\|REF_NAME))' .gitlab-ci.yml` then check for `eval`, unquoted use, or use inside `sh -c` strings. GitLab expands variables in the shell, not by text substitution, so quoted `"$VAR"` is safe; `eval`, `bash -c "… $VAR"` and `rules:if` with regexes are where it goes wrong |
| `excessive-permissions` | `CI_JOB_TOKEN` access: which projects allow this project's job token in (Settings → CI/CD → Job token permissions, the allowlist) | `glab api projects/:id/job_token_scope` (prompts) |
| `unpinned-action` | `include: remote:` URLs, `include: project:` with `ref:` a branch, CI/CD components `component: …@main` or `@~latest`, `image:` by tag | `rg -n -A3 '^include:\|component:\|image:' .gitlab-ci.yml` |
| `oidc-trust` | `id_tokens:` with `aud`; cloud trust on `sub` = `project_path:group/project:ref_type:branch:ref:main`. Wildcards on `project_path:group/*` or missing `ref_protected` checks | Cloud trust policy, as for GitHub |
| `self-hosted-runner` | Shared or group runners with the `docker` executor in `privileged = true`, or shell executors, picking up jobs from projects that accept outside MRs | Runner `config.toml` (owner), runner tags in `.gitlab-ci.yml` |
| `fork-secrets` | Variables not marked **Protected** are exposed to pipelines on unprotected branches, which anyone with Developer role can create | Settings → CI/CD → Variables: protected and masked flags |
| `cache-poisoning` | "Use separate caches for protected branches" off, so an unprotected branch can write a cache key a protected-branch release restores | Settings → CI/CD → General pipelines; `cache:key:` in release jobs |
| `artifact-trust` | `needs: { pipeline: …, artifacts: true }` or `dependencies:` pulling artifacts from an unprotected-branch pipeline into a deploy job | Deploy jobs' `needs:` |
| `unprotected-publish` | Deploy or publish jobs without `rules:` limiting them to protected branches/tags, or without a protected `environment:` | `rg -n 'environment:\|rules:\|only:' .gitlab-ci.yml` |

GitLab Duo or agent jobs reading MR and issue text: same three questions as
[ai-agents-in-ci.md](ai-agents-in-ci.md), with the job token's project access as the token scope.

## CircleCI

| Class | CircleCI shape | Where to look |
|---|---|---|
| `pwn-request` / `fork-secrets` | Project settings "Build forked pull requests" plus "Pass secrets to builds from forked pull requests": both on means fork PR code runs with project environment variables and contexts' secrets | Project Settings → Advanced (owner); `circleci` API v2 `project/{slug}/settings` (prompts) |
| `script-injection` | Pipeline parameters and `<< pipeline.git.branch >>`, `<< pipeline.trigger_parameters.* >>` expanded into `run: command:` text at config compile time, like `${{ }}` | `rg -n '<<\s*pipeline\.(git\.(branch\|tag)\|trigger_parameters)' .circleci/config.yml` |
| `unpinned-action` | Orbs on `@volatile` or a major-only range (`orb@5`), Docker executors by tag, `setup: true` dynamic config that pulls a config from a branch | `rg -n '^orbs:' -A10 .circleci/config.yml`; prefer exact orb versions and image digests |
| `excessive-permissions` | Contexts without security-group or expression restrictions: any project member's pipeline on any branch gets the context's secrets | Organization Settings → Contexts → restrictions (owner) |
| `oidc-trust` | `CIRCLE_OIDC_TOKEN_V2`; `sub` = `org/<org-id>/project/<project-id>/user/<user-id>` (plus VCS origin and ref claims in v2). Cloud trust that checks only the org ID admits every project and branch | Cloud trust policy |
| `self-hosted-runner` | Self-hosted runner resource classes used by jobs that build fork PRs; machine runners keep state between jobs | `resource_class:` values with a namespace prefix |
| `cache-poisoning` | `save_cache` keys from `{{ .Branch }}` with broad `restore_cache` fallbacks used by release jobs | `rg -n 'save_cache\|restore_cache\|keys:' -A4 .circleci/config.yml` |

## Sources

GitLab Docs: CI/CD variables (protected variables), merge request pipelines for forks, job token scope, ID tokens,
cache (separate caches for protected branches). CircleCI Docs: forked pull request settings, contexts and
restrictions, OIDC tokens, orb versioning. Summarized for this repo; no text copied.
