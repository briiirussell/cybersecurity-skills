# Worked examples

One `findings.json` from a review of a public repository's workflows, with a record for each verdict. The workflows
are illustrative. Each record would pass `node references/validate-findings.mjs findings.json`.

The situation:

- `.github/workflows/claude.yml` runs `anthropics/claude-code-action` on `issues: [opened]` and `issue_comment`, with
  `allowed_non_write_users: "*"`, `claude_args: --allowedTools "Bash(*)"`, and `permissions: contents: write`.
- `.github/workflows/deploy.yml` runs on `push` to any branch and on `pull_request`, has `id-token: write`, and
  assumes an AWS role whose trust policy is not in the repo.
- `.github/workflows/pr-preview.yml` runs on `pull_request_target`, checks out the PR head, runs `npm ci && npm run
  build`, and deploys with `VERCEL_TOKEN`.
- `.github/workflows/issue-triage.yml` uses the issue title in a `run:` step, but through `env:`.

```json
[
  {
    "fingerprint": "cicd-security/agent-prompt-injection/.github/workflows/claude.yml/claude",
    "verdict": "confirmed",
    "skill": "cicd-security",
    "title": "Any GitHub user can steer claude-code-action, which has unrestricted shell and a contents:write token",
    "cwe": "CWE-77",
    "ext": {
      "platform": "github-actions",
      "workflow": ".github/workflows/claude.yml",
      "trigger": ["issues", "issue_comment"],
      "job": "claude",
      "lower_trust_actor": "any-github-user",
      "token_permissions": ["contents:write", "issues:write"],
      "secrets_in_scope": ["ANTHROPIC_API_KEY"],
      "agent": "claude-code-action"
    },
    "location": { "file": ".github/workflows/claude.yml", "line": 24 },
    "trace": [
      { "kind": "entrypoint", "file": ".github/workflows/claude.yml", "line": 3, "description": "on: issues [opened] and issue_comment; any GitHub user can open an issue or comment on this public repo" },
      { "kind": "propagation", "file": ".github/workflows/claude.yml", "line": 27, "description": "allowed_non_write_users: \"*\" turns off the action's write-access check, so the issue body becomes the agent's task" },
      { "kind": "sink", "file": ".github/workflows/claude.yml", "line": 29, "description": "claude_args --allowedTools \"Bash(*)\" in a job with contents:write (line 9) and ANTHROPIC_API_KEY in env" }
    ],
    "evidence": [
      { "file": ".github/workflows/claude.yml", "line": 9, "description": "permissions: contents: write, issues: write" },
      { "file": ".github/workflows/claude.yml", "line": 27, "description": "allowed_non_write_users: \"*\"" }
    ],
    "counterevidence": "Looked for an author_association guard or an if: on the job: none. The action's best-effort env scrub applies with allowed_non_write_users, but it narrows neither the token scope nor the tool list, and Bash(*) allows any command. Branch protection on main is a platform fact; even with it, the token can push new branches and edit issues.",
    "confidence": "medium",
    "severity": {
      "likelihood": { "score": "high", "reason": "Public repo; opening an issue needs only a GitHub account" },
      "impact": { "score": "high", "reason": "Repo write token and the model API key reachable by an outsider-directed shell" },
      "overall": "high"
    },
    "conditions": [
      { "kind": "system_configuration", "description": "Whether main has branch protection decides if pushes land on the default branch or only on new branches" }
    ]
  },
  {
    "fingerprint": "cicd-security/oidc-trust/.github/workflows/deploy.yml/deploy",
    "verdict": "needs_validation",
    "skill": "cicd-security",
    "title": "Deploy role may trust OIDC tokens from pull_request runs and any branch",
    "ext": {
      "platform": "github-actions",
      "workflow": ".github/workflows/deploy.yml",
      "trigger": ["push", "pull_request"],
      "job": "deploy",
      "lower_trust_actor": "fork-pr-author",
      "token_permissions": ["id-token:write"]
    },
    "location": { "file": ".github/workflows/deploy.yml", "line": 31 },
    "trace": [
      { "kind": "entrypoint", "file": ".github/workflows/deploy.yml", "line": 3, "description": "on: push (all branches) and pull_request" },
      { "kind": "sink", "file": ".github/workflows/deploy.yml", "line": 31, "description": "aws-actions/configure-aws-credentials assumes role gha-deploy with id-token: write" }
    ],
    "evidence": [],
    "counterevidence": "The job has no if: restricting it to main and no environment:. The trust policy is not in this repo's Terraform (rg for token.actions.githubusercontent.com found nothing). Fork PRs on pull_request get id-token only if the workflow grants it, which this one does at the top level.",
    "confidence": "medium",
    "blockers": [
      "Does the gha-deploy trust policy's token.actions.githubusercontent.com:sub condition accept pull_request or any ref, or only repo:OWNER/REPO:ref:refs/heads/main?"
    ],
    "validation_plan": "Owner runs: aws iam get-role --role-name gha-deploy --query Role.AssumeRolePolicyDocument. If sub is StringLike repo:OWNER/REPO:* or repo:OWNER/*, or pull_request is allowed → confirmed (rate by the role's permissions, via iam-audit). If sub is StringEquals to the main ref or a protected environment → rejected, ruled out by that condition."
  },
  {
    "fingerprint": "cicd-security/pwn-request/.github/workflows/pr-preview.yml/build",
    "verdict": "confirmed",
    "skill": "cicd-security",
    "title": "pull_request_target builds fork PR code with a write token and VERCEL_TOKEN",
    "cwe": "CWE-829",
    "ext": {
      "platform": "github-actions",
      "workflow": ".github/workflows/pr-preview.yml",
      "trigger": ["pull_request_target"],
      "job": "build",
      "lower_trust_actor": "fork-pr-author",
      "token_permissions": ["contents:write", "pull-requests:write"],
      "secrets_in_scope": ["VERCEL_TOKEN"]
    },
    "location": { "file": ".github/workflows/pr-preview.yml", "line": 18 },
    "trace": [
      { "kind": "entrypoint", "file": ".github/workflows/pr-preview.yml", "line": 3, "description": "on: pull_request_target; any GitHub user can open a PR from a fork" },
      { "kind": "propagation", "file": ".github/workflows/pr-preview.yml", "line": 18, "description": "actions/checkout with ref: github.event.pull_request.head.sha into the workspace root" },
      { "kind": "sink", "file": ".github/workflows/pr-preview.yml", "line": 22, "description": "npm ci && npm run build runs lifecycle and build scripts from the PR's package.json with VERCEL_TOKEN in env and a contents:write token" }
    ],
    "evidence": [
      { "file": ".github/workflows/pr-preview.yml", "line": 8, "description": "permissions: contents: write, pull-requests: write" },
      { "file": ".github/workflows/pr-preview.yml", "line": 24, "description": "env: VERCEL_TOKEN: secrets.VERCEL_TOKEN" }
    ],
    "counterevidence": "No label gate, no author_association check, no environment: with reviewers. The checkout keeps persist-credentials at its default, so the token is also on disk in .git/config. The 2025-12-08 pull_request_target change pins the workflow file to the default branch but doesn't affect this checkout.",
    "confidence": "medium",
    "severity": {
      "likelihood": { "score": "high", "reason": "Opening a fork PR is enough; pull_request_target runs need no maintainer sign-off" },
      "impact": { "score": "high", "reason": "Repo write token plus a deploy token for the team's Vercel projects" },
      "overall": "high"
    },
    "conditions": []
  },
  {
    "fingerprint": "cicd-security/script-injection/.github/workflows/issue-triage.yml/label",
    "verdict": "rejected",
    "skill": "cicd-security",
    "title": "Issue title used in a run: step of an issues-triggered workflow",
    "ext": {
      "platform": "github-actions",
      "workflow": ".github/workflows/issue-triage.yml",
      "trigger": ["issues"],
      "job": "label",
      "tool_rule": "zizmor/template-injection"
    },
    "location": { "file": ".github/workflows/issue-triage.yml", "line": 20 },
    "trace": [],
    "evidence": [
      { "file": ".github/workflows/issue-triage.yml", "line": 17, "description": "env: TITLE: github.event.issue.title" }
    ],
    "counterevidence": "The run: script references \"$TITLE\" in double quotes and never evals it; no ${{ }} appears inside the script body. The zizmor hit points at the env: line, which the runner sets as data.",
    "confidence": "high",
    "ruled_out_by": {
      "control": "Title passed through env: TITLE and used only as a quoted shell variable, so the runner never pastes it into the script text",
      "location": { "file": ".github/workflows/issue-triage.yml", "line": 20 }
    }
  }
]
```

How the hardening notes from the same review read (no records, no severity):

- `release.yml` has no top-level `permissions:`; it runs only on tag pushes by maintainers and its job sets
  `contents: write` explicitly. Add `permissions: {}` at the top. Effort: minutes.
- `lint.yml` uses `some-org/setup-linter@v2` by tag in a `pull_request` job with a read-only token and no secrets.
  Pin to a SHA for consistency. Effort: minutes.
