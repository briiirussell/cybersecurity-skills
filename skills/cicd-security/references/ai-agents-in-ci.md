# AI agents in CI

Companion to `cicd-security` check 12 (`agent-prompt-injection`). An agent step is a script whose instructions come
partly from whoever wrote the issue, PR or comment it reads. Treat that text the way the rest of this skill treats
`${{ github.event.issue.title }}`: attacker-controlled input reaching a step that holds a token. The model's judgment
is not a control. Decide three things, in this order.

## 1. Find the agent steps

```bash
rg -n 'anthropics/claude-code-(base-)?action|openai/codex-action|google-github-actions/run-gemini-cli|google-gemini/gemini-cli-action|actions/ai-inference' .github
# agents run directly, not through an action
rg -n '\b(claude|codex|gemini|aider|opencode)\b.*(-p|--print|exec|--prompt|--yolo|--dangerously)' .github/workflows .github/actions
# composite actions and reusable workflows can hide an agent one level down: resolve `uses: ./…` and job-level `uses:`
```

For each step record: the action and its ref (pinned?), the triggers that reach it, the job's `permissions:`, secrets
in its `env:`/`with:`, and these inputs:

| Action | Inputs that decide exposure |
|---|---|
| `anthropics/claude-code-action` | `prompt` (pre-v1: `direct_prompt`, `override_prompt`), `claude_args` (`--allowedTools`, `--disallowedTools`, `--add-dir`, `--mcp-config`), `allowed_non_write_users`, `allowed_bots`, `include_comments_by_actor` / `exclude_comments_by_actor`, `github_token`, `settings`, `trigger_phrase`, `show_full_output`, `use_commit_signing` |
| `anthropics/claude-code-base-action` | Same prompt and tool inputs, **no** permission check and no base-branch config restore: any trigger reaches it |
| `openai/codex-action` | `prompt`, `prompt-file`, `sandbox` (`read-only`, `workspace-write`, `danger-full-access`), `safety-strategy`, `allow-users`, `allow-bots`, `codex-args` |
| `google-github-actions/run-gemini-cli` | `prompt`, `settings` (sandbox and tool config as JSON), `extensions` |
| `actions/ai-inference` | `prompt`, `token` scope; output usually consumed by a later step |

## 2. Who can put text in front of it

| Gate | Outsider reaches it? |
|---|---|
| claude-code-action default: actor must have write access (checked on issue, PR, comment, review and `workflow_run` events) | No, for the trigger. But the agent may still **read** outsider text: an issue thread with outsider comments, a fork PR's diff, files in a checked-out PR |
| `allowed_non_write_users: "*"` or a list | Yes for `*`. The action then scrubs known secrets from subprocess environments on a best-effort basis; that reduces, not removes, the risk |
| `allowed_bots: "*"` | Yes on public repos: any GitHub App can open issues or comment, and allowed bots skip the permission check |
| `allow-users` / `allow-bots` wildcards (codex-action) | Yes |
| `claude-code-base-action`, a raw CLI call, `actions/ai-inference` | Whatever the workflow trigger allows; no gate of its own |
| An `if:` on `author_association` before the step | Depends on the check; `CONTRIBUTOR` and `NONE` are outsiders |

Text sources to list for the agent: the triggering issue/PR/comment body and title, the PR diff and files, other
comments it fetches with `gh`, commit messages, and **config it loads from the checkout**. On PR events
claude-code-action restores `.claude/`, `.mcp.json`, `.claude.json`, `CLAUDE.md`, `CLAUDE.local.md`, `.gitmodules`,
`.ripgreprc` and `.husky/` from the base branch, but leaves `package.json`, lockfiles, `Makefile` and other build files
at the PR head. A hook, `apiKeyHelper` or `statusLine` command that runs `npm run …` or `make` therefore runs PR code.
A workflow that checks out the PR head into the workspace root **before** the action defeats the restore; the
documented safe shape checks it out into a subdirectory and passes `--add-dir`.

Prompt-side filtering (the action strips HTML comments, hidden characters, image alt text) narrows the channel; it
doesn't close it. Plain visible text is enough.

## 3. What it can do with what it holds

- **Token scope.** The job's `permissions:` bound the `GITHUB_TOKEN`. `contents: write` lets the agent push branches;
  with no branch protection it can push to the default branch. `pull-requests: write` plus the repo setting that lets
  Actions approve PRs lets it approve. `actions: write` lets it change workflows or caches. Prefer the short-lived
  workflow token or the GitHub App token over a long-lived user token, which outlives the run.
- **Secrets in the environment.** Anything in the job's `env:` is readable by any shell tool the agent has. API keys
  for the model itself count.
- **Tools.** `--allowedTools "Bash(*)"`, `Bash` unscoped, `--dangerously-skip-permissions`, codex
  `danger-full-access` / `safety-strategy: unsafe`, Gemini sandbox off: the agent can run anything the runner can. A
  narrow allow-list helps, but tools that read the environment or write to the network (`env`, `printenv`, `curl`,
  `gh api`, `git push`) carry data out even when "read-only" in spirit; a wildcard such as `Bash(gh:*)` includes
  `gh api -X POST`.
- **Output handling.** The agent's answer is attacker-influenced text. A later `run:` step that evaluates it
  (`${{ steps.agent.outputs.result }}` in a script, `eval`, piping it to a shell) is script injection one hop removed.
  Posting it as a comment is fine; executing it is not.
- **Logs.** `show_full_output: true` (also turned on by `ACTIONS_STEP_DEBUG`) writes full tool output into the run
  log, which is public on public repos.

## Verdicts

| Verdict | Shape |
|---|---|
| `confirmed` | An outsider can trigger the step or put text in its context, **and** the job holds a write scope, a secret, or unrestricted shell. E.g. `issues: opened` → claude-code-action with `allowed_non_write_users: "*"`, `contents: write`, `--allowedTools "Bash(*)"`. Or `pull_request_target` checks out the PR head to the workspace root and then runs the agent with `ANTHROPIC_API_KEY` and `pull-requests: write`. Static: confidence `medium` |
| `needs_validation` | One deciding fact is outside the YAML: the agent reads outsider comments on an issue but the gate is a GitHub App installation whose permissions aren't visible; the job relies on the repo default token permissions; a reusable workflow at an unpinned ref holds the agent step |
| `rejected` | The default write-access gate is in place, the PR head isn't checked out at the root, and the agent reads nothing an outsider wrote (for example it runs on `push` to main to update docs). Name the gate and the line |
| Hardening note | Agent gated to collaborators with a broad tool list and a narrow token; an unpinned agent action in a job with no secrets beyond the model key |

Severity follows what the job holds (SKILL.md Step 6). An outsider steering an agent that holds `contents: write` on
a repo without branch protection is High at least; Critical when the job also holds publish credentials or a
production cloud role.

## Fixes, in order of effect

1. Keep the default write-access gate. Don't set `allowed_non_write_users` or `allowed_bots: "*"` on a job with write
   scopes; if outsiders must reach it (issue labeling), give that job only `issues: write` and no secrets beyond the
   model key.
2. `permissions:` per job, minimal. Read-only for review bots that only comment (`pull-requests: write` is enough to
   comment on PRs).
3. Narrow tools with exact rules; no `Bash(*)`, no unscoped `Bash`, no network tools unless needed.
4. Never check out PR code at the workspace root before the agent; use a subdirectory and `--add-dir`.
5. Treat the agent's output as data in later steps: pass it through `env:` and quote it, never evaluate it.
6. Pin the agent action to a commit SHA like any other third-party action.

## Sources

- [anthropics/claude-code-action security guide](https://github.com/anthropics/claude-code-action/blob/main/docs/security.md): inputs, default gate, base-branch config restore, logging.
- Trail of Bits [agentic-actions-auditor](https://github.com/trailofbits/skills/tree/main/plugins/agentic-actions-auditor) (CC BY-SA 4.0): the per-action input list and the env-var-intermediary, wildcard-allowlist and evaluated-output vectors. Paraphrased.
- Sentry [gha-security-review](https://github.com/getsentry/skills/tree/main/skills/gha-security-review), `references/ai-prompt-injection-via-ci.md` (Apache-2.0): agent config files from fork checkouts. Paraphrased.
