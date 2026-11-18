# Change Control for Committed Agent Config (CC1–CC3)

Companion to `agent-supply-chain-audit` Step 3. Step 3 reads the hooks and settings that are in the repo today. This
file asks who can change them, what changed recently, and whether anything stops the next change. Committed agent
config runs on every developer who opens the repo, so one write to it reaches all of them.

**Incident that prompted this (reported 2026-11-16).** Google Threat Intelligence Group's AI Threat Tracker
("Agentic Threat Activity Crosses a Significant Threshold") describes a suspected DPRK cluster, MIDNIGHT NEPTUNE,
in intrusions at cryptocurrency organizations in North America and Europe. As GTIG reports it:

- Initial access came from fake recruiter profiles (images carrying SynthID watermarks), a fake meeting site with a
  ClickFix lure, and staging scripts GTIG calls likely LLM-authored.
- The actor then pivoted into the victims' internal code repositories and modified `.claude/settings.json` so that
  starting Claude Code triggered a download of the SOMBERMEME backdoor.
- It hid its lateral movement with GitHub PATs named after Microsoft Copilot.

GTIG does not say which hook event or settings key was used, and gives no file contents here. Do not fill them in.
This is vendor research, reported and not re-verified. No CVE: it is not a product flaw. It is a write to a file
that runs code. Source: [GTIG, 2026-11-16](https://cloud.google.com/blog/topics/threat-intelligence/agentic-threat-activity-crosses-a-significant-threshold/).
Checked 2026-11-18 against that page.

The same mechanism has shipped inside npm packages too (a bundled `.claude/settings.json` hook), covered under
"Cross-ecosystem worms" in Step 4. Here the write came from inside the org, through a normal push.

## Paths in scope

`.claude/settings.json`, `.claude/commands/`, `.claude/agents/`, `.claude/skills/`, `.mcp.json`, `CLAUDE.md`,
`AGENTS.md`, `.cursor/`, `.gemini/settings.json`, `.github/copilot-instructions.md`, `.github/instructions/`,
`.vscode/mcp.json`. Add any other project path from the Step 1 inventory that an agent loads.

## CC1 — Who can change it

Agent config should get the same review as `.github/workflows/`. Read-only:

```bash
# Is there a CODEOWNERS file, and which lines cover agent config?
ls .github/CODEOWNERS CODEOWNERS docs/CODEOWNERS 2>/dev/null
rg -n '\.claude|\.mcp\.json|CLAUDE\.md|AGENTS\.md|\.cursor|\.gemini|copilot-instructions|\.vscode' .github/CODEOWNERS CODEOWNERS docs/CODEOWNERS 2>/dev/null
# Does the default branch require code-owner review? (classic protection, then rulesets)
gh api repos/OWNER/REPO/branches/BRANCH/protection --jq '.required_pull_request_reviews' 2>/dev/null
gh api repos/OWNER/REPO/rules/branches/BRANCH --jq '.[] | select(.type=="pull_request") | .parameters'
```

- In CODEOWNERS the last matching pattern wins. A broad line lower in the file (`* @everyone-team`) can override a
  narrow owner for `.claude/`. Read the whole file in order.
- An owner only matters when the branch rule requires code-owner review (`require_code_owner_reviews` in classic
  protection, `require_code_owner_review` in a ruleset `pull_request` rule). Record who can bypass it (`bypass_actors`,
  admins).

| Result | Finding |
|---|---|
| No owner for these paths, and the default branch accepts direct pushes or merges without review | **Medium**, confirmed. Fix: add the paths to CODEOWNERS with a small owning team and require code-owner review |
| Owned, but code-owner review isn't required, or a broad set of users or bots can bypass it | Medium if direct pushes reach the default branch. Otherwise a hardening note |
| Owned and required, bypass limited to admins | Rejected for CC1. Note who the admins are |

Rate CC1 **high** when developers who open this repo hold production or deploy credentials on the same machine.

## CC2 — What changed recently

The user runs these (git is not pre-approved here):

```bash
git log --since='90 days ago' --format='%h %an <%ae> %ad %s' --date=iso -- \
  .claude .mcp.json CLAUDE.md AGENTS.md .cursor .gemini .github/copilot-instructions.md .vscode/mcp.json
# Commits that touched settings keys that run a command or reroute traffic
git log --since='90 days ago' -p --format='--- %h %an %ad' -- .claude/settings.json .cursor/hooks.json .gemini/settings.json \
  | rg -n '^\+.*"(hooks|command|apiKeyHelper|statusLine|awsAuthRefresh|otelHeadersHelper|env|ANTHROPIC_BASE_URL|NODE_OPTIONS)"|^--- '
# Was it a direct push, or did it come through a reviewed PR?
gh api repos/OWNER/REPO/commits/SHA/pulls --jq '.[].number'
```

Review any commit that added or changed a hook command, `apiKeyHelper`, `statusLine`, or an `env` override. Weigh
these more: no linked pull request, an author who doesn't usually touch the repo, a bot or token identity, a time far
outside the author's normal hours, and a commit message that doesn't describe the change.

| Result | Finding |
|---|---|
| A hook or command-running key added with no reviewed PR, or by an identity you can't account for | **needs_validation**. Ask the named author whether they made it. Read the command under BH1–BH4 |
| The author says they didn't make it, or the command downloads and runs something | **Critical**, confirmed. Stop the audit and go to `incident-triage` (dev-tool compromise, "Committed agent config"). Do not open the repo in an agent until it is cleaned |
| Changes all came through reviewed PRs and the commands are explained | Rejected for CC2 |

Do not trust the author name alone. Git author fields are set by whoever made the commit. The push identity is in the
org audit log (`log-watch`), and a token identity there is what CC2 is looking for.

## CC3 — CI guard (optional)

A required check that fails, or asks for an approver, when a pull request changes command-running keys in agent
config. CODEOWNERS covers who reviews. CC3 makes the reviewer see that this PR changes what runs on startup.

Shape, for `cicd-security` to review like any other workflow:

- Trigger on `pull_request`, not `pull_request_target`. Read the diff only. Never run the PR's config, hooks, or
  scripts to test them.
- `git diff --name-only "origin/$BASE"...HEAD` against the paths above. On a hit, grep the added lines for the CC2 key
  list and fail with the file and key named.
- Make the check required on the default branch, the same as a workflow-lockfile check.

No guard is a **hardening note**, not a finding.

## Lookalike agent CLI packages

`@claudecode/cli` on npm is malware that impersonates Claude Code. Every version is affected, and there is no fixed
version. The advisory says any computer that installed or ran it should be considered fully compromised
([GHSA-vp2q-gp5r-xh5j](https://github.com/advisories/GHSA-vp2q-gp5r-xh5j), published 2026-11-13; OSV
[MAL-2026-19243](https://osv.dev/vulnerability/MAL-2026-19243)). No CVE. The official package is
`@anthropic-ai/claude-code`. Checked 2026-11-18 against both pages.

This is IN5 in the Step 4 installers table. Read-only:

```bash
rg -n '"@claudecode/cli"|claude-code|codex|gemini-cli|copilot' package.json 2>/dev/null
npm ls -g --depth=0 2>/dev/null
rg -n 'npm (i|install).*(claude|codex|gemini|copilot)' README* docs/ CONTRIBUTING* 2>/dev/null
```

Compare each agent CLI's package name and scope with the vendor's install docs. A name that only looks right is the
finding.

| Result | Finding |
|---|---|
| `@claudecode/cli` installed globally, in a lockfile, or in install docs that people followed | **Critical**, confirmed. Go to `incident-triage` and treat the machine as compromised. Rotate from a clean machine |
| Another agent CLI under a scope that isn't the vendor's | needs_validation. Check the registry page and the vendor docs, then rate it like the row above if it is malicious |
| Install docs point at a lookalike, nothing installed yet | High. Fix the docs |

`dependency-audit` runs the same check on the project's own dependencies.
