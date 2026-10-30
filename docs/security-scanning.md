# Security scanning and tool permissions

This repo ships prompts that tell an AI agent how to do security work. Before you install them, you should know two things: what the skills pre-approve the agent to do, and how the repo checks itself for prompt-level risks. This page covers both.

## CI checks

Every PR into `development` or `main`, and every push to either branch, runs [`.github/workflows/ci.yml`](../.github/workflows/ci.yml). Each action in it is pinned to a full commit SHA. The workflow has `contents: read` permission, and only the SkillSpector job also gets `security-events: write`.

| Job | Command | Fails when |
|---|---|---|
| Skill lint | `node scripts/lint-skills.mjs` | `name` ≠ folder; description outside 200–1024 chars; `SKILL.md` ≥ 500 lines; no `## Authorization`, `## Boundaries` or `## References` section; an output section spelled other than `## Output Format`; a cross-referenced skill has no folder; a relative link doesn't resolve; two skills share a trigger phrase; `allowed-tools` pairs `WebFetch` with unscoped `Bash`; a `Bash` grant would pre-approve a write (see below) |
| Version check | `node scripts/check-versions.mjs` (PRs: `--base origin/<base branch>`) | `plugin.json` and `marketplace.json` versions differ; `VERSIONS.md` has no entry for the version, or a skill folder has no row (or a row has no folder); on a PR, the repo version isn't higher than the base's, or a skill changed without a row bump (generated `shared/` copies excepted). Dependabot PRs skip the bump check |
| Trigger eval (offline) | `node scripts/eval-triggers.mjs` | a skill has no `evals/triggers/<skill>.json` or fewer than 5 should-fire and 5 near-miss prompts; fewer than 85% of should-fire prompts rank their skill first by BM25 over the descriptions; fewer than 90% of near-misses rank their owner above the skill; any skill wins fewer than 3 of its own 5; two descriptions are more than 0.55 similar. See [evals/README.md](../evals/README.md) |
| Baseline check | `node .github/scripts/skillspector-baseline.mjs --check` | a baseline rule lacks `id`, `path`, `message` or `reason`, or names a skill that doesn't exist |
| Adapter drift | `node scripts/build-adapters.mjs`, then `git diff --exit-code adapters/ skills/` | generated adapters or the `shared/` → `skills/*/references/` copies are stale |
| Plugin validate | `claude plugin validate --json .` via `.github/scripts/plugin-validate.mjs` (CLI pinned in the workflow) | any manifest or content error, or any warning not listed in `ALLOWED` in that script with a reason. Only the root `CLAUDE.md` warning is accepted: it's contributor guidance, not plugin context |
| Tests | `npm test` (`node --test "scripts/test/*.test.mjs"`, Node ≥ 21) | a validator, `to-sarif`, build, grant-check, version-check, trigger-eval, eval-case shape or worked-example test fails (an `examples/*/findings.json` that no longer validates, points at a missing line, or has stale SARIF), or a self-test shows a checker (lint, baseline check, SARIF merge, plugin-validate) no longer catches a known-bad fixture |
| SkillSpector | per-skill `skillspector scan … --no-llm --baseline … --fail-on-findings --format sarif` | any finding that the baseline doesn't cover |

The lint also **fails** when two skills claim the same single-quoted trigger phrase, for example `'security review'` in both `owasp-audit` and `threat-modeling`, because the same request could activate either skill. SkillSpector's TR2 rule looks for the same thing. Fix it by keeping the phrase in the skill that owns the work and narrowing or dropping it in the other (v1.19.5 did this for seven phrases).

Run the lint locally before you push:

```bash
npm run check   # lint, baseline check, version check, adapter drift, tests
```

### Paid checks

[`evals.yml`](../.github/workflows/evals.yml) runs the `claude plugin eval` routing suite in `evals/cases/`. It runs on demand, and on pushes to `main` that change a skill or a case, with a pinned model and CLI, a $15 ceiling and a 0.8 threshold. It never runs on PRs, and it skips until the repo has an `ANTHROPIC_API_KEY` secret. See [evals/README.md](../evals/README.md).

### Scheduled checks

Some problems arrive without a PR, so two things run every Monday:

- **CI on `main`** (`ci.yml` `schedule`). The full workflow runs, including SkillSpector and the code-scanning upload, so a new upstream rule or a drifted pin shows up within a week.
- **Link check** (`.github/workflows/links.yml`). [lychee](https://github.com/lycheeverse/lychee) checks every link in the README, docs, `shared/` and skills, internal anchors included. 403 and 429 count as OK, because some sites block CI runners or rate-limit them. A failing run opens one issue labelled `broken-links`, or updates it if it's already open. The next clean run closes it. The check doesn't block PRs, since external sites break on their own schedule. Run it on demand from the Actions tab (`workflow_dispatch`).

[Dependabot](../.github/dependabot.yml) opens one grouped PR a week against `development` for the SHA-pinned actions. Those PRs skip the version-bump check, and the pin changes ship with the next versioned release. Dependabot doesn't see the SkillSpector commit (`SKILLSPECTOR_REF`) or the Claude Code CLI version (`CLAUDE_CODE_VERSION`) in `ci.yml`; bump those by hand, deliberately.

## SkillSpector

[NVIDIA SkillSpector](https://github.com/NVIDIA/SkillSpector) (Apache-2.0) is a static and LLM-assisted scanner for agent skills. It looks for prompt injection, excessive agency, credential access, exfiltration patterns, hidden Unicode and similar problems. CI installs it pinned to a commit (v2.13.1, `f3b2569…`) and runs it in static-only mode (`--no-llm`). That keeps results reproducible and keeps skill content off third-party APIs. The one network call SkillSpector makes is its supply-chain check, which sends dependency names to OSV.dev. These skills declare no dependencies.

### Why CI scans skill by skill

SkillSpector rejects `--baseline` (and `--use-shipped-baseline`) on recursive multi-skill scans, where it exits with code 2. It also reports paths relative to the skill it scanned (`SKILL.md`), so a single repo-wide rule couldn't tell one skill from another. CI handles this in three steps:

1. Rules in [`.skillspector-baseline.yaml`](../.skillspector-baseline.yaml) are keyed by `path: "<skill>/<file>"`, e.g. `prompt-injection/SKILL.md` or `log-watch/references/detections.md`. `<skill>/*` covers every file in one skill. A finding that comes from a build-copied `shared/` file repeats in every skill holding the copy, so those rules use `*` as the skill segment: `*/references/findings-format.md`. The checker only allows a `*` skill segment on `*/references/<file that exists in shared/>` or `*/SKILL.md`, with a message of at least 8 literal characters.
2. For each skill, [`.github/scripts/skillspector-baseline.mjs`](../.github/scripts/skillspector-baseline.mjs) `<skill>` emits that skill's rules with the prefix removed. CI then scans `skills/<skill>/` against them. As a result, a rule written for `prompt-injection` can never hide a finding in another skill.
3. The per-skill SARIF files are merged by [`.github/scripts/merge-sarif.mjs`](../.github/scripts/merge-sarif.mjs), which rewrites paths to `skills/<skill>/SKILL.md` and gives each run its own category. The merged file is then uploaded to GitHub code scanning. Uploads are skipped for PRs from forks, because those can't get `security-events: write`. The pass/fail gate still runs.

### The baseline

The skills teach attack and defense, so they quote payloads on purpose: prompt-injection test strings, IMDS addresses for SSRF denylists, `/etc/passwd` traversal probes, `privileged: true` pod specs, and code blocks labelled VULNERABLE. A static scanner flags all of that.

The baseline was first built from a real `--no-llm` scan at the v1.4 cut (45 matches across 14 skills). It was re-triaged at v1.19.1 against the integrated 35-skill catalog: 221 matches across 21 skills, covered by 117 rules (8 of them `*` rules for shared copies). Every match was triaged by hand. All of them are intentional teaching examples, detection guidance, attribution links, or the skill's own read-only audit targets (for example `agent-supply-chain-audit` and `personal-opsec` inventory `~/.claude/settings.json` and `~/.aws/credentials` because that is the audit). None is an instruction to the agent. Each is covered by a narrow rule with a written reason.

Two kinds of entry are worth knowing about:

- **AE1 (incomplete referenced-artifact analysis)** for `references/to-sarif.mjs` and `references/validate-coverage.mjs`. SkillSpector's bounded static parser hits its span budget on the template-literal error messages in these plain-JS helpers. The files were reviewed by hand; they do no network or process work. The scan report still shows partial coverage for those skills, and CI does not pass `--fail-on-incomplete`.
- **RP1 (unpinned `npx` / untagged `docker run`)**. The skills describe these as anti-patterns to flag. The shipped workflow template in `scanner-pipeline` pins every image by `@sha256` on the line after `docker run`, which the scanner doesn't join.

Baseline rules follow this policy:

- **Glob rules only, always with `id` + `path` + `message`.** Exact fingerprints break whenever a line moves. Wildcard-only rules would hide new findings. The checker rejects both a missing `message` and a `*`-only value.
- **Every rule has a `reason`.** It shows up as the suppression justification in SARIF.
- **New findings fail CI.** For each one, either fix the skill or add a rule with a reason in the same PR, so the rule gets reviewed with the change that caused it.

To see what's suppressed for one skill:

```bash
node .github/scripts/skillspector-baseline.mjs prompt-injection > /tmp/pi-baseline.json
skillspector scan skills/prompt-injection --no-llm --baseline /tmp/pi-baseline.json --show-suppressed
```

### Scanning before you install

You don't have to trust our baseline. To scan the whole catalog yourself, with no suppressions:

```bash
uv tool install git+https://github.com/NVIDIA/SkillSpector.git
skillspector scan https://github.com/briiirussell/cybersecurity-skills --recursive --no-llm
```

Leave out `--no-llm` if you've configured a provider and want the semantic analyzers too. Expect the skills listed in the baseline to show findings in an unsuppressed scan, and `prompt-injection` to score CRITICAL. Compare what you see against the reasons in `.skillspector-baseline.yaml`.

On shipped baselines: SkillSpector only applies an author-shipped baseline when you opt in with `--use-shipped-baseline`. Even then, it reads only a `.skillspector-baseline.yaml` at the top level of the **single skill** being scanned. It never applies one in a recursive scan. This repo keeps its baseline at the repo root and doesn't ship per-skill copies, so an installer's scan is always unsuppressed unless they pass our rules in explicitly, as shown above.

## `allowed-tools` is pre-approval, not a sandbox

In Claude Code, a skill's `allowed-tools` frontmatter lists tools that run **without a permission prompt** during the turn that invokes the skill. It doesn't stop the skill from using any other tool. Unlisted tools still work, and your normal permission settings decide whether you're prompted for them. Workspace trust doesn't gate this field either. See the [Claude Code skills docs](https://code.claude.com/docs/en/skills) and [permissions docs](https://code.claude.com/docs/en/permissions).

So a broad grant like plain `Bash` lets an invoked skill run any shell command without asking you. The risk is highest when that's paired with `WebFetch`, because fetched content an attacker controls could steer the agent into running commands with no prompt in between.

Rules for this repo:

- Start from `Read, Grep, Glob`.
- Add `Bash` only scoped to a specific, read-only command prefix, e.g. `Bash(trivy fs:*)` or `Bash(dig:*)`. For commands with a destructive sub-mode, use exact rules with no wildcard, e.g. `Bash(npm audit --json)` rather than `Bash(npm audit:*)`, which would also match `npm audit fix --force`. Claude Code already runs `grep`, `cat`, `ls`, `stat` and read-only `git` without a prompt, so those don't need grants.
- Never pre-approve active scanning or exploitation against a target (`nmap`, `curl`, `sqlmap`, `testssl.sh`, `ffuf`), history rewrites (`git filter-repo`, `bfg`), live-credential checks, or anything that changes state. Those should prompt every time, so the user confirms the target and authorization.
- Never pair `WebFetch` with unscoped `Bash`. The lint enforces this.
- The lint also fails any `Bash` grant that would pre-approve a write (`scripts/grant-check.mjs`, since v1.19.11):
  - unscoped `Bash`
  - a write verb in the rule itself (`delete`, `rollback`, `set`, `--fix`, ...)
  - a prefix that also matches a known destructive command. `Bash(heroku releases:*)` also matches `heroku releases:rollback`, so use `Bash(heroku releases -a:*)`.
  - a wildcard on a bare multi-command CLI (`git:*`, `vercel:*`, `aws:*`)
  - a wildcard on a tool that rewrites source files with a flag (`semgrep:*` allows `semgrep --autofix`)
  - a wildcard on a command where a trailing flag turns a read into a write (`gh api`, `exiftool`, `floss`)
  - a secret scanner that can check found keys with their providers (`trufflehog`, `betterleaks`): any wildcard, and an exact rule that verifies (trufflehog without `--no-verification`; betterleaks with `-v`, `-a`, `validate` or `analyze`). Checking a key uses it, so it always prompts

  When a skill starts using a new CLI, add its destructive subcommands to `DESTRUCTIVE_COMMANDS` in that file. Report-file flags (`--output`, `--report-path`) aren't checked; nearly every scanner has one, and they write a new report rather than change the project.
- Add `Write` only if the skill's main output is a file it has to write.

### v1.4 changes (potentially breaking)

If you relied on the old grants to run commands without prompts, you'll now see permission prompts for those commands. To restore any of them, add allow rules to your own `.claude/settings.json`.

| Skill | Before | After | Why |
|---|---|---|---|
| `ai-risk-management` | `Read, Grep, Glob, Bash, Write, WebSearch` | `Read, Grep, Glob, WebSearch` | Runs no commands; output is an assessment in chat |
| `api-audit` | `Read, Grep, Glob, Bash, Write` | `Read, Grep, Glob` | Static review via Grep; curl repros against a live API should prompt |
| `breach-patterns` | `Read, Grep, Glob, Bash, WebSearch, WebFetch` | `Read, Grep, Glob, WebSearch, WebFetch` | Runs no commands; removes the WebFetch→shell path |
| `cloud-audit` | `Bash, Read, Write, Grep, Glob, WebSearch` | `Read, Grep, Glob, WebSearch` + 11 read-only cloud CLI prefixes (`aws iam get-account-summary`, `aws iam list-users`, `aws iam get-credential-report`, `aws s3api list-buckets` / `get-public-access-block` / `get-bucket-policy` / `get-bucket-encryption`, `gcloud projects get-iam-policy`, `gcloud iam service-accounts list`, `az role assignment list`, `az ad user list`) | Only the read-only calls the skill documents; `generate-credential-report` and anything mutating prompt |
| `container-audit` | `Bash, Read, Write, Grep, Glob, WebSearch` | `Read, Grep, Glob, WebSearch, WebFetch, Bash(trivy image:*), Bash(trivy config:*), Bash(kube-bench run:*)` | Read-only scanners it runs; `kubectl` and `xargs`/`sh -c` pipelines prompt; `WebFetch` reads the Red Hat Security Data API for vendor severity (OSV queries are POSTs through `curl`, which prompt) |
| `crypto-audit` | `Read, Grep, Glob, Bash, WebSearch` | `Read, Grep, Glob, WebSearch` | Code review via Grep; `testssl.sh`/`curl` against a target should prompt |
| `csf-mapping` | `Read, Grep, Glob, Bash, WebSearch` | `Read, Grep, Glob, WebSearch` | Runs no commands |
| `dependency-audit` | `Bash, Read, Write, Grep, Glob, WebSearch` | `Read, Grep, Glob, WebSearch, WebFetch, Bash(npm audit), Bash(npm audit --json), Bash(npm audit --omit=dev), Bash(npm audit --omit=dev --json), Bash(npm ls:*), Bash(npm view:*), Bash(npm outdated:*), Bash(pnpm audit --prod), Bash(pnpm audit --prod --json), Bash(pnpm why:*), Bash(yarn audit --groups dependencies --json), Bash(yarn npm audit:*), Bash(yarn why:*), Bash(osv-scanner scan:*), Bash(govulncheck:*), Bash(bundle audit:*), Bash(composer audit:*), Bash(dotnet list package:*), Bash(trivy fs:*), Bash(trivy image:*)` | Read-only auditors; `npm`/`pnpm`/`yarn` audits use exact rules so `npm audit fix --force` / `pnpm audit --fix` always prompt; `*-why`/`ls`, `npm view`/`npm outdated` (for the Latest column) and `osv-scanner scan` are read-only; `pip-audit --fix`/`cargo audit fix` can modify files, so they prompt; `WebFetch` reads the public KEV, EPSS and OSV feeds (Step 2b). The OSV batch POST goes through `curl`, which prompts |
| `disk-forensics` | `Bash, Read, Write, Grep, Glob` | `Read, Grep, Glob, Bash(file:*), Bash(sha256sum:*), Bash(fdisk -l:*), Bash(mmls:*), Bash(fsstat:*), Bash(fls:*), Bash(icat:*), Bash(strings:*)` | Read-only evidence tools; `mount` (needs root) and `exiftool` (can write metadata to evidence) prompt |
| `finding-triage` | `Read, Grep, Glob, Bash, WebSearch` | `Read, Grep, Glob, WebSearch` | Runs no commands |
| `hipaa-audit` | `Read, Grep, Glob, Bash, Write, WebSearch` | `Read, Grep, Glob, WebSearch` | Grep patterns run via the Grep tool |
| `iam-audit` | `Bash, Read, Write, Grep, Glob, WebSearch` | `Read, Grep, Glob, WebSearch` + `aws accessanalyzer list-findings`, `aws iam get-account-authorization-details`, `gcloud asset analyze-iam-policy`, `gcloud policy-intelligence query-activity`, `az role assignment list` | Read-only IAM queries it documents |
| `incident-triage` | `Bash, Read, Write, Grep, Glob, WebSearch` | `Read, Grep, Glob, WebSearch, Bash(ps:*), Bash(netstat:*), Bash(lsof:*), Bash(who:*)` | Live-response reads; `journalctl` prompts because `--vacuum-*`/`--rotate` destroy evidence |
| `mobile-audit` | `Bash, Read, Write, Grep, Glob, WebSearch` | `Read, Grep, Glob, WebSearch` | Tools are listed, not scripted; decompilers write output and should prompt |
| `osint-recon` | `Bash, WebSearch, WebFetch, Read, Write` | `Read, WebSearch, WebFetch, Bash(whois:*), Bash(dig:*)` | Passive lookups only next to WebFetch; `curl` prompts |
| `owasp-audit` | `Read, Grep, Glob, Bash, Write` | `Read, Grep, Glob, Bash(npm audit), Bash(npm audit --omit=dev)` | Exact `npm audit` rules; fixes go through Edit with a prompt |
| `pci-audit` | `Read, Grep, Glob, Bash, Write, WebSearch` | `Read, Grep, Glob, WebSearch` | Grep patterns run via the Grep tool |
| `privacy-engineering` | `Read, Grep, Glob, Bash, Write, WebSearch` | `Read, Grep, Glob, WebSearch` | Grep patterns run via the Grep tool |
| `prompt-injection` | `Read, Grep, Glob, Bash, Write, WebSearch` | `Read, Grep, Glob, WebSearch` | Runs no commands; it handles injection payloads, so it gets the least |
| `recon` | `Bash, Read, Write, WebSearch, WebFetch` | `Read, WebSearch, WebFetch, Bash(whois:*), Bash(dig:*)` | Passive lookups only; `nmap`, `curl` and directory brute-forcing prompt so each target is confirmed |
| `red-team-engagement` | `Read, Write, Bash, Grep, Glob, WebSearch` | `Read, Grep, Glob, WebSearch` | Planning skill; runs no commands |
| `secrets-audit` | `Bash, Read, Write, Grep, Glob, WebSearch` | `Read, Grep, Glob, WebSearch` + exact Betterleaks rules: `version`, `config show ids --validation/--analysis`, and the detection-only default scan (`git . --validate=false --analyze=false --redact --silent -o .security/out/betterleaks.json`) | grep and `git log` are already prompt-free; history rewrites and live-key checks (`-v`, `-a`, `validate`, `analyze`) prompt. `trufflehog git:*` removed in 1.1.5: trufflehog verifies found keys with their providers by default, which uses them |
| `security-comms` | `Read, Write, WebSearch` | `Read, WebSearch` | Output is text in chat |
| `siem-detection` | `Read, Write, Bash, Grep, Glob, WebSearch` | `Read, Write, Grep, Glob, WebSearch` | Keeps `Write`: main output is detection-as-code rule files; runs no shell commands |
| `soc-operations` | `Read, Write, Grep, Glob, WebSearch` | `Read, Grep, Glob, WebSearch` | Output is text in chat |
| `threat-hunting` | `Read, Write, Bash, Grep, Glob, WebSearch` | `Read, Grep, Glob, WebSearch` | Hunt queries run in the SIEM, not the shell |
| `threat-modeling` | `Read, Write, Grep, Glob, WebSearch` | `Read, Grep, Glob, WebSearch` | Output is the model in chat |
| `vuln-research` | `Read, Grep, Glob, Bash, WebSearch, WebFetch` | `Read, Grep, Glob, WebSearch, WebFetch, Bash(npm ls:*), Bash(pip show:*), Bash(bundle info:*), Bash(go list:*)` | Read-only package queries next to WebFetch; `git tag --contains` is already prompt-free |
| `web-pentest` | `Bash, Read, Write, WebFetch, WebSearch` | `Read, Grep, Glob, WebSearch, WebFetch` | Every active test (`curl`, `ffuf`, `sqlmap`, `nuclei`) hits a target and should prompt; Grep/Glob added for white-box mode |

### Skills added in v1.4–v1.19

These shipped with scoped grants from the start (no "before"):

| Skill | `allowed-tools` | Why |
|---|---|---|
| `agent-supply-chain-audit` | `Read, Grep, Glob, Bash(skillspector scan --no-llm:*)` | Reads agent configs, skills and MCP manifests; the only command is a static, local SkillSpector scan (`--no-llm` keeps content off third-party APIs) |
| `business-logic-testing` | `Read, Grep, Glob` | Race / workflow tests hit the authorized target, so every request prompts |
| `log-watch` | `Read, Grep, Glob, Write` | `Write` because the main output is the `log-watch.md` plan (plus an optional scaffolded job); log/API queries prompt |
| `patch-sweep` | `Read, Grep, Glob, WebFetch` + `gh repo list/view`, `git log/ls-remote`, `vercel project ls/inspect`, `vercel ls/inspect/domains ls`, `heroku apps/releases/stack` | Read-only inventory of the user's repos and PaaS projects; deploys, upgrades and PRs prompt. `git branch:*` removed in 1.19.2 (it also matched `git branch -D`). `WebFetch` reads the public KEV and EPSS feeds once per sweep |
| `personal-opsec` | `Read, Grep, Glob` + read-only OS status checks (`fdesetup status`, `socketfilterfw --getglobalstate/--getstealthmode`, `scutil --dns`, `spctl --status`, `csrutil status`, `sw_vers`, `manage-bde -status`, `lsblk`, `resolvectl status`), `which`, `ls -l`, `gh auth status`, `whois` | Checks the user's own machine without changing it; anything needing `sudo` or changing a setting prompts |
| `scanner-pipeline` | `Read, Grep, Glob, Write` + `gitleaks`, `checkov`, `bundle-audit`, `brakeman`, `gosec`, `govulncheck` (`:*`), `osv-scanner scan:*`, `trivy fs/image/config:*`, `gh repo list:*` | `Write` because the main output is the workflow + config files; scanners run locally against the user's own repo. 1.19.2 narrowed `osv-scanner` to `scan` (not `fix`) and `trivy` to its scan subcommands, and dropped `semgrep` and `pip-audit` (`--autofix` / `--fix` rewrite files and a prefix rule can't exclude a trailing flag), so those prompt. 1.0.5 dropped `trufflehog:*`: its verification sends found keys to their providers. 1.1.0 added exact Betterleaks rules: `version` and the detection-only default scan |

## Cursor and Codex adapters carry no tool restrictions

`scripts/build-adapters.mjs` drops `allowed-tools` when it generates `adapters/cursor/*.mdc` and `adapters/codex/*.md`. Neither format has an equivalent field. In those agents, the host's own approval settings decide what runs: Cursor's auto-run / allowlist settings and Codex's approval mode and sandbox. Set those before you use the offensive skills (`recon`, `web-pentest`, `osint-recon`, `red-team-engagement`).

## README snippet (for the coordinator)

Badge:

```markdown
[![CI](https://github.com/briiirussell/cybersecurity-skills/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/briiirussell/cybersecurity-skills/actions/workflows/ci.yml)
```

Section:

```markdown
## Security scanning

Every PR is linted and scanned with [NVIDIA SkillSpector](https://github.com/NVIDIA/SkillSpector) (static mode, pinned version).
Intentional example payloads are suppressed by narrow, reasoned rules in
[`.skillspector-baseline.yaml`](.skillspector-baseline.yaml). Scan it yourself before installing:

    skillspector scan https://github.com/briiirussell/cybersecurity-skills --recursive --no-llm

Our baseline is never applied to your scan; SkillSpector only uses an author-shipped baseline for a single skill
with `--use-shipped-baseline`. `allowed-tools` lists tools pre-approved to run without a prompt in Claude Code — it is
not a sandbox — and the Cursor/Codex adapters carry no tool restrictions at all. Details: [docs/security-scanning.md](docs/security-scanning.md).
```
