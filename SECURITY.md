# Security Policy

This repo is a set of instructions that AI agents follow, so a bug here can look different from a bug in ordinary code. If a skill could lead an agent to do something unsafe, I want to hear about it.

## Reporting a vulnerability

Please report privately through **[GitHub private vulnerability reporting](https://github.com/briiirussell/cybersecurity-skills/security/advisories/new)** (Security tab → Report a vulnerability). Don't open a public issue for anything in scope below.

Include the skill, the file and line, what the agent did or could be led to do, and a minimal prompt or setup that shows it. Please don't include real credentials or data from systems you don't own.

I'm one maintainer, so these are targets, not guarantees:

- acknowledgement within 3 business days
- an assessment within 10 business days
- a fix, or a plan with a date, for anything confirmed

Fixes ship as their own version (see [VERSIONS.md](VERSIONS.md)), with a GitHub security advisory crediting you unless you'd rather not be named.

## In scope

- **Over-broad `allowed-tools` grants.** A grant that pre-approves a write, a destructive subcommand, or a command that can rewrite files, without a prompt. Example: a `Bash(...)` prefix that also matches a `delete` or `--fix` mode the lint in `scripts/grant-check.mjs` misses.
- **Unsafe instructions.** A skill that tells an agent to run active scans, exploits, history rewrites or state changes without the authorization check, or to send code, secrets or findings to a third party.
- **Prompt injection in skill content.** Text in a `SKILL.md`, `references/` file, `shared/` file or example that an agent could read as an instruction it shouldn't follow, including hidden Unicode.
- **Supply chain.** Anything that lets someone change what users install: the plugin manifests in `.claude-plugin/`, the build in `scripts/build-adapters.mjs`, the generated `adapters/`, or the GitHub Actions workflows.
- **Bundled scripts.** Bugs in `shared/validate-findings.mjs`, `shared/to-sarif.mjs` and the other scripts copied into skills, when they run on untrusted input.

## Out of scope

- Vulnerabilities in third-party tools a skill mentions (semgrep, trivy, Burp, ...). Report those upstream.
- A skill giving incomplete or outdated security advice. That's a regular bug: open a [field report](https://github.com/briiirussell/cybersecurity-skills/issues/new/choose).
- Findings in the deliberately vulnerable snippets used as examples or test fixtures, as long as they're clearly marked as examples.
- An agent ignoring a skill's instructions. That's the agent's behavior, though a skill that makes it easy is in scope.
- Reports that need the user to have already granted unscoped `Bash` or similar permissions themselves.

## Supported versions

Only the latest release on `main` gets fixes. Skills are installed by copying, so to pick up a fix, run your install command again (see [Installation](README.md#installation)).
