# dependency-audit

> Audit project dependencies, frameworks, languages, and dev tools for known vulnerabilities, CVEs, and security anti-patterns. Use when the user mentions 'dependency audit,' 'npm audit,' 'CVE,' 'vulnerable packages,' 'supply chain security,' 'outdated dependencies,' 'known vulnerabilities,' 'security advisory,' 'package security,' 'framework vulnerability,' 'is this package safe,' 'pnpm audit,' 'yarn audit,' 'bundle audit,' 'patch this CVE,' 'audit fix broke,' 'lockfile diff,' 'dependency confusion,' 'registry redirection,' 'MCP server pinning,' 'release pipeline,' or needs to check whether their stack, CI, or release pipeline has known security issues.

# Dependency Audit — Framework, Package, and Toolchain Security

Audit project dependencies, frameworks, language runtimes, and dev tools for known vulnerabilities (CVEs), security anti-patterns, and supply chain risks.

Cross-references: `patch-sweep` for patching the same advisory across many repos; `scanner-pipeline` for running osv-scanner / trivy in CI across every lockfile at once; `agent-supply-chain-audit` for reviewing the content of MCP servers, skills, and plugins this skill inventories; `cloud-audit` "PaaS" for platform runtime and config checks behind `Mitigated (platform/config)`; `secrets-audit` for tokens found in `.npmrc` or CI; `iam-audit` for the cloud roles CI assumes via OIDC; `cicd-security` for workflow and runner security; `finding-triage` for dispositioning individual findings.

## Authorization

Confirm the user owns or is authorized to audit the repo, CI system, and registries before running anything. Audit tools are read-only, but fix commands (`audit fix`, `bundle update`) rewrite lockfiles. Run them only when asked, on a branch, never on the production branch directly.

## Methodology

### Step 0: Confirm What Ships

Before inventorying anything, confirm you are auditing the code that is actually deployed:
- **Production branch:** the branch the platform or deploy workflow builds from (Vercel/Netlify production branch, Heroku pipeline, `on: push: branches:` in the deploy workflow). It is not always `main`. In one field sweep, `main` held only a README.
- **Monorepos:** which app or package is deployed, and its lockfile or workspace slice.
- **Package manager:** which lockfile is committed and the `packageManager` field. This decides the audit command in Step 2.

If the deployed branch can't be confirmed from the repo, say which branch you audited and mark it `needs_validation`. Details: [references/fixing-safely.md](references/fixing-safely.md) §10.

### Step 1: Inventory the Stack

Identify everything in use — not just direct dependencies but the full chain:

**Package manifests — read and catalog:**
```
Node/JS:    package.json, package-lock.json, yarn.lock, pnpm-lock.yaml
Python:     requirements.txt, Pipfile.lock, pyproject.toml, poetry.lock
Ruby:       Gemfile, Gemfile.lock
Go:         go.mod, go.sum
Rust:       Cargo.toml, Cargo.lock
Java:       pom.xml, build.gradle
PHP:        composer.json, composer.lock
.NET:       *.csproj, packages.config
```

**Framework and runtime versions:**
- Check framework version (Next.js, Django, Rails, Spring, Laravel, Express, etc.)
- Check language/runtime version (Node.js, Python, Ruby, Go, Java, PHP, .NET)
- Check infrastructure tools (Docker base images, Terraform providers, Kubernetes versions)

**Dev tools and CI/CD:**
- Check CI/CD pipeline configs (.github/workflows, .gitlab-ci.yml, Jenkinsfile)
- Check pre-commit hooks, linters, formatters
- Check container base images and their update status
- Check IaC tool versions (Terraform, Pulumi, CDK)

**Agent extensions** (code a coding agent loads and runs at launch):
- MCP server configs: `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`. Record each server's `command` + `args` (or `url` for remote servers) and whether the version is pinned.
- Installed skills and agent rules: `SKILL.md` folders, `.claude/agents/`, `.claude/commands/`, `.cursor/rules/*.mdc`, `AGENTS.md`
- Plugin marketplaces and enabled plugins: `extraKnownMarketplaces`, `enabledPlugins`, `enableAllProjectMcpServers` in `.claude/settings*.json`
- Inventory and pinning only here. Defer review of what the extension tells the agent to do to `agent-supply-chain-audit`. Greps: [references/source-redirection.md](references/source-redirection.md) §2.

**Edge cases in package manifests:**
- `optionalDependencies` — installed but not audited by default
- `peerDependencies` — version range may not match what's installed
- `overrides` / yarn `resolutions` / pnpm `overrides` — check if used to *silence* advisories rather than fix them
- Monorepos: read every `packages/*/package.json` and `apps/*/package.json`, not just the root
- `engines` field — older-than-LTS Node makes other audits moot

### Step 2: Run Automated Audit Tools

Run the appropriate audit command for the project:

```bash
# Node.js
npm audit --json                # full structured output
npm audit --omit=dev --json     # production-only: filters dev/build-time vulns
# Compare the two — vulns only in dev/build tooling do not ship to users
# and should be triaged as lower priority. Don't bury this in the report.

# pnpm / yarn — use their own audit; npm audit in a pnpm or yarn repo has no
# package-lock.json and fails or audits the wrong tree without a clear error
pnpm audit --prod --json                       # use the pnpm major matching the lockfile (corepack)
yarn audit --groups dependencies --json        # yarn v1
yarn npm audit --environment production -R     # yarn Berry (v2+)

# Python
pip audit          # If pip-audit installed
safety check       # If safety installed

# Ruby
bundle audit

# Go
govulncheck ./...

# Rust
cargo audit

# PHP
composer audit

# .NET
dotnet list package --vulnerable

# Docker
docker scout cves <image>
trivy image <image>

# General (if Trivy is available)
trivy fs .
```

**Applying fixes — read before you `--force`:**

```bash
npm audit fix                   # safe: upgrades within stated ranges
npm audit fix --dry-run --force # ALWAYS dry-run first
npm audit fix --force           # only after reviewing the dry-run
```

`npm audit fix --force` can resolve an advisory by DOWNGRADING a package to an older version that doesn't trigger the audit signature. This is almost always wrong (e.g. downgrading `next@16` to `next@9` to "fix" a transitive postcss CVE). Inspect dry-run output for "Will install X@Y, which is a breaking change" — that's the tool trying to downgrade.

**When `npm audit fix` cannot resolve an advisory** (transitive dep pinned by an upstream package):

1. **Determine reachability** — is the vulnerable code path actually invoked in your usage? `npm ls <package>` + reading the parent's source can rule it out as unreachable.
2. **Consider a `package.json` `overrides` pin** to a patched version (test thoroughly — overrides can break the parent).
3. **Consider swapping the parent provider entirely.**
4. **If none apply:** document explicitly, track upstream, and note in the audit report rather than silently dropping the finding.

**Package-manager traps that pass the build but break at runtime** (open-ended `>=` overrides from `pnpm audit --fix`, duplicated singletons, exact pins in a parent blocking the fix, a raised `engines` floor): [references/fixing-safely.md](references/fixing-safely.md).

**Verify after fixing** ([checklist with commands](references/fixing-safely.md)): advisory gone on re-audit, not suppressed; no downgrades or major jumps in the lockfile diff; no duplicate singletons; engines floor met; clean frozen install; full tests, then a preview smoke test of the features those packages power.

### Step 2b: Enrich with Exploitation Signals

For every advisory, check **CISA KEV** (exploited now) and **EPSS** (likely in 30 days), via its CVE id (OSV `aliases` maps a GHSA id). They set the order of work, never severity above impact. Offline: `not checked`; never infer KEV from memory. No scanner? Use the OSV batch API. Commands, fallback, `ext` keys: [references/exploitation-signals.md](references/exploitation-signals.md).

### Step 3: Research Framework-Specific Known Issues

Beyond CVEs in packages, check for known vulnerability patterns specific to the framework in use. Search for recent advisories and common misconfiguration issues. Runtime defaults that widen a kernel CVE's reach (Go ≥ 1.24 listens with MPTCP) are in [references/runtime-exposure.md](references/runtime-exposure.md).

For every direct dependency, cross-reference the installed version against:
- `https://github.com/advisories?ecosystem=npm&query=<package>`
- `https://github.com/<org>/<repo>/security/advisories`

The framework-specific patterns below cover *evergreen* anti-patterns (mass assignment, debug-in-prod, etc.). Recent CVEs need a fresh check because hardcoded advisory lists rot fast and LLM training data is often 6+ months behind the latest.

**Runtime and framework upgrades** (detail in [references/fixing-safely.md](references/fixing-safely.md) §6–9):
- **Move every runtime pin together.** Ruby: `.ruby-version`, Gemfile `ruby`, `Gemfile.lock` `RUBY VERSION`, Dockerfile `ARG`/`FROM`, CI image, buildpack/stack. Node: `.nvmrc`, `.node-version`, `engines`, Dockerfile, CI `node-version`, platform setting. One missed pin keeps the vulnerable runtime running there.
- **Ruby gotchas:** `bundle update --conservative <gem>` can still jump a shared dependency a major (`json` 2→3 broke `httparty` at runtime), so constrain it (`~> 2.21`). To pin without a permanent Gemfile change, tighten the constraint, resolve, then restore it; Bundler keeps the locked version. Brakeman fails CI when it isn't the latest release, so expect a red patch PR. Patch-level Rails releases can still break specs.
- **No in-place fix exists** when the framework or runtime line gets no backport (an out-of-support Next.js major, an EOL Ruby minor). Report it as `Requires major migration` with the minimum fixed version and an effort estimate, not next to one-command fixes.
- **Platform or config mitigation** can be the right answer: a config flag that blocks the vulnerable path (for example, libvips `VIPS_BLOCK_UNTRUSTED=1`, which only exists in libvips ≥ 8.13), or a managed runtime that patches itself (Vercel-managed Node). Record it as `Mitigated (platform/config)` with the control, where it's set, the version prerequisite, and how it was verified. Unverified platform state is `needs_validation`.

**Next.js / React:**
- Server Actions exposing internal endpoints (pre-14.1.1 middleware bypass CVE-2025-29927)
- `dangerouslySetInnerHTML` without sanitization
- SSRF through image optimization (`next/image` with unrestricted domains)
- Exposed `.env` files in public directory or client bundle (`NEXT_PUBLIC_` prefix leaking secrets)
- Middleware auth bypass patterns — check middleware.ts matches all protected routes
- Server Component / Client Component boundary leaking server-only data:
  - Any module reading `process.env.SECRET` or instantiating a DB client should start with `import "server-only";` — fails the build if imported from a Client Component
  - Grep for: files in `lib/` that touch `process.env.[A-Z_]+` but do NOT import `server-only`
  - Inverse check: any file with `"use client"` importing from such a module is a leak
- Outdated `next.config.js` security headers

**Django:**
- DEBUG=True in production
- ALLOWED_HOSTS misconfigured (wildcard `*`)
- Missing CSRF middleware or `@csrf_exempt` on state-changing views
- Raw SQL via `extra()`, `raw()`, or `RawSQL` without parameterization
- Pickle deserialization in sessions (use JSON serializer)
- Secret key committed to source control

**Rails:**
- Mass assignment without strong parameters
- SQL injection via `where("column = '#{input}'")`
- Unpatched Action Pack, Action View, or Active Record CVEs
- Insecure deserialization in cookies (verify secret_key_base rotation)
- CSRF token bypass in API-only mode

**Express / Node.js:**
- Prototype pollution through `Object.assign`, `lodash.merge`, `deep-extend`
- ReDoS (Regular Expression Denial of Service) in validation patterns
- Path traversal through `req.params` in file serving routes
- Missing rate limiting on auth endpoints
- `eval()` or `Function()` with user input
- Event loop blocking with synchronous operations

**Serverless / edge runtimes (Vercel, Lambda, Cloud Run, Workers):**
- **In-memory state ≠ rate limit.** A module-scoped `Map` or `Set` for rate limiting, sessions, or caches is per-instance. Cold starts reset state; load spreads across instances; attackers bypass trivially.
  - Grep for: `const rateLimitMap = new Map`, `const cache = new Map` in server-action / API-route files
  - Fix: shared store — Vercel KV, Upstash Ratelimit, Redis, DynamoDB
- **Unbounded in-memory collections** leak memory under traffic. Cap size and evict (LRU or FIFO).
- **`x-forwarded-for` trust:** only trustworthy when the edge overwrites it. Behind misconfigured proxy chains it's attacker-spoofable. A fallback to a single `"unknown"` bucket throttles all anonymous traffic together; random-fallback silently disables the limit.

**Spring / Java:**
- Spring4Shell and related RCE vulnerabilities
- Deserialization attacks (Java native serialization, Jackson polymorphic types)
- SpEL injection in Spring Expression Language
- Missing CSRF protection on state-changing endpoints
- Actuator endpoints exposed without authentication

**Laravel / PHP:**
- APP_DEBUG=true in production (leaks env vars in error pages)
- SQL injection via raw DB queries without bindings
- Mass assignment without `$fillable` / `$guarded`
- File upload without type validation (PHP execution via uploaded .php)
- Insecure deserialization in queued jobs

**WordPress:**
- Outdated core, theme, or plugin versions (most common attack vector)
- File editor enabled in wp-admin (allows code injection if admin is compromised)
- XML-RPC enabled (brute force amplification, SSRF)
- Default admin username, weak passwords
- Unpatched plugin vulnerabilities (check WPScan database)

### Step 4: Check for Supply Chain Risks

Beyond known CVEs, look for supply chain attack indicators:

**Dependency confusion / substitution:**
- Private package names that could be claimed on public registries
- Missing `.npmrc` or `pip.conf` scoping to private registry
- No lockfile integrity verification

**Package-source redirection** — any config, CLI call, or env var that adds or replaces where packages come from. Full per-ecosystem table and greps in [references/source-redirection.md](references/source-redirection.md) §1:

| Ecosystem | Surfaces to check |
|---|---|
| npm / pnpm | `.npmrc` `registry=` and `@scope:registry=`; `npm config set registry`; `--registry`; `NPM_CONFIG_REGISTRY` / `npm_config_registry` |
| Yarn | `.yarnrc` `registry`; `.yarnrc.yml` `npmRegistryServer`, `npmScopes.*.npmRegistryServer`, `unsafeHttpWhitelist`; `YARN_NPM_REGISTRY_SERVER` |
| pip / uv | `pip.conf` / `pip.ini` / requirements `--index-url`, `--extra-index-url`, `--trusted-host`; `PIP_INDEX_URL`, `PIP_EXTRA_INDEX_URL`; `UV_INDEX_URL`, `UV_EXTRA_INDEX_URL` |
| Poetry | `[[tool.poetry.source]]` and its `priority`; `poetry source add`; `POETRY_REPOSITORIES_<NAME>_URL` |
| Maven / Gradle | `settings.xml` `<mirrors>` / `<mirrorOf>`; `pom.xml` `<repositories>`; Gradle `repositories { maven { url } }`, init scripts |
| Cargo | `.cargo/config.toml` `[source.crates-io] replace-with`, `[registries.*]`; `CARGO_REGISTRIES_<NAME>_INDEX`, `CARGO_REGISTRY_DEFAULT` |

```bash
grep -rnE "registry\s*=|npmRegistryServer|(extra-)?index-url|trusted-host|<mirrorOf>|replace-with|NPM_CONFIG_REGISTRY|PIP_(EXTRA_)?INDEX_URL|CARGO_REGISTRIES_|poetry source add" \
  .npmrc .yarnrc .yarnrc.yml pip.conf pyproject.toml requirements*.txt settings.xml pom.xml .cargo/ .github/ Dockerfile* scripts/ 2>/dev/null
```

`PIP_EXTRA_INDEX_URL` / `--extra-index-url` is the classic dependency-confusion setup: pip queries every index and installs the highest version from any of them, so a public package with a private package's name and a higher version wins. A default-registry replacement pointing at a host the org doesn't control, over `http://`, or added in the PR under review is a candidate finding.

**Agent extensions (unpinned / unreviewed):** MCP server commands from the Step 1 inventory that fetch the latest version on every launch:
```bash
# npx -y pkg without @x.y.z, uvx/pipx pkg without ==, docker run image without a tag or digest
grep -nE '"(-y|--yes)",\s*"(@[a-z0-9._-]+/)?[a-z0-9._-]+(@latest)?"' .mcp.json .cursor/mcp.json .vscode/mcp.json 2>/dev/null
grep -nE '"(uvx|pipx)"' -A3 .mcp.json .cursor/mcp.json 2>/dev/null | grep -vE '==[0-9]'
grep -nE '"docker"' -A8 .mcp.json .cursor/mcp.json 2>/dev/null | grep -vE ':[0-9][^"]*"|@sha256:'
```
Pinned looks like `some-mcp-server@1.4.2`, `tool==0.9.1`, `image@sha256:...`. Hand each unpinned or unreviewed extension to `agent-supply-chain-audit` for content review.

**Shipped bytecode:** `.pyc` files tracked in git or packaged without a matching `.py` can run code nobody reviewed. `git ls-files | grep -E '\.py[co]$|__pycache__/'`, plus the no-matching-source check in [references/source-redirection.md](references/source-redirection.md) §3.

**Typosquatting:**
- Package names that are close misspellings of popular packages
- Recently published packages with very few downloads
- Packages that changed ownership recently

**Malicious packages:**
- Postinstall scripts that make network requests or execute code (`scripts.postinstall` in package.json)
- Packages with obfuscated code
- Excessive permission requests relative to functionality

**Maintenance risk:**
- Unmaintained packages (no commits in 2+ years, archived repos)
- Single-maintainer packages for critical functionality
- Packages with known but unpatched vulnerabilities (maintainer unresponsive)

**Lockfile integrity:**
- Lockfile committed? `git ls-files | grep -E 'package-lock\.json|yarn\.lock|pnpm-lock\.yaml|Gemfile\.lock|poetry\.lock|composer\.lock|Cargo\.lock|go\.sum'`
- CI installs from lockfile?
  - Check `.github/workflows/*.yml`, `.gitlab-ci.yml`, `Jenkinsfile`, `vercel.json`, `netlify.toml`, `Dockerfile`
  - `npm install` (bad) vs `npm ci` (good); `yarn install` (bad) vs `yarn install --immutable` (good); `pip install -r` (bad) vs `pip install --require-hashes -r` (good)
- `integrity` hashes present in the lockfile? (modern npm/pnpm yes by default)

### Step 5: Check Dev Tool and CI/CD Security

**GitHub Actions and other CI:** workflow security (pull_request_target, script injection, token permissions, SHA pinning, fork secrets, self-hosted runners, agents in CI) → `cicd-security`.

**Docker:**
- Running as root in container (missing `USER` directive)
- Base image with known CVEs (check with `trivy` or `docker scout`)
- Secrets baked into image layers (visible via `docker history`)
- `latest` tag instead of pinned version

**Terraform / IaC:**
- Hardcoded secrets in `.tf` files
- Unpinned provider versions
- Missing state file encryption
- Over-permissive IAM in provider configuration

### Step 5b: CI and Release Trust Handoffs

CI configuration is authorization code: it decides who can run what, with which credentials, against which targets. Most pipeline compromises go through a handoff, where a lower-trust job writes something a higher-trust job later restores, executes, or ships. Check each handoff below. Greps, validation rules, and reporting fields are in [references/ci-release.md](references/ci-release.md). Handoffs 1–4, 7 and 8 belong to `cicd-security`; this step keeps 5 and 6.

| # | Handoff | Starting grep (`.github/workflows/*.y*ml`) |
|---|---|---|
| 1 | `workflow_run` / `pull_request_target` restoring artifacts or caches into a privileged job | `grep -lE "workflow_run\|pull_request_target" … \| xargs grep -nE "download-artifact\|actions/cache\|gh run download"` |
| 2 | `actions/cache` keys or `restore-keys` an untrusted PR run can write | `grep -nE "actions/cache\|restore-keys:\|cache:\s*(npm\|yarn\|pnpm\|pip)"` |
| 3 | `permissions:` missing or `write-all`, **combined with** a privileged step an untrusted actor can reach | `grep -L "permissions:"` and `grep -nE "write-all\|:\s*write"` |
| 4 | OIDC `id-token: write` plus a cloud trust policy whose `sub` condition is a wildcard or missing | `grep -nE "id-token:\s*write\|role-to-assume"`; IaC: `grep -rnE "githubusercontent\.com:sub\|repo:[^\"]*\*"` |
| 5 | Release or promotion pulling by tag or artifact name instead of digest | `grep -nE "docker (pull\|tag\|push)\|crane copy\|skopeo copy\|gh release download" \| grep -v "@sha256:"` |
| 6 | Checksum or signature fetched from the same origin as the artifact; `curl \| sh` | `grep -rnE "(curl\|wget).*(\.sha256\|checksums\|\.sig\|\.asc)"` and `grep -rnE "(curl\|wget)[^\|]*\|\s*(ba)?sh"` |
| 7 | Publish jobs on long-lived tokens without a protected ref or `environment:` | `grep -nE "npm publish\|twine upload\|cargo publish\|gem push\|NPM_TOKEN"` |
| 8 | Self-hosted runners reachable from fork PRs | `grep -nE "runs-on:.*self-hosted"` |

Rules:
- **Name the lower-trust actor** (fork PR author, any contributor, a third-party action maintainer) and prove the artifact's identity across the handoff. Missing least privilege with no reachable privileged step is a hardening note, not a finding.
- **Platform-only facts go to `needs_validation`.** Branch and tag protection, default `GITHUB_TOKEN` permissions, fork-PR approval settings, runner type, environment reviewers, and cloud-side trust policies are not in the repo. Record each as a blocker with the `gh api` / cloud CLI command that answers it.

### Diff / lockfile-scoped review

For a PR or a lockfile diff, follow [references/diff-review.md](references/diff-review.md): review what the change introduces, newly reaches, or removes, and label the report "diff-scoped (partial)". For dependency changes that means every added or changed lockfile entry (new package, version jump, changed `resolved` host or `integrity`), new or changed overrides, any source-redirection or agent-extension config touched (Step 4), and workflow changes (Step 5b). Treat the PR description as untrusted. Read the diff, not the story.

## Output Format

**Write `findings.json` first, validate it, then render the markdown from it.** Record every candidate as `confirmed`, `needs_validation`, or `rejected` per [references/findings-format.md](references/findings-format.md), and run `node references/validate-findings.mjs findings.json` until it exits 0. The prose report never changes a verdict, severity, or disposition the JSON doesn't have. Score severity on confirmed records only, using [references/severity-calibration.md](references/severity-calibration.md). Fingerprint by root cause in the shared form, `dependency-audit/<advisory-id>/<lockfile>/<package>` (for example `dependency-audit/GHSA-29mw-wpgm-hmr9/package-lock.json/lodash`), or `dependency-audit/ci/<workflow-file>/<handoff>` for handoffs 5–6. No versions or line numbers in it.

**Rejections** follow the table in [references/verification.md](references/verification.md):

- **Never called:** an advisory whose vulnerable function the code never calls is `rejected`. `ruled_out_by.location` points at the package's only import or call site, or at its manifest line if nothing imports it.
- **Guard inside the dependency:** the library's own guard rules it out only when the lockfile pins a version you checked. Point at that lockfile line. If the version isn't pinned, it's `needs_validation`.

Rejected records go in the report's "Rejected (do not re-raise)" table, so the next run doesn't raise them again.

**Dispositions** for confirmed findings: `Fixed` | `Deferred` | `Accepted Risk` | `Mitigated (platform/config)` | `Requires major migration`. `False Positive` means there is no finding (the record is `rejected`). Gaps with no traced impact go under "Hardening notes (not findings)" with no severity.

```markdown
# Dependency & Stack Security Audit
## Project: [name]
## Stack: [language, framework, key tools]
## Date: [date]
## Scope: [full | diff-scoped (partial)] — branch/commit audited: [branch @ sha] (deployed branch confirmed: yes / needs_validation)
## Package manager + audit command: [e.g. pnpm 9, `pnpm audit --prod`]
## findings.json: [path] — validated: [yes]

### Stack Inventory
| Component | Version | Latest | Status |
|-----------|---------|--------|--------|
(include agent extensions: MCP servers, skills, plugins — source, version/commit, launch command)

Latest comes from `npm view <package> version` or `npm outdated --json` (both need network). In an offline run, write "not checked" rather than guessing.

### Known Vulnerabilities (CVEs)
| Package | Installed | Vuln | Severity | KEV | EPSS | Where reachable | CVE | Fix Version | Disposition |
|---------|-----------|------|----------|-----|------|-----------------|-----|-------------|-------------|

Where reachable values: `runtime` / `build-only` / `dev-only`. Confirm with `npm ls --omit=dev <package>` or inspect the deployment artifact (Vercel function bundle, Docker layer). Build- and dev-only vulnerabilities should not block a release on their own; runtime-reachable ones should.

A mutable or known-vulnerable dependency is not a finding by itself. To confirm it, show who can influence what gets resolved (or reach the vulnerable code), which build or runtime consumes it, and what boundary follows (user input reaching the vulnerable function, secrets in a build, a publish or deploy). Without that it is `needs_validation` (missing fact as the blocker) or a hardening note, not a severity-rated row.

Fix Version values: a version, **"Blocked by exact pin in `<parent>@<ver>`"** (+ scoped override or upstream issue link), or **"None on this line — Requires major migration to `<ver>` (effort S/M/L)"**. Never just "no fix available".
Disposition values: `Fixed` / `Deferred` / `Accepted Risk` / `Mitigated (platform/config)` (name the control, where it's set, its version prerequisite) / `Requires major migration`.

### Framework-Specific Issues
#### [SEVERITY] [Title]
**Component:** [framework/tool name and version]
**Issue:** [description]
**Evidence:** [code or config snippet]
**Remediation:** [specific fix]

### Supply Chain Risks
| Risk | Package/Component | Details | Remediation |
|------|-------------------|---------|-------------|

Risk types include: Dependency confusion, Source redirection (registry/index/mirror), Typosquat, Malicious install script, Unmaintained, Shipped bytecode without source, **Agent extension (unpinned / unreviewed)** — MCP server, skill, or plugin launched without a version pin or from an unreviewed source (hand content review to `agent-supply-chain-audit`).

### Dev Tool / CI Security
| Tool | Issue | Severity | Remediation |
|------|-------|----------|-------------|

For CI/release trust handoffs (Step 5b), each row names the lower-trust actor, the handoff object, the privileged consumer, and the boundary crossed. Platform facts not verified → `needs_validation` with the command that answers them.

### Needs Validation
| Candidate | Blockers | Validation plan |
|-----------|----------|-----------------|

### Hardening Notes (not findings)
- [gap with no traced impact, e.g. workflow without `permissions:` and no reachable privileged step — no severity]

### Rejected (do not re-raise)
| Fingerprint | Package | Ruled out by | Location |
|-------------|---------|--------------|----------|

### Prioritized Action Plan
1. KEV-listed, runtime-reachable: patch or mitigate now (CISA's due date is a ceiling, not the plan)
2. KEV-listed, build- or dev-only: patch this cycle; check CI runners and dev machines
3. Critical/High with EPSS above 0.7: patch this cycle
4. Remaining Critical/High (incl. supply chain risks), ordered by EPSS
5. Medium: framework misconfigurations, outdated dependencies
6. Low: maintenance risks, best-practice improvements
- Signals not checked: [advisories with no KEV/EPSS lookup, so the order above is partial]
```

## Boundaries

- Only audit code and configurations the user provides
- When identifying CVEs, verify they apply to the actual installed version
- Provide specific fix versions or remediation steps for every finding
- Note when a vulnerability requires specific conditions to exploit (reducing effective severity)
- Refuse to help exploit found vulnerabilities against unauthorized targets
- Don't run `audit fix`, `bundle update`, or other lockfile-rewriting commands unless asked, and never directly on the production branch
- Don't trigger, re-run, or modify CI workflows, publish packages, or assume cloud roles to "prove" a CI/release finding. Static evidence plus a validation plan for the owner is the bar

## References

- OWASP Dependency-Check
- National Vulnerability Database (NVD)
- GitHub Advisory Database
- CISA KEV, FIRST EPSS, OSV API: [references/exploitation-signals.md](references/exploitation-signals.md)
- Snyk Vulnerability Database
- npm audit / pip-audit / bundler-audit documentation
- SLSA (Supply-chain Levels for Software Artifacts) framework
- Cloudflare security-audit-skill, [`SUPPLY-CHAIN-AND-RELEASE.md`](https://github.com/cloudflare/security-audit-skill/blob/main/skills/security-audit/SUPPLY-CHAIN-AND-RELEASE.md) (MIT) — CI/release trust-handoff principles, paraphrased in [references/ci-release.md](references/ci-release.md)
- NVIDIA SkillSpector (Apache-2.0) — [dependency-source redirection](https://github.com/NVIDIA/SkillSpector/blob/main/docs/DEPENDENCY_SOURCE_REDIRECTION.md), [MCP rug-pull](https://github.com/NVIDIA/SkillSpector/blob/main/src/skillspector/nodes/analyzers/mcp_rug_pull.py), and [supply-chain patterns](https://github.com/NVIDIA/SkillSpector/blob/main/README.md#supply-chain-10-patterns), paraphrased in [references/source-redirection.md](references/source-redirection.md)
- Field notes from a 45-app CVE sweep (Rails/Heroku, Next.js/Vercel; npm, pnpm, yarn v1), October 2026 — [references/fixing-safely.md](references/fixing-safely.md)

## Reference files

This skill links to supporting files under `references/`. They are not inlined in this adapter; open them on GitHub (or in `skills/dependency-audit/references/` if you have the repo checked out):

- [references/ci-release.md](https://github.com/briiirussell/cybersecurity-skills/blob/main/skills/dependency-audit/references/ci-release.md)
- [references/diff-review.md](https://github.com/briiirussell/cybersecurity-skills/blob/main/skills/dependency-audit/references/diff-review.md)
- [references/enrich-advisories.mjs](https://github.com/briiirussell/cybersecurity-skills/blob/main/skills/dependency-audit/references/enrich-advisories.mjs)
- [references/exploitation-signals.md](https://github.com/briiirussell/cybersecurity-skills/blob/main/skills/dependency-audit/references/exploitation-signals.md)
- [references/findings-format.md](https://github.com/briiirussell/cybersecurity-skills/blob/main/skills/dependency-audit/references/findings-format.md)
- [references/findings.schema.json](https://github.com/briiirussell/cybersecurity-skills/blob/main/skills/dependency-audit/references/findings.schema.json)
- [references/fixing-safely.md](https://github.com/briiirussell/cybersecurity-skills/blob/main/skills/dependency-audit/references/fixing-safely.md)
- [references/runtime-exposure.md](https://github.com/briiirussell/cybersecurity-skills/blob/main/skills/dependency-audit/references/runtime-exposure.md)
- [references/severity-calibration.md](https://github.com/briiirussell/cybersecurity-skills/blob/main/skills/dependency-audit/references/severity-calibration.md)
- [references/source-redirection.md](https://github.com/briiirussell/cybersecurity-skills/blob/main/skills/dependency-audit/references/source-redirection.md)
- [references/to-sarif.mjs](https://github.com/briiirussell/cybersecurity-skills/blob/main/skills/dependency-audit/references/to-sarif.mjs)
- [references/validate-findings.mjs](https://github.com/briiirussell/cybersecurity-skills/blob/main/skills/dependency-audit/references/validate-findings.mjs)
- [references/verification.md](https://github.com/briiirussell/cybersecurity-skills/blob/main/skills/dependency-audit/references/verification.md)
