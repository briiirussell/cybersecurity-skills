---
name: dependency-audit
description: "Audit project dependencies, frameworks, languages, and dev tools for known vulnerabilities, CVEs, and security anti-patterns. Use when the user mentions 'dependency audit,' 'npm audit,' 'CVE,' 'vulnerable packages,' 'supply chain security,' 'outdated dependencies,' 'known vulnerabilities,' 'security advisory,' 'package security,' 'framework vulnerability,' 'is this package safe,' or needs to check whether their stack has known security issues."
allowed-tools: Bash, Read, Write, Grep, Glob, WebSearch
---

# Dependency Audit — Framework, Package, and Toolchain Security

Audit project dependencies, frameworks, language runtimes, and dev tools for known vulnerabilities (CVEs), security anti-patterns, and supply chain risks.

## Methodology

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

### Step 3: Research Framework-Specific Known Issues

Beyond CVEs in packages, check for known vulnerability patterns specific to the framework in use. Search for recent advisories and common misconfiguration issues.

For every direct dependency, cross-reference the installed version against:
- `https://github.com/advisories?ecosystem=npm&query=<package>`
- `https://github.com/<org>/<repo>/security/advisories`

The framework-specific patterns below cover *evergreen* anti-patterns (mass assignment, debug-in-prod, etc.). Recent CVEs need a fresh check because hardcoded advisory lists rot fast and LLM training data is often 6+ months behind the latest.

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

**GitHub Actions:**
- `pull_request_target` trigger with checkout of PR code (code injection risk)
- Secrets accessible in forked PR workflows
- Unpinned action versions (`uses: actions/checkout@main` vs `@v4.1.0` or SHA pin)
- Script injection via `${{ github.event.issue.title }}` in `run:` blocks

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

## Output Format

```markdown
# Dependency & Stack Security Audit
## Project: [name]
## Stack: [language, framework, key tools]
## Date: [date]

### Stack Inventory
| Component | Version | Latest | Status |
|-----------|---------|--------|--------|

### Known Vulnerabilities (CVEs)
| Package | Installed | Vuln | Severity | Where reachable | CVE | Fix Version |
|---------|-----------|------|----------|-----------------|-----|-------------|

Where reachable values: `runtime` / `build-only` / `dev-only`. Confirm with `npm ls --omit=dev <package>` or inspect the deployment artifact (Vercel function bundle, Docker layer). Build- and dev-only vulnerabilities should not block a release on their own; runtime-reachable ones should.

### Framework-Specific Issues
#### [SEVERITY] [Title]
**Component:** [framework/tool name and version]
**Issue:** [description]
**Evidence:** [code or config snippet]
**Remediation:** [specific fix]

### Supply Chain Risks
| Risk | Package/Component | Details | Remediation |
|------|-------------------|---------|-------------|

### Dev Tool / CI Security
| Tool | Issue | Severity | Remediation |
|------|-------|----------|-------------|

### Prioritized Action Plan
1. [Critical — actively exploited CVEs, RCE vulnerabilities]
2. [High — known CVEs with public exploits, supply chain risks]
3. [Medium — framework misconfigurations, outdated dependencies]
4. [Low — maintenance risks, best practice improvements]
```

## Boundaries

- Only audit code and configurations the user provides
- When identifying CVEs, verify they apply to the actual installed version
- Provide specific fix versions or remediation steps for every finding
- Note when a vulnerability requires specific conditions to exploit (reducing effective severity)
- Refuse to help exploit found vulnerabilities against unauthorized targets

## References

- OWASP Dependency-Check
- National Vulnerability Database (NVD)
- GitHub Advisory Database
- Snyk Vulnerability Database
- npm audit / pip-audit / bundler-audit documentation
- SLSA (Supply-chain Levels for Software Artifacts) framework
