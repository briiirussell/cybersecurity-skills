# dependency-audit

> Audit project dependencies, frameworks, languages, and dev tools for known vulnerabilities, CVEs, and security anti-patterns. Use when the user mentions 'dependency audit,' 'npm audit,' 'CVE,' 'vulnerable packages,' 'supply chain security,' 'outdated dependencies,' 'known vulnerabilities,' 'security advisory,' 'package security,' 'framework vulnerability,' 'is this package safe,' or needs to check whether their stack has known security issues.

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

### Step 2: Run Automated Audit Tools

Run the appropriate audit command for the project:

```bash
# Node.js
npm audit
npm audit --json  # For structured output

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

### Step 3: Research Framework-Specific Known Issues

Beyond CVEs in packages, check for known vulnerability patterns specific to the framework in use. Search for recent advisories and common misconfiguration issues.

**Next.js / React:**
- Server Actions exposing internal endpoints (pre-14.1.1 middleware bypass CVE-2025-29927)
- `dangerouslySetInnerHTML` without sanitization
- SSRF through image optimization (`next/image` with unrestricted domains)
- Exposed `.env` files in public directory or client bundle (`NEXT_PUBLIC_` prefix leaking secrets)
- Middleware auth bypass patterns — check middleware.ts matches all protected routes
- Server Component / Client Component boundary leaking server-only data
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
- Is the lockfile committed to source control?
- Does CI install from the lockfile (`npm ci` not `npm install`, `pip install --require-hashes`)?
- Are integrity hashes present and verified?

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
| Package | Installed | Vuln | Severity | CVE | Fix Version |
|---------|-----------|------|----------|-----|-------------|

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