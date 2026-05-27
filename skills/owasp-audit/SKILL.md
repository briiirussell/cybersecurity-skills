---
name: owasp-audit
description: "Audit application source code against the OWASP Top 10 vulnerability categories. Use when the user mentions 'OWASP,' 'security audit,' 'code security review,' 'vulnerability audit,' 'find vulnerabilities,' 'secure code review,' 'security review,' or wants to check their codebase for common security weaknesses."
allowed-tools: Read, Grep, Glob, Bash, Write
---

# OWASP Audit — Source Code Security Review

Perform a systematic security audit of application source code against the OWASP Top 10 (2021).

## Scope the Audit

1. Identify the project's language, framework, and architecture
2. Map entry points (routes, API handlers, form processors)
3. Identify data flows (user input → processing → storage → output)
4. Locate authentication and authorization boundaries

## Audit Checklist

Work through each category systematically. For each, grep for known vulnerability patterns, then read flagged files for deeper analysis.

### A01: Broken Access Control
- Missing authorization checks on endpoints or routes
- IDOR — user-controlled IDs without ownership verification
- Missing CSRF protections on state-changing requests
- Role checks only on the frontend, not enforced server-side
- Open redirect via post-auth return-to parameter — `?from=`, `?next=`, `?returnTo=`, `?continue=`, `?redirect=` passed unsanitized to `redirect()` / `Response.redirect()`. Restrict to same-origin paths under the expected scope, normalize (`new URL(target, "http://localhost").pathname`) to defeat traversal like `/admin/../foo`
- Grep for: direct object references, missing auth middleware, user ID from request params, `redirect(.*from`, `redirect(.*next`, `redirect(.*returnTo`

### A02: Cryptographic Failures
- Hardcoded secrets, API keys, or passwords in source
- Weak hashing (MD5, SHA1 for passwords instead of bcrypt/argon2/scrypt)
- Sensitive data in logs, URLs, or localStorage
- Missing encryption at rest or in transit
- **Before recommending `VERIFY_PEER` for a TLS connection,** identify the cert issuer at the deployment target. Many managed services ship self-signed cert chains at lower tiers (Heroku Redis Mini/Hobby, some ElastiCache configurations, Supabase legacy) — `VERIFY_PEER` fails there without an explicit `ca_file:` pin. When `VERIFY_PEER` is genuinely infeasible, present three remediation options in priority order:
  1. Upgrade the plan or pin the CA bundle — restores cert verification
  2. Accept the risk explicitly — leave `VERIFY_NONE` with (a) an in-line comment at every call site, (b) a documented compensating control (private network, internal-only routing), (c) a follow-up issue tracking re-verification conditions
  3. Restrict the network path — private subnet / VPC peering / no public exposure

  Never quietly recommend `VERIFY_PEER` without checking that the cert chain at the deployment target is verifiable.
- Grep for: `password`, `secret`, `api_key`, `private_key`, `MD5`, `SHA1`, `base64`
- **Include non-source file extensions in the sweep.** Rails `cable.yml` / `database.yml` / `storage.yml`, Kubernetes manifests, and Vercel / Netlify deploy configs routinely contain TLS or cert config that a source-only sweep misses. Concrete sweep for VERIFY_NONE / VERIFY_PEER:

  ```bash
  grep -rn "VERIFY_NONE\|verify_mode" \
    --include="*.rb" --include="*.yml" --include="*.yaml" \
    --include="*.toml" --include="*.json" \
    .
  ```

### A03: Injection
- **SQL injection:** raw queries with string concatenation, missing parameterized queries
- **NoSQL injection:** unsanitized user input in MongoDB/Convex queries
- **Command injection:** `exec()`, `spawn()`, `system()` with user input
- **XSS:** unescaped user input in HTML, `dangerouslySetInnerHTML`, `v-html`. Note the common safe-ish case: `dangerouslySetInnerHTML={{ __html: JSON.stringify(internalObject) }}` for SEO JSON-LD is typically safe *if* the object contains only internal data — flag it if user-editable fields (e.g. CMS-authored descriptions, vendor names) flow into the object
- **Rails ERB sinks:** `raw()`, `.html_safe`, `<%==`, `sanitize` with a permissive allowlist, and `simple_format` on user input. Grep for these alongside `dangerouslySetInnerHTML` / `v-html`.
- **Rails JSON-LD breakout:** inside `<script type="application/ld+json">`, do NOT use `j` / `escape_javascript` for field values — `j` emits `\'` and `\$` (valid JS, invalid JSON), so `JSON.parse` fails on any field containing an apostrophe or `$`. Use this idiom instead:

  ```erb
  <% schema = { "@context" => "https://schema.org",
                "@type" => "Article",
                "headline" => @post.title } %>
  <script type="application/ld+json">
  <%= json_escape(schema.to_json).html_safe %>
  </script>
  ```

  `to_json` handles JSON escaping; `json_escape` covers `<>&\u2028\u2029` against `</script>` breakout. Verify with round-trip: `JSON.parse(json_escape(article.to_json))` equals the source hash.
- **Template injection:** user input in template literals
- Grep for: `exec(`, `eval(`, `innerHTML`, `dangerouslySetInnerHTML`, `$where`, raw SQL strings

### A04: Insecure Design
- Authentication flows with logic flaws
- Missing rate limiting on sensitive endpoints (login, password reset, API)
- Business logic constraints only enforced client-side
- **Configured-but-not-loaded check.** Before declaring a security middleware (rate-limit, auth, CSRF, throttle) as "already configured," verify the gem/package is actually installed — not just that the initializer file exists. Initializers wrapped in `if defined? Foo` / `if PACKAGE in sys.modules` silently no-op when the package isn't bundled.

  | Stack | Check |
  |---|---|
  | Ruby/Rails | `grep -E "^    GEM_NAME " Gemfile.lock` (4-space indent = top-level gems) |
  | Node | `grep "\"PACKAGE_NAME\":" package-lock.json` or `node -e "require('PACKAGE_NAME')"` |
  | Python | `pip show PACKAGE_NAME` |
  | Go | `grep PACKAGE_PATH go.sum` |

  For Rails: also verify the middleware is in the runtime stack — `bundle exec rails middleware | grep -i FOO`.

### A05: Security Misconfiguration
- Debug mode enabled in production configs
- Overly permissive CORS policies (`Access-Control-Allow-Origin: *`)
- Missing HTTP security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options)
- Default credentials or configurations shipped
- Verbose error messages exposing stack traces or internals — including validation libraries echoing schema details (e.g. Zod `err.issues`, Joi error trees) to clients
- **Runtime-API mismatch.** Code running in Edge / Workers / V8-isolate runtimes can't load Node-only modules. Imports of `node:crypto`, `node:fs`, `node:buffer`, `node:net`, etc. inside Next.js `middleware.ts` / Cloudflare Workers / Vercel Edge functions compile cleanly and fail at first request with `Failed to load external module`. Audit middleware and edge-marked routes for Node-only imports; prefer Web Crypto (`crypto.subtle`) for portable code
- **Rails admin-engine mounts.** Grep `config/routes.rb` for engine and dashboard mounts (PgHero, Sidekiq::Web, Flipper UI, Mission Control, Audit1984) and verify the auth middleware in the corresponding initializer applies in *every* environment reachable from the internet — not just production:

  ```bash
  grep -E "mount .+::(Engine|Web|UI)|mount .+::App" config/routes.rb
  grep -rn "Rails.env.production?" config/initializers/ | \
    grep -B1 -A5 "Auth::Basic\|authenticate\|secure_compare"
  ```

  The README examples for PgHero, Sidekiq::Web, Flipper, and Mission Control all wrap auth in `if Rails.env.production?`, which leaves staging, review apps, and preview deploys serving the admin UI anonymously. Fix shape: switch the guard to `unless Rails.env.local?` (Rails 7.1+ helper for `development || test`), and add a fail-closed check that refuses access when the auth env vars are unset.

### A06: Vulnerable Components
- Run `npm audit` (Node), `pip audit` (Python), or equivalent
- Check lock files for known vulnerable dependency versions
- Flag dependencies with critical CVEs

### A07: Authentication Failures
- Weak password policies
- Session management issues (missing secure/httpOnly flags, no expiry, no rotation)
- **Credential-as-cookie:** the cookie value *is* the credential (e.g. `cookies.set("admin_token", process.env.ADMIN_PASSWORD)` and equality-checked on read). Even with `httpOnly` and `secure`, this is plaintext-credential storage (CWE-522) and lacks rotation/revocation. Replace with an HMAC-signed expiring token verified via `crypto.subtle.verify` / `crypto.timingSafeEqual`
- **Non-constant-time credential comparison:** `submitted === expected` for passwords, API keys, or signatures leaks length and prefix-match via timing. Use `crypto.timingSafeEqual` (Node) or `crypto.subtle.verify` (Web Crypto)
- Missing rate limiting on login (credential stuffing risk)
- Broken password reset flows
- **Rails / Devise — `password_length` requires `:validatable`.** `config.password_length` in `config/initializers/devise.rb` is only enforced when the User model includes `:validatable` in its `devise :...` declaration. A model with `devise :database_authenticatable, :registerable, :recoverable, :rememberable` (no `:validatable`) accepts passwords of any length and any email format, regardless of what the initializer says. Grep: `^\s*devise\s+:` in `app/models/`; flag any line where `:validatable` is absent. Adding it on an existing app validates on create+update but does not retro-invalidate existing weak passwords.
- Grep for: `cookies.set\(.*process\.env`, `=== .*PASSWORD`, `!== .*SECRET`, `!== .*Bearer.*\${`

### A08: Data Integrity Failures
- Unsafe deserialization of user input
- Missing integrity checks on CI/CD pipelines
- No lockfile integrity verification (SRI hashes)

### A09: Logging & Monitoring Failures
- Auth events not logged (login, failure, privilege changes)
- Sensitive data written to logs (passwords, tokens, PII)
- No alerting on suspicious patterns

### A10: SSRF
- User-controlled URLs passed to server-side HTTP requests
- Missing URL validation and allowlisting
- Allow-lists that only check hostname — a real allow-list must reject **all** of these:
  - Wrong scheme: `http://allowed.com/` (when only `https:` is expected)
  - Embedded credentials: `https://user:pass@allowed.com/`
  - `@`-host trick: `https://allowed.com@evil.com/` (hostname resolves to `evil.com`)
  - Non-default ports: `https://allowed.com:8443/`
  - Punycode/IDN spoof: `https://аllowed.com/` (Cyrillic а) or `xn--llowed-pdc.com`
  - Trailing dot: `https://allowed.com./` (DNS-equivalent, often missed by string compare)
  - Subdomain confusion: `https://allowed.com.evil.com/`
  - Bracketed IPv6 literal: `https://[::1]/`
  - Bare IPv4: `https://127.0.0.1/`
- Fetch-time guards: `redirect: "error"` (don't follow attacker-controlled redirects), explicit timeout, no following 3xx into the metadata service
- Note the TOCTOU between validation and fetch — DNS can resolve differently between the two (DNS rebinding). For high-risk callers, pin the resolved IP and connect by IP with `Host:` header, or use a vetted proxy
- Grep for: `fetch(`, `axios(`, `http.get(`, `urllib`, `requests.get(` with user input

## Verify Fixes at Runtime

After applying a fix, exercise the affected code path — do not stop at typecheck or build. Modern frameworks have runtime-only failure modes that compile cleanly:

- **Edge / Node split runtimes.** Next.js middleware, Cloudflare Workers, Vercel Edge — Node-only imports (`node:crypto`, `node:fs`) build successfully but throw on first request.
- **Lazy module loads.** Adapters/plugins loaded via `import()` or runtime DI surface only when the codepath runs.
- **Environment-variable fallthrough.** `Bearer ${process.env.X}` with X unset becomes a literal that the tests never hit because the test env defines X.

For each shipped fix, run the affected route or job and capture the response. `tsc --noEmit` + build success ≠ fix verified.

## Report Format

Findings have three possible dispositions:

- **Fixed** — remediation shipped in this PR. Closed pending verification.
- **Deferred** — remediation acknowledged and scheduled. Specify whether the next deploy is gated on it (release blocker) or not (acceptable risk with calendar fix). Severity does not change because you decided to defer it.
- **Accepted Risk** — remediation is NOT planned at the current configuration. The report must record:
  1. **Why the fix doesn't apply** — cost tier, dependency version constraint, deployment topology, vendor limitation
  2. **Compensating controls** — private network, signed cookies, internal-only routing, etc.
  3. **Re-evaluation trigger** — what condition (plan upgrade, dependency bump, traffic pattern change) would cause this finding to leave the Accepted Risk lane

An "Accepted Risk" entry without all three fields is a real finding being silently dropped under a different label.

For each finding, document:

```markdown
#### [SEVERITY] A0X: [Title]
**File:** `path/to/file.ts:42`
**CWE:** CWE-XXX

**Description:** [What the vulnerability is and why it matters]

**Vulnerable Code:**
[code snippet]

**Remediation:**
[Fixed code snippet with explanation]

**Verification:** Concrete adversarial input + the command or code path that proves the fix holds. For XSS: the script-tag breakout payload that no longer breaks out. For open redirects: the off-host URL that now rejects. For password-length: the 1-char password that now fails to save. "The linter says it's fine" is not verification — static analysis has known blind spots for correctness bugs that happen to also be security fixes.
```

Produce an executive summary:

```markdown
# Security Audit Report
## Project: [name]
## Stack: [technologies]
## Date: [date]

### Summary
- Total findings: X
- Critical: X | High: X | Medium: X | Low: X | Info: X

### Findings
[Individual findings as above]

### Prioritized Remediation Plan
1. [Critical fixes — immediate]
2. [High fixes — this week]
3. [Medium/Low — scheduled]
```

## Boundaries

- Only audit code the user provides or points you to
- Provide fixes, not exploits — always include remediation
- Flag low-confidence findings as "Potential" rather than confirmed
- If the codebase is too large for a full audit, prioritize: auth, input handling, data access layers
- Refuse requests to insert backdoors or weaken security controls

## References

- OWASP Top 10 (2021)
- OWASP Code Review Guide
- CWE Top 25
