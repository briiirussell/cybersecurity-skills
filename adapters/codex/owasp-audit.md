# owasp-audit

> Audit application source code against the OWASP Top 10 vulnerability categories. Use when the user mentions 'OWASP,' 'security audit,' 'code security review,' 'vulnerability audit,' 'find vulnerabilities,' 'secure code review,' 'security review,' or wants to check their codebase for common security weaknesses.

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
- Grep for: direct object references, missing auth middleware, user ID from request params

### A02: Cryptographic Failures
- Hardcoded secrets, API keys, or passwords in source
- Weak hashing (MD5, SHA1 for passwords instead of bcrypt/argon2/scrypt)
- Sensitive data in logs, URLs, or localStorage
- Missing encryption at rest or in transit
- Grep for: `password`, `secret`, `api_key`, `private_key`, `MD5`, `SHA1`, `base64`

### A03: Injection
- **SQL injection:** raw queries with string concatenation, missing parameterized queries
- **NoSQL injection:** unsanitized user input in MongoDB/Convex queries
- **Command injection:** `exec()`, `spawn()`, `system()` with user input
- **XSS:** unescaped user input in HTML, `dangerouslySetInnerHTML`, `v-html`
- **Template injection:** user input in template literals
- Grep for: `exec(`, `eval(`, `innerHTML`, `dangerouslySetInnerHTML`, `$where`, raw SQL strings

### A04: Insecure Design
- Authentication flows with logic flaws
- Missing rate limiting on sensitive endpoints (login, password reset, API)
- Business logic constraints only enforced client-side

### A05: Security Misconfiguration
- Debug mode enabled in production configs
- Overly permissive CORS policies (`Access-Control-Allow-Origin: *`)
- Missing HTTP security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options)
- Default credentials or configurations shipped
- Verbose error messages exposing stack traces or internals

### A06: Vulnerable Components
- Run `npm audit` (Node), `pip audit` (Python), or equivalent
- Check lock files for known vulnerable dependency versions
- Flag dependencies with critical CVEs

### A07: Authentication Failures
- Weak password policies
- Session management issues (missing secure/httpOnly flags, no expiry, no rotation)
- Missing rate limiting on login (credential stuffing risk)
- Broken password reset flows

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
- Grep for: `fetch(`, `axios(`, `http.get(`, `urllib`, `requests.get(` with user input

## Report Format

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