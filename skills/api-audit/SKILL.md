---
name: api-audit
description: "Audit REST, GraphQL, and RPC APIs against the OWASP API Security Top 10 (2023). Use when the user mentions 'API security,' 'API audit,' 'BOLA,' 'broken object level authorization,' 'BFLA,' 'function-level authorization,' 'mass assignment,' 'API rate limiting,' 'GraphQL security,' 'REST security,' 'API authentication,' 'API authorization,' 'excessive data exposure,' or needs to review API endpoints for security weaknesses."
allowed-tools: Read, Grep, Glob, Bash, Write
---

# API Audit — REST / GraphQL / RPC Security Review

Perform a systematic security audit of API endpoints against the OWASP API Security Top 10 (2023). Distinct from `owasp-audit` — that's category-driven over a whole codebase, this is surface-driven over the API contract.

Use `owasp-audit` for the codebase as a whole. Use this when you need a focused pass over every endpoint with API-specific bypass patterns. They cross-reference each other where categories overlap.

## Scope the Audit

1. Inventory every API surface — REST routes, GraphQL resolvers, tRPC procedures, gRPC services, Server Actions, webhook handlers, internal RPC
2. Identify auth model — JWT, session cookies, API keys, mTLS, OAuth scopes
3. Identify the tenancy model — single-tenant, multi-tenant, row-level isolation
4. Map sensitive resources — user data, payments, files, admin functions

## Audit Checklist

### API1: Broken Object Level Authorization (BOLA)

The #1 API vulnerability by exploitation frequency. Every endpoint that accepts an object ID needs an explicit ownership check before reading or mutating.

- For each route that takes an ID parameter (`/users/:id`, `/orders/:id`, `/projects/:id`), verify a query like `findFirst({ where: { id, userId } })` runs before any data access — not `findById(id)` then a separate check
- ORM relation traversal: `posts.find(id).user.creditCard` returns another tenant's card if the relation isn't guarded. Audit every `.include`, `.with`, `includes`, eager-loaded relation
- UUIDs are not access control. Sequential IDs make enumeration trivial; UUIDs only slow it down
- Predictable surrogate keys (slugs, public_ids) used as if they were unguessable
- Grep for: `params.id`, `req.params.<id>`, `formData.get("<id>")`, ORM `.findById(` / `.find(` without a `where` clause, GraphQL resolvers that take an `id` arg and call `.findUnique`

### API2: Broken Authentication

- JWT with `alg: none` accepted by the verifier
- JWT secret comparison without `crypto.timingSafeEqual` / equivalent
- Refresh tokens that never rotate or have no revocation list
- Password reset that returns a token in the response body instead of mailing it
- API keys passed in URL query string (logged everywhere — access logs, CDN, proxies)
- Bearer-token compare against `process.env.X` without a presence check — when X is unset, `"Bearer ${undefined}"` is a valid literal
- Grep for: `jwt.verify`, `jsonwebtoken`, `Bearer ${process.env`, `jwt.decode` (without verify), `verify.*alg`

### API3: Broken Object Property Level Authorization (BOPLA / BFLA / Excessive Data Exposure)

- API returns the whole DB row instead of a curated DTO — `res.json(user)` leaks `password_hash`, `stripe_customer_id`, internal flags
- Admin-only fields (role, is_verified, tenant_id) accepted on update endpoints from regular users — **mass assignment**
- GraphQL exposes admin-mutation fields without role-based field-level auth — `mutation UpdateUser($id, $role)` succeeds because the resolver only checks "is the user logged in"
- Grep for: `res.json(<entity>)` without explicit field projection, `Object.assign(record, req.body)`, Mongoose `findByIdAndUpdate(id, req.body)`, Drizzle `.update().set(req.body)`, Sequelize `update(req.body)`, GraphQL resolvers without role checks

### API4: Unrestricted Resource Consumption

- No rate limit on auth endpoints (login, signup, password-reset, SMS-send, email-verify)
- No per-tenant quota on expensive operations (LLM calls, search, file processing, webhook fan-out)
- Page size unbounded — `?limit=10000000` returns 10M rows
- GraphQL query depth not capped — `user { posts { user { posts { ... } } } }` runs forever
- GraphQL query complexity not analyzed — single query that triggers N+1 against 100M rows
- Webhook handlers that re-trigger expensive work without idempotency

### API5: Broken Function Level Authorization (BFLA)

- Auth check on the route but not on the handler — wildcard middleware misses a manually-mounted route
- "Admin-ish" endpoints reachable by changing `POST /api/v1/users/me` to `POST /api/v1/users/<other_id>`
- HTTP verb tampering — `DELETE /admin/users/123` blocked, but `POST /admin/users/123/delete` succeeds
- Conditional auth based on `req.user.role === "admin"` where role is set from a header the client controls
- Sister-route gaps — `PUT /:id` is guarded but `POST /:id/send` writes the same row without the guard. Run sister-route audit (see `owasp-audit`)
- Grep for: every route handler — does it call an auth check explicitly, or rely on something upstream that may or may not match this route's path?

### API6: Unrestricted Access to Sensitive Business Flows

- Endpoint allows automation that bypasses business intent — buying limited stock 1000× per second, reserving every seat in a venue, brute-forcing referral codes
- No CAPTCHA / proof-of-work / device fingerprint on flows that have business-rate constraints (signup, coupon redemption, vote, like)
- Anti-automation checks only on UI, not on the API

### API7: Server-Side Request Forgery (SSRF)

- User-controlled URLs passed to server-side fetch — webhook URLs, image-fetch, SSO callback, PDF render, OG-scrape, link unfurling
- Allow-list checks only the hostname — see `owasp-audit` A10 for the full bypass matrix (9+ patterns including IPv4-mapped IPv6, trailing-dot, cloud metadata, encoded IPs)
- `redirect: "follow"` (default) on fetches with user-controlled URLs lets an attacker bounce through a 302 into the metadata service
- Webhook delivery from your domain to attacker URL — your server's IP is now their proxy

### API8: Security Misconfiguration

- CORS `Access-Control-Allow-Origin: *` combined with `Allow-Credentials: true` (browsers refuse this; servers shouldn't ship it)
- CORS reflection of the `Origin` header without an allow-list — any origin gets allowed
- Verbose error responses leaking stack traces, query strings, internal IDs
- Default OpenAPI / GraphQL introspection exposed in production with full schema
- Missing security headers — see `owasp-audit` A05 for the full baseline values
- HTTP-only flag missing on session cookies

### API9: Improper Inventory Management

- Old API versions (`/v1/`) still live and unpatched alongside `/v2/` — attackers prefer the version with fewer checks
- "Internal" / "staging" endpoints reachable from the internet (deploy-preview URLs, `*-staging.fly.dev` left open)
- Undocumented endpoints — every endpoint should appear in the OpenAPI spec / type-generated client; orphans are an audit signal
- Auto-generated debug endpoints — `/__debug`, `/__db`, `/.well-known/internal/`, framework-default routes
- Grep for: `app.get`, `router.get`, `pages/api/`, `app/api/` directory contents; reconcile against the published API contract

### API10: Unsafe Consumption of APIs

- Your service calls a third-party API and trusts the response without validation — open redirect via `provider.user.profile_url`, XSS via `provider.user.bio` rendered un-escaped
- Server-to-server calls without integrity check (signed JWT, mTLS, HMAC) — anyone who can reach the upstream URL can pretend to be the upstream
- Caching upstream errors as success — a 200 with a JSON error body cached as data

## GraphQL-specific

- Introspection enabled in production (`__schema`, `__type` queries return the full schema)
- Field-level authorization missing — resolvers check "is this query allowed" but not "is this field allowed for this user"
- Query depth + complexity limits absent
- Batching abuse — single HTTP request containing 1000 queries each costing 100ms
- Error messages reveal internal field paths the user shouldn't know exist

## REST-specific

- HTTP verbs not enforced — `GET` accepted on state-changing endpoints (CSRF risk + cache poisoning)
- Content-Type assumptions — handler expects `application/json` but accepts `application/x-www-form-urlencoded` and parses inconsistently
- Path traversal in resource IDs — `/files/../../etc/passwd`

## Webhook handler-specific

- Signature verification missing or bypassable (see `owasp-audit` A02 type-coercion + A04 multi-tenant signature N-way matching)
- Replay attack — no timestamp tolerance or nonce check
- Endpoint exists at a predictable path (`/webhooks/stripe`) without IP allow-list or signature

## Verify Fixes at Runtime

- For BOLA fixes: actually authenticate as user A and request user B's resource; observe 404, not 200
- For mass-assignment fixes: send the request with the extra field set; observe the field is ignored or rejected
- For rate-limit fixes: hit the endpoint at 10× the configured rate; observe 429 not 200
- For CORS fixes: send the request with `Origin: https://evil.com`; observe the browser blocks, not the server

`tsc --noEmit` + build success ≠ fix verified. See also `owasp-audit`'s Verify Fixes at Runtime + Second-Opinion Pass — same playbook applies.

## Report Format

Findings have three dispositions (Fixed / Deferred / Accepted Risk) per the `owasp-audit` convention. For every finding:

```markdown
#### [SEVERITY] APIN: [Title]
**Endpoint:** `METHOD /path/to/endpoint`
**Handler:** `path/to/handler.ts:42`
**CWE:** CWE-XXX

**Description:** [What the vulnerability is]

**Proof of concept:**
```
[curl / request showing the bypass]
```

**Vulnerable Code:**
[snippet]

**Remediation:**
[fixed snippet]

**Verification:** [Concrete adversarial input and the observed response that proves the fix holds]
```

Produce an executive summary grouped by API category, plus an inventory of every endpoint with one of:
- **Audited — clean** (with what was checked)
- **Audited — N findings** (with severities)
- **N/A** (with reason — e.g. health-check endpoint with no auth surface)

## Boundaries

- Only audit APIs the user provides or points you to
- Provide remediation, not exploits — for proof-of-concept, generate the minimum request that demonstrates the issue, not a weaponized payload
- Flag low-confidence findings as "Potential" rather than confirmed
- Never run a BOLA proof-of-concept against a live production endpoint without explicit written authorization — read the code, then propose how to verify in a test environment
- Refuse mass-scanning, credential-stuffing, or any active abuse-flow exploitation

## References

- OWASP API Security Top 10 (2023)
- OWASP Cheat Sheet: REST Security
- OWASP Cheat Sheet: GraphQL Security
- CWE-639 (Authorization Bypass Through User-Controlled Key)
- CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes)
