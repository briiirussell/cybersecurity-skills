---
name: owasp-audit
description: "Audit application source code against the OWASP Top 10 (2021) vulnerability categories — broken access control, cryptographic failures, injection, insecure design, security misconfiguration, vulnerable components, authentication failures, data integrity, logging failures, SSRF. Use when the user mentions 'OWASP,' 'OWASP Top 10,' 'security audit,' 'security review,' 'secure code review,' 'code security review,' 'vulnerability audit,' 'find vulnerabilities,' 'appsec review,' 'application security audit,' 'check for security issues,' 'broken access control,' 'IDOR,' 'SQL injection,' 'XSS,' 'SSRF,' or wants to check their codebase for common security weaknesses."
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
- **Auth-check ordering.** Verify the authorization check runs *before* any branch that can reveal whether the resource exists, what state it's in, or any other resource-specific metadata. Returning 404 for "not found", 400 for "wrong state", and 401 for "not authenticated" is itself a leak — an attacker enumerates resource IDs and learns states without ever passing the auth gate. Recommended response shape: uniform 404 for everything an unprivileged caller should not see.
- **Framework RPC surfaces that don't appear as routes.** Server actions and equivalents are publicly-exposed RPCs that file scans miss. Enumerate and audit each one for auth + ownership:
  - Next.js: every exported function in a file with `'use server'`
  - Remix / React Router: every `action` / `loader` export
  - tRPC: every procedure
  - GraphQL: every resolver
  - Rails: non-resource controller actions
- **IDOR via foreign keys in mutation payloads.** Form posts a foreign-key UUID (`categoryId`, `projectId`, `teamId`, `organizationId`) → server validates ownership of the primary record but blindly accepts the FK → ORM relation join later surfaces another tenant's data. Look for `formData.get("<id>")` / `body.<id>` passed straight to insert/update without a preceding `findFirst({ where: { id, userId } })`. For ORM relation joins (Drizzle `with:`, Prisma `include`, ActiveRecord `includes`), trace whether the join target is filtered by the same tenant/ownership predicate as the parent query.
- Missing CSRF protections on state-changing requests
- Role checks only on the frontend, not enforced server-side
- Open redirect via post-auth return-to parameter — `?from=`, `?next=`, `?returnTo=`, `?continue=`, `?redirect=` passed unsanitized to `redirect()` / `Response.redirect()`. Restrict to same-origin paths under the expected scope, normalize (`new URL(target, "http://localhost").pathname`) to defeat traversal like `/admin/../foo`. Also reject control bytes in the path before redirect: tab/newline/null (`\t`, `\n`, `\0`) — URL parsers strip these and collapse `/\tevil` into protocol-relative `//evil`; null bytes can turn the redirect into a 500. Reject any byte in `[\x00-\x1F\x7F]`, any backslash, and any percent-encoded slash/backslash (`%2f`, `%5c`).
- Grep for: direct object references, missing auth middleware, user ID from request params, `redirect(.*from`, `redirect(.*next`, `redirect(.*returnTo`

### A02: Cryptographic Failures
- Hardcoded secrets, API keys, or passwords in source
- Weak hashing (MD5, SHA1 for passwords instead of bcrypt/argon2/scrypt)
- For bcrypt, also check the cost factor. OWASP 2024 guidance is ≥ 12 (cost 10 ≈ 10ms / 100 hashes/sec/core for an attacker)
- **Type coercion in cryptographic-verification paths.** Numeric parsing (`parseInt`, `Number`, `parseFloat`) silently produces `NaN` for garbage input, and `NaN` compares as `false` for both `<` and `>`. A timestamp-freshness check `if (Math.abs(now - parsed) > tolerance) return false` *fails to reject* `NaN` — because `NaN > tolerance` is `false`. Grep for: `parseInt|parseFloat|Number\(.*\)` inside `verifySignature` / `validateToken` / signed-cookie / JWT-claim code. Each numeric extraction must be followed by `if (!Number.isFinite(parsed)) return false` before any inequality. Same family: `parseInt('0x123', 10) === 0`, `parseInt('1e10', 10) === 1`, `parseFloat('Infinity') === Infinity`.
- Sensitive data in logs, URLs, or localStorage
- Missing encryption at rest or in transit
- **Before recommending `VERIFY_PEER` for a TLS connection,** identify the cert issuer at the deployment target. Many managed services ship self-signed cert chains at lower tiers (Heroku Redis Mini/Hobby, some ElastiCache configurations, Supabase legacy) — `VERIFY_PEER` fails there without an explicit `ca_file:` pin. When `VERIFY_PEER` is genuinely infeasible, present three remediation options in priority order:
  1. Upgrade the plan or pin the CA bundle — restores cert verification
  2. Accept the risk explicitly — leave `VERIFY_NONE` with (a) an in-line comment at every call site, (b) a documented compensating control (private network, internal-only routing), (c) a follow-up issue tracking re-verification conditions
  3. Restrict the network path — private subnet / VPC peering / no public exposure

  Never quietly recommend `VERIFY_PEER` without checking that the cert chain at the deployment target is verifiable.
- Grep for generic secret names AND known provider key prefixes:
  - Generic: `password`, `secret`, `api_key`, `private_key`, `MD5`, `SHA1`, `base64`
  - Stripe: `sk_live_`, `sk_test_`, `rk_live_`, `whsec_`
  - GitHub: `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`
  - AWS: `AKIA[0-9A-Z]{16}`, `ASIA[0-9A-Z]{16}`
  - Google Cloud: `AIza[0-9A-Za-z\-_]{35}`, service-account JSON (`"type": "service_account"`)
  - Slack: `xox[baprs]-`, `xoxe.xoxp-`
  - OpenAI / Anthropic: `sk-`, `sk-ant-`
  - Vercel: `vercel_blob_rw_`
  - Run via `git ls-files | xargs grep -lE 'sk_live|ghp_|AKIA[0-9A-Z]{16}|sk-ant-' 2>/dev/null` so binaries and gitignored files don't pollute output.
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
- **XSS:** unescaped user input in HTML, `dangerouslySetInnerHTML`, `v-html`.
- **Inline-script breakout via `JSON.stringify`.** Any `<script type="application/ld+json">` or `<script>window.__DATA__ = ...</script>` that interpolates server data through `JSON.stringify` is vulnerable — `JSON.stringify` does NOT escape `<`, `>`, `&`, U+2028, or U+2029. A stored title containing `</script><script>alert(1)</script>` will break out. The "internal-only object" framing only saves you when every field is guaranteed never to come from user-editable input.
  - Grep for: `application/ld+json`, `__html: JSON.stringify`, `window.__` + `JSON.stringify`
  - Fix: wrap with an escape helper that replaces `<>&\u2028\u2029` with their `\uXXXX` Unicode escapes before injecting.
- **Rails ERB sinks:** `raw()`, `.html_safe`, `<%==`, `sanitize` with a permissive allowlist, and `simple_format` on user input. Grep for these alongside `dangerouslySetInnerHTML` / `v-html`.
- **Sanitizer choice.** When remediating an HTML/SVG XSS sink, the fix MUST use a vetted parser-based sanitizer (DOMPurify / isomorphic-dompurify / sanitize-html for JS; bleach for Python). Reject regex-based sanitizers in code review. If unavoidable, a regex sanitizer must:
  - Treat `[/\s]` (not just `\s`) as the attribute-name separator — HTML accepts `/` between tag name and first attribute: `<img/onerror=…>`
  - Strip both SVG- and HTML-namespace dangerous elements (`<img>`, `<body>`, `<video>`, `<iframe>`) — HTML elements instantiate even in SVG-rendering contexts
  - Include a final fallback pass that strips any `on*=` regardless of surrounding context
  - Be paired with `Content-Security-Policy: script-src-attr 'none'` as a browser-level backstop
- **SVG uploads as stored XSS.** SVG files can carry `<script>` / `onload`. Most blob / object storage serves uploads with the declared content-type. Reject `image/svg+xml` in upload allow-lists unless you have a sanitizer (e.g. DOMPurify SVG profile) and serve with `Content-Disposition: attachment`.
- **Sanitize on write AND on render.** For stored XSS / injection, sanitize at the trust boundary (write to DB) AND at the render boundary (defense in depth). On finding a stored-XSS bug, plan a one-time backfill migration to sanitize existing data — render-only fixes leave poisoned rows that any new render path will re-expose.
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
- **Background / fire-and-forget jobs** inherit the caller's auth context but lose the request-scoped guards. Re-check authorization inside the job, not just at enqueue. Grep for: `Promise.all(...).catch(`, `void someAsync(`, `.catch(noop)`, queue `enqueue(` without re-auth in the worker.
- **Sister-route audit.** When you find a state-machine or immutability guard on one handler (e.g., `WHERE … AND signedAt IS NULL` on `PUT /api/foo/[id]`), grep for every other handler that writes the same table:

  ```bash
  rg 'update\(\s*tableName\b|\.update\(tableName' --type ts -B1 -A8
  ```

  Each call site needs the same guard, the same `userId` predicate, and the same conflict-handling (`returning()` + 0-rows check). Common offender: a `POST /:id/send` or `POST /:id/convert` route that ships after the `PUT` was hardened and was never re-audited.
- **External-resource-create TOCTOU with billing implications.** Any handler that does "SELECT to check, then `provider.create()`, then INSERT to record the new resource ID" can create orphan resources on the provider side under concurrency. Stripe accounts, Auth0 / Clerk users, SendGrid templates, S3 buckets — all bill or count toward quota whether you stored the ID or not. Fix pattern:
  1. Claim first with `INSERT … ON CONFLICT DO NOTHING` (DB UNIQUE constraint is the lock)
  2. Call the provider
  3. Persist with optimistic guard: `UPDATE … SET externalId = ? WHERE externalId IS NULL` and check 0-rows
  4. On race-loss, clean up the orphan via `provider.delete(id)` best-effort; log on cleanup failure
- **Worker-queue state transitions need atomic claim.** Any cron / worker polling pending rows must atomically claim each row before processing. `SELECT` + `process()` + `UPDATE` is a race — two workers (or two overlapping cron invocations) both see the same pending row and both call out, causing duplicate delivery. Fix: `UPDATE … SET status='processing' WHERE id=? AND status='pending' RETURNING …` — Postgres `RETURNING` lets you claim and read in one round-trip. If the UPDATE returns 0 rows, someone else got it. Alternative: `SELECT … FOR UPDATE SKIP LOCKED` (Postgres / Cockroach) for higher-throughput queues.
- **Multi-tenant webhook signature matching.** When an unauthenticated webhook endpoint identifies its tenant by trying each tenant's secret in turn, every request — including garbage — does O(N) DB lookups + O(N) HMAC computations. Attackers flood with random signatures and amplify CPU/DB load without ever passing auth. Defences (compose them):
  1. **Signature-shape prefilter** before any DB work — reject signatures that aren't the exact length/charset the provider sends (e.g., `/^[a-f0-9]{64}$/i` for HMAC-SHA256 hex)
  2. **Hard cap** on per-request signature checks (e.g., `LIMIT 200`)
  3. **Per-IP rate limit** on the endpoint
  4. If the provider supports it, **embed the tenant ID in the webhook URL** (`/api/webhooks/foo/<connection_id>`) so lookup is O(1)
- **Rate-limit key fallback.** If your rate-limit key includes an attacker-controllable or potentially-missing identifier (IP, user-id, session-id), do NOT fall back to a shared constant string when it's absent. Either (a) refuse the request, (b) fall back to a per-resource identifier the attacker can't share (per-email for signup, per-Stripe-customer for billing), or (c) explicitly fail-open and log. A shared `'unknown'`/`'anon'` bucket is a lockout vector — one attacker pinning the bucket locks out every user behind that proxy path.
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
- **Baseline header starter values** (paste-and-tune):
  | Header | Value |
  |---|---|
  | `Strict-Transport-Security` | `max-age=63072000; includeSubDomains; preload` — preload requires verifying every `*.example.com` serves HTTPS first |
  | `X-Content-Type-Options` | `nosniff` |
  | `X-Frame-Options` | `DENY` (defence-in-depth alongside CSP `frame-ancestors`) |
  | `Referrer-Policy` | `strict-origin-when-cross-origin` |
  | `Permissions-Policy` | `camera=(), microphone=(), geolocation=(), browsing-topics=()` — note `interest-cohort` is the legacy FLoC name (Chrome ≤ 100); current Chrome uses `browsing-topics` |
  | `Content-Security-Policy` | start with `frame-ancestors 'self'`; full CSP needs per-site script audit (inline `<style>`, JSON-LD, analytics) |

  HSTS preload submission is sticky — removal takes months. Verify before submitting.
- Where security headers live, by framework:
  - Next.js: `next.config.{js,ts}` `headers()` block; `vercel.json` `headers`
  - Rails: `config/initializers/secure_headers.rb`, `config/application.rb`
  - Express: `app.use(helmet())`
  - Django: `SECURE_*` settings in `settings.py`
- **Runtime-API mismatch.** Code running in Edge / Workers / V8-isolate runtimes can't load Node-only modules. Imports of `node:crypto`, `node:fs`, `node:buffer`, `node:net`, etc. inside Next.js `middleware.ts` / Cloudflare Workers / Vercel Edge functions compile cleanly and fail at first request with `Failed to load external module`. Audit middleware and edge-marked routes for Node-only imports; prefer Web Crypto (`crypto.subtle`) for portable code
- **Rails admin-engine mounts.** Grep `config/routes.rb` for engine and dashboard mounts (PgHero, Sidekiq::Web, Flipper UI, Mission Control, Audit1984) and verify the auth middleware in the corresponding initializer applies in *every* environment reachable from the internet — not just production:

  ```bash
  grep -E "mount .+::(Engine|Web|UI)|mount .+::App" config/routes.rb
  grep -rn "Rails.env.production?" config/initializers/ | \
    grep -B1 -A5 "Auth::Basic\|authenticate\|secure_compare"
  ```

  The README examples for PgHero, Sidekiq::Web, Flipper, and Mission Control all wrap auth in `if Rails.env.production?`, which leaves staging, review apps, and preview deploys serving the admin UI anonymously. Fix shape: switch the guard to `unless Rails.env.local?` (Rails 7.1+ helper for `development || test`), and add a fail-closed check that refuses access when the auth env vars are unset.
- **Concurrent-execution races on paid endpoints.** When an endpoint triggers paid downstream work (LLM calls, third-party APIs, scrape jobs), look for `SELECT` followed by a `runX()` call without an intervening atomic claim, and unconditional `UPDATE … SET status='processing'` writes. Two concurrent requests can both pass the read-side check and both run. Fix: conditional `UPDATE … WHERE id = ? AND status = 'pending' RETURNING …`, or a Postgres advisory lock. Charge rate-limit budget only on a successful claim so polling and retries don't burn quota.

(Note: This bullet lives under A05 because the failure manifests as a misconfigured invariant guard. The race pattern itself spans A04 / A05 / A08 depending on framing.)

- **Source-tree hygiene.** Grep for sync-conflict duplicates and dead code that could let a reviewer fix the canonical file while leaving a vulnerable copy in place:

  ```bash
  find . \( -name '* 2.*' -o -name '* 3.*' -o -name '*.orig' \
       -o -name '*~' -o -name '*.bak' \) -not -path '*/node_modules/*'
  ```

  Treat findings as A05 — the canonical file may be patched while the duplicate retains the vulnerability.
- **Next.js `headers()` rule merging.** Rules in `next.config.ts` `headers()` match per route and *merge* — a more-specific rule does not override headers it doesn't redeclare. Shipping `frame-ancestors 'none'` + `X-Frame-Options: DENY` in a `/:path*` default plus `frame-ancestors *` in a `/embed` override results in both `frame-ancestors *` and `X-Frame-Options: DENY` on the embed route (contradicting; older browsers may break framing). Verify with `curl -I` against the deployed origin — config inspection alone misses the merge. Either set XFO in every rule or drop it entirely (CSP `frame-ancestors` supersedes on modern browsers).
- **Auth middleware that doesn't exempt bearer/HMAC routes.** Cron jobs, Stripe / GitHub webhooks, and any route that authenticates via bearer token or HMAC need to be excluded from session-cookie middleware. Symptom: those routes silently 302 to `/login` on every deploy or scheduled invocation, the route-level signature check never runs, and the integration appears to "work" until it doesn't.
- **Bearer-token compare with unset env interpolation.** Comparisons that interpolate `process.env.X` without a presence check — `\`Bearer ${process.env.WEBHOOK_TOKEN}\`` — resolve to a literal `"Bearer undefined"` when the env var is missing. An attacker who guesses the env-not-set condition can replay that literal string. Assert presence at module load: `if (!process.env.WEBHOOK_TOKEN) throw new Error(...)`.
- **API routes returning HTML 302 redirects instead of JSON 401.** Auth middleware that 302s every unauthenticated request to `/login` breaks `fetch` clients (they follow the redirect and consume HTML), obscures auth state in monitoring, and lets attackers learn endpoint existence by 302 vs 404. API routes should return `401 application/json` with a machine-readable body.

### A06: Vulnerable Components
- Run `npm audit` (Node), `pip audit` (Python), or equivalent
- Check lock files for known vulnerable dependency versions
- Flag dependencies with critical CVEs
- Run `npm audit --omit=dev` alongside `npm audit` and triage by reachability:
  - Runtime-reachable (in `dependencies`) — must fix
  - Build-time-only (Vite, esbuild via drizzle-kit, postcss) — usually defer
  - Dev-only (linters, test libs) — defer
- For the full CVE picture and triage by reachability, invoke `dependency-audit`. A06 here is a one-line sanity check.

### A07: Authentication Failures
- Weak password policies
- Session management issues (missing secure/httpOnly flags, no expiry, no rotation)
- **Credential-as-cookie:** the cookie value *is* the credential (e.g. `cookies.set("admin_token", process.env.ADMIN_PASSWORD)` and equality-checked on read). Even with `httpOnly` and `secure`, this is plaintext-credential storage (CWE-522) and lacks rotation/revocation. Replace with an HMAC-signed expiring token verified via `crypto.subtle.verify` / `crypto.timingSafeEqual`
- **Non-constant-time credential comparison:** `submitted === expected` for passwords, API keys, or signatures leaks length and prefix-match via timing. Use `crypto.timingSafeEqual` (Node) or `crypto.subtle.verify` (Web Crypto)
- Missing rate limiting on login (credential stuffing risk)
- Broken password reset flows
- **Rails / Devise — `password_length` requires `:validatable`.** `config.password_length` in `config/initializers/devise.rb` is only enforced when the User model includes `:validatable` in its `devise :...` declaration. A model with `devise :database_authenticatable, :registerable, :recoverable, :rememberable` (no `:validatable`) accepts passwords of any length and any email format, regardless of what the initializer says. Grep: `^\s*devise\s+:` in `app/models/`; flag any line where `:validatable` is absent. Adding it on an existing app validates on create+update but does not retro-invalidate existing weak passwords.
- **NextAuth v5 / Auth.js footguns:**
  - `AUTH_SECRET` unset silently derives a weak dev value — assert presence at module load: `if (!process.env.AUTH_SECRET) throw ...`
  - Credentials provider `authorize()` has no built-in rate limit — wrap or add upstream limiter; otherwise credential stuffing is trivial
  - Account-existence enumeration via signup error strings ("email already exists") — return a uniform "check your email" response
  - JWT strategy + DrizzleAdapter / PrismaAdapter — the adapter is a near no-op in this combination; revocation must be designed in explicitly
- Grep for: `cookies.set\(.*process\.env`, `=== .*PASSWORD`, `!== .*SECRET`, `!== .*Bearer.*\${`

### A08: Data Integrity Failures
- Unsafe deserialization of user input
- Missing integrity checks on CI/CD pipelines
- No lockfile integrity verification (SRI hashes)
- **External-resource overwrite without state check.** Any handler that creates a provider-side resource (Stripe payment intent, subscription, webhook subscription) and stores the ID on a DB row should check whether a prior resource is still in-flight before overwriting. The old `clientSecret` / token may still be held by the client; on completion, the webhook handler may not find the row because the ID has changed (money lands, DB sits at `processing` forever). Fix: before creating a new resource, retrieve the existing one. If status is non-terminal (`processing`, `requires_payment_method`, `requires_action`) and parameters haven't changed, REUSE it — return the existing clientSecret. Only create a new resource when the prior one is canceled / succeeded or the parameters changed.
- **External side-effects before durable DB state.** When a handler both writes to the DB and triggers an external side-effect (email, charge, webhook, S3 write), the external call should come *after* the DB write commits. The failure mode of "DB durable, external retried" is recoverable; "external done, DB stale" is not. Fix pattern: reserve-then-act. Issue a conditional UPDATE that flips the row to the post-action state guarded by the pre-action state (`WHERE status='draft'`). If 0 rows, refuse. If 1 row, call the provider. On provider failure, the row already reflects intent — alert and retry. Bonus: this also makes the handler idempotent.

### A09: Logging & Monitoring Failures
- Auth events not logged (login, failure, privilege changes)
- Sensitive data written to logs (passwords, tokens, PII)
- No alerting on suspicious patterns
- **Silent error swallowing.** Empty catch blocks hide both bugs and attack signals (rate limiter falling over, deserialization errors, auth failures).
  - Grep for: `catch \{\}`, `catch (_) \{\}`, `catch (_e) \{\}`, `.catch(() => {})`, `.catch(() => null)`, `try { ... } catch { return null }`
  - Fix: at minimum log the error category (`error.name`, status code) without PII
- **Unauthenticated endpoints sending email from a verified domain to user-supplied addresses.** Any handler reachable without auth that triggers an outbound email — confirmation, password-reset to-be-claimed, invite, "we got your message" — to an attacker-supplied `to:` address, especially with attacker-influenced subject/body, is a phishing vector against your verified sender's deliverability reputation. Defences (pick one):
  1. Don't auto-confirm — replies happen when a human responds
  2. Require ownership proof before any reply email (verification link / double opt-in)
  3. Use a separate, plainly-templated `noreply@` sender with subject/body the attacker can't influence

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
  - Decimal-integer IPv4: `http://2130706433/` → 127.0.0.1
  - Hex IPv4: `http://0x7f000001/`
  - Octal IPv4: `http://0177.0.0.1/`; zero-padded `0010.0.0.1/` → 8.0.0.1 (octal!)
  - IPv4-mapped IPv6: `http://[::ffff:127.0.0.1]/` → block the whole `::ffff:*` range
  - Trailing-dot hostname: `http://localhost./`, `http://metadata.google.internal./`
  - Cloud metadata endpoints: AWS `169.254.169.254`, GCP `metadata.google.internal`, ECS `169.254.170.2`
  - CGNAT range: `100.64.0.0` – `100.127.255.255`
  - Link-local IPv6: `fe80::/10`; unique-local IPv6: `fc00::/7`
- Fetch-time guards: `redirect: "error"` (don't follow attacker-controlled redirects), explicit timeout, no following 3xx into the metadata service
- Note the TOCTOU between validation and fetch — DNS can resolve differently between the two (DNS rebinding). For high-risk callers, pin the resolved IP and connect by IP with `Host:` header, or use a vetted proxy
- **Image-optimizer-as-proxy** (Next.js, Nuxt, SvelteKit): `next.config.{ts,js}` with `images.remotePatterns: [{ hostname: '**' }]`, `domains: ['*']`, or any wildcard entry lets attackers route arbitrary URLs through your CPU/bandwidth.
  - Grep for: `remotePatterns`, `domains:` in image config
  - Fix: pin to specific known hostnames; leave empty if all images are local.
- Grep for: `fetch(`, `axios(`, `http.get(`, `urllib`, `requests.get(` with user input

## Verify Fixes at Runtime

After applying a fix, exercise the affected code path — do not stop at typecheck or build. Modern frameworks have runtime-only failure modes that compile cleanly:

- **Edge / Node split runtimes.** Next.js middleware, Cloudflare Workers, Vercel Edge — Node-only imports (`node:crypto`, `node:fs`) build successfully but throw on first request.
- **Lazy module loads.** Adapters/plugins loaded via `import()` or runtime DI surface only when the codepath runs.
- **Environment-variable fallthrough.** `Bearer ${process.env.X}` with X unset becomes a literal that the tests never hit because the test env defines X.

For each shipped fix, run the affected route or job and capture the response. `tsc --noEmit` + build success ≠ fix verified.

**For XSS / sanitizer-config fixes**, run the canonical payload set through the configured policy and confirm each is neutralized:

```
<img src=x onerror=alert(1)>
<a href="javascript:alert(1)">x</a>
<a href="data:text/html,<svg onload=alert(1)>">x</a>
<img srcset="javascript:alert(1) 1x,https://ok.com/a.png 2x">
<svg><script>alert(1)</script></svg>
<math><mtext></style><img src=x onerror=alert(1)></math>
<a href="//evil.com">protocol-relative</a>
<svg></svg><img/onerror=alert(1) src=x>
```

## Second-Opinion Pass

A single-pass audit reliably catches the categories on the checklist but misses the specific bypasses that aren't *in* the checklist (`localhost.` vs `localhost`, IPv4-mapped IPv6, status-enumeration via ordered 404/400/401, callback-URL control chars, concurrent-execution races on paid endpoints).

After producing the first report AND after applying fixes, run a second pass with explicit adversarial framing ("assume the author is overconfident; find what they missed") — ideally with a different model or agent entirely, to break correlated blind spots. Treat any disagreement with the first pass as the higher-value finding.

Common things to find in the second pass:
- New attack surface introduced by the fix itself (auth bypass via exempted routes, IDOR introduced by a new query)
- Comments that became stale during the rewrite
- Boundary conditions in the new code (env-unset fallthrough, empty input)
- Documentation drift between the fix and the report
- **Fixes that configure third-party libraries.** When the fix is a snippet from a library's own docs (auth, crypto, HTTP client, rate-limit middleware), the snippet may be correct *and still not run on your code path*. Before declaring fixed: grep the library at the pinned version, trace from your call site to the code path the config affects. Example: enabling Better Auth's `rateLimit` doesn't help if you call `auth.api.signInEmail(...)` programmatically — that bypasses the HTTP router where the limiter attaches.

## Report Format

For every OWASP category, document one of three states:

- **Findings** (with severity + remediation)
- **Clean** — explicitly state "Checked X, found no issues" with what you grepped for
- **N/A** — explain why the category doesn't apply (e.g. "A07 N/A: no authentication surface in this codebase")

Include an "Items checked and found clean" section in the executive summary. Audit credibility comes from proving you looked, not just from the findings list.

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
