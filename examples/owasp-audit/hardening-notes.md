# Hardening notes (not findings)

Gaps with no traced impact. No severity, no findings.json record.

- `src/app.js:4` — no security headers (no `helmet()`). The API only returns JSON and no HTML sink was found, so nothing traced; add `helmet()` for `X-Content-Type-Options: nosniff` and a default CSP. Effort: one line.
- `src/auth.js:7` — `crypto.scryptSync` with Node defaults (N=16384, r=8, p=1) is below OWASP's scrypt minimum (N=2^17, r=8, p=1). Pass explicit cost parameters and store them with the hash so they can be raised later. Effort: small, with a rehash-on-login path.
- `src/config.js:6` — 7-day JWTs with no revocation (no `jti`, no denylist, no token version on the user row). The traced consequence, a deleted user's token re-binding to a reused id, is the confirmed `CWE-613` record. Beyond that, shorten the lifetime or add a token version so a demoted or compromised user can be cut off. Effort: medium.
- `src/auth.js:28` — `req.user.role` is copied from the token claim but nothing reads it. Remove it, so a future check doesn't trust a stale or forged claim. Effort: trivial.
- `src/auth.js:27` — `jwt.verify` is called without `{ algorithms: ["HS256"] }`. The alg:none path is closed today only because the secret is always truthy (see rejected `CWE-347` record). Pin the algorithm. Effort: trivial.
- `src/routes/notes.js:13` — `SORT_COLUMNS[req.query.sort]` also resolves inherited keys (`__proto__`, `constructor`), which pass the `!order` check and cause a 500. Use `Object.hasOwn(SORT_COLUMNS, sort)` or a `Map`. Effort: trivial.
- `src/routes/users.js:17-18` — login skips scrypt when the email doesn't exist, so response time reveals which emails are registered. Signup already reveals this directly (duplicate email → error), so it adds nothing today; run a dummy `checkPassword` on a miss if signup is ever made non-enumerating. Effort: small.
- `src/app.js:16` — the only logging is `console.error(err)`. No log lines for login success/failure, signup or admin user deletion (`src/routes/admin.js:12-15`), and no alerting. Add structured auth and admin-action events. Effort: small.
- `src/routes/admin.js:13-14` — the two deletes are not in a transaction; if the second fails, the user's notes are gone but the user remains. Wrap them in `db.transaction(...)`. Effort: trivial.
- `src/app.js:20` — the app serves plain HTTP, and passwords and Bearer tokens cross that hop. TLS has to terminate in front of it. Owner check: `curl -sI http://<origin>/healthz` should redirect to HTTPS, and `curl -sI https://<origin>/healthz | grep -i strict-transport` should show HSTS. Effort: deployment config.
- `src/routes/users.js:7`, `src/routes/preview.js:8`, `src/routes/notes.js:33` — signup (one scrypt per call), preview fetches (up to 5 s / 1 MB each) and note creation have no rate limits or quotas. No metered cost was traced. Add per-IP/per-user limits alongside the login limiter. Effort: small.
- `src/routes/notes.js:33-35` and `src/routes/users.js:8-9` — no type or length validation on `title`, `body`, `email` and `password` (non-strings and missing fields surface as 500s via the error handler). Validate with a schema and return 400. Effort: small.
