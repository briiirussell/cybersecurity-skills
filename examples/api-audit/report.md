# API Security Audit: notes-api (examples/target)

**Date:** 2026-10-26
**Skill:** api-audit
**Run profile:** full, standard (every REST surface; one independent verifier per candidate; one coverage-critic wave)
**Method:** read-only static review. The app was not run and no requests were sent. Every proof of concept below is a **proposed** request pair, and every confirmed record has `reproduced: false`, so confidence is capped at medium.
**Coverage:** complete for the API surface: 29 ledger units, none deferred or blocked. Two units are out of scope and handed off: dependency advisories (`dependency-audit`) and committed credentials (`secrets-audit`).

| Verdict | Count |
|---|---|
| confirmed | 7 (1 critical, 3 high, 1 medium, 2 low) |
| needs_validation | 1 |
| rejected | 4 |

Rendered from [`findings.json`](findings.json) and [`coverage.json`](coverage.json). If this report and the JSON disagree, the JSON wins.

## Confirmed findings

#### [CRITICAL] API2: JWT signing secret falls back to the hard-coded string "changeme", so tokens for any user, including admins, can be forged
**Fingerprint:** `api-audit/CWE-798/src/config.js/jwtSecret`  **Verdict:** confirmed
**Endpoint:** every route behind `requireAuth` (`/api/notes/*`, `POST /api/preview`, `/api/admin/*`)
**Handler:** `src/config.js:5`   **CWE:** CWE-798   **OWASP:** API2:2023

**Description:** `jwtSecret` is `process.env.JWT_SECRET || "changeme"`. The shipped `.env.example:3` leaves `JWT_SECRET=` empty, an empty string also falls through `||`, and nothing loads `.env` or refuses the default at startup. An unauthenticated attacker can sign `{sub: <id>}` with "changeme" and `jwt.verify` (`src/auth.js:27`) accepts it. `requireAdmin` re-reads the role from the database, but it does so for the forged `sub`, so forging an admin's id (ids are small sequential integers) also passes the admin check.

**Paired proof of concept (proposed, not run):** authn pair. Both requests are identical except for the token.
```
# Baseline: token signed with a random secret (expected: 401 invalid token)
curl -s -i https://TEST-HOST/api/notes -H "authorization: Bearer $TOKEN_SIGNED_WITH_RANDOM_SECRET"

# Attack: same request, token = HS256 {"sub":1} signed with "changeme" (finding if 200 with user 1's notes)
curl -s -i https://TEST-HOST/api/notes -H "authorization: Bearer $TOKEN_SIGNED_WITH_CHANGEME"
```

**Vulnerable code:**
```js
jwtSecret: process.env.JWT_SECRET || "changeme",
```
**Remediation:**
```js
const jwtSecret = process.env.JWT_SECRET;
if (!jwtSecret || jwtSecret.length < 32) throw new Error("JWT_SECRET must be set (>= 32 chars)");
module.exports = { /* ... */ jwtSecret };
```
Rotate the secret on any deployment that may have run with the default, because every token issued there is forgeable.
**Counterevidence:** The verifier looked for a startup assertion, issuer or audience checks, and a session lookup backed by the database. None exist. The signature check runs on every path but fails open with the shipped default. The fact that an operator can set `JWT_SECRET` does not refute the finding, because the shipped default is unsafe.
**Verification:** Start the app without `JWT_SECRET`. It must refuse to boot. With a real secret set, the "changeme"-signed request above must return 401.

#### [HIGH] API1: GET /api/notes/:id returns any user's note to any authenticated user (BOLA)
**Fingerprint:** `api-audit/CWE-639/src/routes/notes.js/GET-notes-id`  **Verdict:** confirmed
**Endpoint:** `GET /api/notes/:id`
**Handler:** `src/routes/notes.js:28`   **CWE:** CWE-639   **OWASP:** API1:2023

**Description:** The note is loaded with `SELECT * FROM notes WHERE id = ?` and nothing else. There is no `owner_id` predicate, and the `shared` column (`src/db.js:18`) is never checked. Signup is open and note ids are sequential, so any account can read every note in the database. The sibling PATCH (`notes.js:41`) and DELETE (`notes.js:50`) routes do filter by owner.

**Paired proof of concept (proposed, not run):** owner vs. non-owner. Both requests are identical except for the token.
```
# Baseline: owner A reads A's note (expected: 200)
curl -s -i https://TEST-HOST/api/notes/$A_NOTE -H "authorization: Bearer $A_TOKEN"

# Attack: non-owner B reads A's note (expected 404; finding if 200 with A's body)
curl -s -i https://TEST-HOST/api/notes/$A_NOTE -H "authorization: Bearer $B_TOKEN"
```

**Vulnerable code:**
```js
const note = db.prepare("SELECT * FROM notes WHERE id = ?").get(req.params.id);
```
**Remediation:**
```js
const note = db.prepare("SELECT * FROM notes WHERE id = ? AND (owner_id = ? OR shared = 1)")
  .get(req.params.id, req.user.id);
```
**Counterevidence:** `requireAuth` (`notes.js:7`) runs on every path and fails closed, but it only establishes who the caller is. No other middleware, route guard or row-level rule is present, and `/search` is declared before `/:id`, so it does not shadow this route. The safe PATCH and DELETE siblings do not protect this route.
**Verification:** Replay the pair above. B must get 404 for A's unshared note and 200 once A sets `shared = 1`.

#### [HIGH] API3: Mass assignment in PATCH /api/notes/:id lets a user rewrite id and owner_id, taking over or planting notes in other accounts
**Fingerprint:** `api-audit/CWE-915/src/routes/notes.js/PATCH-notes-id`  **Verdict:** confirmed
**Endpoint:** `PATCH /api/notes/:id`
**Handler:** `src/routes/notes.js:43`   **CWE:** CWE-915   **OWASP:** API3:2023

**Description:** The ownership check (`notes.js:41`) proves only that the caller owns the note at `req.params.id`. Then `_.merge(note, req.body)` copies every key in the body onto that row object, mutating it in place. The UPDATE at `notes.js:45` takes `owner_id` from the merged object and targets `WHERE id = note.id`, which is also attacker-chosen. Sending `{"id": <victim note>}` on your own note overwrites the victim note's title, body and shared values and makes you its owner. Sending `{"owner_id": <victim user>}` plants a note in the victim's account.

**Paired proof of concept (proposed, not run):** payload vs. benign. Same URL (the attacker's own note) and same token. Only the `id` field is added.
```
# Baseline: benign edit of own note (expected: 200; only A_NOTE changes)
curl -s -i -X PATCH https://TEST-HOST/api/notes/$A_NOTE -H "authorization: Bearer $A_TOKEN" \
  -H "content-type: application/json" -d '{"title":"x"}'

# Attack: same request plus "id" (finding if B_NOTE now has title "x" and owner_id = A)
curl -s -i -X PATCH https://TEST-HOST/api/notes/$A_NOTE -H "authorization: Bearer $A_TOKEN" \
  -H "content-type: application/json" -d '{"title":"x","id":'$B_NOTE'}'
```

**Vulnerable code:**
```js
const updated = _.merge(note, req.body);
db.prepare("UPDATE notes SET owner_id = ?, title = ?, body = ?, shared = ? WHERE id = ?")
  .run(updated.owner_id, updated.title, updated.body, updated.shared, note.id);
```
**Remediation:**
```js
const { title = note.title, body = note.body, shared = note.shared } = req.body;
db.prepare("UPDATE notes SET title = ?, body = ?, shared = ? WHERE id = ? AND owner_id = ?")
  .run(title, body, shared ? 1 : 0, req.params.id, req.user.id);
```
**Counterevidence:** Nothing re-checks ownership after the merge. No allow-list or schema validation sits between `:43` and `:45`. `id` is not in the SET list, so no primary-key conflict is raised. The `owner_id` foreign key rejects only users that do not exist.
**Verification:** Replay the attack. B's note must be unchanged and A's note must be the only row updated. Sending `{"owner_id": <B>}` must leave `owner_id` as A.

#### [HIGH] A05:2025 (Injection): SQL injection in GET /api/notes/search via q reads every user's notes and every password hash
**Fingerprint:** `api-audit/CWE-89/src/routes/notes.js/GET-notes-search`  **Verdict:** confirmed
**Endpoint:** `GET /api/notes/search?q=`
**Handler:** `src/routes/notes.js:22`   **CWE:** CWE-89   **OWASP:** A05:2025 (OWASP API Top 10 2023 has no injection category)

**Description:** `q` is interpolated into `... title LIKE '%${q}%'`. A quote breaks out of the LIKE string. `OR 1=1 --` drops the owner filter, and `UNION SELECT` against `users` (notes has 6 columns) returns every email, role and `salt:hash` scrypt password hash. better-sqlite3 compiles a single statement and `.all()` needs a statement that returns rows, so the impact is read-only. SQLite errors are returned to the caller (`src/app.js:17`), which makes building the payload easier.

**Paired proof of concept (proposed, not run):** payload vs. benign. Same token. Only the value of `q` changes.
```
# Baseline: benign search (expected: only the caller's matching notes)
curl -s -G https://TEST-HOST/api/notes/search --data-urlencode "q=groceries" -H "authorization: Bearer $A_TOKEN"

# Attack: finding if other users' notes are returned
curl -s -G https://TEST-HOST/api/notes/search --data-urlencode "q=' OR 1=1 --" -H "authorization: Bearer $A_TOKEN"
```

**Vulnerable code:**
```js
db.prepare(`SELECT * FROM notes WHERE owner_id = ${req.user.id} AND title LIKE '%${q}%'`).all();
```
**Remediation:**
```js
db.prepare("SELECT * FROM notes WHERE owner_id = ? AND title LIKE ? ESCAPE '\\'")
  .all(req.user.id, `%${String(q).replace(/[\\%_]/g, "\\$&")}%`);
```
**Counterevidence:** `requireAuth` is no barrier because signup is open. Nothing validates, casts or escapes `q`, and qs arrays or objects are stringified back by the template literal. The driver's single-statement rule blocks stacked writes but not `OR` or `UNION`. The verifier rated the impact high rather than critical because the attack is read-only and scrypt slows offline cracking. The `req.user.id` interpolation on the same line is a second injection source, but it is reachable only with a token forged under the default secret, so it adds no impact beyond the critical finding above.
**Verification:** The attack request must return only the caller's notes whose title contains the literal text `' OR 1=1 --`, which is none.

#### [MEDIUM] API7: SSRF in POST /api/preview: any user can make the server request arbitrary internal URLs, with an error-message port-scan oracle
**Fingerprint:** `api-audit/CWE-918/src/routes/preview.js/POST-preview`  **Verdict:** confirmed
**Endpoint:** `POST /api/preview`
**Handler:** `src/routes/preview.js:12`   **CWE:** CWE-918   **OWASP:** API7:2023

**Description:** The only check is that the URL starts with `http://` or `https://` (`preview.js:11`). `axios.get(url)` then fetches any host, including loopback, RFC 1918 and link-local addresses, and follows redirects that never pass through the check. The response returns the page's `<title>`. When the fetch fails, `err.message` (ECONNREFUSED host:port, timeout, status code) and the stack come back through `src/app.js:17`, so the endpoint works as an internal port scanner. Full-body exfiltration is **not** claimed: only the `<title>` is returned, and the attacker controls only the URL of a GET.

**Paired proof of concept (proposed, not run):** payload vs. benign. Same token. Only the URL changes.
```
# Baseline: public URL (expected: 200 {"title":"Example Domain"})
curl -s -X POST https://TEST-HOST/api/preview -H "authorization: Bearer $A_TOKEN" \
  -H "content-type: application/json" -d '{"url":"https://example.com/"}'

# Attack: loopback port (finding if the error reveals ECONNREFUSED/127.0.0.1:6379 vs a different message for an open port)
curl -s -X POST https://TEST-HOST/api/preview -H "authorization: Bearer $A_TOKEN" \
  -H "content-type: application/json" -d '{"url":"http://127.0.0.1:6379/"}'
```

**Vulnerable code:**
```js
if (!/^https?:\/\//.test(url || "")) return res.status(400).json({ error: "http(s) url required" });
const page = await axios.get(url, { timeout: 5000, maxContentLength: 1_000_000 });
```
**Remediation:** Resolve the hostname, reject private, loopback, link-local and metadata ranges (including IPv4-mapped IPv6), connect to the IP you checked, set `maxRedirects: 0` (or re-check each hop), and return a generic error on failure. Route the request through an egress proxy that enforces the same rules where the platform allows it.
**Counterevidence:** The scheme regex is the strongest control. It runs on every path but limits neither host nor IP, and redirects skip it. The timeout and size cap limit duration and size, not destination. The repo has no proxy, interceptor or egress config. Impact is limited to medium because no credential read is shown. How much damage this does depends on what the deployed host can reach.
**Verification:** `http://127.0.0.1:6379/`, `http://169.254.169.254/` and a public URL that 302s to `http://10.0.0.1/` must all return the same generic 400, while `https://example.com/` still works.

#### [LOW] API8: Global error handler returns err.message and err.stack to any client, and turns login into an email-enumeration oracle
**Fingerprint:** `api-audit/CWE-209/src/app.js/errorHandler`  **Verdict:** confirmed
**Endpoint:** all routes. The cleanest case is `POST /api/users/login` (unauthenticated).
**Handler:** `src/app.js:17`   **CWE:** CWE-209   **OWASP:** API8:2023

**Description:** The error handler sends `{ error: err.message, stack: err.stack }` with status 500 for every error. If a login request names a registered email and leaves out the password, `checkPassword(undefined, ...)` throws inside `scryptSync` (`src/auth.js:13`) and the client gets a 500 with a stack trace. An unregistered email gets the normal 401. Malformed JSON bodies (`src/app.js:5`), duplicate-email signups (UNIQUE error) and array passwords on signup reach the same handler, and the stack traces leak absolute paths and the `node_modules` layout.

**Paired proof of concept (proposed, not run):** payload vs. benign. Identical unauthenticated requests. Only the email value changes.
```
# Baseline: unregistered email, no password (expected: 401 bad credentials)
curl -s -i -X POST https://TEST-HOST/api/users/login -H "content-type: application/json" -d '{"email":"nobody@example.test"}'

# Attack: registered email, no password (finding if 500 with TypeError message + stack)
curl -s -i -X POST https://TEST-HOST/api/users/login -H "content-type: application/json" -d '{"email":"alice@example.test"}'
```

**Vulnerable code:**
```js
res.status(500).json({ error: err.message, stack: err.stack });
```
**Remediation:**
```js
app.use((err, req, res, next) => {
  console.error(err);
  const status = err.status && err.status < 500 ? err.status : 500;
  res.status(status).json({ error: status === 500 ? "internal error" : "bad request" });
});
```
In `/login` and `/signup`, also reject a missing or non-string `email` or `password` with 400 before hashing.
**Counterevidence:** The uniform 401 branch at `users.js:18` never runs on the registered-email path, because the throw happens first. Signup already partly reveals which emails are taken, which is why the impact is rated low. The login oracle still adds a check that has no side effects and creates no account.
**Verification:** Both requests in the pair must return the same status and body, and no response may contain `stack`.

#### [LOW] API2: Tokens outlive account deletion, and SQLite rowid reuse can hand a deleted user's token the next new user's account
**Fingerprint:** `api-audit/CWE-613/src/auth.js/requireAuth-no-revocation`  **Verdict:** confirmed
**Endpoint:** `DELETE /api/admin/users/:id`, then any `/api/notes/*` route
**Handler:** `src/auth.js:28`   **CWE:** CWE-613   **OWASP:** API2:2023

**Description:** `requireAuth` trusts `claims.sub` for 7 days (`src/config.js:6`) and never checks that the user still exists. `users.id` is `INTEGER PRIMARY KEY` without `AUTOINCREMENT` (`src/db.js:8`), so after the highest-id user is deleted, the next signup is given the same id. The deleted user's still-valid token then authenticates as the new account, with full read and write access to that user's notes.

**Paired proof of concept (proposed, not run):** the same request with the same old token, sent before and after the variable under test (a new signup that reuses the id).
```
# Baseline: after admin deletes user N (the highest id), N's old token lists notes (expected: [])
curl -s https://TEST-HOST/api/notes -H "authorization: Bearer $DELETED_N_TOKEN"

# Attack: a new user signs up (receives id N) and creates a note; identical request (finding if the new user's note is returned)
curl -s https://TEST-HOST/api/notes -H "authorization: Bearer $DELETED_N_TOKEN"
```

**Vulnerable code:**
```js
const claims = jwt.verify(token, config.jwtSecret);
req.user = { id: claims.sub, role: claims.role };
```
**Remediation:** Add `AUTOINCREMENT` to `users.id` so ids are never reused (this needs a migration for existing databases). In `requireAuth`, look the user up and reject the token if the user is missing or if the token's `iat` predates a per-user `tokens_valid_after` column. Shorten the token lifetime.
**Counterevidence:** The only check that consults the database is `requireAdmin`, and it runs only on `/api/admin`. Foreign keys stop a deleted user whose id is not reused from creating notes. The preconditions (highest id, a following signup, inside 7 days) lower the likelihood, which is why the finding is rated low with medium impact. They don't remove the finding.
**Verification:** Delete the highest-id user and sign up a new one. The old token must get 401 and the new user must receive a fresh id.

## Needs validation

#### No rate limiting or lockout on POST /api/users/login and /signup
**Fingerprint:** `api-audit/CWE-307/src/routes/users.js/login-signup-rate-limit`  **Verdict:** needs_validation  **CWE:** CWE-307  **OWASP:** API4:2023
**Location:** `src/routes/users.js:15` (sink `src/auth.js:13`)

**Claim:** No limiter is mounted anywhere in `src/` and none is in `package.json`. Login allows unlimited password guesses against a known email, with only a minimum of 8 characters. Each login for a known email, and **every** signup (`users.js:10` hashes before the INSERT), runs a synchronous `scryptSync` that blocks the single Node thread, so a burst of signups degrades service for everyone without needing an account.

**Blockers:**
- Whether anything in front of the deployment (reverse proxy, WAF, API gateway, platform firewall) rate-limits `POST /api/users/login` and `POST /api/users/signup` before traffic reaches Node, and whether that limit is per IP or per account.

**Validation plan:** Run this against staging, or against production with written authorization, using a test account you own.
1. Check the edge config (nginx `limit_req`, Cloudflare or AWS WAF rate rules, gateway throttling) for rules on the two paths.
2. From one IP, send 200 logins with wrong passwords over about 60 seconds.
   - All 401, with no 429, block or slowdown: **confirmed**.
   - 429s or blocks after N requests: **rejected**, ruled out by that rule.
3. Repeat from a second IP after the first is blocked. If it succeeds, the limit is per IP only and distributed guessing remains possible.
4. While sending about 50 concurrent signups with random emails, poll `GET /healthz` from another client. Latency that climbs well above baseline and recovers when the load stops confirms the event-loop exhaustion path.

## Hardening notes (not findings)

- **`SORT_COLUMNS` lookup without an own-property check** (`src/routes/notes.js:13`). `?sort=constructor` reaches SQL as fixed engine text and causes a 500 that leaks the SQL error. Use `Object.hasOwn` or a `Map`. Trivial effort.
- **`jwt.verify` without an `algorithms` list** (`src/auth.js:27`). Pass `{ algorithms: ["HS256"] }` so the allow-list is set in this code rather than inferred by the library. Trivial effort.
- **Unused `role` claim** (`src/auth.js:18`, `:28`). It is copied into `req.user` but never read, so a later handler could trust it by mistake. Drop it from the token or stop copying it. Trivial effort.
- **No security headers; `x-powered-by` left on** (`src/app.js`). There is no traced impact on a JSON-only, Bearer-auth API. Add `helmet()` or `app.disable("x-powered-by")`. Trivial effort.
- **No pagination on `GET /api/notes`** (`src/routes/notes.js:15`). It returns only the caller's own rows, so no boundary is crossed. Add `LIMIT`/`OFFSET` with a cap. Small effort.
- **No per-user quota on `POST /api/preview`** (`src/routes/preview.js:12`). Each fetch is capped at 5 s and 1 MB, but nothing limits how many a user can make. Add a per-user rate limit. Small effort.
- **Preview `title` is untrusted third-party text** (`src/routes/preview.js:14`). It is returned as a JSON string. Clients must render it as text, not HTML. Rendering is outside this repo.
- **`notes.shared` is never read** (`src/db.js:18`). The README promises sharing, but no endpoint implements it. Fixing the BOLA finding is the moment to define what shared means.

## Rejected (do not re-raise)

| Fingerprint | Claim | Ruled out by | Location |
|---|---|---|---|
| `api-audit/CWE-1321/src/routes/notes.js/PATCH-notes-id-merge` | Prototype pollution via `_.merge(note, req.body)` | lodash 4.17.15's merge skips `__proto__` and function-valued `constructor` keys, and the version is pinned by the lockfile. No gadget in the app either. Confidence medium: the control is in the dependency, not in repo source. Owner check after `npm ci` is in `findings.json` | `package-lock.json:554` |
| `api-audit/CWE-285/src/auth.js/requireAdmin-role-claim` | Admin access trusts the JWT role claim (BFLA) | `requireAdmin` re-reads the role from `users` by id and returns 403 unless it is `admin`. It is applied router-wide at `admin.js:6`, and `req.user.role` is never read | `src/auth.js:36` |
| `api-audit/CWE-347/src/auth.js/requireAuth-jwt-alg` | `alg:none` or algorithm confusion accepted | The secret is always a non-empty, non-PEM HMAC string, which puts jsonwebtoken 8.5.1 on its signature-required, HS-only path. Errors return 401. Confidence medium: the deciding check is inside the library | `src/config.js:5` |
| `api-audit/CWE-89/src/routes/notes.js/GET-notes-sort` | SQL injection via `ORDER BY ${order}` | Only `SORT_COLUMNS` property values (or fixed `Object.prototype` text) can reach SQL. Unknown keys get 400 | `src/routes/notes.js:13` |

## Items checked and found clean

Generated from the `covered` and `not_applicable` units in `coverage.json`.

| Surface | Boundary | Category | Invariant: result |
|---|---|---|---|
| `GET /healthz` | anonymous → app | API9 | No internal state returned: holds (static "ok", `app.js:12`) |
| App middleware stack | attacker origin → authenticated responses | API8 | No cross-origin credentialed read: holds (no CORS middleware; Bearer header, not a cookie). Body size bounded: holds (100kb). Headers: absent, hardening note |
| Route inventory | internet → undocumented endpoints | API9 | No legacy, debug or unknown routes: holds (12 routes plus the error handler). No OpenAPI spec exists to reconcile against; the README's sharing feature is not implemented |
| `POST /api/users/signup` | anonymous → elevated role | API3 | Caller cannot choose a role: holds (`users.js:8`, `:10`; DB default `user`). Response has no secrets: holds |
| `POST /api/users/signup` | automated client → business flow | API6 | Not applicable: there are no stock, seat, coupon, vote or referral flows |
| `GET /api/notes` | user A → user B's notes | API1 | List scoped to the caller: holds (`notes.js:15` binds `req.user.id`) |
| `GET /api/notes?sort=` | user → arbitrary SQL | A05:2025 | Only server-defined ORDER BY text: holds (rejected candidate above) |
| `POST /api/notes` | user A → note owned by B | API3 | Caller cannot set `owner_id` or `shared`: holds (`notes.js:34`, `:35`) |
| Note responses (GET /, /search, /:id, PATCH) | user → extra fields | API3 | No sensitive columns beyond the note itself: holds (notes schema `db.js:13-20`) |
| `DELETE /api/notes/:id` | user A → user B's note | API1 | Delete scoped to the owner: holds (`notes.js:50`) |
| All `/api/notes` routes | anonymous → notes API | API5 | No handler reachable without a verified token: holds (`notes.js:7`) |
| `POST /api/preview` | remote page → API consumers | API10 | Upstream content not executed server-side: holds (only `<title>` text returned as JSON) |
| `POST /api/preview` | user → server resources | API4 | Each fetch bounded: holds (5 s, 1 MB). No per-user quota, hardening note |
| `GET /api/admin/users` | regular user → admin function | API5 | Only admins confirmed in the DB: holds (`admin.js:6`, `auth.js:36-37`), **as long as token subjects are authentic** (see the critical finding). Projection excludes `password_hash`: holds |
| `DELETE /api/admin/users/:id` | regular user → admin function | API5 | Only admins confirmed in the DB: holds, same guard and same dependency on the token secret |
| GraphQL, RPC, webhooks, WebSocket, jobs | n/a | n/a | Not applicable: none exist (grep of `src/` and `package.json`) |

## Deferred / out of scope

Nothing in scope was deferred or blocked. Two surfaces are out of scope for this skill and handed off:

- **Pinned dependencies** (axios 0.21.0, express 4.17.1 with qs 6.7.0, jsonwebtoken 8.5.1, lodash 4.17.15): run `dependency-audit` for known advisories. This run reasoned about library behaviour only where a call site depended on it (lodash merge, jsonwebtoken verify, axios redirects).
- **Credential values in `.env.example`** (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`): run `secrets-audit`. They are not an API surface. The values match AWS's documented example key pair.

The run is static-only. No finding was reproduced. Before a fix is called verified, run the request pairs above against a local or staging instance (see each finding's **Verification** line).
