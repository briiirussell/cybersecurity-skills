# Security Audit Report
## Project: notes-api (examples/target)   ## Stack: Node.js, Express 4.17.1, better-sqlite3 9.4.3, jsonwebtoken 8.5.1, axios 0.21.0, lodash 4.17.15   ## Date: 2026-10-26
## Mode: full — static, read-only (no git history in the target, so no base/head sha)
## Profile: standard   ## Coverage: complete (3 units out of scope by engagement: dependency advisory sweep, frontend, dynamic testing)
## Prior run: none — carried forward: 0, re-verified: 0

### Summary
- Confirmed: 8 (Critical 0 | High 4 | Medium 2 | Low 2)
- Needs validation: 3   Rejected: 7   Hardening notes: 12
- Units: 21 covered, 11 candidate, 1 not applicable, 0 deferred, 3 out of scope
- Static review only: nothing was run, so no finding is `reproduced` and confirmed confidence is capped at medium. `npm audit` was not run (it needs network), so the dependency picture is limited to what the lockfile shows.

### Confirmed findings

#### [HIGH] A04:2025: JWT signing secret falls back to the hard-coded string "changeme" when JWT_SECRET is unset or empty  `owasp-audit/CWE-321/src/config.js/jwtSecret`
**File:** `src/config.js:5`   **CWE:** CWE-321   **Confidence:** medium

**Trace:** entrypoint `src/auth.js:22` (requireAuth reads the Bearer token from the attacker's Authorization header. It runs on notes (notes.js:7), preview (preview.js:8) and admin (admin.js:6)) → propagation `src/config.js:5` (jwtSecret = process.env.JWT_SECRET || "changeme". An unset or empty env var silently becomes the public literal) → propagation `src/auth.js:27` (jwt.verify(token, config.jwtSecret) accepts any HS256 token signed with "changeme". The app's own tokens are signed the same way (auth.js:18)) → propagation `src/auth.js:28` (req.user.id comes from the forged claims.sub, with no check that the user exists) → propagation `src/auth.js:36` (requireAdmin looks up the DB role for the forged id, so a forged sub equal to an admin's id passes line 37) → sink `src/routes/admin.js:14` (DELETE /api/admin/users/:id deletes any user and their notes (line 13). GET /api/admin/users (line 9) lists every email and role)

**Conditions:** system_configuration: JWT_SECRET is unset or empty in the runtime environment (the shipped default path); authentication_level: None. An anonymous internet client forges the token; data_state: Admin takeover needs an admin row and its id. Ids are sequential, and once the attacker has any admin token, GET /api/admin/users lists all of them

**Description:** JWT signing secret falls back to the hard-coded string "changeme" when JWT_SECRET is unset or empty. Evidence: `src/config.js:5` Hard-coded fallback literal "changeme" for the JWT secret; `.env.example:3` The template ships JWT_SECRET= empty. An empty string is falsy, so it also falls through to "changeme"; `src/app.js:20` The app starts without checking that JWT_SECRET is present or strong. Nothing loads .env (no dotenv), so a plain npm start runs on the fallback; `src/db.js:8` users.id is INTEGER PRIMARY KEY, so ids to forge are sequential and easy to guess.

**Counterevidence:** Checked for a startup presence or strength check on JWT_SECRET: none. JWT_SECRET appears only at config.js:5. There is no dotenv or other config loader, so the secret comes only from the process environment, and copying .env.example to .env changes nothing. requireAuth trusts claims.sub as-is. requireAdmin reads the role from the DB, which defeats a forged role claim but not a forged sub. An algorithms allow-list would not help, because the attacker signs with the same HS256 secret the app uses. Whether a particular deployment exports a real JWT_SECRET is the one fact outside the code. Under the unsafe-shipped-default rule, that lowers likelihood and confidence but does not rule the finding out.

**Vulnerable Code:** `src/config.js:2-8`

```js
module.exports = {
  port: Number(process.env.PORT) || 3000,
  databasePath: process.env.DATABASE_PATH || "./notes.db",
  jwtSecret: process.env.JWT_SECRET || "changeme",
  jwtExpiresIn: "7d",
  backupBucket: process.env.BACKUP_BUCKET,
};
```

**Remediation:**

```js
const jwtSecret = process.env.JWT_SECRET;
if (!jwtSecret || jwtSecret.length < 32) {
  throw new Error("JWT_SECRET must be set to at least 32 random characters");
}
module.exports = { /* ... */ jwtSecret, /* ... */ };
```
Fail closed at startup, and rotate any secret that was ever `changeme`. That rotation invalidates all existing tokens, which is the point.

**Verification:** `env -u JWT_SECRET npm start` and `JWT_SECRET= npm start` both exit with the error. A token signed with `changeme` (`jwt.sign({sub:1,role:"admin"},"changeme")`) gets 401 from `GET /api/notes` on a correctly configured instance.

**Disposition:** not set (open; triage with `finding-triage`)

#### [HIGH] A01:2025: Any user can read any other user's note by id (IDOR)  `owasp-audit/CWE-639/src/routes/notes.js/GET-note-by-id`
**File:** `src/routes/notes.js:28`   **CWE:** CWE-639   **Confidence:** medium

**Trace:** entrypoint `src/routes/notes.js:27` (GET /api/notes/:id behind requireAuth (notes.js:7), which only authenticates. The attacker controls req.params.id) → sink `src/routes/notes.js:28` (SELECT * FROM notes WHERE id = ? binds only the id. There is no owner_id or shared predicate, and line 30 returns the whole row)

**Conditions:** authentication_level: Any authenticated user account (open signup); data_state: Other users have stored notes

**Description:** Any user can read any other user's note by id (IDOR). Evidence: `src/routes/notes.js:28` The query filters on id alone. req.user.id is never used in this handler; `src/routes/notes.js:30` res.json(note) returns the full row: owner_id, title, body, shared, created_at; `src/db.js:14` notes.id is INTEGER PRIMARY KEY, so ids are sequential and easy to enumerate; `src/routes/notes.js:41` The sibling PATCH /:id adds AND owner_id = ?, and DELETE at line 50 does too. Ownership was clearly intended.

**Counterevidence:** Walked app.js:8 -> notes.js:7 -> notes.js:27-30. The only control is requireAuth (auth.js:22). It authenticates without authorizing, and open signup (users.js:7) gets past it. The handler never compares note.owner_id with req.user.id. The shared column (db.js:18) exists, but this route doesn't read it. /search is registered before /:id, so route shadowing doesn't change anything. The query is parameterized, which rules out SQLi on this route but doesn't authorize the read.

**Vulnerable Code:** `src/routes/notes.js:27-31`

```js
router.get("/:id", (req, res) => {
  const note = db.prepare("SELECT * FROM notes WHERE id = ?").get(req.params.id);
  if (!note) return res.status(404).json({ error: "not found" });
  res.json(note);
});
```

**Remediation:**

```js
const note = db
  .prepare("SELECT * FROM notes WHERE id = ? AND (owner_id = ? OR shared = 1)")
  .get(req.params.id, req.user.id);
if (!note) return res.status(404).json({ error: "not found" });
```
Scope the read to the caller (plus `shared = 1` if sharing is intended), and return the same 404 for "missing" and "not yours".

**Verification:** User B requests user A's unshared note id and gets 404, the same body as for a non-existent id. User A still gets 200.

**Disposition:** not set (open; triage with `finding-triage`)

#### [HIGH] A05:2025: SQL injection in note search via the q query parameter  `owasp-audit/CWE-89/src/routes/notes.js/GET-search`
**File:** `src/routes/notes.js:22`   **CWE:** CWE-89   **Confidence:** medium

**Trace:** entrypoint `src/routes/notes.js:20` (GET /api/notes/search (router mounted at src/app.js:8). The only guard is router.use(requireAuth) at notes.js:7) → propagation `src/routes/notes.js:21` (q = req.query.q || "" goes through as-is: no validation, type check, escaping or length limit) → sink `src/routes/notes.js:22` (q is interpolated into a template-literal SQL string (title LIKE '%${q}%'), then passed to db.prepare(...).all() with no bound parameters)

**Conditions:** authentication_level: Any valid user JWT, available to anyone from the open POST /api/users/signup

**Description:** SQL injection in note search via the q query parameter. Evidence: `src/routes/notes.js:22` `SELECT * FROM notes WHERE owner_id = ${req.user.id} AND title LIKE '%${q}%'` is built by string interpolation. The sibling queries at lines 15, 28, 35, 41 and 50 use ? placeholders; `src/routes/users.js:7` POST /api/users/signup is open with no invite or approval, so anyone can get the JWT that requireAuth wants; `src/db.js:7` users table (id, email, password_hash, role) shares the database with notes (6 columns), so q=' UNION SELECT id,email,password_hash,role,0,'' FROM users-- matches the column count.

**Counterevidence:** requireAuth (src/auth.js:22) only authenticates. It does no authorization and never touches q. Open signup gets past it. The owner_id = ${req.user.id} predicate comes before the injection point, so a ' that closes the LIKE string followed by OR 1=1 or a UNION gets around it. q gets no validation or escaping. The SORT_COLUMNS allow-list (line 9) protects GET / only. better-sqlite3 prepare() takes a single statement, which blocks stacked writes, so the impact is reading data, not changing it. Express/qs can turn q into an array or object, which changes how it becomes a string but still leaves it injectable. The error handler (app.js:17) sends back SQL error text, which makes error-based tuning easier.

**Vulnerable Code:** `src/routes/notes.js:20-24`

```js
router.get("/search", (req, res) => {
  const q = req.query.q || "";
  const notes = db.prepare(`SELECT * FROM notes WHERE owner_id = ${req.user.id} AND title LIKE '%${q}%'`).all();
  res.json(notes);
});
```

**Remediation:**

```js
router.get("/search", (req, res) => {
  const q = typeof req.query.q === "string" ? req.query.q : "";
  const notes = db
    .prepare("SELECT * FROM notes WHERE owner_id = ? AND title LIKE ? ESCAPE '\\'")
    .all(req.user.id, `%${q.replace(/[\\%_]/g, "\\$&")}%`);
  res.json(notes);
});
```
Bind both values. Escape LIKE wildcards so a search for `%` doesn't match everything, and reject non-string `q`.

**Verification:** `GET /api/notes/search?q=x' UNION SELECT id,email,password_hash,role,0,'' FROM users--` as a normal user returns `[]` (no rows from `users`). A search for `%` returns only titles that contain a literal `%`.

**Disposition:** not set (open; triage with `finding-triage`)

#### [HIGH] A01:2025: PATCH /api/notes/:id merges the request body into the row, so id and owner_id are attacker-controlled and any note can be overwritten or taken over  `owasp-audit/CWE-915/src/routes/notes.js/PATCH-note`
**File:** `src/routes/notes.js:43`   **CWE:** CWE-915   **Confidence:** medium

**Trace:** entrypoint `src/routes/notes.js:40` (PATCH /api/notes/:id, behind express.json() (app.js:5) and requireAuth (notes.js:7)) → propagation `src/routes/notes.js:41` (Ownership check: SELECT * WHERE id = req.params.id AND owner_id = req.user.id loads the caller's own note as a plain row object that includes id and owner_id) → propagation `src/routes/notes.js:43` (_.merge(note, req.body) mutates that same row object in place with every body key, including id and owner_id. updated and note are the same object) → sink `src/routes/notes.js:45` (UPDATE notes SET owner_id=?, title=?, body=?, shared=? WHERE id=? runs with updated.owner_id ... note.id. note.id now holds the id from the body, not the one that passed the check)

**Conditions:** authentication_level: A valid JWT for any user account; data_state: The attacker owns at least one note, which POST /api/notes lets anyone create, so the check at line 41 passes

**Description:** PATCH /api/notes/:id merges the request body into the row, so id and owner_id are attacker-controlled and any note can be overwritten or taken over. Evidence: `src/routes/notes.js:43` Unfiltered _.merge of req.body into the row loaded by the ownership check. No allow-list, and id/owner_id are not stripped; `src/routes/notes.js:45` The WHERE clause binds note.id, which is the merged attacker-supplied value, not req.params.id. Ownership was only checked against req.params.id at line 41; `src/routes/notes.js:28` GET /:id has no owner filter, so victim note ids can be found (sequential INTEGER PRIMARY KEY, db.js:14).

**Counterevidence:** The ownership check at notes.js:41 runs first and fails closed, but it checks req.params.id. The merge then rewrites the row object it returned, so the UPDATE's WHERE id is no longer the checked value. Nothing between line 41 and line 45 validates the body, applies a schema or filters fields. express.json passes JSON numbers through and better-sqlite3 binds them as integers, so {"id": 7} matches row 7. owner_id NOT NULL REFERENCES users(id) (db.js:15) is satisfied when the attacker supplies their own id. The UPDATE has no owner_id predicate and no row-count check. The finding depends only on _.merge mutating and returning its first argument, which line 45 relies on by reading note.id after the merge. The deeper lodash internals don't matter here. Static only, not reproduced.

**Vulnerable Code:** `src/routes/notes.js:40-47`

```js
router.patch("/:id", (req, res) => {
  const note = db.prepare("SELECT * FROM notes WHERE id = ? AND owner_id = ?").get(req.params.id, req.user.id);
  if (!note) return res.status(404).json({ error: "not found" });
  const updated = _.merge(note, req.body);
  db.prepare("UPDATE notes SET owner_id = ?, title = ?, body = ?, shared = ? WHERE id = ?")
    .run(updated.owner_id, updated.title, updated.body, updated.shared, note.id);
  res.json(updated);
});
```

**Remediation:**

```js
router.patch("/:id", (req, res) => {
  const { title, body, shared } = req.body; // allow-list, never id/owner_id
  const info = db
    .prepare(`UPDATE notes SET title = COALESCE(?, title), body = COALESCE(?, body),
              shared = COALESCE(?, shared) WHERE id = ? AND owner_id = ?`)
    .run(title ?? null, body ?? null, shared === undefined ? null : Number(Boolean(shared)), req.params.id, req.user.id);
  if (!info.changes) return res.status(404).json({ error: "not found" });
  res.json(db.prepare("SELECT * FROM notes WHERE id = ?").get(req.params.id));
});
```
Drop `_.merge`, which also removes the prototype-pollution sink. Put the ownership predicate in the `UPDATE` itself, keyed on `req.params.id`.

**Verification:** User A sends `PATCH /api/notes/<A's note>` with `{"id": <B's note>, "owner_id": <A>, "title": "x"}`. B's note is unchanged and still owned by B, and only A's note title changes. `{"owner_id": <B>}` on A's own note leaves `owner_id` as A.

**Disposition:** not set (open; triage with `finding-triage`)

#### [MEDIUM] A07:2025: No rate limiting or lockout on POST /api/users/login (online password guessing)  `owasp-audit/CWE-307/src/routes/users.js/POST-login`
**File:** `src/routes/users.js:15`   **CWE:** CWE-307   **Confidence:** medium

**Trace:** entrypoint `src/routes/users.js:15` (POST /api/users/login, anonymous (router mounted at app.js:7 with only express.json in front of it). email and password come from req.body (line 16)) → propagation `src/routes/users.js:17` (User looked up by email. No attempt counter, lockout column or delay) → sink `src/routes/users.js:18` (checkPassword (src/auth.js:11-14, synchronous scryptSync). On a match, line 19 returns a 7-day JWT)

**Conditions:** authentication_level: None. The endpoint is anonymous; data_state: The target account's password appears in a guessing list (only 8+ characters is enforced); network_routing: No rate limiter at a proxy, edge or WAF in front of the app. None is defined in the repo

**Description:** No rate limiting or lockout on POST /api/users/login (online password guessing). Evidence: `src/app.js:5` The only global middleware is express.json({limit:'100kb'}). No rate-limit, slow-down or brute-force middleware; `package.json:10` The dependencies are axios, better-sqlite3, express, jsonwebtoken and lodash. No limiter package, here or in package-lock.json; `src/db.js:7` The users table has id, email, password_hash and role only. No failed-attempt or lockout state; `src/routes/users.js:9` The only password rule is length >= 8. No complexity or breached-password check.

**Counterevidence:** app.js mounts the users router with only express.json in front of it. users.js has no per-route middleware. config.js has no limiter settings, and the schema has no lockout columns. Grepping src/ for rate, limit, lock, attempt and throttle finds only the body-size limit. The repo has no proxy, WAF or deploy config, and app.listen serves directly. An edge limiter outside the repo could exist. That is recorded as a network_routing condition: it lowers confidence and doesn't remove the finding. Unknown emails return 401 before scrypt runs, so the per-attempt CPU cost only applies to existing accounts. Emails can be enumerated through the signup duplicate-email error (see CWE-209 finding).

**Vulnerable Code:** `src/routes/users.js:15-20`

```js
router.post("/login", (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare("SELECT id, role, password_hash FROM users WHERE email = ?").get(email);
  if (!user || !checkPassword(password, user.password_hash)) return res.status(401).json({ error: "bad credentials" });
  res.json({ token: issueToken(user) });
});
```

**Remediation:**

```js
const rateLimit = require("express-rate-limit");
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: true });
router.post("/login", loginLimiter, (req, res) => { /* ... */ });
```
Add a per-account failure counter with backoff, because per-IP limits alone don't stop distributed guessing. Pair it with a stronger password policy (length 12+, breached-password check).

**Verification:** Send 11 wrong-password `POST /api/users/login` requests for one email in under a minute. The 11th returns 429, and a correct password is also refused until the window passes.

**Disposition:** not set (open; triage with `finding-triage`)

#### [MEDIUM] A01:2025: Link preview fetches any user-supplied http(s) URL server-side (SSRF)  `owasp-audit/CWE-918/src/routes/preview.js/POST-preview`
**File:** `src/routes/preview.js:12`   **CWE:** CWE-918   **Confidence:** medium

**Trace:** entrypoint `src/routes/preview.js:8` (POST /api/preview, guarded only by requireAuth (any signed-up user, open signup at users.js:7)) → propagation `src/routes/preview.js:10` (url taken straight from req.body) → propagation `src/routes/preview.js:11` (The only check is the scheme regex /^https?:\/\//. Any host, IP literal, port or path passes) → sink `src/routes/preview.js:12` (axios.get(url, { timeout: 5000, maxContentLength: 1_000_000 }) makes the request from the server)

**Conditions:** authentication_level: Any user account (open signup); network_routing: What can be reached depends on what is on the server's network (loopback services, private ranges); environmental_dependency: Cloud metadata is reachable only on a cloud VM without IMDSv2/hop-limit or egress blocking, and even then plain-text responses yield no &lt;title>

**Description:** Link preview fetches any user-supplied http(s) URL server-side (SSRF). Evidence: `src/routes/preview.js:11` Only the scheme is checked. No allow-list, and no deny-list for loopback, RFC 1918, link-local, CGNAT or IPv6 ranges, so http://127.0.0.1:&lt;port>/, http://10.x/ and http://169.254.169.254/ all pass; `src/routes/preview.js:14` The &lt;title> of the fetched page goes back to the caller, so internal HTML pages leak their titles; `src/app.js:17` The error handler returns err.message and err.stack. Connection-refused, timeout and status-code errors tell the attacker whether an internal host or port is open.

**Counterevidence:** requireAuth (auth.js:22) only verifies a JWT, and signup hands one to anyone. The scheme regex at preview.js:11 is the strongest control. It runs on every path and fails closed, but it never looks at the host. express.json's size limit, the timeout and maxContentLength cap size and time, not the destination. The repo has no proxy, egress or network config. Redirect-following behaviour depends on axios internals that weren't read (no node_modules), but the finding doesn't depend on it, because an internal IP literal passes the check directly. What limits the impact: only a regex-matched &lt;title> is returned. Cloud metadata responses are plain text/JSON, so their title comes back null, and stealing metadata credentials is NOT shown. That keeps this at Medium, not High.

**Vulnerable Code:** `src/routes/preview.js:8-14`

```js
router.post("/", requireAuth, async (req, res, next) => {
  try {
    const { url } = req.body;
    if (!/^https?:\/\//.test(url || "")) return res.status(400).json({ error: "http(s) url required" });
    const page = await axios.get(url, { timeout: 5000, maxContentLength: 1_000_000 });
    const match = /<title>([^<]*)<\/title>/i.exec(page.data);
    res.json({ url, title: match ? match[1] : null });
```

**Remediation:** Resolve the host first, reject private, loopback, link-local, CGNAT, metadata and IPv6 ULA/link-local addresses (including IPv4-mapped IPv6), then connect to the vetted IP. Disable redirects, or re-validate every hop:
```js
const page = await axios.get(url, {
  timeout: 5000, maxContentLength: 1_000_000, maxRedirects: 0,
  httpAgent: ssrfSafeAgent, httpsAgent: ssrfSafeAgent, // e.g. an agent whose lookup() rejects non-public IPs
});
```
Also map fetch errors to a generic 502 so the error text stops working as a port-scan oracle. A vetted egress proxy is a valid alternative.

**Verification:** Run each URL in the checklist-details.md "A01: SSRF allow-list bypass set" (`http://127.0.0.1/`, `http://2130706433/`, `http://[::ffff:127.0.0.1]/`, `http://169.254.169.254/`, `http://localhost./`, a public URL that 302s to `http://127.0.0.1/`) through `POST /api/preview`. Each returns 400/502 with no internal error text. `https://example.com` still returns its title.

**Disposition:** not set (open; triage with `finding-triage`)

#### [LOW] A02:2025: Global error handler returns err.message and err.stack to any client, including anonymous ones  `owasp-audit/CWE-209/src/app.js/error-handler`
**File:** `src/app.js:17`   **CWE:** CWE-209   **Confidence:** medium

**Trace:** entrypoint `src/routes/users.js:7` (POST /api/users/signup, unauthenticated (also any route behind express.json at app.js:5, when sent a malformed JSON body)) → propagation `src/routes/users.js:10` (The INSERT throws synchronously when the email already exists (email TEXT UNIQUE, db.js:9). There is no try/catch, so Express 4 passes the throw to next(err)) → propagation `src/app.js:15` (The only error handler: a 4-arg middleware with no env gating and no status or message mapping) → sink `src/app.js:17` (res.status(500).json({ error: err.message, stack: err.stack }) sends the raw message and the full stack trace to the caller)

**Conditions:** authentication_level: None for the signup and malformed-body paths. The /api/preview error-text variant needs any account

**Description:** Global error handler returns err.message and err.stack to any client, including anonymous ones. Evidence: `src/app.js:14` Comment: 'Errors go back to the client so the frontend can show them.' The exposure is intentional; `src/app.js:17` err.stack goes into the response body, with no NODE_ENV check; `src/routes/preview.js:16` axios errors (internal network error text) reach the same handler through next(err).

**Counterevidence:** The signup validation (users.js:9) checks only that the fields are present and the password is long enough. It doesn't catch duplicates. No NODE_ENV or production check exists anywhere in the repo, and the custom handler replaces Express's default, which would hide stacks in production. The /api/preview variant needs an account (preview.js:8), but the signup and malformed-body paths are anonymous. Body-parser internals weren't read, but the signup path doesn't depend on them.

**Vulnerable Code:** `src/app.js:14-18`

```js
// Errors go back to the client so the frontend can show them.
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: err.message, stack: err.stack });
});
```

**Remediation:**

```js
app.use((err, req, res, next) => {
  const status = err.status && err.status < 500 ? err.status : 500;
  console.error({ name: err.name, code: err.code, path: req.path, status });
  res.status(status).json({ error: status === 500 ? "internal error" : "bad request" });
});
```
Log details server-side only. For signup, catch the UNIQUE error and return a generic response.

**Verification:** Repeat a signup with the same email, and send `POST /api/users/login` with body `{bad json`. The responses contain no `stack`, no file paths and no SQLite text (`grep -c 'at \|SqliteError\|node_modules'` on the body gives 0). The malformed body returns 400.

**Disposition:** not set (open; triage with `finding-triage`)

#### [LOW] A07:2025: A deleted user's still-valid JWT authenticates as whoever next receives the reused user id  `owasp-audit/CWE-613/src/auth.js/requireAuth-user-id-reuse`
**File:** `src/auth.js:28`   **CWE:** CWE-613   **Confidence:** medium

**Trace:** entrypoint `src/auth.js:22` (requireAuth runs on every notes route (notes.js:7) and takes the Bearer token) → propagation `src/auth.js:27` (jwt.verify checks only the signature and exp. No jti, token version or revocation list) → propagation `src/auth.js:28` (req.user.id = claims.sub, with no lookup to check that the users row still exists or is the same account) → propagation `src/routes/admin.js:14` (Admin DELETE /api/admin/users/:id removes the users row (and its notes at :13). Nothing invalidates the user's tokens) → propagation `src/db.js:8` (users.id is INTEGER PRIMARY KEY without AUTOINCREMENT, so SQLite assigns max(rowid)+1 and hands out the id of a deleted highest-id row again) → propagation `src/routes/users.js:10` (Open signup inserts a new user, who receives the reused id) → sink `src/routes/notes.js:15` (WHERE owner_id = req.user.id returns the new account's notes to the old token. The same scoping lets it create (:35), edit (:41-45) and delete (:50) notes as the new user)

**Conditions:** authentication_level: The attacker holds an unexpired JWT from an account that has since been deleted; authorization_role: An admin performs the deletion. There is no self-delete path; data_state: The deleted row had the highest users.id (or every higher row is also deleted) before the next signup; timing_dependency: The victim signs up within the remaining lifetime of the attacker's token (at most 7 days from issue)

**Description:** A deleted user's still-valid JWT authenticates as whoever next receives the reused user id. Evidence: `src/config.js:6` jwtExpiresIn: "7d". Old tokens stay valid for up to 7 days from issue; `src/auth.js:18` The token holds only sub and role. Nothing binds it to one account instance; `src/db.js:8` id INTEGER PRIMARY KEY, no AUTOINCREMENT.

**Counterevidence:** requireAdmin (auth.js:36-37) re-reads the users row, but only on /api/admin. Because the reused row has role 'user', even a deleted admin's token can't reach admin routes. That control isn't on the notes routes. requireAuth never touches the DB. Expiry (jsonwebtoken default, internals not read) limits the window but doesn't stop the attack. No logout, revocation or token-version code exists. Preconditions: an admin deletes the attacker's account (there's no self-delete), the attacker's row has the highest id at that moment, and someone signs up before the attacker's newest token expires. The attacker can't choose the victim. Abuse accounts tend to be the newest rows, which makes the id condition plausible in exactly the deleted-for-abuse case. The verifier rated overall medium. The coordinator downgraded it to low (calibration: a real boundary crossing that needs unlikely preconditions). Static only.

**Vulnerable Code:** `src/auth.js:26-29`

```js
  try {
    const claims = jwt.verify(token, config.jwtSecret);
    req.user = { id: claims.sub, role: claims.role };
    next();
```

**Remediation:** Make ids non-reusable and bind tokens to a live account:
```sql
-- src/db.js
id INTEGER PRIMARY KEY AUTOINCREMENT
```
```js
// src/auth.js requireAuth, after jwt.verify
const row = db.prepare("SELECT id, token_version FROM users WHERE id = ?").get(claims.sub);
if (!row || row.token_version !== claims.tv) return res.status(401).json({ error: "invalid token" });
```
Issue `tv` in `issueToken`, and bump `token_version` on deletion, password change and role change.

**Verification:** Sign up user X (the highest id) and keep their token. Have an admin delete X, then sign up Y. X's old token gets 401 on `GET /api/notes`, and Y's id differs from X's.

**Disposition:** not set (open; triage with `finding-triage`)

### Needs validation

#### A03:2025: axios 0.21.0 (lockfile marks it "Critical security vulnerability fixed in v0.21.1") is used on a user-controlled URL; a redirect may bypass an egress proxy  `owasp-audit/CVE-2020-28168/package-lock.json/axios`
**Location:** `package-lock.json:38`   **CWE:** CWE-918   **Confidence:** low

**What the code shows:** entrypoint `src/routes/preview.js:8` POST /api/preview, behind requireAuth only → propagation `src/routes/preview.js:11` The url from req.body is checked only against /^https?:\/\//. No host allow-list and no redirect restriction → sink `src/routes/preview.js:12` axios.get(url, {timeout, maxContentLength}) with no maxRedirects, proxy or beforeRedirect option. axios resolves to 0.21.0 (package-lock.json:37-41). The repo has no egress-proxy control: no HTTP_PROXY, HTTPS_PROXY or NO_PROXY in .env.example, no proxy in config.js, and no proxy option on the call. If production uses no proxy, there is nothing for this to bypass. The direct SSRF is then the separate confirmed record (CWE-918), and this one is only outdated-dependency hygiene. The lockfile cites PR 3410 without naming CVE-2020-28168. Mapping the PR to that CVE, and the redirect-skips-proxy behaviour, come from advisory knowledge outside the repo and weren't checked (no node_modules, no network).

**Blockers:**
- Whether the production runtime routes outbound HTTP through an egress proxy (HTTP_PROXY/HTTPS_PROXY, which axios 0.21.0 honours by default) that is relied on to block internal or metadata destinations
- Whether the installed axios 0.21.0 sends a cross-host redirect hop directly instead of through the configured proxy (the CVE-2020-28168 behaviour)

**Owner-run check:** 1) In the production container: `printenv | grep -iE '^(https?|no)_proxy='`. If nothing prints, there is no proxy control. Close this as rejected, ruled out by the absence of a proxy (the direct-SSRF finding still applies). 2) If a proxy is set: run `npm ls axios` (expect axios@0.21.0) and `npm audit --omit=dev`. Then, locally, point HTTP_PROXY at a stub proxy that answers every request with a 302 to http://127.0.0.1:9999/internal, run a stub server on 9999, and call require('axios').get('http://preview.test/'). Confirmed: the stub on 9999 receives the request directly, so the redirect hop skipped the proxy. Rejected: the proxy receives the redirected request for 127.0.0.1:9999/internal. Upgrading axios (>= 0.21.1, ideally current 1.x) closes this either way.

#### A03:2025: Express 4.17.1 resolves qs 6.7.0, affected by CVE-2022-24999 (query-string \_\_proto\_\_ process hang), reachable pre-auth  `owasp-audit/CVE-2022-24999/package-lock.json/qs`
**Location:** `package-lock.json:821`   **CWE:** CWE-1321   **Confidence:** medium

**What the code shows:** entrypoint `src/app.js:12` GET /healthz, no auth. Every router mounted at app.js:7-10 also receives the raw query string before any route-level requireAuth → propagation `package-lock.json:346` express 4.17.1 (lock lines 320-321) depends on qs 6.7.0. app.js sets no 'query parser' override, so Express keeps its default extended (qs) parser → sink `package-lock.json:821` node_modules/qs resolves to 6.7.0. It is the only qs entry, with no nested patched copy. No control exists ahead of query parsing. requireAuth runs per route, after Express has already parsed req.query. The 100kb express.json limit applies only to bodies. The lockfile has one qs copy, with no override or resolution. Two facts are library internals or advisory data that this static, offline review couldn't check: that Express 4.17.1's default parser passes the payload to qs.parse in an exploitable way, and that qs 6.7.0 loops on the attacker-set length. Both match the public advisory (fixed in qs 6.7.3 and Express 4.17.3), but neither was checked against code.

**Blockers:**
- Whether the installed qs 6.7.0, called through Express 4.17.1's default extended query parser, blocks the event loop on a[\_\_proto\_\_]b&a[\_\_proto\_\_]&a[length]=100000000. This needs node_modules or npm audit, and both were out of scope here

**Owner-run check:** Locally, from the repo root: `npm ci && npm audit --omit=dev` (look for qs, GHSA for CVE-2022-24999). Then `PORT=3999 node src/app.js &` and run `curl -s -m 5 -o /dev/null -w '%{http_code}\n' 'http://localhost:3999/healthz?a[__proto__]b&a[__proto__]&a[length]=100000000'; curl -s -m 5 http://localhost:3999/healthz`. Confirmed: the first curl times out (exit 28) and the plain /healthz also stalls while node sits at 100% CPU. Rejected: both return quickly (200 / 'ok') and npm audit doesn't list qs.

#### A08:2025: Prototype pollution through _.merge of the JSON request body in PATCH /api/notes/:id  `owasp-audit/CWE-1321/src/routes/notes.js/PATCH-note-merge`
**Location:** `src/routes/notes.js:43`   **CWE:** CWE-1321   **Confidence:** low

**What the code shows:** entrypoint `src/routes/notes.js:40` PATCH /api/notes/:id behind requireAuth (notes.js:7). The caller must own the note (notes.js:41-42) → propagation `src/app.js:5` express.json parses the body with JSON.parse, which keeps "\_\_proto\_\_" as an own key. No schema or key filtering → sink `src/routes/notes.js:43` _.merge(note, req.body) deep-merges the whole untrusted body into a plain row object. Nothing in the repo filters keys, validates a schema or freezes Object.prototype. requireAuth and the owner check don't look at the body. The strongest possible control lives inside lodash 4.17.15. Public merge advisories (CVE-2018-3721, CVE-2018-16487) were fixed before 4.17.15, but node_modules isn't present, so that code wasn't read. Under the skill's rules, library trust can't support a rejection. The claimed impact isn't traced either: the only role check, requireAdmin (auth.js:36-37), reads an own property from a DB row, so a polluted isAdmin or role changes nothing there. One gadget does exist if pollution works: SORT_COLUMNS[req.query.sort] at notes.js:13 reads inherited keys, so a polluted string property would be interpolated into ORDER BY at notes.js:15, giving a process-wide pollution -> SQL injection chain. That chain stays unproven until the blocker resolves. The mass-assignment bug at this same sink is a separate, confirmed record (CWE-915).

**Blockers:**
- Whether lodash 4.17.15's _.merge writes '\_\_proto\_\_' or 'constructor.prototype' keys from a JSON.parse'd source through to Object.prototype. The library code is not vendored in the repo

**Owner-run check:** In the repo root after `npm ci`, run: node -e "const _=require('lodash'); console.log(_.VERSION); _.merge({}, JSON.parse('{\"\_\_proto\_\_\":{\"polluted1\":1}}')); _.merge({}, JSON.parse('{\"constructor\":{\"prototype\":{\"polluted2\":1}}}')); console.log(({}).polluted1, ({}).polluted2)". Confirmed: '4.17.15' then a 1 for either value. Then rate impact via the notes.js:13 -> :15 ORDER BY gadget, e.g. pollute a key 'x' and call GET /api/notes?sort=x. Rejected: '4.17.15' then 'undefined undefined', ruled out by lodash's merge key guard at the pinned version.

### Hardening notes (not findings)

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

### Rejected (do not re-raise)

| Fingerprint | Claim | Ruled out by | Location |
|---|---|---|---|
| `owasp-audit/CWE-285/src/routes/admin.js/admin-role-check` | Admin routes trust a role that a non-admin user can influence (privilege escalation to /api/admin/*) | requireAdmin reads the role from the database by the authenticated user id (not the token claim) and returns 403 unless it is 'admin'. Mounted with router.use before every /api/admin route | `src/auth.js:36` |
| `owasp-audit/CWE-347/src/auth.js/requireAuth-algorithms` | jwt.verify is called without an algorithms list on jsonwebtoken 8.5.1, allowing unsigned (alg none) tokens (CVE-2022-23540) | config.jwtSecret always falls back to a non-empty string, so jwt.verify never gets the falsy secret the alg:none bypass needs. Unsigned tokens throw, and requireAuth returns 401 | `src/config.js:5` |
| `owasp-audit/CWE-352/src/app.js/state-changing-routes` | No CSRF protection on state-changing routes (POST/PATCH/DELETE notes, admin DELETE user) | requireAuth takes the credential only from the Authorization Bearer header and fails closed with 401. The app has no cookie or other ambient credential | `src/auth.js:25` |
| `owasp-audit/CWE-639/src/routes/notes.js/DELETE-note` | Any user can delete another user's note via DELETE /api/notes/:id | Parameterized ownership predicate AND owner_id = req.user.id in the DELETE itself. Non-owned ids delete 0 rows and return 404 | `src/routes/notes.js:50` |
| `owasp-audit/CWE-798/.env.example/AWS_ACCESS_KEY_ID` | AWS access key and secret committed in .env.example | The values are AWS's published documentation placeholders, which were never issued and can't authenticate. The file marks them as placeholders, and no code reads them or calls AWS | `.env.example:6` |
| `owasp-audit/CWE-89/src/routes/notes.js/GET-list-sort` | SQL injection through the sort parameter of GET /api/notes (ORDER BY built with a template literal) | SORT_COLUMNS allow-list: user input picks a key, the interpolated value is always a constant map value (or a fixed non-attacker-controlled Object.prototype member that fails to parse), and unknown keys return 400 at line 14 before the query is built | `src/routes/notes.js:13` |
| `owasp-audit/CWE-915/src/routes/users.js/POST-signup` | Signup accepts a role field, letting a new user register as admin (mass assignment) | Signup destructures only email and password, and inserts into a fixed (email, password_hash) column list. role falls back to the schema default 'user' | `src/routes/users.js:8` |

### Items checked and found clean

Generated from every `covered` and `not_applicable` unit in coverage.json. Units that produced a confirmed or needs-validation finding are `candidate` and appear through their findings above, not here. A covered unit can still name a rejected candidate.

| Surface | Boundary | Category | Invariant checked | Result |
|---|---|---|---|---|
| POST /api/users/signup | anonymous -> admin role | A01:2025 | a new account cannot choose its role | holds: only email/password destructured (users.js:8); INSERT (email, password_hash) at users.js:10; role DEFAULT 'user' (db.js:11). Candidate closed as rejected |
| POST /api/users/signup, POST /api/users/login | anonymous -> database | A05:2025 | signup/login SQL is parameterized | holds: users.js:10, :11, :17 all use ? placeholders |
| POST /api/users/signup | anonymous -> weak credentials for other users | A07:2025 | password policy enforced server-side | fails without a separate traced impact: only an 8-char minimum (users.js:9), no complexity or breached-password check, and no type check (an 8-element array passes the length test, then scrypt throws a 500). Weak passwords are the precondition of the CWE-307 finding; no separate record |
| GET /healthz | anonymous -> app | A01:2025 | health check exposes nothing sensitive | holds: returns the literal 'ok' |
| express.json body parser (all routes) | anonymous -> process memory/CPU | A06:2025 | request parsers have explicit limits | holds: express.json limit 100kb (app.js:5); no urlencoded or multipart parser mounted; no uploads |
| error paths in all handlers | any client -> availability / fail-open | A10:2025 | auth checks fail closed on error | holds: verify throw -> 401 (auth.js:30-31); missing/non-admin row -> 403 (auth.js:37) |
| error paths in all handlers | any client -> availability / fail-open | A10:2025 | async rejections cannot crash the process | holds: only preview.js is async and it wraps everything in try/next(err) (preview.js:9-17); all other handlers are sync, which Express 4 catches |
| error paths in all handlers | any client -> availability / fail-open | A10:2025 | multi-step writes are atomic | fails without traced impact: two deletes outside a transaction (admin.js:13-14), admin-only -> hardening note |
| requireAuth middleware | anonymous -> authenticated user | A07:2025 | unsigned or wrongly signed tokens are rejected | holds: secret is always truthy; verify failure -> 401. alg:none candidate closed as rejected; missing algorithms allow-list is a hardening note |
| requireAuth middleware | anonymous -> authenticated user | A07:2025 | requireAuth is mounted on every non-public router | holds: notes.js:7, preview.js:8, admin.js:6; users router and /healthz are intentionally public |
| all state-changing routes | attacker web origin -> victim's session | A01:2025 | no ambient credential a cross-site request could ride | holds: Bearer header only (auth.js:23-25); no cookies anywhere. CSRF candidate closed as rejected |
| password hashing | database read -> plaintext passwords | A04:2025 | passwords stored with a salted slow KDF | holds: scrypt + per-user random salt (auth.js:6-8); Node default cost below OWASP scrypt minimum -> hardening note |
| GET /api/notes | user -> other users' notes | A01:2025 | list is scoped to the caller | holds: WHERE owner_id = ? bound to req.user.id (notes.js:15) |
| GET /api/notes?sort= | user -> database | A05:2025 | sort input cannot reach SQL text | holds while Object.prototype is unpolluted: allow-list map (notes.js:9, :13-14); inherited keys only yield a syntax-error 500. Candidate closed as rejected; the rejection is conditional on the open prototype-pollution needs_validation record (a polluted prototype string would be interpolated at notes.js:15) |
| POST /api/notes | user -> another user's account | A01:2025 | new note's owner comes from the session, not the body | holds: only title/body taken from body; owner_id = req.user.id (notes.js:35) |
| DELETE /api/notes/:id | user -> another user's note | A01:2025 | delete is scoped to the caller | holds: WHERE id = ? AND owner_id = ? (notes.js:50), 0 changes -> 404. Candidate closed as rejected |
| note title/body and preview title in responses | user -> other users' browsers (stored XSS) | A05:2025 | no HTML sink in this repo renders stored content | holds: all responses are res.json (application/json) except the literal 'ok' at app.js:12; no templates or HTML. Rendering in a frontend is out of scope (separate unit) |
| GET /api/admin/users, DELETE /api/admin/users/:id | user -> admin | A01:2025 | admin role is checked server-side from a source the user can't set | holds: role read from DB per request (auth.js:36-37), mounted on the router (admin.js:6); no path writes users.role. Candidate closed as rejected |
| admin and auth events | insider / compromised account -> undetected actions | A09:2025 | auth and admin events are logged and alertable | fails without traced impact: only console.error(err) at app.js:16 -> hardening note |
| admin and auth events | insider / compromised account -> undetected actions | A09:2025 | no secrets or passwords written to logs | holds: console.error(err) logs the error object; no request bodies or tokens logged |
| .env.example and src/ secret sweep | repo reader -> cloud / third-party accounts | A04:2025 | no live credentials in the repo | holds: AWS values are AWS's published doc placeholders and unused (candidate closed as rejected); the only real issue is the JWT fallback (separate unit) |
| HTTP response headers and CORS | other web origins -> API responses | A02:2025 | cross-origin reads of authenticated responses are not allowed | holds: no CORS middleware, so browsers block cross-origin reads; Bearer auth means no ambient credentials |
| HTTP response headers and CORS | other web origins -> API responses | A02:2025 | baseline security headers set | fails without traced impact (JSON-only API, no HTML sink) -> hardening note |
| source tree | reviewer -> stale vulnerable copies | A02:2025 | no sync-conflict duplicates or dead copies of route files | holds: none found |
| remaining db.prepare sinks: notes.js:28, :35, :41, :44-45, :50; admin.js:9, :13, :14; auth.js:36 | user/admin -> database | A05:2025 | every other SQL statement binds its input | holds: all use ? placeholders with .get/.run arguments; the only string-built SQL is notes.js:15 (allow-listed) and notes.js:22 (confirmed CWE-89) |
| POST /api/users/signup, POST /api/preview, POST /api/notes | any (self-registered) user -> server CPU, outbound bandwidth, disk | A06:2025 | costly operations are rate- or quota-limited | fails without traced impact: signup (scrypt per call), preview (outbound fetch up to 5s / 1MB each) and note creation are unlimited. No metered third-party cost is involved, so this is a hardening note; the preview fetch's security impact is the confirmed CWE-918 |
| app.listen plain HTTP (app.js:20) carrying passwords and Bearer tokens | network path -> credentials in transit | A04:2025 | credentials only travel over TLS | not decidable from the repo: the app speaks plain HTTP and TLS, if any, terminates in front of it (deployment). No traced impact in code -> hardening note with an owner check (confirm HTTPS-only + HSTS at the edge) |

### Deferred / out of scope

- **all dependencies (npm audit, install scripts, typosquats)** (out_of_scope, A03:2025): out of scope for this run; hand to dependency-audit. Noted while reading: better-sqlite3 has an install script (package-lock.json:71, prebuild-install); express 4.17.1 / body-parser 1.19.0 / jsonwebtoken 8.5.1 / lodash 4.17.15 are old pins whose other advisories need reachability triage
- **any frontend that renders notes or preview titles** (out_of_scope, A05:2025): No frontend is in the repo. Note titles/bodies and fetched page titles are attacker-controlled; whoever renders them must escape them
- **running instance** (out_of_scope, no category): Static, read-only review by agreement: the app was not run, so no finding is reproduced and confirmed confidence is capped at medium

### Prioritized Remediation Plan

1. **Critical — immediate:** none
2. **High — this week:** `owasp-audit/CWE-321/src/config.js/jwtSecret` (JWT signing secret falls back to the hard-coded string "changeme" when JWT_SECRET is unset or empty); `owasp-audit/CWE-639/src/routes/notes.js/GET-note-by-id` (Any user can read any other user's note by id); `owasp-audit/CWE-89/src/routes/notes.js/GET-search` (SQL injection in note search via the q query parameter); `owasp-audit/CWE-915/src/routes/notes.js/PATCH-note` (PATCH /api/notes/:id merges the request body into the row, so id and owner_id are attacker-controlled and any note can be overwritten or taken over)
3. **Medium/Low — scheduled:** `owasp-audit/CWE-307/src/routes/users.js/POST-login` (No rate limiting or lockout on POST /api/users/login); `owasp-audit/CWE-918/src/routes/preview.js/POST-preview` (Link preview fetches any user-supplied http(s) URL server-side); `owasp-audit/CWE-209/src/app.js/error-handler` (Global error handler returns err.message and err.stack to any client, including anonymous ones); `owasp-audit/CWE-613/src/auth.js/requireAuth-user-id-reuse` (A deleted user's still-valid JWT authenticates as whoever next receives the reused user id)
4. **Owner-run validation checks:** `owasp-audit/CVE-2020-28168/package-lock.json/axios`; `owasp-audit/CVE-2022-24999/package-lock.json/qs`; `owasp-audit/CWE-1321/src/routes/notes.js/PATCH-note-merge`. Upgrading axios and express (and running `dependency-audit`) closes the two A03 items whatever the checks show.
