# Finding Triage Session
## Source: `examples/finding-triage/input.md`: one semgrep alert, one OWASP ZAP baseline alert (staging), both against `examples/target/`
## Date: 2026-10-26
## Triaged by: finding-triage (agent run). Owner and reviewer names below are placeholders.

Scope and method: the maintainer owns the code. This was a static review only. The app wasn't run and no requests were sent to staging. Paths are relative to `examples/target/`. Each alert got its own refutation pass from a separate verifier that saw only the claim and the code (`references/verification.md`), and both verifiers reached the same verdict as the triage. The two alerts in `input.md` were written for this example and aren't captured scanner output. So the ZAP "evidence" line counts as the claim, not as a reproduction, and the confirmed record isn't marked `reproduced`.

### Summary
| Finding | Fingerprint | Verdict | Original severity | Contextual severity | SLA | Disposition |
|---------|-------------|---------|-------------------|---------------------|-----|-------------|
| Error handler returns `err.message` + `err.stack` to clients | `finding-triage/CWE-209/src/app.js/errorHandler` | confirmed (medium confidence) | ZAP Risk: Medium | **Low** | 2027-01-24 (90 days, default Low SLA) | Fix now (planned, not yet deployed) |
| semgrep tainted-sql-string on `ORDER BY ${order}` | `finding-triage/CWE-89/src/routes/notes.js/listNotes` | rejected | semgrep ERROR / CWE-89 | none (no finding) | none | False positive |

`findings.json` holds both records and passes `node shared/validate-findings.mjs` (2 records: 1 confirmed, 0 needs_validation, 1 rejected).

### Detail

## Finding: Global error handler discloses error messages and stack traces to any client
**Source:** OWASP ZAP baseline, staging (rule 90022, Application Error Disclosure)  **Fingerprint:** `finding-triage/CWE-209/src/app.js/errorHandler`
**Severity:** Low (Scanner reported: Medium)  **SLA:** 2027-01-24
**Likelihood / Impact:** High: any anonymous client can trigger it on any route with a malformed JSON body / Low: it discloses paths, module layout, SQLite schema fragments and internal-network reachability, but no credentials, tokens or user data
**CWE / CVE:** CWE-209 (Generation of Error Message Containing Sensitive Information). OWASP A10:2025
**Location:** `src/app.js:17`

### What
The only error middleware (`src/app.js:15-18`) sends every unhandled error back to the client as `{ error: err.message, stack: err.stack }` with status 500. The comment at `src/app.js:14` says this is deliberate ("so the frontend can show them"). There's no `NODE_ENV` branch, so the deployed build does exactly what the code says. ZAP happened to hit it through `/api/preview`, but the root cause is the global handler, not that route.

### Boundary + result
- **Lower-trust principal:** an anonymous internet client. For the internal-network detail, any signed-up user (signup is open at `src/routes/users.js:7`).
- **Accepted input:**
  - a malformed JSON body to any route (`express.json()` at `src/app.js:5` runs before every router);
  - a duplicate-email signup (`src/routes/users.js:10`);
  - a login with a known email and no password (`src/auth.js:13`);
  - the `url` body field of `POST /api/preview` (`src/routes/preview.js:10-12`).
- **Intended control:** server-side error details stay on the server: logged (`src/app.js:16`), not returned. Nothing enforces this. The handler does the opposite.
- **Boundary crossed:** client → server internals (filesystem layout, dependency layout, DB schema, and the server's view of its internal network).
- **Affected resource:** the server and the network it sits on.
- **Concrete result (traced, not run):** the response body carries the error text and the stack. Here's what each trigger discloses:
  - **body-parser `SyntaxError`:** absolute install paths and the `node_modules` layout;
  - **`SqliteError: UNIQUE constraint failed: users.email`:** table and column names;
  - **axios via `/api/preview`:** Node's network error text: `getaddrinfo ENOTFOUND <host>`, `connect ECONNREFUSED <ip>:<port>`, `timeout of 5000ms exceeded`, `Request failed with status code <n>`. This tells a user whether an internal hostname resolves, the IP it resolves to, and whether a port is open, closed or filtered.

  The handler doesn't serialize the axios request config or headers, so no secrets go out this way.

### Why this severity
ZAP's Medium is its rule default. In this app:
- **Likelihood rises above "authenticated preview only":** the same handler is reachable pre-auth on every route.
- **Impact is Low and stays Low:** `severity-calibration.md` lists verbose errors without a specific exploitable consequence as over-rated, and puts "information disclosure of internal hostnames" at Low. The concrete consequences here are recon detail. The error text also makes two separate bugs easier to use: it turns the preview fetcher into an internal port and host scanner, and it gives error-based feedback for the `/search` injection. Both of those bugs are open candidates of their own (see "Related candidates" below). Rating this alert up for them would be "could matter if chained", so they're rated where they live, not here.
- **Overall: Low** (≤ impact). The High/Critical checklist doesn't apply.
- **Confidence: medium.** It's a static trace, and one deployment fact is unseen: whether a reverse proxy or platform layer in front of staging or production replaces 500 bodies. That's recorded as a `network_routing` condition. If a proxy turns out to strip the bodies, the code is still vulnerable and the disposition becomes Mitigated (platform/config) until the code fix ships. It doesn't become a false positive.

### Fix
Log the full error server-side and return a generic body. Keep 4xx statuses that middleware already set, such as body-parser's 400:

```js
// src/app.js
const crypto = require("crypto");

app.use((err, req, res, next) => {
  const id = crypto.randomUUID();
  console.error(id, err);
  const status = err.status >= 400 && err.status < 500 ? err.status : 500;
  res.status(status).json({ error: status === 500 ? "internal error" : "bad request", id });
});
```

In `src/routes/preview.js`, map fetch failures to a single client-facing message (`502 { error: "could not fetch that URL" }`) instead of `next(err)`. Otherwise the axios error text is just one refactor away from coming back.

This fix does **not** address the SSRF in `/api/preview` or the SQL injection in `/search`. Both still need their own triage.

### Verification
Run against a local instance or staging. These are non-destructive requests to the maintainer's own service.
- Run `curl -s -X POST localhost:3000/api/users/login -H 'content-type: application/json' -d '{bad'`
  - Observe: status 400, and the body has no `stack` key and no path containing `node_modules`.
- Run `curl -s -X POST localhost:3000/api/preview -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' -d '{"url":"http://nope.invalid/"}'`
  - Observe: status 502 or 500 with a generic message. The body doesn't contain `getaddrinfo`, `ENOTFOUND` or `stack`.
- Run a duplicate-email signup twice.
  - Observe: the second response doesn't contain `UNIQUE constraint` or `users.email`.
- Add a regression test that throws inside a test route and asserts the response body has only `error` and `id`.
- Re-run ZAP baseline against staging. Observe: 90022 no longer fires on `/api/preview`.

### Owner: notes-api maintainer (placeholder)
### Target deploy: 2026-11-09 (placeholder; within the 2027-01-24 SLA)

`findings.json` records this finding as `confirmed` / Low with no `disposition` yet. Set `"disposition": "Fixed"` after the verification above passes on the deployed build, not before.

---

## Finding: semgrep tainted-sql-string on `ORDER BY` in GET /api/notes — FALSE POSITIVE
**Scanner:** semgrep `javascript.express.security.injection.tainted-sql-string`
**Original severity:** ERROR (confidence MEDIUM), CWE-89

### What the scanner claimed
User input reaches the SQL template literal at `src/routes/notes.js:15` (`ORDER BY ${order}`), so an authenticated caller could inject SQL into the notes list query and read or change the database.

### Why it's not real
`order` is never the request value. At `src/routes/notes.js:13` the value of `req.query.sort` is used only as a **key** into `SORT_COLUMNS`, a constant map of three fixed clauses (`src/routes/notes.js:9`). If the key isn't there, line 14 returns 400 before the query is built. `owner_id` is bound as a `?` parameter. So the template only ever receives text the developer wrote.

Values tried against the trace (static, not run):

| `sort` input | What reaches line 15 | Result |
|---|---|---|
| `x' OR 1=1--`, any string not in the map | nothing | 400 at line 14 |
| `sort[]=a&sort[]=b` (qs 6.7.0 array) | key `"a,b"`, not in the map | 400 |
| `sort[]=title` (one-element array) | key `"title"` | allowed clause `title ASC` |
| `sort[k]=v` (qs object) | key `"[object Object]"`, not in the map | 400 |
| `constructor`, `toString`, `valueOf` (inherited keys) | fixed text `function ...() { [native code] }` | SQLite syntax error, 500 |
| `__proto__` | `Object.prototype` → `[object Object]` | SQLite reads it as a bracket-quoted column: "no such column", 500 |

The inherited keys do pass the check, which is a weakness of using `obj[key]` as an allow-list. But the text they produce is fixed, so an attacker can't shape the SQL and no data comes back. The 500s they cause go through the error handler above, so they're covered by that finding, not this one.

The one way an attacker could get their own text into this lookup is prototype pollution elsewhere in the process, for example via `_.merge(note, req.body)` at `src/routes/notes.js:43` on lodash 4.17.15. Neither the triage nor the verifier found a known `merge` pollution path in 4.17.15; the advisory against that version is in `zipObjectDeep`. That chain wasn't proven, and it would be a separate candidate with its own fingerprint, so it doesn't keep this one open.

**Ruled out by:** the `SORT_COLUMNS` allow-list lookup at `src/routes/notes.js:13` (map defined at `:9`; unknown keys get 400 at `:14`). It's the only path to the sink and it runs before the query is built.

### Suppression decision
- [x] Suppress this exact finding (location + rule ID): `nosemgrep: javascript.express.security.injection.tainted-sql-string` on `src/routes/notes.js:15` only, with a comment pointing to the `SORT_COLUMNS` allow-list.
- [ ] Add allow-list rule. **Not recommended:** a file- or rule-wide suppression would also hide `src/routes/notes.js:22` (see below).
- [ ] No suppression — re-evaluate if it returns

Re-open if `SORT_COLUMNS` stops being a constant, if line 13 starts interpolating `req.query.sort` itself, or if prototype pollution is found anywhere in the process.

### Determination by: finding-triage (agent run), 2026-10-26
### Reviewed by: notes-api maintainer (placeholder), by 2026-11-02

---

### Needs validation (no severity yet)
| Finding | Blocker | Validation plan | Owner |
|---------|---------|-----------------|-------|
| none | | | |

Neither alert ended as `needs_validation`. The error-disclosure finding has one deployment unknown: does a proxy rewrite 500 bodies in production? It's recorded as a condition with medium confidence rather than as a blocker. The code returns the stack on every path with no environment switch, so the finding stands either way. A proxy would change the disposition, not the verdict. Check it by sending the malformed-JSON request from the Verification section to production and seeing whether the 500 body still contains `stack`.

### Hardening notes (not findings)
- **Gap:** `SORT_COLUMNS[req.query.sort]` (`src/routes/notes.js:13`) also matches inherited `Object.prototype` keys. **Why no finding:** they only produce fixed text that fails as SQL (see the False Positive above). **Would help because:** checking with `Object.hasOwn(SORT_COLUMNS, sort)` or using a `Map` makes the allow-list exact and closes off any future prototype-pollution chain. **Effort:** S

### Related candidates seen during triage (not triaged here, not covered by either record)
Triage handles one finding at a time. These came up while reading the code for the two alerts. Each needs its own candidate record and its own pass; neither verdict above settles them.
- **`src/routes/notes.js:22`:** `GET /api/notes/search` puts `req.query.q` straight into the SQL string. This looks like a real SQL injection (CWE-89), and semgrep didn't flag it in this input. Don't let the false positive above suppress it.
- **`src/routes/preview.js:11-12`:** `POST /api/preview` fetches any `http(s)` URL with no host allow-list (possible SSRF, CWE-918). Whether it reaches cloud metadata or internal services depends on egress controls that aren't in the repo, so expect `needs_validation`.
- **`src/routes/notes.js:43` + lodash 4.17.15:** `_.merge(note, req.body)` takes the whole request body. That's a mass-assignment question (`owner_id`, `shared`) and a dependency-advisory question for `dependency-audit`.

### Escalations
- **Error-disclosure finding:** it triggers pre-auth, which is on the skill's "don't triage alone" list. The severity is Low, so this is a light second review, not a security-team approval: the reviewer should confirm Low and the planned fix. Reviewer: notes-api maintainer (placeholder), by 2026-11-02.
- **False positive:** none needed beyond the reviewer named above. The suppression is narrow, and the sibling `/search` sink is called out so it can't be hidden.
