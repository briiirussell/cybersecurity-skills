# Dependency & Stack Security Audit
## Project: notes-api (examples/target)
## Stack: Node.js (runtime version not pinned), Express 4.17.1, better-sqlite3 9.4.3, jsonwebtoken 8.5.1, axios 0.21.0, lodash 4.17.15
## Date: 2026-10-26
## Scope: full — branch/commit audited: `feature/v1.23.8-examples` @ `3de0401`, working tree (`examples/target/` is not yet committed) (deployed branch confirmed: n/a, the target is never deployed per its README)
## Package manager + audit command: npm 11.6.2, lockfileVersion 3, `npm audit --json` run from `examples/target/` on 2026-10-26 (raw output: [`npm-audit.json`](npm-audit.json)). `--omit=dev` was not run separately: the lockfile has 0 dev dependencies, so its output would match.
## findings.json: [`findings.json`](findings.json) — validated: yes (`node shared/validate-findings.mjs`: 27 records, 3 confirmed, 3 needs_validation, 21 rejected)

`npm audit` reported 10 vulnerable packages (7 high, 3 low) carrying 49 distinct advisories. Each advisory was read on GitHub and checked against the app's call sites, then grouped by root cause into 26 records. One more confirmed record came from the Express checks in Step 3. Two of the 49 advisories are reachable by an unauthenticated client. Seven, in three records, need a fact from the production environment. The other 40 are in code this app never calls.

### Stack Inventory
| Component | Version | Latest | Status |
|-----------|---------|--------|--------|
| Node.js | not pinned (no `engines`, `.nvmrc`, Dockerfile) | — | Unknown; see hardening notes |
| express | 4.17.1 | 5.3.0 (4.x: 4.22.3) | 2 own advisories, both rejected; its bundled body-parser and qs carry the 2 confirmed findings |
| body-parser (via express) | 1.19.0 | 2.4.0 (1.x: 1.20.9) | 1 confirmed, 2 rejected |
| qs (via express, body-parser) | 6.7.0 | 6.16.1 | 1 confirmed, 3 rejected |
| path-to-regexp (via express) | 0.1.7 | 9.0.0 (express line: 0.1.13) | 3 advisories, rejected |
| cookie, send, serve-static (via express) | 0.4.0, 0.17.1, 1.14.1 | 2.0.1, 1.2.1 (0.x: 0.19.2), 2.2.1 (1.x: 1.16.3) | 3 advisories, rejected |
| axios | 0.21.0 | 1.20.0 (0.x: 0.34.0) | 25 advisories: 7 needs_validation (proxy env), 18 rejected |
| follow-redirects (via axios) | 1.16.2 | — | Not flagged by npm audit |
| jsonwebtoken | 8.5.1 | 9.0.3 | 3 advisories, rejected |
| lodash | 4.17.15 | 4.18.1 | 6 advisories, rejected; the one call site is a mass-assignment bug (confirmed, below) |
| better-sqlite3 | 9.4.3 | 13.0.3 | No advisories; has an install script (native addon) |
| Agent extensions (MCP, skills, plugins) | none in `examples/target/` | — | Nothing to inventory |

### Known Vulnerabilities (CVEs)
| Package | Installed | Vuln | Severity | Where reachable | CVE | Fix Version | Disposition |
|---------|-----------|------|----------|-----------------|-----|-------------|-------------|
| body-parser | 1.19.0 | A compressed body with trailing bytes throws an uncaught exception that kills the process. `express.json()` is mounted app-wide (`src/app.js:5`), so this needs no auth and no matching route. ([GHSA-27r3-jxmh-p828](https://github.com/advisories/GHSA-27r3-jxmh-p828)) | High | runtime | CVE-2026-111181 | 1.20.9. express 4.22.3 declares `~1.20.5`, so after upgrading express check that the lockfile resolves body-parser ≥ 1.20.9 (`npm ls body-parser`). Stopgap: `express.json({ limit: "100kb", inflate: false })` | not set (finding-triage) |
| qs | 6.7.0 | An `__proto__` key in the query string hangs the process. Express parses every request's query with `qs.parse(str, { allowPrototypes: true })`, unauthenticated `/healthz` included (`src/app.js:12`). ([GHSA-hrpp-h998-j3pp](https://github.com/advisories/GHSA-hrpp-h998-j3pp)) | High | runtime | CVE-2022-24999 | 6.7.3 (backport). Upgrading express to 4.22.3 brings qs `~6.16.0` | not set (finding-triage) |

Both are traced statically from the advisory text plus express 4.17.1 / body-parser 1.19.0 source. Neither was run, so confidence is `medium`.

### Framework-Specific Issues
#### [HIGH] `_.merge(note, req.body)` lets any user overwrite and take ownership of another user's note
**Component:** Express 4.17.1 route + lodash 4.17.15 `_.merge` (`src/routes/notes.js:40-46`)
**Issue:** This came up while checking the "prototype pollution through `lodash.merge`" pattern. Prototype pollution is ruled out: lodash 4.17.15's merge skips `__proto__` and `constructor` (`safeGet`). The merge is still unrestricted mass assignment. The ownership check runs on `req.params.id`. `_.merge` then mutates that same row object with every body key, including `id` and `owner_id`. The `UPDATE ... WHERE id = ?` uses the post-merge `note.id`. A self-registered user who owns one note can send `PATCH /api/notes/<own id>` with `{"id": <victim note id>, "owner_id": <own id>, "title": "...", "body": "..."}`. That overwrites the victim's note and moves it into the attacker's account. Note ids are sequential. Static trace only (confidence `medium`).
**Evidence:**

```js
// src/routes/notes.js
41  const note = db.prepare("SELECT * FROM notes WHERE id = ? AND owner_id = ?").get(req.params.id, req.user.id);
43  const updated = _.merge(note, req.body);
44  db.prepare("UPDATE notes SET owner_id = ?, title = ?, body = ?, shared = ? WHERE id = ?")
45    .run(updated.owner_id, updated.title, updated.body, updated.shared, note.id);
```

**Remediation:** Drop the merge and copy an allow-list of editable fields: `const { title = note.title, body = note.body, shared = note.shared } = req.body`. Keep `WHERE id = ? AND owner_id = ?` using `req.params.id` and `req.user.id`, never values from the body.

### Supply Chain Risks
| Risk | Package/Component | Details | Remediation |
|------|-------------------|---------|-------------|
| Install script | better-sqlite3 9.4.3 | `hasInstallScript: true` (native addon build). Resolved from registry.npmjs.org with a sha512 integrity hash. That is expected for this package; the script's content was not reviewed. | None needed beyond keeping it lockfile-pinned |

No other supply chain risks found. All 105 lockfile entries resolve from `https://registry.npmjs.org` and carry `integrity` hashes. There is no `.npmrc` or other registry override, and no `overrides` or `resolutions`. None of the 5 direct dependencies is a typosquat. There is no agent-extension config.

### Dev Tool / CI Security
| Tool | Issue | Severity | Remediation |
|------|-------|----------|-------------|
| — | No CI workflows, Dockerfile or IaC in `examples/target/`. Step 5 and the Step 5b handoffs had nothing to check. | — | — |

### Needs Validation
| Candidate | Blockers | Validation plan |
|-----------|----------|-----------------|
| axios 0.21.0: a redirect bypasses a configured egress proxy ([GHSA-4w2v-q235-vp99](https://github.com/advisories/GHSA-4w2v-q235-vp99)) via `POST /api/preview` | Is `HTTP(S)_PROXY` set in production? (axios 0.21.0 reads it from the env; neither `src/` nor `.env.example` sets it.) If so, is the proxy relied on to block internal and metadata addresses? | Run `printenv \| grep -i _proxy` in the production runtime. If no proxy is set, reject. If one is, POST a URL that 302s to `http://169.254.169.254/latest/meta-data/` from staging and check whether the proxy sees the second hop. |
| axios 0.21.0: NO_PROXY matching is a literal string compare (GHSA-3p68-rc4w-qgx5, GHSA-m7pr-hjqh-92cm, GHSA-pmwg-cvhr-8vh7, GHSA-pjwm-pj3p-43mv) | Are both a proxy env var and `NO_PROXY` set, and does egress policy depend on `NO_PROXY`? | If either is unset, reject. Otherwise POST `http://localhost.:<port>/` and `http://[::ffff:7f00:1]/` from staging and check the proxy logs. |
| axios 0.21.0: proxy credentials leak to a redirect target (GHSA-p92q-9vqr-4j8v, GHSA-j5f8-grm9-p9fc). The caller picks the origin, so they control the redirect. | Does the production proxy URL carry credentials (`http://user:pass@…`)? | Look for `@` in the `*_proxy` values. If present, POST an `http://` URL you control that redirects to an `https://` URL you control, and check for a `Proxy-Authorization` header. |

### Rejected (do not re-raise)
Each record below names the control that rules it out. Re-open one only if the code at its `ruled_out_by.location` changes.

| Advisories | Package | Ruled out by |
|------------|---------|--------------|
| GHSA-43fc-jf86-j433 | axios | Config passed to axios is a hard-coded literal (`src/routes/preview.js:12`) |
| GHSA-5c9x-8gcm-mpgx, GHSA-62hf-57xw-28j9, GHSA-xhjh-pmcv-23jw | axios | Only a bodyless GET with no params, so the upload, FormData and URLSearchParams serializers never run |
| GHSA-cph5-m8f7-6c5x | axios | `utils.trim` is reached only via `parseHeaders`, which only the XHR adapter calls. Node uses the http adapter. (The advisory names no function; this rests on 0.21.0 source.) |
| GHSA-jr5f-v2jv-69x6 | axios | No `baseURL` or instance headers to bypass or leak |
| GHSA-pf86-5x62-jrwf, GHSA-w9j2-pvgh-6h63, GHSA-6chq-wfr3-2hj9, GHSA-3g43-6gmg-66jw, GHSA-898c-q2cr-xwhg, GHSA-fvcv-3m26-pcqx, GHSA-mmx7-hfxf-jppx, GHSA-7q8q-rj6j-mhjq, GHSA-xx6v-rp6x-q39c | axios | All need a separate `Object.prototype` pollution primitive. None was found on request paths (JSON.parse, qs, lodash 4.17.15 merge guards). Confidence medium: the transitive tree was not exhaustively checked for primitives. |
| GHSA-vf2m-468p-8v99 | axios | Default buffered `responseType` enforces `maxContentLength: 1_000_000` |
| GHSA-wf5p-g6vw-rhxx, GHSA-hfxv-24rg-xrqf | axios | XSRF cookie code runs only in browsers; axios runs server-side only |
| GHSA-qwcr-r2fm-qrc7 | body-parser | urlencoded parser never mounted (`src/app.js:5`) |
| GHSA-v422-hmwv-36x6 | body-parser | Hard-coded valid `limit: "100kb"` |
| GHSA-pxg6-pf52-xh8x | cookie | The app never sets cookies; auth is a Bearer header (`src/auth.js:23`) |
| GHSA-qw6h-vgh9-j6wx, GHSA-m6fv-jmcg-4jfg, GHSA-cm22-4g7w-348p | express, send, serve-static | No `res.redirect`, static or `sendFile` responses |
| GHSA-rv95-896h-c2vc | express | No `res.location` / `res.redirect` |
| GHSA-9wv6-86v2-598j, GHSA-rhx6-c78j-4q9w, GHSA-37ch-88jc-xwx2 | path-to-regexp | Every route has at most one parameter per segment |
| GHSA-4mjr-xmp4-gh2g | qs | Parsed queries are never passed to `qs.stringify` |
| GHSA-6rw7-vpxm-498p, GHSA-w7fw-mjwx-w883 | qs | Express keeps qs defaults: `parameterLimit` 1000, `comma` off |
| GHSA-8cf7-32gw-wr33, GHSA-hjrf-2m68-5959 | jsonwebtoken | One HMAC string secret, no asymmetric keys, no key callback |
| GHSA-qwph-4952-7xr6 | jsonwebtoken | The secret is never falsy, so 8.5.1 rejects unsigned tokens. The thing that makes it truthy is the hard-coded fallback in `src/config.js:5`, which is its own problem; handed to secrets-audit. |
| GHSA-29mw-wpgm-hmr9 | lodash | `toNumber` / `trim` / `trimEnd` never called |
| GHSA-35jh-r3h4-6jhm, GHSA-r5fr-rjxr-66jc | lodash | `_.template` never called |
| GHSA-p6mc-m468-83gw | lodash | Listed functions never called; the `_.merge` that is called guards `__proto__` / `constructor` in 4.17.15 |
| GHSA-xxjr-mmjv-4gpg, GHSA-f23m-r3pf-42rh | lodash | `_.unset` / `_.omit` never called |

### Hardening Notes (not findings)
- **Node runtime is not pinned.** Add `engines.node` and `.nvmrc` so the runtime is a reviewed choice and the "engines floor" check in fixing-safely.md has something to compare against. Effort: S.
- **Upgrade the unreachable advisories anyway:** axios to ≥ 0.33.0 on 0.x (or ≥ 1.18.0 on 1.x), jsonwebtoken to 9.0.3 (major; it drops the default `none` support), lodash to 4.18.1. Nothing above is reachable today, but each new call site (a `baseURL` instance, `_.template`, `res.redirect`) would make one of the 40 rejected advisories live, and clean re-audits keep the real ones visible. Effort: S, plus M for the jsonwebtoken major.
- **`npm audit`'s fix suggestion for axios understates the fix.** npm reports `fixAvailable: axios@0.21.4`, but several advisories in its own output are fixed only in 0.31.x–0.33.0. Use the advisory ranges, not `audit fix`, to choose the target.
- **Pass `algorithms: ["HS256"]` to `jwt.verify`** (`src/auth.js:27`). It closes the algorithm-default class of bugs at the call site, whatever the library version. Effort: S.

### Prioritized Action Plan
1. Critical: none.
2. High:
   - Upgrade express to 4.22.3 and confirm the lockfile resolves body-parser ≥ 1.20.9 and qs ≥ 6.16.0. This closes both unauthenticated process-kill findings. Until it ships, set `inflate: false` on `express.json` and reject query keys containing `__proto__` at the edge.
   - Replace `_.merge(note, req.body)` in `PATCH /api/notes/:id` with an allow-list of editable fields.
3. Medium: answer the three proxy questions in Needs Validation, then reject those records or promote them.
4. Low: the hardening notes above (runtime pin, axios/jsonwebtoken/lodash upgrades, explicit JWT algorithms).

Seen while tracing reachability but outside this skill, so not recorded here. Hand these to the named skills: SQL built from `req.query.q` in `GET /api/notes/search` (`src/routes/notes.js:22`), no owner check on `GET /api/notes/:id` (`src/routes/notes.js:28`), and no host allow-list on `POST /api/preview` (`src/routes/preview.js:11-12`) go to owasp-audit / api-audit. Stack traces in error responses (`src/app.js:17`) go to owasp-audit. The hard-coded JWT fallback (`src/config.js:5`) and the AWS-style keys in `.env.example` go to secrets-audit.
