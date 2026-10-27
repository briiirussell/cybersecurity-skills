# Worked example: an Express IDOR, one rule, every hit closed

The original is a real record from this repo's `owasp-audit` example run against `examples/target`, the deliberately vulnerable notes API. Steps 1–5 ran for real, with semgrep 1.182.1, and the output below is what came back. Step 6, the org-wide run, uses two illustrative repos (`acme/notes-files`, `acme/billing-api`) to show a `confirmed` and a `needs_validation` variant, since the example target has only one of each route.

## 1. The original

From `examples/owasp-audit/findings.json`:

```text
fingerprint: owasp-audit/CWE-639/src/routes/notes.js/GET-note-by-id    verdict: confirmed (high)
entrypoint   src/routes/notes.js:27   GET /api/notes/:id behind requireAuth, which only authenticates
sink         src/routes/notes.js:28   SELECT * FROM notes WHERE id = ? binds only the id
evidence     src/routes/notes.js:41   sibling PATCH /:id adds AND owner_id = ?, and DELETE at line 50 does too
```

| Part | Here |
|---|---|
| Source | `req.params.id` inside an Express route handler |
| Sink | A row lookup or change keyed on that value (`db.prepare(sql).get/run/all`) |
| Missing guard | An owner or tenant predicate tied to the caller (`AND owner_id = ?` bound to `req.user.id`) |

Root cause in one sentence: *the handler trusts the URL id to pick the row and never asks whose row it is.*

The fixed siblings at lines 41 and 50 show what the guard looks like. They become the `ok:` cases.

Where variants could hide: other verbs (PATCH, DELETE), other tables (attachments, comments), other handler styles (`function (req, res)`, `async`), other DB APIs (node-postgres `pool.query`, Prisma `findUnique`).

## 2. Exact match first

```yaml
pattern: db.prepare("SELECT * FROM notes WHERE id = ?").get(req.params.id)
```

One hit: `src/routes/notes.js:28`. The pattern sees the bug the way the finding describes it, so generalizing can start.

## 3. Generalize one element per run

| Change | New hits in `examples/target` | Kept? |
|---|---|---|
| SQL text becomes `"$SQL"`, `.get` becomes `.$EXEC` | notes.js:28, notes.js:41, notes.js:50, admin.js:13, admin.js:14 | Yes, but now needs the guard |
| Add `pattern-not` for SQL naming `owner_id` / `user_id` / `tenant_id` / `org_id` | notes.js:41 and :50 drop (fixed siblings); admin.js:13 drops too (see the gap below) | Yes |
| Add `pattern-inside` for Express route handlers (arrow, async, function) | no change here; drops helpers outside routes | Yes |
| Add node-postgres `pool.query("$SQL", [...])` and Prisma `findUnique({ where: { id } })` branches | none here; covered by fixture cases | Yes |

Two gotchas showed up on the way, both now in [semgrep-rules.md](semgrep-rules.md): Prisma's object pattern matched a `where` that also had `userId: req.user.id` (object patterns match a subset of keys), and a `metavariable-regex` on `$FIND` silently dropped the SQL branch, which never binds `$FIND`.

## 4. Rule and tests

The finished rule and fixture: [rules/express-idor-param-lookup.yml](rules/express-idor-param-lookup.yml) and [rules/express-idor-param-lookup.js](rules/express-idor-param-lookup.js). Copy both into the target repo's `.semgrep/variants/`.

The fixture has four `ruleid` cases (the original's shape, a function handler on another table, node-postgres DELETE, Prisma `findUnique`), five `ok` cases (owner predicate in SQL, tenant predicate in node-postgres, Prisma `where` with `userId`, an id from the session, a helper outside a route), and one `todoruleid`: `WHERE owner_id = ?` bound to `req.params.id`, which names the owner column but binds it to the URL.

```text
$ semgrep --test --metrics=off .semgrep/variants/
1/1: ✓ All tests passed
$ semgrep --validate --metrics=off --config .semgrep/variants/
Configuration is valid - found 0 configuration error(s), and 1 rule(s).
```

## 5. Run on the repo

```text
$ semgrep scan --metrics=off --config .semgrep/variants/ --exclude .semgrep --json --output .security/out/variants.json .
Ran 1 rule on 8 files: 2 findings.
  src/routes/admin.js:14   db.prepare("DELETE FROM users WHERE id = ?").run(req.params.id);
  src/routes/notes.js:28   const note = db.prepare("SELECT * FROM notes WHERE id = ?").get(req.params.id);
```

- **notes.js:28** is the original. The rule still finds the bug it was written for. Not recorded again.
- **admin.js:14** is a candidate. Walk it: `app.js:10` mounts the admin router; `admin.js:6` runs `router.use(requireAuth, requireAdmin)` before every handler; `requireAdmin` (`auth.js:35-38`) re-reads the role from the database and returns 403 unless it's `admin`. Deleting a user by id is what an admin route is for. **Rejected**, ruled out by `admin.js:6`.
- **Not a hit, but the gap:** `admin.js:13`, `DELETE FROM notes WHERE owner_id = ?` bound to `req.params.id`, is the `todoruleid` shape. A grep for `owner_id = ?` lines with `req.params` finds it. The same control at `admin.js:6` rules it out, so no record; list it under "Known gaps in the rule".

Should `requireAdmin` routers become an `ok:` case? Not yet. One rejected hit isn't a pattern; if admin routers keep showing up across repos, add `pattern-not-inside` for a router that `use`s `requireAdmin`, with a test.

## 6. Run across the org (illustrative)

With `patch-sweep`'s inventory (repos plus production branches), the same command runs in each clone. Two more hits come back:

| Repo | Hit | Walk | Verdict |
|---|---|---|---|
| acme/notes-files | `src/routes/attachments.js:22` `SELECT path, note_id FROM attachments WHERE id = ?` with `req.params.attachmentId`, then `res.sendFile(row.path)` | Only `requireAuth` on the router; no join to `notes.owner_id`; the sibling DELETE does join and check | `confirmed`, high, static (confidence medium) |
| acme/billing-api | `src/routes/invoices.ts:17` `prisma.invoice.findUnique({ where: { id: Number(req.params.id) } })` | Router mounted at `/internal/invoices` with no auth; a comment says the gateway keeps `/internal` private; gateway config isn't in the repo | `needs_validation`: is `/internal` reachable from the internet? |

## 7. Records, one per verdict

Each repo gets its own `findings.json`; the three records are shown together here. All three pass `validate-findings.mjs`.

**Rejected** (examples/target):

```json
{
  "fingerprint": "variant-analysis/CWE-639/src/routes/admin.js/DELETE-admin-users-id",
  "verdict": "rejected",
  "skill": "variant-analysis",
  "title": "Admin user-removal route deletes a user by URL id with no owner predicate",
  "cwe": "CWE-639",
  "owasp_category": "A01:2025",
  "ext": {
    "variant_of": "owasp-audit/CWE-639/src/routes/notes.js/GET-note-by-id",
    "rule_id": "express-idor-param-lookup",
    "rule_engine": "semgrep",
    "rule_path": ".semgrep/variants/express-idor-param-lookup.yml"
  },
  "location": { "file": "src/routes/admin.js", "line": 14 },
  "trace": [],
  "evidence": [{ "file": "src/routes/admin.js", "line": 14, "description": "Rule hit: DELETE FROM users WHERE id = ? bound to req.params.id" }],
  "counterevidence": "Walked app.js:10 -> admin.js:6 -> admin.js:12-15. Acting on any user's id is the route's purpose; the control that matters is who may call it. router.use(requireAuth, requireAdmin) runs before every handler on this router, and requireAdmin (auth.js:35-38) re-reads the role from the users table and returns 403 unless it is 'admin'. No other mount reaches this handler.",
  "confidence": "high",
  "ruled_out_by": {
    "control": "Router-level requireAdmin: role re-read from the database, 403 for non-admins, before every handler on the admin router",
    "location": { "file": "src/routes/admin.js", "line": 6 }
  }
}
```

**Confirmed** (acme/notes-files):

```json
{
  "fingerprint": "variant-analysis/CWE-639/src/routes/attachments.js/GET-attachments-id",
  "verdict": "confirmed",
  "skill": "variant-analysis",
  "title": "Any signed-in user can download another user's attachment by id (IDOR variant)",
  "cwe": "CWE-639",
  "owasp_category": "A01:2025",
  "ext": {
    "variant_of": "owasp-audit/CWE-639/src/routes/notes.js/GET-note-by-id",
    "rule_id": "express-idor-param-lookup",
    "rule_engine": "semgrep",
    "rule_path": ".semgrep/variants/express-idor-param-lookup.yml",
    "repo": "acme/notes-files"
  },
  "location": { "file": "src/routes/attachments.js", "line": 22 },
  "trace": [
    { "kind": "entrypoint", "file": "src/routes/attachments.js", "line": 20, "description": "GET /api/attachments/:attachmentId behind requireAuth (attachments.js:8), which only authenticates" },
    { "kind": "propagation", "file": "src/routes/attachments.js", "line": 22, "description": "SELECT path, note_id FROM attachments WHERE id = ? binds only req.params.attachmentId" },
    { "kind": "sink", "file": "src/routes/attachments.js", "line": 24, "description": "res.sendFile(row.path) streams the file to the caller" }
  ],
  "evidence": [
    { "file": "src/routes/attachments.js", "line": 22, "description": "No owner_id, no join to notes.owner_id, req.user.id unused in the handler" },
    { "file": "src/db.js", "line": 31, "description": "attachments.id is INTEGER PRIMARY KEY: sequential ids" }
  ],
  "counterevidence": "Looked for a guard the rule can't see: no router-level middleware besides requireAuth, no ownership helper called in the handler, no join through notes. The sibling delete handler for attachments (line 30) joins notes and checks owner_id, so ownership was intended. Static trace only; not reproduced.",
  "confidence": "medium",
  "severity": {
    "likelihood": { "score": "high", "reason": "Open signup and sequential ids; any account can walk the id space" },
    "impact": { "score": "high", "reason": "Reads other users' uploaded files, which fully defeats the per-user access control" },
    "overall": "high"
  },
  "conditions": [{ "kind": "authentication_level", "description": "Any signed-in account" }]
}
```

**Needs validation** (acme/billing-api):

```json
{
  "fingerprint": "variant-analysis/CWE-639/src/routes/invoices.ts/GET-invoices-id",
  "verdict": "needs_validation",
  "skill": "variant-analysis",
  "title": "Invoice lookup keyed only by the URL id on an internal router",
  "cwe": "CWE-639",
  "owasp_category": "A01:2025",
  "ext": {
    "variant_of": "owasp-audit/CWE-639/src/routes/notes.js/GET-note-by-id",
    "rule_id": "express-idor-param-lookup",
    "rule_engine": "semgrep",
    "rule_path": ".semgrep/variants/express-idor-param-lookup.yml",
    "repo": "acme/billing-api"
  },
  "location": { "file": "src/routes/invoices.ts", "line": 17 },
  "trace": [
    { "kind": "entrypoint", "file": "src/app.ts", "line": 12, "description": "invoices router mounted at /internal/invoices with no auth middleware in the app" },
    { "kind": "sink", "file": "src/routes/invoices.ts", "line": 17, "description": "prisma.invoice.findUnique({ where: { id: Number(req.params.id) } }) returns the full invoice" }
  ],
  "evidence": [],
  "counterevidence": "The code has no owner predicate and no auth on the /internal mount. A comment in app.ts says the gateway only routes /internal from the VPC; comments are claims, and the gateway config is not in this repo.",
  "confidence": "medium",
  "blockers": ["Does the production API gateway route /internal/* only from the private network, or is it reachable from the internet?"],
  "validation_plan": "From a machine outside the VPC, send one GET for /internal/invoices/1 to the production API host and note which component answers. A 2xx or a 4xx from the app (JSON error body) means it is reachable: confirmed. A gateway 403/404 with no app response means rejected, ruled out by the gateway route; record the gateway rule's file and line."
}
```

Note what the needs-validation record does **not** say: "internal, so fine". An internal-only route is a `network_routing` condition once confirmed, not a rejection.

## 8. Rule report line

| Rule id | Engine | Tests (ok / ruleid / todo) | Hits | Confirmed / NV / Rejected |
|---|---|---|---|---|
| express-idor-param-lookup | semgrep | 5 / 4 / 1 | 4 (1 original + 3 variants) | 1 / 1 / 1 |

One in three hits rejected, and the rejection came from a control the rule couldn't reasonably see. Good enough for CI at `WARNING`. The rule stays in `.semgrep/variants/`, `scanner-pipeline`'s PR scan picks it up, and the fix for `attachments.js` is verified by the hit disappearing on the fix branch while the `ok:` cases still pass.
