# Recon, Coverage Ledger, and Coverage Critic

Shared reference for `owasp-audit` and `api-audit`. It covers three things:

1. A **read-only recon pass** that runs before any hunting and writes `architecture.md`
2. A **coverage ledger** (`coverage.json`) that tracks what was actually reviewed, one unit per entry surface × trust
   boundary × attack class
3. A **coverage critic** that looks for gaps before the report is written

Without these, a report line like "A01: clean" is a claim about a whole category, and it can hide routes nobody opened.
With them, "clean" means: these paths were read, these checks were run, and here are the results.

Audit output lives in one directory so re-runs can find it. Default: `security-audit/` at the repo root (ask whether
the user wants it committed or gitignored):

```text
security-audit/
  architecture.md     # recon output, ≤ ~1,000 words
  coverage.json       # the ledger
  findings.json       # verdict records (see findings-format.md)
  hardening-notes.md  # gaps with no traced impact (not findings)
  report.md           # rendered from the JSON, never edited by hand
```

## Phase 1 — Recon (read-only, before hunting)

Don't grep for vulnerabilities yet. Build the map first. Recon answers:

| Question | What to record |
|---|---|
| What is this? | Product in one sentence, languages, frameworks, runtime(s) (Node / Edge / Workers / serverless), datastore(s) |
| How does it build and run? | Install, build, test, and local-run commands. Which of those you actually ran |
| Who are the principals? | Every lower-trust principal: anonymous visitor, signed-in user, member of another tenant, org admin, webhook sender, cron/job runner, internal service, LLM/agent tool caller |
| Where are the controls? | For each principal, the `file:line` where its authentication and authorization are enforced (middleware, guard, policy, RLS policy, resolver directive) |
| What are the entry surfaces? | HTTP routes, server actions / RPC procedures / resolvers, loaders, webhooks, queues and job workers, cron, file uploads, CLI entrypoints, WebSocket handlers, admin engines |
| What are the sinks? | DB writes and raw queries, shell/exec, filesystem, outbound HTTP, HTML rendering, email/SMS, payment and other paid third-party calls, deserializers, `redirect()` |
| What's deployed vs local? | Hosting platform, proxies/CDN, what config lives outside the repo (env, IdP, WAF, platform headers). These become `needs_validation` blockers later |

Use the `threat-modeling` vocabulary (principals, trust boundaries, data flows) so the two skills line up.

Enumeration aids (adapt per stack):

```bash
# Next.js server actions and route handlers
rg -l "^['\"]use server['\"]" ; rg --files -g '**/app/**/route.{ts,js}' -g '**/pages/api/**'
# Remix / React Router loaders and actions
rg -n "export (async )?function (loader|action)\b"
# tRPC / GraphQL
rg -n "\.(query|mutation|subscription)\(" -g '*.ts' ; rg -n "Resolver|@Query|@Mutation"
# Rails / Express / FastAPI routes
rg -n "^\s*(get|post|put|patch|delete|resources?|mount)\b" config/routes.rb
rg -n "\b(app|router)\.(get|post|put|patch|delete|all|use)\(" -g '*.{js,ts}'
rg -n "@(app|router)\.(get|post|put|patch|delete)\(" -g '*.py'
# Webhooks, jobs, cron
rg -n -i "webhook|inbound|cron|enqueue|perform_later|@task|worker" -g '!node_modules'
```

Portable fallback where `rg` isn't installed: `grep -rnE '<pattern>' --include='*.ts' --include='*.js' .`

### architecture.md

About 1,000 words or fewer. Sections: **Product & stack**, **Build/run**, **Principals & controls** (table with
`file:line`), **Entry surfaces** (grouped by principal that can reach them), **Trust boundaries**, **Sinks**,
**Deployed vs local**, **Out of scope** (with a reason for each exclusion).

Recon is done when every entry surface you found appears in the ledger as at least one unit. The architecture summary
itself is **not** coverage evidence.

## Phase 2 — The coverage ledger (`coverage.json`)

One **unit** per entry surface × trust boundary × attack class. Give each a stable `id` that survives line-number
churn: `<file>#<method> <route>` or `<file>#<exportName>`, plus the boundary and category, e.g.
`src/app/api/invoices/[id]/route.ts#PUT:tenant-isolation:A01`.

```json
{
  "id": "src/app/api/invoices/[id]/route.ts#PUT:tenant-isolation:A01",
  "surface": "PUT /api/invoices/:id",
  "boundary": "signed-in user → another tenant's invoice",
  "owasp_category": "A01",
  "status": "covered",
  "reviewed_paths": ["src/app/api/invoices/[id]/route.ts", "src/lib/auth/requireOrg.ts"],
  "checks": [
    {
      "invariant": "invoice is loaded with orgId = session.orgId before any read or write",
      "method": "read handler + guard; traced orgId source to session, not body",
      "result": "holds: findFirst({ where: { id, orgId } }) at route.ts:18 precedes update at :31"
    }
  ],
  "finding_fingerprints": [],
  "unresolved": []
}
```

The authoritative shape lives in [coverage.schema.json](coverage.schema.json). Validate with [validate-coverage.mjs](validate-coverage.mjs) (usage in
[findings-format.md](findings-format.md)).

### Statuses

| Status | Meaning | Rule |
|---|---|---|
| `planned` | Identified in recon, not started | Default for every new unit |
| `in_progress` | Being reviewed now | Only one owner at a time (see [orchestration.md](orchestration.md)) |
| `blocked` | Can't proceed: missing code, unreadable generated output, needs a running instance | Put the reason in `unresolved[]` |
| `covered` | Reviewed, and no candidate came out of it | Requires **non-empty `reviewed_paths` and at least one check** |
| `candidate` | Review produced at least one candidate | List the fingerprints in `finding_fingerprints[]`. Stays `candidate` until every fingerprint has a verdict |
| `deferred` | In scope but not reviewed in this run (profile budget, time) | Reported under "Deferred / out of scope". Makes the run **partial** |
| `out_of_scope` | Excluded by the user or by diff mode | State the reason. In diff mode, everything outside the diff is `out_of_scope` |
| `not_applicable` | The attack class can't apply to this surface (no outbound HTTP → no SSRF) | State why in a check: the check is the evidence it doesn't apply |

**Not coverage evidence:** an architecture summary, the number of agents that ran, "auth reviewed", "grepped the repo
for X" without naming the paths read, or a framework's reputation. A check names an invariant, how you tested it, and
what you found.

Once all a unit's candidates have verdicts, it can move to `covered`. Its `finding_fingerprints[]` keeps the
confirmed, needs_validation, and rejected fingerprints so the report can link them.

## Phase 3 — Coverage critic

After each hunting wave, and always before writing the report, run a critic over `architecture.md` + `coverage.json`.
Use a fresh subagent where possible. Otherwise run it as its own step. The critic doesn't hunt for bugs. It looks for
holes in the ledger and returns `missing_units`:

- **Unmapped entry points.** Surfaces in the code that no unit covers. Re-run the enumeration commands and diff the
  results against the ledger. Usual misses: server actions, `loader`s, GraphQL field resolvers, job workers, admin-engine
  mounts, webhook routes, `middleware.ts` matchers, and duplicate/legacy route files.
- **Unchecked parallel paths.** A boundary checked on one surface but not on its siblings: the REST route and the server
  action that write the same table, `PUT` hardened but `POST /:id/send` not, v1 and v2 of the same API.
- **Thin `covered` units.** Empty or generic checks, `reviewed_paths` that don't include the guard the check relies on,
  or a check whose result doesn't state the invariant held.
- **Unjustified exclusions.** `out_of_scope` / `not_applicable` / `deferred` with no reason, or a reason that doesn't
  hold up ("internal only" with a public route).
- **Stale `candidate` units.** Fingerprints with no verdict.

Critic output (one JSON object):

```json
{
  "missing_units": [
    { "surface": "app/actions/invite.ts#acceptInvite", "boundary": "anonymous → org membership", "owasp_category": "A01",
      "why": "server action not in ledger; writes memberships table" }
  ],
  "weak_units": [ { "id": "...", "why": "check cites route but not requireOrg guard" } ],
  "unjustified_exclusions": [ { "id": "...", "why": "marked internal but exposed via /api/internal/*" } ]
}
```

Add every missing unit to the ledger as `planned`, then review it (or mark it `deferred` with a reason if the profile
budget is spent). How many critic waves to run depends on the run profile ([orchestration.md](orchestration.md)): `quick` runs one,
`standard` runs until a wave adds nothing high-value, `deep` runs until a wave comes back empty.

## Rendering coverage into the report

- **Items checked and found clean** is generated from `covered` and `not_applicable` units. List the surface, boundary,
  category, and the check's invariant and result. Don't hand-write this section.
- **Deferred / out of scope** lists every `deferred`, `out_of_scope`, and `blocked` unit with its reason.
- If any in-scope unit is `deferred` or `blocked`, or the run was diff-scoped, the report header says **partial**
  (`diff-scoped (partial)` for diff mode). A partial audit never says "no issues found" about the whole codebase.

## Sources

Paraphrased and adapted, not copied:

- Cloudflare security-audit-skill (MIT): [RECONNAISSANCE.md](https://github.com/cloudflare/security-audit-skill/blob/main/skills/security-audit/RECONNAISSANCE.md)
  (recon pass, architecture summary, coverage ledger), [HUNTING.md](https://github.com/cloudflare/security-audit-skill/blob/main/skills/security-audit/HUNTING.md)
  (coverage-critic waves), [validate-coverage-ledger.cjs](https://github.com/cloudflare/security-audit-skill/blob/main/skills/security-audit/validate-coverage-ledger.cjs)
- Strix (Apache-2.0): [tools/coverage/tools.py](https://github.com/usestrix/strix/blob/main/strix/tools/coverage/tools.py)
  (per-unit coverage outcomes)
