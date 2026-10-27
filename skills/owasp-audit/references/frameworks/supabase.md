# Supabase playbook

Load this during an `owasp-audit` run when recon detects Supabase ([detection signals](README.md)). Supabase exposes
tables in the `public` schema through its Data API (PostgREST, plus GraphQL and Realtime) to anyone holding the
project's anon / publishable key, and that key ships in every client. So Row Level Security (RLS) and grants are
the access control. Client-side `.eq('user_id', user.id)` filters are not.

Findings use the normal OWASP Top 10:2025 categories, verdicts, and `findings.json` format. Fingerprints name the
table, policy, bucket, or function: `owasp-audit/CWE-862/supabase/migrations/<file>.sql/<table>`.

## Add these surfaces to the ledger

| Surface | Where it lives | Principal to test against |
|---|---|---|
| Each table and view in an exposed schema | `supabase/migrations/*.sql`, `supabase/schema.sql`, or a `pg_dump --schema-only` | `anon`, `authenticated` (another user / tenant) |
| Each RPC function (`/rest/v1/rpc/<fn>`) | `create function` in migrations | `anon`, `authenticated` |
| Each storage bucket | `insert into storage.buckets`, `[storage.buckets.*]` in `supabase/config.toml`, policies on `storage.objects` | `anon`, `authenticated` |
| Each Edge Function | `supabase/functions/<name>/index.ts`, `verify_jwt` in `config.toml` | anonymous caller, other user |
| Server code that holds the service-role / secret key | `createClient(url, <service key>)` in route handlers, actions, jobs | whoever can reach that code |

Which schemas the API exposes is set in `config.toml` (`[api] schemas`) locally and in the dashboard for the hosted
project. A table in an unexposed schema isn't reachable through the Data API.

```bash
ls supabase/migrations supabase/functions 2>/dev/null; rg -n "^\[api\]" -A4 supabase/config.toml
rg -n -i "create (or replace )?function|security definer|create policy|enable row level security|storage\.buckets" supabase/
rg -n "createClient\(|createServerClient\(|createBrowserClient\(" -g '!node_modules'
```

The `scanner-pipeline` skill ships semgrep rules for three of these checks (policy self-comparison, literal-true
policies, tables created without RLS): [supabase-rls.yml](../../../scanner-pipeline/references/semgrep/supabase-rls.yml).
Use their hits as candidates. They match text, so every hit still needs the verification below.

## Checks

### 1. RLS not enabled on an exposed table (A01)

**Look for:** a table created in `public` (or another exposed schema) with no later
`alter table ... enable row level security`. Without RLS, the anon key reads and writes every row, subject only to
grants, and Supabase grants the API roles broad table privileges by default. Views are a second path: a view runs
with its owner's rights unless it's created `with (security_invoker = true)` (Postgres 15+), so it can return rows
the underlying table's RLS would hide. Supabase's Security Advisor flags these as `rls_disabled_in_public` and
`security_definer_view`.

**Find candidates:** list created tables and RLS-enabled tables, then diff.

```bash
# created but never RLS-enabled (bash/zsh)
comm -23 \
  <(rg -i --no-filename -o "create table (if not exists )?(public\.)?\"?([a-z0-9_]+)" -r '$3' supabase/migrations | tr A-Z a-z | sort -u) \
  <(rg -i --no-filename -o "alter table (only )?(if exists )?(public\.)?\"?([a-z0-9_]+)\"? enable row level security" -r '$4' supabase/migrations | tr A-Z a-z | sort -u)
rg -n -i "create (or replace )?view" supabase/migrations | rg -v -i "security_invoker"
# portable
grep -hoiE "create table (if not exists )?(public\.)?\"?[a-z0-9_]+" supabase/migrations/*.sql | awk '{print $NF}' | sed 's/^public\.//; s/"//g' | sort -u
```

Owner-run, read-only, against the real database (the dashboard can enable or disable RLS outside migrations):

```sql
select n.nspname, c.relname from pg_class c join pg_namespace n on n.oid = c.relnamespace
where c.relkind in ('r','p') and not c.relrowsecurity and n.nspname = 'public';
```

**Verify:** confirmed when the table is in an exposed schema, RLS is off, the API roles have privileges on it, and it
holds data an anonymous or other user shouldn't see or change. If the migrations aren't the source of truth (the team
edits in the dashboard), make it `needs_validation` with the query above as the owner-run check. Rejected when RLS is
enabled (even with zero policies: that denies everything to `anon` / `authenticated`), when
`revoke all ... from anon, authenticated` removes API access, or when the schema isn't exposed. Name the line.

### 2. Policies that allow too much (A01)

**Look for:**
- `using (true)` or `with check (true)` on a table that isn't meant to be public, or on a write command
- `to public` / no `to` clause (applies to `anon` too) on a write policy
- `auth.role() = 'authenticated'` or `auth.uid() is not null` as the only condition: any signed-up user gets every row.
  Sign-up is usually open, so this is close to public
- A policy on `select` only, with `insert` / `update` / `delete` covered by a separate `using (true)` policy.
  Permissive policies combine with OR, so the loosest one wins
- An `insert` policy whose `with check` doesn't pin `user_id = auth.uid()`, so a user can create rows owned by someone
  else
- Roles read from `auth.jwt() -> 'user_metadata'` (or `raw_user_meta_data`). Users can change their own user
  metadata from the client with `auth.updateUser`, so a role there is attacker-controlled. Roles belong in
  `app_metadata` or a table the user can't write
- A column compared with itself (`profiles.id = profiles.id`), which is always true; the semgrep rule catches this
- Tenant tables keyed only on `user_id` when the app's model is per-org: a member removed from an org keeps access

**Find candidates:**

```bash
rg -n -i -U "create policy[^;]*;" supabase/migrations | rg -i "\(\s*true\s*\)|auth\.role\(\)|is not null|user_metadata|raw_user_meta_data"
grep -rniE "using \( *true *\)|with check \( *true *\)|user_metadata" supabase/migrations
```

**Verify:** for each table, write out the effective rule per command and role (OR all permissive policies, AND any
restrictive ones). Confirmed when a lower-trust role can read or change rows it shouldn't, and you can name the
policy. Rejected when the table is intentionally public for that command (published posts, a pricing table) and the
policy is scoped to that command; record that as the control with its location.

### 3. Service-role / secret key exposure and misuse (A04, A01)

**Look for:**
- The legacy `service_role` JWT or a new `sb_secret_...` key anywhere a client can reach: a `NEXT_PUBLIC_`,
  `VITE_`, `EXPO_PUBLIC_`, or `REACT_APP_` variable, a mobile app bundle, a committed `.env`, a public repo. Either
  key bypasses RLS entirely. Supabase rejects secret keys sent from a browser, but that check is on the request
  headers, so a copied key still works from a script
- Legacy keys are JWTs: decode the middle segment and read the `role` claim (`anon` vs `service_role`). New keys say
  what they are in the prefix (`sb_publishable_` vs `sb_secret_`). Creating new keys doesn't disable the legacy ones
- Server code (route handler, server action, Edge Function, job) that builds a service-role client and then reads or
  writes using an id from the request without its own ownership check. RLS doesn't run for that client, so the code
  is the only control

**Find candidates:**

```bash
rg -n --hidden "(NEXT_PUBLIC|VITE|EXPO_PUBLIC|REACT_APP)_[A-Z_]*(SERVICE|SECRET)" -g '!node_modules'
rg -n --hidden "sb_secret_|service_role" -g '!node_modules' -g '!supabase/migrations/**'
rg -n "SUPABASE_SERVICE_ROLE_KEY|SUPABASE_SECRET_KEY" -g '!node_modules'      # then check each importer is server-only
```

**Verify:** exposure is confirmed when the key with service-role authority is in client-reachable output or a public
location (hand rotation and history cleanup to `secrets-audit`). Rejected when the only references are in server-only
code (Edge Functions reading `Deno.env`, modules guarded by `server-only`) and the key never appears in a built
client chunk. Misuse is confirmed with the usual A01 trace from request to service-role query.

### 4. Storage buckets and policies (A01)

**Look for:**
- A bucket with `public = true` holding private files (invoices, IDs, exports). Public buckets serve objects by URL
  with no policy check
- Policies on `storage.objects` that check only `bucket_id = 'x'`, so any user reads or overwrites every object in the
  bucket. Per-user buckets usually scope on the path: `(storage.foldername(name))[1] = auth.uid()::text`
- Upload policies without an owner or path check, and no content-type limits (HTML/SVG served from the storage
  domain)
- Long-lived signed URLs stored or sent where other users can see them

**Find candidates:**

```bash
rg -n -i "storage\.buckets|on storage\.objects" -A6 supabase/migrations
rg -n "^\[storage\.buckets" -A6 supabase/config.toml
```

**Verify:** confirmed when another principal can read, list, or overwrite an object it shouldn't, by policy or by public
URL. Rejected when the bucket is private and every policy on it pins the path to `auth.uid()` (or the tenant), named
by line.

### 5. `security definer` functions and RPC (A01)

**Look for:** `security definer` functions in an exposed schema. They run as their owner, skip RLS, and are callable at
`/rest/v1/rpc/<name>` by any role with `execute` (by default, `public`, which includes `anon`). Check that each one:
- derives the caller from `auth.uid()` and checks ownership or role inside the body, rather than trusting a
  `user_id` / `org_id` argument
- has `execute` revoked from `anon` (and `public`) unless anonymous calls are intended
- sets `search_path` (`set search_path = ''` with schema-qualified names). A mutable `search_path` is a hardening note
  unless a lower-trust role can create objects in a schema that's searched first

Trigger functions that are `security definer` aren't callable through the API (they return `trigger`), but check what
they write.

**Find candidates:**

```bash
rg -n -i -U "create (or replace )?function[^;]*security definer" supabase/migrations
rg -n -i "grant execute|revoke execute" supabase/migrations
```

**Verify:** confirmed when a role that can call the function can make it read or write rows outside its own scope.
Rejected when the body checks `auth.uid()` against the target row (name the line) or `execute` is revoked from every
API role.

### 6. Anon-key-plus-RLS reliance and auth helpers (A01, A07)

**Look for:**
- Data scoping done only in the client query. The anon key plus the user's JWT can call the API directly with any
  filter, so the client's `.eq()` is not a control. Every table the client touches needs check 1 and check 2 to hold
- Server code that trusts `supabase.auth.getSession()` to authorize. It reads the session from cookies without
  re-validating the JWT. Supabase's guidance is to use `getUser()` (or `getClaims()` with asymmetric keys) for
  server-side auth decisions
- Edge Functions with `verify_jwt = false` that then use a service-role client without verifying the caller another
  way (a webhook signature, a shared secret)
- Realtime: a table in the `supabase_realtime` publication without RLS streams every change to every subscriber.
  Broadcast/presence channels need their own authorization if enabled

**Find candidates:**

```bash
rg -n "auth\.getSession\(\)" -g '!node_modules' -g '!**/*.test.*'
rg -n "verify_jwt\s*=\s*false" supabase/config.toml
rg -n -i "supabase_realtime" supabase/migrations
```

**Verify:** a `getSession()` call is a finding only on a server-side authorization path where a forged or expired
cookie would pass; on the client it's fine. An unauthenticated Edge Function is confirmed when it reaches a privileged
client without another caller check.

## Worked examples

**Confirmed (A01).** `supabase/migrations/20250114_invoices.sql` creates `public.invoices` (line 3). No migration
enables RLS on it, the project exposes `public`, and `lib/supabase/browser.ts` creates a client with
`NEXT_PUBLIC_SUPABASE_ANON_KEY`. Anyone with the anon key from the bundle can list every customer's invoices.

```json
{
  "fingerprint": "owasp-audit/CWE-862/supabase/migrations/20250114_invoices.sql/invoices",
  "verdict": "confirmed", "owasp_category": "A01:2025", "cwe": "CWE-862", "confidence": "medium",
  "counterevidence": "searched all migrations for enable row level security on invoices and for revokes from anon; none. Deployed DB not checked, so confidence stays medium",
  "conditions": [ { "kind": "system_configuration", "description": "deployed schema matches migrations (owner can confirm with the pg_class query)" } ],
  "severity": { "likelihood": { "score": "high", "reason": "anon key ships in the client bundle" },
                "impact": { "score": "high", "reason": "read and write all invoices" }, "overall": "high" }
}
```

**Rejected (A01).** The semgrep rule `table-created-without-rls` flagged `public.audit_log` in
`20250201_audit.sql`. A later migration, `20250301_lockdown.sql`, enables RLS on it at line 12 and defines no policy
for `anon` or `authenticated`, so the Data API returns no rows to either. Only the service-role writer in a server job
touches it.

```json
{
  "fingerprint": "owasp-audit/CWE-862/supabase/migrations/20250201_audit.sql/audit_log",
  "verdict": "rejected", "owasp_category": "A01:2025", "confidence": "high",
  "counterevidence": "table is created without RLS, but RLS is enabled in a later migration and no permissive policy exists for API roles",
  "ruled_out_by": { "control": "RLS enabled with no policy for anon/authenticated: default deny through the Data API",
                    "location": { "file": "supabase/migrations/20250301_lockdown.sql", "line": 12 } }
}
```

Both are abridged; see [findings-format.md](../findings-format.md) for the full record shape.

## Sources

Paraphrased, not copied:

- Strix (Apache-2.0): [technologies/supabase.md](https://github.com/usestrix/strix/blob/main/strix/skills/technologies/supabase.md)
  (RLS gaps per command, RPC and `security definer`, storage, service-role exposure, new key formats)
- Supabase docs: [Row Level Security](https://supabase.com/docs/guides/database/postgres/row-level-security),
  [API keys](https://supabase.com/docs/guides/api/api-keys),
  [Migrating to publishable and secret keys](https://supabase.com/docs/guides/getting-started/migrating-to-new-api-keys),
  [Database Advisors](https://supabase.com/docs/guides/database/database-advisors),
  [Storage access control](https://supabase.com/docs/guides/storage/security/access-control)
