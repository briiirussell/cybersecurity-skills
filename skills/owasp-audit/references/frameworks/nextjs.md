# Next.js playbook

Load this during an `owasp-audit` run when recon detects Next.js ([detection signals](README.md)). It adds
framework-specific surfaces and checks on top of the main checklist. It doesn't replace it. Every candidate still goes
through the normal verification pass and is recorded in `findings.json` with an OWASP Top 10:2025 category, a verdict,
and a fingerprint like `owasp-audit/<class>/<file>/<name>`.

Version notes below were checked against the advisories linked in [Sources](#sources) on 2026-10-30. Re-check the
installed version against current advisories on each run. Known-CVE triage belongs to `dependency-audit`.

## Add these surfaces to the ledger

| Surface | How to enumerate | Why it gets its own units |
|---|---|---|
| Server actions | Every exported function in a file that starts with `'use server'`, plus inline functions marked `'use server'` | Each one is a public POST endpoint, called by action ID. It doesn't show up as a route |
| Route handlers | `app/**/route.{ts,js}` exports `GET`, `POST`, `PUT`, `PATCH`, `DELETE` | Each method needs its own auth. A layout's auth check doesn't run for them |
| Pages Router API routes | `pages/api/**` | Often coexists with the App Router and ships with older, different auth |
| Middleware / proxy | `middleware.{ts,js}` (or `proxy.{ts,js}` from Next.js 16, which renames the convention), plus its `config.matcher` | Defines which paths get the edge check. Paths outside the matcher get nothing |
| Cached and revalidated data | `unstable_cache`, `'use cache'`, `export const revalidate`, `dynamic = 'force-static'`, `revalidatePath` / `revalidateTag` callers | A shared cache entry can hand one user's data to another |
| Server → client props | Server Components passing objects to `'use client'` components; `getServerSideProps` return values | Everything passed is serialized into the RSC payload or `__NEXT_DATA__`, rendered or not |

```bash
rg -l "^\s*['\"]use server['\"]" -g '*.{ts,tsx,js,jsx}' -g '!node_modules'      # action modules
rg -n "['\"]use server['\"]" -g '*.{ts,tsx,js,jsx}' -g '!node_modules'           # also inline actions
rg --files -g '**/app/**/route.{ts,js}' -g '**/pages/api/**'
rg --files -g '{middleware,proxy}.{ts,js}' -g '!node_modules'
rg -n "unstable_cache\(|['\"]use cache['\"]|export const (revalidate|dynamic)|force-static|revalidate(Path|Tag)\(" -g '!node_modules'
# portable
grep -rlE "^[[:space:]]*['\"]use server['\"]" --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' . | grep -v node_modules
find . -path ./node_modules -prune -o \( -path '*/app/*' -name 'route.[jt]s' \) -print
```

## Checks

### 1. Server actions without auth or ownership (A01)

**Look for:** an exported action that reaches a DB write, a paid call, or a read of another user's data without first
(a) resolving the session on the server and (b) scoping the record to that user or tenant. Arguments arrive from the
client. TypeScript types aren't enforced at runtime, so an `id: string` parameter can be any value, and a `FormData`
field can be anything.

Common shapes:
- No session check at all, because "the button only renders for admins"
- Session checked, but `where: { id }` with no `userId` / `orgId` predicate (IDOR)
- Role taken from an argument or a hidden form field
- A foreign key from the form (`projectId`, `teamId`) stored as-is, with no check that the caller owns the referenced record
- Auth in a wrapper (`next-safe-action`, a custom `withAuth`) applied to most actions but not all

**Find candidates:** in each action module, list the exports and look for a session call before the first sink:

```bash
rg -n "^export (async )?function|^export const \w+ = (async|action|authAction)" <action-file>
rg -n "auth\(\)|getServerSession|currentUser\(|getUser\(|getClaims\(|requireUser|requireOrg" <action-file>
```

**Verify:** confirmed when a lower-trust principal (anonymous, or a signed-in user of another tenant) can reach the
action with chosen arguments and the trace reaches the sink without an ownership predicate. The action counts as
reachable when any client module imports it (it's then in the action manifest). Rejected only when a server-side
check inside the action, or a wrapper that runs on every call, enforces session and ownership before the sink. Name
the `file:line`. Middleware that only checks "a session cookie exists" doesn't rule out an IDOR.

### 2. Middleware as the only gate: matcher gaps and CVE-2025-29927 (A01, A03)

**Look for:** pages, route handlers, or actions with no auth of their own that depend on middleware for it. Then check
whether middleware actually runs for them:

- `config.matcher` uses a negative lookahead such as `/((?!api|_next/static|_next/image|favicon.ico).*)`, which
  excludes all of `/api`. Any route handler under `/api` that assumes middleware ran is unprotected.
- A matcher lists `/dashboard/:path*` but the sensitive handler lives at `/api/dashboard/...` or `/internal/...`.
- The middleware returns `NextResponse.next()` on an exception, or skips paths by `startsWith` checks that a trailing
  slash, a different case, or an encoded segment avoids.
- **CVE-2025-29927**: Next.js used an internal request header to mark its own subrequests, and middleware skipped
  requests that carried it, so an outside caller could skip middleware entirely. Fixed in 12.3.5, 13.5.9, 14.2.25 and
  15.2.3. Self-hosted apps (`next start`, `output: 'standalone'`) were affected; Vercel- and Netlify-hosted apps and
  static exports were not.

**Find candidates:**

```bash
rg -n "matcher" -A6 middleware.ts proxy.ts src/middleware.ts src/proxy.ts 2>/dev/null
rg -n '"next":' package.json
grep -A3 '"node_modules/next"' package-lock.json | grep '"version"'     # npm
grep -E "^  /?next@|^  next@" pnpm-lock.yaml                              # pnpm
```

**Verify:** a matcher gap is confirmed when you can name a protected path, show the matcher doesn't match it, and the
handler has no auth of its own. For the CVE: an affected version is an A03 finding (hand the upgrade to
`dependency-audit`). Whether it's exploitable as an A01 bypass depends on hosting and on whether the edge strips the
internal header, so record it as `needs_validation` with those as blockers unless the repo shows the deploy target.
Rejected when every protected handler re-checks auth itself (a data access layer or per-handler guard), because then
middleware is defence in depth, not the control.

Fix direction: keep middleware for redirects and coarse gating, and enforce auth next to the data (Next.js's own
guidance since 2025). Upgrade past the fixed versions. Next.js 16 renames `middleware` to `proxy`; the same rules apply.

### 3. `NEXT_PUBLIC_` and other client-bundle leaks (A04, A01)

**Look for:**
- A `NEXT_PUBLIC_` variable holding something with authority: a service-role or secret DB key, a server API key, an
  admin token, a webhook secret. Next.js inlines every `NEXT_PUBLIC_` value into the client JavaScript at build time.
- The `env:` key in `next.config.*`. Values set there are inlined into the client bundle too, whatever their name.
- A module that reads `process.env.<SECRET>` and is imported by a `'use client'` component (non-public env vars
  become `undefined` on the client, but constants and fallbacks don't). `import 'server-only'` turns this into a build
  error. Its absence is a hardening note, not a finding.
- Server Components passing whole records to Client Components (`user` with `passwordHash`, `stripeCustomerId`, other
  members' emails). Everything passed is in the RSC payload, rendered or not. Same for `getServerSideProps`.

**Find candidates:**

```bash
rg -n --hidden "NEXT_PUBLIC_[A-Z0-9_]*(SECRET|SERVICE|PRIVATE|TOKEN|PASSWORD|ADMIN|WEBHOOK)" -g '!node_modules'
rg -n --hidden "^NEXT_PUBLIC_" -g '.env*'
rg -n "^\s*env:\s*\{" next.config.*
rg --files-without-match "server-only" $(rg -l "process\.env\.[A-Z_]*(SECRET|KEY|TOKEN)" -g '*.ts' -g '!node_modules')   # env readers without the guard
# after a local build, search the shipped chunks themselves
rg -l "sk_live_|sb_secret_|service_role|BEGIN PRIVATE KEY" .next/static
```

**Verify:** confirmed when the value grants authority beyond what an anonymous visitor already has and it is in
client-reachable output (show the variable and where it's read, or the chunk). Check the key type first: Stripe
`pk_`, a Supabase anon or `sb_publishable_` key, a Firebase web `apiKey`, a Maps browser key are meant to ship. For
props, confirmed when a field the viewer isn't entitled to is present in the serialized payload.

### 4. Route handler and API route auth (A01)

**Look for:** each exported method in `route.ts` and each `pages/api` handler resolving the session itself. Auth in
`layout.tsx` or a page doesn't cover route handlers. Watch for a `GET` that's been secured while `POST` / `DELETE` in
the same file weren't, and for both routers serving the same resource with different checks.

**Find candidates:**

```bash
rg -n "^export (async )?function (GET|POST|PUT|PATCH|DELETE)|^export const (GET|POST|PUT|PATCH|DELETE)" -g '**/route.{ts,js}'
```

**Verify:** same bar as the main A01 checklist. Rejected only by a guard that runs for that method on every path.

### 5. Caching and revalidation leaking per-user data (A01, A02)

**Look for:**
- `unstable_cache(fn, keyParts)` where `fn` returns user- or tenant-specific data and `keyParts` / the arguments don't
  include the user or tenant id. The first caller's result is served to everyone.
- A `'use cache'` function that returns per-user data but receives its identity in a way that isn't part of the key.
- `export const dynamic = 'force-static'` or `revalidate = N` on a page or `GET` handler that reads per-user data
  through a path Next.js can't see (a custom header helper, a module-level variable).
- `Cache-Control: public` or `s-maxage` set on a personalized response (in `headers()` in `next.config.*`, or by the
  handler), so a CDN caches it. Next.js 14 cached `fetch` and `GET` route handlers by default; 15 made both uncached
  by default, so check which major you're on before assuming.
- A route that calls `revalidatePath` / `revalidateTag` with no auth or a guessable secret (anyone can flush or warm
  the cache on demand; usually A02 or A06 rather than a data leak).

**Find candidates:** the cache `rg` line in the surfaces section, then `rg -n "s-maxage|Cache-Control" -g '!node_modules'`.

**Verify:** confirmed when you can trace user-specific data into a cache entry whose key doesn't include the user,
and a second principal's request is served from that entry. CDN behaviour depends on the host, so a `Cache-Control`
issue is `needs_validation` until someone runs `curl -sI` against the deployed origin as two users and compares
`age` / `x-vercel-cache` / `cf-cache-status`.

### 6. Version-specific advisories (A03, hand off)

Check the installed `next` and React versions against current advisories. Examples worth knowing:

| Advisory | What | Fixed in |
|---|---|---|
| CVE-2025-29927 | Middleware could be skipped from outside (check 2) | 12.3.5, 13.5.9, 14.2.25, 15.2.3 |
| CVE-2024-34351 | Server action redirect to a relative path trusted the `Host` header (SSRF), self-hosted only | 14.1.1 |
| CVE-2025-55182 | React Server Components payload decoding allowed remote code execution in App Router apps ("React2Shell"; the Next.js-specific ID CVE-2025-66478 was merged into it) | Next.js 15.0.5, 15.1.9, 15.2.6, 15.3.6, 15.4.8, 15.5.7, 16.0.7; React 19.0.1, 19.1.2, 19.2.1 |
| GHSA-673q-mjm6-r5xr (no CVE) | Critical. Unauthenticated RCE in App Router apps with Cache Components when a `use cache` function returns multiple typed arrays (upstream React GHSA-xqc2-xf4c-x3h3). No workaround; Next.js says to upgrade even if no function looks like that | 16.4.1 (affected 16.0.0–16.4.0; GitHub lists no 15.x range) |
| GHSA-2464-fhr4-w9xw (CVE-2026-96889) | Critical. RCE through the Image Optimization API with SVG, from a memory bug in an upstream library, when Next.js runs on glibc-based Linux. Workaround: the `sharp` Next.js uses must be 0.35.5 or later | 15.5.28, 16.4.1 (affected 10.0.0–15.5.27, 16.0.0–16.4.0) |
| GHSA-p3m5-59mp-jv5r (CVE-2026-94482) | High. CPU-exhaustion DoS in App Router apps with at least one Server Action (upstream React GHSA-h3gv-c5rc-p453). Pages Router apps and apps without Server Actions aren't affected | 15.5.28, 16.4.1 (affected 13.0.0–15.5.27, 16.0.0–16.4.0) |

**Match on GHSA id and fixed version, not CVE.** Some Next.js advisories ship with no CVE, or with a CVE that names
the upstream library. GitHub's record for GHSA-2464 has no `cve_id`, and NVD describes CVE-2026-96889 as a librsvg
use-after-free (Red Hat, CVSS 3.1 7.8 with a local vector), not as a Next.js bug. A CVE-only lookup on `next` misses
the `use cache` RCE entirely. The release went out on 2026-10-14, but GitHub's advisory database published all three on
2026-10-22, so scanners that read it stayed quiet for eight days. Read the framework's own security posts too.

**`sharp` is resolved separately from `next`.** Upgrading `next` normally pulls a fixed `sharp`, but a lockfile, an
override or a Docker layer can keep an old one. Check what the app actually resolves:

```bash
npm ls next sharp 2>/dev/null || pnpm why sharp || yarn why sharp
node -p "require('next/package.json').version"
node -p "require('sharp/package.json').version" 2>/dev/null     # want >= 0.35.5
rg -n "dangerouslyAllowSVG|images\s*:" next.config.* 2>/dev/null  # image optimizer settings, SVG allowed?
rg -n "'use cache'|\"use cache\"" -g '!node_modules' .           # GHSA-673q exposure (upgrade anyway)
```

An affected `next` version is an A03 hand-off to `dependency-audit` either way. Call out `sharp` below 0.35.5 on a
glibc Linux deployment where the optimizer serves SVG. Record the runtime's libc (Alpine images use musl) rather than
guessing. Runtime advisories that need a Node.js upgrade rather than a `next` upgrade, such as the Node.js Brotli
decoder RCE (CVE-2026-111497, which Next.js image optimization doesn't block when self-hosted), belong to
`patch-sweep`.

The image optimizer's `remotePatterns` wildcard (SSRF) and `headers()` merging are already in the main checklist.

## Worked examples

**Confirmed (A01).** `app/actions/invoices.ts` starts with `'use server'` and exports
`deleteInvoice(id: string)`, imported by `components/InvoiceRow.tsx` (`'use client'`). The action calls
`db.delete(invoices).where(eq(invoices.id, id))` at line 9. Middleware matches `/dashboard/:path*` and only checks
that a session cookie exists. Any signed-in user of any org can delete any invoice by id.

```json
{
  "fingerprint": "owasp-audit/CWE-639/app/actions/invoices.ts/deleteInvoice",
  "verdict": "confirmed", "owasp_category": "A01:2025", "cwe": "CWE-639", "confidence": "medium",
  "counterevidence": "middleware.ts checks a session cookie exists but not org membership; no orgId predicate in the action; no wrapper",
  "severity": { "likelihood": { "score": "high", "reason": "any signed-in user; ids are in list responses" },
                "impact": { "score": "high", "reason": "delete another tenant's invoices" }, "overall": "high" }
}
```

**Rejected (A01).** The matcher `/((?!api|_next/static|_next/image).*)` excludes `/api`, so
`app/api/admin/users/route.ts` was flagged as unprotected. Its `GET` and `DELETE` both call `requireAdmin()` on their
first line, which reads the session server-side and throws a 403 for non-admins before any query.

```json
{
  "fingerprint": "owasp-audit/CWE-862/app/api/admin/users/route.ts/middleware-matcher-gap",
  "verdict": "rejected", "owasp_category": "A01:2025", "confidence": "high",
  "counterevidence": "matcher does exclude /api, but both methods call requireAdmin() before any DB access",
  "ruled_out_by": { "control": "requireAdmin() resolves the session server-side and throws 403 unless role is admin",
                    "location": { "file": "app/api/admin/users/route.ts", "line": 6 } }
}
```

Both are abridged. Real records also carry `skill`, `title`, `location`, `trace`, `evidence`, and (confirmed)
`conditions`; see [findings-format.md](../findings-format.md).

## Sources

Paraphrased, not copied:

- Strix (Apache-2.0): [frameworks/nextjs.md](https://github.com/usestrix/strix/blob/main/strix/skills/frameworks/nextjs.md)
  (server actions as hidden endpoints, middleware bypass, cache-boundary and props over-exposure)
- Next.js security advisories: [GHSA-f82v-jwr5-mffw](https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw)
  (CVE-2025-29927), [GHSA-fr5h-rqp8-mj6g](https://github.com/vercel/next.js/security/advisories/GHSA-fr5h-rqp8-mj6g)
  (CVE-2024-34351), [Vercel CVE-2025-55182 summary](https://vercel.com/changelog/cve-2025-55182),
  [React advisory](https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components),
  [Next.js security update, 2026-10-14](https://nextjs.org/blog/nextjs-security-update-october-14-2026) with
  [GHSA-673q-mjm6-r5xr](https://github.com/vercel/next.js/security/advisories/GHSA-673q-mjm6-r5xr),
  [GHSA-2464-fhr4-w9xw](https://github.com/vercel/next.js/security/advisories/GHSA-2464-fhr4-w9xw) and
  [GHSA-p3m5-59mp-jv5r](https://github.com/vercel/next.js/security/advisories/GHSA-p3m5-59mp-jv5r);
  [NVD CVE-2026-96889](https://nvd.nist.gov/vuln/detail/CVE-2026-96889);
  [Vercel: Node.js Brotli advisory](https://vercel.com/kb/bulletin/node-js-security-advisory). Proposed by
  @coreyhaines31 in issue #233
- Next.js docs: [Data security](https://nextjs.org/docs/app/guides/data-security),
  [Upgrading to version 16](https://nextjs.org/docs/app/guides/upgrading/version-16) (`middleware` → `proxy`)
