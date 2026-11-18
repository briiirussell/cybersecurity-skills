# undici cache and redirect advisories (2026-11-05)

Worked example for Step 3. Facts re-checked 2026-11-15 against the six undici advisories and the 7.30.2 / 8.12.4
release notes. None of the six CVEs were on the CISA KEV catalog that day. cve.now for CVE-2026-116592:
`kev` false, `exploits` 0, `epssReached` false.

## What the batch is

On 2026-11-05 undici shipped **7.30.2** and **8.12.4**, fixing six advisories. The high one is
[GHSA-mqg3-3v4r-cm32](https://github.com/nodejs/undici/security/advisories/GHSA-mqg3-3v4r-cm32) /
CVE-2026-116592 (CVSS 3.1 7.4, `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N`). When an originless Agent composes
`redirect()` with a shared `cache()`, undici could store the final response of a redirect chain under the original
request key without applying origin, cache policy, freshness, or `Vary` from every intermediate hop. That can poison
a cache or serve one user's response to another.

The same tags fix five medium advisories. They do not all need that compose pattern, so an app that only uses
stock `fetch()` is still in scope for the bump:

| Advisory | CVE | What it is | Vulnerable |
|---|---|---|---|
| [GHSA-mqg3-3v4r-cm32](https://github.com/nodejs/undici/security/advisories/GHSA-mqg3-3v4r-cm32) | CVE-2026-116592 | High. Cache poisoning / cross-user disclosure via intermediate redirect hops | 7.30.1 only (`>= 7.30.1, < 7.30.2`); 8.12.2 through 8.12.3 |
| [GHSA-7xg3-fphp-28hg](https://github.com/nodejs/undici/security/advisories/GHSA-7xg3-fphp-28hg) | CVE-2026-120474 | Medium. Same-origin credentialed redirect stored in a shared cache | `>= 7.0.0, < 7.30.2`; `>= 8.0.0, < 8.12.4` |
| [GHSA-5rm8-gv32-r954](https://github.com/nodejs/undici/security/advisories/GHSA-5rm8-gv32-r954) | CVE-2026-116630 | Medium. Cross-origin revalidation (`304`) validates another origin's cached body | same 7.x and 8.x span |
| [GHSA-9v6h-8rgp-m69f](https://github.com/nodejs/undici/security/advisories/GHSA-9v6h-8rgp-m69f) | CVE-2026-120415 | Medium. Array-of-tuples headers skip credential stripping on cross-origin redirect | same 7.x and 8.x span |
| [GHSA-3g9m-rv3r-w5w2](https://github.com/nodejs/undici/security/advisories/GHSA-3g9m-rv3r-w5w2) | CVE-2026-120222 | Medium. Cache-replay exception escapes and can take the process down | same 7.x and 8.x span |
| [GHSA-r4pc-4jcp-7pqc](https://github.com/nodejs/undici/security/advisories/GHSA-r4pc-4jcp-7pqc) | CVE-2026-120423 | Medium. SRI skipped when integrity metadata uses ASCII whitespace other than a space | `>= 7.15.0, < 7.30.2`; `>= 8.0.0, < 8.12.4` |

Floor for the batch: **7.30.2** on the 7.x line, **8.12.4** on the 8.x line. undici 6.x is outside every range above.

## Check

```bash
rg -n '"undici"' package-lock.json pnpm-lock.yaml yarn.lock bun.lock bun.lockb 2>/dev/null
npm ls undici 2>/dev/null || pnpm why undici 2>/dev/null || yarn why undici 2>/dev/null
rg -n "compose\(.*redirect|from 'undici'|from \"undici\"|require\(['\"]undici" app src lib --glob '!node_modules'
```

Also read the Node version the app actually runs. Node vendors undici for built-in `fetch`, and Next.js 16.4.6
(registry `latest` on 2026-11-15) does not depend on undici itself. From each release tag's
`deps/undici/src/package.json`:

| Node release | Vendored undici | This batch |
|---|---|---|
| 22.23.5 | 6.29.1 | Outside the six ranges. A lockfile copy of undici 7 or 8 is still in scope |
| 24.22.2 | 7.30.1 | Vulnerable, including the high advisory |
| 24.22.3 (2026-11-11) | 7.30.2 | Patched |
| 26.12.1 and 26.13.0 | 8.12.2 | Vulnerable, including the high advisory |
| 26.13.1 (2026-11-11) | 8.12.4 | Patched |

A managed Node runtime (Vercel and similar) may already be on the patched release. Confirm the platform's current
runtime before recording a repo change. Unconfirmed platform state is `needs_validation`.

## Findings

- Lockfile undici below the floor for its line → bump. Fingerprint `dependency-audit/GHSA-mqg3-3v4r-cm32/<lockfile>/undici`
  when the resolved version is in the high range; otherwise name the medium advisory that actually matches.
- App code that composes `redirect()` and a shared `cache()` on an originless Agent, on a version in the high range →
  the cross-user cache bug is reachable. Say so. Stock `fetch()` without undici's cache interceptor is lower priority
  for that high advisory and still gets the bump, because the medium SRI, credential-stripping, and cache-replay
  items do not all need the compose.
- After the upgrade, run `npm ls undici` / `pnpm why undici` / `yarn why undici` again. A pnpm override or a second
  copy can leave a vulnerable singleton. Do not close the finding while one remains.
- Not on KEV as of 2026-11-15. Schedule it as a normal dependency bump unless the app shares one undici cache across
  tenants, in which case the high advisory is the row to do first.

A fleet of apps goes to `patch-sweep`.
