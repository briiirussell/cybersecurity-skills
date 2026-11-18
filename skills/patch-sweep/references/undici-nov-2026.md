# undici 7.30.2 / 8.12.4 — fleet bump (2026-11-05)

Node runtime row for Step 4. Facts re-checked 2026-11-15 against the six undici advisories, the release notes, and
the Node tags that vendor undici. Not on CISA KEV that day. cve.now for CVE-2026-116592: `kev` false, `exploits` 0,
`epssReached` false. Per-repo commands are in `dependency-audit`'s `references/undici-nov-2026.md`. This page is the
sweep rule.

| Id | Line | Vulnerable | Fixed |
|---|---|---|---|
| [GHSA-mqg3-3v4r-cm32](https://github.com/nodejs/undici/security/advisories/GHSA-mqg3-3v4r-cm32) / CVE-2026-116592 (high, CVSS 7.4) | 7.x | 7.30.1 only | **7.30.2** |
| same | 8.x | 8.12.2 through 8.12.3 | **8.12.4** |
| [GHSA-7xg3-fphp-28hg](https://github.com/nodejs/undici/security/advisories/GHSA-7xg3-fphp-28hg) / CVE-2026-120474, [GHSA-5rm8-gv32-r954](https://github.com/nodejs/undici/security/advisories/GHSA-5rm8-gv32-r954) / CVE-2026-116630, [GHSA-9v6h-8rgp-m69f](https://github.com/nodejs/undici/security/advisories/GHSA-9v6h-8rgp-m69f) / CVE-2026-120415, [GHSA-3g9m-rv3r-w5w2](https://github.com/nodejs/undici/security/advisories/GHSA-3g9m-rv3r-w5w2) / CVE-2026-120222 (medium) | 7.x and 8.x | `>= 7.0.0, < 7.30.2` and `>= 8.0.0, < 8.12.4` | **7.30.2** / **8.12.4** |
| [GHSA-r4pc-4jcp-7pqc](https://github.com/nodejs/undici/security/advisories/GHSA-r4pc-4jcp-7pqc) / CVE-2026-120423 (medium, SRI) | 7.x and 8.x | `>= 7.15.0, < 7.30.2` and `>= 8.0.0, < 8.12.4` | **7.30.2** / **8.12.4** |

undici 6.x is outside this batch.

## Per app

Resolve undici from the production lockfile **and** from the Node version that actually runs. Built-in `fetch` uses
the copy Node vendors. Next.js 16.4.6 does not depend on undici, so a clean Next lockfile does not clear the row.

Vendored versions, read from `deps/undici/src/package.json` on 2026-11-15:

- Node 22.23.5 vendors 6.29.1 (outside this batch).
- Node 24.22.2 vendors 7.30.1. **24.22.3** (2026-11-11) vendors 7.30.2.
- Node 26.12.1 and 26.13.0 vendor 8.12.2. **26.13.1** (2026-11-11) vendors 8.12.4.

If the resolved copy is below the floor, bump the direct dependency, add an override, or take the Node (or Next, once
it picks up the patched runtime) release that vendors the fix, then re-check. A managed runtime that already moved
(Vercel-managed Node, for example) may need no repo change. Confirm the platform's current version before marking
the row clear. Unknown platform state stays `unknown`.

## Reachability

The high advisory needs `redirect()` composed with a shared `cache()` on an originless Agent. Apps that only use
stock `fetch()` without undici's cache interceptor are lower priority for that one issue. Still bump them. The medium
SRI, credential-stripping, and cache-replay items do not all need the compose.

Not on KEV as of 2026-11-15. This is a normal dependency bump, not an emergency page, unless the app deliberately
shares one undici cache across tenants. Those rows go first.

After the bump, `npm ls undici` / `pnpm why undici` / `yarn why undici` must show no copy below the floor. A duplicate
singleton keeps the row open.
