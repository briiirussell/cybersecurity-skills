# Better Auth Expo proxy — fleet bump (CVE-2026-121802)

Node/auth row for Step 4. Facts re-checked 2026-11-15 against the vendor advisory. Not on CISA KEV that day
(cve.now: `kev` false, `exploits` 0, `epssReached` false). CVSS 3.1 9.1, unauthenticated account takeover.
Per-repo version floors and the `expo()` grep are in `dependency-audit`'s `references/better-auth-expo.md`.
This page is the sweep rule.

| Id | Packages | Vulnerable | Fixed |
|---|---|---|---|
| [GHSA-4wq4-2ppv-q3hg](https://github.com/better-auth/better-auth/security/advisories/GHSA-4wq4-2ppv-q3hg) / [GHSA-hv45-wgqh-c9j5](https://github.com/advisories/GHSA-hv45-wgqh-c9j5) / CVE-2026-121802 | `@better-auth/expo` | ≥1.4.0-beta.6 and <1.7.16; ≥1.8.0-beta.0 and <1.8.0-beta.5 | **1.7.16** or **1.8.0-beta.5** |
| same | `better-auth` | <1.7.16; ≥1.8.0-beta.0 and <1.8.0-beta.5 | **1.7.16** or **1.8.0-beta.5** |

## Per app

Read the production branch's lockfile.

1. If either package is present and below the floor, bump **both**. They share the application secret.
2. `expo()` registered (grep `expo(` and `@better-auth/expo` imports outside `node_modules`) → the row is urgent.
   The public proxy signs caller-supplied `state`. An unauthenticated attacker who knows an email can take the
   account over.
3. Packages present, `expo()` not registered → still bump both, on a same-week cadence. CVSS 9.1, but the
   unauthenticated proxy path is absent, and the advisory is not on KEV. Do not page overnight for that row.
4. Neither package → `not affected (no better-auth)`.

## Close the row only after the secret rotates

The advisory is explicit: signatures issued before the fix stay valid until the application secret changes. On every
app where the proxy was reachable:

- Rotate the application secret. Do not keep the old secret as a fallback.
- Invalidate sessions.
- Re-check `trustedOrigins` for wildcards. A wildcard that matched outside the intended scheme, host, or path is
  part of the same advisory.

Record the rotation date on the board. "Bumped to 1.7.16" with the old secret still in the platform env is not
`Fixed`. An app that cannot rotate today stays open, with the owner named.

An app that does not use Expo social sign-in may remove the `expo()` plugin as the vendor's workaround. That does
not replace the bump, and it does not replace rotation if the endpoint was already reachable.
