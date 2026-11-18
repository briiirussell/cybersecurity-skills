# Better Auth Expo authorization proxy (CVE-2026-121802)

Worked example for Step 3. Facts re-checked 2026-11-15 against the vendor advisory and the CVE record.
Not on the CISA KEV catalog that day (cve.now: `kev` false, `exploits` 0, `epssReached` false).

## What it is

The `expo()` server plugin from `@better-auth/expo` adds a public `/expo-authorization-proxy` endpoint under the
auth base path. From 1.4.0-beta.6 it signed a caller-supplied `state` with the application secret and did not check
that the server had issued it. Better Auth uses that same secret for email-verification links and, when the cookie
cache is on, for the session cookie cache. An unauthenticated attacker who knows a user's email can sign in as that
user and change the account email. With the cookie cache enabled, knowing a user id is enough to act as that user.
The same endpoint was an open redirect, and a wildcard `trustedOrigins` entry could match outside the intended
scheme, host, or path.

You are affected when the server registers `expo()`. No other setting is required for the signing bug. The wildcard
problem also needs a wildcard in `trustedOrigins` (`myapp://*`, `https://*.example.com`).

Vendor advisory: [GHSA-4wq4-2ppv-q3hg](https://github.com/better-auth/better-auth/security/advisories/GHSA-4wq4-2ppv-q3hg)
(critical, CVSS 3.1 9.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`, published 2026-11-03). CVE record:
[CVE-2026-121802](https://github.com/advisories/GHSA-hv45-wgqh-c9j5) ([GHSA-hv45-wgqh-c9j5](https://github.com/advisories/GHSA-hv45-wgqh-c9j5)).
Fixed in the [1.7.16](https://github.com/better-auth/better-auth/releases/tag/v1.7.16) release the same day.

## Version floors

Upgrade **both** packages. They share the secret and the cookie-cache surface, and the advisory says to upgrade both.

| Package | Vulnerable | Fixed |
|---|---|---|
| `@better-auth/expo` | ≥1.4.0-beta.6 and <1.7.16; ≥1.8.0-beta.0 and <1.8.0-beta.5 | **1.7.16** or **1.8.0-beta.5** |
| `better-auth` | <1.7.16; ≥1.8.0-beta.0 and <1.8.0-beta.5 | **1.7.16** or **1.8.0-beta.5** |

## Check

```bash
rg -n '"better-auth"|"@better-auth/expo"' package-lock.json pnpm-lock.yaml yarn.lock 2>/dev/null
rg -n "expo\(|from '@better-auth/expo'|from \"@better-auth/expo\"" app src lib --glob '!node_modules'
npm ls better-auth @better-auth/expo 2>/dev/null || pnpm why better-auth 2>/dev/null
```

Read the lockfile on the branch that production builds, not the `package.json` range.

## Findings

- Lockfile below the floor **and** `expo()` registered → `confirmed`, critical. Unauthenticated account takeover.
  Fingerprint `dependency-audit/CVE-2026-121802/<lockfile>/better-auth`.
- Lockfile below the floor, `expo()` not registered → still bump both packages. Do not call it a confirmed account
  takeover: the proxy path is absent. Record the version gap (the release also fixes the shared secret and cookie
  cache) and name the missing `expo()` registration as what rules the critical path out.
- Neither package in the lockfile → not this advisory.

## After the bump

1. Rotate the application secret when the endpoint was reachable. Signatures from before the fix stay valid until
   the secret changes. Invalidate sessions. Do not leave the old secret as a fallback.
2. Re-check `trustedOrigins` for wildcards. The fix matches a wildcard by the URL's parsed scheme, host, and path.
   If Expo sign-in through an SSO provider fails after the upgrade, add that provider's origin to `trustedOrigins`.
3. An app that does not use Expo social sign-in can remove the `expo()` server plugin (the vendor's workaround).
   Removal does not close a below-floor lockfile row. Bump both packages anyway.
4. A fleet of apps goes to `patch-sweep`. Do not close a sweep row until the secret is rotated on every app where
   the proxy was reachable.

Custom auth code that signs a caller-supplied value with the application secret, or that uses one secret for email
links and the session cookie cache, is the same class of bug with these packages absent. Flag it from `owasp-audit`
A07.

## Sources

- [GHSA-4wq4-2ppv-q3hg](https://github.com/better-auth/better-auth/security/advisories/GHSA-4wq4-2ppv-q3hg), read 2026-11-15
- [GHSA-hv45-wgqh-c9j5](https://github.com/advisories/GHSA-hv45-wgqh-c9j5) / [CVE-2026-121802](https://cve.now/CVE-2026-121802)
- [v1.7.16](https://github.com/better-auth/better-auth/releases/tag/v1.7.16)
- CISA KEV catalog and the cve.now entry, both fetched 2026-11-15: not listed, no public exploit count
