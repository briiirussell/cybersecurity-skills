# Third-Party Scripts in Logged-In Pages (TP1–TP6)

Companion to `breach-patterns` Pattern 11. Pattern 2 and `owasp-audit` A03 cover a versioned CDN file, which SRI can
pin. This file covers the scripts SRI can't pin: a vendor snippet that's **meant** to change (real-user monitoring,
tag managers, chat widgets, A/B testing, session replay). On a logged-in page, such a script never needs a password.
It already runs as the user.

## The incident (2026-10-29)

- Polymarket loaded DebugBear's real-user-monitoring script from `cdn.debugbear[.]com/C7xcKKrjUnXK.js`. During the
  incident the file was a wallet drainer that talked to `data.debugbear.com` (BleepingComputer).
- Ohey's analysis: the drainer was 15,187 bytes, against 60,493 for the last clean copy. It ran between 16:54 UTC,
  when the script's origin went down, and 17:59 UTC, when Polymarket removed the script. It took 28,636,284.45 POL
  and positions from 33 accounts.
- It read the session's own localStorage (`polymarket.auth.params`, `poly_clob_api_key_map`,
  `polymarket.auth.proxyWallet`), found Polymarket's trading client by walking React's fiber objects, signed with the
  account's existing signer, and submitted through Polymarket's own relayer. Email-login accounts had their positions
  sold. Browser-wallet accounts had positions transferred out, and the wallet showed each batch as a signature
  request (Ohey).
- "Every host it called, apart from DebugBear's, was on Polymarket's Content Security Policy" (Ohey). The CSP was
  there; the exfil host was an allowed vendor domain.
- Hudson Rock found no routine that sends a password, seed phrase or private key: "Its central approach is to reuse
  authority already available in the authenticated application" (SecurityWeek).
- Loss estimates differ: about $2.5M traced (BleepingComputer); Hudson Rock about $2.19M ("not a verified tally"),
  GoPlus about $2.71M, Arkham about $2.65M (SecurityWeek). Polymarket removed the script (commit
  `chore(polymarket): remove debugbear rum script (#15337)`) and says "Anyone who has been impacted will be made
  whole." DebugBear told customers: "If you use our RUM product, please remove the embed code from your website"
  (BleepingComputer).
- **How the file was replaced isn't known.** Hudson Rock hasn't determined it (SecurityWeek). Ohey saw a different
  server answering for both DebugBear hostnames, but DebugBear hasn't published a root cause.
- SecurityWeek reports an earlier third-party script compromise at Polymarket, disclosed in June, with about $3M lost.

**The pattern:** any third-party script on a logged-in page can do anything the user can do, so a vendor breach
becomes account takeover with no stolen credentials.

## Checks

| ID | Check | How | Finding |
|---|---|---|---|
| **TP1** | Third-party scripts by page type | List every external `<script src>` and tag-manager tag, and mark which load on logged-in, checkout, payout or admin pages. RUM, analytics, chat, A/B testing and session replay all count | A third-party script on a page that moves money or changes the account: **Medium**, **High** if TP3 fails |
| **TP2** | Can it be pinned? | A versioned, immutable file gets SRI (`integrity="sha384-…" crossorigin`; `owasp-audit` A03). A per-project or "always latest" file breaks SRI on every vendor update, so the options are a self-hosted reviewed copy, loading it only on logged-out pages, or removing it | An unpinnable vendor script on an authenticated page: finding, sized by TP1 |
| **TP3** | Sensitive actions need fresh user intent | Withdrawals, payouts, email or password changes and API key creation need a step-up (re-auth, passkey, or a confirmation outside the page) that page JavaScript can't complete on its own. `business-logic-testing` Step 5 tests it | A sensitive action a script can complete with the existing session alone: **High** |
| **TP4** | What the page exposes to scripts | Session or API credentials in `localStorage` / `sessionStorage` or on `window` are readable by every script on the page. Prefer `HttpOnly` cookies (`owasp-audit` A04 and A07). This doesn't stop a script acting as the user (TP3 does); it stops theft that outlives the page | Long-lived API credentials in web storage: **Medium** |
| **TP5** | CSP isn't a fence for vendor domains | Read `script-src` and `connect-src`. An allowed vendor host is also an allowed exfil channel, as it was here. Narrow the list per page and keep vendor hosts off authenticated pages | Note, not a finding on its own (`owasp-audit` A02 header notes) |
| **TP6** | Change detection | For each vendor script that stays, monitor its hash or size and alert on a change. The drainer was a quarter the size of the real file | A remaining vendor script with no monitoring: **Low** |

Read-only, in the codebase:

```bash
# External scripts and tag managers, and where they load
rg -n --glob '!node_modules' -e '<script[^>]+src="https?://' -e 'next/script' \
  -e 'googletagmanager|gtag\(|segment|debugbear|hotjar|fullstory|logrocket|intercom|posthog' .
# Session or API credentials written to web storage
rg -n --glob '!node_modules' -e 'localStorage\.setItem\(' -e 'sessionStorage\.setItem\(' . | rg -i 'token|key|auth|session|secret'
# The CSP as written in config
rg -n --glob '!node_modules' -i 'content-security-policy|connect-src|script-src' .
```

The CSP as served, on an app the user owns (no login needed):

```bash
curl -sI https://<app>/ | rg -i 'content-security-policy'
```

Config shows intent; a proxy or CDN can change what's sent, so record the served header next to the config.

## Framing

The sources describe what happened. Step-up for sensitive actions, self-hosting or removing vendor scripts on
logged-in pages, narrowing CSP per page and hash monitoring are **our recommendations**, not claims the sources make.
Say so in the report.

## Sources

- [BleepingComputer, 2026-10-29](https://www.bleepingcomputer.com/news/security/polymarket-halts-trading-after-crypto-draining-script-breach-25m-traced/)
- [Ohey, 2026-10-29](https://ohey.ca/research/polymarket-debugbear-wallet-drainer/)
- [SecurityWeek, 2026-10-30](https://www.securityweek.com/2-million-drained-from-polymarket-traders-in-new-supply-chain-attack/)
- MDN: [Subresource Integrity](https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity),
  [CSP `connect-src`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/connect-src)
- Proposed by @coreyhaines31 in issue #243
