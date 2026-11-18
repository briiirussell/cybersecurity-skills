# Third-Party Scripts in Logged-In Pages (TP1–TP7)

Companion to `breach-patterns` Pattern 11. Pattern 2 and `owasp-audit` A03 cover a versioned CDN file, which SRI can
pin. This file covers the scripts SRI can't pin: a vendor snippet that's **meant** to change (real-user monitoring,
tag managers, chat widgets, A/B testing, session replay). On a logged-in page, such a script never needs a password.
It already runs as the user.

## Incident 1: Polymarket via DebugBear (2026-10-29)

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

## Incident 2: OPTIMJACK, Optimizely Web Experimentation (2026-11-16)

Researchers call it OPTIMJACK (StepSecurity's name; Report URI doesn't use it). Checked 2026-11-18 against Report URI,
StepSecurity, Hudson Rock's InfoStealers write-up and Optimizely's status page. No CVE. Researcher figures are as
reported, not re-verified.

- An attacker wrote code into the **Project JavaScript** (`projectJS`) of Optimizely Web customer projects. The rest
  of each snippet was untouched, and it was still served from `cdn.optimizely.com`. "Optimizely's CDN served exactly
  what it was given; this was not a CDN cache-poisoning attack" (Report URI).
- Report URI fetched 1,611 snippets and found 188 infected, belonging to 178 organisations. Optimizely's own
  `www.optimizely.com` and `login.optimizely.com` snippets carried the code. Customers who serve the snippet from
  their own domain were hit too: the content still comes from the Optimizely project.
- Optimizely's status page ("Web Experimentation Security Incident"): an unauthorized third party "exploited a flaw in
  the Optimizely Web Experimentation account signup flow", impersonated users on targeted customer accounts and added
  malicious JavaScript to their projects. Optimizely says the flaw was closed, the code removed, fewer than 5% of
  customers were affected, and no other product was. It has not said how a signup-flow flaw gave write access to
  unrelated projects.
- Window, per Report URI: first injection seen 04:21 UTC on 16 November; mass clean-up about 20:40–21:10 UTC; all
  files clean by 23:11 UTC. One site (Smartsheet) was cleaned and then re-infected. StepSecurity cites Helme counting
  26 builds of the payload that day.
- Three loader variants (Report URI): a plain script tag for `1688360[.]cc/track.js`; the same URL base64-encoded and
  decoded with `atob()`, so a search for the domain finds nothing; and a full inline copy run through `eval` if the
  domain is blocked.
- The payload swapped crypto wallet addresses in the page, forms and clipboard, skimmed card number, expiry and CVV
  from the site's own forms (added 13:43 UTC), sent non-`HttpOnly` cookies and a screenshot near payment wording, and
  loaded iOS exploit kits. Cards typed into hosted payment iframes (Stripe, Adyen and similar) were out of its reach
  (Report URI).
- CSP, from Report URI's crawl of 256 affected organisations' own hosts (counts as published; they sum to 159 and the
  post doesn't say why): no CSP 68; CSP allowed the payload and the data theft 50; payload ran but `connect-src`
  blocked the data theft (address swapping still worked) 17; payload blocked 24. "Allowing `cdn.optimizely.com` was
  never going to help." The 24 had a restrictive `script-src` in common. `'strict-dynamic'` let the loader through,
  because a script the trusted snippet inserts is trusted too. `'unsafe-eval'`, which Optimizely's documentation tells
  customers to allow, let the inline copy run: HSBC's CSP blocked `track.js` and the data theft, but the inline copy
  still ran.
- An earlier wave from 13 November used Kissmetrics, StorifyMe and minute-ly scripts to load `webshell[.]lol/get.js`,
  an iOS exploit loader (Hudson Rock). It links the two by shared infrastructure, and says that doesn't prove one
  operator or one way in.

The full IoC and wallet list is in the Report URI post. It isn't copied here.

**The pattern:** any third-party script on a logged-in page can do anything the user can do, so a vendor breach
becomes account takeover with no stolen credentials. A vendor's customer dashboard is also a code-deploy path to every
page that loads its snippet (OPTIMJACK).

## Checks

| ID | Check | How | Finding |
|---|---|---|---|
| **TP1** | Third-party scripts by page type | List every external `<script src>` and tag-manager tag, and mark which load on logged-in, checkout, payout or admin pages. RUM, analytics, chat, A/B testing and session replay all count | A third-party script on a page that moves money or changes the account: **Medium**, **High** if TP3 fails |
| **TP2** | Can it be pinned? | A versioned, immutable file gets SRI (`integrity="sha384-…" crossorigin`; `owasp-audit` A03). A per-project or "always latest" file breaks SRI on every vendor update, so the options are a self-hosted reviewed copy, loading it only on logged-out pages, or removing it | An unpinnable vendor script on an authenticated page: finding, sized by TP1 |
| **TP3** | Sensitive actions need fresh user intent | Withdrawals, payouts, email or password changes and API key creation need a step-up (re-auth, passkey, or a confirmation outside the page) that page JavaScript can't complete on its own. `business-logic-testing` Step 5 tests it | A sensitive action a script can complete with the existing session alone: **High** |
| **TP4** | What the page exposes to scripts | Session or API credentials in `localStorage` / `sessionStorage` or on `window` are readable by every script on the page. Prefer `HttpOnly` cookies (`owasp-audit` A04 and A07). This doesn't stop a script acting as the user (TP3 does); it stops theft that outlives the page | Long-lived API credentials in web storage: **Medium** |
| **TP5** | CSP isn't a fence for vendor domains | Read `script-src` and `connect-src`. An allowed vendor host is also an allowed exfil channel (Polymarket), and allowlisting the vendor host does nothing when the vendor serves the attack (OPTIMJACK). What limited OPTIMJACK: `script-src` listing only the hosts the page needs, no `'strict-dynamic'` or `'unsafe-eval'` on pages that load vendor snippets, and a restricted `connect-src` (it stopped the card and cookie theft, not the in-page address swap). Narrow the list per page and keep vendor hosts off authenticated pages | Note, not a finding on its own (`owasp-audit` A02 header notes) |
| **TP6** | Change detection | For each vendor script that stays, monitor its hash or size and alert on a change. The drainer was a quarter the size of the real file. After an incident, search the served file for `atob(`, `eval(` and script tags created at runtime, not only the published IoC domain: one OPTIMJACK variant hid the domain in base64. A clean fetch now doesn't show the file was clean earlier (it was cleaned the same evening); compare against an archived copy if you have one | A remaining vendor script with no monitoring: **Low** |
| **TP7** | Who can change what the vendor serves | For tag managers and experimentation tools (Optimizely, GTM, VWO, Segment and similar), the vendor dashboard publishes code to every page with the snippet. Check who has edit or publish rights, SSO and MFA enforced, API tokens and integrations with write access, an audit log someone reviews, and whether custom code (`projectJS`, custom HTML tags) is needed at all. This doesn't cover a flaw on the vendor's side, as OPTIMJACK was; TP5 and TP6 do | Anyone outside the web team can publish code, or no audit trail: **Medium**, **High** on logged-in or checkout pages |

Read-only, in the codebase:

```bash
# External scripts and tag managers, and where they load
rg -n --glob '!node_modules' -e '<script[^>]+src="https?://' -e 'next/script' \
  -e 'googletagmanager|gtag\(|segment|debugbear|hotjar|fullstory|logrocket|intercom|posthog' \
  -e 'optimizely|kissmetrics|storifyme|minute-ly' .
# Inside a saved copy of a vendor snippet: obfuscated loaders, not only the IoC domain (TP6)
rg -n -e 'atob\(' -e 'eval\(' -e 'createElement\(.script' <saved-snippet>.js
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

TP7 is a dashboard review, not a grep: read the vendor's user and role list, SSO settings, API tokens and audit log with
the account owner. On payment pages, TP1 and TP6 are also the PCI DSS v4.0.1 6.4.3 and 11.6.1 evidence (`pci-audit`
Req 6 and Req 11). If a script vendor you load is breached, `incident-triage`
`references/vendor-breach-notice.md` covers the customer side.

## Framing

The sources describe what happened. Step-up for sensitive actions, self-hosting or removing vendor scripts on
logged-in pages, narrowing CSP per page, hash monitoring, comparing against archived copies and the TP7 dashboard
review are **our recommendations**, not claims the sources make. Report URI's own checklist does say to audit write
access to the Optimizely account, deploy a CSP with a restricted `connect-src`, and avoid `'unsafe-eval'` where
possible. Say which is which in the report.

## Sources

- [BleepingComputer, 2026-10-29](https://www.bleepingcomputer.com/news/security/polymarket-halts-trading-after-crypto-draining-script-breach-25m-traced/)
- [Ohey, 2026-10-29](https://ohey.ca/research/polymarket-debugbear-wallet-drainer/)
- [SecurityWeek, 2026-10-30](https://www.securityweek.com/2-million-drained-from-polymarket-traders-in-new-supply-chain-attack/)
- MDN: [Subresource Integrity](https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity),
  [CSP `connect-src`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/connect-src)
- [Report URI (Scott Helme), 2026-11-16, updated 2026-11-17](https://blog.report-uri.com/worlds-largest-brands-infected-with-malware-via-optimizely/)
- [StepSecurity, 2026-11-17](https://www.stepsecurity.io/blog/optimjack-optimizely-hosted-scripts-crypto-clipper-card-skimmer)
- [InfoStealers / Hudson Rock](https://www.infostealers.com/article/poisoned-scripts-on-bbc-zoom-and-other-major-websites-linked-to-iphone-exploit-loaders/)
- [Optimizely status page, "Web Experimentation Security Incident"](https://status.optimizely.com/incidents/ftw0fh9wx43z)
- Proposed by @coreyhaines31 in issues #243 and #297
