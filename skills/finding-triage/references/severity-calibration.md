# Severity calibration

How to decide whether something is a finding at all, and if it is, how severe it is. Every skill that rates findings uses this file. The short version: **name the boundary and the result, cap severity at the impact you showed, and keep hardening notes out of the findings list.**

This applies to `confirmed` findings only. `needs_validation` items carry blockers and a plan instead of a severity, and `rejected` items carry the control that rules them out (see `findings-format.md` where it ships alongside this file).

## 1. The boundary + result gate

Before a candidate becomes a finding, write down all six of these. Each one has to be concrete, not "an attacker".

| # | Element | Example |
|---|---|---|
| 1 | **Lower-trust principal**: who starts the attack | Any signed-up user; an unauthenticated internet client; tenant B's admin |
| 2 | **Accepted input**: what they control, and where it enters | The `:id` path segment of `POST /orders/:id/refund` |
| 3 | **Intended control**: what is supposed to stop them | The ownership check that `GET /orders/:id` already performs |
| 4 | **Boundary crossed**: which trust line the input gets across | User A → user B's data |
| 5 | **Affected principal or resource**: who or what gets hurt | Another customer's payment |
| 6 | **Concrete result**: what you observed, or what the traced code does | A refund is issued against an order the caller doesn't own |

If one element is missing:

- **No crossed boundary, or the "victim" is the attacker themselves** (self-XSS, editing your own profile in a weird way, admin doing admin things): it's a hardening note, or nothing.
- **No intended control** that the result defeats: it's a hardening note. A checklist deviation is not a vulnerability by itself.
- **The result depends on a fact outside the code** (proxy rule, IdP setting, deploy flag): it's `needs_validation`, with that fact as the blocker.
- **No concrete result**, only "this could be dangerous": keep tracing, or drop it.

## 2. Likelihood × impact, and overall ≤ impact

Rate likelihood and impact separately, each with a one-line reason, then pick an overall.

**Overall may never exceed demonstrated impact.** High likelihood of a low-impact bug is a low finding. If you can't state the concrete damage, the severity is lower than it feels.

### Severity anchors

| Level | Anchor | Typical shape |
|---|---|---|
| **Critical** | Fully defeats a core control with broad, severe consequences and little or no precondition | Pre-auth RCE; auth bypass to any account; cross-tenant read/write of all data; leaked production secret with write authority |
| **High** | **Fully defeats an explicit security control, with real consequences** | IDOR that reads or changes another user's data; privilege escalation to admin; stored XSS that runs in other users' sessions on a sensitive origin; SSRF to cloud metadata credentials |
| **Medium** | **Weakens a control** without fully defeating it, or fully defeats one with limited consequences | Rate limit bypassable only partly; data leak limited to non-sensitive fields; CSRF on a low-value state change; reflected XSS needing unusual interaction |
| **Low** | A real boundary crossing with minor consequences, or one that needs unlikely preconditions | User enumeration with no follow-on; information disclosure of internal hostnames; open redirect that does nothing more on its own |

Low is a finding: something crossed a boundary. **Defense-in-depth is not Low.** It's a hardening note (section 5).

### Availability

The anchors above are written for confidentiality and integrity. For a crash or hang an attacker can cause:

| Level | Shape |
|---|---|
| **High** | One unauthenticated request, or a handful, takes down the whole service or keeps it down: an uncaught exception that kills a single-process server, a ReDoS or `qs`-style parser hang on the main event loop, unbounded memory growth until the process is killed |
| **Medium** | The same, but it needs an account, only hits one worker of several, or the platform restarts it within seconds so the attacker has to keep sending |
| **Low** | It only slows or fails the attacker's own request, or needs volumes that rate limits or the platform already absorb |

Volumetric floods (DDoS) are out of scope for code review. Note the edge protection in the report instead. "Restarts
automatically" lowers likelihood and duration, not the fact that the request crashed it. Keep the restart behaviour
as a `system_configuration` condition, or as a blocker when you can't see it.

The question that separates High from Medium: *does the attack fully defeat the control, and does that cause damage you can name?* If both, High is on the table. If the control is only weakened, or the damage is vague, it's Medium or lower.

## 3. Usually NOT High or Critical

These get over-rated habitually. Rate them High or Critical only when you've traced a specific, severe consequence:

- **Self-XSS**: the only victim is the person typing.
- **Clickjacking** on actions that aren't sensitive.
- **Missing security headers, cookie flags or TLS configuration nits** with no traced exploit path.
- **An open redirect on its own.** It's a phishing aid, not account takeover, until you show the chain.
- **"Could matter if chained"** when the other links are unproven. Rate what you showed, not the hypothetical chain.
- **Anything that already requires admin, shell, or physical access.** Those principals can usually do the damage directly.
- **Session weaknesses that need the attacker to already hold a victim secret** (their cookie, their reset token). Getting that secret is the hard part, and it isn't free.
- **Verbose errors and version banners** without a specific exploitable consequence.
- **Missing rate limiting** where no concrete abuse with real cost has been traced (see below).

### Missing rate limiting

Checklists list rate limiting (OWASP A07, API4), so reviewers find it missing everywhere. Decide it the same way each
time:

- **Finding:** there's no limit in the code on an endpoint where repeated requests do concrete harm. Examples are
  online password guessing against accounts with no lockout, brute-forcing a 6-digit OTP or reset code, and sending
  paid SMS or email, or paid API calls, at the attacker's choice of volume. The intended control is the limit that
  login, OTP and paid-send endpoints are expected to have. Usually Medium, since it weakens authentication rather than
  bypassing it. It's High when the guessable space is small enough to exhaust (a 4- or 6-digit code with no attempt
  limit).
- **`needs_validation`:** the code has no limit, but a gateway, WAF or platform limiter might apply and you can't see
  it. The blocker is that limiter.
- **Hardening note:** endpoints where repetition costs nothing beyond load (search, list, profile reads), or where
  another control already caps the harm (a lockout after N failures).

## 4. High/Critical acceptance checklist

Before you write High or Critical, all six must be true. If any fails, **downgrade rather than delete**: the finding stays, at the level you can defend.

1. **Realistic, in-scope path.** The vulnerable code runs in the deployed product, on a route or job that exists.
2. **Obtainable attacker position.** The principal from the gate can actually get there (open signup counts; "an employee with database access" usually doesn't).
3. **Impact demonstrated, not asserted.** You traced or ran it to the sink and can say what happens there.
4. **Counterevidence found nothing limiting.** The refutation pass looked for the strongest control on the path and didn't find one that stops it.
5. **Concrete reachability evidence.** `file:line` for entrypoint, propagation and sink, or a request/response pair.
6. **Defensible in a debrief.** A skeptical engineer or client would accept the rating after reading the evidence. Anchor test: *would serious triage accept this as High?*

### Missing deployment evidence

When the decisive fact lives in the deployment (is there a WAF? does the proxy strip this header?), that lowers **confidence**, not the severity floor. Either record it as `needs_validation` with the fact as a blocker, or keep the severity you traced and set confidence to `medium` or `low`. Don't quietly mark a traced High as Low because you couldn't see production.

## 5. Hardening notes are not findings

A **hardening note** is a gap with no traced impact: defense in depth, a best-practice deviation, a missing header with no exploit path, a cookie flag that changes nothing reachable.

- If layer A prevents the attack, the absence of layer B is a hardening note.
- Hardening notes **never get a severity** and don't go in `findings.json`.
- They go in a separate report section titled **"Hardening notes (not findings)"**, one line each: what's missing, why it would help, and the effort.
- Headers, cookie flags and CORS settings become findings only when you trace a concrete impact (e.g. a permissive CORS policy that, combined with credentialed requests, lets an attacker origin read a user's data).

Reporting hardening notes separately keeps the findings list credible. A report where half the "Lows" are missing headers trains readers to skip the Lows.

## 6. Keys: publishable vs restricted vs secret

A public identifier called a "key" is not a secret. Before rating an exposed key, find out which kind it is and what it can do:

| Kind | Examples | Rating |
|---|---|---|
| **Publishable** (designed to ship to browsers or apps) | Stripe `pk_live_…`, Firebase web config, Google Maps browser keys, Supabase `anon` key, Sentry DSN | Not a finding by itself. A finding only if its restrictions are missing and that enables real abuse (e.g. an unrestricted Maps key billed to you, or a Supabase `anon` key in front of tables with no row-level security), and then rate that consequence |
| **Restricted** (scoped server key) | Stripe `rk_…`, a read-only API token | Rate by the scope it grants |
| **Secret** (full authority) | Stripe `sk_live_…`, AWS secret access key, Supabase `service_role`, database URL with password | Rate by the authority: production write access is usually High or Critical |

The prefix alone doesn't decide it. `AIza…` is the format of many Google API keys; some are meant to be public and some unlock paid APIs. Check what the key is restricted to before rating.

## 7. Severity vs SLA

Severity describes the bug. The remediation deadline (SLA) is a policy decision your org attaches to a severity. Keep them in separate columns. A deferral changes the deadline, never the severity.

## Sources

Paraphrased and adapted; no text copied.

- Cloudflare, [security-audit-skill](https://github.com/cloudflare/security-audit-skill) (MIT): `SKILL.md` ("Require a boundary and result", "Separate priority from certainty", anti-patterns), `ATTACK-CLASSES.md` (a flag is not a finding), `WEB-PROTOCOL-AND-AUTH.md` (public identifiers vs secrets).
- Strix, [`analysis/severity_calibration.md`](https://github.com/usestrix/strix/blob/main/strix/skills/analysis/severity_calibration.md) and the CVSS block in [`tools/reporting/tool.py`](https://github.com/usestrix/strix/blob/main/strix/tools/reporting/tool.py) (Apache-2.0): over-rating list, High/Critical acceptance checklist, downgrade-rather-than-delete.
- FIRST, [CVSS v4.0](https://www.first.org/cvss/) for teams that need a numeric score alongside this.
