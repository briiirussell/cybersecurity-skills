---
name: vuln-research
description: "Research a specific CVE or vulnerability disclosure end-to-end — what version is affected, is your code reachable, is there a public PoC, is there a patch, what's the exposure window, what's the mitigation if you can't patch immediately. Use when the user mentions 'CVE,' 'vulnerability research,' 'is this CVE relevant,' 'zero-day,' 'CISA KEV,' 'GitHub Security Advisory,' 'reachability analysis,' 'patch analysis,' 'exploit availability,' 'EPSS,' 'CVSS,' or 'should we drop everything and patch this.'"
allowed-tools: Read, Grep, Glob, Bash, WebSearch, WebFetch
---

# Vuln Research — CVE Deep-Dive and Applicability Assessment

When a CVE drops, the question isn't "do we have this package?" — `dependency-audit` answers that. The questions are:

- Is the vulnerable code path actually invoked in our usage?
- Is there a public proof-of-concept making this easy to exploit?
- Is there a patch? When? What's our exposure window if we can't deploy in 24 hours?
- If we can't patch, what's the mitigation?
- Is CISA tracking it as actively exploited?

This skill walks that workflow end-to-end. Pairs with `dependency-audit` (which surfaces the CVE in the first place) and `finding-triage` (which closes the disposition loop).

## Workflow

### Step 1 — Pull the canonical sources

Start with the authoritative descriptions; everything downstream is summarized or sometimes wrong.

- **NVD record** — `https://nvd.nist.gov/vuln/detail/CVE-YYYY-NNNNN`
- **Vendor advisory** — search the vendor's security page; this is usually the most accurate description of which versions are affected and what the fix is
- **GitHub Security Advisory** — `https://github.com/advisories/GHSA-...` (often more concise than NVD, sometimes has detail NVD lacks; check the parent project's security tab)
- **CISA Known Exploited Vulnerabilities catalog** — `https://www.cisa.gov/known-exploited-vulnerabilities-catalog`. If the CVE is here, treat as actively exploited — patch within CISA's stated due date
- **EPSS score** — `https://www.first.org/epss/` — Exploit Prediction Scoring System; a 30-day probability of exploitation. Useful tiebreaker between high-CVSS-low-EPSS vs medium-CVSS-high-EPSS

### Step 2 — Confirm affected versions

Vendor advisories sometimes hedge ("affects versions before X"); pin down the exact range.

- Check the vendor's release notes and the commit history of the fix
- For OSS projects: find the patch commit (usually mentioned in the advisory) and run `git tag --contains <commit>` to see which releases include the fix
- For closed-source: the advisory is the only source — verify version comparisons carefully (semver isn't always observed)
- For monorepos / re-publishers: confirm the same fix landed in any forks or distributions you depend on

### Step 3 — Map to your environment

```bash
# Is the package installed at all?
npm ls <package>           # or yarn why <package>, pnpm why <package>
pip show <package>          # or pip list | grep <package>
bundle info <gem>
go list -m all | grep <package>

# What version exactly?
# Inspect lockfiles directly — the resolved version is what runs, not the range
grep -A1 '"<package>"' package-lock.json

# Where is it used?
# Direct dependency, transitive, dev-only?
npm ls <package> --omit=dev  # production-reachable?
```

If transitive, walk up the dependency tree until you find which direct dependency is pulling it in. That's where the override / pin / replacement lives.

### Step 4 — Reachability analysis (the high-leverage step)

A CVE is only exploitable if you actually call the vulnerable code path. This is where dependency-audit's noise gets cut down to real risk.

**Read the patch.** The fix commit shows exactly which function / file / API was vulnerable. Then:

```bash
# Does your code call the vulnerable function directly?
grep -rn "vulnerableFunction\|VulnerableClass" . \
  --include="*.{js,ts,py,rb,go,java}" \
  --exclude-dir=node_modules

# Does the dependency call it internally even if you don't?
# Trickier — you have to read the parent's source. For an indirect call:
cd node_modules/<package>
grep -rn "vulnerableFunction" .
```

**Common reachability outcomes:**

- **Reachable, direct:** You call the bad code. Highest priority — patch or workaround now
- **Reachable, indirect:** Your dependency calls the bad code as part of normal use. Still high priority
- **Not reachable:** The bad code is in a feature you don't use (different module, different entry point, different runtime). Lower priority; still recommend patching but won't break SLA
- **Unknown:** Document as unknown and patch on the cautious side

Don't write "not reachable" without showing the work. Future-you will want to revisit when usage changes.

### Step 5 — Check for public PoCs and active exploitation

- **GitHub:** search for `CVE-YYYY-NNNNN` in code and repos — PoCs land here within days of disclosure
- **CISA KEV:** if listed, it's actively exploited in the wild
- **Exploit-DB:** `https://www.exploit-db.com/` — confirmed exploits
- **Vendor's security mailing list:** sometimes the most recent intel
- **GreyNoise:** `https://www.greynoise.io/` — internet-wide scanning telemetry; if attackers are mass-scanning for this, your exposure window is now
- **Twitter / Mastodon security circles** — for breaking intel, but verify against canonical sources before acting

**EPSS interpretation:**

| EPSS score | Meaning |
|---|---|
| > 0.7 | High probability of exploitation in next 30 days — treat as urgent |
| 0.1 – 0.7 | Meaningful exploitation likelihood — patch on regular cadence |
| < 0.1 | Low predicted exploitation — patch when convenient |

EPSS is empirically tuned; it correlates better with actual exploitation than CVSS does.

### Step 6 — Patch / mitigate / accept-risk

**Patch (preferred):**
- If a patched version exists and you can deploy quickly — upgrade the package, run tests, deploy
- For transitive deps without a direct patch, use `overrides` (npm) / `resolutions` (yarn) / `pin` to force the patched version

**Mitigate (when you can't patch):**
- Disable the affected feature if your code doesn't need it
- Add a request-level filter (WAF rule, proxy filter) that blocks the known-malicious input pattern — for exploitation that goes through HTTP, this is often deployable in hours
- Network-segment the vulnerable service so it can't be reached from untrusted networks
- Add detection (see `siem-detection`) so you'll see exploitation attempts even if mitigations fail

**Accept risk (only when truly justified):**
- Code path is genuinely unreachable in your usage
- Vulnerable component is in an internal-only service with no untrusted input
- Compensating controls reduce exploitation likelihood / impact enough to justify
- See the Accepted Risk disposition in `owasp-audit`'s Report Format — three required fields (why, compensating controls, re-evaluation trigger). No exceptions.

### Step 7 — Document and close the loop

After deciding:

- Record the decision in your vuln-tracking system (Jira, Linear, Vanta, etc.)
- For accept-risk: set a re-evaluation date and a calendar reminder
- For patches: confirm via `npm ls` / lockfile that the patched version is actually deployed (rollouts are not the same as decisions)
- For mitigations: write a runbook entry so the next person knows the mitigation exists and why

## Common research traps

- **The advisory says "fixed in vX" but the package never released vX** — happens with abandoned projects. Use `overrides` to a known-good fork, or replace the dependency
- **The vendor patched it silently** — fix landed before the CVE; advisory is for the version before the silent fix. Verify the fix commit is in your version
- **The CVE applies to a sibling package you also have** — same code, different name (forks, monorepo siblings). Search every package you have for the vulnerable function, not just the named one
- **The CVSS is high but the EPSS is low** — usually means complex preconditions in the wild. Patch but don't panic
- **The CVSS is medium but the EPSS is high** — usually means it's already being exploited in mass scans. Treat as urgent
- **The PoC needs auth that's hard to get** — but your application makes that auth easy to get (signup is open). The "complexity" attacker rating doesn't account for *your* threat model

## Output Format

```markdown
# Vulnerability Assessment: CVE-YYYY-NNNNN
## Date: [date]
## Assessor: [name]

### Summary
- **Title:** [from advisory]
- **CVSS / EPSS:** [scores]
- **CISA KEV:** [yes / no, and due date if listed]
- **Affected versions:** [exact range]
- **Our version:** [version + how installed]

### Reachability
- **Direct call:** [yes / no — with evidence]
- **Indirect via dependency:** [yes / no — with evidence]
- **Verdict:** Reachable / Not reachable / Unknown

### Exploitation availability
- **Public PoC:** [yes / no — link]
- **Active exploitation:** [yes / no — source]

### Decision
- [ ] Patch (target deploy: [date])
- [ ] Mitigate (controls: [list]; re-evaluate: [date])
- [ ] Accept risk (why / compensating controls / re-eval trigger)

### Action items
| Item | Owner | Deadline |
|------|-------|----------|

### References
[Links to advisory, patch commit, PoC, EPSS, CISA, etc.]
```

## Boundaries

- Research vulnerabilities affecting code, dependencies, or systems the user has authorization for
- Do not develop, weaponize, or distribute exploits — read existing PoCs only for the purpose of assessing applicability
- For internal-only vulnerabilities or pre-disclosure intel, do not redistribute without authorization
- If research surfaces an unreported vulnerability in someone else's code, follow responsible disclosure — do not publish, do not exploit
- Refuse requests to use CVE research output to attack systems

## References

- NVD (National Vulnerability Database)
- CISA Known Exploited Vulnerabilities Catalog
- GitHub Security Advisories Database
- EPSS (Exploit Prediction Scoring System) — FIRST.org
- MITRE CVE — `cve.mitre.org` (now redirects to `cve.org`)
- Exploit-DB
- GreyNoise — internet scanning telemetry
- "Patch Tuesday" / vendor-specific cadences for context on disclosure timing
- Project Zero disclosure policy — the reference for responsible disclosure timelines
