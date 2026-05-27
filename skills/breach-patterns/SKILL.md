---
name: breach-patterns
description: "Learn from public breach disclosures — extract the audit question each one implies and check your own stack. Capital One IMDS abuse, LastPass vault exfiltration, Okta Lapsus$, Snowflake credential reuse, MOVEit, SolarWinds, Equifax, Target POS, Codecov, Uber, Twilio — what would you check now if your boss said 'could that happen to us?' Use when the user mentions 'breach analysis,' 'lessons learned,' 'security postmortem,' 'breach patterns,' 'breach lessons,' 'has this happened to us,' 'apply breach lessons,' 'preempt breaches,' 'security retrospective,' 'real-world security incidents,' or wants to harden against known attacker playbooks."
allowed-tools: Read, Grep, Glob, Bash, WebSearch, WebFetch
---

# Breach Patterns — Preemptive Hardening from Public Breach Disclosures

The inverse of `incident-triage`. That skill is "we're on fire, what now." This skill is "go read the breach writeups, extract the audit question each one implies, and check your own stack."

Breaches catalogued here are public, well-documented, and pattern-bearing. Each pattern surfaces a control or check that often falls between OWASP categories — IMDS abuse, supplier credential blast radius, secrets-in-CI, single-sign-on lateral movement, log-tampering pre-breach. These are the controls people add *after* their first incident; reading other people's breaches is cheaper than writing your own.

Cross-references: every audit skill in this repo. Use this skill to surface "have we considered X?" questions, then pivot to the relevant audit skill for the deep dive. When a breach pattern surfaces a regulatory implication — health data exposure, payment card data exposure, PII exposure — also reach for `hipaa-audit`, `pci-audit`, or `privacy-engineering` to understand the regulatory clock and notification obligations that come with that breach class.

## How to use this skill

For each breach pattern below:

1. **Read** the one-paragraph summary of the breach
2. **Ask** the audit question(s) it implies for your environment
3. **Map** to specific checks in the existing audit skills
4. **Decide** disposition — "we've confirmed this can't happen," "we have a gap, here's the plan," or "we accept-risk for these reasons"

The output is a "breach-pattern coverage" document — not a fixed report, an evergreen checklist you re-run against your evolving stack.

## Pattern 1 — IMDS abuse (Capital One, 2019)

**What happened:** A misconfigured WAF allowed SSRF. An attacker used SSRF to reach the EC2 instance metadata service (IMDSv1, no token requirement), pulled temporary IAM credentials, and used them to enumerate and exfiltrate S3 buckets containing 100M+ records.

**Audit question:** Does any service that takes a URL from user input also have IAM credentials reachable via IMDS?

**Check:**
- IMDSv2 enforced on every EC2 launch template (`MetadataOptions.HttpTokens: required`) — see `cloud-audit`
- SSRF defences on every URL-taking endpoint — see `owasp-audit` A10 bypass matrix (especially the cloud metadata endpoints row: `169.254.169.254`, `metadata.google.internal`, `169.254.170.2`)
- WAF rules log + alert on metadata-endpoint patterns

## Pattern 2 — Supplier credential blast radius (SolarWinds, 2020)

**What happened:** Attackers compromised SolarWinds' build pipeline and inserted a backdoor (Sunburst) into the Orion product. Customers who installed legitimate Orion updates received the backdoored binary. The backdoor enabled lateral movement into customer networks, including the US federal government.

**Audit questions:**
- Which suppliers have credentials in your environment that could similarly compromise you if the supplier was breached?
- Do your CI / CD systems have credentials that could move laterally into prod?
- Are software updates verified against signatures, or trusted by source URL?

**Check:**
- CI/CD secrets minimized to scope (read-only deploy tokens, not full admin)
- Signed commit / signed artifact enforcement where critical
- Third-party JavaScript pinned to specific versions or SHA-pinned via SRI
- Vendor-managed services audited for blast radius — see `iam-audit` for cross-account trust patterns

## Pattern 3 — Vault exfiltration via developer endpoint (LastPass, 2022)

**What happened:** Attackers initially compromised an engineer's home computer via a vulnerable third-party media plugin. That gave them access to the engineer's corporate vault. Months later, they used that access to exfiltrate customer vault data — including unencrypted URLs that helped target customers for phishing.

**Audit questions:**
- Which engineering accounts can reach production data, and what device posture is required?
- Are device security policies enforced for personal devices used to access corporate systems?
- What metadata is stored unencrypted around encrypted user data?

**Check:**
- Device-trust requirements for any high-value access (Zero Trust posture — see `iam-audit`)
- Privileged access through dedicated workstations / jump hosts, not engineer personal laptops
- Encrypt the metadata too, not just the "important" payload — URLs are PII

## Pattern 4 — SSO push fatigue (Okta / Lapsus$, 2022)

**What happened:** Attackers obtained credentials for a third-party support engineer (Sitel). They spammed the engineer with push-notification MFA prompts until the engineer approved one out of habit / annoyance. They then used the support engineer's access to view (but not modify) some Okta customer tenants.

**Audit questions:**
- Is MFA on your admin accounts phishing-resistant (FIDO2 / hardware key), or just push?
- Are third-party support / contractor accounts treated with the same controls as employees?
- What's the blast radius of a support / customer-success role being compromised?

**Check:**
- Phishing-resistant MFA (FIDO2 / WebAuthn) for admins and privileged users — see `iam-audit`
- "Number matching" enabled on push MFA (where allowed) so users can't approve blindly
- Push-fatigue detection — repeated push prompts in a short window trigger an alert
- Third-party access reviewed quarterly with same rigor as employee access

## Pattern 5 — Stolen credentials → SaaS lateral movement (Snowflake customers, 2024)

**What happened:** Attackers used credentials stolen from infostealer malware on personal devices to log into Snowflake customer environments (which had no MFA enforced). They exfiltrated data from Ticketmaster, AT&T, Santander, and others. Snowflake itself wasn't breached — customers were.

**Audit questions:**
- Are there SaaS services in your stack where users can authenticate without MFA?
- Is access to SaaS gated on enterprise SSO with MFA enforcement, or are local accounts allowed?
- Could credentials stolen from a personal device unlock your business-critical SaaS?

**Check:**
- Every SaaS in your environment audited for MFA enforcement and SSO federation
- Local-account access disabled where SSO is available
- Conditional Access policies require compliant device — see `iam-audit`
- Credential monitoring (HIBP, internal dark-web monitoring) for employee emails

## Pattern 6 — Unpatched zero-day in file transfer (MOVEit, 2023)

**What happened:** Cl0p ransomware group exploited an SQL injection zero-day (CVE-2023-34362) in Progress MOVEit Transfer. They exfiltrated data from hundreds of customers — many of whom were transferring sensitive HR / financial / health data via MOVEit. Patches arrived after the exploitation campaign was already running.

**Audit questions:**
- For internet-facing third-party software in your environment, what's your patch SLA when a zero-day surfaces?
- What sensitive data sits in pre-built / off-the-shelf software you don't control the code of?
- Do you have detection for unusual data egress from third-party systems?

**Check:**
- Inventory of internet-facing third-party software, owners, patch process
- Network egress monitoring on third-party systems (see `siem-detection`)
- CISA KEV monitoring — automatic alerting when listed CVEs apply to your stack (see `vuln-research`)
- Data classification — sensitive data minimized in third-party platforms

## Pattern 7 — Compromised CI build artifact (Codecov, 2021)

**What happened:** A flaw in Codecov's Docker image creation process let attackers extract a credential. They modified Codecov's Bash uploader script to exfiltrate environment variables from every CI run using Codecov. CI environments leak: AWS keys, Stripe keys, npm tokens, GitHub tokens.

**Audit questions:**
- What third-party tools run inside your CI with access to env vars?
- Are CI env vars scoped to just what each job needs, or do all jobs see everything?
- Would you notice if a CI step started phoning home?

**Check:**
- CI secrets scoped per-job and per-workflow, not global — see `secrets-audit` and `iam-audit`
- Third-party CI integrations reviewed (every uploader, scanner, deployer that has access to env vars)
- CI network egress monitored where feasible
- Build artifact provenance — SLSA framework, signed builds, sigstore

## Pattern 8 — Insider access misuse (Twitter / X internal tool abuse, 2020)

**What happened:** Attackers social-engineered Twitter employees to access an internal admin tool with broad customer-account powers. They used it to hijack high-profile accounts and run a Bitcoin scam.

**Audit questions:**
- Which employees have access to powerful internal admin tools?
- Is access logged and reviewed?
- Could one employee take a high-impact action without a second party?

**Check:**
- Internal admin tooling treated as high-trust — strong auth, JIT access, audit log
- Two-person rule for sensitive actions (account takeover, mass data export)
- Quarterly review of who has admin tool access — see `iam-audit`
- Honeypot accounts that alert on access

## Pattern 9 — Long-standing breach undetected (Equifax, 2017)

**What happened:** Attackers exploited unpatched Apache Struts CVE-2017-5638 (a known vulnerability with a 2-month-old patch available). They were inside for 76 days before detection, exfiltrating 147M credit records. Patch had been available; vulnerability scanning didn't find it because scan target lists were stale.

**Audit questions:**
- How long would it take you to detect an attacker with valid credentials sitting in your environment?
- Is your patch SLA enforced in practice, or only on paper?
- Does your vuln-scan inventory match your actual asset inventory?

**Check:**
- Asset inventory cross-checked against vuln-scan targets quarterly
- Patch SLA per severity is measured, not just stated (`vuln-research`)
- Detection coverage for post-exploitation behavior (lateral movement, data staging, exfil) — see `siem-detection`
- MTTD (Mean Time To Detect) measured for representative scenarios

## Pattern 10 — Cookie / token theft → MFA bypass (Uber breach via contractor, 2022)

**What happened:** Attackers compromised a contractor's credentials, used MFA-prompt-fatigue to get in, and then explored. They found PowerShell scripts on a network share containing privileged credentials, and from there accessed AWS, GCP, Google Workspace, and Slack. Among the goodies: a Privileged Access Management tool that the attackers could use to grant themselves more access.

**Audit questions:**
- What credentials are sitting on network shares?
- If an attacker got to your network share, what would they find?
- What's the blast radius of contractor accounts?

**Check:**
- Credential discovery scan on every internal file share, wiki, ticketing system — see `secrets-audit`
- Contractor accounts subject to same MFA and review as employees
- Privileged Access Management (PAM) systems themselves audited as crown-jewel assets

## Patterns to add (your job)

This skill should grow with each major public breach. Process:

1. Read the post-mortem (vendor, news writeup, regulatory filing)
2. Extract the **one-sentence pattern** that generalizes beyond the specific vendor
3. Phrase it as an audit question your stack should be able to answer "no" to
4. Map to specific checks in existing audit skills
5. Add to this skill

Good post-mortem sources:
- Vendor security blogs (the breached company's own writeup is usually most accurate)
- SEC 8-K filings for public companies (legal-grade detail)
- "BleepingComputer," "Risky.Biz News," "Krebs on Security" — solid breach coverage
- The Verizon DBIR (annual) — patterns across the year aggregated
- The MITRE ATT&CK in the wild reports

## Output Format

```markdown
# Breach Pattern Coverage Assessment
## Environment: [name]
## Date: [date]

### Coverage status
| Pattern | Audit question | Status | Owner |
|---------|----------------|--------|-------|
| IMDS abuse (Capital One) | SSRF-to-metadata reachable? | Clean | sec |
| Supplier blast radius (SolarWinds) | CI/CD blast radius? | Gap — plan attached | platform |
| ... | | | |

### Gaps with plans
[For each Gap row above — what's the plan, by when]

### Patterns not yet evaluated
[Patterns where you don't yet have data to mark Clean / Gap]
```

This is a quarterly-rerunable document — not one-and-done. Industry patterns evolve.

## Boundaries

- This skill is preemptive ("does this happen to us?"), not exploitive ("could we do what Lapsus$ did")
- Public breach details are public; use them. Do not seek leaked credential dumps or non-public details
- If your assessment surfaces an active issue (not "could happen" but "is happening"), pivot to `incident-triage`
- Do not generate attack patterns or detailed attacker playbooks beyond what's necessary to assess defensive coverage

## References

- "Cyber Incident Reporting and Analysis Methods" — DHS / CISA
- Verizon Data Breach Investigations Report (DBIR) — annual industry breach analysis
- MITRE ATT&CK in the wild reports
- CISA cybersecurity advisories
- Krebs on Security (krebsonsecurity.com)
- "Risky.Biz" news podcast / newsletter
- Project Zero — Google's offensive security team writeups
- Mandiant / CrowdStrike threat reports
- "Tracing Stolen Bitcoin" — investigative writeups on attacker workflows
