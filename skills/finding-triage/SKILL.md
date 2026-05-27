---
name: finding-triage
description: "Triage a single security finding — from a scanner, audit, advisory, or report — to a defensible disposition with a mitigation plan, false-positive justification, or accepted-risk writeup. Use when the user mentions 'triage this finding,' 'is this a real vulnerability,' 'mitigation plan,' 'false positive,' 'accept this risk,' 'compensating controls,' 'risk justification,' 'security ticket,' 'CVSS this,' 'should we fix this,' 'disposition,' 'sign off on,' or has a single security finding and needs to decide what to do."
allowed-tools: Read, Grep, Glob, Bash, WebSearch
---

# Finding Triage — Single-Finding Disposition with Defensible Justification

Every other skill in this repo *generates* findings. This skill *closes the loop* — for a single finding, walk through whether it's real, what severity it deserves in your context, and what to do about it. Output is a complete ticket-ready writeup with the right fields, the right justification, and an audit trail that survives a regulator reading it six months later.

The dispositions match `owasp-audit`'s Three-Disposition rule: **Fixed**, **Deferred**, or **Accepted Risk**. False positive is a fourth — but it isn't a disposition for a real finding, it's a determination that there *is* no finding.

This skill works on findings from any source: SAST output, DAST scanner, dependency advisory, manual audit, threat-hunt hit, pentest report, vendor disclosure, internal red-team writeup, bug bounty submission.

Cross-references:
- `vuln-research` for the technical CVE deep-dive that feeds reachability assessment here
- `owasp-audit` Three-Disposition rule (the framework this implements per-finding)
- `security-comms` for translating the disposition writeup into stakeholder-readable language when the finding has to leave the security context
- Any audit skill — this consumes their findings as input

## Workflow

The agent works through these steps with the user. Stop and ask clarifying questions where the user has context the finding alone doesn't reveal.

### Step 1 — Restate the finding in your own words

If the finding came from a scanner, restate what's actually being claimed. Scanners produce noise; restating filters out the boilerplate.

A good restatement names:
- **What** the issue is (specific weakness — CWE if applicable)
- **Where** it lives (file:line, endpoint, resource ARN, host)
- **How** it could be exploited (preconditions, attacker capability needed)
- **Impact** if it were exploited (data loss, privilege escalation, availability)

If you can't restate it clearly, you don't understand it yet. Ask the user for context.

### Step 2 — Is this actually true?

Half of automated-scanner findings are false positives by volume. The triage:

| Question | If yes | If no |
|---|---|---|
| Does the vulnerable code path exist as described? | Continue | False positive — scanner found a phantom |
| Is the code path reachable from any attacker-controllable input? | Continue | Continue, but severity drops |
| Does the exploit precondition match your environment? | Continue | Severity drops or false positive |
| Is there a public PoC, or has anyone confirmed this in the wild? | Severity stays / rises | Severity may drop |
| Are existing controls (WAF, auth, network segmentation) preventing exploitation? | Severity drops; controls become the mitigation | Severity stays |

**Common false-positive patterns:**
- SAST flag on test files or dead code
- Dependency scanner flag on package in `devDependencies` only — runtime-unreachable (see `dependency-audit` reachability column)
- DAST flag on a path that returns 404 in your real environment but was confused by SPA routing
- Outdated advisory — vendor silently fixed it before the CVE; your version contains the fix
- Pattern match on code that *looks* vulnerable but is inside a function never invoked

**Document a false-positive determination as carefully as a real finding.** If a future scanner or auditor flags the same thing, the prior false-positive note saves them the work.

### Step 3 — Contextual severity

The scanner's CVSS or severity rating is a starting point, not the answer. Adjust for your context.

**Factors that increase severity beyond the rating:**
- Vulnerable endpoint is internet-facing, not internal
- Authentication preconditions are easy to satisfy (open signup) in your app, even if the CVE assumes "authenticated"
- Vulnerable data is regulated (PII, PCI cardholder data, PHI) — exploitation has reportable-incident consequences
- Public PoC exists or active exploitation observed
- Vulnerable component is in the critical path (every request touches it)
- Compensating controls are missing or weak

**Factors that decrease severity below the rating:**
- Vulnerable code path is unreachable in your usage (read the patch, grep for the function — see `vuln-research`)
- Strong compensating controls (WAF blocks the payload pattern, network segmentation prevents reach)
- Exploit requires preconditions that don't exist in your environment (specific OS version, specific config)
- Authentication preconditions are hard in your app (closed signup, MFA, employee-only)
- Component is dev-only or build-only, not runtime-reachable

**Severity scale (use the one your org uses; here's a common one):**

| Level | Definition |
|---|---|
| **Critical** | Pre-auth or trivially exploitable; immediate data loss / RCE / takeover; patch within 24-72 hours |
| **High** | Auth required but minimal privilege; or post-auth path to significant impact; patch within 1-2 weeks |
| **Medium** | Requires meaningful privilege or chain; realistic but not trivial; patch within 30 days |
| **Low** | Defense-in-depth; hard to chain; patch within 90 days |
| **Info** | Hardening or hygiene; documented behavior; patch when convenient |

### Step 4 — Pick the disposition

| Disposition | When to choose | Required fields |
|---|---|---|
| **Fix now** (synonym: **Fixed**) | Patch / mitigation deployable within the severity's SLA | Fix description, deploy plan, verification method |
| **Defer** | Severity warrants action, but operational constraints make immediate fix infeasible | Reason for deferral, new deadline, who owns, alerting if conditions change before deadline |
| **Accept risk** | Fix isn't planned at current configuration | (1) Why fix doesn't apply, (2) Compensating controls, (3) Re-evaluation trigger |
| **False positive** | Not actually a vulnerability | Evidence for the determination, scanner rule ID to suppress (with care) |

**On Defer:** severity does NOT change because you decided to defer. Recording a "High deferred to Q3" is honest; downgrading a High to Medium because Q3 is far away is risk-laundering.

**On Accept Risk:** all three fields are required. An "Accepted Risk" without all three is a real finding being silently dropped. The re-evaluation trigger is the most-skipped field — name a specific condition (plan upgrade, dependency bump, traffic pattern change, audit anniversary).

### Step 5 — Write the disposition

Produce a ticket-ready writeup. Use one of these templates depending on disposition.

#### Template: Fix

```markdown
## Finding: [Title]
**Source:** [scanner / audit / advisory]
**Severity:** [contextual] (Scanner reported: [original])
**CWE / CVE:** [if applicable]
**Location:** [file:line / endpoint / resource]

### What
[Plain-English description — what the issue is]

### Why this severity
[Contextual reasoning — what the scanner missed, what your environment adds]

### Fix
[Specific change — code diff, config update, dependency upgrade]

### Verification
[Concrete test — adversarial input + observed result that proves the fix holds]
- Run [command / test case]
- Observe [response / behavior]

### Owner: [name]
### Target deploy: [date]
```

#### Template: Defer

```markdown
## Finding: [Title] — DEFERRED
**Severity:** [unchanged]
**Original target:** [original SLA date]
**New target:** [date]

### Why deferred
[Operational constraint — release freeze, dependency on third party, etc.]

### Risk during deferral window
[What's the exposure? What controls reduce it?]

### Alerting / conditions that would escalate
[What would force action sooner than the new target?]

### Owner: [name]
### Re-evaluation: [date — usually before new target]
```

#### Template: Accept Risk

```markdown
## Finding: [Title] — ACCEPTED RISK
**Severity:** [contextual]
**Approver:** [name + role]
**Date accepted:** [date]

### Why fix doesn't apply
[Cost tier, dependency version constraint, deployment topology, vendor limitation, etc. — be specific]

### Compensating controls
- [Control 1 — what it is, why it reduces impact / likelihood]
- [Control 2]
- ...

### Re-evaluation trigger
[Specific condition — plan upgrade, dependency bump, traffic pattern change, calendar anniversary]
- Trigger: [what would change this decision]
- Calendar review: [date — at minimum, annually]

### Approvals
- [ ] Engineering owner: [name, date]
- [ ] Security: [name, date]
- [ ] (if required) Compliance / Legal: [name, date]
```

#### Template: False Positive

```markdown
## Finding: [Title] — FALSE POSITIVE
**Scanner:** [name + rule ID]
**Original severity:** [as reported]

### What the scanner claimed
[Restate the claim]

### Why it's not real
[Specific evidence — code path not reachable, version contains the fix, etc.]

### Suppression decision
- [ ] Suppress this exact finding (location + rule ID)
- [ ] Add allow-list rule (with care — broad suppression breeds blind spots)
- [ ] No suppression — re-evaluate if it returns

### Determination by: [name, date]
### Reviewed by: [name, date — for non-trivial suppressions]
```

### Step 6 — Validate the writeup

Before submitting:

- Could a future you (or auditor) reading this in 12 months understand the decision without further context?
- Is the verification step concrete enough that someone other than the original author could run it?
- For Accept Risk: are all three required fields filled in with specifics, not platitudes ("standard controls in place" is not a compensating control)?
- Does the severity reflect your environment, or just the scanner's default?

## When to escalate

Findings that should NOT be triaged unilaterally by a single engineer:

- Anything Critical
- Anything pre-auth exploitable
- Anything affecting regulated data (PII / PCI / PHI)
- Anything with public PoC or active exploitation
- Anything where the proposed disposition is Accept Risk and the severity is High or above

These get a second reviewer (Tier 3 / security team / approver named in policy).

## Output Format

The primary output is the disposition writeup itself (templates above). For a triage session that covers multiple findings or a batch import, summarize:

```markdown
# Finding Triage Session
## Source: [scanner / audit / report]
## Date: [date]
## Triaged by: [name]

### Summary
| Finding | Original severity | Contextual severity | Disposition |
|---------|-------------------|---------------------|-------------|

### Detail
[Per-finding writeup using the appropriate template]

### Escalations
[Findings that need senior review or approval]
```

## Boundaries

- This skill operates on findings the user has authority to triage and dispose of
- Severity decisions and Accept Risk dispositions affect organizational risk posture — for High+ findings, ensure the listed approver actually approves; don't fabricate sign-offs
- False-positive determinations should be evidence-based, not "we don't want to fix it" rebranded — push back if the user wants to FP a real finding
- Refuse to help downgrade severities to avoid disclosure or audit obligations
- If a finding surfaces an active incident, hand off to `incident-triage` — disposition triage is for steady-state findings, not fires

## References

- CVSS v4.0 specification — `first.org/cvss`
- EPSS — Exploit Prediction Scoring System (FIRST.org)
- NIST SP 800-30 (Guide for Conducting Risk Assessments)
- "FAIR" (Factor Analysis of Information Risk) — quantitative risk framework if you need dollar-denominated decisions
- ISO 27005 — risk management
- "Measuring and Managing Information Risk" — Jack Freund, Jack Jones (the FAIR book)
- OWASP Risk Rating Methodology
