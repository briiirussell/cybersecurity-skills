---
name: soc-operations
description: "Build, run, and improve a Security Operations Center — alert prioritization, runbook authoring, escalation criteria, on-call structure, alert tuning workflow, MTTD / MTTR / fidelity KPIs, analyst tiering, and shift handoffs. Use when the user mentions 'SOC,' 'security operations,' 'SOC analyst,' 'alert triage workflow,' 'runbook,' 'escalation,' 'on-call,' 'SOC tiering,' 'tier 1 / tier 2,' 'MTTD,' 'MTTR,' 'alert fatigue,' 'alert tuning,' 'shift handoff,' 'SOAR,' or wants to design or improve a security operations team."
allowed-tools: Read, Write, Grep, Glob, WebSearch
---

# SOC Operations — Building and Running a Security Operations Center

The operations layer above `siem-detection` (engineering rules) and `incident-triage` (response). This skill is about the *people and process* of running 24/7 alert triage — alert prioritization, runbook authoring, escalation, on-call hygiene, MTTD / MTTR, and the slow drift toward alert fatigue that kills SOCs.

Three modes:
- **Build** — designing a SOC from scratch (small org standing up its first IR capability, or MSSP onboarding)
- **Run** — daily operations for an existing SOC
- **Improve** — analyzing an existing SOC's metrics and fixing the broken parts

Cross-references: `siem-detection` (the rules that feed alerts to the SOC), `incident-triage` (the playbook for confirmed incidents), `threat-hunting` (proactive work between alert triage), `breach-patterns` (what attacks the SOC should be ready for).

## Mode 1 — Build a SOC

### Decision: in-house, MSSP, or hybrid?

| Model | When it fits | Pitfalls |
|---|---|---|
| Fully in-house | Mature security org, ≥ 5 dedicated analysts, regulated industry | Hard to staff 24/7 with under 8 people; on-call burnout |
| Fully outsourced (MSSP) | Smaller orgs, regulated requirements without internal staffing | MSSP context drift — they don't know your business; alert tuning slow |
| Hybrid (MSSP Tier 1, in-house Tier 2+) | Most common for growth-stage companies | Handoff complexity, "MSSP filtered it but didn't tell us" gaps |

### Staffing model

For 24/7 in-house coverage, the math:

- 24 × 7 = 168 hours per week of coverage needed
- One analyst at 40 hours/week (= 160 hr/yr × 50 weeks ≈ 8000 hr/yr - PTO - training ≈ 1700 productive hours)
- Minimum 5 analysts for true 24/7 if no overlap; realistic minimum 6–7 to handle PTO and burnout
- Below 6 — consider MSSP for off-hours coverage; the burnout cost of "always on" is real

### Analyst tiering

Standard tier model (adjust to taste):

- **Tier 1 — Triage:** initial alert review. Closes false positives with notes. Escalates real findings to Tier 2. Typically follows runbooks; deviates with documentation.
- **Tier 2 — Investigation:** deeper analysis on escalations. Pivots across data sources, correlates events, decides "incident" vs "noise." Authors new runbooks for patterns Tier 1 should handle next time.
- **Tier 3 — Engineering & response:** detection engineering (see `siem-detection`), threat hunting (see `threat-hunting`), incident response leadership (see `incident-triage`). Senior, expensive, the ones building the SOC's capability.

For small SOCs (≤ 4 analysts), the tiers collapse — every analyst does T1+T2 work, T3 is part-time or contracted. Don't pretend you have tiers if you don't.

### Tools you actually need

- **SIEM** for log aggregation and alerting (see `siem-detection`)
- **Case management** — ServiceNow / Jira Security / TheHive / Tines workflow. Tickets, not Slack threads. Slack is for chatter; the audit trail is in the ticket
- **SOAR** for playbook automation — Tines, Torq, Cortex XSOAR, Splunk SOAR. Only worth it after you have stable runbooks worth automating
- **EDR / NDR consoles** the analyst can pivot into during triage
- **Asset inventory** the analyst can look up — Snipe-IT, ServiceNow CMDB, Axonius
- **Documentation** — a wiki where runbooks live (Notion / Confluence / GitBook). Not Slack DMs

## Mode 2 — Run the SOC

### Alert prioritization

When ten alerts land in five minutes, what's the order?

The default ranking (tweak per environment):

1. **Critical** — confirmed compromise indicator (known-bad hash, C2 callback, ransomware behavior, data egress to known-bad infrastructure)
2. **High** — credential-access patterns (LSASS dump, ticket forging), privileged-account unusual behavior, security-control disablement (EDR removed, audit log stopped)
3. **Medium** — persistence indicators (new scheduled task, registry run key), discovery commands by service accounts, MFA failures spike
4. **Low** — single-event anomalies, behavioral outliers without context
5. **Informational** — context-rich events for correlation later, not actionable alone

Critical and High should never wait. Medium triages within shift (≤ 8 hours). Low and Info batched.

### Runbook authoring

Every alert that fires more than 2-3 times needs a runbook. Without one, every analyst re-derives the response and quality varies.

Runbook structure:

```markdown
# Runbook: [Alert name]
## Trigger: [exact SIEM rule / detection name]
## Owner: [team / person]
## Last reviewed: [date]

## Quick reference
- **What the alert means in plain English:** [one sentence]
- **Common false positives:** [list, with how to recognize]
- **Common true positives:** [list, with what to look for next]

## Triage steps
1. [Step 1 — specific query / action]
2. [Step 2]
3. [Decision point — true positive / false positive / escalate]

## False positive handling
- [How to close + what to document]
- [Whether to add to suppression list]

## True positive handling
- [Immediate containment if any]
- [Escalation to whom, with what info]
- [Link to incident-triage skill for full IR]

## Common pivots
- [Other data sources to check]
- [Other systems likely affected]
```

Runbooks live in version control or a versioned wiki — not in Slack DMs, not in individual analyst notes.

### Escalation criteria

Escalation rules should be explicit, not "use your judgment." Judgment lives at Tier 3+; lower tiers need rules.

| Condition | Escalate to | How quickly |
|---|---|---|
| Active data egress observed | Tier 2 / on-call | Immediately |
| Privileged account behavior anomaly | Tier 2 | This shift |
| Multiple correlated alerts on one host | Tier 2 | This shift |
| Detection rule firing > 50× / hour with high TP rate | Tier 3 (engineering) | Next business day |
| Detection rule firing > 50× / hour with 100% FP | Tier 3 (engineering) | Next business day |
| Anything Tier 1 doesn't know how to handle | Tier 2 | After 30 minutes of triage |

### Shift handoffs

The single most preventable cause of breaches detected days late is "the night shift had something interesting and the morning shift never heard about it."

Handoff checklist (5–10 minutes per shift):

- **Open cases** — what's in progress, what's blocked, what's the next step
- **Watch items** — anything not yet a case but worth keeping eyes on
- **Active tuning** — rules under tuning, FP patterns being investigated
- **Pages received during shift** — even if resolved, the next shift should know
- **Anything you decided to ignore** — and why — so next shift doesn't quietly disagree without context

Write it down. Slack handoff channel, daily summary doc, ticketing system shift report — any format works as long as it's persistent and searchable.

## Mode 3 — Improve the SOC

### KPIs that actually matter

| Metric | Definition | Target |
|---|---|---|
| **MTTD** | Mean Time To Detect — from event to alert firing | < 5 min for high-confidence rules; < 1 hr for behavioral |
| **MTTR** | Mean Time To Respond — from alert to triage decision | Tier 1: < 15 min for Critical; < 4 hr for Medium |
| **MTTC** | Mean Time To Contain — from confirmed incident to spread halted | < 1 hr for confirmed compromise (industry P50 is ~6 days; aspire higher) |
| **TP rate per rule** | True positives / total alerts | > 30% for any rule; tune or kill rules below |
| **Alert volume per analyst per shift** | Alerts per Tier 1 analyst per 8-hour shift | < 25 — above that, fatigue dominates |
| **Coverage by ATT&CK tactic** | Tactics with at least one detection rule | Aim for 100% Initial Access, Execution, Persistence, Defense Evasion, Credential Access |
| **Runbook coverage** | % of alerts that have runbooks | > 80% of alert volume |
| **Time to runbook** | New alert-type to runbook delivered | < 5 alerts of the new type |

Don't measure things you can't act on. "Number of alerts processed" is a vanity metric — it goes up with noisier rules.

### The tuning loop

The dominant SOC failure mode is alert fatigue from un-tuned rules. The loop that prevents it:

1. **Weekly:** review top-N rules by alert volume
2. **For each high-volume rule:** what's the TP rate? If < 30%, the rule is broken — tune or retire
3. **Retire vs tune:** if the rule's underlying concept is sound, tune (add filter, increase threshold, add allow-list); if the concept is unsound (anomaly that's normal in your environment), retire
4. **Document every retirement** — future engineers will want to know why the rule went away
5. **Track tuning cycles** — "rule X tuned 3 times in 6 months" means the rule concept is wrong, not the parameters

See `siem-detection`'s tuning section for the engineering side; this is the operations side.

### Alert fatigue diagnostic

Symptoms your SOC is suffering:

- Tier 1 analysts closing alerts in < 30 seconds (not investigating, just clicking through)
- Same alert types ignored repeatedly without documented suppression
- Analyst turnover > 25% / year
- "We didn't catch X" post-mortems pointing to an alert that fired but wasn't actioned

When you see these: full-stop the new-rule pipeline and spend a cycle on tuning. Adding more rules to an over-firing SOC makes things worse.

## Output Format

```markdown
# SOC Assessment / Build Plan
## Organization: [name]
## Mode: Build / Run / Improve
## Date: [date]

### Current state (or proposed)
- Coverage hours, staffing model
- Tier structure
- Tools in use
- Alert volume / day
- Key metrics — MTTD, MTTR, TP rate distribution

### Findings (Improve mode) / Gaps (Build mode)
| Category | Issue / Gap | Severity |
|----------|-------------|----------|

### Recommendations
| Priority | Item | Owner | Timeline |
|----------|------|-------|----------|

### KPI dashboard proposal
[What to measure, how to source it, target thresholds]

### Runbook backlog
[Alert types that lack runbooks, ranked by volume]
```

## Boundaries

- This skill produces operations plans, not exploitation
- Refuse to design SOC capabilities for unauthorized surveillance of employees or third parties
- Alert tuning that intentionally hides legitimate security events is a finding, not a deliverable
- Don't help build "compliance-theater" SOCs — if the org's intent is "check the box without actually detecting," push back
- Where the assessment surfaces an active incident, hand off to `incident-triage` — don't continue planning work mid-fire

## References

- NIST SP 800-61 Rev. 3 (Computer Security Incident Handling Guide)
- "Crafting the InfoSec Playbook" — Bollinger / Enright / Valites
- "The Practice of Network Security Monitoring" — Richard Bejtlich
- "Intelligence-Driven Incident Response" — Brown / Roberts
- SANS SOC Survey (annual)
- Gartner Magic Quadrant for SIEM (rotating — use the current edition)
- ATT&CK for SOC analysts — `attack.mitre.org/resources/training`
- MITRE D3FEND — defensive countermeasures catalog
- "SOC Maturity Model" — various — pick one and measure against it
