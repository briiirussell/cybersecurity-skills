---
name: csf-mapping
description: "Map your security posture against the NIST Cybersecurity Framework 2.0 (Govern, Identify, Protect, Detect, Respond, Recover). Produce a gap analysis, current/target tier assessment, and roadmap in the governance language that boards, auditors, and CISOs actually use. Use when the user mentions 'NIST CSF,' 'CSF 2.0,' 'cybersecurity framework,' 'security posture,' 'governance mapping,' 'CSF gap analysis,' 'CSF tiers,' 'cybersecurity maturity,' 'security roadmap,' 'CISO report,' 'board reporting,' 'security program,' or needs to translate technical findings into governance language."
allowed-tools: Read, Grep, Glob, Bash, WebSearch
---

# CSF Mapping — NIST Cybersecurity Framework 2.0 Posture Assessment

Translate your security posture into the language every CISO, board, auditor, and insurer already speaks. Distinct from the audit skills (which find specific issues); this skill assesses your *program* against a recognized framework and produces governance-ready output.

NIST CSF 2.0 is the framework that, as of 2024, replaced CSF 1.1. It added a sixth function — **Govern** — recognizing that the others can't work without governance backing.

The six functions:

| Function | What it covers |
|---|---|
| **Govern (GV)** | Cybersecurity strategy, roles, policies, oversight, supply chain risk |
| **Identify (ID)** | Asset inventory, business environment, risk assessment, supply chain |
| **Protect (PR)** | Access control, awareness, data security, baseline configurations, maintenance, protective tech |
| **Detect (DE)** | Continuous monitoring, anomaly detection, adverse event analysis |
| **Respond (RS)** | Incident management, analysis, mitigation, reporting, comms |
| **Recover (RC)** | Recovery planning, improvements, communications |

Each function contains Categories (e.g., `PR.AA` — Identity Management, Authentication, and Access Control), and each category contains Subcategories (e.g., `PR.AA-01` — Identities and credentials for authorized users, services, and hardware are managed).

This skill maps your reality to those Subcategories.

Cross-references: every audit skill in this repo (they produce evidence that becomes the "current state" entries here), `iam-audit` (most of PR.AA), `siem-detection` (most of DE), `incident-triage` (most of RS), `threat-modeling` (informs ID.RA risk assessment), `breach-patterns` (informs ID.IM improvements from lessons learned).

## Methodology

### Step 1 — Establish scope

CSF assessments are scope-bounded. Decide which of these you're assessing:

- **Whole organization** — every system, every business unit
- **One product / service** — for vendor due-diligence questionnaires (SIG, CAIQ)
- **One environment** — production cloud only, or PCI-in-scope only
- **Regulatory scope** — HIPAA-covered systems, FedRAMP boundary, etc.

Write down what's in and what's out. Most CSF assessments fail at scope drift.

### Step 2 — Choose your CSF profile

CSF 2.0 introduced Organizational Profiles — instead of "score every Subcategory equally," you tailor based on what matters.

- **Current Profile** — where you actually are
- **Target Profile** — where you want to be (informed by business goals, regulatory requirements, risk appetite)
- **Community Profile** — pre-built profile for your sector (manufacturing, healthcare, financial services — published by NIST and others)

For a first-pass assessment, start with a Community Profile if one exists for your sector, then tailor.

### Step 3 — Assess each Subcategory

For each Subcategory in scope:

| Field | What to record |
|---|---|
| **ID** | e.g., `PR.AA-05` |
| **Subcategory text** | Verbatim from NIST or paraphrased |
| **Current state** | What you actually do today (evidence, not aspiration) |
| **Evidence** | Document / system / process that proves the current state |
| **Tier** | Partial / Risk-Informed / Repeatable / Adaptive (1-4) |
| **Target tier** | What you're aiming for |
| **Gap** | The delta |
| **Plan** | What closes the gap |
| **Owner** | Who's accountable |
| **Timeline** | When |

#### CSF Implementation Tiers

| Tier | Name | Characteristic |
|---|---|---|
| 1 | **Partial** | Ad-hoc, reactive, undocumented; awareness is informal |
| 2 | **Risk-Informed** | Risk management is approved but not org-wide; processes are repeatable for some teams |
| 3 | **Repeatable** | Documented org-wide policies; consistent processes; risk-informed budgeting |
| 4 | **Adaptive** | Continuous improvement; quantitative risk; learning from incidents (yours and peers'); cybersecurity culture |

Tier 4 is rare and expensive. Most mature SaaS orgs target Tier 3 across most subcategories. Set targets based on what the business actually needs, not what looks good.

### Step 4 — Identify gaps and prioritize

For each gap, ask:

- **Impact** if exploited / not addressed (regulatory, reputational, financial)
- **Likelihood** given current threat landscape and your specific exposure
- **Cost to close** (engineering hours, tooling, headcount)
- **Dependencies** on other gaps closing first

Prioritize by **Risk × Cost-to-close** — not just by risk. Some critical-risk items take a year and three vendors; some quick wins reduce real risk in a sprint.

### Step 5 — Build the roadmap

CSF roadmaps usually run in quarters with annual targets. A useful structure:

- **Next 30 days** — immediate gaps (quick wins, low-cost high-risk items)
- **Next 90 days** — medium effort, named owners, defined success criteria
- **Next 12 months** — strategic gaps requiring budget approval, tooling decisions, headcount
- **Annual review** — full reassessment; profile refresh; tier movement

Each item on the roadmap names: the Subcategory it closes, the owner, the budget, the success metric, the review date.

## Subcategory cross-references to skills in this repo

A useful shortcut — these are the audit skills that produce evidence for which CSF Subcategories.

| CSF Subcategory | Audit skill | Type of evidence |
|---|---|---|
| `GV.SC` (Supply Chain Risk) | `dependency-audit` | CVE inventory, vendor list, supply chain risk register |
| `ID.AM` (Asset Management) | `cloud-audit`, `container-audit`, `recon` | Asset inventory output |
| `ID.RA` (Risk Assessment) | `threat-modeling`, `breach-patterns` | Threat models, breach-pattern coverage doc |
| `ID.IM` (Improvement from past incidents) | `incident-triage` post-mortems, `breach-patterns` | Post-incident reviews, lessons-learned applied |
| `PR.AA` (Identity & Access Control) | `iam-audit` | IAM audit reports, role inventory |
| `PR.DS` (Data Security) | `crypto-audit`, `secrets-audit` | Crypto posture, secrets management posture |
| `PR.PS` (Platform Security) | `container-audit`, `cloud-audit` | K8s hardening, cloud posture |
| `PR.IR` (Infrastructure Resilience) | `container-audit`, `cloud-audit` | Network policy, segmentation, backup posture |
| `DE.CM` (Continuous Monitoring) | `siem-detection`, `soc-operations` | SIEM coverage, ATT&CK Navigator export |
| `DE.AE` (Anomaly & Event Analysis) | `siem-detection`, `threat-hunting` | Detection rule inventory, hunt findings |
| `RS.MA` (Incident Management) | `incident-triage`, `soc-operations` | IR plan, runbooks, recent incident reports |
| `RS.AN` (Analysis) | `disk-forensics`, `incident-triage` | Forensic analysis outputs |
| `RS.MI` (Mitigation) | `finding-triage`, `incident-triage` | Triage decisions, mitigation tracking |
| `RC.RP` (Recovery Plan) | (not directly covered — separate BCP/DR work) | BCP / DR plans, tested recovery |

For Subcategories without direct skill coverage, the gap is usually "we have technical depth but not the program-level artifact." E.g., `RC.RP-01` (Recovery plan is executed during or after an incident) needs an actual documented and tested BCP/DR plan — running incident-triage doesn't automatically produce one.

## High-impact gaps most orgs have

Patterns I see repeatedly in CSF assessments. Not universal, but starting points:

- **GV.OC-04 (Critical objectives, capabilities, and services are identified and communicated)** — Most orgs can't name their crown-jewel systems consistently across security, IT, and engineering
- **GV.SC (Supply Chain Risk Management category)** — Either no vendor risk program at all, or one that exists on paper but doesn't actually gate procurement
- **ID.AM-08 (Systems, hardware, software, services, and data are managed throughout their life cycles)** — Asset inventory is "the SaaS vendor's list" plus "what we remember"
- **ID.IM-04 (Incident response plans are exercised)** — Plan exists, last tested three years ago
- **PR.AA-05 (Access permissions and authorizations are managed, incorporating the principles of least privilege)** — Quarterly access review exists in policy, not in practice
- **PR.DS-01 (The confidentiality, integrity, and availability of data-at-rest are protected)** — Encryption at rest "yes," but key management is "ask AWS"
- **DE.AE-08 (Incidents are declared when adverse events meet defined criteria)** — Criteria not actually defined; "we'll know when we see it"
- **RS.CO-02 (Internal and external stakeholders are notified of incidents)** — Notification matrix is in someone's head
- **RC.RP-01 (Recovery plan is executed)** — Documented, never tested

## Output Format

```markdown
# NIST CSF 2.0 Posture Assessment
## Organization: [name]
## Scope: [what's in / out]
## Date: [date]
## Assessor: [name]

## Executive summary
[2-3 paragraphs in plain English — overall posture, top 3 risks, top 3 wins, recommended 90-day priorities]

## Profile

### Tier summary across functions
| Function | Current tier | Target tier |
|----------|--------------|-------------|
| GV | 2 | 3 |
| ID | 2 | 3 |
| PR | 3 | 3 |
| DE | 2 | 3 |
| RS | 3 | 3 |
| RC | 1 | 2 |

### Per-Subcategory detail
| Subcategory | Current state | Evidence | Tier | Target | Gap | Owner | Timeline |
|-------------|---------------|----------|------|--------|-----|-------|----------|

## Prioritized roadmap

### Next 30 days
- [Item, owner, success metric]

### Next 90 days
- [Item, owner, success metric]

### Next 12 months
- [Item, owner, success metric]

## Cross-references
[Links to evidence — audit reports, IR plans, IAM reports, etc.]
```

## Translating to board language

Boards don't want Subcategory IDs. They want answers to three questions:

1. **Where are we exposed?** (Top 3-5 material risks)
2. **What are we doing about it?** (Specific investments, named owners, dates)
3. **How will we know we're better?** (Quantitative metrics, target dates)

Use the CSF assessment as the *backing detail*. The board view is a one-page heatmap and three slides of priorities. The assessment goes in the appendix.

## Boundaries

- This skill produces governance artifacts and roadmaps — not exploitation
- CSF assessments are not audits in the regulatory sense (SOC 2 audit, FedRAMP assessment, ISO 27001 certification audit are all separate processes); CSF mapping informs those but doesn't replace them
- For audited environments (PCI, HIPAA, FedRAMP), the auditor's specific framework is authoritative; CSF mapping is a useful complement
- Refuse to inflate tier ratings without evidence — Tier 3 means "evidence of documented org-wide processes," not "we hope to do this someday"
- Where the assessment surfaces a finding that needs immediate action (active incident, exposed system), hand off to `incident-triage` or the relevant audit skill

## References

- NIST Cybersecurity Framework 2.0 (`nist.gov/cyberframework`)
- NIST CSF 2.0 Quick Start Guides
- NIST CSF Community Profiles (sector-specific starting points)
- NIST SP 800-53 (controls catalog — provides specific controls that map to CSF Subcategories)
- ISO 27001:2022 (alternative ISMS framework — frequently mapped against CSF for organizations doing both)
- CIS Critical Security Controls v8 (alternative prioritized framework — strong overlap with CSF)
- Cybersecurity Maturity Model Certification (CMMC) — for DoD contractors; uses CSF + NIST 800-171
- "Cybersecurity Risk Management: Mastering the Fundamentals Using the NIST Cybersecurity Framework" — Cynthia Brumfield
