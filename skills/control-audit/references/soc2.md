# SOC 2 — Trust Services Criteria reference

For `control-audit`. Criteria are paraphrased, not quoted: the AICPA text is copyrighted, and the auditor will use the official wording. Get the current publication from the AICPA & CIMA site before fieldwork.

## Version

- **Criteria:** 2017 Trust Services Criteria (TSP section 100), with the **revised points of focus published in 2022**. The 2022 revision changed only the points of focus; the criteria themselves are unchanged since 2017. Points of focus are guidance for designing and assessing controls, not requirements a control must tick off one by one.
- **Guide:** the AICPA SOC 2 Guide, 2022 edition, which is what the service auditor follows.
- **2026:** the AICPA Auditing Standards Board has an open project revising the attestation standards (AT-C 105/205/210); exposure drafts were issued in early 2026. As of late 2026 no final standard is out and the project does not change the criteria (verify before relying on this; check the AICPA project page).

## Report types

| | Type 1 | Type 2 |
|---|---|---|
| Covers | Fairness of the system description and **suitability of design** of controls | The same, plus **operating effectiveness** over a period |
| Point in time | As of a single date | A period, commonly 3 to 12 months; renewals are usually 12 months back to back |
| Testing | Mostly inquiry and inspection of design (one instance) | Samples across the whole period |
| When to choose | First report when a customer needs something now; proves design | What most enterprise customers ask for |

Related: a **bridge (gap) letter** from management covers the time between the end of the last period and today; it's management's statement, not the auditor's. A **SOC 3** is a general-use summary of a SOC 2 Type 2 with no control detail. A **SOC 1** is about controls relevant to customers' financial reporting, not security.

### Things in scope that people forget

- **System description** (management writes it, the auditor opines on it): services, infrastructure, software, people, procedures, data, principal service commitments and system requirements, incidents in the period that matter, and changes to the system in the period.
- **Subservice organizations**: carve-out (their controls are excluded, and you list the complementary subservice organization controls you rely on them for, then show you monitor them, usually by reviewing their SOC 2 each year) or inclusive (their controls are tested in your report; rare).
- **CUECs**: complementary user entity controls, the controls your customers have to run for yours to work (managing their own users, protecting their API keys).
- **Exceptions**: a Type 2 report lists test exceptions with management's response. Exceptions don't automatically mean a qualified opinion, but a pattern of them in one criterion can.

## Categories

| Category | Criteria | In scope |
|---|---|---|
| Security | CC1–CC9 (common criteria) | Always |
| Availability | CC plus A1 | When uptime commitments matter to customers |
| Confidentiality | CC plus C1 | When you hold data customers designate confidential |
| Processing Integrity | CC plus PI1 | When customers rely on complete, accurate, timely processing (payments, payroll, calculations) |
| Privacy | CC plus P1–P8 | When you handle personal information under your own privacy notice; pair with `privacy-engineering` |

## Common criteria (CC1–CC9)

CC1–CC5 follow the COSO 2013 internal control components and principles. CC6–CC9 are the security-specific additions. Each row: what the criterion is about (paraphrased), then the evidence auditors usually ask for, then what the repo can show.

### CC1 — Control environment

| Criterion | About | Usual evidence | Repo can show |
|---|---|---|---|
| CC1.1 | Commitment to integrity and ethical values | Code of conduct, signed acknowledgements for hires in the period, disciplinary process | — |
| CC1.2 | Board (or equivalent) oversight independent of management | Board or advisory meeting minutes covering security, charter | — |
| CC1.3 | Structures, reporting lines, authorities and responsibilities | Org chart, security role descriptions, named security owner | `CODEOWNERS`, `SECURITY.md` owner |
| CC1.4 | Attracting, developing and keeping competent people | Job descriptions, background checks (sample of hires), training records | — |
| CC1.5 | Holding people accountable for internal control | Performance reviews that include security duties, disciplinary records | — |

### CC2 — Communication and information

| Criterion | About | Usual evidence | Repo can show |
|---|---|---|---|
| CC2.1 | Generating and using quality information for internal control | System inventory, data flow diagrams, logging of control activity | Architecture docs, IaC as inventory |
| CC2.2 | Communicating internally about objectives and responsibilities | Policy acknowledgements, security training completion, internal channel for reporting issues | Contributor docs, internal security docs |
| CC2.3 | Communicating with external parties | Customer-facing security page, terms, status page, incident notification process, vulnerability disclosure | `SECURITY.md`, `security.txt` |

### CC3 — Risk assessment

| Criterion | About | Usual evidence | Repo can show |
|---|---|---|---|
| CC3.1 | Objectives specified clearly enough to identify risks | Security objectives, risk methodology | — |
| CC3.2 | Identifying and analyzing risks | Risk register with dates, owners, ratings; annual risk assessment | Threat models (`threat-modeling`) |
| CC3.3 | Considering fraud risk | Fraud section of the risk assessment | — |
| CC3.4 | Identifying changes that affect internal control | Change-triggered risk reviews (new vendor, new region, acquisition) | — |

### CC4 — Monitoring activities

| Criterion | About | Usual evidence | Repo can show |
|---|---|---|---|
| CC4.1 | Ongoing and separate evaluations of controls | Internal audit or control self-assessment, penetration test report, GRC tool monitoring | Scheduled scanner workflows |
| CC4.2 | Communicating and fixing control deficiencies | Deficiency tracker with owners and dates, management review | Issue tracker labels for findings |

### CC5 — Control activities

| Criterion | About | Usual evidence | Repo can show |
|---|---|---|---|
| CC5.1 | Selecting controls that reduce risk to acceptable levels | Risk-to-control mapping (the control matrix itself) | — |
| CC5.2 | General controls over technology | Technology control set (access, change, operations) | CI policy, IaC |
| CC5.3 | Deploying controls through policies and procedures | Approved policies with review dates and owners | `policies/`, `docs/` with history |

### CC6 — Logical and physical access

| Criterion | About | Usual evidence | Repo can show | Hand off |
|---|---|---|---|---|
| CC6.1 | Logical access security: identification, authentication, access architecture, encryption of data at rest | Asset inventory, SSO/MFA config, network segmentation, encryption settings, key management | IaC encryption and network settings; auth config | `iam-audit`, `cloud-audit`, `crypto-audit` |
| CC6.2 | Registering and authorizing new users; removing access | Provisioning tickets (sample of hires), leaver deprovisioning (sample of terminations vs HR list) | SCIM / IaC user definitions | `iam-audit` |
| CC6.3 | Granting, changing and removing access by role, least privilege, segregation of duties | Role definitions, periodic access reviews with evidence of removals | IAM policies in IaC | `iam-audit` |
| CC6.4 | Restricting physical access | Data center: the cloud provider's SOC 2 (carve-out); office badge logs if offices are in scope | — | — |
| CC6.5 | Disposing of assets and data securely | Device wipe records, data deletion procedure, cloud provider's media handling (carve-out) | Data retention / deletion jobs | `privacy-engineering` |
| CC6.6 | Protecting against threats from outside the boundary | Firewall / WAF / security group config, TLS settings, external pen test | IaC ingress rules, WAF config | `cloud-audit` |
| CC6.7 | Restricting and protecting data in transmission and movement | TLS everywhere, DLP or removable-media controls, encrypted backups in transit | TLS config, HSTS | `crypto-audit` |
| CC6.8 | Preventing or detecting unauthorized or malicious software | Endpoint protection (MDM report), dependency and container scanning, signed builds | Dependabot/Renovate, scanner jobs | `dependency-audit`, `container-audit`, `agent-supply-chain-audit` |

### CC7 — System operations

| Criterion | About | Usual evidence | Repo can show | Hand off |
|---|---|---|---|---|
| CC7.1 | Detecting configuration changes and new vulnerabilities | Vulnerability scans with remediation within the policy SLA, config drift monitoring | Scanner workflows, IaC drift checks | `dependency-audit`, `patch-sweep`, `cloud-audit` |
| CC7.2 | Monitoring for anomalies that indicate attacks or errors | Logging and alerting config, alert samples and how they were handled | Alert rules as code | `siem-detection` |
| CC7.3 | Evaluating security events to decide if they're incidents | Triage procedure, event tickets with decisions | — | `soc-operations` |
| CC7.4 | Responding to incidents | Incident response plan, incident tickets in the period, tabletop record if no real incident | IR runbooks | `incident-triage` |
| CC7.5 | Recovering from incidents | Post-incident reviews, recovery actions, lessons applied | Postmortem docs | `incident-triage` |

### CC8 — Change management

| Criterion | About | Usual evidence | Repo can show | Hand off |
|---|---|---|---|---|
| CC8.1 | Authorizing, designing, testing, approving and implementing changes to infrastructure, data, software and procedures | Change policy; sample of changes showing ticket, peer review, testing, approval before deploy; emergency change process; segregation between author and approver | Branch protection, required reviews and checks, `CODEOWNERS`, deploy workflows, IaC plan/apply gating | `cloud-audit` (deploy path) |

Change management is where the repo carries the most evidence. Check: who can push to the production branch, whether admins can bypass, whether the deploy job only runs from the protected branch, and whether infrastructure changes go through the same review.

### CC9 — Risk mitigation

| Criterion | About | Usual evidence | Repo can show |
|---|---|---|---|
| CC9.1 | Mitigating risk of business disruption | Business continuity and disaster recovery plans, insurance, test records | DR runbooks, multi-region IaC |
| CC9.2 | Assessing and managing vendor and business partner risk | Vendor inventory, risk tiering, annual review of critical vendors' SOC reports, contracts with security terms | Third-party list in `package.json` is not a vendor inventory |

## Additional criteria

### Availability (A1)

| Criterion | About | Usual evidence |
|---|---|---|
| A1.1 | Managing capacity to meet availability commitments | Capacity monitoring, autoscaling config, capacity reviews |
| A1.2 | Environmental protections, backups, recovery infrastructure | Backup config and schedule, backup monitoring, provider SOC 2 for data centers |
| A1.3 | Testing recovery plan procedures | Restore tests and DR exercises in the period, with results |

### Confidentiality (C1)

| Criterion | About | Usual evidence |
|---|---|---|
| C1.1 | Identifying and protecting confidential information | Data classification, encryption, access restriction for confidential data |
| C1.2 | Disposing of confidential information | Retention schedule, deletion records, customer-offboarding deletion |

### Processing Integrity (PI1)

| Criterion | About | Usual evidence |
|---|---|---|
| PI1.1 | Defining and communicating processing specifications | Documented processing objectives and data definitions |
| PI1.2 | Controlling inputs for completeness and accuracy | Input validation, rejected-input handling |
| PI1.3 | Controlling processing | Reconciliations, job monitoring, error queues |
| PI1.4 | Controlling outputs | Output review, delivery confirmation |
| PI1.5 | Storing inputs and outputs completely and accurately | Storage integrity checks, retention |

### Privacy (P1–P8)

| Criterion group | About |
|---|---|
| P1 | Notice about privacy practices |
| P2 | Choice and consent |
| P3 | Collection limited to the stated purposes |
| P4 | Use, retention and disposal |
| P5 | Access by data subjects |
| P6 | Disclosure to third parties and notification of breaches |
| P7 | Quality of personal information |
| P8 | Monitoring and enforcement, including complaints |

The 2022 points-of-focus revision put much of its weight on the privacy and confidentiality criteria. For implementation detail (DSARs, deletion across systems, consent), hand off to `privacy-engineering`.

## Common exceptions in Type 2 testing

Starting hypotheses for readiness, not findings until evidenced:

- Leavers whose access was removed late, or only from the IdP and not from a direct-login system (database, cloud root, a SaaS admin outside SSO)
- Access reviews done, but with no evidence of the removals they called for
- PRs merged without review by admins, or emergency changes with no after-the-fact approval
- Background checks or policy acknowledgements missing for a few hires in the sample
- Vulnerabilities past the policy SLA with no exception record
- Vendor SOC reports not reviewed, or reviewed while the CUECs they list were never mapped to our own controls
- Backups configured but never restore-tested in the period
- Incident response plan untested, with no real incident and no tabletop in the period
- Policies whose annual review date passed during the period

## Severity, not opinion

A Type 2 exception and a security exposure aren't the same thing. Rate the exposure:

| Gap | Record | Why |
|---|---|---|
| Terminated engineer's account still active with production admin | `confirmed`, High or Critical by what it reaches | Live access across the leaver boundary |
| Production branch has no required review, admins push directly | `confirmed`, Medium or High by who has push and what deploys | Defeats the change control on a live path |
| Q3 access review missing, no other evidence of over-provisioning | `needs_validation` until the record is produced; then confirmed (operating) and rated by what unreviewed access reaches | The review is the detective control |
| Information security policy last approved 14 months ago | Documentation gap | No exposure by itself |
| Two hires missing signed code of conduct | Documentation gap | No exposure by itself |
| Encryption at rest on but key rotation off, no traced impact | Hardening note | Another layer covers it |

## Sources

- AICPA & CIMA, 2017 Trust Services Criteria (Revised Points of Focus — 2022) and the SOC 2 Guide (2022). Paraphrased; consult the official text.
- AICPA Auditing Standards Board, attestation standards project (2026 exposure drafts) — status per secondary sources as of 2026 (verify).
- COSO, Internal Control — Integrated Framework (2013).
- Sample-size ranges are common practitioner guidance, not an AICPA requirement; each firm sets its own.
