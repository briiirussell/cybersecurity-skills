---
name: hipaa-audit
description: "Audit applications and infrastructure handling Protected Health Information against HIPAA — Security Rule (administrative, physical, technical safeguards), Privacy Rule, Breach Notification Rule, plus HITECH. Covers ePHI scoping, the 18 HIPAA identifiers, Business Associate Agreement (BAA) chain-of-liability, minimum-necessary standard, and breach notification timing. Use when the user mentions 'HIPAA,' 'HIPAA Security Rule,' 'HIPAA Privacy Rule,' 'PHI,' 'ePHI,' 'protected health information,' 'BAA,' 'business associate agreement,' 'covered entity,' 'business associate,' 'minimum necessary,' 'HIPAA breach,' 'HITECH,' 'healthcare compliance,' 'medical data,' 'patient data,' or audits any system that creates, receives, maintains, or transmits PHI."
allowed-tools: Read, Grep, Glob, Bash, Write, WebSearch
---

# HIPAA Audit — Health Insurance Portability and Accountability Act

HIPAA governs how Protected Health Information (PHI) is handled in the United States healthcare ecosystem. The engineering surface area is large because PHI is broader than people often realize: a calendar entry naming a patient's appointment is PHI; an IP address logged on a portal accessed by a patient may be PHI in combination with a health condition.

The skill is structured around the four HIPAA rules with emphasis on the Security Rule's three safeguard categories (Administrative / Physical / Technical) — that's where engineering work happens. Privacy Rule, Breach Notification Rule, and HITECH layer on top.

Final compliance determinations stay with counsel and your privacy officer; this skill is the technical engineering layer.

Cross-references: `privacy-engineering` for the GDPR / CCPA-shaped privacy work that often overlaps; `iam-audit` for access control and authentication; `crypto-audit` for encryption-at-rest and in-transit detail; `secrets-audit` for key management; `siem-detection` for audit-log engineering; `incident-triage` and `security-comms` for breach response.

## Scope — who is covered and what is PHI

### Who must comply

- **Covered entity (CE)** — health plans, healthcare clearinghouses, healthcare providers who transmit health info electronically in connection with HIPAA-defined transactions
- **Business associate (BA)** — anyone who creates / receives / maintains / transmits PHI on behalf of a covered entity (cloud hosts holding PHI, SaaS analytics, EHR vendors, billing services, even some attorneys and consultants)
- **Subcontractor of a BA** — also a BA. The chain extends; every link needs a BAA with the link above

If a system handles PHI for a CE without a BAA, that's a violation regardless of how secure the handling is.

### What is PHI / ePHI

PHI = individually identifiable health information held or transmitted by a CE or BA. ePHI = the electronic form.

The 18 HIPAA identifiers (Safe Harbor de-identification list — if all are stripped, data is no longer PHI):

1. Names
2. Geographic subdivisions smaller than state (street, city, county, ZIP — full ZIP if population < 20,000; first 3 digits OK in most cases)
3. Dates more specific than year (DOB, admission, discharge, death) — for individuals over 89, even the year requires aggregation
4. Phone numbers
5. Fax numbers
6. Email addresses
7. Social Security numbers
8. Medical record numbers
9. Health plan beneficiary numbers
10. Account numbers
11. Certificate / license numbers
12. Vehicle identifiers and serial numbers (including license plates)
13. Device identifiers and serial numbers
14. URLs
15. IP addresses
16. Biometric identifiers (finger, voice)
17. Full-face photographs and comparable images
18. Any other unique identifying number, characteristic, or code

**Important:** removing the 18 identifiers via Safe Harbor is one of two de-identification methods. The other is Expert Determination (statistical analysis confirming low re-identification risk). De-identified data is not PHI; **pseudonymized data is still PHI** (because the key linking the surrogate back to the individual is still held somewhere).

### Scope reduction patterns

The most common scope reductions:

- **Limit data classes collected** — if you don't need DOB, don't collect it; don't transmit it; don't store it
- **Pseudonymize internally** where regulators allow, but understand that internal pseudonyms are still ePHI (the linking table is held by the CE / BA)
- **Use BA-signed services** where possible — AWS, Google Cloud, Azure, Stripe Healthcare, certain analytics vendors sign BAAs; many SaaS tools do not
- **Use services that contractually commit to never receive PHI** — analytics platforms that scrub on ingest, error reporters with strict PII filtering

## Security Rule — the three safeguard categories

### Administrative safeguards (program-level)

These are policy and program controls. Engineering teams contribute artifacts; the privacy officer owns the program.

- **§164.308(a)(1) Security Management Process** — risk analysis (the foundation; redone on material change), risk management, sanction policy, information system activity review
- **§164.308(a)(2) Assigned Security Responsibility** — a named Security Official
- **§164.308(a)(3) Workforce Security** — authorization / supervision, termination procedures
- **§164.308(a)(4) Information Access Management** — access authorization, modification
- **§164.308(a)(5) Security Awareness and Training** — including security reminders, malicious software protection, log-in monitoring, password management
- **§164.308(a)(6) Security Incident Procedures** — see `incident-triage`
- **§164.308(a)(7) Contingency Plan** — backup, disaster recovery, emergency mode operation, testing
- **§164.308(a)(8) Evaluation** — periodic technical and non-technical evaluation
- **§164.308(b)(1) Business Associate Contracts** — BAA with every BA

**Engineering audit input:** evidence packages for risk analysis (asset inventory, threat model, controls list), workforce-security records (access reviews, joiner/mover/leaver evidence), training completion records.

### Physical safeguards (data center / facility)

For modern SaaS, most physical safeguards are inherited from the cloud provider's compliance posture (covered by the cloud's BAA). Verify:

- **§164.310(a) Facility Access Controls** — for any office space where ePHI is processed
- **§164.310(b) Workstation Use** — policies for workstations that access ePHI
- **§164.310(c) Workstation Security** — physical security of those workstations
- **§164.310(d) Device and Media Controls** — disposal, media re-use, accountability, data backup and storage

**Engineering audit input:** confirm cloud provider's BAA covers the relevant physical-safeguard obligations; confirm workstation disk encryption and remote-wipe for any employee laptop touching ePHI.

### Technical safeguards (where engineering audits)

This is where this skill spends its time.

#### §164.312(a) Access Control

- **Unique user identification** — required. Every individual accessing ePHI has a unique ID. No shared accounts
- **Emergency access procedure** — break-glass path for emergency PHI access, logged
- **Automatic logoff** — addressable; idle session termination
- **Encryption and decryption** — addressable; encrypt ePHI at rest (in practice, treat as required; OCR enforcement strongly suggests this)

**Audit grep patterns:**
- Shared service-account access to PHI tables: `SELECT.*patient`, `SELECT.*encounter` from non-individual accounts
- Lack of session timeout: search for session config without explicit timeout
- Unencrypted ePHI at rest: confirm DB-level + bucket-level encryption per data store

#### §164.312(b) Audit Controls

- **Hardware, software, and procedural mechanisms that record and examine activity** in systems containing ePHI

In practice: every read, every write, every access decision involving ePHI logged. Logs preserved for at least 6 years (HIPAA's general document-retention period). See `siem-detection` for the engineering implementation.

#### §164.312(c) Integrity

- **Mechanisms to authenticate ePHI** — verify ePHI has not been altered or destroyed in unauthorized manner
- Addressable in practice — hash / signature controls on critical ePHI records, immutable log storage

#### §164.312(d) Person or Entity Authentication

- Verify identity of person or entity accessing ePHI
- MFA is not explicitly required by Security Rule text — but post-2013 enforcement and HHS guidance strongly recommend MFA for any remote access to ePHI; treat as effectively required. New HHS guidance (2024+) is moving MFA toward explicit requirement

See `iam-audit` for implementation.

#### §164.312(e) Transmission Security

- **Integrity controls** — addressable; protect ePHI in transit from improper modification
- **Encryption** — addressable in text but treat as required; TLS 1.2+ for any ePHI traversing networks

See `crypto-audit`.

## Privacy Rule — what can be done with PHI

The Privacy Rule sets the rules for how PHI is used and disclosed. The Security Rule says "protect it"; the Privacy Rule says "you can only use it for these specific purposes."

Engineering-relevant slices:

- **Minimum Necessary Standard** — when using or disclosing PHI for purposes other than treatment, use or disclose only the minimum necessary. The engineering implementation: role-based access, query-level scoping (don't `SELECT *` from patient tables), API contracts that return only the fields the caller needs
- **TPO exception** — Treatment, Payment, and Healthcare Operations do not require authorization. Most other uses do
- **Individual rights** — right to access (similar to GDPR DSAR — 30-day delivery), right to amend, accounting of disclosures
- **Notice of Privacy Practices** — published, presented at first interaction

**Audit grep patterns:**
- Over-broad PHI queries: `SELECT \*.*patient`, `SELECT \*.*encounter`, `SELECT \*.*observation` — almost always a minimum-necessary violation
- API endpoints returning full patient records when callers only need specific fields
- Analytics platforms / monitoring tools receiving PHI without a TPO basis

## Breach Notification Rule

A breach is the unauthorized acquisition, access, use, or disclosure of unsecured PHI that compromises the security or privacy of the PHI. "Unsecured" = not encrypted per HHS guidance (encryption is the safe harbor).

**Notification timing:**

| Recipient | Timing |
|---|---|
| **Affected individuals** | Without unreasonable delay, no later than 60 calendar days after discovery |
| **Department of Health and Human Services (HHS / OCR)** | Within 60 days of discovery for breaches affecting ≥ 500 individuals; annually for breaches < 500 |
| **Media** | Same 60-day window for breaches affecting > 500 in a state or jurisdiction |
| **Business associate to covered entity** | Without unreasonable delay, no later than 60 days |

A "breach" includes the unauthorized access — not just exfiltration. If a workforce member views a record they had no need to view, that is a breach (unless one of the limited exceptions applies).

**Engineering hook:** ability to scope a breach quickly. Audit logs (Security Rule §164.312(b)) are the source of truth. Time-to-scope directly impacts the 60-day clock.

**Safe harbor:** if the PHI was encrypted per HHS-recognized standards (and the key wasn't also compromised), the unauthorized acquisition may not be a breach. This is the strongest reason to encrypt ePHI at rest comprehensively.

See `incident-triage` (response), `security-comms` (notification draft — legal review required), `breach-patterns` (post-incident pattern extraction).

## HITECH layer

HITECH (2009) strengthened HIPAA in several ways relevant here:

- Made BAs directly liable for many Security Rule violations (was previously CE-only)
- Increased civil monetary penalties (tiered up to $1.5M per provision per year)
- Made the Breach Notification Rule federal (replacing some state-level patchwork)
- Strengthened the right of patients to obtain electronic copies of their PHI

For modern engineering work, HITECH means: a BA that handles ePHI is subject to most of the Security Rule directly. Vendors cannot hide behind the CE.

## Audit checklist

```markdown
# HIPAA Audit Findings
## Entity: [name]
## Entity type: Covered Entity / Business Associate / Subcontractor
## Date: [date]
## Auditor: [name]

### Scope
- [ ] ePHI inventory complete (every data store containing PHI)
- [ ] Data flow diagrams for PHI transmission paths
- [ ] BAA in place with every BA (and BA's subcontractors where required)
- [ ] Cloud provider BAA on file (AWS / GCP / Azure / etc.)
- [ ] Risk analysis (§164.308(a)(1)(ii)(A)) current

### Administrative safeguards
| Subsection | Status | Findings |
|------------|--------|----------|
| Security Management Process | | |
| Assigned Security Responsibility | | |
| Workforce Security | | |
| Information Access Management | | |
| Security Awareness and Training | | |
| Security Incident Procedures | | |
| Contingency Plan | | |
| Evaluation | | |
| BA Contracts | | |

### Technical safeguards
| Subsection | Status | Findings |
|------------|--------|----------|
| Access Control — unique IDs | | |
| Access Control — emergency access | | |
| Access Control — automatic logoff | | |
| Access Control — encryption at rest | | |
| Audit Controls | | |
| Integrity | | |
| Person / Entity Authentication (MFA) | | |
| Transmission Security (encryption in transit) | | |

### Privacy Rule
- [ ] Minimum necessary applied in code (no SELECT * on PHI tables)
- [ ] Notice of Privacy Practices published and presented
- [ ] Individual access path implemented (30-day delivery)
- [ ] Amendment / accounting of disclosures process exists

### Breach response readiness
- [ ] Audit logs sufficient to scope a breach within 60-day clock
- [ ] Incident-response procedures tested
- [ ] Notification templates drafted (see security-comms)
- [ ] Encryption-as-safe-harbor verified across ePHI stores

### Findings detail
[Per finding: section reference, severity, location, evidence, remediation]

### Recommendations
[Prioritized]
```

Disposition rule (Fixed / Deferred / Accepted Risk) per `owasp-audit`. HIPAA accepted-risk is highly disfavored — most "accepted risks" should be documented as residual risk with compensating controls and re-evaluation triggers.

## Common audit findings (real-world starting hypotheses)

- **PHI in non-BAA vendor pipelines** — Sentry, Datadog, Mixpanel, Segment, Slack receiving PHI without a BAA (Sentry has a BAA path; Datadog has a healthcare offering; Mixpanel does not by default — verify each vendor's BAA stance)
- **Unique-user-ID violation via shared service accounts** — engineering team uses a shared admin account for ad-hoc PHI access
- **`SELECT *` on PHI tables** — minimum-necessary violation; API serializers returning all fields when callers need few
- **DOB stored when only age range needed** — minimization gap
- **Backups encrypted but with key co-located** — safe harbor depends on key separation
- **Lower environments seeded from production** — staging DB contains real PHI from a prod dump
- **MFA not enforced for all ePHI access paths** — pre-2024 environments may have gaps; trend is toward universal MFA requirement
- **Audit log retention < 6 years** — HIPAA's 6-year retention applies to documentation required by the rules, including audit logs that evidence compliance
- **No automatic logoff on ePHI-accessing workstations / clinical applications**
- **BA chain breaks** — vendor's subcontractor handles ePHI but the BA never put their own BAA in place with the subcontractor

## Boundaries

- This skill is the engineering audit and preparation. Privacy Officer / counsel make final determinations on covered-entity status, BA relationships, and notification decisions
- Refuse to help build flows that violate HIPAA — PHI to non-BAA vendors, shared-account access to PHI, transmission of PHI via end-user messaging tech (consumer email, SMS, chat) outside narrow authorization, marketing uses of PHI without authorization
- For breaches: this skill scopes the breach and produces engineering inputs to the notification; the notification itself goes through `security-comms` and counsel
- HIPAA enforcement (OCR) has expanded since 2013; regulatory interpretation continues to evolve. Where this skill's content lags current OCR guidance, current OCR guidance prevails
- State laws may impose stricter requirements (e.g., Texas HB 300, California CMIA) — preempted only where state law is less protective; otherwise state requirements apply on top
- Genetic information has additional protections under GINA — out of scope here, refer to specialized guidance

## References

- **HHS HIPAA Rules** — `hhs.gov/hipaa` (regulatory text, FAQs, OCR resolution agreements)
- **HHS / OCR Audit Protocol** — used by OCR auditors; useful checklist for self-assessment
- **HHS Security Risk Assessment Tool** — free tool for small/medium providers
- **NIST SP 800-66 Rev. 2** (2024) — "Implementing the HIPAA Security Rule: A Cybersecurity Resource Guide" — the most current technical guidance
- **HITRUST CSF** — common controls framework that maps to HIPAA Security Rule; many BAs pursue HITRUST certification as compliance evidence
- **OCR Resolution Agreements** — published enforcement actions; useful precedent for what OCR considers material
- **HHS Wall of Shame** — public breach portal; useful for industry-pattern context
- **45 CFR Parts 160 and 164** — the regulatory text itself
- **OCR Cybersecurity Newsletter** — quarterly guidance updates
- **"HIPAA Plain & Simple"** — Carolyn P. Hartley — practitioner reference
