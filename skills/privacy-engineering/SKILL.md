---
name: privacy-engineering
description: "Implement and audit privacy controls in product and infrastructure — GDPR, CCPA / CPRA, LGPD, PIPEDA. Covers data minimization, lawful basis, consent management, data subject access requests (DSARs — access, deletion, portability), data processing agreements, DPIA / TIA, breach notification timing, data classification, and the technical implementation of 'right to be forgotten' across backups, caches, analytics, and third parties. Use when the user mentions 'GDPR,' 'CCPA,' 'CPRA,' 'data privacy,' 'privacy engineering,' 'data subject access request,' 'DSAR,' 'right to deletion,' 'right to be forgotten,' 'data portability,' 'consent management,' 'cookie consent,' 'data minimization,' 'DPIA,' 'data protection impact assessment,' 'breach notification,' 'BAA,' 'DPA,' 'data processing agreement,' 'sub-processor,' 'cross-border data transfer,' 'SCCs,' or needs to implement or review privacy controls."
allowed-tools: Read, Grep, Glob, Bash, Write, WebSearch
---

# Privacy Engineering — GDPR / CCPA Technical Implementation

Implement privacy controls at the code, data, and infrastructure layers. This skill is not legal compliance theater — it is the engineering work that turns the legal requirements into systems that actually do what they claim.

Privacy and security overlap but are not the same. Security protects against unauthorized access; privacy protects against authorized-but-improper use. A perfectly secure system that logs every keystroke and shares the log with vendors is a privacy disaster. This skill covers the privacy half of that distinction.

Cross-references: `owasp-audit` for the security side, `iam-audit` for access control to personal data, `secrets-audit` for credential handling, `incident-triage` for the response side of a privacy breach (72-hour GDPR notification clock starts when you find out, not when you finish investigating), `security-comms` for the customer-disclosure draft.

## Regulatory landscape (engineering-relevant subset)

The skill produces compliant technical implementations. Final compliance determinations stay with counsel; this skill is the technical execution layer.

| Regulation | Scope | Key engineering hooks |
|---|---|---|
| **GDPR** (EU) | Any processing of personal data of EU/EEA residents | Articles 5 (principles), 6 (lawful basis), 7 (consent), 15-22 (data subject rights), 25 (privacy by design), 30 (records of processing), 32 (security), 33 (breach notification — 72 hours), 35 (DPIA) |
| **CCPA / CPRA** (California) | Businesses processing CA resident data above thresholds | Right to know, delete, correct, opt out of sale / share. Sensitive PI category. Annual privacy notice. Service-provider contracts |
| **LGPD** (Brazil) | Brazilian residents | Similar shape to GDPR with local twists |
| **PIPEDA** (Canada) | Federal commercial | Consent-based with reasonable expectation, breach notification |
| **State laws (US)** | Varies — VA, CO, CT, UT, etc. | Roughly CCPA-shaped; engineering practices that meet GDPR + CCPA usually cover state laws |

Engineering reality: build for the strictest regime that applies and stop worrying about the rest. GDPR is the strictest in most dimensions; CCPA adds the "opt out of sale / share" and sensitive-PI category.

## Privacy by design — the engineering practices

### Practice 1: Data classification

You cannot enforce privacy on data you have not classified. Every data store needs a classification.

A minimal classification (more is fine, less is not):

| Class | Definition | Engineering treatment |
|---|---|---|
| **Public** | Information published or freely sharable | No special handling |
| **Internal** | Internal business data, no PI | Standard access controls |
| **Personal** | Data identifying a natural person (email, name, IP, device ID, account ID) | Access logging, retention limits, deletion path |
| **Sensitive personal** | GDPR Art 9 special categories (health, biometric, political, sexual orientation, race, religion), CCPA SPI (precise location, race, religion, biometric, genetic, sex life, mail content, government ID, financial account, citizenship, union membership) | Stricter access (need-to-know), encryption at rest with separate KMS key, audit on every read |
| **Regulated** | PHI under HIPAA, PCI cardholder data, NPI under GLBA | Regulation-specific controls; out of scope here, see `hipaa-audit` and `pci-audit` |

**Audit step:** for each data store (database, S3 bucket, BigQuery dataset, etc.), confirm classification is documented and matches the actual data. Many systems start "internal" and quietly become "personal" because someone added an email column.

### Practice 2: Data minimization

Collect the minimum to deliver the service; retain the minimum to deliver value; share the minimum with vendors.

**Common minimization findings:**
- IP address logged in every request when it is only needed for rate limiting (truncate to /24 after rate-limit decision)
- Full user-agent stored when only the device class matters (truncate)
- Date of birth collected for age verification when only "over 13 / over 18 / over 21" is needed (store the boolean, not the date)
- Phone numbers collected for "optional" notifications and retained after opt-out
- Backup data retained for years past the operational need
- Analytics platforms receiving full URL paths that contain order IDs / user IDs

**Audit grep patterns:**
- Personal-data column names in DB schemas: `email`, `phone`, `name`, `address`, `ssn`, `dob`, `birth`, `gender`, `ip`, `user_agent`, `device_id`, `ip_address`
- Logging statements emitting these: `log\..*\$\{user\.email\}`, `console\.log\(.*user\.`, `logger\.info\(.*email`
- Analytics integrations sending more than they need: `analytics\.identify\(.*email`, full-page URL parameters

### Practice 3: Lawful basis (GDPR) / purpose (CCPA)

Every processing activity needs a documented lawful basis under GDPR Article 6. CCPA requires purpose-of-use disclosure.

Common bases and where they fit:
- **Contract** (Art 6(1)(b)) — necessary to provide the service the user signed up for
- **Consent** (Art 6(1)(a)) — opt-in, freely given, specific, informed, revocable. The bar is high. The bar is especially high for sensitive data (Art 9 requires explicit consent on top of the lawful basis)
- **Legitimate interest** (Art 6(1)(f)) — the catch-all for security, fraud prevention, internal analytics. Requires a balancing test documented somewhere
- **Legal obligation, vital interest, public task** — narrow applicability

**Engineering hook:** the application logs every processing activity (insert into `data_processing_log` or equivalent) with the lawful basis. When DSARs arrive, this is the source of truth for what to disclose.

### Practice 4: Consent management

Consent is the most over-engineered and under-built part of privacy. The skill is keeping it simple and provable.

**The consent record:**
- User ID (or device ID for pre-auth)
- Specific purpose (marketing emails ≠ product analytics ≠ third-party advertising)
- Timestamp
- Version of the consent text shown
- Source (which form / banner / API)
- Whether granted or denied
- Revocation timestamp if withdrawn

Withdrawal of consent must be as easy as granting it (GDPR Art 7(3)). If "accept all" is one click on the cookie banner, "reject all" must also be one click. Banners that require traversing five panels to refuse are non-compliant.

**Common audit findings:**
- Cookie banner that loads tracking scripts before the user clicks anything
- "Legitimate interest" set as the default for non-essential cookies
- Consent timestamp not stored, so the app cannot prove when (or whether) consent was obtained
- Marketing consent bundled with terms-of-service acceptance (consent must be specific)
- No way for the user to see their consent history or withdraw

### Practice 5: Data subject rights (the DSAR pipeline)

Users have rights under GDPR Articles 15-22 and CCPA. The technical implementation often falls down in the same places.

**Right to access (Art 15 / CCPA "right to know"):**
The user gets a copy of personal data held about them. Implementation:
- Enumerate every data store containing personal data tied to a user ID
- Pull from each store on request
- Format in a machine-readable export (JSON / CSV)
- Verify identity before disclosing — verification standard must be appropriate to sensitivity, not "we sent an email to the address on file"
- 30-day delivery (GDPR) / 45-day (CCPA)

**Right to deletion (Art 17 / CCPA "right to delete"):**
The user gets data deleted. The technical reality is harder than it looks.
- **Primary database:** straightforward DELETE / soft-delete with retention
- **Replicas / standbys:** confirm replication propagated, or schedule for purge
- **Backups:** retention windows mean backups will continue to contain deleted data until they age out. GDPR is OK with this *if* you document the retention and re-delete on any restore
- **Caches:** Redis, CDN, application-level caches — invalidate on delete
- **Search indexes:** Elasticsearch / Algolia / Meilisearch — re-index, do not just delete the source
- **Analytics:** Mixpanel, Amplitude, Segment, GA — separate deletion APIs per vendor
- **Data warehouses:** BigQuery / Snowflake / Redshift — separate pipeline; usually batched
- **Logs:** application logs containing the user's PII age out by retention. Verify log retention is shorter than the user can reasonably expect
- **Third parties / sub-processors:** every vendor processing personal data on your behalf needs a deletion fan-out

**Audit grep patterns:**
- Search for places PII flows out: `analytics\.track`, `segment\.identify`, `sentry\.setUser`, `mixpanel\.people\.set`, `datadog.*user`, `posthog\.identify`
- Find vendor SDK initializations: `Sentry\.init`, `analytics\.load`, `LogRocket\.init`, `FullStory\.init`
- Each is a deletion-fanout destination

**Right to portability (Art 20):**
Machine-readable export of data the user provided. Distinct from access — only covers data they gave you, in a structured format. JSON / CSV is fine.

**Right to rectification (Art 16 / CCPA "right to correct"):**
Update incorrect data. Engineering hook: build the correction path into the product; do not require email-to-support.

**Right to object (Art 21):**
Stop processing for direct marketing / specific other purposes. Engineering hook: a suppression list / opt-out flag honored everywhere processing happens.

**Audit step:** simulate a DSAR end to end against your own account before a real user does. Most teams find broken parts on first try.

### Practice 6: Vendor / sub-processor management

Every vendor processing personal data is a sub-processor. GDPR requires a Data Processing Agreement (DPA) with each one and a documented sub-processor list available to users.

**Engineering audit:**
- Inventory every SaaS / API integration in the codebase that touches user data
- For each, confirm DPA on file (legal can answer)
- For each, confirm the data sent is the minimum needed
- For each, confirm deletion API or process exists
- For each, confirm data-residency (where is the data stored — EU, US, elsewhere) and that cross-border transfer mechanism is in place (Standard Contractual Clauses for transfers out of EU)

**Common findings:**
- Sentry / Datadog / LogRocket / FullStory capturing PII in error reports and session recordings
- Slack used for customer-data discussion (Slack becomes a sub-processor if PII is shared in DMs/channels)
- Analytics tools pre-2024 cross-border transfer (US adequacy decision after EU-US Data Privacy Framework — verify your vendors are listed)
- Webhook deliveries to vendors not under DPA

### Practice 7: Breach notification

GDPR Article 33: notify supervisory authority within 72 hours of becoming aware of a personal data breach. Article 34: notify affected individuals without undue delay if breach poses high risk.

Engineering hooks (this skill is for the technical detection / scoping side; legal handles the actual notification):
- Detection: SIEM rules for personal-data exfiltration / unauthorized-access patterns (see `siem-detection`)
- Scoping: ability to determine *quickly* which records / fields / individuals were involved (audit logs, access logs, query history)
- Containment: revoke access, rotate credentials (see `secrets-audit`, `incident-triage`)
- Documentation: timeline-of-awareness clock starts when *anyone* on the team becomes aware, not when leadership is briefed — your detection-to-leadership latency directly impacts the 72-hour clock

### Practice 8: DPIA (Data Protection Impact Assessment)

Required for high-risk processing (Art 35) — large-scale processing of sensitive data, systematic monitoring, automated decision-making affecting individuals.

Engineering input to a DPIA:
- Data flow diagram (re-use the `threat-modeling` artifact)
- Categories of personal data
- Categories of data subjects
- Recipients (internal + vendors)
- Retention periods per category
- Security measures (link to `owasp-audit`, `iam-audit`, `crypto-audit` outputs)
- Risk assessment + mitigations

This skill produces the engineering inputs; legal / privacy counsel produces the DPIA itself.

## Output format

```markdown
# Privacy Engineering Audit / Implementation Report
## Scope: [system / product / data flow]
## Regulation context: [GDPR / CCPA / both / other]
## Date: [date]

### Data inventory
| Data store | Classification | Categories of PI | Lawful basis | Retention |
|------------|----------------|------------------|--------------|-----------|

### Findings
| ID | Severity | Practice | Issue |
|----|----------|----------|-------|

### DSAR pipeline status
- [ ] Access — implemented and tested end-to-end
- [ ] Deletion — implemented with full fan-out (DBs, caches, search, analytics, vendors)
- [ ] Portability — implemented in machine-readable format
- [ ] Rectification — self-service path exists
- [ ] Objection / opt-out — honored in all processing paths

### Vendor / sub-processor inventory
| Vendor | Purpose | Data shared | DPA | Deletion path | Data residency |
|--------|---------|-------------|-----|---------------|----------------|

### Consent records (if applicable)
[State: present / partial / missing. Storage location. Fields captured.]

### Action items
[Prioritized with owner and deadline]
```

Disposition rule (Fixed / Deferred / Accepted Risk) per `owasp-audit`'s Report Format. Accepted-risk decisions for privacy findings often need legal sign-off as well as engineering — note this in the writeup.

## Boundaries

- This skill produces technical implementations and audit findings; final compliance determinations require legal / privacy counsel
- For breach notification: the skill produces the technical scope and timeline; the notification itself requires legal review and goes through `security-comms`
- Refuse to help build systems designed to violate privacy laws — including dark-pattern consent flows, surveillance-as-marketing, or PI hoarding past lawful retention
- "Anonymization" is a high bar — pseudonymization (replacing direct identifiers with surrogate keys while retaining ability to re-identify) is not the same as anonymization (irreversibly removing identifiability). Treat re-identification risk seriously
- Cross-border transfer to non-adequate jurisdictions requires Standard Contractual Clauses or equivalent — the legal mechanism is not this skill's scope, but the engineering work of routing data through compliant pipelines is

## References

- GDPR — full regulation: `eur-lex.europa.eu/eli/reg/2016/679`
- EDPB Guidelines — the European Data Protection Board issues binding guidance on GDPR interpretation
- ICO (UK) — accessible, practitioner-oriented guidance: `ico.org.uk`
- CCPA / CPRA — California AG: `oag.ca.gov/privacy/ccpa`
- IAPP — International Association of Privacy Professionals (training, certification, resource library)
- NIST Privacy Framework — companion to CSF, useful for translating between security and privacy controls
- ISO/IEC 27701 — privacy extension to ISO 27001
- "Privacy by Design" — Ann Cavoukian's seven foundational principles
- "Privacy Engineering" — Bibi Lin, M. Selvi, A. Acar (academic / practitioner overview)
- "The Algorithmic Foundations of Differential Privacy" — Dwork & Roth (for the anonymization / differential-privacy slice)
- Data Privacy Framework (EU-US, US-UK, US-Swiss) — current cross-border transfer mechanisms
