---
name: pci-audit
description: "Audit applications and infrastructure handling payment card data against PCI DSS v4.0. Heavy emphasis on scope determination (the single most-leveraged variable) plus the engineering-relevant requirements — Req 3 (storage of CHD), Req 4 (transmission), Req 6 (secure SDLC), Req 7-8 (access), Req 10 (logging), Req 11 (testing), Req 12 (program). Use when the user mentions 'PCI,' 'PCI DSS,' 'PCI DSS 4.0,' 'payment card,' 'cardholder data,' 'CHD,' 'PAN,' 'PCI scope,' 'PCI compliance,' 'SAQ,' 'AoC,' 'attestation of compliance,' 'tokenization,' 'P2PE,' 'network segmentation for PCI,' or audits any system that stores, processes, or transmits payment card data."
allowed-tools: Read, Grep, Glob, Bash, Write, WebSearch
---

# PCI Audit — Payment Card Industry Data Security Standard

PCI DSS v4.0 (effective March 2025) is the security standard for any environment that stores, processes, or transmits payment card data. Twelve high-level requirements; hundreds of sub-requirements. Most organizations pass or fail on a single decision: **scope**.

This skill emphasizes scope determination first, then the engineering-relevant requirements. Final compliance attestation (SAQ self-assessment or QSA audit producing an Attestation of Compliance) is a process this skill prepares for — it is not the attestation itself.

Cross-references: `crypto-audit` for Req 3 / 4 cryptographic detail; `iam-audit` for Req 7-8; `siem-detection` for Req 10 logging; `dependency-audit` and `owasp-audit` for Req 6 (secure SDLC); `incident-triage` for Req 12.10 (incident response).

## The scope question (do this first)

"Scope" in PCI DSS means: the systems that store, process, or transmit cardholder data (CHD), plus systems that can affect the security of those systems (connected-to and security-impacting systems). Everything in scope is subject to all 12 requirements. Everything out of scope is not.

**Most PCI failures are scope failures.** A system pulled into scope by accident creates years of compliance debt; a system kept out of scope via good architecture saves substantial cost.

### Determine scope

For every system in the environment, classify:

| Type | Definition | In scope? |
|---|---|---|
| **CDE** (Cardholder Data Environment) | Stores, processes, or transmits PAN, expiration, service code, name when paired with PAN, or sensitive authentication data | **Yes — full PCI DSS** |
| **Connected-to** | Has direct connectivity to the CDE without compensating segmentation | **Yes** |
| **Security-impacting** | Provides security services to the CDE (auth, logging, monitoring, time sync, DNS) | **Yes** |
| **Segmented** | No direct connectivity; segmentation validated annually | **No** |
| **Cardholder data flow only as masked / tokenized** | The system handles tokens or masked PANs that cannot be reversed without out-of-band access | Usually **No**, but verify the token type — surrogate tokens reversible by the merchant are still in scope |

**Audit step:** trace every payment flow end-to-end. Where does the PAN enter the environment, where does it go, where does it stop. Every system the PAN touches is in scope; every system that touches *that* system without segmentation is also in scope.

### Reduce scope (the leveraged engineering work)

The highest-ROI PCI work is usually scope reduction:

- **Use a hosted payment page** — let Stripe / Adyen / Braintree / Worldpay host the input form. The PAN never reaches your servers. The browser communicates directly with the processor. Your scope shrinks to "iframe integration."
- **Use tokenization** — payment processor converts PAN into a token your systems store instead. The token is meaningless without processor-side access. Your systems handle tokens, not PANs.
- **Use P2PE** (Point-to-Point Encryption) — for terminal-present commerce, encrypt at the swipe so plaintext never traverses your network.
- **Network segmentation** — for retained CDE, ensure firewall / VLAN / namespace separation between CDE and the rest. Default-deny at the CDE perimeter.

A merchant doing 1M transactions/year via Stripe Checkout with no PAN on their servers is *radically* less in scope than the same merchant taking PANs into their own form and proxying to Stripe. Same merchant; very different audit.

## Merchant levels and assessment types (compliance posture, not engineering)

Briefly, because it sets the audit cadence and rigor:

| Level | Volume (Visa) | Validation requirement |
|---|---|---|
| **1** | > 6M transactions/year, or breached merchant of any volume | Annual on-site QSA assessment → AoC |
| **2** | 1M-6M transactions/year | Annual SAQ (self) or QSA assessment (Visa requires QSA from 2024) |
| **3** | 20K-1M e-commerce transactions/year | Annual SAQ |
| **4** | All other | Annual SAQ |

**SAQ types** (Self-Assessment Questionnaire) match the merchant's CDE shape — SAQ A (fully outsourced e-commerce), SAQ A-EP (e-commerce that does some redirection), SAQ B (terminal only, dial / IP without electronic storage), SAQ C-VT (web-based virtual terminal), SAQ D (everything else, the longest). The right SAQ is the one whose conditions all match your environment.

## Engineering-relevant requirements (the subset this skill audits)

### Req 3 — Protect stored cardholder data

**The default position: do not store PAN.** If you must, encrypt at rest and minimize the data retained.

- PAN at rest must be unreadable: strong cryptography (AES-256), key management per Req 3.6 (see `crypto-audit`), key rotation, separation of duties on key custody
- Sensitive authentication data (CVV / CVV2, full magnetic stripe, PIN / PIN block) **must not be stored** after authorization — period, regardless of encryption
- Mask PAN on display by default — typically first 6 + last 4
- Render PAN unreadable in any other form (backups, logs, debug output)

**Audit grep patterns:**

- Database schemas: columns named `pan`, `card_number`, `cc_number`, `cardnum`, `account_number`
- Code paths writing card data: `pan`, `cardNumber`, regex `^4[0-9]{12,15}$` (Visa), `^5[1-5][0-9]{14}$` (Mastercard), `^3[47][0-9]{13}$` (Amex), `^6(?:011|5[0-9]{2})[0-9]{12}$` (Discover)
- Logs: `console\.log.*cardNumber`, `logger\..*\.pan`, `log\..*card`
- Error reporting: confirm Sentry / Datadog / Bugsnag scrubbing rules redact card patterns (Luhn-valid 13-19 digit sequences)
- Backups: confirm backup retention does not include unencrypted CHD

If a Luhn-valid PAN appears anywhere in source, lock files, or logs — that is a finding regardless of intent.

### Req 4 — Protect transmission across open networks

- TLS 1.2 or higher, modern cipher suites only (see `crypto-audit` for the configuration detail)
- No PAN transmitted via end-user messaging tech (email, SMS, chat) — and reject any flow that does
- Internal-only networks transmitting PAN should still encrypt (defense in depth — Req 4.2.1.1 in v4.0)

### Req 6 — Develop and maintain secure systems and software

This is where the security audit family meets PCI. Most of this requirement is satisfied by running the existing skills:

- **6.2** Custom software developed securely — see `owasp-audit`, `api-audit`
- **6.3** Vulnerabilities identified and addressed — see `vuln-research`, `dependency-audit`, `finding-triage`
- **6.4** Public-facing web applications protected from attacks — WAF or annual code review + post-release manual review
- **6.5** Changes to all system components managed securely — change management, separation of duties between dev and prod, sanitization of pre-production data before lower-environment use

**Audit grep patterns:**
- Lower-environment configs containing real PANs (the common failure: staging seeded from a prod DB dump that included card data)
- Code paths that bypass the secure SDLC (direct prod hotfix patterns, `--no-verify` on commits to prod-impacting branches)

### Req 7 — Restrict access to cardholder data by business need to know

- Role-based access — only personnel needing CHD for their job have access
- Default-deny — access is granted explicitly, never inherited
- Privileged user IDs documented and reviewed

See `iam-audit` for the full identity-and-access deep dive.

### Req 8 — Identify users and authenticate access

- Unique IDs (no shared accounts) for every user — including service accounts
- Strong authentication — passwords meeting current PCI complexity requirements, MFA for non-console administrative access AND for all remote network access AND (new in v4.0) for all access into the CDE
- MFA must be phishing-resistant for the most sensitive access paths (recommended in v4.0)
- Account lockout, session timeout, password rotation per current PCI parameters (v4.0 relaxed some legacy requirements — verify current text)

See `iam-audit` for implementation patterns and identity-provider integration.

### Req 10 — Log and monitor all access to network resources and cardholder data

- Every access to CHD logged — who, when, what, from where
- Logs centralized, time-synced (Req 10.6 — NTP), retained at least 12 months (3 months immediately available)
- Logs reviewed daily — manual or automated. Anomalies trigger investigation
- Log integrity protected — separate system, write-only, immutable storage

See `siem-detection` for the engineering implementation; see `soc-operations` for the review cadence.

### Req 11 — Test security of systems and networks regularly

- **Vulnerability scans** — internal and external, quarterly. External scans must be by an ASV (Approved Scanning Vendor)
- **Penetration tests** — annual at minimum, after significant changes. Internal AND external. Network and application layer. Tested by qualified internal resource or third party
- **Segmentation testing** (for environments relying on segmentation to reduce scope) — annual penetration testing specifically to validate segmentation
- **File integrity monitoring** on critical files / configs

See `dependency-audit` (vulnerability scan), `web-pentest` (annual app pentest), `red-team-engagement` (annual offensive engagement for higher levels).

### Req 12 — Maintain an information security policy

The program-level layer. Engineering inputs:

- **12.10** Incident response plan — see `incident-triage`. Tested at least annually
- **12.5** Third-party / service-provider management — DPA-like attestations, annual review of provider compliance (your processor will send you an AoC; you must retain it)
- **12.6** Security awareness training — for personnel handling CHD

## Putting it together — audit checklist

```markdown
# PCI DSS v4.0 Audit Findings
## Merchant: [name]
## Merchant level: [1/2/3/4]
## SAQ type: [A / A-EP / B / C-VT / D / not applicable - Level 1 QSA]
## Date: [date]
## Auditor: [name + qualification]

### Scope determination
- [ ] Payment data flow diagrammed end-to-end
- [ ] CDE explicitly bounded
- [ ] Connected-to systems enumerated
- [ ] Segmentation evidence documented
- [ ] Scope-reduction opportunities identified

### Per-requirement findings
| Req | Compliant? | Findings | Severity |
|-----|------------|----------|----------|
| 3 — Stored CHD | | | |
| 4 — Transmission | | | |
| 6 — Secure SDLC | | | |
| 7 — Access restriction | | | |
| 8 — Authentication | | | |
| 10 — Logging | | | |
| 11 — Testing | | | |
| 12 — Program | | | |

### Per-finding detail
[Title, req reference, severity, location, vulnerable config, remediation, verification]

### Recommended scope reductions (if applicable)
[Hosted payment page, tokenization, network segmentation improvements with effort estimates]

### Compensating controls (if used)
[Each compensating control: control description, what it compensates for, evidence of effectiveness, review cadence]
```

Disposition rule (Fixed / Deferred / Accepted Risk) per `owasp-audit`. PCI accepted-risk is heavily disfavored — most "accepted risks" should be Compensating Controls with documented evidence of effectiveness.

## Common audit findings (real-world starting hypotheses)

- **PAN in logs** — error / debug / access logs containing card data, captured by Sentry / Datadog / Bugsnag, retained beyond authorization
- **Sensitive authentication data persistence** — CVV stored "for re-billing convenience" (forbidden), or full track data captured by accident
- **Lower environments seeded from production** — staging database contains real PANs from a prod dump that was not sanitized
- **Tokenization scope misunderstanding** — surrogate tokens stored in your DB that are reversible by your processor account are still in scope; only one-way tokens reduce scope
- **Iframe vs proxy** — "hosted payment page" implemented as a proxy where your server briefly handles the PAN before forwarding (still in scope) vs a true iframe where your server never sees it (out of scope)
- **Segmentation by firewall rule, not by architecture** — firewall rule "permits" only specific traffic but the systems share a VLAN; effective segmentation requires architectural separation
- **MFA gaps** — v4.0 broadened MFA requirements; older environments that met v3.2.1 may have gaps

## Boundaries

- This skill is the engineering-side audit and preparation. Final compliance attestation (signed SAQ for self-assessing merchants, AoC produced by a QSA for higher-tier merchants) is a separate process
- For QSA-led Level 1 assessments, this skill produces inputs to the QSA; it does not replace the QSA's independent assessment
- Refuse to help build flows that violate PCI DSS — storing CVV, transmitting PAN via email, bypassing tokenization to capture raw cards
- Where the audit surfaces an active compromise (PAN already exposed, suspected breach), pivot to `incident-triage` — PCI breach response has specific timing and notification requirements (acquirer notification typically within 24 hours)
- Brand-specific rules (Visa, Mastercard, Amex, Discover, JCB) layer on top of PCI DSS — for merchants with brand-specific obligations (e.g., Visa's Cardholder Information Security Program), consult the card brand's program documentation

## References

- **PCI DSS v4.0** — `pcisecuritystandards.org/document_library`
- **PCI DSS v4.0 Quick Reference Guide** — practitioner-focused summary
- **SAQ Instructions and Guidelines** — for self-assessing merchants
- **PCI SSC FAQ database** — official interpretive guidance
- **QIR / QSA / PFI / ASV registries** — for approved assessor / vendor selection
- **Visa Cardholder Information Security Program (CISP)** — Visa-specific layered requirements
- **Mastercard Site Data Protection (SDP) Program** — Mastercard layer
- **Open Web Application Security Project (OWASP)** — Req 6 substantive content
- **NIST SP 800-53** — control catalog that maps cleanly to many PCI requirements
- **"PCI Compliance"** — Branden Williams, Anton Chuvakin — practitioner book, updated through v4.0
