---
name: security-comms
description: "Translate technical security work into the language of non-security audiences — board, executives, engineering, customer success, customers, legal, procurement, sales. Covers incident communication, post-mortem narrative, audit-findings-for-stakeholders, risk justification, security spend justification, and customer-facing breach disclosure. Use when the user mentions 'security comms,' 'communicate this finding,' 'explain to my boss,' 'board update,' 'executive summary,' 'incident communication,' 'breach notification,' 'customer disclosure,' 'security memo,' 'post-mortem narrative,' 'risk justification,' 'why this matters to the business,' 'translate this finding,' 'stakeholder update,' or has technical security work that needs to land with a non-security audience."
allowed-tools: Read, Write, WebSearch
---

# Security Comms — Translating Security Work for Non-Security Audiences

The skill that closes the gap every other skill produces. The audit family generates findings; the response family generates incidents; the governance family generates roadmaps. None of those outputs survive contact with a board, a customer, a sales engineer trying to answer a security questionnaire, or a CFO asking "is this going to cost us money."

This skill takes technical security work and turns it into the deliverable that audience can actually use. It's the skill security practitioners reach for two to three times a week and that founders without dedicated security teams reach for whenever a finding has to leave the security context.

Cross-references: feeds from every other skill (audit output, incident write-ups, threat-model summaries, CSF assessments) and produces audience-specific deliverables; pairs especially closely with `finding-triage` (the disposition writeup) and `incident-triage` (the response narrative).

## The seven audiences (and what each one actually needs)

Security comms is not one register. Each audience needs a different deliverable; using the wrong register is the most common failure mode.

### 1. Board of directors / non-executive directors

**They need to know:** Are we materially exposed? Is the team handling it? Is more investment needed?

**They do not need:** CVE numbers, file paths, scanner names, technical jargon, the methodology.

**Format:** One slide or one page. Three sections — current posture in one paragraph, top three risks with one sentence each, named investments / decisions needed. Numbers must be material (in dollars or % impact), not raw counts ("we have 47 vulnerabilities" tells them nothing; "two of our payments-team services have unpatched issues an attacker could use to access customer card data" tells them what to do).

**Common mistake:** Boards get scored heat maps and 30-row CVE tables. They want the punchline.

### 2. Executive leadership (CEO / CFO / COO / GC)

**They need to know:** What decision is being asked of them? What's the trade-off? What's the cost of inaction?

**Format:** Memo, one to three pages. Lead with the decision; then context, options with trade-offs, recommendation, the cost / time / people / risk if they say no. Quantify where possible (regulatory exposure dollars, customer-trust risk in churn percentage, engineering hours).

**Common mistake:** Asking for budget without naming the alternative if the budget is denied.

### 3. Engineering leadership / senior engineers

**They need to know:** What's broken, how to fix it, what's the priority, what's the trade-off in their roadmap.

**Format:** Ticket or design-doc-shaped writeup. Specific files / endpoints / commits. Reproduction steps. Fix proposal. Verification step. Effort estimate. Engineering leadership respects specificity; vague "you have an XSS somewhere" creates resentment.

**Common mistake:** Framing security work as urgent without showing the work. Engineers want to verify the finding themselves.

### 4. Individual engineers (the person who has to do the work)

**They need to know:** What exactly to change, in their code, with verification they can run themselves.

**Format:** Ticket with code-shaped detail — file path, line number, current code, fixed code, the test that proves the fix held. This is the most concrete register of all.

**Common mistake:** Pasting the scanner output without context. The engineer doesn't know which of the scanner's 50 fields matter.

### 5. Customer success / sales engineering

**They need to know:** What to say to customers who ask. What the answer is to common security questionnaire fields. What changed that they need to mention.

**Format:** Internal FAQ — questions phrased the way a customer would phrase them, answers written for an SE to read aloud or paste into a reply. Avoid security jargon; avoid "we cannot comment" unless legal actually said so.

**Common mistake:** Drafting customer-facing language and not letting customer-success read it for tone before it ships. Security folks default to language that sounds defensive or evasive.

### 6. Customers (under public disclosure)

**They need to know:** Did my data get accessed? What did you do about it? What do I need to do?

**Format:** A short letter. Lead with what happened in their terms (not yours). State what data may have been involved. State what's been done. State what they should do. Provide a contact path that works. Avoid corporate-PR softeners; they read as evasive.

**Common mistake:** Saying "out of an abundance of caution" when you mean "we don't know yet but we have to tell you." Customers can tell.

Disclosure to customers has legal and regulatory dimensions — this skill produces a draft; legal and possibly outside counsel review before it ships.

### 7. Procurement / legal / compliance counterparts (internal or vendor-side)

**They need to know:** Are we compliant, what's documented, what's the contractual position, do we have evidence?

**Format:** Structured artifact — questionnaire response, BAA / DPA red-line input, audit-evidence pull. Use the framework language the counterpart is using (CSF Subcategory IDs, ISO controls, PCI requirement numbers, HIPAA safeguard names). Avoid translating into your own framework; they want their language back.

**Common mistake:** Answering "yes" or "no" without the evidence pointer. Procurement-side reviewers need the evidence inline, not on request.

## Workflow

The skill works in two modes — drafting from a technical input, or reviewing a draft someone else wrote.

### Mode 1: Draft from technical input

1. **Identify the audience.** Which of the seven above? If more than one, separate deliverables — do not merge.
2. **Identify the decision being asked.** Boards: "approve budget." Engineering: "fix this by date." Customers: "trust that we handled this." If you cannot name the decision in one sentence, the audience does not have one and your deliverable is informational, not action-oriented.
3. **Strip the technical artifacts not relevant to this audience.** CVE numbers are for engineers. Dollar amounts are for executives. Customer impact is for customers. Same finding, three different drafts.
4. **Write the lead first.** What do they take away if they only read the first paragraph? Write that, then back into the supporting detail.
5. **Quantify where possible — even rough.** "Affects roughly 8% of paying customers" beats "affects some customers." If you do not know, say so explicitly; do not hedge with weasel words.
6. **Pass through a second-reviewer who shares the audience's perspective.** Engineering deliverables: another engineer. Customer disclosures: customer success. Board updates: someone who actually sits in board meetings.

### Mode 2: Review a draft

1. **Audience check.** Is the register right for the named audience?
2. **Decision check.** Is the decision they need to make obvious?
3. **Jargon check.** Highlight any term the audience would not use in their own work.
4. **Hedging check.** "Out of an abundance of caution," "best efforts," "industry-standard" — these read as evasive. Replace with concrete statements where possible.
5. **Specificity check.** Does the draft say what was found, what was done, what's next, with names attached?

## Templates

### Template: Board update on a security incident

```markdown
# Security Update — [Date]
## To: Board
## From: [CISO / equivalent]

### Bottom line
[One sentence — material exposure yes / no, contained yes / no, action needed yes / no]

### What happened
[Two to four sentences in the board's terms. No file paths or CVE numbers.]

### What's been done
- [Action 1, by date]
- [Action 2, by date]

### What we're asking of the board
[If anything — funding, vendor change, communications approval. If nothing, say so.]

### What we'll know by [next-meeting date]
[Open questions, planned investigations]
```

### Template: Executive memo asking for a decision

```markdown
# Memo: [Decision name]
## From: [author]
## To: [decision-maker]
## Date: [date]
## Decision needed by: [date]

### The decision
[One sentence — what you're asking them to approve.]

### Why now
[Two sentences — what changed, what the regulatory / customer / risk pressure is.]

### Options
1. [Option A — cost, time, residual risk]
2. [Option B — cost, time, residual risk]
3. [Do nothing — what happens]

### Recommendation
[Which option and why.]

### Cost of inaction
[Specific — regulatory fines, customer-trust impact, engineering hours saved elsewhere, etc.]
```

### Template: Customer-facing breach disclosure (DRAFT — legal review required)

```markdown
# Security Notice
## Date: [date]

Dear [customer],

On [date], we identified [what happened — in the customer's terms]. Information that may have been involved includes [specific data fields]. Information not involved includes [specific data fields].

We have taken the following steps:
- [Action 1]
- [Action 2]

We recommend you:
- [Action 1 they should take, e.g., reset password]
- [Action 2]

If you have questions, contact [working contact path — not a generic security@].

We are sorry this happened.

[Name and title — not a corporate signature]
```

### Template: Post-mortem narrative (internal)

```markdown
# Post-mortem: [Incident name]
## Severity: [SEV1 / SEV2 / SEV3]
## Date detected: [date]
## Date resolved: [date]
## Duration: [hh:mm]
## Authors: [names]

### Summary
[One paragraph that someone outside the response can read and understand the incident.]

### Timeline
[Bulleted, with timestamps in one timezone. Detection → triage → containment → eradication → recovery → all-clear.]

### Impact
- [Who was affected — customers, internal users, third parties]
- [What was affected — service availability, data confidentiality, data integrity]
- [Quantify where possible — affected user count, downtime minutes, data records involved]

### Root cause
[The actual root cause — not the proximate trigger. Why did the trigger lead to user impact?]

### What went well
[Two to four items. Be specific.]

### What did not go well
[Two to four items. Be specific. No blame language.]

### Action items
| Item | Owner | Deadline | Status |
|------|-------|----------|--------|

### Lessons for the rest of the org
[What other teams should change based on this incident.]
```

### Template: Audit-findings translation (for engineering)

```markdown
# Security Findings — [Project / sprint]
## Audit source: [owasp-audit / api-audit / etc.]
## Date: [date]

### Summary
[One sentence — N findings, severity breakdown, target resolution window.]

### Findings (prioritized)
| ID | Severity | File / endpoint | Effort estimate | Sprint candidate |
|----|----------|-----------------|-----------------|------------------|

### Per-finding detail
[Per-finding entries with file:line, reproduction, fix proposal, verification step, effort estimate.]

### Not findings (FYI)
[Items the scanner / audit flagged that we've determined are not real — with one line each on why. This builds engineering trust that we're not crying wolf.]
```

### Template: Sales-engineering FAQ

```markdown
# Customer Q&A — [Topic, e.g., recent vulnerability disclosure]
## Internal — for SE use; not customer-facing

**Q: Were we affected by [CVE / event]?**
A: [Straight answer. Yes / no / partially with which part.]

**Q: What did you do about it?**
A: [Specific actions with dates.]

**Q: Should I be doing anything on my end?**
A: [Customer-facing recommendation, or "no action required, here's why."]

**Q: When can I expect a written notice?**
A: [Date / not applicable / "you're reading the only one, you can quote it."]

**Q: [Other anticipated question]**
A: [...]

**If asked something not on this list:** [Escalation path — to whom, with what info, how fast.]
```

## Reviewing AI-generated security comms

A specific note because this skill is itself used by AI agents:

When an AI generates a security comm, do not ship it without a human reviewer for that audience. Specifically:
- Customer disclosures must go through legal review before sending
- Board updates should pass through CEO / CISO before going in the deck
- Executive memos should pass through someone who has watched the executive's decision-making style
- Engineering tickets can ship with lighter review but should not skip the verification step

AI-drafted security comms are most useful as the first draft, not the final draft. The skill cuts the time-to-first-draft from 90 minutes to 10; it does not eliminate the review loop.

## Boundaries

- This skill produces communication artifacts; it does not authorize disclosure
- Customer-facing breach disclosure has legal, regulatory (GDPR Article 33, HIPAA Breach Notification Rule, state breach-notification laws, SEC 8-K disclosure for material incidents at public companies), and contractual dimensions — a draft is not a sent message
- Refuse to draft communications designed to mislead — including downplaying material impact, attributing blame falsely, or characterizing accepted-risk findings as resolved
- Do not draft disclosures naming individual customers or providing PII about them without authorization
- For incidents involving law enforcement involvement (ransomware payments, nation-state attribution), the comms strategy is determined with counsel — this skill produces drafts for the named-audience side, not the law-enforcement side

## References

- "Crafting the InfoSec Playbook" — Bollinger / Enright / Valites (the communication chapter)
- SANS — Communicating with Executives reports (annual)
- "The Manager's Path" — Camille Fournier (on writing for non-technical audiences)
- SEC Final Rule on Cybersecurity Risk Management, Strategy, Governance, and Incident Disclosure (2023) — material-incident disclosure timing
- GDPR Article 33 (breach notification timing — 72 hours to supervisory authority)
- HIPAA Breach Notification Rule (60 days to affected individuals)
- ENISA — Crisis Communication Guidance
- "Cybersecurity Incident Response: How to Contain, Eradicate, and Recover from Incidents" — Eric C. Thompson
