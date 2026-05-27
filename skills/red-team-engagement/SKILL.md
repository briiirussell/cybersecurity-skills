---
name: red-team-engagement
description: "Plan, scope, and execute an authorized red-team engagement — distinct from a penetration test. Covers engagement methodology, assumed-breach scenarios, ATT&CK emulation plans, rules of engagement, deconfliction with the blue team, post-engagement debriefs, and the program-level work that makes red teams actually improve defenses. Use when the user mentions 'red team,' 'red team engagement,' 'red teaming,' 'adversary emulation,' 'ATT&CK emulation,' 'assumed breach,' 'purple team exercise,' 'tabletop with technical execution,' 'red team scope,' 'rules of engagement,' 'red team RoE,' 'deconfliction,' 'red team debrief,' or wants to design or run a red-team engagement against systems with authorization."
allowed-tools: Read, Write, Bash, Grep, Glob, WebSearch
---

# Red Team Engagement — Authorized Adversary Emulation

This skill is for **planning and executing an authorized red-team engagement against systems and an organization that has explicitly contracted for it**. It is distinct from a penetration test (technique-focused; see `web-pentest`) and from threat hunting (defensive; see `threat-hunting`). A red-team engagement is multi-week, objective-based, often assumed-breach, and explicitly tries to test the blue team's detect-and-respond capability — not just to find vulnerabilities.

This is the most dual-use skill in this catalog. The skill refuses to help conduct unauthorized adversary simulation, regardless of how the request is framed. The authorization check below is enforced strictly.

## Authorization Check — required before any planning or execution

Before working with this skill at all, confirm:

1. **Written authorization** for this specific engagement, against this specific target, signed by an executive with authority to grant it. The "get-out-of-jail" letter — a physical / digital document the team can produce if challenged
2. **Defined scope** — what systems, what time windows, what techniques are in / out of scope
3. **Identified target organization owns the target systems** — not a third party (vendor, customer, sub-tenant) whose authorization has not been obtained
4. **Defined success criteria** — what does this engagement need to demonstrate or test
5. **Identified deconfliction contact** — a single internal person who can pause / abort the engagement and answer "is this you?" when the blue team finds activity
6. **Legal review on file** — engagement contract or internal authorization reviewed by counsel, including for any controlled-data exposure
7. **Communication plan for unintended impact** — what happens if production is affected, how is it reported, how fast

If any of the above is missing or unclear, **stop**. Ask the user to confirm. Do not proceed with planning, technique selection, or any execution work.

If the user describes a target that does not appear to belong to them or to a contracted client, refuse — this is not a misunderstanding to be cleared up by adding "for educational purposes" or "in a CTF." The skill refuses to help simulate an attack on systems whose authorization is not present.

## What red-team engagements are for (and what they are not for)

Red-team engagements exist to **test the security program's response capability** — not just to find vulnerabilities. A good red-team engagement answers questions like:

- If an attacker gets initial access, how long until the blue team notices?
- When the blue team notices, how fast and how completely do they contain it?
- Are the documented incident-response procedures actually used?
- Do detections that exist in theory actually fire in practice?
- Can a determined adversary escalate to the named crown-jewel objective?

Red-team engagements are **not for**:

- Vulnerability discovery — pentests do that with much less overhead
- Compliance check-box — engagements are designed to teach, not to pass
- Performance reviews — using a red-team engagement to evaluate individual blue-team employees creates incentive problems that distort everyone's behavior

If the goal is "find vulnerabilities," use `web-pentest` or the relevant audit skill. If the goal is "test whether our detection and response actually works," this is the right skill.

## Engagement model — three flavors

| Model | Description | When to use |
|---|---|---|
| **External red team** | Engagement starts from outside the perimeter; no initial foothold | Mature programs testing the full attack chain end-to-end |
| **Assumed breach** | Engagement starts from a granted initial foothold (workstation, credentials, low-privilege account) | When the perimeter is well-tested already and the question is post-compromise containment |
| **Purple team** | Red and blue work side-by-side; red executes technique, blue verifies detection live | Early in detection-engineering maturity; high learning rate |

Assumed-breach is the most common modern engagement model — the value-per-week is highest because almost every real breach starts with the perimeter already past. Pure external red teams are valuable but expensive in calendar time.

## Engagement lifecycle

### Phase 0 — Pre-engagement (4-8 weeks before kickoff)

**Scoping with the client / sponsor:**

- **Objectives** — what crown-jewel access or capability does the engagement need to demonstrate? "Access customer data at rest" is concrete; "find what you can" is not
- **In-scope assets** — specific environments, specific subnets, specific applications. List by name, not by description
- **Out-of-scope assets** — explicitly named. Third-party SaaS, customer data of named accounts, specific production systems, executive personal accounts, regulated data the contract does not cover
- **Time window** — engagement window with start and end dates. Tighter windows force focus; longer windows allow assumed-breach scenarios to play out
- **Techniques out of scope** — what the team will NOT do regardless of value. Common: destructive techniques, modification of customer data, mass-exfiltration of real customer data, social engineering of named executives, physical access without separate authorization
- **Trusted-agent ("white cell") identification** — minimum number of internal people who know the engagement is happening. Typically 2-4: executive sponsor, security leadership, deconfliction contact, legal
- **Reporting cadence** — daily standup, weekly checkpoint, end-of-engagement debrief
- **Communication channels** — secure out-of-band (Signal, encrypted email, dedicated bridge) so that the engagement does not leak to the blue team during execution

**Documentation deliverables before kickoff:**

- Signed Rules of Engagement (RoE) — the contract between the red team and the sponsor
- Get-out-of-jail letter (physical and digital), signed by an authorized executive
- Engagement plan with objectives, scope, techniques planned (per-objective; not a complete attack list)
- Communication / escalation matrix

### Phase 1 — Reconnaissance and intelligence (per the engagement type)

For external engagements, leverage `recon` and `osint-recon`. For assumed-breach engagements, this phase is internal recon from the granted starting position.

The output is a *target map* — the systems, accounts, and pivots the team will work through to reach the objective.

### Phase 2 — Execution

Following an ATT&CK emulation plan tailored to the engagement.

**Emulation plans** are published playbooks of how specific threat actors operate. Use them as starting points, not scripts:

- **MITRE ATT&CK Emulation Plans** — open-source, threat-actor-specific (APT29, FIN6, FIN7, menuPass, OilRig, Carbanak, Sandworm, etc.). Available at `attack.mitre.org/resources/adversary-emulation-plans/`
- **CALDERA** — automated adversary emulation framework from MITRE; runs ATT&CK plans against a target environment
- **Atomic Red Team** — short, focused technique tests (one ATT&CK technique per "atomic"). Useful for purple-team exercises

The engagement progresses through the kill chain — initial access (for external) or post-foothold execution (for assumed breach), persistence, privilege escalation, defense evasion, credential access, discovery, lateral movement, collection, exfiltration (simulated — see boundaries) — toward the named objective.

**Operational notes:**

- Every action logged with timestamp, technique, target, and observed effect — for the eventual debrief
- The deconfliction contact answers when the blue team finds the engagement — to pause if escalation risk, to confirm and continue if not
- No destructive techniques unless explicitly authorized — and even then, only against systems that can be safely restored
- Real data is never exfiltrated — use synthetic markers (specific filenames, specific hash values) so blue can verify what was accessed without the team actually moving customer data
- Engagement pauses if the blue team's response would impact real customer service — the engagement is not worth a real outage

### Phase 3 — Debrief and reporting

The most under-invested phase, and the one that determines whether the engagement actually improves defenses.

**Same-day debrief (within 24 hours of engagement end):**
- Red team walks through the timeline of actions
- Blue team walks through what they saw, when they saw it, what they did
- Gaps between the two are the highest-value findings (red did X, blue saw nothing)

**Full written report (within 2-4 weeks):**

```markdown
# Red Team Engagement Report
## Engagement: [name]
## Sponsor: [executive sponsor]
## Engagement window: [start - end]
## Engagement type: External / Assumed Breach / Purple
## Authors: [red team leads]

### Executive summary
[3-5 paragraphs — were objectives achieved, what the blue team's detection-and-response posture looks like, top 3-5 systemic recommendations]

### Engagement timeline
[Red-team actions with timestamps and ATT&CK technique IDs]

### Blue-team observations
[For each red-team action, what the blue team saw, when, and how they responded — or did not]

### Detection coverage analysis
[Map of techniques used vs detections that did / should have fired]

### Findings
| ID | Severity | Category | Description |
|----|----------|----------|-------------|

(Categories: Detection gap, Response gap, Privileged-access exposure, Lateral-movement enabler, Crown-jewel access path, Compensating control reliance)

### Per-finding detail
[Technique used, what was achieved, what the blue team did / didn't see, recommended remediation]

### Recommendations
[Prioritized — usually 5-10 items mapping to specific systemic improvements, not point fixes]

### What the engagement did NOT cover
[Honesty about what was out of scope and where coverage gaps remain]
```

### Phase 4 — Improvement and revalidation

Recommendations from the report become work items. The red team's value compounds when:

- High-severity recommendations are tracked to closure (typically: detection rules added per `siem-detection`, response runbooks updated per `soc-operations`, control improvements per the audit skills)
- Specific findings are revalidated 6-12 months later, ideally as a purple-team exercise
- Lessons feed `breach-patterns` and `incident-triage` runbooks

A red team that finds the same problem twice is a budget that was wasted the second time.

## Rules of Engagement (RoE) — what goes in the document

The RoE is the contract. It must be specific.

| Section | What it specifies |
|---|---|
| **Authorization** | Who authorized this engagement, when, with what authority |
| **Scope — in** | Specific systems, accounts, environments, applications by name |
| **Scope — out** | Explicitly excluded — third parties, regulated data, named accounts, specific production systems |
| **Techniques in scope** | Categories of technique permitted (e.g., "credential capture in named test environments") |
| **Techniques out of scope** | Categories of technique not permitted (e.g., "no destructive techniques," "no social engineering of named executives," "no exploitation of vendor systems") |
| **Time window** | Start date, end date, blackout periods (e.g., "no engagement activity during quarterly close") |
| **Data handling** | What happens to data discovered during the engagement — destruction timelines, encryption requirements, exfiltration markers |
| **Reporting cadence** | Daily / weekly / end-of-engagement |
| **Deconfliction contact** | Single named individual + backup + 24/7 contact path |
| **Stop conditions** | When the engagement pauses or aborts — production outage caused, regulatory event triggered, unintended scope crossed |
| **Get-out-of-jail letter** | Format, distribution, contact for verification |

## Boundaries

This is the most consequential boundaries section in this catalog. Read it.

- **Authorization is the floor, not the ceiling.** A signed authorization does not make every technique acceptable — the contract still bounds what is permitted. When the user is unsure, the answer is "ask the sponsor before proceeding"
- **Unauthorized targets are refused.** No "hypothetical" engagements against systems the user does not own or control. No "what would you do if" against named third parties. The skill is for authorized engagements, not for adversary-thinking exercises against arbitrary targets
- **Destructive techniques are off by default.** Even when in-scope, prefer non-destructive alternatives — simulated ransomware (file enumeration without encryption), demonstrated persistence (artifact placement without execution), proof-of-access (read-only)
- **Real customer data is not exfiltrated.** Use synthetic markers. The blue team verifies what was accessed by what was *marked*; the red team does not move real data
- **Pause for safety.** Engagement pauses when real-world impact occurs — outage, data exposure to unauthorized parties, regulatory notification trigger. Restart only after sponsor approval
- **Refuse to help build offensive tooling.** This skill plans engagements that use existing techniques and tooling responsibly. It does not help write new malware, new C2 frameworks, or new evasion-by-default tooling. Tooling decisions are upstream of this skill
- **Refuse to help with social engineering against people who have not consented to be tested.** Social engineering can be in-scope, but the targets must be people whose role accepts engagement testing (typically: employees broadly, with explicit exclusions). Refuse if the request is to phish a specific individual outside the consent envelope
- **Refuse if the request looks like an internal red team being used to surveil specific employees.** Red teams test systems and processes, not people
- **Findings are findings, not weapons.** A red-team report that produces remediation work is value-positive; one that becomes ammunition in internal politics is value-negative. Authors and reviewers carry responsibility for keeping it the former

## References

- **MITRE ATT&CK Framework** — `attack.mitre.org`
- **MITRE ATT&CK Adversary Emulation Plans** — `attack.mitre.org/resources/adversary-emulation-plans/`
- **MITRE CALDERA** — automated adversary emulation
- **Atomic Red Team** — `github.com/redcanaryco/atomic-red-team`
- **TIBER-EU** (Threat Intelligence-Based Ethical Red-teaming) — European framework for financial-sector red teaming
- **CBEST** (UK Bank of England) — UK financial-sector red-team framework
- **NIST SP 800-115** (Technical Guide to Information Security Testing and Assessment)
- **PTES** (Penetration Testing Execution Standard) — methodology source, with red-team-relevant phases
- **Red Team Field Manual** — Ben Clark — operator-oriented reference
- **Adversary Tradecraft and the Importance of Cyber Threat Intelligence** — MITRE / CTID writeups
- **CTID (Center for Threat-Informed Defense)** — `ctid.mitre.org` — open-source emulation content
- **"Red Team Development and Operations"** — Joe Vest, James Tubberville
- **"How to Hack Like a Ghost"** — Sparc Flow (narrative-style; useful for understanding the model of an extended engagement)
