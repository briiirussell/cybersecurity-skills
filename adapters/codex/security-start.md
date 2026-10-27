# security-start

> Start here when a security ask is vague and no specific skill fits yet. Asks two or three questions about what you have (source code, a live site, a cloud setup, logs, a suspicious file, an auditor's request) and what's going on (building, shipping, an active incident, a compliance deadline), then hands off to the right skill or skills from this catalog, in order. It does no auditing itself. Use when the user says things like 'make this secure,' 'is this secure,' 'where do I start with security,' 'which security skill should I use,' 'security checkup,' 'what do we check,' 'secure my startup,' or 'help me with security' without naming a framework, a target or a tool. If the ask already names one (OWASP, a CVE, a workflow file, SOC 2, a phishing email, a pasted finding), use that skill directly instead.

# Security Start — Pick the Right Skill

Some security asks arrive with no shape: "make this secure", "where do I start?". This skill turns one into a plan of one
to three skills from this catalog, in order, and then gets out of the way. It doesn't audit anything itself.

Cross-references: every skill in the table below. The README's "Where to start" section is the long-form version of
this table.

## When to use

- The ask is vague: "is my app secure?", "help me with security", "what should we check first?"
- The user doesn't know which of the skills applies, or asks which one to use
- A quick look at the repo is enough to decide (package.json, Dockerfile, `.github/workflows/`, Terraform, an `.apk`)

**Not for:** any ask that already names its subject. Route those straight to the owning skill without this one: a
pasted finding → `finding-triage`; a CVE → `vuln-research`; "OWASP audit" → `owasp-audit`; a workflow file →
`cicd-security`; "SOC 2" → `control-audit`; "we've been hacked" → `incident-triage`.

## Authorization

- Read-only. This skill reads file names and manifests in the current repo to decide; it doesn't run tools or touch
  any system.
- The skills it hands off to carry their own authorization checks. Offensive skills (`recon`, `osint-recon`,
  `web-pentest`, `red-team-engagement`, `business-logic-testing`) need written authorization for the target. Say so
  when routing to them.

## Workflow

### Step 1 — Look before asking

If there's a repo, spend a minute on it before asking anything:

```bash
ls; ls .github/workflows 2>/dev/null
ls package.json requirements.txt pyproject.toml go.mod Cargo.toml Gemfile pom.xml 2>/dev/null
ls Dockerfile docker-compose.yml *.tf k8s helm 2>/dev/null
```

Note the language, frameworks, whether there's an API, CI, containers, IaC, an AI feature, a mobile app.

### Step 2 — Ask at most three questions

Only ask what Step 1 didn't answer:

1. **What do you have?** Source code, a deployed app you're allowed to test, cloud accounts, logs, a single finding, a
   suspicious file, a regulation or an auditor.
2. **What's happening?** Building something new, about to ship, an incident right now, a CVE wave, an audit date,
   general worry.
3. **Who's it for?** Just you, your engineers, or a board, a customer or an auditor.

An active incident skips the questions: go straight to `incident-triage`.

### Step 3 — Route

Pick from the table. Most asks need one skill, some two or three in sequence. Prefer the cheapest first step that gives
real evidence.

| Situation | Start with | Then |
|---|---|---|
| Active incident, breach, ransomware, account takeover | `incident-triage` | `disk-forensics`, `malware-triage`, `security-comms` |
| A suspicious file, attachment or binary | `malware-triage` | `incident-triage` if it ran |
| "Is my app secure?" with source code | `owasp-audit` | `api-audit` (APIs), `dependency-audit`, `secrets-audit` |
| An API (REST / GraphQL / RPC) | `api-audit` | `business-logic-testing` for money flows |
| Dependencies, CVEs in packages | `dependency-audit` | `vuln-research` for one CVE, `patch-sweep` for many repos |
| One specific CVE | `vuln-research` | `patch-sweep` |
| GitHub Actions or other CI | `cicd-security` | `secrets-audit` |
| Leaked keys, `.env` worries | `secrets-audit` | `iam-audit` for rotation and scope |
| C, C++ or Rust code | `native-code-review` | `fuzzing-harness` |
| Parsers or decoders that take untrusted bytes | `fuzzing-harness` | `native-code-review` |
| Crypto code, tokens, signatures | `crypto-audit` | |
| A mobile app | `mobile-audit` | `api-audit` for its backend |
| An AI feature, LLM or agent in the product | `prompt-injection` | `ai-risk-management` for governance |
| The AI coding agents, skills, MCP servers you use | `agent-supply-chain-audit` | `personal-opsec` |
| Cloud accounts or PaaS (Vercel, Heroku, ...) | `cloud-audit` | `iam-audit`, `container-audit` |
| Docker or Kubernetes | `container-audit` | `cloud-audit` |
| Identity, SSO, roles | `iam-audit` | |
| A live app to test (authorized) | `recon` | `web-pentest`, `business-logic-testing` |
| Adversary emulation program (authorized) | `red-team-engagement` | |
| Investigation from public sources (authorized) | `osint-recon` | |
| New feature or system design | `threat-modeling` | `owasp-audit` once it's built |
| Scanners in CI | `scanner-pipeline` | `finding-triage` |
| A finding to triage | `finding-triage` | `variant-analysis` for siblings |
| A bug that probably exists elsewhere | `variant-analysis` | `scanner-pipeline` to keep the rule |
| Logs but no SIEM | `log-watch` | `siem-detection` later |
| Detection rules, SIEM | `siem-detection` | `threat-hunting` |
| Hunting for something that didn't alert | `threat-hunting` | `siem-detection` |
| Running a SOC | `soc-operations` | |
| GDPR / CCPA / privacy | `privacy-engineering` | |
| Health data (HIPAA) | `hipaa-audit` | `privacy-engineering` |
| Payment cards (PCI DSS) | `pci-audit` | |
| SOC 2, ISO 27001, FedRAMP audit | `control-audit` | `csf-mapping` for crosswalks |
| Building a security program, board posture | `csf-mapping` | `security-comms` |
| Learning from public breaches | `breach-patterns` | the audit skill each lesson points at |
| The founder's own accounts and devices | `personal-opsec` | `secrets-audit` |
| Explaining security work to non-security people | `security-comms` | |

If two rows fit, pick the one closest to real evidence: code over policy, the deployed thing over the diagram.

### Step 4 — Hand off

Say which skill comes first and why in one line, then the next steps. Start the first skill straight away if the user
agrees. Don't summarize what the skills will find.

## Output Format

```markdown
## Security start
**What you have:** [source / live app / cloud / logs / file / audit]   **What's happening:** [situation]

1. `skill-name` — [why this first, one line]
2. `skill-name` — [what it adds after step 1]
3. `skill-name` — [optional]

[One line on authorization, if any step is offensive.]
```

## Boundaries

- Routing only. No findings, no severities, no tool runs.
- Never route an offensive skill without saying it needs written authorization for the target.
- If nothing in the catalog fits, say so plainly rather than stretching a skill.

## References

- README "Where to start" and the skill map (this table is a condensed version)
- Router skills elsewhere informed the shape: obra/superpowers `using-superpowers` (MIT), addyosmani/agent-skills `using-agent-skills` (MIT), and the foundation skill in coreyhaines31/marketingskills (MIT). Paraphrased, nothing copied.