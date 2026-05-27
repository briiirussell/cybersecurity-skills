---
name: siem-detection
description: "Engineer and audit SIEM detection rules — log source coverage, Sigma / KQL / SPL / Elastic query authoring, MITRE ATT&CK mapping, false-positive tuning, and detection-as-code workflows. Use when the user mentions 'SIEM,' 'detection engineering,' 'detection rules,' 'Sigma,' 'KQL,' 'SPL,' 'Splunk,' 'Sentinel,' 'Elastic,' 'Wazuh,' 'Chronicle,' 'detection-as-code,' 'MITRE ATT&CK mapping,' 'log coverage,' 'alert tuning,' 'use case development,' or needs help building or improving security detections."
allowed-tools: Read, Write, Bash, Grep, Glob, WebSearch
---

# SIEM Detection — Detection Engineering

Build, audit, and maintain SIEM detection content — the rules that fire alerts. Distinct from `incident-triage` (responds when alerts fire) and from `soc-operations` (runs the SOC that triages alerts). This skill is the engineering layer: log coverage, rule authoring, tuning, and detection-as-code workflows.

Cross-references: `incident-triage` for what happens after the alert, `threat-hunting` for proactive hypothesis-driven hunts that often graduate into detection rules, `breach-patterns` for detection ideas pulled from public breach disclosures, `soc-operations` for the alert-triage operations on top of the detections engineered here.

## Scope

This skill covers:
- Log source coverage assessment ("are we even collecting the events we'd need to detect X?")
- Rule authoring across major SIEM query languages (Sigma, KQL, SPL, Elastic ES|QL, Chronicle YARA-L)
- MITRE ATT&CK mapping — every rule tagged with technique IDs for coverage analysis
- Detection-as-code workflows (rules in Git, CI tests, deployment automation)
- Alert tuning workflow — reducing false positives without losing true positives
- Coverage gap analysis using ATT&CK Navigator

This skill does NOT cover:
- Live alert triage (that's `incident-triage`)
- Building a SOC team or alert escalation criteria (`soc-operations`)
- Active threat hunting (`threat-hunting`)

## Methodology

### Step 1: Map log sources to ATT&CK coverage

Before writing any rule, audit what you can detect.

**Categorize log sources by what they observe:**

| Category | Sources | Observes |
|---|---|---|
| Endpoint | EDR (CrowdStrike, SentinelOne, Defender), Sysmon, osquery | Process exec, file write, network, registry, parent-child |
| Network | Zeek/Bro, Suricata, NSM, firewall, DNS query logs | Connections, protocols, DNS queries, TLS metadata |
| Identity | Okta, Entra ID, AD, Auth0, GCP/AWS sign-in | Authentications, MFA, group changes, role assignments |
| Cloud | CloudTrail (AWS), Audit Logs (GCP), Activity Log (Azure) | API calls — what was created/changed/deleted |
| Application | App logs, WAF logs, load balancer logs, gateway logs | Request URLs, status codes, auth outcomes |
| SaaS | Google Workspace, M365, Salesforce, GitHub audit | Admin actions, sharing, sensitive doc access |

**Run a gap check:**
- Pull the [MITRE ATT&CK Enterprise matrix](https://attack.mitre.org/matrices/enterprise/)
- For each technique relevant to your environment, ask: which of my log sources would surface this?
- Techniques with NO source mapped are blind spots — write them down before writing any rules

**Common blind spots:**
- Endpoint logs but no command-line argument capture (most Windows event logs default to logging only the binary, not the args)
- Cloud audit logs collected but `ReadOnly: true` events filtered out — pre-attack recon invisible
- No SaaS audit logs — every modern attack involves a SaaS pivot at some point
- App logs without correlation IDs — can't connect "WAF saw payload" to "app processed payload"

### Step 2: Pick the right detection model per case

Not every threat needs a SIEM rule. Match the detection model to what you're detecting.

| Threat character | Best model | Example |
|---|---|---|
| Known IOC (hash, IP, domain) | Threat-intel lookup | Sysmon hash matches known malware |
| Known pattern (specific command, specific path) | Signature rule | `powershell.exe -enc <base64>` |
| Known anomaly (behavior outside baseline) | Statistical detection | Service account suddenly authenticating from new geography |
| Sequence of events | Correlation rule | Failed logon → success → privilege change in 5 min |
| Novel / never-seen-before | Threat hunting (see `threat-hunting`) | Hypothesis-driven SIEM search |
| Insider abuse | UEBA / risk scoring | Cumulative risky behaviors weighted over time |

Signature rules are cheapest to write and easiest to tune; statistical detections need baseline data and produce more false positives in the first month.

### Step 3: Write the rule

#### Use Sigma as the source of truth where possible

Sigma is the cross-SIEM detection format. Write the rule in Sigma; auto-convert to your backend via `sigmac` / `sigma-cli` / pySigma. Even if you only target Splunk today, future-you will thank you.

```yaml
title: AWS IAM CreateUser Followed by AttachUserPolicy
id: <UUID>
status: experimental
description: Detects an identity creating a new IAM user and immediately attaching an admin policy
references:
  - https://attack.mitre.org/techniques/T1136/003/
author: <name>
date: 2026-05-26
tags:
  - attack.persistence
  - attack.t1136.003
logsource:
  product: aws
  service: cloudtrail
detection:
  create_user:
    eventName: CreateUser
  attach_policy:
    eventName: AttachUserPolicy
    requestParameters.policyArn|contains: 'Administrator'
  timeframe: 10m
  condition: create_user and attach_policy
falsepositives:
  - Legitimate provisioning workflows (CI roles that bootstrap admin accounts)
level: high
```

#### KQL (Microsoft Sentinel / Defender / Azure Monitor)

```kql
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType != 0
| summarize FailureCount = count() by UserPrincipalName, IPAddress, bin(TimeGenerated, 5m)
| where FailureCount > 10
| join kind=inner (
    SigninLogs
    | where TimeGenerated > ago(1h)
    | where ResultType == 0
) on UserPrincipalName, IPAddress
| project TimeGenerated, UserPrincipalName, IPAddress, FailureCount
```

(Failed logons spike on one user/IP, then a success on the same user/IP — classic password spray success.)

#### SPL (Splunk)

```spl
index=aws sourcetype=aws:cloudtrail
  (eventName=CreateUser OR eventName=AttachUserPolicy)
| transaction userIdentity.arn maxspan=10m
| where like(eventName, "%CreateUser%") AND like(eventName, "%AttachUserPolicy%")
| table _time, userIdentity.arn, eventName, requestParameters
```

#### ES|QL (Elastic)

```esql
FROM logs-aws.cloudtrail-*
| WHERE event.action == "CreateUser" OR event.action == "AttachUserPolicy"
| STATS create_count = COUNT(*) BY user.arn, event.action
| WHERE create_count > 0
```

(Use the LookML / KQL / SPL / ES|QL that matches your SIEM, but author the canonical version in Sigma.)

### Step 4: Map to MITRE ATT&CK

Every rule should tag at least one ATT&CK technique. Coverage maps roll up to ATT&CK Navigator (`navigator.mitre-attack.org`):

- Export your rules with their ATT&CK tags
- Render onto the Navigator matrix
- Identify coverage gaps by tactic — "we have nothing for Initial Access via Phishing" is more actionable than "we need more rules"

The Navigator JSON format is open; building this report from your rules-as-code repo is a few hundred lines of Python and pays for itself the first time someone asks "what do we detect?"

### Step 5: Tune

The false-positive lifecycle:

1. **Deploy the rule with `level: experimental`** for 1-2 weeks
2. **Review every fire** — true positive, false positive, suppressible?
3. **For each FP, ask:** can I narrow the rule (more specific filter) or add a tuning exception (allow-list specific known-good)?
4. **Track the ratio** — if FPs are > 80% after tuning, the detection model is wrong (signature might need to be statistical, or vice versa). Don't paper over a bad model with 100 allow-list entries.
5. **Promote to `level: high` / production** only after FP rate is acceptable

Rules that have never fired are also a signal — either the log coverage is broken, the query is wrong, or the threat truly hasn't occurred. Verify which by running a deliberate-test event through the system.

### Step 6: Detection-as-code

Rules live in Git, not in the SIEM console.

```
detections/
├── aws/
│   ├── credential-access/
│   │   └── iam-create-user-attach-admin.yml
│   └── ...
├── windows/
├── linux/
└── identity/
    └── okta-password-spray.yml
.github/workflows/
└── detection-ci.yml
```

CI checks:
- Sigma validates (`sigma-cli check`)
- ATT&CK tag present and resolvable
- Description and references fields non-empty
- Backend translation succeeds (`sigma convert -t splunk` etc.)
- Optional: replay the rule against a known-good event store and assert hit count

Deployment: post-merge, push rules to the SIEM via API. Roll back via Git revert.

## Output Format

**Coverage assessment:**

```markdown
# SIEM Detection Coverage
## Environment: [name]
## Date: [date]

### Log sources mapped
| Source | Status | Notes |
|---|---|---|

### ATT&CK coverage
| Tactic | Techniques covered / total | Blind spots |
|---|---|---|

### Rule inventory
| Rule | ATT&CK | Severity | Status | Last fired |
|------|--------|----------|--------|------------|

### Tuning queue
[Rules in experimental / needing FP triage]

### Recommended next 30 days
[Prioritized — usually 3-5 items]
```

**Per-rule documentation lives with the rule** (Sigma YAML), not in a separate runbook. The `description`, `references`, and `falsepositives` fields are the runbook.

## Boundaries

- Detection content for your own environment, or environments where the user has explicit authorization
- Refuse to write evasion rules or detections designed to flag legitimate security tools
- Detections that intentionally surveil employees beyond what HR/legal have approved are out of scope — escalate to the user
- Provide enough context with each rule that the analyst who triages the alert understands what to do; rules without that context produce alert fatigue

## References

- MITRE ATT&CK Enterprise matrix
- MITRE ATT&CK Navigator
- Sigma rules repo (SigmaHQ/sigma)
- Florian Roth's "Detection Engineering" writings
- Splunk Security Essentials / Microsoft Sentinel content hub / Elastic detection rules repo
- "Detection Engineering Maturity Matrix" (Florian Roth)
- "The Pyramid of Pain" (David Bianco) — IOC value hierarchy
- NIST SP 800-92 (Computer Security Log Management)
