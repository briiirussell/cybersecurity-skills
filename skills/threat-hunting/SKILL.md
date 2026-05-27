---
name: threat-hunting
description: "Conduct proactive, hypothesis-driven threat hunts — search SIEM / EDR / logs for adversaries who haven't tripped an alert yet. ATT&CK-driven, hypothesis-based methodology. Use when the user mentions 'threat hunting,' 'proactive hunt,' 'TaHiTI,' 'PEAK framework,' 'MITRE ATT&CK hunt,' 'hypothesis-driven hunt,' 'hunt hypothesis,' 'living off the land,' 'LOLBins,' 'beaconing,' 'lateral movement detection,' 'data staging,' 'persistence hunting,' or wants to find threats that have evaded existing detections."
allowed-tools: Read, Write, Bash, Grep, Glob, WebSearch
---

# Threat Hunting — Proactive Adversary Detection

Hunt for adversaries who are already inside but haven't tripped an alert. Distinct from `incident-triage` (reactive, alert is firing) and from `siem-detection` (engineer rules so future alerts fire). This skill is the *proactive* layer — assume something has slipped through, look for it.

Hunting is hypothesis-driven, not browse-driven. "Let's look around the SIEM" is not hunting; "let's check for the specific pattern of T1059.001 (PowerShell) being launched by Office processes" is.

Cross-references: `siem-detection` (queries you write here often graduate to detection rules), `incident-triage` (what to do if a hunt confirms a finding), `breach-patterns` (a rich source of hunt hypotheses), `disk-forensics` (deeper analysis on confirmed hits).

## Methodology — PEAK framework

The PEAK (Prepare, Execute, Act, Knowledge) framework from Splunk SURGe — the most actionable hunting methodology I've seen.

### Step 1: Prepare

Form the hypothesis. Strong hypotheses share three properties:

1. **Specific** — names a technique, log source, and expected artifact
2. **Testable** — describes what evidence would confirm or deny
3. **Bounded** — has a defined time window and scope

**Bad hypothesis:** "Look for anomalies in the SIEM"
**Good hypothesis:** "Within the last 30 days, no service account should have run interactive PowerShell with `-encodedCommand` flag (T1059.001 + T1027). Search Sysmon event 1 for parent process = service-account-launched scheduled task, child = `powershell.exe`, command line contains `-enc` or `-encodedcommand`."

Hunt hypothesis sources, ranked by yield:

| Source | Yield | Effort |
|---|---|---|
| Recent incident (yours or peer's) | High | Low — pattern is concrete |
| `breach-patterns` skill catalog | High | Low — generalizes from public breaches |
| MITRE ATT&CK technique you don't have a detection for | Medium | Medium — read the technique, design the hunt |
| Threat intel report (CrowdStrike, Mandiant, vendor reports) | Medium | Medium — current patterns |
| Anomaly: "this number went up — why" | Low | Low — often FP, occasionally gold |

### Step 2: Execute

Run the hunt. Three execution patterns:

**Pattern A — Pivot from indicator.** Start with a specific IOC (IP, hash, domain) and look for any host or user that touched it.

```kql
// Sentinel — pivot from a suspicious IP across all log sources
union *
| where TimeGenerated > ago(90d)
| where contains("198.51.100.42")
| project TimeGenerated, Type, Computer, _ResourceId
```

**Pattern B — Pivot from technique.** Start with an ATT&CK technique and look for any host doing that.

```spl
// Splunk — T1547.001 Registry Run Keys persistence
index=sysmon EventCode=13 
  TargetObject="*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*"
| stats values(Details) by Computer, User
| where len(values(Details)) > 1
```

**Pattern C — Anomaly hunt.** Establish a baseline; look for outliers.

```kql
// Sentinel — service accounts authenticating from new geographies
SigninLogs
| where TimeGenerated > ago(30d)
| where UserType == "Service"
| summarize Countries = make_set(Location) by UserPrincipalName
| where array_length(Countries) > 1
```

### Step 3: Act

For every hit, three possible outcomes:

| Outcome | Action |
|---|---|
| Confirmed malicious | Escalate to `incident-triage` immediately |
| Confirmed benign | Document and move on |
| Unknown / unable to confirm | Deepen investigation (host artifacts, network traffic, user interview) |

Don't leave hits in the "unknown" state. Either resolve, or hand off with a documented next-step.

### Step 4: Knowledge

The hunt's value isn't the one hit — it's the artifacts.

For each hunt:

- If you found something, **write a detection rule** so future occurrences fire automatically (see `siem-detection`)
- If you didn't find anything, **document the hunt** — query, scope, time window, conclusion. Future hunters won't re-do it
- If the hunt was hard because of missing log coverage, **document the gap** and create a backlog item to fix log ingestion

Hunts that don't produce artifacts are work without compounding return. The whole point of the methodology is to turn every hunt into either a rule, a documented dead-end, or a coverage improvement.

## High-yield hunt catalog

### Persistence

- **Scheduled tasks created outside business hours** — `schtasks.exe /create` from Sysmon event 1 + EventCode 4698 from Windows Security
- **Run-key persistence** — registry writes to `HKCU\...\Run`, `HKLM\...\Run`, `HKCU\...\RunOnce`
- **Service installation outside known software-install windows** — EventCode 7045
- **WMI persistence** — `__EventFilter` and `CommandLineEventConsumer` subscriptions
- **Login items / launch daemons (macOS)** — `/Library/LaunchDaemons/*.plist`, `~/Library/LaunchAgents/*.plist`
- **Cron / systemd timers (Linux)** — `/etc/cron.*`, `/etc/systemd/system/*.timer`, user crontabs

### Defense evasion

- **PowerShell with `-EncodedCommand`** — base64-encoded scripts are evasion 80% of the time
- **`certutil.exe -decode`** — LOLBin used to decode dropper payloads
- **Sysmon EventCode 7 (Image loaded) for known-bad DLLs from non-standard paths**
- **Process executing from `%TEMP%`, `%APPDATA%`, `\Users\Public`** — non-standard exec paths
- **Command-line obfuscation patterns** — large amounts of `^`, backticks, `cmd /c echo y | ...`

### Credential access

- **LSASS access from unexpected processes** — Sysmon EventCode 10 with TargetImage = `lsass.exe` and SourceImage not in `[mssense.exe, NisSrv.exe, ...]`
- **`procdump.exe` or `comsvcs.dll` use** — process-dumping LOLBins
- **NTDS.dit access outside backup windows** — domain controller DB
- **AWS `GetSessionToken` or `AssumeRole` from new IPs** — credential capture pivot
- **OAuth consent grants for high-scope applications** — see `iam-audit`

### Discovery

- **`net group "Domain Admins"`** or equivalent enumeration commands
- **AD service ticket requests for high-value SPNs** (Kerberoasting prep) — EventCode 4769 with RC4 encryption
- **`whoami /all`, `quser`, `nltest /domain_trusts`** — situational awareness commands run by service accounts (humans rarely run these)
- **Cloud API listing — `ListBuckets`, `ListUsers`, `DescribeInstances` from unusual principals**

### Lateral movement

- **WMI execution to remote hosts** — Sysmon EventCode 1 with `wmic.exe` or `Invoke-WmiMethod`
- **PsExec / remote service creation patterns** — EventCode 7045 with random service name
- **Remote registry connections to unusual hosts**
- **SSH key reuse — one private key authenticating to many hosts in a short window**
- **AWS / GCP `AssumeRole` chains across accounts** — pivot detection

### Collection / staging / exfil

- **Large-volume reads from cloud storage by single principal** — unusual S3 / GCS access patterns
- **Archive creation patterns** — `Compress-Archive`, `7z.exe`, `tar`, `zip` operating on directories outside user home
- **DNS queries to recently-registered domains** — exfil over DNS or C2 beacon resolution
- **Outbound TLS to high-risk geographies** — depends on your organization's normal pattern
- **Beaconing patterns** — regular-interval connections (every N seconds ± jitter) to the same destination over hours

### Cloud-specific

- **IAM credential exfiltration patterns** — `GetCredentialReport`, `GenerateCredentialReport` from unusual principals
- **IMDS access from unusual processes / containers** — anything reaching `169.254.169.254` that isn't the cloud SDK
- **CloudTrail / Audit Log tampering attempts** — `StopLogging`, `DeleteTrail`, log-bucket access from non-logging principals
- **Cross-region resource creation by single principal in short window** — pivot or coin-mining setup

### Identity-provider-specific

- **OAuth app grants of high-scope permissions** (Google Workspace, M365) — adversary technique for persistence outside the user's password
- **MFA method enrollment from new device** — attacker registering their own MFA after stealing a session
- **Sign-ins from impossible geographies** — geolocation jumps that exceed travel time
- **Service-account authentication from new client / new IP** — service accounts should be predictable

## Tools

- **SIEM** — Splunk, Sentinel, Elastic, Chronicle, Sumo, Wazuh
- **EDR** — CrowdStrike (RTR), SentinelOne (deep visibility), Microsoft Defender (advanced hunting), Carbon Black
- **Sysmon** — open-source endpoint logging on Windows, output to SIEM
- **osquery** — SQL queries over endpoint state (cross-platform)
- **Velociraptor** — open-source live response and hunting framework (much more capable than free EDR)
- **Zeek** — network metadata for traffic analysis
- **MITRE ATT&CK Navigator** — coverage visualization
- **Hunt-Evil** — hunting playbook content (open-source)
- **MaxMind GeoIP** — geolocation lookup for IP-based hunts

## Output Format

```markdown
# Threat Hunt Report
## Hunt name: [descriptive — e.g., "Office process → encoded PowerShell"]
## Hypothesis: [specific, testable, bounded]
## Date range: [from - to]
## Hunter: [name]

### Methodology
- ATT&CK technique(s): [TXXXX.NNN]
- Data sources queried: [list]
- Query / queries:
  [the actual SIEM query]

### Findings
| Hit ID | Host / User / Resource | Outcome | Notes |
|--------|------------------------|---------|-------|

### Conclusion
- [Confirmed malicious / All benign / Inconclusive]
- [Confidence level — Low / Medium / High]

### Artifacts produced
- [ ] Detection rule added (link)
- [ ] Coverage gap documented (link)
- [ ] Negative-result documentation filed (link)

### Recommended follow-up
[Anything that needs deeper investigation, escalation, or future hunts]
```

## Boundaries

- Hunt only environments the user has authorization for
- Never query SIEM / EDR data outside the user's authority — even if the dataset is available, scope matters
- For confirmed-malicious findings, escalate to `incident-triage` immediately — do not continue hunting and risk tipping the adversary
- Live response actions (host isolation, account disablement) are incident response, not hunting — escalate
- Refuse to use threat-hunting techniques to surveil employees beyond what HR / legal has authorized
- Negative hunt results are valuable evidence, not failure — document and credit accordingly

## References

- PEAK Threat Hunting Framework (Splunk SURGe)
- TaHiTI (Targeted Hunting integrating Threat Intelligence) — Dutch model
- MITRE ATT&CK
- "The ThreatHunter Playbook" (Cyb3rWard0g) — open-source content
- Sigma rules repo — many rules can become hunt queries
- "Practical Threat Intelligence and Data-Driven Threat Hunting" — Valentina Costa-Gazcón
- David Bianco's "Pyramid of Pain" — IOC value hierarchy
- SANS FOR508 / FOR578 course materials
- Velociraptor community hunt content
