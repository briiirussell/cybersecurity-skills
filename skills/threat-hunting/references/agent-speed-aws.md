# Agent-speed cloud intrusions (AWS) — perishable IOCs

Companion to the "Agent-speed cloud intrusions (AWS)" hunt in `SKILL.md`. The hunts there do not depend on this list. These indicators go stale: user agents are trivial to change, and the addresses were hosting that week. Treat a hit as a lead, then run the burst hunts. Never alert on a user agent alone.

Checked against the issue's cited sources on 2026-11-13. The Datadog IOC table below was re-read from the article on 2026-11-15. No CVE. AWS's statement, as quoted by BleepingComputer, was that its services were not compromised.

## What was confirmed

| Claim | Status | Source |
|---|---|---|
| AntiFox-linked infrastructure used valid IAM users and an assumed EC2 role; hundreds of cross-service calls in about 30 minutes; mostly denied, with successes embedded, including `GetSecretValue` on a production secret | Confirmed, researcher primary | Arctic Wolf Labs alert pack (2026-11-10) |
| S3 `ListBuckets` / `ListObjects` / `ListObjectVersions` / `HeadObject` / `GetObject`, then `CopyObject` / `DeleteObject`, with a valid identity | Confirmed | Arctic Wolf Labs |
| IIS foothold via an ASPX web shell under `w3wp.exe`, plus `web.config` parsing. The initial vulnerability was not identified. Some intrusions began with an AWS credential obtained by unknown means | Confirmed | Arctic Wolf Labs |
| AntiFox is a fork of ARTEX 0.1.1 | Reported, not a researcher primary | BleepingComputer |
| ARTEX: anonymous S3 reads first, `FilterLogEvents` with `limit` 1000 hunting `AKIA` and passwords, Cognito self-signup, then failed enumeration | Confirmed, researcher primary | Datadog Security Labs (2026-11-09) |

## AntiFox (Arctic Wolf, November 2026)

Addresses and the user agent are defanged or quoted as published. Confirm them against the pack before you block anything; hosting gets reassigned.

| Indicator | Type |
|---|---|
| `47.79.4[.]33` | Source IP |
| `8.208.101[.]210` | Source IP |
| TCP/8787 | Console port on the hosted platform |
| `Boto3/1.43.125` | User agent (raises confidence only) |

## ARTEX (Datadog, November 2026)

| IOC | Type | ASN / note |
|---|---|---|
| `169.128.55[.]214` | IP | Caelus Technology LLC — hosting |
| `154.64.252[.]77` | IP | NetLab Global — hosting |
| `154.36.136[.]197` | IP | NetLab Global — hosting |
| `154.36.136[.]23` | IP | NetLab Global — hosting |
| `102.216.154[.]102` | IP | Vilcom Networks Limited — ISP, Kenya |
| `82.158.88[.]233` | IP | Zenixcloud — hosting |
| `88.229.22[.]232` | IP | TTNet A.S. (Turk Telekom) — ISP, Turkey |
| `103.54.154[.]40` | IP | Zeofast Network — hosting |
| `103.54.154[.]32` | IP | Zeofast Network — hosting |
| `45.145.228[.]25` | IP | Yecaoyun / LUCIDACLOUD LIMITED — hosting |
| `artex-readonly/1.0` | User agent | |
| `artex-pentest/1.0` | User agent | |
| `artex-audit/1.0` | User agent | |
| `Mozilla/5.0 ARTeX` | User agent | |
| `artex-spawn/1` | User agent | |
| `artex-verify/1.0` | User agent | |
| `Mozilla/5.0 (Windows NT 10.0; Win64; x64) ARTeX-authorized-pentest` | User agent | |
| `Mozilla/5.0 (X11; Linux x86_64) artex-verify/1.0` | User agent | |
| `artex-i21861-canary` | User agent | |
| `ARTEX-worker/1.0` | User agent | |

Placeholder object keys seen just before a guess burst: `zzz_nonexistent_abc.txt`, `Notexist-xyz`. `FilterLogEvents` calls used `limit` 1000 (the API allows 10000).

## Remediation (link, do not duplicate)

- S3 versioning, Object Lock, and data events on sensitive buckets: `cloud-audit`.
- IMDSv2 with a hop limit of 1, and app roles with no account-wide `List*`: `cloud-audit` and `iam-audit`.
- After a web compromise, rotate everything the app config held and revoke sessions before issuing new keys: `incident-triage`. What a leaked key is allowed to do is a separate control (issue #249).

## Sources

- [Arctic Wolf Labs alert pack](https://github.com/rtkwlf/wolf-tools/tree/main/pack_alerts/202611-antifox-alibaba-hosted-platforms-facilitate-web-cloud-intrusions) (2026-11-10)
- [Datadog Security Labs, "On the hunt for ARTEX"](https://securitylabs.datadoghq.com/articles/artex-agentic-attacks-aws-environments/) (2026-11-09)
- [BleepingComputer, including the AWS statement](https://www.bleepingcomputer.com/news/security/hackers-use-antifox-ai-agents-in-aws-credential-theft-attacks/)
- [The Hacker News](https://thehackernews.com/2026/11/antifox-ai-pentesting-platform-linked.html)
