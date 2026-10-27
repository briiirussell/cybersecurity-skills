---
name: cloud-audit
description: "Audit cloud infrastructure (AWS, GCP, Azure) and PaaS deployment platforms (Vercel, Netlify, Heroku, Render, Railway, Fly) for misconfigurations, excessive permissions, stale or manual production deploys, and security gaps. Use when the user mentions 'cloud security,' 'cloud audit,' 'AWS security,' 'GCP security,' 'Azure security,' 'IAM audit,' 'S3 bucket,' 'cloud misconfiguration,' 'cloud hardening,' 'Vercel security,' 'Heroku audit,' 'Render audit,' 'PaaS security,' 'is production built from main,' 'old vercel.app still live,' 'preview deployments exposed,' 'Supabase RLS,' or needs to review cloud or deployment-platform security."
allowed-tools: Read, Grep, Glob, WebSearch, Bash(aws iam get-account-summary:*), Bash(aws iam list-users:*), Bash(aws iam get-credential-report:*), Bash(aws s3api list-buckets:*), Bash(aws s3api get-public-access-block:*), Bash(aws s3api get-bucket-policy:*), Bash(aws s3api get-bucket-encryption:*), Bash(gcloud projects get-iam-policy:*), Bash(gcloud iam service-accounts list:*), Bash(az role assignment list:*), Bash(az ad user list:*)
---

# Cloud Audit — Cloud Infrastructure Security Review

Audit cloud infrastructure configurations for misconfigurations, excessive permissions, public exposure, and compliance gaps. Covers AWS, GCP, and Azure, plus the PaaS deployment platforms many small teams run everything on (Vercel, Netlify, Heroku, Render, Railway, Fly).

Cross-references: `iam-audit` for the consultant-style IAM deep-dive (design / audit / migrate across identity providers and federation patterns) — this skill includes an IAM section but stays at the cloud-posture level; for role design, JIT access, workload identity federation, and migration plans, invoke `iam-audit`. `container-audit` for Kubernetes-specific posture sitting on top of cloud. `secrets-audit` for secrets-manager hygiene and rotation. `patch-sweep` for responding to a CVE wave across a fleet of PaaS apps (this skill's PaaS section is the posture half of that). `scanner-pipeline` for running Supabase's security advisor and the other scanners on a schedule.

Findings are recorded in the shared `findings.json` format (see [Verify, then record](#verify-then-record)). Dispositions, usually set later by `finding-triage`: Fixed / Deferred / Accepted Risk / Mitigated (platform/config) / Requires major migration.

## Authorization

Audit only cloud accounts, projects, subscriptions and PaaS teams the user owns or is authorized to review, with credentials provided for that purpose. The pre-approved commands are read-only lists and describes. Never change a policy, rotate a key, delete a resource or redeploy as part of the audit: recommend it and let the owner run it. If the audit credentials grant more than read access, report that as a finding of its own.

## Scope the Audit

Identify:
1. Cloud provider(s) and account(s)
2. Regions in use
3. Whether CLI tools are available (`aws`, `gcloud`, `az`, `vercel`, `heroku`, `netlify`, `fly`, `railway`, `gh`) or reviewing IaC files (Terraform, CloudFormation, Pulumi)
4. For PaaS: every team/account and GitHub owner/org in scope, and which of them belong to clients or other maintainers

## Audit Categories

### Identity and Access Management

**AWS:**
```bash
aws iam get-account-summary
aws iam list-users
aws iam generate-credential-report && aws iam get-credential-report --output text --query Content | base64 -d
```
Check for: root account usage without MFA, access keys older than 90 days, unused credentials, wildcard permissions (`"Action": "*"`), overprivileged roles.

**GCP:**
```bash
gcloud projects get-iam-policy $PROJECT_ID
gcloud iam service-accounts list
```
Check for: primitive roles (Owner/Editor) on too many principals, unused service accounts, service account keys instead of workload identity.

**Azure:**
```bash
az role assignment list --all
az ad user list
```
Check for: excessive Owner/Contributor assignments, guest users with high privileges.

**IaC review:** Grep Terraform/CloudFormation files for `"Action": "*"`, `"Resource": "*"`, hardcoded secrets, overly broad trust policies.

### Network Security

Check for:
- Security groups or firewall rules allowing `0.0.0.0/0` ingress
- Unrestricted SSH (port 22) or RDP (port 3389) from the internet
- VPC flow logs disabled
- Databases in public subnets
- Missing network segmentation between tiers

### Storage

**AWS S3:**
```bash
aws s3api list-buckets
aws s3api get-public-access-block --bucket <name>
aws s3api get-bucket-policy --bucket <name>
aws s3api get-bucket-encryption --bucket <name>
```
Check for: public buckets, missing encryption, no versioning, no lifecycle policies, overly permissive bucket policies.

**GCP/Azure:** Equivalent checks for Cloud Storage and Blob Storage — look for `allUsers`/`allAuthenticatedUsers` access or anonymous blob access.

### Compute

- IMDSv2 enforced? (AWS: `HttpTokens = required`)
- Unencrypted EBS volumes or disks
- Public IP addresses on instances that don't need them
- Outdated AMIs or images (check patch age)
- Privileged containers, missing security contexts in Kubernetes

### Logging and Monitoring

- CloudTrail / Cloud Audit Logs / Activity Log enabled in all regions
- Log storage: encrypted, immutable, adequate retention
- GuardDuty / Security Command Center / Defender for Cloud enabled
- Alerting configured for: root login, IAM changes, security group changes, large data transfers
- VPC Flow Logs and DNS query logs enabled

### Secrets Management

- Hardcoded secrets in source code, environment variables, or IaC files
- Secrets Manager / Key Vault usage for sensitive values
- KMS key rotation configured

### PaaS (Vercel / Netlify / Heroku / Render / Railway / Fly)

Many small teams have no AWS account at all; production is a Vercel team, a few Heroku apps, and a Render service. The exposures there don't show up on an AWS-style checklist: production that no merge will ever replace, git deploys that have been failing for months, old projects still serving unpatched code on a platform URL. Each check below comes from a real fleet sweep in October 2026.

Inventory first: list every project/app per team, the repo and branch it builds from, and every domain it serves (`patch-sweep` Step 1 has the full mapping commands). Commands below are read-only unless marked. Netlify, Railway, and Fly equivalents are in [references/paas.md](references/paas.md).

**1. Stale manual production deploy.** A client site's production was a 96-day-old `vercel deploy --prod` from a developer's laptop, still serving a vulnerable Next.js. The repo's `main` held only a README, so no merge would ever replace it.
```bash
vercel ls <project> --prod --scope <team>                    # latest production deployments, age
vercel inspect <production-url> --scope <team>               # target, created, url
vercel api "/v6/deployments?projectId=<id>&target=production&limit=5" --scope <team> \
  | jq '.deployments[] | {url, created, source, sha: .meta.githubCommitSha, ref: .meta.githubCommitRef, creator: .creator.username}'
git ls-remote origin refs/heads/<production-branch>          # compare with the deployed sha
heroku releases -a <app> -n 20                               # who deployed, and how
```
Check: source is git (not `cli`), the deployed commit equals the production branch HEAD (or is an ancestor of it), and the deployment is younger than the last merge. A mismatch is the finding type below.

**2. Git deploys silently broken.** Two patterns: an Ignored Build Step running `git diff HEAD^ HEAD` while `.vercelignore` excluded `.git` — `.vercelignore` applies to git builds too — so every git deploy errored and production only moved by CLI; and a second project still git-linked to the repo's *old* org, so every PR showed a failing check people learned to ignore.
```bash
vercel ls <project> --status ERROR --scope <team>            # recent failures
vercel api /v9/projects/<project> --scope <team> | jq '{link: .link, productionBranch: .link.productionBranch, ignore: .commandForIgnoringBuildStep, rootDirectory}'
grep -n '\.git' .vercelignore 2>/dev/null
gh api repos/<o>/<r>/commits/<branch>/check-runs --jq '.check_runs[] | {name, app: .app.slug, conclusion}'   # duplicate/failing Vercel checks
```
Check: failure rate of the last 10–20 git-triggered deploys, what the ignore command needs (git history, files `.vercelignore` drops), and whether `link.org`/`link.repo` matches the repo's current owner.

**3. Legacy projects still serving old code.** After domains moved to a new monorepo, the old projects kept serving `*.vercel.app` addresses from unpatched code.
```bash
vercel project ls --format json --scope <team>
vercel api /v9/projects/<project>/domains --scope <team> | jq -r '.domains[].name'
heroku apps --all --json | jq -r '.[] | "\(.name)\t\(.updated_at)"'; heroku domains -a <app>
```
Check: projects whose only domains are platform defaults (`*.vercel.app`, `*.herokuapp.com`, `*.onrender.com`, `*.netlify.app`, `*.fly.dev`, `*.up.railway.app`), and their last deploy dates. Recommend delete, or protect (deployment protection / maintenance mode) if the owner wants to keep it.

**4. Duplicate projects per repo.** One repo triggered builds in two Vercel teams. Only one served the domain, but both held env vars and secrets.
Check: group every team's projects by `link.org/link.repo`; more than one project per repo + root directory is a finding unless the owner can say why. Compare env var *names* (`vercel env ls --scope <team>`) to see what the extra copy holds.

**5. Preview and production exposure.**
```bash
vercel project protection <project> --format json --scope <team>   # SSO / password / bypass settings
curl -s -o /dev/null -w '%{http_code}\n' https://<project>.vercel.app/   # 200 = generated production URL is public
vercel env ls preview --scope <team>                                   # names only
```
Check: deployment protection is on for previews; the generated `*.vercel.app` production URL isn't reachable when the custom domain sits behind Cloudflare or another WAF (it bypasses that WAF — Vercel's Standard Protection covers generated URLs); preview env vars don't point at production databases. To compare database hosts without exposing secrets, pull to a temp file, print only the host, delete the file: `vercel env pull /tmp/p.env --environment=preview && sed -nE 's/^DATABASE_URL="?[^@]*@([^/:]+).*/\1/p' /tmp/p.env; rm /tmp/p.env`.

**6. Build queue as an availability risk.** On a team that runs one build at a time, an emergency patch waited 30–60 minutes behind unrelated builds.
```bash
vercel ls --status QUEUED,BUILDING --scope <team>
```
Check: the team's concurrent build limit. Record in the incident runbook how to get an emergency patch out: an on-demand concurrency increase, cancelling queued non-urgent builds, or an owner-approved CLI deploy path (which then needs to be reconciled with git — check 1).

**7. Heroku specifics.**
```bash
heroku stack -a <app>                                   # heroku-22 / heroku-24
heroku run --no-tty "vips --version" -a <app>           # libvips on the running dyno
heroku run --no-tty "ruby -v" -a <app>                  # compare with .ruby-version / Gemfile ruby
heroku pg:backups:schedules -a <app>
heroku pg:backups -a <app>                              # lists backups AND restores
heroku config -a <app> --json | jq -r 'keys[]'          # names only, never values
heroku --version
```
Check:
- Stack and libvips version. `VIPS_BLOCK_UNTRUSTED=1` (the mitigation for CVE-2026-66066) needs libvips ≥ 8.13; Heroku-24 ships 8.15.1.
- The runtime in `.ruby-version` is what's actually running.
- A `pg:backups` schedule exists, and at least one restore has been done (a backup that's never been restored is untested).
- Heroku CLI 8.x can't run `pg:backups` on Essential plans; upgrade the CLI before concluding backups are missing.
- Review apps don't inherit live keys: check the pipeline's review-app config vars and `app.json` `env` for production Stripe/email/database credentials.

**8. Repo-level security defaults.** Dependabot alerts were off on 142 repos in one account and org.
```bash
gh api repos/<o>/<r>/vulnerability-alerts --silent && echo on || echo off   # 204 = on, 404 = off
gh api repos/<o>/<r> --jq '.security_and_analysis'                          # secret scanning, push protection
gh api repos/<o>/<r>/branches/<production-branch>/protection                # 404 = no classic protection
gh api repos/<o>/<r>/rules/branches/<production-branch>                     # rulesets that apply
```
Check: vulnerability alerts, secret scanning, push protection, and branch protection (or a ruleset) on the **production branch** — which may not be the default branch. Enabling alerts is `gh api -X PUT repos/<o>/<r>/vulnerability-alerts`; it's a write, so it prompts.

**Backend-as-a-service (Supabase).** If the app uses Supabase, run its security advisor — `rls_disabled_in_public` flags public tables readable and writable with the anon key. In the October 2026 sweep that was 10 tables, including 472k inbound email bodies. Use `supabase db advisors` or the Management API `GET /v1/projects/{ref}/advisors/security`; `scanner-pipeline` covers running it on a schedule and a semgrep rule for always-true policies such as `x.col = x.col`.

#### Finding type: Production not reproducible from source (manual deploy / branch mismatch)

Raise this when what's serving production can't be rebuilt from the production branch:
- the current production deployment came from a CLI/manual deploy, not git;
- the deployed commit isn't on the production branch;
- git deploys fail, so the branch and production have diverged;
- the platform's production branch isn't the branch people merge into (e.g., `main` holds only a README and the app lives on `development`).

Why it matters: patches merged to the branch never reach production, nobody can say what code is live, and a rollback goes to an unknown state. Severity follows what's live: a vulnerable framework in the manual deploy makes it as severe as that vulnerability; with nothing known-vulnerable, it's a medium. Remediation is an owner decision — redeploy from git after fixing the build, adopt the deployed code into the branch, or retire the project — never a silent `vercel deploy --prod` over someone else's deploy. For a fleet of these, run `patch-sweep`.

## Verify, then record

Close every candidate from the categories above with one verdict, as defined in [references/findings-format.md](references/findings-format.md), then write `findings.json`.

**1. Save the evidence first.** Most of these findings are about deployed resources, not files. For each one, save the read-only command output, redacted, to `<audit dir>/evidence/<name>.json` (or `.txt`), pretty-printed (`| jq .`) so line numbers stay put. Name the file after the command and resource: `evidence/aws-s3api-get-bucket-policy-prod-uploads.json`, `evidence/vercel-deployments-acme-web.json`. Point `location`, `trace[]` and `evidence[]` at that file and the line of the decisive field (`"Principal": "*"`, `"CidrIp": "0.0.0.0/0"`, `"source": "cli"`), with the path repo-relative like any other location (`security-audit/evidence/...`). For an account-only audit with no repository, make paths relative to the audit directory and say so in the report header. For IaC-only findings, point at the `.tf` / CloudFormation / Pulumi file and line instead.

Never save a secret value. Strip env var and config var values, tokens, presigned URLs, connection-string passwords and key material before writing the file. Keep the identifiers needed to find the resource (account ID, ARN, bucket name, project ID); shorten access key IDs to the last 4 (`AKIA…7QXZ`).

**2. Run the refutation pass** in [references/verification.md](references/verification.md) on every candidate before it is confirmed. For a cloud finding, the "path" is: who can reach it (internet, any authenticated principal in the provider, another tenant, a CI job) → the rule that lets them in → the resource and what it holds. Look for the strongest control that sits in front of it: account-level Block Public Access, an SCP or organization policy, a VPC endpoint policy, a private subnet with no route to an internet gateway, deployment protection, an IdP condition. Write the path as `trace[]` over the evidence files: `entrypoint` = the rule or setting that lets the principal in, `propagation` = what links it to the resource (the group attached to the instance's ENI, the route table), `sink` = the resource and what it holds.

**3. Pick the verdict.**

| Verdict | What it looks like here |
|---|---|
| `confirmed` | The saved output shows the exposure and what sits behind it. Examples: `get-bucket-policy` grants `s3:GetObject` to `"Principal": "*"`, `get-public-access-block` shows `RestrictPublicBuckets: false` at bucket and account level, and the bucket holds customer uploads. A security group allows `0.0.0.0/0` on 5432 and is attached to an RDS instance with `PubliclyAccessible: true`. Production on Vercel is a `source: cli` deployment from 96 days ago, its commit is not on the production branch, and it serves a Next.js version with a known CVE. |
| `needs_validation` | The config supports the claim, but one fact lives somewhere you didn't or couldn't read. Examples: Terraform opens 22 to `0.0.0.0/0`, but there's no state or account access to show it's applied and attached (blocker: is the module deployed; plan: `aws ec2 describe-security-groups --group-ids <id>` and `aws ec2 describe-network-interfaces --filters Name=group-id,Values=<id>`). A preview environment's `DATABASE_URL` host looks like production, but the env var can only be pulled by the owner (plan: the host-only `vercel env pull` command from check 5). Any check you describe but don't run, because it wasn't authorized, is `needs_validation` with the exact command in `validation_plan`. |
| `rejected` | A named control at a named location stops it on every path. Examples: a bucket policy grants `"Principal": "*"`, but the account-level public access block (`aws s3control get-public-access-block`, saved to evidence) has `RestrictPublicBuckets: true`, so `ruled_out_by.location` is that evidence file and line. A wide-open security group is attached to nothing (`describe-network-interfaces` returns `[]`), and `ruled_out_by` points at that saved output. |

An unsafe default in an IaC module you were given (a module that creates buckets public unless `block_public = true` is passed) is `confirmed`, with a `system_configuration` condition ("deployments that don't override `block_public`") and confidence `medium`.

Gaps with no traced impact are hardening notes, not records: VPC flow logs off, KMS rotation off, no S3 lifecycle policy, versioning off on a bucket with no traced loss scenario, GuardDuty off with nothing else wrong. They go in the report's hardening section with no severity.

**4. Calibrate severity** with [references/severity-calibration.md](references/severity-calibration.md), on `confirmed` records only, and rate by what the exposed resource holds and allows, not by the benchmark ID. A public bucket of marketing images is Low or a hardening note; a public bucket of customer documents is High. `overall` ≤ demonstrated impact.

Confidence: config read from the live API is evidence, not reproduction. Set `"reproduced": true` (and allow `high` confidence) only when you demonstrated the exposure with an authorized, non-destructive request: an anonymous `curl -sI` that returns 200 for an object, the generated `*.vercel.app` URL answering 200 while the custom domain sits behind a WAF. IaC-only findings cap at `medium`.

**5. Fingerprint by resource, not by line.** Form: `cloud-audit/<class>/<provider>/<account>/<resource>`, or `cloud-audit/<class>/<IaC file>/<resource address>` for IaC. Write ARNs and `host:port` with slashes; the validator rejects `:<digits>` segments.

```
cloud-audit/public-bucket/aws/123456789012/prod-uploads
cloud-audit/open-ingress/aws/123456789012/sg-0a1b2c3d/5432
cloud-audit/iam-wildcard/aws/123456789012/role/deploy        # arn:aws:iam::123456789012:role/deploy
cloud-audit/manual-prod-deploy/vercel/acme-team/acme-web
cloud-audit/iam-wildcard/infra/iam.tf/aws_iam_policy.deploy
```

Classes in use: `public-bucket`, `open-ingress`, `public-database`, `iam-wildcard`, `root-no-mfa`, `stale-access-key`, `imdsv1`, `logging-disabled`, `manual-prod-deploy`, `git-deploy-broken`, `legacy-project`, `duplicate-project`, `preview-exposure`, `review-app-live-keys`, `rls-disabled`, `repo-security-defaults`. Add a new one when none fits.

**6. Domain fields go under `ext`:**

| Key | Value |
|---|---|
| `provider` | `aws`, `gcp`, `azure`, `vercel`, `netlify`, `heroku`, `render`, `railway`, `fly`, `supabase`, `github` |
| `account` | Account ID, project ID, subscription ID, or PaaS team / org slug |
| `region` | `us-east-1`, `europe-west1`, `global` (omit for PaaS without regions) |
| `resource` | The resource as the provider prints it (ARN, bucket name, `sg-…`, project name, deployment URL) |

**7. Write and validate.** Set `skill: "cloud-audit"`, sort by fingerprint, write `findings.json`, and fix until it passes:

```bash
node references/validate-findings.mjs findings.json
node references/to-sarif.mjs findings.json -o findings.sarif   # optional
```

On a re-run, load the previous `findings.json` and match by fingerprint. A `rejected` record stays rejected unless the control it names changed (re-read that evidence first).

## Output Format

Write `findings.json` first. The report is rendered from it and never changes a verdict, severity, blocker or impact the JSON doesn't already say. No "Potential" or "Possible" labels: an item is a confirmed finding, a needs-validation item, a rejected record, or a hardening note.

```markdown
# Cloud Security Audit Report
## Provider(s): [AWS / GCP / Azure / Vercel / Heroku / Render / ...]
## Account(s) / team(s): [IDs or slugs]   ## Regions: [audited regions]   ## Date: [date]
## Scope: [full | partial — what was left out and why]   ## Access: [read-only role / CLI identity used]
## findings.json: [path] — validated: [yes]   ## Evidence: [audit dir]/evidence/

### Summary
- Confirmed: [N] (Critical [n] | High [n] | Medium [n] | Low [n])
- Needs validation: [N]   Rejected: [N]   Hardening notes: [N]

### Confirmed findings
#### [SEVERITY] [Category]: [Title]  `fingerprint`
**Provider / account / region:** [ext.provider / ext.account / ext.region]
**Resource:** [ext.resource]
**Evidence:** `evidence/<file>:<line>` — [the decisive lines, redacted]
**Confidence:** [medium | high (reproduced)]   **Conditions:** [from conditions[]]
**What and why it matters:** [who can reach it → the rule that lets them in → what the resource holds]
**Fix:** [specific command or IaC change; note availability impact]
**Verify the fix:** [the read-only command that shows it's closed]

### Needs validation
| Finding | Blocker | Check for the owner to run |
|---|---|---|

### Hardening notes (not findings)
- [gap] — [why it isn't a finding] — [effort]

### Rejected (do not re-raise)
| Fingerprint | Ruled out by | Location |
|---|---|---|

### Coverage
| Category | Accounts / teams checked | Not checked (and why) |
|---|---|---|
| IAM / Network / Storage / Compute / Logging / Secrets / PaaS / Supabase / Repo defaults | | |

### PaaS deployment inventory
| Team | Project / app | Repo + production branch | Source of live deploy (git / cli) | Deployed sha = branch HEAD? | Domains |
|---|---|---|---|---|---|

### Prioritized remediation plan
1. [Critical — immediate]
2. [High — this week]
3. [Medium — this month]
4. [Low — next quarter]
```

## Boundaries

- Only audit accounts or projects the user has access to
- For PaaS: don't delete projects, overwrite another person's production deploy, or disable protections during an audit; record the owner decision
- Never print env var or config var values; list names
- Do not attempt to access other accounts or tenants
- Provide remediation for every finding
- Note if a fix might impact availability (e.g., tightening a security group could break connectivity)
- Flag any evidence of active compromise found during the audit
- Refuse requests to exploit found misconfigurations on others' infrastructure

## References

- CIS Benchmarks for AWS/GCP/Azure
- AWS Well-Architected Security Pillar
- ScoutSuite (multi-cloud auditing tool)
- Vercel CLI: [`vercel list`](https://vercel.com/docs/cli/list), [`vercel inspect`](https://vercel.com/docs/cli/inspect), [`vercel project`](https://vercel.com/docs/cli/project), [`vercel api`](https://vercel.com/docs/cli/api)
- [Heroku CLI commands](https://devcenter.heroku.com/articles/heroku-cli-commands); [Render API](https://api-docs.render.com/)
- [GitHub REST — vulnerability alerts](https://docs.github.com/en/rest/repos/repos#check-if-vulnerability-alerts-are-enabled-for-a-repository)
- [Supabase database advisors](https://supabase.com/docs/guides/database/database-advisors)
- Shared references (copied into `references/` at build time): [findings-format.md](references/findings-format.md), [findings.schema.json](references/findings.schema.json), [validate-findings.mjs](references/validate-findings.mjs), [to-sarif.mjs](references/to-sarif.mjs), [severity-calibration.md](references/severity-calibration.md), [verification.md](references/verification.md)
- Per-platform PaaS commands: [references/paas.md](references/paas.md)
