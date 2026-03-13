# cloud-audit

> Audit cloud infrastructure (AWS, GCP, Azure) for misconfigurations, excessive permissions, and security gaps. Use when the user mentions 'cloud security,' 'cloud audit,' 'AWS security,' 'GCP security,' 'Azure security,' 'IAM audit,' 'S3 bucket,' 'cloud misconfiguration,' 'cloud hardening,' or needs to review cloud infrastructure security.

# Cloud Audit — Cloud Infrastructure Security Review

Audit cloud infrastructure configurations for misconfigurations, excessive permissions, public exposure, and compliance gaps. Covers AWS, GCP, and Azure.

## Scope the Audit

Identify:
1. Cloud provider(s) and account(s)
2. Regions in use
3. Whether CLI tools are available (`aws`, `gcloud`, `az`) or reviewing IaC files (Terraform, CloudFormation, Pulumi)

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

## Output Format

```markdown
# Cloud Security Audit Report
## Account(s): [account ID(s)]
## Provider: [AWS/GCP/Azure]
## Regions: [audited regions]
## Date: [date]

### Summary
- Total findings: X
- Critical: X | High: X | Medium: X | Low: X

### Findings

#### [SEVERITY] [Category]: [Title]
**Resource:** [resource ARN/ID]
**Region:** [region]

**Issue:** [What the misconfiguration is]

**Risk:** [What an attacker could do]

**Evidence:** [CLI output or IaC snippet]

**Remediation:** [Specific fix command or IaC change]

---

### Prioritized Action Plan
1. [Critical — immediate]
2. [High — this week]
3. [Medium — this month]
4. [Low — next quarter]
```

## Boundaries

- Only audit accounts or projects the user has access to
- Do not attempt to access other accounts or tenants
- Provide remediation for every finding
- Note if a fix might impact availability (e.g., tightening a security group could break connectivity)
- Flag any evidence of active compromise found during the audit
- Refuse requests to exploit found misconfigurations on others' infrastructure

## References

- CIS Benchmarks for AWS/GCP/Azure
- AWS Well-Architected Security Pillar
- ScoutSuite (multi-cloud auditing tool)