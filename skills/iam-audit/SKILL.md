---
name: iam-audit
description: "Audit, design, and migrate Identity and Access Management — cloud provider IAM (AWS, GCP, Azure), identity providers (Okta, Entra ID / Azure AD, Auth0, Google Workspace), application authorization (RBAC, ABAC, ReBAC), and federated identity. Use when the user mentions 'IAM,' 'identity,' 'access management,' 'least privilege,' 'role design,' 'SSO,' 'SAML,' 'OIDC,' 'OAuth,' 'JIT access,' 'just-in-time access,' 'break-glass,' 'service accounts,' 'RBAC,' 'ABAC,' 'privilege creep,' 'role explosion,' 'identity governance,' 'IAM strategy,' 'identity migration,' 'Okta,' 'Entra ID,' 'Azure AD,' 'Auth0,' 'Cognito,' or needs identity consultant-level guidance."
allowed-tools: Bash, Read, Write, Grep, Glob, WebSearch
---

# IAM Audit — Identity & Access Management Review and Design

Cover the identity and access layer end-to-end: audit existing setup, design from scratch, plan migrations, and codify the patterns most teams get wrong. This is the consultant-style skill — not just "what's misconfigured" but "what should this look like."

Three modes — pick the one that matches the engagement:
- **Audit** — review what's already deployed, find privilege creep and gaps
- **Design** — greenfield IAM for a new project or new identity provider
- **Migrate** — consolidate multiple identity providers, federate access, move to SSO

Cross-references: `cloud-audit` for the cloud-provider audit (broader than IAM), `container-audit` for K8s RBAC and ServiceAccounts (orchestration-layer identity).

## Mode 1 — Audit existing IAM

### Cloud provider IAM

**AWS:**
- IAM users with console access — should be zero in mature setups (use SSO/Identity Center)
- IAM users with permanent access keys — every one is a credential rotation problem; replace with role assumption via SSO or IAM Roles Anywhere
- Permissions boundaries set on every role that can create roles (prevents privilege escalation via `iam:CreateRole` + `iam:AttachRolePolicy`)
- `AdministratorAccess` policy attachments — flag every one and justify
- Wildcard `Action: "*"` or `Resource: "*"` outside of break-glass roles
- Cross-account trust policies — `Principal: { AWS: "*" }` is open to the world; should be specific account IDs with optional `aws:PrincipalOrgID` condition
- IMDSv2 enforced — `MetadataOptions.HttpTokens: required` on every EC2 launch template
- Service-linked roles audited — they bypass normal restrictions
- Run: `aws accessanalyzer list-findings`, `aws iam generate-credential-report`, `aws iam get-account-authorization-details`

**GCP:**
- `roles/owner` and `roles/editor` are too broad — replace with custom roles or fine-grained `roles/*Admin`
- Service account keys downloaded (`projects.serviceAccounts.keys.create`) — should be zero; use Workload Identity Federation
- Service accounts with `iam.serviceAccountTokenCreator` on themselves = self-impersonation = privilege escalation
- Org-level vs project-level bindings — over-scoped bindings at the org level are silent privilege grants to every project
- `allUsers` / `allAuthenticatedUsers` bindings on any sensitive resource
- Run: `gcloud asset analyze-iam-policy`, `gcloud policy-intelligence query-activity`, Recommender API

**Azure:**
- `Owner` and `Contributor` role assignments at subscription/management-group scope
- Custom roles with `*` actions
- Conditional Access policies cover *every* sign-in surface (legacy auth, service principals, break-glass accounts excluded with explicit reason)
- Privileged Identity Management (PIM) used for all Global Admin / Privileged Role Admin / Application Admin roles
- Service principal credentials (client secrets) — should expire and rotate; check expiration dates
- Run: `az role assignment list --all`, Microsoft Graph `auditLogs/signIns`, Microsoft Entra recommendations

### Identity provider

**Okta / Entra ID / Auth0 / Google Workspace:**
- MFA enforced for 100% of users — no "MFA optional" cohort
- Phishing-resistant MFA (FIDO2 / WebAuthn / hardware key) for admins; TOTP is the minimum for everyone
- Inactive accounts disabled after 30/60/90 days (pick a policy, enforce it)
- Lifecycle automation — joiner / mover / leaver flows are automated, not ticket-driven
- Group-based access — users get permissions via group membership, not direct assignment; group membership is the auditable surface
- Admin separation — privileged admin actions require a separate elevated account, not the day-to-day account
- App assignments — every SaaS app reviewed quarterly; orphaned apps (no longer used) removed
- Authentication policies — block legacy protocols (IMAP, POP, SMTP basic auth), enforce device compliance for high-trust apps
- Session lifetime appropriate to sensitivity (admin: short, end user: longer with refresh)
- Logs forwarded to SIEM — sign-ins, admin changes, MFA failures

### Application authorization

- Role definitions written down somewhere (not just in code) — `docs/roles.md` or equivalent
- "Admin" is not one role — usually 3-5: support, billing, content moderator, platform admin, security responder
- Per-tenant role isolation — a "tenant admin" of org A cannot read org B even with the same role
- Permission checks centralized — one `can(user, action, resource)` function, not scattered `if (user.role === "admin")` checks throughout
- ABAC where the access decision depends on resource attributes (record owner, tenant, status) — ReBAC tools (Cerbos, OpenFGA, Oso, SpiceDB) when role explosion threatens
- Permission checks logged for the audit trail

### Common audit findings

- **Role explosion** — every new requirement spawned a new role; nobody knows what they all do; nobody dares delete one
- **Permission accretion** — engineers got temporary permissions for an incident, permissions were never revoked
- **Shadow admin** — a non-admin role can `iam:AssumeRole` into admin, transitively
- **Stale break-glass** — emergency-access accounts haven't been tested in 12+ months; nobody knows if they work
- **MFA bypass via legacy auth** — IMAP/POP/SMTP basic auth still works against accounts that "have MFA"
- **Service account sprawl** — more service accounts than humans, half are unused, half are over-privileged

## Mode 2 — Design greenfield IAM

### Principles (the consultant ones, not just OWASP)

1. **Identity provider is the source of truth.** Even for cloud IAM — federate via SAML/OIDC, don't manage users in AWS/GCP/Azure directly.
2. **People get access via groups, not directly.** Direct assignments are auditable noise.
3. **Service accounts are roles.** Don't issue keys; use workload identity federation (AWS IRSA, GCP Workload Identity, Azure Workload Identity, Kubernetes ServiceAccounts → OIDC).
4. **Privileged access is JIT, not standing.** Default to "no access"; grant for a defined window with audit trail (AWS IAM Identity Center + permission sets with session duration, Azure PIM, Okta Workflows, Google JIT via context-aware access).
5. **Break-glass is a tested, alarming path.** Emergency-access accounts exist but are heavily audited and tested quarterly.
6. **Least privilege is observable, not aspirational.** Pull access advisor / unused-access reports monthly; remove what isn't used.
7. **Authorization decisions are logged.** Every `allow` or `deny` should be traceable for incident response.

### Greenfield checklist (web app + cloud)

For a new project, design these in this order:

1. **Pick the identity provider.** Okta or Entra ID for enterprise; Auth0 / Clerk / Stytch / WorkOS for B2B SaaS; Google Workspace for small teams. Don't roll your own.
2. **Define your authorization model.** RBAC is the floor. Add ABAC when permissions depend on record attributes. Use a permission service (Cerbos, OpenFGA, Oso) when permissions get complex enough that an `if` statement in code is no longer readable.
3. **Define your roles before you write code.** What roles will exist in your product? Write them in a doc with one sentence per role describing what they can do. Most products are: end user, end user admin (tenant-scoped), support, billing, content moderator, platform admin.
4. **Federate cloud access.** AWS IAM Identity Center + your IdP; GCP Workload Identity Federation + your IdP; Azure AD as the source of truth for Azure roles.
5. **Workload identity, not keys.** EC2 → IAM Roles; EKS → IRSA / Pod Identity; ECS → task role; Lambda → execution role; GitHub Actions → OIDC federation. No long-lived keys.
6. **Logging from day 1.** Cloud trail / audit log to a SIEM-bound bucket; deny `*:Delete*` and `*:Put*` on the log bucket from anything but the logging service.
7. **Break-glass account documented and tested.** Two-person rule, hardware MFA, used only for "the IdP is down" scenarios, alarms on every login.

### Auth flow choices (web/mobile clients)

- Public clients (browser, mobile) — OAuth 2.0 Authorization Code with PKCE; never implicit flow (deprecated, leaks tokens)
- Confidential clients (server-to-server) — Client Credentials grant with short-lived access tokens
- First-party native — your IdP's native SDK (Okta, Auth0, Clerk) handles the storage and refresh nuance
- Long-lived refresh tokens stored in HttpOnly Secure cookies; never in `localStorage` (XSS-exfiltratable)
- Token revocation list — your IdP should support it; if it doesn't, you have a JWT problem (see `owasp-audit` A07)

## Mode 3 — Migrate / consolidate

### Common migrations

- **From AWS IAM users → AWS IAM Identity Center (SSO):** map users to permission sets via groups; rotate / disable IAM user access keys with a deadline; the long tail is service accounts and CI/CD — convert those to OIDC federation
- **From Active Directory → Entra ID:** sync with Entra Connect, then add Conditional Access; the hard part is legacy auth (SMB, NTLM, on-prem LDAP) — those need their own deprecation plan
- **From "Google Workspace as IdP" → dedicated IdP (Okta / Entra):** Google handles email but provisioning into 30 SaaS apps starts to drag; the migration is mostly SCIM provisioning + SAML federation; users barely notice
- **From `roles/owner` everywhere → custom roles (GCP):** use Recommender API to suggest least-privilege replacements; cut over one project at a time

### Migration playbook (works for all of the above)

1. **Inventory current state.** Who has what access where? Spreadsheet is fine. Include service accounts.
2. **Decide the target state.** Roles defined, groups defined, IdP chosen, federation pattern picked.
3. **Set up the target in parallel.** New IdP / IAM Identity Center / etc. lives alongside the current setup. No cutover yet.
4. **Pilot with a small group.** 5-10 people use the new path, find friction, fix it.
5. **Migrate in waves.** By team or by app, not big bang. Each wave has a rollback procedure.
6. **Deprecate the old path with a deadline.** Set a "by X date, the old IAM users are disabled" — and enforce it. Migrations without deadlines never finish.
7. **Audit-trail the cutover.** Document who moved, when, what they had, what they got, who approved.

## Output Format

```markdown
# IAM [Audit | Design | Migration] Report
## Scope: [accounts / orgs / IdPs covered]
## Date: [date]

### Executive Summary
[2-3 paragraphs — the IAM posture in plain English, top 3 risks, recommended next 90 days]

### Findings / Recommendations
| ID | Severity | Mode | Category | Issue / Recommendation |
|----|----------|------|----------|------------------------|

### Per-finding detail
[as in owasp-audit — file/resource, description, vulnerable config, remediation, verification]

### Roadmap
[Quarterly milestones — what to do this month, next 90 days, next year]
```

Disposition rule (Fixed / Deferred / Accepted Risk) per `owasp-audit`.

## Boundaries

- Only audit accounts and identity providers the user has authorization for
- Read-only operations during audit (no `iam:AttachPolicy`, no role creation, no user disablement)
- For migrations: never disable a user without a confirmed rollback path
- Refuse to help bypass MFA, recover credentials by social engineering, or design backdoor access
- Privilege escalation chains found during audit are documented as findings, not exploited

## References

- AWS IAM Best Practices
- GCP IAM Best Practices
- Microsoft Entra ID — privileged access strategy
- NIST SP 800-63 (Digital Identity Guidelines)
- NIST SP 800-207 (Zero Trust Architecture)
- OWASP Authentication Cheat Sheet
- OWASP Authorization Cheat Sheet
- Open Policy Agent / Cedar / Cerbos / OpenFGA documentation
- AWS Permission Boundary documentation
- "Just enough access" / JIT access patterns
