# Active Directory and Entra ID — Paths to Tier 0

Companion to `iam-audit` Mode 1. This is the defender's view of attack-path analysis. List what counts as Tier 0,
find every way a lower-tier identity can reach it, and close each path with a configuration change. It reads
directory data. It never uses a path.

## Authorization for this section

- Only directories (AD forests, Entra tenants) the user owns or administers, for an audit they have approved.
- **Prefer data that already exists.** The security team's last BloodHound / AzureHound export, a PingCastle report,
  Microsoft Defender for Identity or Entra recommendations, Microsoft Secure Score. Reading those needs no new
  collection.
- **New collection needs the directory owner's yes, every time.** SharpHound, AzureHound, PingCastle and Locksmith
  enumerate the whole directory. That's read-only, but it's noisy, and EDR or Defender for Identity may alert on it.
  Agree the timing with whoever watches those alerts.
- **Never use a path to prove it.** No ticket requests, no certificate enrollment, no password changes, no
  delegation changes. A path shown in directory data is the evidence. If the owner wants a live demonstration, that's
  an authorized engagement under `red-team-engagement` rules of engagement, not this audit.
- Locksmith has a remediation mode. Run it only in its read-only modes, and leave fixes to the owner's change process.

## 1. Inventory Tier 0

Tier 0 is everything that can control the identity plane. Write the list down before looking at paths; most findings
are a Tier 0 asset someone forgot was Tier 0.

| On-premises AD | Entra ID / hybrid |
|---|---|
| Domain controllers, and anything that can manage them (backup agents, hypervisors hosting DCs, DC management tools) | Global Administrator, Privileged Role Administrator, Privileged Authentication Administrator |
| Domain Admins, Enterprise Admins, Schema Admins, Administrators, and the built-in operator groups (Account / Backup / Server / Print Operators) | Application owners and service principals holding `RoleManagement.ReadWrite.Directory`, `AppRoleAssignment.ReadWrite.All` or similar Graph permissions |
| AD CS certificate authorities and the accounts that manage templates | The Entra Connect / Cloud Sync server and its service accounts |
| AD FS servers and their signing certificates | Conditional Access administrators, and break-glass accounts |
| Accounts with DCSync rights (Replicating Directory Changes All) | Synced on-prem accounts that hold cloud admin roles |
| GPOs linked to the Domain Controllers OU, and anyone who can edit them | Identity governance and PIM administrators |

## 2. Get the paths

From an existing graph export, ask for the shortest paths from **any non-Tier-0 principal** (Domain Users,
Authenticated Users, Everyone, all users in a cloud tenant) to each Tier 0 asset. In BloodHound CE that's the
built-in "shortest paths to Tier Zero" queries, with Tier Zero tagged to match the inventory above. Record each
path as a list of edges: principal → relationship → object.

Without a graph, native read-only queries cover the common classes:

```powershell
# Privileged group membership, including nested
Get-ADGroupMember "Domain Admins" -Recursive | Select-Object name, objectClass
# Accounts with SPNs (service accounts) and their password age
Get-ADUser -Filter 'servicePrincipalName -like "*"' -Properties servicePrincipalName, pwdLastSet, adminCount
# Accounts that don't require Kerberos pre-authentication
Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true'
# Computers trusted for unconstrained delegation (DCs are expected; anything else is not)
Get-ADComputer -Filter 'TrustedForDelegation -eq $true'
```

For AD CS, run Locksmith in a read-only mode, or review `certutil -v -template` output for each published template.
In Entra, list role assignments (including PIM-eligible ones) and app permissions through Microsoft Graph read
calls, and save the output as evidence.

## 3. Exposure classes and the fix that closes each

| Class | What makes it a path | Fix |
|---|---|---|
| Nested or indirect privileged membership | A group several levels deep, or a helpdesk group, ends up in a Tier 0 group | Flatten; Tier 0 groups contain named Tier 0 admin accounts only; review quarterly |
| Control rights over Tier 0 objects | GenericAll / WriteDacl / WriteOwner / password-reset rights on a Tier 0 user, group, GPO or OU held by a lower tier | Remove the ACE; protect Tier 0 objects through AdminSDHolder and clean up stale `adminCount` flags |
| Service accounts with SPNs and weak or old passwords | Any domain user can request a service ticket and test the password offline | Group Managed Service Accounts; 25+ character random passwords; AES-only encryption types; remove SPNs from admin accounts |
| Pre-authentication disabled | Anyone can request encrypted material for that account and test it offline | Re-enable pre-authentication; if an app needs it off, isolate that account and give it a long random password |
| Unconstrained delegation outside DCs | A compromised host with this setting can capture tickets of anyone who connects to it | Remove it, or move to constrained / resource-based delegation; put Tier 0 accounts in Protected Users and mark them "sensitive and cannot be delegated" |
| Misconfigured certificate templates | A template lets the requester set the subject, allows client authentication, and is enrollable by broad groups (the ESC1 pattern; Locksmith and Certify name the others) | Remove broad enroll rights; require CA manager approval; turn off requester-supplied subject; restrict template edit rights to Tier 0 |
| Local admin reuse | The same local administrator password across machines links a workstation to servers | Windows LAPS on every machine; check coverage, not just deployment |
| GPO edit rights | A lower tier can edit a GPO linked to Tier 0 machines or the DC OU | Restrict edit rights; separate GPOs per tier |
| Stale or forgotten admins | Disabled-but-privileged accounts, admins with old passwords, Tier 0 accounts that log on to workstations | Remove or disable; enforce tiered logon restrictions (authentication policies / silos) |
| Hybrid bridge | The Entra Connect server is managed like an ordinary server, or on-prem admins are synced into cloud admin roles | Treat the sync server as Tier 0; cloud-only admin accounts with phishing-resistant MFA; no synced accounts in privileged roles |
| App and service principal permissions | A service principal or its owner can grant itself roles through Graph permissions | Remove the permission or the owner; admin consent workflow; review app credentials |

## 4. Verdicts

- **Confirmed:** every edge from a non-Tier-0 principal to a Tier 0 asset is shown in saved directory data
  (a graph export, query output or Locksmith report under `<audit dir>/evidence/`). Severity follows what the
  Tier 0 asset controls; a path from Domain Users or all tenant users to domain or tenant control is critical.
  Confidence is `medium`, because directory data is evidence but nothing was exercised.
- **Needs validation:** one edge depends on a fact the data doesn't show. Examples: whether a service account's
  password is actually weak, whether a host with unconstrained delegation is reachable by users, whether Protected
  Users membership applies to the protocol in question. Name the blocker and the read-only check the owner can run.
- **Rejected:** the edge is blocked by a named control at a named location. Examples: the account is in Protected
  Users; the template requires manager approval; the ACE is inherited only onto a container with no Tier 0 objects.

Fingerprint: `iam-audit/<class>/<directory>/<tier0-object>` (for example
`iam-audit/cert-template-enrollee-subject/corp.example.com/UserAuthTemplate`). `ext` keys: `provider` (`ad` or
`entra`), `tier0_asset`, `path_length`, `entry_principal`.

## References

- Microsoft: securing privileged access, the enterprise access model (tiering), Protected Users, Windows LAPS
- SpecterOps: BloodHound Community Edition documentation; "Certified Pre-Owned" (AD CS abuse classes and their
  mitigations)
- PingCastle and Locksmith project documentation (read-only health and AD CS audit modes)
- ANSSI Active Directory security checkpoints
