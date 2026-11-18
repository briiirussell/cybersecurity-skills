# A vendor you use was breached

Companion to `incident-triage` Step 1, for when a SaaS or platform you use says an attacker reached **its** systems. Your own code and machines may be fine. The work is every secret you handed that vendor: find it, rotate it at the issuer, and check the issuer's logs.

Read-only inventory first. Revoking a token, rotating a key, or disconnecting an integration changes production: name it and get the incident lead's go-ahead, the same rule as Step 2. Never use a found credential to probe the vendor or anyone else.

The notices below were checked on 2026-11-03 against each vendor's own page, except where a row says otherwise. No CVE is assigned to any of them. How any of these attackers got in, whether the "AI agents" claims are accurate, how many customers are affected, and whether a stolen key was used beyond what customers reported to Northflank are **not known and not claimed**.

GitBook, Northflank, and Warp each describe an AI-agent or "agent swarm" attack, but only as that vendor's own early assessment. Northflank also ties the AI-key misuse to Wiz's "Black October" report. Treat the "AI agents" attribution as vendor-reported, not confirmed.

## Vendor notices

| Vendor | What happened (as the vendor described it) | What customers were told |
|---|---|---|
| **GitBook** ([status page](https://www.gitbook.com/status/security-incident-2026-11-03), incident 2026-11-02, disclosed 2026-11-03) | At 19:00 CET on Nov 2 an attacker "using AI agents" got some of GitBook's infrastructure credentials. GitBook says the attacker may have accessed integration tokens, Git Sync secrets, API tokens, and visitor questions to GitBook Assistant. No evidence content was modified. | Rotate GitBook API tokens (all personal tokens were revoked), rotate third-party secrets used to connect other tools, rotate secrets in published integrations, and re-authenticate the GitBook MCP server. The 13:15 CET update said "Action required: None at this time". The 16:21 CET update reversed that. |
| **Northflank** ([status page](https://status.northflank.com), from 2026-10-30) | Wiz threat alert Oct 30 11:43 UTC. By 13:58 UTC: "Assume all environment variables have been decrypted." Customers later reported unauthorised use of AI provider keys. On Nov 2 Northflank said evidence suggests the attack focused on secrets in its control plane and that running workloads were unaffected. | Rotate all secrets now, even with no suspicious activity: integration and project secrets, starting with AI provider keys, cloud credentials, payment keys, private keys, and database credentials. Review provider logs. Sign in again and reconnect integrations. |
| **Bubble** ([status incident](https://status.bubble.io/incidents/01M5WJ5HV7RWPN15GFDHZMCSSS), 2026-10-26) | Unauthorized access. The attacker reached plugin metadata, including private keys stored in plugins, and downloaded data from apps whose editor was set to publicly viewable. Later probing of individual apps for common misconfigurations. Read from the incident page and the Bubble forum Q&A, not fetched in full on 2026-11-03. | Check third-party account activity, rotate possibly exposed credentials, run the security dashboard, mark credentials "Private", and set apps to "Private app". Official messages come only from Bubble's own domain and status page. Bubble does not ask for passwords by email. |
| **Allium** ([status page](https://status.allium.so/), detected 2026-10-25) | Unauthorized access. The app was offline for days. Read from a status-page excerpt on 2026-11-03: API keys revoked Oct 28. | Existing API keys were revoked and must be recreated. Set a new password and turn on MFA. |
| **Warp** (CEO statement, via [BleepingComputer](https://www.bleepingcomputer.com/news/security/warp-discloses-breach-exposing-ai-agent-logs-user-telemetry-data/), incident 2026-10-23, disclosed 2026-10-26) | An unnamed vendor in Warp's infrastructure was exploited. Attackers reached "a limited amount of agent trace and telemetry data", upper bound roughly 1% of users. Warp has not said whether code, prompts, or credentials were in that data. The vendor, the vulnerability, and the exposed fields are not disclosed. | Follow Warp's notice. Third-party write-ups suggest rotating anything pasted or printed in an agent session. That advice is from the write-ups, not from Warp. |
| **Railway** ([final RCA](https://blog.railway.com/p/incident-report-october-security-incident), published 2026-11-10; incident Oct 20–21; [preliminary guidance](https://blog.railway.com/p/preliminary-report-october-security-incident) Oct 22) | Multi-tenant build-sandbox escape (Oct 20 07:28 UTC) led to an over-trusted build credential being accepted by Temporal. That exposed 353 build histories (secrets, a GitHub App token) and a Railway monorepo cache. Re-entry used misconfigured OIDC, then SSH/VPC access and a decrypt credential on an orchestration box. Queries prioritized AI provider keys by variable-name regex (names like `OPENAI_API_KEY`) and also matched cloud, database, and payment names. Railway's forensics, read 2026-11-10, not re-verified here. No CVE. "Abliterated models" and ARTEX-like harness language is Railway citing Wiz, not independently verified. | Follow Railway's notice. Rotate at the issuing provider, not only in the Railway UI. Inventory more than the dashboard env vars (below). Treat "at most 1.85%" (~100k workspaces) as Railway's ceiling on workspaces that *could* have had variables decrypted, not a confirmed victim count. 1,852 BYOK / GitHub OAuth tokens were reset. About $740k unauthorized key spend was reported. |
| **Fireworks** ([Oct 10 bulletin](https://fireworks.ai/security/bulletins/october-2026-security-incident), incident identified Oct 6; [Nov 9 update](https://fireworks.ai/security/bulletins/october-2026-security-incident-update)) | Oct 6: unauthorized use of internal credentials, and access to environment variables used in evaluation jobs in a limited number of customer accounts. The Oct 10 bulletin reported no detected unauthorized access to customer models, datasets, training data, personal information, or inference traffic, and described the platform as zero-data-retention by default. The Nov 9 update reported later-discovered impact to account and billing information and, for a limited set of accounts, secrets, datasets, and incomplete model weights. A third-party cloud provider that hosted Fireworks R&D machines had an incident on Oct 23; on Oct 24 the actor reached Fireworks development machines. Fireworks says it has not detected impact to Inference, Training SDK, and Nexus, which it states are zero-data-retention by default. Investigation ongoing. Read 2026-11-11. No CVE. | Direct notice to identified affected customers, with account-specific actions. If you have not received a notice, Fireworks says it has not identified your account as affected based on the investigation to date. |
| **Notion** ([advisory, updated Nov 10](https://www.notion.com/security/advisories/security-incident-involving-a-third-party-ai-vendor); [help center](https://www.notion.com/help/security-incident-involving-a-third-party-ai-vendor)) | Notion was not the breached party. Nov 2: Fireworks notified Notion of accessed data that Notion first assessed as synthetic testing data only. By the morning of Nov 3 Notion disconnected, deleted data at Fireworks, and stopped communication. Nov 6: Fireworks said malicious actors may have accessed potential customer data. Nov 8: Fireworks confirmed the dataset, which included Notion AI chat transcripts used for the Insights feature. Notion reports less than 1% of workspaces may be affected. Notion used Fireworks for Insights classification and as a general inference provider for open-weight models. Insights is disabled, and Notion is no longer serving open-weight models through Fireworks. Read 2026-11-11. No CVE. | Notion contacted impacted customers on Nov 9. If you have not heard from Notion, it says it has not identified your workspace as affected and no action is needed right now; the investigation is ongoing. Affected workspace owners review the export on desktop: workspace sidebar, then ?, then Security incident review. Treat the data as exposed and rotate passwords, API keys, or other credentials pasted into Notion AI during the incident window. AI Meeting Notes were not affected unless used as input in a Notion AI chat. |

## Playbook

1. **Inventory what you gave the vendor.** Use the [vendor-held secrets inventory](../../secrets-audit/SKILL.md#vendor-held-secrets) in `secrets-audit`: env vars and secrets stored there, Git Sync and VCS tokens, integration and OAuth tokens, API keys, cloud IAM roles or service accounts the vendor can use, MCP servers or agents connected to it, and anything pasted into its chat or agent features. Names and owners only. Do not print secret values into the session.

2. **Rotate the highest-value keys first.** AI provider keys, cloud credentials, payment keys, private keys, database credentials. Revoke at the **issuing provider**, not only in the vendor's UI. Rotate new-then-revoke-old, as in `secrets-audit` step 5: create the new key, deploy it, then revoke the old one. Revoke-first breaks production.

3. **Check the issuing providers' logs, not the vendor's.** Look for unexpected usage or spend on AI and cloud keys from the breach window onward. Northflank customers reported AI-key abuse that showed up at the AI provider, not in Northflank's UI.

4. **Don't wait for the vendor to say "action required."** GitBook's first notice said none, and its second said rotate. Rotate on the first notice of unauthorized access to credentials, and note the time.

5. **Treat "revoked for you" as partial.** GitBook revoked personal API tokens, and customers still had to rotate third-party secrets in integrations. Northflank revoked some sessions and IAM roles, and customers still had to reconnect. Record what the vendor revoked and what is still yours.

6. **Phishing watch.** A breach notice is a pretext. Bubble warned that official messages come only from its own domain and status page, and that it never asks for passwords by email. Verify any "rotate now" email against the vendor's status page that you already know. Open that page yourself. Do not use a link from the email.

7. **Log the clock.** Record when the vendor's breach began (as the vendor stated it), when you were told, when you declared, and when each secret was rotated. This feeds Step 6 notification clocks. Unknown stays unknown.

| Event | Time (UTC) | Source |
|---|---|---|
| Vendor says the breach began | | vendor status page |
| We were told | | the notice you actually received |
| Declared (Step 1) | | incident lead |
| Each secret rotated | | issuer audit log |

## Railway, October 2026

The row above is the first full root-cause writeup in this set. Steps 1–7 still apply. Add these, from what the RCA actually says.

1. **Provider notification may precede the customer notice.** Railway notified GitHub, GitLab, Anthropic, OpenAI, OpenRouter, SpaceXSI, Google, and Stripe first. A key may already be revoked or flagged when you first hear. Record what the issuer already did, then rotate whatever is still yours.

2. **Inventory more than dashboard env vars.** Include CI and build or task histories, cached snapshots, GitHub App / OAuth / BYOK tokens, and agent keys. The same classes belong on the `secrets-audit` vendor-held inventory, not only the variables visible in the project UI.

3. **Rotate at the issuer.** Same rule as step 2. Railway reported about $740k of unauthorized key spend. A hard spend cap on the leaked key limits that bill. Caps, scope, and short-lived credentials are the controls. Renaming is not.

4. **Do not treat env-var renaming as a primary control.** The queries matched conventional names (`OPENAI_API_KEY` and similar). Renaming is evasion at best.

5. **Keep upper bounds honest.** "At most 1.85%" is a ceiling, not a count of affected workspaces. Unknown stays unknown.

Do not copy Railway's indicators into a hunt as if they were independently verified, and do not claim any attacker tooling worked. A Railway project inventory stays in `cloud-audit` (`references/paas.md`). This section is the incident response, not a second PaaS checklist.

## AI subprocessors and zero-data-retention claims

Notion / Fireworks is a different shape from the rows above. The SaaS you pay was not itself breached. Its classification vendor was, and a zero-data-retention promise did not cover stored chat transcripts sent for an Insights job. Checked 2026-11-11 against Notion's advisory and help center (including the ZDR FAQ) and both Fireworks bulletins. No CVE.

Notion's word "unattributable" means the chats were not labeled with who wrote them or which workspace they came from, and the transcripts did not contain tool-call results. Notion says that for the vast majority of impacted workspaces the Insights transcripts were unattributable. That is not the same as the transcript text being non-identifying. Notion still tells affected customers to treat the content as exposed.

Notion's Enterprise zero-data-retention terms, in its own FAQ: they apply to the API requests Notion sends to third-party model vendors to generate responses to Notion AI requests. They are not intended to cover features that store requests and responses, including chat history and Insights. For Insights, Notion sent those stored chats to Fireworks for classification. Fireworks had given Notion a contractual zero-data-retention commitment. Notion later learned that data was retained from the Fireworks endpoints it used.

A screenshot attached to a 2026-11-11 post by @kepano shows an Enterprise customer who said they received a Fireworks notice and that the export contained both sides of conversations in detail. Treat that as the customer's report, not as Notion's wording.

Steps 1–7 still apply. Add these.

1. **Inventory AI subprocessors and secondary copies, not only the primary SaaS.** List features that re-send stored chats or agent transcripts for insights, classification, usage dashboards, training, or eval, and which third party receives them. Record that on the `secrets-audit` vendor-held inventory.

2. **Ask what a zero-data-retention claim actually covers.** In this case it covered the API requests that generate Notion AI responses, not features that store chats. A contractual commitment from Fireworks also did not prevent retention on the Insights endpoints. Fireworks separately says Inference, Training SDK, and Nexus were not detected as impacted and are zero-data-retention by default. Record the scope. "ZDR" is not a single yes or no.

3. **Do not treat "unattributable" or unlabeled transcripts as harmless.** Missing workspace or user labels is not the same as non-identifying content. If a notice and an export exist, review the transcript text and rotate anything sensitive pasted into that vendor's AI. Notion's `__analysis` column in the annotated export is an aid for that review, not a complete finding list.

4. **Do not treat the first "no customer data" bulletin as final.** This extends step 4. Fireworks' Oct 10 bulletin reported no detected dataset or prompt access. The Nov 9 update, and Notion's Nov 6–9 timeline, added stored datasets used for classification.

5. **If you have not received a notice, follow the vendor's current guidance and keep watching.** Both vendors say that no notice means they have not identified your account or workspace as affected, and that the investigation is ongoing. Do not claim that an unnotified customer was in the unattributable pool.

Not known, and not claimed: how the Fireworks actor got in, a complete list of every dataset, whether any specific unattributable transcript identified a company from its text, notification timing to any authority, or a CVE number.

## What not to do with these notices

- Do not state that AI agents carried out the intrusion. That is the vendor's early assessment.
- Do not treat a third-party write-up as the vendor's instruction. Warp's "rotate anything pasted into an agent session" advice is from write-ups, not from Warp.
- Do not copy a status page into a customer notice. Draft that with `security-comms` after counsel decides whether a clock has started.
