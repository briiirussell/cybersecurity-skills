# Hard spend caps on pay-per-use API keys

Blast radius for a leaked LLM key, from `secrets-audit` step 4. Checked against the provider docs on 2026-10-30.

A widely shared post recommended **daily** caps on OpenAI and Anthropic keys. That is not what those providers document. OpenRouter can reset a per-key limit daily. OpenAI and Anthropic Console limits are monthly. Cite the docs below, not the post.

Northflank's incident is why the cap matters. From 2026-10-30 to 2026-11-02 its [status page](https://status.northflank.com/cmvv0rn5a092f14rutwccodpp) told customers to assume environment variables had been decrypted, customers reported unauthorised use of AI API keys, and Northflank said the attack focused on secrets in the control plane. No CVE was assigned, and no root cause was published as of 2026-11-02. A cap does not replace rotation. It bounds the bill until someone notices.

## What each provider actually caps

| Provider | Hard cap | Scope | Period | When hit |
|---|---|---|---|---|
| OpenRouter | Per-key credit `limit`, plus workspace and guardrail budgets | One key | `limit_reset`: daily, weekly, or monthly. Daily resets at 00:00 UTC | `402` (key limit) or `403` (budget) |
| OpenAI | "Enforce a hard limit" | Organization or project | Monthly. "Enforcement is not instantaneous." Spend alerts alone cap nothing | `429` (`project_spend_limit_exceeded` / `organization_spend_limit_exceeded`) |
| Anthropic (Console) | Org spend limit; workspace spend limits | Organization or workspace. The Default Workspace cannot have its own limit | Monthly | `400` "You have reached your specified API usage limits" |

Give each app its own OpenAI project, its own non-default Anthropic workspace, or its own OpenRouter key with a `limit`, so the cap applies to the key that leaked and not the whole organization. A key in Anthropic's Default Workspace is capped only by the org limit.

## Check

Ask first. Reading the cap uses the key, the same rule as the liveness check in step 2. Do not use the key to read customer data.

```bash
# OpenRouter: the key reports its own cap. limit: null means no per-key cap.
curl -s https://openrouter.ai/api/v1/key -H "Authorization: Bearer $OPENROUTER_API_KEY" \
  | jq '.data | {limit, limit_reset, limit_remaining, effective_budget}'
```

OpenAI and Anthropic have no equivalent read-only call in this check. Ask the owner to read the project or workspace limit in the dashboard.

## Findings

Severity goes on `confirmed` records only, after the cap state is shown (the OpenRouter fields above, or the owner reading the dashboard). An unchecked key is `needs_validation` with that check as the plan.

| ID | Check | Finding |
|---|---|---|
| **SC1** | Leaked or long-lived LLM key with no hard cap at key, project, or workspace level | Medium. High if the key is in a public repo or a client bundle |
| **SC2** | A cap exists, but only at org level, shared by every app | Low. Hardening note |
| **SC3** | OpenRouter management (provisioning) key with no expiry | Medium. A management key can create, edit, and delete keys. Set an expiry |

## Sources

- [OpenRouter: API key limits](https://openrouter.ai/docs/api-reference/limits) (checked 2026-10-30)
- [OpenRouter: provisioning API keys](https://openrouter.ai/docs/guides/overview/auth/provisioning-api-keys) (checked 2026-10-30)
- [OpenAI: spend limits](https://developers.openai.com/api/docs/guides/spend-limits) (checked 2026-10-30)
- [Anthropic: rate limits](https://platform.claude.com/docs/en/api/rate-limits) and [workspaces](https://platform.claude.com/docs/en/manage-claude/workspaces) (checked 2026-10-30). "You cannot set spend limits on the Default Workspace."
