# Log Watch — Detection Queries by Source

Starter queries for the detections in `SKILL.md`. Every query reads `[checkpoint − overlap, now]`. Run each one by hand first, look at real output, and adjust field names to what the source actually emits. Items marked **(verify)** use flags or fields that vary by plan or version; check `--help` or the provider's schema before relying on them.

All credentials here are read-only. If a query needs more than read, the query is wrong.

## Discovery first

Before writing any detection, find out what each source records. Ten minutes here saves a week of tuning.

```sql
-- Postgres / Supabase: what auth-ish tables exist?
SELECT table_schema, table_name FROM information_schema.tables
WHERE table_name ~* '(auth|login|session|audit|event|api_key|token|member|role)'
ORDER BY 1, 2;

-- Supabase: which actions does the auth audit log actually record in this project?
SELECT payload->>'action' AS action, count(*)
FROM auth.audit_log_entries
WHERE created_at > now() - interval '7 days'
GROUP BY 1 ORDER BY 2 DESC;
```

Supabase's `auth.audit_log_entries` records auth events with a JSON `payload` (the `action` key names the event) — but whether **failed** password logins appear there depends on version and configuration; they are reliably in the Auth logs (Logs Explorer / log drain). If the table doesn't have them, read the Auth logs or add an app-level `login_failed` record.

```bash
vercel logs --help                      # current flags; they change between CLI versions
vercel logs --since 15m --limit 5 --json # look at one JSON line before writing jq
heroku logs -a APP -n 20 --dyno router   # confirm router line format
```

## Reference app tables

Most detections are easier if the app has one append-only table. If it doesn't, recommend it (that's a logging gap, not a finding):

```sql
CREATE TABLE security_events (
  id          bigserial PRIMARY KEY,
  created_at  timestamptz NOT NULL DEFAULT now(),
  event_type  text NOT NULL,   -- login_succeeded, login_failed, role_changed, api_key_created, export_requested, webhook_sig_failed
  actor_id    text,            -- user/account id (not email)
  target_id   text,            -- affected user / org / key id
  ip          inet,
  user_agent  text,
  detail      jsonb
);
CREATE INDEX ON security_events (event_type, created_at);
-- Watcher role: SELECT only.
CREATE ROLE log_watch LOGIN PASSWORD '…';
GRANT USAGE ON SCHEMA public TO log_watch;
GRANT SELECT ON security_events TO log_watch;
```

The queries below assume `security_events`; translate to the team's real tables.

## D1 — Credential stuffing / brute force

```sql
-- Per IP: many failures or many distinct accounts
SELECT ip, count(*) AS failures, count(DISTINCT target_id) AS accounts,
       min(created_at) AS first_seen, max(created_at) AS last_seen
FROM security_events
WHERE event_type = 'login_failed'
  AND created_at > now() - interval '10 minutes'
GROUP BY ip
HAVING count(*) >= 20 OR count(DISTINCT target_id) >= 10;

-- Per account: targeted guessing
SELECT target_id, count(*) AS failures, count(DISTINCT ip) AS ips
FROM security_events
WHERE event_type = 'login_failed'
  AND created_at > now() - interval '10 minutes'
GROUP BY target_id
HAVING count(*) >= 10;

-- Escalation: a success from an IP that just crossed the failure threshold
SELECT s.target_id, s.ip, s.created_at
FROM security_events s
WHERE s.event_type = 'login_succeeded'
  AND s.created_at > now() - interval '10 minutes'
  AND s.ip IN (
    SELECT ip FROM security_events
    WHERE event_type = 'login_failed' AND created_at > now() - interval '30 minutes'
    GROUP BY ip HAVING count(*) >= 20);
```

Dedupe key: `D1:ip:<ip>` and `D1:acct:<target_id>`. Distributed attacks spread across thousands of IPs — add a global rate check (total failures in 10 min > 5× the trailing 7-day same-hour mean).

## D2 — New admin / owner grant

```sql
SELECT created_at, actor_id, target_id, detail->>'old_role' AS old_role, detail->>'new_role' AS new_role, ip
FROM security_events
WHERE event_type = 'role_changed'
  AND detail->>'new_role' IN ('owner', 'admin', 'superuser')
  AND created_at > :checkpoint;
```

If roles live in a `memberships` table with no history, there's nothing to diff. Recommend an audit trigger that writes to `security_events` on `UPDATE OF role`.

GitHub (Enterprise Cloud orgs):

```bash
gh api -X GET "/orgs/$ORG/audit-log" \
  -f phrase="action:org.update_member created:>=$SINCE_DATE" -f per_page=100
gh api -X GET "/orgs/$ORG/audit-log" \
  -f phrase="action:org.add_member created:>=$SINCE_DATE" -f per_page=100
```

`-X GET` matters: without it, `gh api -f` sends a POST. `created:` takes a date (`YYYY-MM-DD`); filter to the exact checkpoint client-side on `@timestamp`. Other useful actions: `repo.add_member`, `team.add_member`, `hook.create`, `org.add_outside_collaborator` **(verify names against the audit-log docs for your plan)**.

## D3 — API key / token created or rotated

```sql
SELECT created_at, actor_id, target_id AS key_id, detail->>'scopes' AS scopes, ip
FROM security_events
WHERE event_type IN ('api_key_created', 'api_key_rotated')
  AND created_at > :checkpoint;
```

AWS access keys: `CreateAccessKey` via CloudTrail (D9 query with `EventName`). GitHub: `phrase=action:personal_access_token` / deploy keys **(verify)**.

## D4 — 401/403/404 spikes on sensitive paths

Path pattern (portable ERE):

```
^/(\.env(\..*)?|\.git(/.*)?|wp-admin(/.*)?|wp-login\.php|admin(/.*)?|api/internal(/.*)?|.*\.(bak|sql|zip|tar\.gz))$
```

Vercel **(verify field names on one JSON line first)**:

```bash
vercel logs --environment production --since 10m --limit 2000 --json \
| jq -c 'select((.requestPath // .path // "") | test("^/(\\.env|\\.git|wp-admin|wp-login|admin|api/internal)"))
         | {ts: (.timestamp // .ts), status: (.responseStatusCode // .statusCode), path: (.requestPath // .path), ip: (.clientIp // .ip)}'
```

Heroku router lines (`path="…" status=404 fwd="1.2.3.4"`):

```bash
heroku logs -a APP -n 1500 --dyno router \
| grep -E 'path="/(\.env|\.git|wp-admin|wp-login\.php|admin|api/internal)' \
| grep -E 'status=(401|403|404|200)'
```

For scheduled runs, read from the drain destination instead; `heroku logs` is a small rolling buffer.

Cloudflare GraphQL Analytics **(verify dataset and field names for your plan)**:

```graphql
query ($zone: String!, $since: Time!) {
  viewer {
    zones(filter: { zoneTag: $zone }) {
      httpRequestsAdaptiveGroups(
        limit: 100
        filter: { datetime_geq: $since, edgeResponseStatus_in: [200, 401, 403, 404], clientRequestPath_like: "%/.env%" }
        orderBy: [count_DESC]
      ) {
        count
        dimensions { clientIP clientRequestPath edgeResponseStatus }
      }
    }
  }
}
```

Severity: probes returning 4xx are background noise on the internet — low, digest only, unless one IP is persistent. **Any 2xx on `/.env` or `/.git/config` is critical**: something sensitive is being served.

## D5 — Webhook signature failures

The provider doesn't know your verification failed; only your app does. Make the handler log a structured line (`event=webhook_sig_failed provider=stripe ip=…`) or a `security_events` row, then:

```sql
SELECT detail->>'provider' AS provider, ip, count(*)
FROM security_events
WHERE event_type = 'webhook_sig_failed' AND created_at > now() - interval '10 minutes'
GROUP BY 1, 2 HAVING count(*) >= 5;
```

Sentry, if the handler raises on bad signatures **(verify search syntax in your Sentry version)**:

```bash
curl -s -H "Authorization: Bearer $SENTRY_READ_TOKEN" \
  "https://sentry.io/api/0/organizations/$ORG/issues/?project=$PROJECT_ID&statsPeriod=1h&query=is:unresolved%20signature"
```

A spike right after a deploy is usually a rotated secret, not an attack — check the deploy log before paging high.

## D6 — Unusual export / download volume

```sql
WITH recent AS (
  SELECT actor_id, count(*) AS n
  FROM security_events
  WHERE event_type = 'export_requested' AND created_at > now() - interval '1 hour'
  GROUP BY actor_id),
baseline AS (
  SELECT actor_id, percentile_cont(0.95) WITHIN GROUP (ORDER BY n) AS p95
  FROM (SELECT actor_id, date_trunc('hour', created_at) AS h, count(*) AS n
        FROM security_events
        WHERE event_type = 'export_requested' AND created_at > now() - interval '14 days'
        GROUP BY 1, 2) x
  GROUP BY actor_id)
SELECT r.actor_id, r.n, coalesce(b.p95, 0) AS p95
FROM recent r LEFT JOIN baseline b USING (actor_id)
WHERE r.n > greatest(5 * coalesce(b.p95, 0), 50);
```

Include signed-URL generation and bulk list endpoints with large `limit` if exports aren't a discrete action.

## D7 — Impossible travel

Needs IP geolocation (e.g. MaxMind GeoLite2 loaded locally — don't send customer IPs to a third-party geo API without saying so). Compute in code, not SQL, unless PostGIS is present:

```
for each account with ≥2 login_succeeded in the last 24 h, ordered by time:
  d = haversine(geo(prev.ip), geo(cur.ip)) in km
  t = (cur.ts − prev.ts) in hours
  if d > 500 and d / max(t, 0.01) > 900 and asn(cur.ip) not in known_vpn_or_cloud_asns:
      alert D7:acct:<id>
```

High false-positive rate (VPNs, mobile carriers, corporate egress). Keep at medium and route to digest until tuned.

## D8 — Stripe refund / dispute spikes

Restricted key with **Events: read** only.

```bash
curl -sG https://api.stripe.com/v1/events -u "$STRIPE_RESTRICTED_KEY:" \
  -d "types[]=charge.refunded" -d "types[]=charge.dispute.created" \
  -d "created[gte]=$CHECKPOINT_UNIX" -d limit=100
```

Paginate with `starting_after` while `has_more` is true. Compare hourly refund count to the trailing 7-day hourly mean; disputes are rarer, so use an absolute count. A refund spike can be a compromised admin account or support tool — check D2/D3 for the same window.

## D9 — CloudTrail IAM changes and root logins

Read-only policy: `cloudtrail:LookupEvents` on `*`. `lookup-events` takes one lookup attribute per call, covers 90 days of management events, and is rate-limited (~2 requests/s per account per region). IAM is a global service whose events, and most sign-in events, are recorded in `us-east-1`.

```bash
# IAM writes since checkpoint
aws cloudtrail lookup-events --region us-east-1 \
  --lookup-attributes AttributeKey=EventSource,AttributeValue=iam.amazonaws.com \
  --start-time "$CHECKPOINT" --end-time "$NOW" --output json \
| jq -c '.Events[].CloudTrailEvent | fromjson | select(.readOnly == false)
         | {eventTime, eventName, principal: .userIdentity.arn, type: .userIdentity.type, ip: .sourceIPAddress, eventID}'

# Root console logins
aws cloudtrail lookup-events --region us-east-1 \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin \
  --start-time "$CHECKPOINT" --end-time "$NOW" --output json \
| jq -c '.Events[].CloudTrailEvent | fromjson | select(.userIdentity.type == "Root")
         | {eventTime, ip: .sourceIPAddress, result: .responseElements.ConsoleLogin, mfa: .additionalEventData.MFAUsed}'

# Logging tampering — any is critical
for ev in StopLogging DeleteTrail UpdateTrail PutEventSelectors; do
  aws cloudtrail lookup-events --region "$TRAIL_REGION" \
    --lookup-attributes AttributeKey=EventName,AttributeValue=$ev \
    --start-time "$CHECKPOINT" --end-time "$NOW" --output json
done
```

Exclude the deploy pipeline's role ARN from "IAM write outside pipeline", but never from root-login or logging-tamper rules. Use `eventID` as part of the evidence link. At higher volume, an EventBridge rule on these event names is cheaper and faster than polling — mention it, but that's moving toward `siem-detection` / `cloud-audit` territory.

## D10 — Outbound to collector domains

Only if egress/DNS logs exist (Route 53 Resolver query logs, Cloudflare Gateway, a forward proxy, VPC flow logs + DNS).

Domain pattern (portable ERE, match against the queried hostname or `Host`):

```
(^|\.)(webhook\.site|requestbin\.(com|net)|pipedream\.net|ngrok\.io|ngrok-free\.app|ngrok\.app|burpcollaborator\.net|oast\.(fun|live|site|online|pro|me)|interact\.sh)$
```

Plus URL-level matches where full URLs are logged: `discord(app)?\.com/api/webhooks/`, `api\.telegram\.org/bot`.

Any match from a server workload is high; from a developer laptop it's likely legitimate testing — scope the rule to production egress.

## Stage 1 input normalization

What the Stage 1 classifier actually sees per row — fields truncated, no free-form blobs:

```json
{"id": "evt_…", "src": "vercel", "ts": "2026-10-26T14:03:11Z", "status": 404,
 "method": "GET", "path": "/api/v1/../../.env", "ip_prefix": "203.0.113.0/24",
 "ua": "Mozilla/5.0 … (truncated to 200)", "msg": "(error message truncated to 300)"}
```
