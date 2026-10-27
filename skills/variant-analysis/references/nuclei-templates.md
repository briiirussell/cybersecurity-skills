# Writing nuclei templates for variants

Some variants only show from outside: the same route shape deployed on five apps, a header a reverse proxy should set, an endpoint that answers when it shouldn't. A nuclei template checks those over HTTP. It sends real requests, so every rule here is about keeping it safe and scoped.

Field names follow nuclei v3 (`http:`, not the v2 `requests:`) per the [template docs](https://docs.projectdiscovery.io/templates/introduction), [HTTP basics](https://docs.projectdiscovery.io/templates/protocols/http/basic-http), [matchers](https://docs.projectdiscovery.io/templates/reference/matchers) and [variables](https://docs.projectdiscovery.io/templates/reference/variables); CLI flags from the nuclei README (`-validate`, `-var`, `-rl`), October 2026.

## Before writing one

- The code variant (Semgrep or CodeQL) is the primary proof. Use nuclei when you don't have the code (another team's deploy of the same service), when the guard lives in infrastructure (gateway, proxy, CDN), or to confirm the fix landed in production.
- Hosts: only those the user owns and names in this conversation, after `web-pentest`'s authorization step. Staging first.
- Requests change nothing: `GET` or `HEAD`, or a request the app treats as read-only. No `DELETE`, no writes, no fuzzing, no payload lists.
- Data: two test accounts the user created (A and B), and a record B owns that holds a unique marker string. The template proves A can read B's marker. It never reads real users' records.

## Skeleton: cross-account read (IDOR variant)

```yaml
id: notes-idor-read-by-id

info:
  name: Notes API - one account can read another account's note by id
  author: your-team
  severity: high
  description: >-
    Variant check for a lookup keyed only by the URL id. Account A requests a note
    owned by account B and the response contains B's marker string.
  tags: variant,idor,authz
  classification:
    cwe-id: CWE-639
  metadata:
    variant-of: owasp-audit/CWE-639/src/routes/notes.js/GET-note-by-id

variables:
  token_a: "set-with-var"       # account A's session token (test account)
  record_b: "0"                 # id of a note account B owns
  marker_b: "set-with-var"      # unique string planted in that note's body

http:
  - method: GET
    path:
      - "{{BaseURL}}/api/notes/{{record_b}}"
    headers:
      Authorization: "Bearer {{token_a}}"
      Accept: application/json

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "{{marker_b}}"
```

Why it's built this way:

- `matchers-condition: and`: a 200 alone means nothing (an error page can be 200); the marker alone could come from a cached page. Both together mean A read B's data.
- The marker is a random string you planted, so a match can't be a coincidence and the response carries no real data.
- `variables` hold placeholders; real values come in at run time with `-var`, so no token lives in the template file.

Other variant shapes, same structure:

| Variant | Request | Matchers (all with `and`) |
|---|---|---|
| Admin route reachable without the admin role | `GET {{BaseURL}}/api/admin/users` with a normal test account | `status: [200]` + a `word` that only appears in the admin payload |
| Proxy not stripping an internal header | `GET` with the header set | `status: [200]` + `word` in `part: header` |
| Debug endpoint left on | `GET {{BaseURL}}/<path from the original finding>` | `status: [200]` + a `word` or `regex` unique to the debug page |
| Fixed shape (use as a negative check) | the same request | add a matcher with `negative: true` for the safe response's marker |

## Validate, then run against known answers

```bash
nuclei -validate -t .nuclei/variants/notes-idor-read-by-id.yaml
```

`-validate` parses the template and sends nothing. Then, on staging, one host at a time:

```bash
# 1. Known present: the original, unfixed deploy. Expect a match.
nuclei -t .nuclei/variants/notes-idor-read-by-id.yaml -u https://staging.example.com \
  -var token_a=<test-A-token> -var record_b=<B-note-id> -var marker_b=<marker> \
  -rl 5 -c 1 -jsonl -o .security/out/nuclei-variants.jsonl
# 2. Known fixed: a deploy with the owner check. Expect no match.
# 3. Only then: the other hosts the user named, same flags.
```

If step 1 doesn't match, the template is wrong; if step 2 matches, the matchers are too loose. Fix before step 3. Stop on 5xx spikes, rate limiting or lockouts and tell the user.

Pass test-account tokens only, and expire them after the run. Values given on the command line can land in shell history.

## Triage

A nuclei match is a candidate like any other hit:

- Match on a host whose code you can read: trace the route in code, then `confirmed` with `reproduced: true` (the match is the reproduction) if the trace holds.
- Match on a host whose code you can't see: `confirmed` is still possible when the response proves the impact (B's marker in A's response); record the request and response as evidence under `<audit dir>/evidence/`, redacted, and `location` pointing at that file.
- No match, but the host may be behind a gateway that differs between environments: `needs_validation`, with the gateway's behaviour in production as the blocker.

`ext.rule_engine` is `nuclei`, `ext.rule_id` is the template `id`, `ext.rule_path` is the template's repo-relative path.

## Keeping it

Store variant templates in the repo (`.nuclei/variants/`) or a private templates repo, and run them on a schedule against staging from `scanner-pipeline`'s guarded live-scan step. Don't contribute a template to the public community repository without the user deciding to; it describes a bug in their product.
