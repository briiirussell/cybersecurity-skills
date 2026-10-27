# findings.json — the shared findings format

Audit skills in this repo write their results to `findings.json` first, validate it, and only then write the markdown report. The JSON is the record of what happened. The prose is rendered from it and **never changes a verdict, severity, blocker, or demonstrated impact** that the JSON doesn't already say.

Files that ship next to this guide in `references/`:

| File | What it is |
|---|---|
| `findings.schema.json` | JSON Schema (draft 2020-12), for editors and external tools |
| `validate-findings.mjs` | Zero-dependency validator. It is the authority: it enforces rules JSON Schema can't express |
| `to-sarif.mjs` | Converts `findings.json` to SARIF 2.1.0 for GitHub code scanning and other SARIF viewers |

Any current Node (18+) runs both scripts. Nothing to install.

## Workflow

1. Drop the candidates the fixed exclusion rules catch (test code, fixtures, generated, vendored, docs; see "Two stages" in `verification.md`). They get no record. Close every remaining candidate with one verdict (see below) and write the record.
2. Sort by `fingerprint` and write `findings.json`.
3. Validate, and fix until it passes:
   ```bash
   node references/validate-findings.mjs findings.json
   ```
   Exit `0` = valid, `1` = invalid (one line per problem), `2` = unreadable or not JSON.
4. Render the markdown report from the JSON. Confirmed findings go in the findings table. Needs-validation items go in their own section with their blockers and plan. Rejected records go in "Rejected (do not re-raise)". Hardening notes are not records at all (see below).
5. Optional, export SARIF:
   ```bash
   node references/to-sarif.mjs findings.json -o findings.sarif
   node references/to-sarif.mjs findings.json --include-needs-validation -o findings.sarif
   ```

On a re-run, load the previous `findings.json` first and match candidates by fingerprint. A candidate that matches a `rejected` record stays rejected unless the code at `ruled_out_by.location` changed. A candidate that matches a `Fixed` record is re-checked against the fix: if the fix still rules it out, the record stays `Fixed` and isn't re-raised; if not, it's a regression and the record reopens (see `finding-triage`'s fix verification).

## Verdicts

Every record has exactly one `verdict`. Each verdict has its own shape, and unknown fields are errors.

| Verdict | Meaning | Extra required fields | Severity? |
|---|---|---|---|
| `confirmed` | Complete entrypoint → sink trace with impact, or a working PoC | `severity`, `conditions[]`. Optional: `disposition`, `reproduced` | Yes |
| `needs_validation` | The code supports the claim, but one decisive fact lives outside it (proxy, IdP, deploy config, feature flag) | `blockers[]` (non-empty), `validation_plan` | **No** |
| `rejected` | A named control at a named location runs on every attacker-reachable path before the sink, or the claim is ruled out by reachability or a known-inert value | `ruled_out_by {control, location}` | **No** |

`needs_validation` is not a parking spot for a hunch. If you can't name the blocker and a check the owner can run to settle it, the candidate is either rejected or not ready to record. The old "Potential" label is retired.

A **false positive** is recorded as `rejected`. It is not a disposition.

## Fields

Common to all three shapes:

| Field | Type | Notes |
|---|---|---|
| `fingerprint` | string | Stable root-cause id: 3–200 chars of `A-Z a-z 0-9 . _ : / @ + -`. **Never** a line number, severity or verdict. The validator rejects `:<digits>` segments that look like line numbers |
| `verdict` | enum | `confirmed` \| `needs_validation` \| `rejected` |
| `skill` | string | The skill that produced it, e.g. `owasp-audit` |
| `title` | string | One line, specific |
| `cwe` | string, optional | `CWE-639` |
| `owasp_category` | string, optional | `A01:2025`, `API1:2023` |
| `ext` | object, optional | The producing skill's own fields (see "Skill-specific fields" below) |
| `location` | `{file, line}` | Primary location. `file` is repo-relative, `line` ≥ 1 |
| `trace[]` | `{kind, file, line, description}` | `kind` ∈ `entrypoint` \| `propagation` \| `sink`. A non-empty trace starts with `entrypoint`, ends with `sink`, and has neither in the middle. `confirmed` needs ≥ 2 steps; the others may be `[]` |
| `evidence[]` | `{file, line, description}` | `confirmed` needs ≥ 1 |
| `counterevidence` | string | What the verifier tried in order to refute it, and what it found. Required on every verdict |
| `confidence` | enum | `high` \| `medium` \| `low`. On `confirmed`, `high` requires `"reproduced": true`: a static-only trace caps at `medium` |

`confirmed` only:

| Field | Type | Notes |
|---|---|---|
| `severity` | `{likelihood{score, reason}, impact{score, reason}, overall}` | Scores and `overall` ∈ `critical` \| `high` \| `medium` \| `low`. **`overall` ≤ `impact.score`.** See `severity-calibration.md` |
| `conditions[]` | `{kind, description}` | Preconditions for exploitation. `kind` ∈ `authentication_level`, `authorization_role`, `user_interaction`, `system_configuration`, `network_routing`, `environmental_dependency`, `data_state`, `timing_dependency`, `third_party_dependency`. May be `[]` |
| `reproduced` | boolean, optional | `true` only when demonstrated dynamically (PoC, test, request/response pair) |
| `disposition` | enum, optional | `Fixed` \| `Deferred` \| `Accepted Risk` \| `Mitigated (platform/config)` \| `Requires major migration`. Usually set by `finding-triage` |

`needs_validation` only: `blockers[]` (non-empty strings, one per decisive fact) and `validation_plan` (a concrete check the owner can run locally and/or against the deployment).

`rejected` only: `ruled_out_by.control` (what the control does) and `ruled_out_by.location` (`{file, line}` where it runs). When nothing runs because the code is never reached, the value is a published example, or the guard is inside a dependency, `control` states that fact and `location` points at its evidence: the only call site, the declaring manifest line, the line holding the value, or the lockfile pin. `verification.md` has the table.

A hard-coded fallback or other unsafe shipped default is `confirmed`, not `needs_validation`; the deployment fact caps confidence instead. See "Unsafe shipped defaults" in `verification.md`.

### Rules the validator enforces

- Top level is an array, sorted by `fingerprint` in plain code-unit order (`jq 'sort_by(.fingerprint)'` gives the same order for ASCII ids). No duplicate fingerprints.
- Shape per verdict, with no extra fields. `severity` and `disposition` appear only on `confirmed`.
- Paths are repo-relative with forward slashes: no leading `/`, drive letter, `~`, URL, backslash or `..` segment.
- Every `line` is an integer ≥ 1.
- Trace order (entrypoint first, sink last). `overall` ≤ impact. `high` confidence on `confirmed` needs `reproduced: true`.
- `needs_validation` has non-empty `blockers` and `validation_plan`. `rejected` has `ruled_out_by`.

### Skill-specific fields (`ext`)

Some skills need fields the common shape doesn't have: the PCI DSS requirement a gap is against, the cloud account and region of a resource, the MASVS control, the HIPAA standard. Those go in `ext`, never as new top-level fields (the validator rejects unknown fields). Each skill lists its `ext` keys in its own SKILL.md.

- Keys are snake_case (`requirement`, `in_cde`, `account`). Values are a non-empty string, a number, a boolean, or a non-empty array of those. No nesting, no `null`, no empty `ext` (leave it out instead).
- Don't repeat what already has a field. The CWE goes in `cwe`, the OWASP category in `owasp_category`, the file in `location`.
- `to-sarif.mjs` copies `ext` into the SARIF result's `properties.ext` unchanged.

```json
"ext": { "requirement": "8.4.2", "in_cde": true }
```

`finding-triage` adds three keys to any confirmed record it closes as `Fixed`, next to the producing skill's own: `fixed_in` (the fixing commit SHA or release tag), `fix_verified_on` (`YYYY-MM-DD`, when the fix check passed against the shipped fix) and `regression_test` (repo-relative path or array of paths). A record that regresses loses `disposition`, `fixed_in` and `fix_verified_on`, and gets `regressed_after` with the old `fixed_in` value. Skills shouldn't use these four names for anything else.

### Findings about deployed resources

Not every finding lives in a source file. A cloud bucket policy, an IdP setting, a live host's TLS configuration or a decompiled app binary still needs a `location`. Save the read-only output that shows the problem into the audit's output directory, then point `location` and `evidence[]` at that file and line:

```text
security-audit/evidence/aws-s3-get-bucket-policy-prod-assets.json   # aws s3api get-bucket-policy ... > this file
```

- Redact before saving. Never write a secret value, a session token or customer data into an evidence file.
- Record the command and the time it ran in the evidence `description`, so the owner can run it again.
- Build the fingerprint from the resource's own id, with slashes: `cloud-audit/s3-public-read/aws/123456789012/prod-assets`. ARNs and `host:port` contain `:<digits>`, which the validator reads as a line number.

## Fingerprints

A fingerprint names the root cause, so the same bug keeps the same id after code moves, severity changes, or the verdict flips. A good pattern:

```
<skill>/<cwe-or-class>/<repo-relative file>/<function, route, or resource>
api-audit/CWE-639/src/routes/orders.ts/refundOrder
secrets-audit/aws-access-key/config/deploy.yml/AWS_ACCESS_KEY_ID
dependency-audit/GHSA-xxxx-xxxx-xxxx/package-lock.json/lodash
```

If a file is renamed, keep the old fingerprint when it's obviously the same root cause. Don't put the line number, the date or the severity in it.

## Example

```json
[
  {
    "fingerprint": "api-audit/CWE-639/src/routes/orders.ts/refundOrder",
    "verdict": "confirmed",
    "skill": "api-audit",
    "title": "Refund endpoint lets any user refund another user's order (IDOR)",
    "cwe": "CWE-639",
    "owasp_category": "API1:2023",
    "location": { "file": "src/routes/orders.ts", "line": 88 },
    "trace": [
      { "kind": "entrypoint", "file": "src/routes/orders.ts", "line": 84, "description": "POST /api/orders/:id/refund reads :id" },
      { "kind": "propagation", "file": "src/services/orders.ts", "line": 41, "description": "findOrder(id) has no owner filter" },
      { "kind": "sink", "file": "src/services/payments.ts", "line": 17, "description": "refund issued" }
    ],
    "evidence": [{ "file": "src/services/orders.ts", "line": 41, "description": "WHERE id = $1, no user_id predicate" }],
    "counterevidence": "requireAuth only authenticates; no policy on this route. Sibling GET /orders/:id does check ownership.",
    "confidence": "high",
    "reproduced": true,
    "severity": {
      "likelihood": { "score": "high", "reason": "Open signup; sequential ids" },
      "impact": { "score": "high", "reason": "Refunds another customer's payment" },
      "overall": "high"
    },
    "conditions": [{ "kind": "authentication_level", "description": "Any user account" }]
  },
  {
    "fingerprint": "owasp-audit/CWE-89/src/db/search.ts/searchProducts",
    "verdict": "rejected",
    "skill": "owasp-audit",
    "title": "String-built SQL in product search",
    "location": { "file": "src/db/search.ts", "line": 30 },
    "trace": [],
    "evidence": [{ "file": "src/db/search.ts", "line": 30, "description": "ORDER BY column interpolated" }],
    "counterevidence": "Column comes from a fixed map; user input never reaches the template literal.",
    "confidence": "high",
    "ruled_out_by": { "control": "SORT_COLUMNS allow-list; unknown keys throw before the query is built", "location": { "file": "src/db/search.ts", "line": 22 } }
  },
  {
    "fingerprint": "owasp-audit/CWE-918/src/lib/fetch-preview.ts/fetchPreview",
    "verdict": "needs_validation",
    "skill": "owasp-audit",
    "title": "Link-preview fetcher may reach the cloud metadata endpoint (SSRF)",
    "location": { "file": "src/lib/fetch-preview.ts", "line": 12 },
    "trace": [
      { "kind": "entrypoint", "file": "src/routes/preview.ts", "line": 5, "description": "GET /preview?url=" },
      { "kind": "sink", "file": "src/lib/fetch-preview.ts", "line": 12, "description": "fetch(url), no allow-list" }
    ],
    "evidence": [],
    "counterevidence": "No allow-list in code. Egress filtering, if any, is in the platform, not the repo.",
    "confidence": "medium",
    "blockers": ["Does the production egress proxy block 169.254.169.254 and RFC 1918 ranges?"],
    "validation_plan": "From staging, request /preview?url=http://169.254.169.254/latest/meta-data/ and confirm it is blocked."
  }
]
```

## Hardening notes are not records

A gap with no traced impact (defense-in-depth, a missing header with no exploit path, a cookie flag that changes nothing reachable) is a **hardening note**. It doesn't go in `findings.json`, never gets a severity, and goes in the report's "Hardening notes (not findings)" section.

## SARIF export

`to-sarif.mjs` validates first and writes nothing if validation fails (exit 1).

| findings.json | SARIF 2.1.0 |
|---|---|
| `confirmed` record | one `result` and one `rule` (rule id = fingerprint, so each rule's severity matches its only result) |
| `needs_validation` | skipped by default. With `--include-needs-validation`: a `note`-level result with no `security-severity`; the message starts "Needs validation:" and lists the blockers and plan; `properties.verdict = "needs_validation"` |
| `rejected` | never exported |
| `fingerprint` | `partialFingerprints["cybersecuritySkills/v1"]` |
| `severity.overall` | `security-severity` on the rule and the result: critical `9.5`, high `8.0`, medium `5.5`, low `3.0`. `level`: critical/high → `error`, medium → `warning`, low → `note` |
| `location` | `locations[0]`, relative to `%SRCROOT%` |
| `trace[]` | `codeFlows[0].threadFlows[0].locations`, each with `kinds: [<trace kind>]` |
| `evidence[]` | `relatedLocations` |
| `cwe`, `owasp_category` | rule tags `external/cwe/cwe-N` and `owasp/<id>`; `helpUri` → the MITRE CWE page |
| `disposition: Fixed` | skipped (nothing left to alert on) |
| `disposition: Accepted Risk` / `Mitigated (platform/config)` | exported with an `accepted` external suppression, so it shows as dismissed rather than open |

Upload to GitHub code scanning with `github/codeql-action/upload-sarif` (`sarif_file: findings.sarif`).

## Coverage (owasp-audit, api-audit)

Those skills also write `coverage.json`, which records what was reviewed so "no findings" can be told apart from "not looked at". Validate it, and optionally cross-check its fingerprints against `findings.json`:

```bash
node references/validate-coverage.mjs coverage.json --findings findings.json
```

A unit is `{id, surface, boundary, owasp_category, status, reviewed_paths[], checks[{invariant, method, result}], finding_fingerprints[], unresolved[]}`. All fields are required; `owasp_category` may be `null`. `status` ∈ `planned`, `in_progress`, `blocked`, `covered`, `candidate`, `deferred`, `out_of_scope`, `not_applicable`. Units have unique ids, and `reviewed_paths` follow the same safe-path rule (globs allowed). The validator also requires:

- `covered`: at least one reviewed path and at least one check. With `--findings`, it may list only `rejected` fingerprints
- `candidate`: at least one finding fingerprint. A unit with a confirmed or needs_validation finding stays `candidate`
- `blocked`: at least one unresolved item

Unit ids use the same characters as fingerprints and may also start with `.`, for dotfiles.

`coverage.schema.json` documents the shape.

## Attribution

The three verdict-shaped records, the root-cause fingerprint, the trace/evidence split, the condition kinds, the coverage ledger and the "JSON drives the prose" rule are adapted from [cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill) (`report-schema.json`, `validate-findings.cjs`, `VALIDATION-AND-REPORTING.md`), MIT License, Copyright (c) Cloudflare, Inc. The schema, validator code and this guide are this repo's own and are paraphrased, not copied.
