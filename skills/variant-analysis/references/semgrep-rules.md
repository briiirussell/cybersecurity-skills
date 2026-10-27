# Writing Semgrep rules for variants

What you need to turn a root cause into a Semgrep rule with tests. Checked against semgrep 1.182.1 (October 2026); syntax from the [rule syntax](https://docs.semgrep.dev/writing-rules/rule-syntax), [pattern syntax](https://docs.semgrep.dev/writing-rules/pattern-syntax), [taint mode](https://docs.semgrep.dev/writing-rules/data-flow/taint-mode/overview) and [testing](https://docs.semgrep.dev/writing-rules/testing-rules) docs.

## Rule skeleton

```yaml
rules:
  - id: <rule-id>                 # same as the file's base name
    languages: [javascript, typescript]
    severity: WARNING             # INFO | WARNING | ERROR; start at WARNING
    message: >-
      What is wrong, why it matters, and the fix. Metavariables like $REQ render in the message.
    metadata:
      cwe: "CWE-639: Authorization Bypass Through User-Controlled Key"
      category: security
      confidence: MEDIUM
      variant_of: <fingerprint of the original finding>
    patterns:
      - ...
```

One rule per file. A rule id that matches the file name keeps `semgrep --test` output readable.

## Pattern operators

| Operator | What it does | Variant use |
|---|---|---|
| `pattern` | Matches one code shape | The sink call |
| `patterns` | All children must match (logical AND) | Sink + context + guard exclusions |
| `pattern-either` | Any child may match (OR) | The same sink through several APIs |
| `pattern-not` | Removes matches of this shape | The fixed sibling (the guard is present) |
| `pattern-inside` | Keeps only matches inside this shape | "inside an Express route handler" |
| `pattern-not-inside` | Removes matches inside this shape | "unless inside `if (!isOwner(...)) return`" |
| `pattern-regex` | PCRE match on the source text | `generic` mode, SQL migrations, config |
| `metavariable-regex` | Filters on a bound metavariable's text | HTTP verb, method name, SQL text |
| `metavariable-pattern` | Runs a sub-pattern against a metavariable's content (can switch `language`) | SQL in a JS string, a nested expression |
| `metavariable-comparison` | Numeric or string comparison on a metavariable | key length, timeout values |
| `focus-metavariable` | Reports the metavariable's span instead of the whole match | Point at the argument, not the call |

Pattern syntax worth knowing:

- `...` matches any sequence of arguments, statements or keys: `f(..., $X, ...)`.
- `$X` binds any expression; the same name twice must match the same code.
- `<... $X ...>` matches `$X` anywhere inside an expression (deep expression operator).
- `"=~/regex/"` inside a pattern matches a string literal by regex: `$DB.prepare("=~/(?i)owner_id/")`.
- `"$SQL"` binds a string literal's content for `metavariable-regex`.

## Taint mode

Use it when the question is "does data from here reach there without passing through this". It tracks values through assignments and destructuring within a function (and, in Semgrep's Pro engine, across functions and files).

```yaml
    mode: taint
    pattern-sources:
      - patterns:
          - pattern-either:
              - pattern: $REQ.body
              - pattern: $REQ.query
              - pattern: $REQ.params
          - pattern-inside: |
              $ROUTER.$METHOD($PATH, ..., async ($REQ, $RES, ...) => { ... })
    pattern-sinks:
      - patterns:
          - pattern-either:
              - pattern: axios.get($URL, ...)
              - pattern: fetch($URL, ...)
          - focus-metavariable: $URL      # only the URL argument is the sink
    pattern-sanitizers:
      - by-side-effect: true              # a call that throws on bad input cleans the variable after it
        patterns:
          - pattern: assertAllowedHost($X)
          - focus-metavariable: $X
```

- `focus-metavariable` on a sink stops a tainted header or timeout option from counting as a URL.
- `by-side-effect: true` is for validators that throw or return early instead of returning a clean value. Without it, `assertAllowedHost(url); axios.get(url)` still reports.
- `pattern-propagators` teach taint about calls it can't see through (for example `Object.assign($TO, $FROM)` from `$FROM` to `$TO`).
- Check the sanitizer with an `ok:` case. In testing for this guide, adding a plain `pattern: assertAllowedHost(...)` sanitizer next to the `by-side-effect` one made the `ok:` case fail. Keep only the form the test proves.

## Test fixtures

Same base name as the rule, the target language's extension, in the same directory:

```text
.semgrep/variants/express-idor-param-lookup.yml
.semgrep/variants/express-idor-param-lookup.js
```

| Annotation (on the line above the code) | Meaning |
|---|---|
| `ruleid: <id>` | Must match. A miss fails the test |
| `ok: <id>` | Must not match. A hit fails the test |
| `todoruleid: <id>` | Should match one day; doesn't fail today |
| `todook: <id>` | Should stop matching one day; doesn't fail today |

```bash
semgrep --test --metrics=off .semgrep/variants/
# rules and fixtures in separate trees (subdirectory layouts must mirror each other)
semgrep --test --metrics=off --config .semgrep/rules/ .semgrep/tests/
# rule config sanity (duplicate patterns, missing fields)
semgrep --validate --metrics=off --config .semgrep/variants/
```

Output on failure names the rule and the lines: `missed lines: [12], incorrect lines: [50]`. Missed = a `ruleid` that didn't match; incorrect = a hit on a line with no `ruleid`.

Autofix rules get a `<rule-id>.fixed.<ext>` file with the expected result; `semgrep --test` compares the two. This skill doesn't ship autofix rules into CI.

## Gotchas found while building the example rule

- **Object patterns match a subset of keys.** `{ where: { id: $X } }` also matches `{ where: { id: $X, userId: req.user.id } }`. Exclude the guarded form explicitly with a `pattern-not`, and prove it with an `ok:` case.
- **`metavariable-regex` on a metavariable a branch doesn't bind drops that branch's matches.** Put the filter inside the branch that binds it (a nested `patterns` under `pattern-either`).
- **A regex guard checks that a name appears, not what it's bound to.** `WHERE owner_id = ?` bound to `req.params.id` passes an "owner_id is present" guard. Record it as `todoruleid` and triage those by hand.
- **Fixtures get scanned.** `semgrep scan --config .semgrep/ .` reports the `ruleid` lines in your own fixture. Add `--exclude .semgrep`.
- **Rule ids carry the config path.** Run from a local directory, `express-idor-param-lookup` comes out as `.semgrep.variants.express-idor-param-lookup`. Match on the suffix when rolling up.
- **Default ignores.** With no `.semgrepignore`, semgrep skips `tests/`, `node_modules/` and similar paths. Run with `--verbose` once to see what was skipped, so "no hits" means "no hits".
- **Generic mode** (`languages: [generic]`) is for SQL, config and templates semgrep can't parse. It matches text, so it needs more `ok:` cases than a parsed language. `scanner-pipeline`'s Supabase RLS rule is an example.

## Precision targets

- Start with `confidence: MEDIUM` and `severity: WARNING`.
- After the first run, count hits per verdict. More rejected than confirmed or needs-validation means another `pattern-not` (with an `ok:` case) before the rule goes to CI.
- Every rejected hit caused by a control the rule could have seen becomes an `ok:` case.

Ideas here are paraphrased from Trail of Bits' `semgrep-rule-creator` (tests first, taint where data flows, no rule without negative cases) and Semgrep's own docs. See SKILL.md References for links and licenses.
