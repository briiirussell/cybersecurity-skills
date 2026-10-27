# Writing CodeQL queries for variants

Use CodeQL when the variant's flow crosses functions or files, or when you need to know a sink is reachable from a request handler rather than just present. It costs more than Semgrep: a database build per repo and a slower edit-run loop. If a Semgrep rule finds the variants with acceptable noise, stop there.

Layout and commands follow GitHub's [testing custom queries](https://docs.github.com/en/code-security/codeql-cli/using-the-advanced-functionality-of-the-codeql-cli/testing-custom-queries) and [CodeQL packs](https://docs.github.com/en/code-security/codeql-cli/using-the-advanced-functionality-of-the-codeql-cli/creating-and-working-with-codeql-packs) docs; the data flow API follows [analyzing data flow in JavaScript and TypeScript](https://codeql.github.com/docs/codeql-language-guides/analyzing-data-flow-in-javascript-and-typescript/). The skeleton below was written against those docs and the `Express.qll` model in github/codeql (October 2026). It was not compiled for this guide, so run `codeql test run` before trusting it, and fix what the compiler reports.

## Layout

```text
.codeql/variants/
  codeql-workspace.yml          # lets the test pack resolve the query pack locally
  queries/
    qlpack.yml
    IdorParamLookup.ql
  tests/
    qlpack.yml
    IdorParamLookup/
      IdorParamLookup.qlref     # one line: the query's path relative to the query pack root
      test.js                   # positive and negative cases
      IdorParamLookup.expected  # reviewed output; .qlref and .expected share a base name
```

`codeql-workspace.yml`:

```yaml
provide:
  - "*/qlpack.yml"
```

`queries/qlpack.yml`:

```yaml
name: acme/variant-queries
version: 0.0.1
dependencies:
  codeql/javascript-all: "*"
```

`tests/qlpack.yml` (no `version`, so it can't be published by accident):

```yaml
name: acme/variant-queries-tests
dependencies:
  acme/variant-queries: "*"
extractor: javascript
tests: .
```

`tests/IdorParamLookup/IdorParamLookup.qlref`:

```text
IdorParamLookup.ql
```

## Query skeleton (taint tracking, path problem)

```ql
/**
 * @name Record lookup keyed by a route parameter with no owner predicate
 * @description A route parameter reaches a SQL lookup whose text never mentions an owner or tenant column.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id js/variants/idor-param-lookup
 * @tags security
 *       external/cwe/cwe-639
 */

import javascript

module IdorConfig implements DataFlow::ConfigSig {
  // Source: Express req.params.* / req.query.* reads (kind "parameter" in Express.qll)
  predicate isSource(DataFlow::Node source) {
    source.(Http::RequestInputAccess).getKind() = "parameter"
  }

  // Sink: an argument to .get/.all/.run on a statement prepared from SQL that
  // never names an owner or tenant column (better-sqlite3 style)
  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::MethodCallNode prepare, DataFlow::MethodCallNode exec |
      prepare.getMethodName() = "prepare" and
      exec = prepare.getAMethodCall(["get", "all", "run"]) and
      sink = exec.getAnArgument() and
      not prepare.getArgument(0).getStringValue()
          .regexpMatch("(?is).*\\b(owner_id|user_id|tenant_id|org_id)\\b.*")
    )
  }

  // Barrier: a value that went through an explicit ownership check
  predicate isBarrier(DataFlow::Node node) {
    node.(DataFlow::CallNode).getCalleeName() = ["assertOwner", "requireOwnership"]
  }
}

module IdorFlow = TaintTracking::Global<IdorConfig>;

import IdorFlow::PathGraph

from IdorFlow::PathNode source, IdorFlow::PathNode sink
where IdorFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Record looked up by $@ with no owner or tenant predicate in the query.", source.getNode(),
  "a route parameter"
```

Adapt per bug:

- **Sources:** `Http::RequestInputAccess` covers Express, Koa, Fastify and others the library models; filter on `getKind()` (`parameter`, `body`, `header`, `cookie`, `url`). For a framework the library doesn't model, write the source as a property read on the handler's first parameter.
- **Sinks:** start from the exact call in the original finding, as in Semgrep, then add the other APIs from Step 1 one at a time.
- **Barriers:** the guard from the fixed sibling. A missing barrier shows up as hits on your negative test cases.
- **`@kind problem`** with `select node, "message"` is enough when you don't need the path.

## Tests

`test.js` holds the same positive and negative cases as the Semgrep fixture. CodeQL has no `ruleid` comments in this layout; the `.expected` file is the assertion.

```bash
cd .codeql/variants/tests && codeql pack install && cd -
codeql test run .codeql/variants/tests/IdorParamLookup
# first run fails (no .expected) and writes IdorParamLookup.actual
# read it: every positive case must appear, no negative case may appear
mv .codeql/variants/tests/IdorParamLookup/IdorParamLookup.actual .codeql/variants/tests/IdorParamLookup/IdorParamLookup.expected
codeql test run .codeql/variants/tests/IdorParamLookup    # now passes: "All 1 tests passed."
```

Commit the generated `codeql-pack.lock.yml`. On later runs, a mismatch prints a diff between `.expected` and `.actual`; a new or missing row is either a regression or a case you meant to add.

## Run it

All of these write to disk and prompt:

```bash
codeql database create .security/out/codeql-db --language=javascript --source-root .
codeql database analyze .security/out/codeql-db .codeql/variants/queries/IdorParamLookup.ql \
  --format=sarif-latest --output=.security/out/variants-codeql.sarif
```

For a whole org, build one database per repo (production branch, from `patch-sweep`), run the query against each, and roll up the SARIF. GitHub code scanning can also run a custom query pack on every repo that has it enabled: add the pack to the CodeQL workflow's `packs:` or `queries:` input.

## Triage the output

SARIF results become candidates exactly like Semgrep hits: each gets its own trace and verdict, and `ext.rule_engine` is `codeql`, `ext.rule_id` is the query's `@id`.
