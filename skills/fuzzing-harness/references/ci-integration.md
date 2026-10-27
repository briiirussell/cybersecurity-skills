# Fuzzing in CI

Three layers, cheapest first. Add them in this order and stop where the project's risk stops.

1. **Regression replay on every PR.** Deterministic, seconds long, no fuzzing. Replays every committed crash input and
   the minimized corpus. This is the one that must never be skipped.
2. **Short fuzzing on PRs** that touch a fuzzed target: a few minutes per target.
3. **Longer batch fuzzing on a schedule**, with corpus pruning and coverage reports: ClusterFuzzLite, or OSS-Fuzz for
   eligible open-source projects.

Writing workflow files is part of this skill's output. Pin third-party actions to a full commit SHA (with the tag in
a comment), give workflows `permissions: read-all` or narrower, and never pass secrets to a job that builds
pull-request code. `scanner-pipeline` covers the rest of the CI security jobs.

## 1. Regression replay

| Engine | Command |
|---|---|
| Go | `go test ./...` (replays `f.Add` seeds and `testdata/fuzz/`) |
| libFuzzer | build the fuzzer, then `./tlv_fuzzer -runs=0 fuzz/regressions/tlv/ fuzz/corpus/tlv/` |
| cargo-fuzz | `cargo +nightly fuzz run tlv fuzz/regressions/tlv -- -runs=0` |
| Atheris | `python fuzz/fuzz_manifest.py -runs=0 fuzz/regressions/manifest/` |
| Jazzer.js | `./node_modules/.bin/jest` (Jest regression mode is the default) or `./node_modules/.bin/jazzer <target> <dir> --mode=regression` |
| Jazzer | `mvn test` / `gradle test` (regression mode unless `JAZZER_FUZZ` is set) |
| Hypothesis / fast-check / proptest | the normal test run; `@example`, `examples` and `proptest-regressions/` carry the pinned cases |

For Hypothesis in CI, use a fixed profile (`settings.register_profile("ci", max_examples=200, deadline=None,
derandomize=True)` loaded by an env var) so CI runs are repeatable, and keep exploration for local and scheduled runs.

## 2. Short PR fuzzing without extra infrastructure

```yaml
# .github/workflows/fuzz-pr.yml
name: fuzz (PR)
on:
  pull_request:
    paths: ["internal/token/**", "fuzz/**"]
permissions: read-all
jobs:
  go-fuzz:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@<full-sha> # vX
      - uses: actions/setup-go@<full-sha> # vX
        with: { go-version: stable }
      - run: go test ./internal/token
      - run: go test -run='^$' -fuzz='^FuzzParseTokenHeader$' -fuzztime=3m ./internal/token
      - if: failure()
        uses: actions/upload-artifact@<full-sha> # vX
        with: { name: fuzz-failures, path: internal/token/testdata/fuzz }
```

Same idea for cargo-fuzz (`cargo +nightly fuzz run tlv -- -max_total_time=180`) and libFuzzer builds. A failed PR
run uploads the crash input as an artifact. On a public repo that artifact is visible to anyone who can see the run,
so for native memory-safety targets prefer ClusterFuzzLite with private storage, or run PR fuzzing only on the
private fork.

## 3. ClusterFuzzLite

Runs libFuzzer-based fuzzing in CI for C, C++, Rust, Go, Python, Java/JVM and Swift, with ASan, UBSan and MSan.
Needs three files in `.clusterfuzzlite/`, using the OSS-Fuzz build conventions:

```text
.clusterfuzzlite/project.yaml   # language: c++ | rust | go | python | jvm | swift
.clusterfuzzlite/Dockerfile     # FROM the OSS-Fuzz base-builder image for the language; COPY . $SRC/<project>
.clusterfuzzlite/build.sh       # builds each fuzzer into $OUT using $CC/$CXX/$CFLAGS/$LIB_FUZZING_ENGINE
```

`build.sh` for the libFuzzer example:

```bash
#!/bin/bash -eu
$CC $CFLAGS -c src/tlv.c -Iinclude -o tlv.o
$CXX $CXXFLAGS -Iinclude fuzz/tlv_fuzzer.cc tlv.o $LIB_FUZZING_ENGINE -o $OUT/tlv_fuzzer
cp fuzz/tlv.dict $OUT/tlv_fuzzer.dict                       # <fuzzer>.dict is picked up automatically
zip -j $OUT/tlv_fuzzer_seed_corpus.zip fuzz/corpus/tlv/*      # <fuzzer>_seed_corpus.zip likewise
```

Workflows (from the ClusterFuzzLite docs; pin the actions to a SHA):

| Workflow | Trigger | `run_fuzzers` mode | Typical `fuzz-seconds` |
|---|---|---|---|
| PR fuzzing | `pull_request` | `code-change` (fuzzes targets affected by the diff) | 300–600 |
| Batch fuzzing | `schedule` every few hours | `batch` | 3600 |
| Continuous builds | `push` to main, with `upload-build: true` | (build only; lets PR runs tell new crashes from old) | n/a |
| Cron | daily | `prune` (corpus) and `coverage` (with `sanitizer: coverage`) | 600 |

```yaml
# .github/workflows/cflite_pr.yml (abridged)
name: ClusterFuzzLite PR fuzzing
on: pull_request
permissions: read-all
jobs:
  PR:
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix: { sanitizer: [address, undefined] }
    steps:
      - id: build
        uses: google/clusterfuzzlite/actions/build_fuzzers@<full-sha> # v1
        with:
          language: c++
          github-token: ${{ secrets.GITHUB_TOKEN }}
          sanitizer: ${{ matrix.sanitizer }}
      - id: run
        uses: google/clusterfuzzlite/actions/run_fuzzers@<full-sha> # v1
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          fuzz-seconds: 600
          mode: code-change
          sanitizer: ${{ matrix.sanitizer }}
          output-sarif: true
```

Batch fuzzing needs pruning running too, and a `storage-repo` (a separate repository the action writes corpora and
crashes to). Keep that storage repo private. `output-sarif: true` puts crashes into GitHub code scanning; they're
raw crashes, so still triage them with this skill before they count as findings.

## 4. OSS-Fuzz

Free, continuous fuzzing on Google's infrastructure, with bugs filed privately and disclosed after a fix or a deadline.

- **Eligibility:** open source, with a significant user base or importance to widely used infrastructure. Google
  decides. A small internal service or a closed-source product is not eligible; use ClusterFuzzLite.
- **Needs:** a primary contact who is an established committer (checked against the VCS history) with a Google
  account, and willingness to fix the bugs it files.
- **How:** a PR to `google/oss-fuzz` adding `projects/<name>/project.yaml`, `Dockerfile` and `build.sh`, the same
  shape as ClusterFuzzLite's files, so a ClusterFuzzLite setup ports over almost unchanged.
- **Before applying:** harnesses build with `$LIB_FUZZING_ENGINE`, seed corpora and dictionaries are in place, and the
  existing harnesses run clean for a while locally. A project that arrives with 50 known crashes spends its first
  months closing auto-filed bugs.

## Sources

Paraphrased from the ClusterFuzzLite docs (overview, build integration, GitHub Actions page) and the OSS-Fuzz docs
(accepting new projects, new project guide), plus the Go fuzzing docs and the Hypothesis settings docs. The OSS-Fuzz
section also follows the Trail of Bits Testing Handbook's `ossfuzz` chapter (CC-BY-SA-4.0), paraphrased.
