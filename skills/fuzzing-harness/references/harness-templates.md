# Harness and property-test templates

Starting points per engine. Replace the placeholder target (`tlv_read_value`, `parse_manifest`, `parseHeader`, ...)
with the function you ranked in Step 2, and keep the rules from SKILL.md Step 3: deterministic, fast, catch only the
documented error type, respect the API contract, add an oracle where one exists.

Every build and run command here executes the user's code. Ask before running any of them (SKILL.md, Authorization).
APIs were checked against each project's docs in October 2026. Check the installed version's docs if a flag is
rejected.

Contents: [libFuzzer](#libfuzzer-c-c) · [cargo-fuzz](#cargo-fuzz-rust) · [Go](#go-native-fuzzing) ·
[Atheris](#atheris-python) · [Jazzer.js](#jazzerjs-javascript-typescript) · [Jazzer](#jazzer-java-kotlin) ·
[Hypothesis](#hypothesis-python) · [fast-check](#fast-check-javascript-typescript) · [proptest](#proptest-rust) ·
[Common libFuzzer flags](#common-libfuzzer-flags)

## libFuzzer (C, C++)

```cpp
// fuzz/tlv_fuzzer.cc
#include <cstddef>
#include <cstdint>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>
extern "C" {
#include "tlv.h"
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size > 64 * 1024) return 0;              // cap work per input
  tlv_ctx ctx;
  tlv_init(&ctx);                              // fresh state every call
  tlv_parse(&ctx, data, size);                 // the target: raw bytes in
  tlv_free(&ctx);                              // leaks are findings too (LeakSanitizer)
  return 0;                                    // non-zero return values are reserved
}
```

Structured input, when the API takes typed arguments instead of one buffer:

```cpp
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);
  uint8_t version = fdp.ConsumeIntegral<uint8_t>();
  bool strict = fdp.ConsumeBool();
  std::vector<uint8_t> body = fdp.ConsumeRemainingBytes<uint8_t>();
  frame_decode(version, strict, body.data(), body.size());
  return 0;
}
```

State machine: loop, and let the input pick the operation each time.

```cpp
  FuzzedDataProvider fdp(data, size);
  session_t *s = session_new();
  while (fdp.remaining_bytes() > 0) {
    switch (fdp.ConsumeIntegralInRange<int>(0, 3)) {
      case 0: session_handshake(s, fdp.ConsumeRandomLengthString(256).c_str()); break;
      case 1: session_send(s, fdp.ConsumeRandomLengthString(1024).c_str()); break;
      case 2: session_rekey(s); break;
      case 3: session_close(s); break;
    }
    assert(session_invariants_hold(s));        // oracle after every step
  }
  session_free(s);
```

Build and run (Linux clang, or Homebrew LLVM on macOS; Apple clang has no libFuzzer):

```bash
# library code: instrumented, no libFuzzer main
clang -g -O1 -fno-omit-frame-pointer -fsanitize=fuzzer-no-link,address,undefined -c src/tlv.c -Iinclude -o tlv.o
# harness: links libFuzzer's main
clang++ -g -O1 -fno-omit-frame-pointer -fsanitize=fuzzer,address,undefined -Iinclude fuzz/tlv_fuzzer.cc tlv.o -o tlv_fuzzer

mkdir -p security-audit/fuzz/crashes/tlv
ASAN_OPTIONS=abort_on_error=1:detect_leaks=1:symbolize=1 UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 \
  ./tlv_fuzzer -max_total_time=600 -timeout=10 -rss_limit_mb=2048 -max_len=4096 \
  -dict=fuzz/tlv.dict -artifact_prefix=security-audit/fuzz/crashes/tlv/ fuzz/corpus/tlv/
```

Reproduce, minimize, merge:

```bash
./tlv_fuzzer security-audit/fuzz/crashes/tlv/crash-<sha1>                       # replay one input
./tlv_fuzzer -minimize_crash=1 -runs=10000 \
  -exact_artifact_path=security-audit/fuzz/crashes/tlv/min-<sha1> security-audit/fuzz/crashes/tlv/crash-<sha1>
mkdir -p fuzz/corpus/tlv.min && ./tlv_fuzzer -merge=1 fuzz/corpus/tlv.min fuzz/corpus/tlv
./tlv_fuzzer -runs=0 fuzz/regressions/tlv/                                     # replay a directory, no fuzzing
```

MemorySanitizer (`-fsanitize=fuzzer,memory`) needs every linked library built with it, including libc++. Leave it to
a separate CI build.

## cargo-fuzz (Rust)

Needs a nightly toolchain, Linux or macOS on x86-64 or AArch64, and a library crate to call into.

```bash
cargo install cargo-fuzz
cargo +nightly fuzz init           # creates fuzz/ with its own Cargo.toml
cargo +nightly fuzz add tlv        # creates fuzz/fuzz_targets/tlv.rs
```

```rust
// fuzz/fuzz_targets/tlv.rs
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Errors are fine; panics, overflows (with -a) and sanitizer reports are what we want.
    let _ = mycrate::tlv::parse(data);
});
```

Structured input with `arbitrary` (add `arbitrary = { version = "1", features = ["derive"] }` to the fuzz crate and
derive `Arbitrary` on the input type):

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;

#[derive(Debug, arbitrary::Arbitrary)]
struct Input { version: u8, strict: bool, body: Vec<u8> }

fuzz_target!(|input: Input| {
    if let Ok(frame) = mycrate::frame::decode(input.version, input.strict, &input.body) {
        // round-trip oracle
        let bytes = frame.encode();
        let again = mycrate::frame::decode(input.version, input.strict, &bytes).expect("re-decode of our own output");
        assert_eq!(frame, again);
    }
});
```

```bash
cargo +nightly fuzz run tlv -- -max_total_time=600 -timeout=10 -rss_limit_mb=2048 -dict=fuzz/tlv.dict
cargo +nightly fuzz run --sanitizer none tlv          # pure safe Rust: faster, ASan adds little
cargo +nightly fuzz run -a tlv                        # -a / --debug-assertions: catch integer overflow
cargo +nightly fuzz run tlv fuzz/artifacts/tlv/crash-<sha1>    # reproduce
cargo +nightly fuzz tmin tlv fuzz/artifacts/tlv/crash-<sha1>   # minimize
cargo +nightly fuzz cmin tlv                                   # shrink the corpus
cargo +nightly fuzz coverage tlv                               # coverage report for the corpus
```

Crashes land in `fuzz/artifacts/<target>/`. Copy the minimized one to `security-audit/fuzz/crashes/<target>/`.

## Go native fuzzing

Go 1.18+. One `f.Fuzz` per fuzz test, arguments limited to `string`, `[]byte`, the integer and float types, `rune`,
`byte` and `bool`.

```go
// internal/token/header_fuzz_test.go
package token

import (
	"errors"
	"testing"
)

func FuzzParseTokenHeader(f *testing.F) {
	f.Add("eyJhbGciOiJIUzI1NiIsImtpZCI6ImsxIn0")       // seeds: valid and edge cases
	f.Add("")
	f.Add("e30")
	f.Fuzz(func(t *testing.T, raw string) {
		h, err := ParseTokenHeader(raw)
		if err != nil {
			if !errors.Is(err, ErrMalformedHeader) {   // only the documented error is fine
				t.Fatalf("unexpected error type: %v", err)
			}
			return
		}
		// round-trip oracle
		h2, err := ParseTokenHeader(h.Encode())
		if err != nil || h2 != h {
			t.Fatalf("round-trip mismatch: %#v vs %#v (%v)", h, h2, err)
		}
	})
}
```

```bash
go test -run='^$' -fuzz='^FuzzParseTokenHeader$' -fuzztime=10m ./internal/token
go test -run='FuzzParseTokenHeader/<hash>' ./internal/token      # replay one saved failure
go test ./internal/token                                          # seeds + testdata/fuzz replay as unit tests
```

Failures are minimized and written to `testdata/fuzz/FuzzParseTokenHeader/<hash>`. Each input has a 1-second
timeout. The working corpus lives in `$GOCACHE/fuzz` and isn't committed. The older `dvyukov/go-fuzz` is superseded by
native fuzzing; port harnesses rather than extending it.

## Atheris (Python)

Current source supports Python 3.11+ on Linux and macOS (older wheels remain on PyPI). On macOS, building from
source needs a non-Apple LLVM (`CLANG_BIN`).

```python
# fuzz/fuzz_manifest.py
import sys
import atheris

with atheris.instrument_imports():
    from myapp.manifest import parse_manifest, ManifestError


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    text = fdp.ConsumeUnicodeNoSurrogates(8192)
    try:
        parse_manifest(text)
    except ManifestError:
        pass                  # documented rejection; anything else propagates and counts as a crash


atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
```

```bash
mkdir -p security-audit/fuzz/crashes/manifest
python fuzz/fuzz_manifest.py -max_total_time=600 -timeout=10 -rss_limit_mb=2048 \
  -artifact_prefix=security-audit/fuzz/crashes/manifest/ fuzz/corpus/manifest/
python fuzz/fuzz_manifest.py -minimize_crash=1 -runs=10000 security-audit/fuzz/crashes/manifest/crash-<sha1>
```

`FuzzedDataProvider` also has `ConsumeBytes`, `ConsumeIntInRange`, `ConsumeBool`, `ConsumeFloat`, `PickValueInList`.
For C extensions, build the extension with ASan/UBSan and preload the sanitizer runtime as Atheris's
`native_extension_fuzzing.md` describes; otherwise native memory bugs show up only as segfaults.

An existing Hypothesis test can run under Atheris for coverage guidance:
`atheris.Setup(sys.argv, atheris.instrument_func(test_roundtrip.hypothesis.fuzz_one_input))`.

## Jazzer.js (JavaScript, TypeScript)

CLI form:

```js
// fuzz/header.fuzz.js
const { FuzzedDataProvider } = require("@jazzer.js/core");
const { parseHeader, HeaderError } = require("../src/header");

module.exports.fuzz = function (data) {
  const fdp = new FuzzedDataProvider(data);
  const raw = fdp.consumeString(4096, "utf-8");
  try {
    parseHeader(raw);
  } catch (e) {
    if (!(e instanceof HeaderError)) throw e;   // only the documented error is expected
  }
};
```

```bash
npm install --save-dev @jazzer.js/core
./node_modules/.bin/jazzer fuzz/header.fuzz.js fuzz/corpus/header --sync -i src/ --timeout=5000 -- -max_total_time=600
./node_modules/.bin/jazzer fuzz/header.fuzz.js fuzz/regressions/header --mode=regression      # replay only
```

`--sync` only when the target has no async code. The first positional directory after the target is the corpus.
libFuzzer flags go after `--`.

Jest form (`npm install --save-dev @jazzer.js/jest-runner`, and a Jest project with
`"testRunner": "@jazzer.js/jest-runner"` matching `*.fuzz.js`):

```js
require("@jazzer.js/jest-runner");
const { parseHeader, HeaderError } = require("../src/header");

describe("parseHeader", () => {
  it.fuzz("rejects or parses, never throws anything else", (data) => {
    try { parseHeader(data.toString("utf-8")); }
    catch (e) { if (!(e instanceof HeaderError)) throw e; }
  });
});
```

Jest runs these in regression mode by default (replaying the per-test input directory). `JAZZER_FUZZ=1 ./node_modules/.bin/jest
--testNamePattern='parseHeader'` fuzzes one test. Crashing inputs are saved under a directory named after the test
file, describe block and test name, which makes them regression inputs on the next plain run.

## Jazzer (Java, Kotlin)

Add `com.code-intelligence:jazzer-junit` as a test dependency (JUnit 5.9+).

```java
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;

class TokenParserFuzzTest {
  @FuzzTest
  void parse(FuzzedDataProvider data) {
    String raw = data.consumeRemainingAsString();
    try {
      TokenParser.parse(raw);
    } catch (MalformedTokenException expected) {
      // documented rejection
    }
  }
}
```

```bash
JAZZER_FUZZ=1 mvn test -Dtest=TokenParserFuzzTest      # fuzz
mvn test -Dtest=TokenParserFuzzTest                    # regression mode: replays saved inputs
```

Crashing inputs go to `src/test/resources/<package path>/TokenParserFuzzTestInputs/parse/`, which regression mode
replays. Jazzer's bug detectors also flag deserialization, expression-language and command injection sinks reached
from the input. Treat those as candidates for `owasp-audit`-style tracing, not as confirmed findings.

## Hypothesis (Python)

```python
from hypothesis import example, given, settings, strategies as st
from myapp.codec import decode, encode, DecodeError

messages = st.builds(Message, kind=st.sampled_from(["ping", "data", "close"]),
                     body=st.binary(max_size=512), seq=st.integers(0, 2**32 - 1))

@given(messages)
def test_roundtrip(msg):
    assert decode(encode(msg)) == msg

@settings(max_examples=2000, deadline=500)
@given(st.binary(max_size=4096))
@example(b"\x00\xff\xff\xff\xff")          # pinned regression from a past failure
def test_decode_rejects_cleanly(raw):
    try:
        decode(raw)
    except DecodeError:
        pass
```

Stateful testing: `hypothesis.stateful.RuleBasedStateMachine` with `@rule` methods and `@invariant` checks.
Failures are saved in the `.hypothesis/` example database and replayed on the next run; the failure output also
prints a `@reproduce_failure(...)` decorator you can paste in temporarily. Turn the shrunk input into a permanent
`@example(...)`. Don't disable deadlines or health checks to make a flaky test pass. Find the nondeterminism.

## fast-check (JavaScript, TypeScript)

```ts
import fc from "fast-check";
import { describe, it } from "vitest";            // any runner works
import { isAllowed, normalizeUrl } from "../src/url";

describe("url allow-list", () => {
  it("normalization is idempotent", () => {
    fc.assert(fc.property(fc.webUrl(), fc.string({ maxLength: 64 }), (base, suffix) => {
      const once = normalizeUrl(base + suffix);
      return normalizeUrl(once) === once;
    }));
  });

  it("allowed URLs stay on the allowed host after the consumer parses them", () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 200 }), (raw) => {
        if (!isAllowed(raw)) return true;
        return new URL(raw).hostname === "api.example.com";      // differential vs WHATWG URL
      }),
      { numRuns: 5000, examples: [["http://api.example.com\\@evil.example/"]] },
    );
  });
});
```

A failure prints a `seed` and `path`. Replay it exactly with `fc.assert(prop, { seed, path, endOnFailure: true })`,
then keep the shrunk value in `examples`. `fc.asyncProperty` for async code; `fc.commands` and `fc.modelRun` for state
machines. `@fast-check/vitest` and `@fast-check/jest` add a `test.prop([...arbitraries])` shorthand.

## proptest (Rust)

```rust
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn decode_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let _ = mycrate::frame::decode_bytes(&bytes);
    }

    #[test]
    fn roundtrip(kind in 0u8..3, body in proptest::collection::vec(any::<u8>(), 0..512)) {
        let frame = mycrate::frame::Frame::new(kind, body);
        prop_assert_eq!(mycrate::frame::decode_bytes(&frame.encode()).unwrap(), frame);
    }
}
```

Failing cases are written to `proptest-regressions/<module>.txt` and replayed first on later runs. Commit that
directory. `proptest-derive` gives `#[derive(Arbitrary)]`; `proptest-state-machine` covers stateful tests.

## Common libFuzzer flags

These work for libFuzzer, cargo-fuzz (after `--`), Atheris and Jazzer.js (after `--`).

| Flag | Use |
|---|---|
| `-max_total_time=<s>` | Total budget |
| `-runs=<n>` | Stop after n inputs; `-runs=0` replays given inputs only |
| `-timeout=<s>` | Per-input timeout; slow inputs are saved as `timeout-*` |
| `-rss_limit_mb=<mb>` | Memory cap; over-limit inputs are saved as `oom-*` |
| `-max_len=<bytes>` | Largest input generated |
| `-dict=<file>` | Dictionary of tokens |
| `-artifact_prefix=<dir/>` | Where crash, timeout and OOM inputs go (trailing slash) |
| `-minimize_crash=1` | Shrink a crash input (with `-runs`) |
| `-merge=1 <out> <in...>` | Minimize a corpus into `<out>` |
| `-jobs=<n> -workers=<n>` | Parallel runs |
| `-print_final_stats=1` | Exec/s and coverage at the end |

## Sources

Paraphrased from each project's own documentation: LLVM libFuzzer, the Rust Fuzz Book and cargo-fuzz README, the Go
fuzzing docs, the Atheris README, the Jazzer.js `fuzz-settings.md` and `jest-integration.md`, the Jazzer README,
the Hypothesis, fast-check and proptest docs. Harness rules and the state-machine loop follow the Trail of Bits
Testing Handbook and its `harness-writing` skill (CC-BY-SA-4.0), paraphrased.
