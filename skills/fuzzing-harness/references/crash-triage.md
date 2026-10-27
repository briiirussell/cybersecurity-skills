# Crash triage

How to turn a pile of crash files into a short list of unique bugs, each with a class, a CWE, a reach trace and a
verdict. SKILL.md Step 6 is the summary; this is the detail.

## 1. Reproduce before anything else

- Replay each input against the same build that found it. Then replay it against a fresh process. Some crashes need
  state that a previous input left behind.
- Doesn't reproduce: look for global caches, static buffers, threads, time or randomness in the target or the harness.
  Fix the harness so each call starts clean, then fuzz again. A crash you can't replay stays out of `findings.json`.
- Reproduces only with one sanitizer: note it. A UBSan-only signed overflow in a length calculation can still lead to
  an out-of-bounds access that ASan would catch on a different input.

## 2. Minimize

| Engine | Command |
|---|---|
| libFuzzer, Atheris | `<fuzzer> -minimize_crash=1 -runs=10000 -exact_artifact_path=<out> <crash>` |
| cargo-fuzz | `cargo +nightly fuzz tmin <target> <crash>` |
| Jazzer.js | `./node_modules/.bin/jazzer <target> -- -minimize_crash=1 -runs=10000 <crash>` |
| Go | automatic (writes the minimized input to `testdata/fuzz/FuzzX/`); `-fuzzminimizetime` controls it |
| Hypothesis, fast-check, proptest, Jazzer JUnit | automatic shrinking; record the shrunk value |

A smaller input makes the root cause obvious and the regression test readable. If minimization changes the crash
(different frame or type), keep both: they may be two bugs.

## 3. Dedupe

Group crashes by **crash type + the top three frames in project code**, skipping sanitizer, allocator, libc,
language-runtime and harness frames. That's close to how ClusterFuzz builds a crash state.

```bash
# libFuzzer/ASan logs: crash type and first project frames per log
for f in security-audit/evidence/*-asan.txt; do
  printf '%s\t' "$f"
  grep -m1 -oE 'ERROR: (AddressSanitizer|LeakSanitizer|UndefinedBehaviorSanitizer|MemorySanitizer): [a-z-]+' "$f" | tr '\n' '\t'
  grep -E '^\s+#[0-9]+ ' "$f" | grep -vE 'libc|libclang_rt|asan_|ubsan_|LLVMFuzzerTestOneInput|fuzzer::' | head -3 \
    | sed -E 's/.* in ([^ ]+) .*/\1/' | paste -sd '>' -
done | sort -t$'\t' -k2,3 | uniq -f1 -c
```

Same root cause, different symptoms (a read overflow on one input, a write on another, same function): one finding,
rated by the worst symptom.

## 4. Classify

Read the first line of the sanitizer or runtime report, then the access type and the frame.

| Report says | `crash_class` | CWE | Security reading |
|---|---|---|---|
| ASan `heap-buffer-overflow` / `stack-buffer-overflow` / `global-buffer-overflow`, **WRITE** | `heap-buffer-overflow-write` (etc.) | CWE-787 | Memory corruption. Potential code execution if reachable. Treat as High until proven otherwise |
| Same, **READ** | `heap-buffer-overflow-read` (etc.) | CWE-125 | Information disclosure (adjacent memory) or crash |
| ASan `heap-use-after-free` | `use-after-free` | CWE-416 | Memory corruption; High when reachable |
| ASan `attempting double-free` | `double-free` | CWE-415 | Memory corruption; High when reachable |
| ASan `SEGV on unknown address 0x000000000000` (near zero) | `null-deref` | CWE-476 | Crash. Availability. A SEGV at a large, input-dependent address is not a null deref: treat it as a wild read or write |
| UBSan `signed integer overflow`, `shift exponent`, `load of misaligned` | `integer-overflow` / `ub-<kind>` | CWE-190 / CWE-758 | Usually a precursor. Follow the value: does it size an allocation or index a buffer? |
| ASan `allocation-size-too-big`, libFuzzer `out-of-memory (malloc(N))` | `excessive-allocation` | CWE-789 | Attacker-chosen allocation size; availability |
| libFuzzer `out-of-memory (used: …Mb)` from growth, Python `MemoryError` | `oom` | CWE-400 | Unbounded consumption; availability |
| libFuzzer `timeout`, Go `fuzzing process hung or terminated unexpectedly` with no panic, Jazzer.js timeout | `timeout` | CWE-835 / CWE-1333 (regex) | Hang or ReDoS; availability. Check whether it scales with input size |
| ASan `stack-overflow`, Python `RecursionError`, Go `goroutine stack exceeds` | `stack-exhaustion` | CWE-674 | Deep nesting; availability |
| LeakSanitizer `detected memory leaks` | `memory-leak` | CWE-401 | Availability only if an attacker can repeat it until exhaustion in a long-lived process |
| Rust panic (`index out of bounds`, `unwrap()` on `Err`, `attempt to add with overflow`) | `panic` | CWE-248 / CWE-129 / CWE-190 | Availability. Near `unsafe` blocks, check whether a nearby input reaches the `unsafe` code without the bounds check |
| Go `panic: runtime error: index out of range` / `nil pointer dereference` | `panic` | CWE-129 / CWE-476 | Availability; depends on whether the panic is recovered (below) |
| Uncaught exception in Python / JS / JVM other than the documented error type | `uncaught-exception` | CWE-248 | Availability, or a fail-open if a caller treats "threw" as "passed" |
| `assert` / `abort()` / `debug_assert!` | `assertion` | CWE-617 | Availability in release builds only if the assertion is compiled in |
| Property test failure: round-trip mismatch | `roundtrip-mismatch` | none, or CWE-436 | Security-relevant only if something trusts the round trip (signatures over re-serialized data, cache keys, dedupe) |
| Property test failure: differential (validator vs consumer) | `parser-differential` | CWE-436 | Bypass of whatever the validator enforces |
| Property test failure: verify accepted a tampered value | `verification-bypass` | CWE-347 | Authentication or integrity bypass. Usually High or Critical |
| Jazzer bug detector (deserialization, command or expression injection sink reached) | `sink-reached-<kind>` | CWE-502 / CWE-78 / CWE-917 | Trace it like an injection candidate in `owasp-audit` |

## 5. Reach: who can deliver this input?

The harness proves the function misbehaves. The finding needs a principal who can make the real program call it with
that input.

1. List the callers of the crashing function (`rg -n '\btlv_read_value\('`) up to an entrypoint: a network handler,
   an upload route, a message consumer, a file the user opens, a CLI flag.
2. On the way, record every limit and check that runs before the call: size caps, content-type checks, schema
   validation, authentication, a decompression ratio limit. Does the minimized input pass all of them? If the cap is
   4 KB and the input is 9 KB, try to re-minimize under the cap with `-max_len`.
3. Prefer a dynamic replay through the real entrypoint in a local test (a unit test that calls the route handler, a
   socket test against a locally started server). That's the strongest evidence and lets you set `confidence: high`.
4. Note the process model for availability bugs:
   - Go `net/http` recovers a panic in the handler goroutine and fails one request. A panic in a goroutine the code
     starts itself kills the process.
   - Node: an exception inside a request handler of most frameworks fails one request. One thrown from a callback,
     timer or stream event without a handler kills the process.
   - Python WSGI/ASGI servers catch per request. Worker-based servers restart killed workers, which lowers duration,
     not the fact that the request crashed it (`severity-calibration.md`, availability).
   - A JVM `StackOverflowError` or `OutOfMemoryError` in a shared thread pool can leave the service degraded.

## 6. Verdict rules specific to fuzzing

- **A reproducing crash input sets `"reproduced": true`.** Confidence `high` needs both the reproduction and a
  complete reach trace, ideally replayed through the entrypoint. Reproduced through the harness only, with the reach
  traced by reading code: `confidence: medium`.
- **Unreachable in shipped builds → `rejected`**: test-only helpers, code behind `#[cfg(test)]` / `#ifdef UNIT_TEST`,
  build-time tools, a debug endpoint compiled out of release. `ruled_out_by.location` is the gating line, or the only
  call site.
- **A named control stops the input → `rejected`**: a size cap below the minimum crashing size (and you tried to
  re-minimize under it), a schema validator that rejects the structure first. Name it and where it runs.
- **One deployment fact decides reach → `needs_validation`**: a proxy body limit, a feature flag, whether a queue
  only accepts messages from an internal producer. The validation plan is a replay of the minimized input through
  staging or a local copy of the deployment.
- **Harness broke the API contract → not a record.** Fix the harness. If the contract is undocumented and real
  callers can break it too, that's a candidate against the callers instead.
- **No boundary crossed → hardening note.** A crash in a developer CLI on a file the developer chose, a panic in a
  build script.
- **Crash inside a third-party library**: record it at your call site that passes untrusted input (the fingerprint
  uses your file and function), put the library frame and version in the evidence description, and report upstream
  privately. Check `vuln-research` for an existing advisory first; the fix may be an upgrade.

## 7. Severity

Use `severity-calibration.md`. Fuzzing-specific anchors:

| Shape | Typical overall |
|---|---|
| Pre-auth out-of-bounds write, use-after-free or double free in a network-facing native service | High (Critical only with evidence of control over the corrupted memory) |
| Out-of-bounds read that returns memory to the requester | High if the memory can hold secrets or other users' data; Medium otherwise |
| Out-of-bounds read that only crashes | Availability table |
| Verification bypass (tampered token or signature accepted) | High or Critical, by what the token grants |
| Parser differential that bypasses an allow-list | Rated as the bypassed control (SSRF, path traversal, open redirect) |
| One unauthenticated request kills the whole process | High (availability) |
| Kills one worker of several, or needs an account | Medium |
| Fails only the attacker's own request | Low, or a hardening note if nothing else is affected |

`overall` never exceeds the impact you showed. "Memory corruption could lead to RCE" is not a demonstrated impact.

## Sources

Crash classes follow the AddressSanitizer, UndefinedBehaviorSanitizer and LeakSanitizer report formats (LLVM docs)
and libFuzzer's artifact naming. Crash-state dedupe follows ClusterFuzz's documented approach. Reach and verdict rules
apply this repo's `verification.md` and `severity-calibration.md`. Triage ideas (minimize first, dedupe by stack,
separate harness bugs from target bugs) are paraphrased from the Trail of Bits Testing Handbook (CC-BY-SA-4.0) and
Strix's `hypothesis.md` (Apache-2.0), which treats a crash or timeout as a robustness result until a boundary
crossing is shown.
