# Hardening flags, binary checks and sanitizers

Hardening flags turn some memory bugs into clean crashes and make others much harder to use. They don't remove bugs,
so a missing flag is a hardening note, never a finding on its own. Sanitizers are for confirming bugs, in test builds
only: never ship a sanitizer build.

## 1. Recommended flags (GCC and Clang, ELF targets)

From the OpenSSF Compiler Options Hardening Guide for C and C++. Check the guide for updates; minimum versions are the
ones it lists.

### Run-time protections

| Flag | What it does | Minimum |
|---|---|---|
| `-D_FORTIFY_SOURCE=3` | Bounds-checked variants of `memcpy`, `strcpy`, `sprintf` and friends when the compiler can work out the destination size; level 3 also uses sizes known only at run time | GCC 12, Clang 9, glibc 2.33. Needs `-O1` or higher. Distros often predefine level 2, so add `-U_FORTIFY_SOURCE` first |
| `-D_GLIBCXX_ASSERTIONS` | Bounds checks in libstdc++ containers (`operator[]`, `front`, `back`) | libstdc++ 6 |
| `-D_LIBCPP_HARDENING_MODE=_LIBCPP_HARDENING_MODE_FAST` | The same for libc++ | libc++ 18 |
| `-fstrict-flex-arrays=3` | Only `[]` counts as a flexible array member, so `[1]` and `[0]` trailing arrays get bounds-checked by FORTIFY and sanitizers | GCC 13, Clang 16 |
| `-fstack-protector-strong` | Stack canaries in functions with arrays or address-taken locals | GCC 4.9, Clang 6 |
| `-fstack-clash-protection` | Probes large stack allocations so they can't jump the guard page | GCC 8, Clang 11 |
| `-fcf-protection=full` | x86 CET: indirect-branch tracking and shadow-stack markers | GCC 8, Clang 7 |
| `-mbranch-protection=standard` | AArch64 BTI and pointer authentication | GCC 9, Clang 8 |
| `-fPIE -pie` (executables), `-fPIC -shared` (libraries) | Position-independent code, so ASLR applies to the main image | |
| `-Wl,-z,relro -Wl,-z,now` | Full RELRO: relocations, including the GOT, read-only after start-up | binutils 2.15 |
| `-Wl,-z,noexecstack` | Non-executable stack | binutils 2.14 |
| `-ftrivial-auto-var-init=zero` | Zero-fills automatic variables that aren't initialized (`pattern` for test builds, to make bugs visible) | GCC 12, Clang 8 (Clang 16 for `zero` without an extra flag) |
| `-fzero-init-padding-bits=all` | Zero struct padding too | GCC 15 |
| `-fno-delete-null-pointer-checks`, `-fno-strict-overflow`, `-fno-strict-aliasing` | Stop the optimizer deleting checks that rely on undefined behaviour | |
| `-fzero-call-used-regs=used-gpr` | Clear used registers on return | GCC 11, Clang 16 |
| `-fhardened` | GCC's shorthand that enables most of the above for the target | GCC 14 |

### Warnings that find bugs

`-Wall -Wextra -Wformat=2 -Wconversion -Wsign-conversion -Wimplicit-fallthrough -Werror=format-security
-Werror=implicit -Werror=incompatible-pointer-types -Werror=int-conversion`, plus `-Wtrampolines` (GCC) and
`-Wbidi-chars=any` (GCC 12). `-Wconversion` and `-Wsign-conversion` are noisy on old code, and their hits on length
variables are exactly the truncation and sign bugs in the catalog.

### Control-flow integrity (Clang)

`-fsanitize=cfi -flto -fvisibility=hidden` checks indirect calls and C++ virtual calls against the expected type. It
needs LTO and is a production option (unlike the other `-fsanitize` modes). Check whether the project's build can use
LTO before recommending it.

### Where to look for flags in the repo

```bash
rg -n 'FORTIFY_SOURCE|fstack-protector|fstack-clash|fcf-protection|branch-protection|-pie\b|fPIE|relro|-z,now|noexecstack|ftrivial-auto-var-init|fhardened|GLIBCXX_ASSERTIONS|fsanitize' \
  -g 'CMakeLists.txt' -g '*.cmake' -g 'Makefile*' -g '*.mk' -g 'meson.build' -g 'configure.ac' -g '*.bzl' -g 'BUILD*' -g '*.yml' -g '*.yaml' -g 'Dockerfile*' .
grep -rnE 'FORTIFY_SOURCE|fstack-protector|fcf-protection|relro|noexecstack|ftrivial-auto-var-init|fhardened|fsanitize' \
  --include=CMakeLists.txt --include='*.cmake' --include='Makefile*' --include=meson.build --include=configure.ac --include='*.yml' .
```

Also check what the toolchain adds by default: Debian, Ubuntu and Fedora compilers enable some of these
(`-D_FORTIFY_SOURCE=2`, `-fstack-protector-strong`, PIE) on their own, and an explicit `-U_FORTIFY_SOURCE` or `-O0`
in the release build silently turns FORTIFY off. The built binary is the ground truth.

## 2. Checking a built ELF binary

`readelf` and `checksec` only read the file. Run them on artifacts already in the repo or handed to you.

| Property | Command | Good result |
|---|---|---|
| PIE | `readelf -hW bin` | `Type: DYN` (and `readelf -dW bin` shows `FLAGS_1` with `PIE` on newer toolchains) |
| RELRO | `readelf -lW bin` | A `GNU_RELRO` segment = partial |
| Full RELRO | `readelf -dW bin` | `BIND_NOW`, or `FLAGS` with `BIND_NOW`, or `FLAGS_1` with `NOW` |
| NX stack | `readelf -lW bin` | `GNU_STACK` flags `RW`, not `RWE` |
| Stack protector | `readelf -sW bin` | `__stack_chk_fail` referenced (absent in a binary with no qualifying functions, so check a few) |
| FORTIFY | `readelf -sW bin` | `__*_chk` symbols such as `__memcpy_chk`, `__sprintf_chk` |
| CET / BTI | `readelf -nW bin` | `x86 feature: IBT, SHSTK` or `AArch64 feature: BTI, PAC` |
| RPATH / RUNPATH | `readelf -dW bin` | None, or only root-owned paths; a relative path, or one other users can write to, lets them place libraries the binary loads |
| Flags it was built with | `readelf --debug-dump=info bin \| grep -m3 DW_AT_producer` | GCC records the command-line options in debug info by default; `readelf -p .GCC.command.line bin` when built with `-frecord-gcc-switches`. Clang needs `-grecord-command-line` |

`checksec file bin` (checksec 3.x, the Go rewrite) reports PIE, RELRO, canary, NX, RPATH, RUNPATH, FORTIFY and symbols
in one line; `--output json` for something you can save as evidence. The 2.x shell script takes `--file=bin` instead
and isn't pre-approved, so it prompts. Leave out checksec's `--exploit` and `--chain` options:
speculation about attack chains isn't evidence.

Save the output to `<audit dir>/evidence/` when a hardening note or a finding's severity depends on it, with the command
and date in the evidence description.

### Other platforms

- **macOS (Mach-O):** `otool -hv bin` shows the `PIE` flag; `otool -Iv bin | grep stack_chk` for canaries; `codesign
  -dv --entitlements - bin` for hardened runtime and entitlements. `readelf` doesn't read Mach-O.
- **Windows (PE), MSVC:** `/GS` (canaries), `/DYNAMICBASE` and `/HIGHENTROPYVA` (ASLR), `/NXCOMPAT` (DEP),
  `/guard:cf` (Control Flow Guard), `/CETCOMPAT` (shadow stack), `/sdl`. Check with `dumpbin /headers /loadconfig`.

### Rust

- Linux targets build PIE, full RELRO and a non-executable stack by default, and Rust code doesn't need FORTIFY. Check
  the C code linked in through `build.rs` and `cc` crate builds: it gets whatever `CFLAGS` the build sets.
- `[profile.release]` in `Cargo.toml`: `overflow-checks = true` turns silent integer wrap into a panic; `panic =
  "abort"` stops unwinding across FFI (and changes `catch_unwind` behaviour); `debug-assertions` stays off in release,
  so `debug_assert!` is not a safety check.
- Stack protector and CFI are nightly-only (`-Zstack-protector=strong`, `-Zsanitizer=cfi`).

## 3. Sanitizers (test builds, with the user's go-ahead)

Build and run only after the user agrees, in a container or VM they control. Building runs the project's build
scripts; running tests runs its code.

| Tool | Finds | C / C++ build | Notes |
|---|---|---|---|
| ASan | Out-of-bounds, use after free, double free, stack use after return | `-fsanitize=address -fno-omit-frame-pointer -g -O1` | `ASAN_OPTIONS=detect_leaks=1:abort_on_error=1:detect_stack_use_after_return=1`. Doesn't see bugs inside uninstrumented libraries, hand-written assembly, or custom allocators that carve one big block |
| UBSan | Signed overflow, shifts, misaligned access, bad casts, NULL dereference | `-fsanitize=undefined -fno-sanitize-recover=all` | Clang `-fsanitize=integer` and `-fsanitize=implicit-conversion` add unsigned wrap and truncation, which are defined behaviour, so expect hits that aren't bugs |
| MSan | Reads of uninitialized memory | `-fsanitize=memory -fsanitize-memory-track-origins` (Clang, Linux) | Every linked library must be instrumented, including the C++ standard library, or you get false reports |
| TSan | Data races | `-fsanitize=thread -g -O1` | Can't combine with ASan or MSan; use a separate build |
| CFI diagnostics | Bad indirect calls | `-fsanitize=cfi -flto -fvisibility=hidden` | Add `-fno-sanitize-trap=cfi` in test builds for readable reports |

Rust on nightly: `RUSTFLAGS=-Zsanitizer=address cargo +nightly test --target <host triple>` (also `memory`, `thread`),
and Miri: `cargo +nightly miri test <test>`, with `MIRIFLAGS=-Zmiri-strict-provenance` or `-Zmiri-tree-borrows` as
needed. See [rust-unsafe-checklist.md](rust-unsafe-checklist.md) section 7.

**Making a report count.** A sanitizer report proves the bad memory operation happened. For a `confirmed` finding it
also needs the input to be one an attacker can send, through an entry point you mapped. Keep the minimal input, the
report, the compiler version, the target and the exact command in `<audit dir>/evidence/`. A report from a harness
that calls an internal function with values no caller can produce is a test bug, not a finding.

**Coverage gaps.** Check that the faulting code was actually instrumented: code in assembly, JIT output, a library
linked as a prebuilt `.a` or `.so`, or memory from a custom pool allocator escapes ASan. If the operation isn't
instrumented, a clean run proves nothing.

## 4. Recommending sanitizers and fuzzing in CI

A project that parses untrusted input should have, in CI: a test job built with ASan + UBSan, a TSan job for threaded
code, Miri on the crates with `unsafe`, and a fuzz target per parser running for a short time on every PR and longer
on a schedule. Recommend these as hardening notes with an effort estimate. The fuzzing harness itself is a separate
piece of work (see the fuzzing hand-off in SKILL.md Step 7).

## Sources

Paraphrased: [OpenSSF Compiler Options Hardening Guide for C and C++](https://best.openssf.org/Compiler-Hardening-Guides/Compiler-Options-Hardening-Guide-for-C-and-C++.html);
[Clang sanitizer documentation](https://clang.llvm.org/docs/index.html) (AddressSanitizer, MemorySanitizer,
ThreadSanitizer, UndefinedBehaviorSanitizer, ControlFlowIntegrity); [checksec](https://github.com/slimm609/checksec)
README; the [rustc book](https://doc.rust-lang.org/rustc/) and the [unstable book's sanitizer
chapter](https://doc.rust-lang.org/beta/unstable-book/compiler-flags/sanitizer.html); Cloudflare security-audit-skill
`MEMORY-SAFETY-AND-BINARY.md` (MIT) on sanitizer coverage gaps.
