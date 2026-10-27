# Bug-class catalog — C, C++ and Rust

What to grep for, what to read once you get a hit, what rules a hit out, and what it takes to confirm one. Grep finds
call sites. It never finds the bug: that's the arithmetic or lifetime you work out by reading the code around it.

Each class gives an `rg` pattern and a portable `grep -E` version (macOS `grep` has no `-P`, so neither uses Perl-only
syntax). The commands restrict file types to cut noise: `-tc -tcpp` / `-trust` for `rg`, and
`--include='*.[ch]' --include='*.[ch]pp' --include='*.cc'` (add `*.cxx`, `*.hh` if the repo uses them) or
`--include=*.rs` for `grep`. Run them from the repo root.

Exclude vendored and generated directories (`--glob '!third_party/**'` for `rg`, `--exclude-dir=third_party` for
`grep`) and note the exclusion in the report's scope line.

## 0. Find the input first

Priority goes to code that touches bytes from a lower-trust source.

```bash
# Where bytes enter
rg -n -tc -tcpp '\b(recv|recvfrom|recvmsg|read|pread|fread|fgets|getline|mmap|getenv)\s*\(' .
grep -rnE --include='*.[ch]' --include='*.[ch]pp' --include='*.cc' '\b(recv|recvfrom|recvmsg|read|pread|fread|fgets|getline|mmap|getenv)[[:space:]]*\(' .
# Parsers and decoders
rg -n -tc -tcpp -trust '\b(fn\s+)?(parse|decode|unpack|deserialize|read|load)_\w+\s*\(' .
grep -rnE --include='*.[ch]' --include='*.[ch]pp' --include='*.cc' --include=*.rs '(parse|decode|unpack|deserialize|load)_[A-Za-z0-9_]+[[:space:]]*\(' .
# Wire-format byte order: a strong parser signal
rg -n -tc -tcpp '\b(ntohs|ntohl|be16toh|be32toh|be64toh|le16toh|le32toh)\s*\(' .
grep -rnE --include='*.[ch]' --include='*.[ch]pp' --include='*.cc' '(ntohs|ntohl|be16toh|be32toh|be64toh|le16toh|le32toh)[[:space:]]*\(' .
# Exported entry points (other languages call these)
rg -n -trust '#\[(unsafe\()?no_mangle\)?\]|extern\s+"C"\s+fn' .
grep -rnE --include=*.rs '#\[(unsafe\()?no_mangle|extern[[:space:]]+"C"[[:space:]]+fn' .
```

## 1. Out-of-bounds write and read

**CWE:** 787 (write), 125 (read), 121 (stack), 122 (heap), 193 (off-by-one), 120 (copy without size check), 170
(missing terminator).

**Look for:** copies whose size comes from input, functions that can't know the destination size, loops bounded by an
input count, and reads of a header field before the input is known to be that long.

```bash
# Functions with no destination bound
rg -n -tc -tcpp '\b(gets|strcpy|strcat|sprintf|vsprintf|stpcpy|wcscpy|wcscat)\s*\(' .
grep -rnE --include='*.[ch]' --include='*.[ch]pp' --include='*.cc' '\b(gets|strcpy|strcat|sprintf|vsprintf|stpcpy|wcscpy|wcscat)[[:space:]]*\(' .
# scanf-family %s with no width
rg -n -tc -tcpp 'scanf\s*\([^;]*"[^"]*%s' .
grep -rnE --include='*.[ch]' --include='*.[ch]pp' --include='*.cc' 'scanf[[:space:]]*\([^;]*"[^"]*%s' .
# Sized copies: read the size expression at every hit
rg -n -tc -tcpp '\b(memcpy|memmove|memset|strncpy|strncat|snprintf|read|fread|recv)\s*\(' .
grep -rnE --include='*.[ch]' --include='*.[ch]pp' --include='*.cc' '\b(memcpy|memmove|memset|strncpy|strncat|snprintf)[[:space:]]*\(' .
# Stack allocations sized at run time
rg -n -tc -tcpp '\balloca\s*\(|\[\s*[a-z_]\w*\s*\]\s*;' .
grep -rnE --include='*.[ch]' --include='*.[ch]pp' --include='*.cc' 'alloca[[:space:]]*\(' .
```

**Read for:**

- The bound is checked against the **source** (bytes left in the packet) and not the **destination** (the field).
- Capacity after the header, alignment padding and the terminator are taken out. `buf[len] = '\0'` with `len ==
  sizeof buf` writes one past.
- `<=` where `<` was meant; `sizeof(ptr)` instead of the buffer's size; `sizeof` of an array that decayed to a pointer
  in a function parameter.
- `strncpy` doesn't terminate when the source fills the buffer (CWE-170); `snprintf` returns the length it *wanted*, so
  `p += snprintf(p, n, ...)` walks off the end once truncation happens.
- An index or offset from input checked for the upper bound but not for negative values (a signed `int`).
- C++: `operator[]` on `std::vector`/`std::array` doesn't check; `.at()` does. `std::span` and `std::string_view` carry
  a length, and `.data()` throws it away.

**Rules it out:** the size is a compile-time constant that fits; a check against the destination's capacity on every
path, before the copy, using the same unit and type as the copy. A check in a sibling caller doesn't count.

**Confirm:** the input value that breaks the bound, worked through the arithmetic, from an entry you mapped; or an ASan
`heap-buffer-overflow` / `stack-buffer-overflow` report on a minimal input.

**Rust:** safe indexing panics instead (availability, CWE-617). Out-of-bounds memory access needs `unsafe`:
`get_unchecked`, `ptr::add`/`offset`, `copy_nonoverlapping`, `from_raw_parts`. See the unsafe checklist.

## 2. Integer overflow, underflow, truncation and sign confusion

**CWE:** 190 (overflow), 191 (underflow), 197 (truncation), 195 / 196 (signed ↔ unsigned), 680 (overflow to buffer
overflow), 131 (wrong buffer size), 681 (bad numeric conversion).

The integer bug matters when the wrong value reaches an allocation, a copy length, an index, a loop bound or a pointer
offset. Follow it there.

```bash
# Allocation sizes computed from arithmetic
rg -n -tc -tcpp '\b(malloc|realloc|alloca|new\s+\w+\s*\[)\s*\(?[^;)]*[*+-]' .
grep -rnE --include='*.[ch]' --include='*.[ch]pp' --include='*.cc' '(malloc|realloc|alloca)[[:space:]]*\([^;)]*[*+-]' .
# Subtraction used as a length
rg -n -tc -tcpp '\b(\w*len|\w*size|count|remaining|total)\s*-\s*\w+' -g '!*test*' .
grep -rnE --include='*.[ch]' --include='*.[ch]pp' --include='*.cc' '(len|size|count|remaining|total)[[:space:]]*-[[:space:]]*[A-Za-z_]' .
# Narrowing casts on lengths
rg -n -tc -tcpp '\((int|short|unsigned short|uint16_t|uint8_t|int16_t|int32_t)\)\s*\w*(len|size|count)' .
grep -rnE --include='*.[ch]' --include='*.[ch]pp' --include='*.cc' '\((int|short|uint16_t|uint8_t|int16_t|int32_t)\)[[:space:]]*[A-Za-z_]*(len|size|count)' .
# Rust: `as` conversions and unchecked arithmetic that reach sizes
rg -n -trust '\bas\s+(u8|u16|u32|i8|i16|i32|usize|isize)\b' .
grep -rnE --include=*.rs '[[:space:]]as[[:space:]]+(u8|u16|u32|i8|i16|i32|usize|isize)\b' .
```

**Read for:**

- `count * sizeof(T)` with `count` from input. On 64-bit a 32-bit `count` times a small struct can't wrap; on a 32-bit
  target it can. Record the target as a blocker if you can't see the build matrix.
- `total - header` where the input can make `header > total`. The unsigned result is huge.
- `size_t` stored into `int`, `uint16_t` or a wire-format field, then used again as a size.
- A signed `int len` that can be negative, compared with a signed bound (passes), then passed to `memcpy` as `size_t`
  (huge). A `-1` error return that is never checked and becomes `SIZE_MAX`.
- Integer promotion: `uint8_t a, b; a + b` is `int`, `uint16_t * uint16_t` can overflow signed `int` (undefined
  behaviour) on common platforms.
- Signed overflow is undefined in C and C++, so the compiler may delete a check written as `if (a + b < a)`. Check
  overflow before the operation, or use `__builtin_add_overflow` / `__builtin_mul_overflow`, `ckd_add` / `ckd_mul`
  (C23), `reallocarray` or `calloc`.
- Rust release builds wrap silently unless `overflow-checks = true`; `as` truncates and reinterprets sign. Use
  `checked_*`, `TryFrom`, or `usize::try_from`.

**Rules it out:** an earlier check bounds the input so the arithmetic can't wrap at the widest accepted value, on every
path; checked arithmetic that fails closed; the allocation function itself checks (`calloc`, `reallocarray`).

**Confirm:** the concrete input values, the wrapped result, and the memory operation it reaches. UBSan
(`-fsanitize=signed-integer-overflow`, or Clang's `-fsanitize=integer` / `implicit-conversion` for unsigned wrap and
truncation, which are noisier because they're not undefined behaviour) plus ASan on the copy that follows.

## 3. Unit and representation confusion

**CWE:** 135 (multi-byte length), 131.

- Bytes versus elements: `wcsncpy(dst, src, sizeof dst)` passes a byte count where a `wchar_t` count is expected;
  `memcpy(dst, src, n)` where `n` is an element count.
- Pointer depth: `sizeof(*p)` versus `sizeof(p)` versus `sizeof(**p)`.
- UTF-8 code units versus characters versus display columns; UTF-16 code units versus bytes in Windows APIs.
- The check and the allocation use the same wrong unit: still wrong.

```bash
rg -n -tc -tcpp '\b(wcsncpy|wcsncat|wmemcpy|MultiByteToWideChar|WideCharToMultiByte|mbstowcs|wcstombs)\s*\(' .
grep -rnE --include='*.[ch]' --include='*.[ch]pp' --include='*.cc' '(wcsncpy|wcsncat|wmemcpy|MultiByteToWideChar|WideCharToMultiByte|mbstowcs|wcstombs)[[:space:]]*\(' .
```

## 4. Use-after-free, double free and dangling references

**CWE:** 416 (use after free), 415 (double free), 825 (expired pointer), 562 (return of stack address), 762
(mismatched allocator), 763 (release of invalid pointer), 401 (leak; a finding only with a reachable exhaustion path).

```bash
rg -n -tc -tcpp '\b(free|delete|delete\[\]|realloc|fclose|close|g_free|av_free)\b' .
grep -rnE --include='*.[ch]' --include='*.[ch]pp' --include='*.cc' '\b(free|realloc|fclose|g_free|av_free)[[:space:]]*\(|delete[[:space:]]' .
# C++ dangling views and invalidated iterators
rg -n -tcpp '\.c_str\(\)|string_view|\.data\(\)|\b(push_back|emplace_back|insert|erase|resize|reserve)\s*\(' .
grep -rnE --include=*.cpp --include=*.cc --include=*.hpp 'c_str\(\)|string_view|(push_back|emplace_back|erase|resize)[[:space:]]*\(' .
```

**Read for:**

- Error paths: an object freed in a `goto err` block and then used, or freed again by the caller that also cleans up.
- Ownership that isn't written down: two structures holding the same pointer, both freeing it on teardown.
- `realloc` moving the block while another pointer still points into the old one; `p = realloc(p, n)` losing `p` on
  failure.
- Callbacks, timers and event-loop handlers registered with a pointer to an object that's freed on close without
  unregistering them.
- C++: iterators, references and pointers into a `std::vector` after `push_back` or `erase`; `c_str()` or `data()` of
  a temporary `std::string`; a `std::string_view` or `std::span` outliving its buffer; a lambda capturing by reference
  that runs after the scope ends; `shared_ptr` built twice from the same raw `this` (use `enable_shared_from_this`);
  `delete` on memory from `new[]` or `malloc`.
- Returning the address of a local, or a `string_view` of a local `std::string`.
- Reference counts changed without atomics, or decremented on one path and not another.

**Rules it out:** a single owner whose free sets the pointer to `NULL` and every user checks it; RAII (`unique_ptr`,
containers) that makes the lifetime structural; a lock that covers both the free and every use.

**Confirm:** the exact sequence of calls (from input you control) that frees and then uses; ASan
`heap-use-after-free` or `attempting double-free`.

## 5. Format strings

**CWE:** 134.

```bash
# printf-family calls whose format argument is not a string literal
rg -n -tc -tcpp '\b(printf|vprintf|syslog|vsyslog|err|warn|errx|warnx)\s*\(\s*[^",)]+\)' .
rg -n -tc -tcpp '\b(fprintf|sprintf|vfprintf|vsprintf|dprintf)\s*\(\s*[^,]+,\s*[^",)]+\)' .
rg -n -tc -tcpp '\b(snprintf|vsnprintf)\s*\(\s*[^,]+,\s*[^,]+,\s*[^",)]+\)' .
rg -n -tc -tcpp 'syslog\s*\(\s*[^,]+,\s*[^",)]+\)' .
grep -rnE --include='*.[ch]' --include='*.[ch]pp' --include='*.cc' '\b(printf|syslog)[[:space:]]*\([^",)]*\)' .
grep -rnE --include='*.[ch]' --include='*.[ch]pp' --include='*.cc' '\b(fprintf|sprintf)[[:space:]]*\([^,]+,[[:space:]]*[A-Za-z_][^",)]*\)' .
# Logging wrappers that take a format but lack the attribute the compiler needs to check them
rg -n -tc -tcpp '\.\.\.\s*\)' . | rg -v 'format\s*\(\s*(printf|__printf__)'
```

**Read for:** user-controlled data reaching the format argument, directly or through a logging wrapper. `%n` writes
through a pointer; `%s` and `%x` read the stack. Wrappers need `__attribute__((format(printf, N, M)))` so
`-Wformat -Wformat-security` can check their callers.

**Rules it out:** the argument is a literal, or a constant table indexed by a checked value. `-Werror=format-security`
in the build catches the simple cases at compile time (and is a good fix).

**Confirm:** the input path to the format argument. A static trace is enough for `confirmed` at medium confidence; a
unit test that logs `%x%x%x` and shows stack words in the output sets `reproduced: true`.

Rust's `format!` family takes literals only and isn't affected. C formatting called over FFI from Rust is.

## 6. Uninitialized memory

**CWE:** 457 (uninitialized variable), 908 (uninitialized resource), 909 (missing initialization), 200 when it leaks.

```bash
rg -n -tc -tcpp '\bmalloc\s*\(|\bstruct\s+\w+\s+\w+\s*;' .
rg -n -trust 'set_len\s*\(|MaybeUninit|assume_init|mem::uninitialized|mem::zeroed|with_capacity' .
grep -rnE --include=*.rs 'set_len[[:space:]]*\(|MaybeUninit|assume_init|mem::uninitialized|mem::zeroed' .
```

**Read for:** a stack struct or `malloc` buffer copied to the network, a file, or a less-privileged process with
fields or padding never written; a variable set only on some branches and read after; an error path that returns a
partly filled output; C++ members missing from a constructor's initializer list. Rust: `set_len` before the bytes are
written, `assume_init` on a partially written value, `mem::uninitialized` (deprecated and almost always undefined
behaviour), `mem::zeroed` for a type where all-zero isn't valid (references, `NonNull`, `Box`, most enums).

**Rules it out:** `calloc` or `= {0}` / `memset` before use; every byte written on every path before the read
(including padding, for structs sent whole); `-ftrivial-auto-var-init=zero` in every shipped build (it covers
automatic variables, not heap memory).

**Confirm:** what consumes the uninitialized bytes and what they could hold. Stack allocation alone isn't disclosure:
it needs a consumer that sends or compares them. MSan (`use-of-uninitialized-value`) or Miri.

## 7. Type confusion

**CWE:** 843.

```bash
rg -n -tcpp 'static_cast<\s*\w+\s*\*>|reinterpret_cast<' .
rg -n -tc -tcpp '\bunion\s+\w*\s*\{' .
grep -rnE --include='*.[ch]' --include='*.[ch]pp' --include='*.cc' 'static_cast<[^>]*\*>|reinterpret_cast<|union[[:space:]]+[A-Za-z_]*[[:space:]]*\{' .
```

A tag byte or object kind is checked in one place and the union member or downcast used somewhere else, a stale tag
survives object reuse, or a serialized type is validated as one element type and consumed as another. C++
`static_cast` down a class hierarchy doesn't check; `dynamic_cast` does.

## 8. Races and TOCTOU

**CWE:** 362, 367 (time-of-check time-of-use), 479 (non-reentrant call in a signal handler), 667 (locking).

```bash
rg -n -tc -tcpp '\b(access|stat|lstat)\s*\(' .
rg -n -tc -tcpp '\bsignal\s*\(|sigaction\s*\(' .
rg -n -trust 'static\s+mut\b|unsafe\s+impl\s+(Send|Sync)' .
grep -rnE --include='*.[ch]' --include='*.[ch]pp' --include='*.cc' '\b(access|lstat)[[:space:]]*\(|signal[[:space:]]*\(|sigaction[[:space:]]*\(' .
```

`access()` or `stat()` then `open()` on a path a lower-privileged user can swap (use `open` with `O_NOFOLLOW` and
`fstat` the descriptor); a refcount or cache shared across threads without a lock; a signal handler calling `malloc`,
`printf` or `free`; a length checked in shared memory and read again from it (double fetch). Confirm with TSan or a
deterministic schedule; a hypothetical interleaving with no security-relevant state change stays `needs_validation`.

## 9. NULL and invalid pointers

**CWE:** 476 (NULL dereference), 822 (untrusted pointer dereference), 824 (uninitialized pointer).

Unchecked `malloc` returns; lookups that return `NULL` on a miss and are dereferenced on input that misses; pointers
and offsets read from a file or received over FFI and used directly. A NULL dereference is usually a crash only (the
availability table), unless the NULL plus an input offset lands on mapped memory.

## 10. Secrets left in memory

**CWE:** 14 (compiler removed the wipe), 226 (not cleared before reuse or release), 244 (left in a reallocated block),
316 (cleartext in memory).

```bash
# A memset right before free/return is the classic dead store
rg -n -tc -tcpp -B1 -A2 'memset\s*\(\s*\w*(key|secret|pass|pwd|token|seed|priv)\w*' .
grep -rnE --include='*.[ch]' --include='*.[ch]pp' --include='*.cc' 'memset[[:space:]]*\([[:space:]]*[A-Za-z_]*(key|secret|pass|pwd|token|seed|priv)' .
# What a correct wipe looks like (absence in key-handling files is the signal)
rg -n -tc -tcpp '\b(explicit_bzero|memset_s|SecureZeroMemory|OPENSSL_cleanse|sodium_memzero|explicit_memset)\s*\(' .
rg -n -trust '\bzeroize\b|Zeroizing|ZeroizeOnDrop' .
# Process-level controls
rg -n -tc -tcpp 'PR_SET_DUMPABLE|MADV_DONTDUMP|RLIMIT_CORE|\bmlock\s*\(' .
```

Read the secret's whole life: where it's created, every copy (struct assignment, `std::string`, `Vec` growth,
`Clone`), and every exit path (errors included). A wipe that only runs on the success path leaves the error path
holding the key. Proving the compiler dropped a wipe needs the optimized IR or assembly; claim CWE-14 only with that,
otherwise record the missing safe-wipe call. See SKILL.md Step 5 for when this is a finding versus a hardening note.

## 11. Rust-specific hot spots

The full review is in [rust-unsafe-checklist.md](rust-unsafe-checklist.md). The inventory grep:

```bash
rg -n -trust '\bunsafe\s*(\{|fn\b|impl\b|extern\b)|\btransmute(_copy)?\b|from_raw_parts|set_len|get_unchecked|assume_init|Box::from_raw|ptr::(read|write|copy)|static\s+mut\b|#\[repr\(packed' .
grep -rnE --include=*.rs 'unsafe[[:space:]]*(\{|fn|impl|extern)|transmute|from_raw_parts|set_len|get_unchecked|assume_init|Box::from_raw|static[[:space:]]+mut|repr\(packed' .
# Panics reachable from input (availability)
rg -n -trust '\.(unwrap|expect)\s*\(|\[[^\]]*\.\.[^\]]*\]' .
```

## Sources

Paraphrased, not copied: Cloudflare security-audit-skill `MEMORY-SAFETY-AND-BINARY.md` (MIT) for the bound-re-derivation
discipline and the high-hit integer shapes; Trail of Bits `c-review` and `rust-review` (CC-BY-SA-4.0) for the class
split; MITRE CWE for the ids. The patterns are this repo's own.
