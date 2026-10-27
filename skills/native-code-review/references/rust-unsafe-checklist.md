# Rust unsafe checklist

Safe Rust promises that no input, from any safe caller, causes undefined behaviour. `unsafe` is where the author
takes over part of that promise by hand. Reviewing it means checking the hand-written proof: what each block needs,
where that's established, and whether safe code anywhere can break it.

A **soundness bug** is safe code that can cause undefined behaviour. It's a bug in the crate whether or not today's
callers trigger it. Whether it's a *finding* follows the rules in SKILL.md Step 8: an application needs a path from
untrusted input; a published library's safe `pub` API that can be driven into undefined behaviour from safe code is a
finding with a condition naming the downstream call pattern.

## 1. Inventory

```bash
# Every unsafe site
rg -n -trust '\bunsafe\s*\{|\bunsafe\s+fn\b|\bunsafe\s+impl\b|\bunsafe\s+extern\b|\bextern\s+"C"' .
grep -rnE --include=*.rs 'unsafe[[:space:]]*\{|unsafe[[:space:]]+(fn|impl|extern)|extern[[:space:]]+"C"' .
# Crates that opt out of unsafe entirely (they're done)
rg -n -trust '#!\[(forbid|deny)\(unsafe_code\)\]' .
# Unsafe blocks with no SAFETY comment on the line above (a lead, not a finding)
git ls-files '*.rs' | xargs awk 'FNR==1{prev=""} /unsafe[[:space:]]*\{/ && prev !~ /SAFETY/ {print FILENAME":"FNR": "$0} {prev=$0}'
```

Group the sites by module. For each block, record the smallest enclosing function and every `pub` function that
reaches it, directly or through calls. That reach list is the attack surface: every safe entry point that can drive
input into the block.

Lints worth having on, which also find sites for you: `clippy::undocumented_unsafe_blocks` (every block needs a
`// SAFETY:` comment), `clippy::missing_safety_doc` (every `pub unsafe fn` needs a `# Safety` section),
`clippy::multiple_unsafe_ops_per_block`, and rustc's `unsafe_op_in_unsafe_fn` (warn by default from the 2024
edition; it makes the body of an `unsafe fn` need its own `unsafe` blocks). Running clippy is a build, so it needs a
yes; reading `clippy.toml`, `Cargo.toml` `[lints]` and `#![warn(...)]` attributes doesn't.

## 2. The contract of each block

For every `unsafe` block:

1. **Name the precondition.** What must be true for each operation inside to be defined? In bounds, aligned,
   initialized, non-null, not aliased by a `&mut`, a valid value of the type, alive for the lifetime claimed.
2. **Read the `// SAFETY:` comment** and check it states that precondition, not something nearby. Treat it as a
   claim. A missing comment is a hardening note; a wrong one is a candidate.
3. **Find where the precondition is established**, and check it holds on every path, including early returns, error
   paths, and after a panic unwinds out of the middle of an operation.
4. **Widen to the module.** Privacy is the boundary unsafe code relies on. Any code in the same module that can write
   a field the block trusts (`len`, `cap`, `head`, a state enum) can break it, even safe code. A `pub` field the block
   trusts is a soundness bug by itself, since any caller can set it.
5. **Ask whether a safe caller can violate it.** A safe `pub fn` must uphold the precondition for every input. A
   `/// # Safety` section on a *safe* function shifts nothing: the function must check at run time or be `unsafe fn`.
   A `pub unsafe fn` may hand the obligation to its callers, but only if its `# Safety` section states it, and then
   every call site in the crate is a place to check.

## 3. Hazards by operation

| Operation | What goes wrong | Check |
|---|---|---|
| `Vec::set_len(n)` | Length covers bytes never written; drop or read of uninitialized elements; exposing them to safe code | Every element below `n` is initialized before `set_len` runs, on every path, including short reads and early returns |
| `slice::from_raw_parts(p, len)` / `_mut` | `p` null or misaligned (undefined even when `len == 0`), `len` too long, wrong element type, memory not initialized, lifetime not tied to the owner | Pointer from a live allocation of `len` elements of `T`; use `NonNull::dangling()` for empty slices; returned lifetime bounded by the owner |
| `Vec::from_raw_parts(p, len, cap)` / `String::from_raw_parts` | Allocation not from the same allocator with the same layout; `cap` wrong; double ownership | Only for parts that came from `Vec::into_raw_parts`-style decomposition of the same type |
| `MaybeUninit::assume_init` | Partially initialized value treated as whole; padding read | Every field written; arrays fully filled; prefer `MaybeUninit::write` and per-element tracking |
| `mem::zeroed()` | All-zero is not valid for references, `Box`, `NonNull`, function pointers, most enums, `NonZero*` | Only for types where zero is a valid value (integers, raw pointers, `#[repr(C)]` structs of those) |
| `mem::uninitialized()` | Deprecated; undefined for almost every type | Replace with `MaybeUninit` |
| `mem::transmute` / `transmute_copy` | Size or layout mismatch, invalid values (`u8` → `bool`, integer → enum), `#[repr(Rust)]` layout assumed, `&T` → `&mut T`, lifetime extension (`&'a T` → `&'static T`) | Both types `#[repr(C)]` or primitive with identical layout; every bit pattern valid for the target; prefer `from_ne_bytes`, `bytemuck`/`zerocopy` derives, `as` for numbers, `.cast()` for pointers |
| `get_unchecked(i)` / `ptr.add(i)` / `ptr.offset(i)` | Index out of bounds; pointer arithmetic past the allocation is undefined before any dereference | A check or invariant (mask, `min`, earlier bound) that covers the widest input on every path |
| `ptr::read(p)` | Bitwise copy leaves two owners; double drop when both are dropped | The original is forgotten (`mem::forget`, `ManuallyDrop`) or overwritten with `ptr::write` |
| `Box::from_raw(p)` | Called twice for one pointer (double free), or on a pointer not from `Box::into_raw` | One `from_raw` per `into_raw`, ownership documented at the FFI boundary |
| `&mut *p` from a raw pointer | Two live `&mut` to the same memory, or `&mut` while a `&` is live: aliasing violation | Derive references so their lifetimes don't overlap; keep raw pointers raw until the last moment |
| `*const T as *mut T` then write | Writing through a pointer derived from a shared reference | Only through `UnsafeCell` (or types built on it) |
| `static mut` | Data races; any reference to it is risky (the 2024 edition lints against taking references) | `Atomic*`, `Mutex`, `OnceLock`, `LazyLock` |
| `#[repr(packed)]` field reference | Misaligned reference: undefined | Copy the field out (`{ s.field }`) or use `ptr::addr_of!` / `&raw const` |
| `str::from_utf8_unchecked` | Invalid UTF-8 in a `str` breaks invariants other code relies on | Only on bytes already validated; use `from_utf8` on input |
| `union` field read | Reading a field other than the one last written, when not all bit patterns are valid | A discriminant checked on every path, or only plain-old-data fields |
| Pointer ↔ integer casts | `usize as *mut T` has no provenance; dereferencing it is undefined unless the address was exposed from a live pointer | Keep pointers as pointers; `with_addr` / `map_addr` for tagging; `expose_provenance` / `with_exposed_provenance` when unavoidable |

## 4. Send, Sync and trait trust

- `unsafe impl Send for X<T> {}` and `unsafe impl Sync for X<T> {}` need bounds that match what `X` does with `T`:
  usually `T: Send` for `Send`, and `T: Sync` (plus `T: Send` if `&X` hands out `T` or `&mut T`) for `Sync`. A
  missing bound lets safe code move an `Rc` or a `RefCell` across threads: a data race (CWE-362) with no `unsafe` in
  the caller.
- A type with interior mutability (`Cell`, `RefCell`, raw pointers to shared state) that implements `Sync` needs
  synchronization behind every access.
- **Unsafe code must not trust safe traits.** `Ord`, `Eq`, `Hash`, `Iterator::size_hint`, `ExactSizeIterator::len`,
  `Borrow`, `Deref`, `Drop` and closures are written by callers, and a safe implementation can return inconsistent
  results, lie about length, or panic. If an `unsafe` block's bound depends on one (allocate `len()` slots and write
  `next()` results without counting), a caller can drive it out of bounds. Use `unsafe` traits (`TrustedLen` is
  unstable; define your own `unsafe trait`) or recheck.
- **Panic safety.** A user closure or trait method that panics in the middle of an `unsafe` operation unwinds with the
  structure half-updated: a `len` already bumped, an element moved out but not replaced. Drop guards or "set length
  last" patterns fix it.

## 5. FFI boundaries

Both sides of every boundary are in scope. For each `extern` function and each callback, fill the boundary table:
types, ownership, lifetime, thread, and what happens on error.

- **Declarations match the C side.** Hand-written `extern` blocks drift from headers; `bindgen` output from the
  actual header is the reference. Check integer widths (`c_int`, `c_long` differs between Windows and Unix,
  `usize` vs `size_t`), `bool` (C `_Bool` is fine; C `int` used as a flag is not `bool`), and struct layout
  (`#[repr(C)]` on every struct that crosses, same field order, same packing).
- **Enums from C.** A Rust `enum` received from C with a value outside its variants is undefined behaviour. Receive
  an integer and convert with a checked match.
- **Ownership.** Memory allocated by C is freed by C's `free` (or the library's own release function), memory from
  Rust by Rust. `CString::into_raw` comes back only through `CString::from_raw`; `Box::into_raw` only through
  `Box::from_raw`. Mixing allocators is CWE-762.
- **Nul-termination and lengths.** `CStr::from_ptr` scans to a nul and needs one inside the allocation; for buffers
  that carry a length, use `CStr::from_bytes_with_nul` / `from_bytes_until_nul`. `CString::new` fails on interior
  nuls, and `.unwrap()` there is a panic reachable from input. Lengths passed to C: bytes or elements, and including
  the terminator or not.
- **Dangling pointers.** `CString::new(s).unwrap().as_ptr()` points into a temporary that's dropped at the end of the
  statement. Bind the `CString` to a variable that outlives the call. The same goes for `Vec`s passed as `as_ptr()`.
- **Retained pointers.** If C keeps a pointer after the call returns (a registered buffer, a callback context), the
  Rust side must keep the memory alive and unmoved (`Box::pin`, leaked or owned by a handle) until C releases it.
- **Null from C.** Every pointer from C is checked before it becomes a reference. `&*p` with `p` null is undefined.
- **Unwinding.** A Rust panic must not cross an `extern "C"` boundary (since Rust 1.81 it aborts the process; earlier
  it was undefined). Callbacks called from C wrap their body in `std::panic::catch_unwind`, or the crate builds with
  `panic = "abort"`. `extern "C-unwind"` is the explicit opt-in.
- **2024 edition.** `extern` blocks must be written `unsafe extern`, with items marked `safe` or `unsafe`;
  `#[no_mangle]` and `#[export_name]` become `#[unsafe(no_mangle)]` and `#[unsafe(export_name)]`. A `safe fn` inside
  an `unsafe extern` block is a promise the C function is sound for every input. Check that promise.
- **Threads.** C libraries that require one thread, or no concurrent calls on a handle, need the Rust wrapper to be
  `!Send`/`!Sync` or to lock.

## 6. Integers and panics

- Release profiles have `overflow-checks = false` by default: arithmetic wraps silently. Any arithmetic on input that
  reaches `unsafe` indexing, `set_len`, an allocation size or pointer arithmetic needs `checked_*`, `saturating_*` or
  a prior bound. Turning on `overflow-checks = true` in `[profile.release]` converts wraps into panics.
- `as` truncates (`u64 as u32`) and reinterprets sign (`-1i32 as usize`). Use `u32::try_from(x)?`.
- Panics reachable from untrusted input (`unwrap`, `expect`, indexing, slicing at an input offset, `RefCell` double
  borrow, division by an input zero) are availability bugs: CWE-617 (reachable assertion) or CWE-248, rated on the
  availability table. Deep recursion on nested input overflows the stack (CWE-674).

## 7. Dynamic checks (with a yes)

- **Miri** (`cargo +nightly miri test`): interprets the test suite and reports undefined behaviour it executes:
  out-of-bounds pointers, use after free, uninitialized reads, invalid values, aliasing violations (Stacked Borrows by
  default, `-Zmiri-tree-borrows` for the newer model), data races. `MIRIFLAGS=-Zmiri-strict-provenance` catches
  integer-to-pointer casts. It only sees paths the tests run, and it can't execute most FFI calls.
- **Sanitizers** on nightly: `RUSTFLAGS=-Zsanitizer=address` (or `memory`, `thread`) with an explicit `--target`;
  needed when the unsafe code calls into C.
- **cargo-geiger**: counts `unsafe` per crate in the dependency tree, which tells you where to look in dependencies.
  It builds the crate, so it runs build scripts.
- A Miri or sanitizer report from safe code (a test that uses only the public safe API) is the strongest evidence of
  a soundness bug: it sets `reproduced: true`.

## Sources

Paraphrased, not copied: [The Rustonomicon](https://doc.rust-lang.org/nomicon/) (MIT / Apache-2.0) on soundness, the
module boundary, `Send`/`Sync`, uninitialized memory, FFI and unwinding; the [Rust 2024 edition
guide](https://doc.rust-lang.org/edition-guide/rust-2024/index.html); [Miri](https://github.com/rust-lang/miri);
Trail of Bits `rust-review` (CC-BY-SA-4.0) for the reach-list idea and the split of unsafe-boundary passes.
