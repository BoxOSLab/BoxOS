# Contributing to BoxKernel

Thanks for your interest in contributing! BoxKernel is a clean-room
Rust re-implementation of [Termux PRoot 5.1.0](https://github.com/termux/proot)
whose overriding constraint is **behavioral parity with the C
reference**. Every contribution is judged against that constraint first,
idiomaticity second.

## Development setup

Requirements:

- Linux (the tool instruments `ptrace`, `seccomp`, `process_vm_*`)
- Rust **1.85 or newer** — pinned via `rust-toolchain.toml`
  (`rustfmt` and `clippy` components are pulled automatically)
- No other dependencies; `libc` is the only crate dependency

```console
$ git clone https://github.com/BoxOSLab/BoxKernel.git
$ cd BoxKernel
$ cargo build            # debug build: target/debug/proot
$ cargo build --release  # release build
$ cargo test             # unit tests
```

## The parity rule

`src/` files carry comments naming the C function each one ports
(e.g. `// port of translate_sysenter_end()`). When fixing a bug:

1. **Reproduce first** — write a shell/C reproducer, or better, run the
   relevant test from the upstream suite (see below).
2. Check the C reference for the intended semantics — the comment above
   each function names its C counterpart.
3. Keep C-identical error paths: return `-errno` from the *innermost*
   failing operation, preserve `errno` conventions (`sys::clear_errno`
   before calls whose success is measured through `errno == 0`), and
   keep C's verdicts for edge cases even when they look odd — they are
   usually load-bearing.
4. Fix the Rust code; re-run the reproducer and the suite.

## Running the reference test suite

The C implementation's integration suite is the behavioral contract.
To run it against the Rust binary:

```console
$ cd ../proot/tests               # the C reference checkout
$ make -C . test PROOT=/path/to/BoxKernel/target/release/proot
```

Expected result: **113 ok, 0 failed**, 8 skipped, 9 xfail (environment
dependent). A change is not done until this suite is green.

## Code quality gates

CI runs all of these; run them locally before pushing:

```console
$ cargo fmt --all -- --check
$ cargo clippy --all-targets --locked -- -D warnings
$ cargo test --locked
$ cargo deny check            # license + advisory audit
$ cargo build --release --locked
```

- **Edition 2024**, MSRV 1.85 — do not use APIs stabilized after 1.85.
- `unsafe_op_in_unsafe_fn = "deny"` is set crate-wide.

## The unsafe policy

`unsafe` is confined to the FFI boundary and to a few documented
islands:

| Location | Rule |
|---|---|
| `src/sys.rs` | The **only** place raw `libc` calls may appear. Every wrapper is a small safe function with a `// SAFETY:` comment. Callers keep C-style status/errno semantics. |
| `src/execve/elf.rs` | Union accessors (`as32`/`as64`/`as32_mut`/`as64_mut`) — ELF-class-validated, all-POD structs. |
| `src/tracee/event.rs` | Kernel-provided `siginfo_t`/`utsname` reads. |
| `loader/` | Freestanding `no_std` naked functions and `asm!` — inherently unsafe, kept minimal. |

Rules for new code:

- **No `static mut`.** Use atomics or `thread_local!`.
- **No `transmute`/`transmute_copy`.** Serialize POD structs through
  `sys::as_bytes`/`sys::as_bytes_mut`; cross-field reads via
  `offset_of!`.
- **No raw pointers in safe function signatures.** Machine words
  (`usize`) represent addresses/data in `sys::ptrace` and friends.
- **Every remaining `unsafe` block needs a `// SAFETY:` comment**
  stating the invariant it relies on.
- If a safe `std` API exists with identical semantics, use it
  (e.g. `std::os::unix::fs::MetadataExt` instead of re-reading `stat`
  fields) — but keep C-visible error semantics through `sys::`
  wrappers when errno identity matters.

## Commit style

- Small, focused commits — one logical change each, following the
  existing history (`Isolate unsafe…`, `Fix SIGTRAP re-delivery…`).
- Commit message: imperative subject line, *why* in the body when it
  is not obvious.
- Do not commit build artifacts or secrets; `target/` is gitignored.

## Reporting bugs and proposing features

- Bugs: use the [bug report template](.github/ISSUE_TEMPLATE/bug_report.yml)
  and include `proot -v 9 …` output where relevant.
- Features: open a feature request describing the C-PRoot behavior or
  the new capability; parity-affecting changes need a corresponding
  C-test-suite story.

## Code of conduct

Participation is governed by the
[Contributor Covenant](CODE_OF_CONDUCT.md).
