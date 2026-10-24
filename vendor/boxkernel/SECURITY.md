# Security Policy

## Scope: BoxKernel is *not* a security boundary

Like PRoot, BoxKernel works by *confusing* traced programs — it rewrites
their syscall arguments so they see a different filesystem view. It does
**not** confine them:

- A guest program can read, modify, or delete **every host file** the
  invoking user could touch. `-r` is a view, not a jail.
- Tracees run with the invoker's full privileges and capabilities.
- Deliberately hostile code can escape the path translation (e.g. via
  `ptrace` of its own children, raw syscalls through mechanisms we do
  not filter, or simply asking for a path we have bound through).

**Never use BoxKernel to isolate untrusted code.** For actual
confinement use namespaces/containers (bubblewrap, runc) or a VM.

## What *is* in scope

- Memory-safety defects in BoxKernel itself (the Rust code, the FFI
  boundary in `src/sys.rs`, the `loader/` stub)
- Incorrect syscall rewriting that corrupts or unexpectedly reveals
  host data *beyond* what the invoking user could already do
- Crashes/hangs of the tracer triggered by tracee input (tracees are
  expected to be non-malicious but arbitrary — a robust tracer should
  not die on weird syscall patterns)
- Vulnerabilities in dependencies (`libc` — audited via `cargo deny`)

## Reporting a vulnerability

**Please do not open a public issue for security reports.**

Use GitHub's private reporting:

- <https://github.com/BoxOSLab/BoxKernel/security/advisories/new>

or email the maintainers at the address in `git shortlog -se` output.

Please include:

- The BoxKernel version/commit and host environment (kernel, arch)
- A minimal reproducer
- `proot -v 9 …` output if the bug is in translation/emulation logic

We aim to acknowledge reports within a few days. Fixes land on `main`
and are disclosed via GitHub Security Advisories.

## Supported versions

Only `main` (currently the 5.1.0 line) is supported. There are no
stable back-port branches yet.

## Hardening notes for contributors

- All kernel-boundary `unsafe` lives in `src/sys.rs` — audit it first.
- `unsafe_op_in_unsafe_fn` is denied crate-wide; every `unsafe` block
  must carry a `// SAFETY:` invariant.
- No `static mut`, no `transmute`; POD serialization goes through
  `sys::as_bytes`/`as_bytes_mut`.
- Tracee memory access is mediated by `src/tracee/mem.rs`; never open-
  code `process_vm_*` or `PTRACE_PEEK/POKE` elsewhere.
