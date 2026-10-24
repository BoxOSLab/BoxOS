# Security model

## BoxKernel is not a sandbox

This is the single most important thing to understand, and it is
inherited verbatim from PRoot:

> **PRoot confuses programs; it does not confine them.**

- Every tracee runs with the **invoker's** uid, capabilities, and
  filesystem access. `-r` only rewrites how paths *resolve* — a guest
  that opens `../../etc/shadow` still lands wherever the host puts it
  (bound paths notwithstanding, every host file reachable to the user
  is reachable to the guest).
- `-0` fakes *reports* of root. It grants nothing the user didn't
  already have, and conversely grants the guest everything the user
  already has.
- Deliberately adversarial guests can escape the emulated view: they
  can invoke `ptrace` themselves (nested tracing is emulated, but the
  emulation is a compat feature, not a containment), use syscalls or
  ABIs the filter doesn't translate, or write through a binding.
- **Do not run untrusted code under BoxKernel.** For confinement use
  mount namespaces (bubblewrap, `unshare`), containers, or VMs.

## What the design *does* protect

- **Tracer integrity.** A tracee cannot corrupt the tracer through
  syscall arguments: every pointer read/write goes through
  `src/tracee/mem.rs` (`process_vm_*` with `PTRACE_PEEK/POKE`
  fallback), and all kernel-boundary calls are funneled through
  `src/sys.rs`.
- **Host CLI argument integrity.** QEMU env pairs (`-E`/`-U`) and exec
  argument vectors are rebuilt in tracer-owned memory, never edited
  in place in tracee memory.
- **No ambient root.** Nothing in BoxKernel requires or grants
  privilege; there is no setuid helper.

## The unsafe-code policy (for auditors)

| Site | What it is | Why it must exist |
|---|---|---|
| `src/sys.rs` (~98 blocks) | thin libc wrappers | *the* FFI boundary; the only file allowed to call libc |
| `src/execve/elf.rs` (8) | `as32`/`as64` union accessors | ELF-class-validated reads on all-POD C-layout headers |
| `src/tracee/event.rs` (3) | `siginfo_t`/`utsname` field reads | kernel-provided pointers in signal handlers |
| `src/syscall/netlink.rs` (1) | `CStr::from_ptr` | bounded interface-name buffer |
| `loader/` (10) | naked fns + `asm!` syscall stubs | freestanding `no_std` code injected into tracees |

Enforced invariants:

- **No `static mut`.** Event flags are `Atomic*`; the pipe-shadow
  table is `thread_local!`; netlink probe caching is `AtomicI32`.
- **No `transmute`.** POD serialization goes through
  `sys::as_bytes`/`as_bytes_mut`; cross-field reads use `offset_of!`.
- **`unsafe_op_in_unsafe_fn` is denied crate-wide** — even inside
  `unsafe fn`, each operation needs its own explicit block.
- Every `unsafe` block carries a `// SAFETY:` invariant comment.
- `ptrace`/`process_vm_*` take `usize` words, not raw pointers — the
  machine-word semantics are kernel ABI, not pointer provenance.

## Auditing dependencies

`libc` is the only dependency. `cargo deny check` (CI-enforced)
verifies licenses, advisories, and banned crates; `Cargo.lock` is
committed.

## Reporting

See [SECURITY.md](https://github.com/BoxOSLab/BoxKernel/blob/main/SECURITY.md)
— private GitHub advisories preferred, no public issues for
vulnerabilities.
