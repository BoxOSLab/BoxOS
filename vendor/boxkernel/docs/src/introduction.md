# Introduction

**BoxKernel** is a clean-room Rust re-implementation of
[Termux PRoot 5.1.0](https://github.com/termux/proot) — a user-space
implementation of `chroot`, `mount --bind`, and `binfmt_misc`.

Users need no privileges or setup to:

- use an arbitrary directory as a new root filesystem (the *guest
  rootfs*),
- make host files visible elsewhere in the filesystem hierarchy
  (*bindings*),
- execute programs built for another CPU architecture transparently
  through QEMU user-mode, and
- instrument Linux processes through a modular *extension* mechanism.

## How it works, in one paragraph

BoxKernel launches a child process under `ptrace(2)`. Every system call
the child attempts is intercepted at syscall-enter and syscall-exit.
BoxKernel reads the syscall arguments out of tracee memory
(`process_vm_readv`, falling back to `PTRACE_PEEKDATA`), rewrites path
arguments according to the configured rootfs and bindings, writes them
back, and lets the syscall proceed — or emulates the syscall entirely
and fabricates its return value. Where the kernel supports it, a
`seccomp` filter pre-selects which syscalls trap into the tracer so
uninteresting syscalls run at full speed. Nothing is ever done in the
guest kernel — there is no guest kernel; everything is emulation in
user space on the host.

## Relationship to C PRoot

| | C PRoot 5.1.0 (reference) | BoxKernel |
|---|---|---|
| Language | C99 + talloc + GNU make | Rust 2024, `libc`-only, Cargo |
| `unsafe` | the whole language | one audited module (`src/sys.rs`) + tiny documented islands |
| Global state | `static` variables, `static mut`-style | atomics + `thread_local!` only |
| Extensions | `(callback, config, sysnums)` triples, untyped payloads | `AnyExtension` enum + typed `Event` variants |
| Syscall table | generated `sysnums.h` | generated `sysnum.rs` via `build.rs` + `data/sysnums-*.txt` |
| Test contract | `tests/` suite | the *same* suite — **113 checks green** |

The binary produced by this crate is named `proot` so existing
consumers (e.g. `proot-distro` scripts) can use it as a drop-in
replacement.

## Feature checklist

- User-space `chroot` (`-r`, `-R`, `-S`) and per-process working dir (`-w`)
- Virtual bind mounts (`-b`, `-m`), including `!` no-deref bindings
- QEMU user-mode mixed execution (`-q`) with `/host-rootfs`
- Full `execve` emulation: ELF parsing, `PT_INTERP` rewriting, shebang
  (`#!`) interpretation, `AT_*` auxv synthesis
- ABI-aware syscall translation (x86-64, x32, i386, ARM, AArch64, SH4
  syscall tables)
- Extensions: `-0`/`-i` fake identity, `--link2symlink`, `-H`,
  `-k` kompat, `-p` port switch, `-L` link-size fix, `--sysvipc`,
  mountinfo rewriting
- Seccomp-accelerated filtering; `--kill-on-exit`; verbose levels `-v`

## Reading this book

- **Using it?** Start with [Installation](installation.md) then
  [Usage and recipes](usage.md); keep the
  [command-line reference](options.md) at hand.
- **Hacking on it?** [Architecture](architecture.md) is the map;
  [Development guide](development.md) covers the toolchain and the
  unsafe/parity rules; [Testing](testing.md) shows how the C suite is
  the behavioral contract.
- **Evaluating it?** [Security model](security.md) explains what it
  does *not* do, and [Compatibility](compatibility.md) lists every
  known deviation from C PRoot.
