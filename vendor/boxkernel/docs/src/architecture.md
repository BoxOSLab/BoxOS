# Architecture

BoxKernel is ~22,000 lines of Rust in one crate (`boxkernel`) producing
a `proot` binary, plus a freestanding `loader/` sub-crate injected into
tracees. This chapter is the map: where each concern lives and how a
syscall flows through the system.

## The big picture

```text
            ┌─────────────────────────── proot process ───────────────────────────┐
            │                                                                     │
 argv ──► cli/mod.rs ──► tracee registry ◄── waitpid ──► tracee/event.rs (loop)    │
            │                     │                       │                       │
            │               ptrace attach            PTRACE_SYSCALL stops         │
            │                     │                       │                       │
            │              syscall pipeline:   sysenter ──► translate ──► sysexit  │
            │                     │                       │                       │
            │        ┌────────────┼───────────┐           │                       │
            │        ▼            ▼           ▼           ▼                       │
            │     path/*      syscall/*    extension/*  execve/*                  │
            │   (canon,      (enter/exit,  (typed       (ELF, ldso,               │
            │   bindings,     chain,        events)      shebang, auxv)            │
            │   glue, /proc)  sockets)                                            │
            │                     │                                               │
            │              tracee/mem.rs ◄── process_vm_* / PTRACE_PEEK/POKE      │
            │                     │                                               │
            └─────────────────────┼───────────────────────────────────────────────┘
                                  ▼
                          src/sys.rs  — every libc call, the only unsafe home
```

## Module map

| Module | Ports | Responsibility |
|---|---|---|
| `src/main.rs` | `main()` | Entry; `--shm-helper` dispatch; atexit cleanup |
| `src/cli/` | `cli.c` | Option parsing, binding/extension setup, `launch_process`, `run` |
| `src/tracee/` | `tracee/` | Tracee registry & lifecycle, the waitpid event loop, register access, tracee memory I/O, ABI word-size, seccomp attach |
| `src/ptrace/` | `ptrace/` | *Emulation of the ptrace API itself* — guest programs that call `ptrace` (gdb, strace inside the guest) get a virtualized view; also `wait` emulation |
| `src/syscall/` | `syscall/` | The translation pipeline: `enter`/`exit` hooks, sysnum chain rewrite, socket/sockaddr translation, netlink dump emulation, pipe-shadow trick, `rlimit` emulation, seccomp filter build, ABI heap |
| `src/path/` | `path/` | Canonicalization (`canon`), binding list (`binding`), `/proc` glue (`proc_emul`), sub-reconfiguration (`glue`), temp files, f2fs workaround |
| `src/fpath.rs` | `path/binding.c`, `path/path.c` helpers | `FixedPath`: `PATH_MAX`-bounded path buffer with C `char*` semantics preserved (NUL, component ops) |
| `src/execve/` | `execve/` | The `execve` machine: ELF header/program-header parsing, `PT_INTERP` rewriting, shebang expansion, auxv (`AT_*`) construction, `aoxp` auxv-pointer fixups, exit-time stack unpoisoning |
| `src/extension/` | `extension/` | Typed `Event` enum + `AnyExtension` dispatcher + the 8 built-in extensions |
| `src/syscall/` (seccomp) | `syscall/seccomp.c` | BPF program building, `seccomp` filter installation, SIGSYS trapping |
| `src/sysnum.rs` + `data/sysnums-*.txt` | `syscall/sysnums-*.list` + gen | Per-ABI syscall-number tables, code-generated at build time |
| `src/arch.rs` | `arch.h` | Per-host-architecture constants (x86_64, aarch64): trap size, red zone, load addresses, seccomp audit arches |
| `src/sys.rs` | all of libc | **The FFI boundary** — the only module allowed to call libc directly |
| `src/note.rs` | `cli/note.c` | `note!`/`verbose!` diagnostics with severity levels |
| `src/util.rs` | misc | Small shared helpers |
| `loader/` | `loader/` | `no_std` position-independent stub mapped into tracees to finish `execve` |

## A syscall's journey

1. **Stop.** `tracee/event.rs` runs `waitpid(-1, …, __WALL)` in a loop.
   On each `PTRACE_EVENT_STOP`/syscall-stop/SIGTRAP it looks up the
   `Tracee` in the registry and dispatches on stop reason. The first
   SIGTRAP is consumed for `ptrace` option setup (`deliver_sigtrap`
   semantics — later SIGTRAPs re-inject so guest handlers see them).

2. **Enter.** `syscall/enter.rs::translate_sysenter` reads the syscall
   number + args via `tracee/reg.rs` (`PTRACE_GETREGS` on x86_64;
   `PTRACE_GETREGSET`/`NT_PRSTATUS` on aarch64, where a rewritten
   syscall number goes back through `NT_ARM_SYSTEM_CALL`). The sysnum is
   decoded ABI-aware (`sysnum.rs` + `data/sysnums-*.txt` for
   x86_64/x32/i386/arm/arm64/sh4). Extensions get `SysEnterStart`, then
   the per-syscall translator runs; extensions get `SysEnterEnd`.

3. **Path translation.** Syscalls carrying paths go through
   `path/canon.rs` (guest→host canonicalization honoring bindings,
   cwd, and `/proc/<pid>/fd`), then `path/binding.rs` picks a host
   substitution, `path/glue.rs` handles sub-reconfiguration, and
   `TranslatedPath`/`SymlinkDeref`/`HostPath`/`GuestPath` events let
   extensions further rewrite. Result is written into tracee memory
   via `tracee/mem.rs` (`process_vm_writev` → `PTRACE_POKEDATA`
   fallback) and the register is repointed.

4. **Emulation or pass-through.** Some syscalls are answered entirely
   in the tracer (`getresuid` under `-0`, `uname` under `-k`, all
   SysV IPC under `--sysvipc`, netlink dumps, `ptrace` itself for
   nested tracing). Others proceed with rewritten args.
   `socket.rs`/`netlink.rs`/`pipe_shadow.rs`/`rlimit.rs` handle the
   special families; `chain.rs` handles "one syscall, several guest
   semantics" cases.

5. **Exit.** `syscall/exit.rs::translate_sysexit` reads the result
   register, post-processes (`fake_id0` pokes fabricated uid/gid
   buffers, `link2symlink` fabricates `st_nlink`, `kompat` adjusts
   uname fields, mountinfo rewrites read buffers), then writes the
   final guest-visible result back.

6. **Special stops.** `SIGSYS` (from our seccomp filter) routes to
   `handle_sigsys`; `PTRACE_EVENT_EXEC` enters `execve/enter.rs`;
   `EXEC_EXIT` unpoisons via `execve/exit.rs`; clone/fork stops drive
   `inherit_extensions` and the tracee registry.

## `execve`: the hardest syscall

`execve` gets its own subsystem because it *replaces* the tracee:

- `execve/enter.rs` parses the new ELF, decides native vs QEMU,
  computes load bias, maps the `loader/` stub into tracee memory, and
  plants a `SIGTRAP` that fires when the kernel finishes `execve` —
  because ptrace loses control across the exec boundary.
- `execve/elf.rs` is a self-contained ELF32/ELF64 parser (the only
  other place `unsafe` legitimately lives — union accessors for
  C-layout headers).
- `execve/ldso.rs` rewrites `PT_INTERP` and assembles
  `LD_LIBRARY_PATH`/`ld.so` arguments; `shebang.rs` expands `#!`;
  `auxv.rs`/`aoxp.rs` rebuild the auxv vector on the new stack.

## The extension framework

C's `(callback, config, filtered_sysnums)` triple becomes:

```rust
pub enum Event<'a> { GuestPath{..}, TranslatedPath{..},
    SysEnterStart, SysExitEnd{status}, InheritParent{..}, … }

pub enum AnyExtension { FakeId0(..), Link2Symlink(Box<..>),
    Kompat(..), Sysvipc(..), … }
```

`AnyExtension::notify(&mut self, &mut Tracee, Event) -> i32` is the
single dispatch point. Inheritance (`fork`/`clone`) is explicit:
`clone_for_child` per variant — `Kompat` shares one
`Rc<RefCell<Config>>` across all tracees (matching C's
`INHERIT_PARENT → shared`), while `FakeId0` clones per-child.

## The `sys` boundary

Every `libc` call — `open`, `stat`, `ptrace`, `process_vm_readv`,
`waitpid`, `socketpair`, `execvp`, `errno` — goes through
`src/sys.rs` as a thin safe wrapper that preserves **C-identical
errno semantics** (raw status return, caller inspects `errno`). This
is the reason the codebase can claim:

- 0 `static mut`, 0 `transmute`, 0 `libc::syscall` outside `sys`
- ~98 `unsafe` blocks, all in one auditable file
- no raw pointers in public safe signatures (machine words, `usize`)

See [Security model](security.md#the-unsafe-code-policy-for-auditors)
for the enforced invariants.

## The `loader/` sub-crate

`execve` needs code running *inside* the tracee at exec-completion
time (to hand registers/auxv back to the tracer). `loader/` is a
`no_std`, position-independent, naked-function crate built as a raw
binary and `include_bytes!`'d into the main crate. Its `unsafe` is
inherent (assembly syscall stubs and the final branch, written for
x86_64 and aarch64; arm64 has no `open(2)`, so the loader uses
`openat(AT_FDCWD, …)` there) and intentionally isolated from the safe
code base.

## Seccomp acceleration

Where `seccomp` filtering is available, `syscall/seccomp.rs` builds a
BPF program that only traps syscalls needing translation; everything
else runs uninterrupted. `tracee/seccomp.rs` attaches it to tracees;
`SIGSYS` events route back into the translator. The C "seccomp
acceleration" design is preserved, including the
`PROOT_ASSUME_NEW_SECCOMP` / `PROOT_NO_SECCOMP` switches.
