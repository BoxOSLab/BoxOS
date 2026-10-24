# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to the version numbering of the PRoot release it
re-implements ([Termux PRoot 5.1.0](https://github.com/termux/proot)).

## [Unreleased]

### Added

- AArch64 host support, for Linux and Android (Bionic):
  - per-architecture register layer: `user_pt_regs` through
    `PTRACE_{GET,SET}REGSET`/`NT_PRSTATUS`, syscall-number rewrites through
    `NT_ARM_SYSTEM_CALL`, AArch32 (compat) register dumps recognized;
  - arm64/ARM EABI syscall tables, `AUDIT_ARCH_AARCH64`/`AUDIT_ARCH_ARM`
    seccomp sections, arm64 load addresses, no red zone, 16-byte stack
    alignment for the loader;
  - chained and seccomp-restarted syscalls are re-armed through the
    register the trap reads its number from (`SYSTRAP_NUM`: rax on x86_64,
    x8 on arm64), and restoring registers at syscall exit skips arguments
    that alias the result register (x0);
  - an aarch64 loader (`openat`-based, `svc #0` syscalls);
  - Android NDK builds (`aarch64-linux-android`, `x86_64-linux-android`):
    Bionic `errno`, request/resource integer types and missing libc
    constants are handled;
  - CI runs the test suite on a native arm64 runner and builds both
    Android ABIs.
- `-L` also fixes symlink sizes reported by `newfstatat(…,
  AT_SYMLINK_NOFOLLOW)` and `statx(…, AT_SYMLINK_NOFOLLOW)`, which is how
  `lstat()` reaches the kernel on arm64 and with current C libraries.
- Complete open-source documentation system:
  - `README.md` with feature overview, quick start, and badges
  - mdBook documentation site under `docs/` (user guide, CLI reference,
    architecture, extensions, mixed-mode/QEMU, security model,
    development and testing guides)
  - `doc/proot.1` manual page
  - `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`,
    `CHANGELOG.md`
  - GitHub issue templates and pull-request template
  - `docs` CI workflow: `cargo doc` plus mdBook build and GitHub Pages
    deployment

### Changed

- Expanded crate-level and module-level rustdoc coverage.
- Tests that poked x86 register fields directly go through
  architecture-neutral helpers and run on both hosts.

## [5.1.0] — clean-room Rust rewrite of PRoot 5.1.0

### Added

- Full clean-room Rust port of Termux PRoot 5.1.0:
  - User-space `chroot` (`-r`, `-R`, `-S`)
  - Virtual bind mounts (`-b`, `-m`) with symlink-deref control
  - QEMU user-mode mixed execution (`-q`) with `/host-rootfs`
  - ABI-aware syscall translation (x86-64, x32, i386, arm, arm64, sh4
    tables in `data/`)
  - ELF parsing, interpreter (`PT_INTERP`) rewriting, loader stub, and
    shebang (`#!`) interpretation
  - Extensions: `-0`/`-i` fake identity, `--link2symlink`, `-H`
    hidden files, `-k` kernel-release kompat, `-p` port switch,
    `-L` symlink-size fix, `--sysvipc` (shm/sem/msg + helper daemon),
    mountinfo rewriting
  - Seccomp-accelerated syscall filtering
  - `--kill-on-exit`, `-w`, `-v` handling identical to C

- `src/sys.rs` FFI boundary: every libc/syscall call is a thin audited
  wrapper; the rest of the codebase contains no direct FFI.
- Freestanding `loader/` sub-crate (`no_std`, position-independent)
  injected into tracees for `execve` completion, matching the C
  loader's role.
- Modern Rust toolchain: edition 2024, MSRV 1.85, rustfmt/clippy
  enforcement, `unsafe_op_in_unsafe_fn` denied, cargo-deny policy,
  GitHub Actions CI, Dependabot.

### Fixed (relative to naive ports)

- `errno` is cleared on `process_vm_*` fast paths, matching the C
  convention — stale errno previously poisoned `getresuid`-style
  emulations and corrupted wait-status delivery.
- `SIGTRAP` delivery semantics: only the first SIGTRAP is consumed for
  ptrace option setup; subsequent ones reach the guest handler.
- `-q` runner resolution happens against the *host* filesystem (matching
  C's `reconf.tracee == NULL` path), so the QEMU binary is found via the
  host `PATH` rather than the guest rootfs.
- Kompat extension configuration is shared across tracees
  (`Rc<RefCell<…>>`), matching C's `INHERIT_PARENT → shared` model.
- Misaligned `&mut *bytes.cast::<libc::stat>()` uses replaced with typed
  reads — a genuine alignment-UB fix.
- No `static mut` anywhere: event flags are atomics, the pipe-shadow
  table is `thread_local!`, netlink probing uses an atomic cache.

### Validation

- Upstream C integration suite: **113 checks pass, 0 failures**
  (8 environment skips, 9 expected failures — identical to the C
  baseline; two QEMU-runner tests actually pass *better* than C because
  the Rust binary has no `libtalloc` dependency).
- `cargo fmt --check`, `cargo clippy --all-targets -D warnings`,
  `cargo test`, `cargo deny check`, debug + release builds all clean.

[Unreleased]: https://github.com/BoxOSLab/BoxKernel/compare/v5.1.0...HEAD
[5.1.0]: https://github.com/BoxOSLab/BoxKernel/releases/tag/v5.1.0
