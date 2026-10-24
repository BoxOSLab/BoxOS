# BoxKernel

[![CI](https://img.shields.io/github/actions/workflow/status/BoxOSLab/BoxKernel/ci.yml?branch=main&style=for-the-badge&label=CI)](https://github.com/BoxOSLab/BoxKernel/actions/workflows/ci.yml)
[![Docs](https://img.shields.io/github/actions/workflow/status/BoxOSLab/BoxKernel/docs.yml?branch=main&style=for-the-badge&label=Docs)](https://github.com/BoxOSLab/BoxKernel/actions/workflows/docs.yml)
[![License: GPL-2.0-or-later](https://img.shields.io/badge/license-GPL--2.0--or--later-blue?style=for-the-badge)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.85-orange?style=for-the-badge)](rust-toolchain.toml)

A clean-room **Rust rewrite of [PRoot](https://github.com/termux/proot) 5.1.0**:
a user-space implementation of `chroot`, `mount --bind`, and
`binfmt_misc` — no privileges or setup required.

BoxKernel traces child processes with `ptrace(2)` (plus `seccomp`
filtering where the kernel supports it) and rewrites their system calls.
Use it to run programs against an arbitrary guest root filesystem,
relocate files into a different place in the hierarchy, execute binaries
built for another CPU architecture transparently through QEMU user-mode,
or instrument Linux processes through its extension mechanism.

## Features

* **User-space `chroot`** — confine programs to an arbitrary directory
  (`-r`, `-R`, `-S`) without root privileges.
* **Virtual bind mounts** — make any host file or directory visible
  anywhere in the guest namespace (`-b`/`-m`), with symlink-aware
  overlay semantics.
* **`binfmt_misc`-style execution** — transparent QEMU user-mode
  execution for foreign-architecture binaries (`-q`), including
  *mixed mode*: host and guest programs interoperating in one
  filesystem namespace via `/host-rootfs`.
* **Full syscall translation** — path canonicalization, `openat`-style
  resolution through `/proc/<pid>/fd`, ABI-aware 32/64-bit syscall
  handling, ELF parsing with interpreter/loader manipulation and
  shebang interpretation.
* **Compatibility extensions** — fake root identity (`-0`, `-i`),
  hard-link emulation (`--link2symlink`), helper-file hiding (`-H`),
  kernel-release spoofing (`-k`), protected-port remapping (`-p`),
  symlink-size fixups (`-L`), System V IPC emulation (`--sysvipc`),
  and a mountinfo rewriter.
* **Seccomp acceleration** — kernel-side syscall filtering reduces
  ptrace round-trips where supported.
* **ptrace instrumentation engine** — extensions subscribe to typed
  events (path translation, syscall enter/exit, inheritance, signals)
  through a single modular dispatcher.

## Why a rewrite?

The C reference implementation is battle-tested but carries decades of
manual memory management, global state, and unchecked pointers. This
rewrite keeps **behavioral parity** (validated against the C test
suite — 113 checks green) while gaining Rust's guarantees:

* All `libc`/kernel-boundary `unsafe` is isolated in one auditable
  module ([`src/sys.rs`](src/sys.rs)); no `static mut`, no `transmute`,
  no scattered FFI calls.
* Modular design — path translation, syscall dispatch, extensions, ELF
  loading, and tracee memory access are independent modules behind
  typed interfaces.
* Modern toolchain — edition 2024, rustfmt + clippy + cargo-deny
  enforced in CI, `unsafe_op_in_unsafe_fn` denied crate-wide.

## Quick start

```console
$ cargo build --release          # produces target/release/proot
$ ./target/release/proot --version
BoxKernel 5.1.0

# Run a command inside a guest rootfs
$ ./target/release/proot -r ~/alpine-rootfs /bin/sh

# Bind a host file into the guest view
$ ./target/release/proot -b /etc/hostname /bin/cat /etc/hostname

# Fake root for package managers
$ ./target/release/proot -0 -r ~/alpine-rootfs /sbin/apk add gcc

# Foreign architecture via QEMU user-mode
$ ./target/release/proot -R ~/armhf-rootfs -q qemu-arm /bin/bash
```

The installed binary is named `proot` for drop-in compatibility with
existing scripts (e.g. `proot-distro`).

## Documentation

| Document | Contents |
|---|---|
| [User guide](docs/src/usage.md) | Recipes: chroot, binds, `-R`/`-S`, fake root |
| [Command-line reference](docs/src/options.md) | Every option, argument, and side effect |
| [Architecture](docs/src/architecture.md) | How the ptrace engine, translation pipeline, and modules fit together |
| [Extensions](docs/src/extensions.md) | What each built-in extension does and how to write one |
| [Mixed mode & QEMU](docs/src/mixed-mode.md) | Foreign-architecture and host/guest mixed execution |
| [Security model](docs/src/security.md) | What BoxKernel does *not* protect you from |
| [Development](docs/src/development.md) | Toolchain, lint/test commands, unsafe policy, parity rules |
| [Testing](docs/src/testing.md) | Unit tests and the C-reference integration suite |
| `man proot` ([doc/proot.1](doc/proot.1)) | The manual page |

The rendered book is published to GitHub Pages by the
[docs workflow](.github/workflows/docs.yml).

## Building

Requirements: Linux or Android on x86_64 or aarch64, Rust **1.85+** (pinned by
[`rust-toolchain.toml`](rust-toolchain.toml)), and a C toolchain is
*not* needed — the only crate dependency is `libc`.

```console
$ cargo build --release
$ cargo test                    # unit tests
$ cargo fmt --check && cargo clippy --all-targets -- -D warnings
$ cargo deny check              # license/advisory audit
```

See [Development](docs/src/development.md) for the full workflow,
including running the upstream C integration suite against the Rust
binary.

## Caveats

* **Not a security boundary.** PRoot confuses programs; it does not
  confine them. A guest program can modify or delete every host file
  the invoking user could. Never use it to isolate untrusted code —
  see [SECURITY.md](SECURITY.md).
* Syscall tracing has a performance cost — small for I/O-bound loads,
  noticeable for syscall-heavy ones (mitigated by seccomp).
* Programs relying on real `chroot(2)`, setuid, or unemulatable kernel
  facilities will misbehave.

## License

GPL-2.0-or-later, matching the upstream PRoot license. See
[LICENSE](LICENSE).

PRoot was written by Cédric Vincent at STMicroelectronics and is
maintained by the Termux contributors. BoxKernel is a clean-room Rust
re-implementation maintained by BoxOSLab.
