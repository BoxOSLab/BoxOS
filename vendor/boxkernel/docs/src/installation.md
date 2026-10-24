# Installation

## From source (the only supported method today)

BoxKernel is a single-crate Rust workspace with one dependency
(`libc`). There is nothing to configure and no system libraries to
install beyond Rust itself.

```console
$ git clone https://github.com/BoxOSLab/BoxKernel.git
$ cd BoxKernel
$ cargo build --release
$ ./target/release/proot --version
BoxKernel 5.1.0
```

Requirements:

- **Linux or Android, on x86_64 or aarch64.** BoxKernel instruments
  `ptrace(2)`, `seccomp`, `process_vm_readv/writev`, and
  `/proc/<pid>/fd`. It does not run on macOS or Windows. Each host
  architecture has its own register layout, syscall table, seccomp
  section and loader; 32-bit hosts are not supported.
- **Rust 1.85 or newer.** `rust-toolchain.toml` pins `stable` and pulls
  in `rustfmt` + `clippy` automatically. Edition 2024 is in use.
- Kernel: any reasonably modern Linux. `process_vm_*` (≥ 3.2) is
  preferred for tracee memory access; the `PTRACE_PEEK/POKE` fallback
  covers older kernels. Seccomp acceleration needs `seccomp` filtering
  support (≥ 3.5 realistically, with `SECCOMP_MODE_FILTER`).

## Installing the binary

```console
$ cargo install --path .          # installs `proot` into ~/.cargo/bin
# or
$ install -Dm755 target/release/proot ~/.local/bin/proot
```

The binary is deliberately named `proot` — it is a drop-in replacement
for the C implementation. If you already have C `proot` installed, pick
a different destination or rename (e.g. `proot-rs`).

## Installing the manual page

```console
$ install -Dm644 doc/proot.1 ~/.local/share/man/man1/proot.1
$ man proot
```

## Verifying the install

```console
$ proot -0 /usr/bin/id -u
0
$ proot -b /etc/hostname /bin/cat /etc/hostname
<your hostname>
$ proot -v 1 /bin/true          # verbose banner, one line
```

## Cross-compiling

The build script compiles the loader with the same `rustc` and the linker
Cargo resolved for the target, so a cross build only needs the usual
target setup:

```console
$ rustup target add aarch64-unknown-linux-gnu
$ CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
    cargo build --release --target aarch64-unknown-linux-gnu
```

If the loader can't be linked (no cross linker), the build still
succeeds with a warning and an empty embedded loader; such a binary only
works with `PROOT_LOADER` pointing at a loader built elsewhere.

## Android

Termux can build BoxKernel natively with its Rust package. To build it
for an app from a desktop, use the NDK through
[`cargo-ndk`](https://github.com/bbqsrc/cargo-ndk):

```console
$ rustup target add aarch64-linux-android x86_64-linux-android
$ cargo ndk -t arm64-v8a -t x86_64 -P 24 build --release
$ ls target/aarch64-linux-android/release/proot
$ ls target/aarch64-linux-android/release/build/boxkernel-*/out/loader.exe
```

Apps targeting Android 10 (API 29) or later cannot execute files from
their writable data directory, which is where BoxKernel extracts its
embedded loader by default. Ship the loader next to `proot` in the APK's
native library directory (for example as `libproot_loader.so`, with
`extractNativeLibs` enabled) and point `PROOT_LOADER` at it; set
`PROOT_TMP_DIR` to a writable directory such as the app's cache.

All Termux-specific options (`-0`, `-l`, `--sysvipc`, `-p`, `-L`,
`-H`, `--kill-on-exit`) are implemented except `--ashmem-memfd`, which
is Android-Bionic-specific and not yet ported — see
[Compatibility](compatibility.md).
