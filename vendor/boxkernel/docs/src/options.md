# Command-line reference

The command line is two parts: `proot` options, then the command to
launch (`/bin/sh` when none is given). This page documents the options
compiled into the Rust binary — it mirrors `proot --help` and
`man proot` ([`doc/proot.1`](https://github.com/BoxOSLab/BoxKernel/blob/main/doc/proot.1)).

## Filesystem view

### `-r path`, `--rootfs=path`

Use *path* as the new guest root filesystem (default `/`).

The path typically contains a Linux distribution. With the default `/`,
the bind mechanism alone relocates host files — see `-b`. Prefer `-R`
or `-S` for real rootfs work.

### `-b path`, `--bind=path` · `-m path`, `--mount=path`

Make *path* accessible inside the guest rootfs. Forms:

- `-b /host/dir` — bound at the same guest path
- `-b /host/dir:/guest/loc` — bound at an explicit guest location
- `-b /host/dir:/guest/loc!` — `!` suppresses dereferencing of a guest
  symlink target

Multiple `-b` options compose; later binds can shadow earlier ones.

### `-q command`, `--qemu=command`

Execute guest programs through the QEMU user-mode command *command*
(it may contain arguments, e.g. `-q "qemu-arm -g 1234"`).

Each guest `execve` is wrapped with the QEMU command; host programs
still run natively, and the whole host rootfs appears at
`/host-rootfs` inside the guest — see
[Mixed mode & QEMU](mixed-mode.md). The runner itself is resolved on
the **host** filesystem via the host `PATH`, so `-q qemu-aarch64`
works even when no QEMU exists inside the rootfs.

### `-w path`, `--pwd=path`, `--cwd=path`

Set the tracee's initial working directory (guest path). Equivalent to
`cd` before the command runs; `PWD` is updated accordingly.

### `-R path`

Alias: `-r path` plus a recommended bind list:

`/etc/host.conf`, `/etc/hosts`, `/etc/hosts.equiv`, `/etc/mtab`,
`/etc/netgroup`, `/etc/networks`, `/etc/passwd`, `/etc/group`,
`/etc/nsswitch.conf`, `/etc/resolv.conf`, `/etc/localtime`, `/dev/`,
`/sys/`, `/proc/`, `/tmp/`, `/run/`,
`/var/run/dbus/system_bus_socket`, `$HOME`, and *path* itself.

### `-S path`

Alias: `-0 -r path` plus a *minimal* protected bind list safe for
package installation:

`/etc/host.conf`, `/etc/hosts`, `/etc/nsswitch.conf`,
`/etc/resolv.conf`, `/dev/`, `/sys/`, `/proc/`, `/tmp/`, `/run/shm`,
`$HOME`, and *path* itself.

## Identity & compat extensions

### `-0`, `--root-id`

Make the current user appear as `root` and fake its privileges:
identity syscalls report uid/gid 0; `chown`, `chmod`, `mknod`,
`faccessat`, `capset`-adjacent checks report success. Persisted changes
are recorded in `.proot-meta-file.*` helpers. Weaker than `fakeroot` —
it only fakes *reports*.

### `-i string`, `--change-id=string`

Like `-0` but with an explicit `uid:gid` — `-0` is `-i 0:0`.

### `-l`, `--link2symlink`

Emulate `link(2)` with symlinks (`.proot.l2s.*` files) for filesystems
that forbid hard links (SELinux-confined storage, FAT, some FUSE).

### `-H`

Hide every `.proot*` helper file from `getdents` listings so guests
never see metadata created by `-0`/`-i`/`-l`.

### `-k string`, `--kernel-release=string`

Make `uname` report *string* as the kernel release and enable the
kompat extension's emulation of newer-kernel syscalls missing from the
host (e.g. running a glibc that wants a newer kernel).

### `-p`

Remap privileged ports: `bind`/`connect` to localhost ports < 1024 are
shifted by +1024 (Android/paranoid-networking kernels).

### `-L`

Correct `lstat` sizes/inodes for links emulated by `-l`
(Bionic reports misleading symlink sizes).

### `--sysvipc`

Handle System V IPC (`shm*`, `sem*`, `msg*`) inside the tracer. Each
`proot` instance is an independent IPC namespace; a detached helper
process (`proot --shm-helper`) backs shared memory with real fds.

## Process control & diagnostics

### `--kill-on-exit`

Kill all tracee processes when the main command exits. Without it,
`proot` waits for orphaned/detached tracees to finish.

### `-v value`, `--verbose=value`

Debug verbosity to stderr (also `PROOT_VERBOSE`). `-1` quiet, `0`
errors only, `1` milestones, higher values dump syscall-level detail
(9 is firehose).

### `-V`, `--version`, `--about`

Print version, license, and contact, then exit.

### `-h`, `--help`, `--usage`

Print version and usage, then exit.

## Exit status

Non-zero on internal `proot` errors; otherwise the exit status of the
last terminated program. To tell them apart, look at the error
message or run with `-v`.

## Files

- `/proc/<pid>/fd/` links are read to support `openat`-family syscalls.
- `-l` stores emulated hard links as `.l2s.*`/`.proot.l2s.*` symlinks.
- `-0`/`-i` record fake ownership/modes in `.proot-meta-file.*`.
- `-H` hides all `.proot*` helpers from directory listings.

## Options present in C PRoot but not ported

`--ashmem-memfd` (Android-Bionic-only `memfd_create` emulation via
ashmem) is not implemented; see
[Compatibility](compatibility.md#known-differences).
