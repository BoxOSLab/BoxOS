# Usage and recipes

`proot` [*option*] … [*command*]

Options come first, then the command to launch (`/bin/sh` when none is
given). This chapter collects practical recipes; the per-option detail
lives in the [command-line reference](options.md).

## A `chroot` equivalent

Give `proot` a guest rootfs and a command:

```console
$ proot -r ~/alpine-rootfs /bin/cat /etc/os-release
NAME="Alpine Linux"
```

Omitting the command gives an interactive shell — the shortest way to
confine a shell and all its children:

```console
$ proot -r ~/alpine-rootfs
/ #
```

Programs inside are still ordinary host processes (same PID namespace,
same network); only their *view* of the filesystem is rewritten.

## `mount --bind` equivalent

`-b` (or `-m`) relocates a host path into the guest view:

```console
$ proot -b ~/alternate_hosts:/etc/hosts /bin/cat /etc/hosts
```

By default the guest side of a binding is dereferenced — binding over
`/bin/sh` actually lands on `/bin/dash` if `/bin/sh` is a symlink. Add
`!` to pin the bind to the link itself:

```console
$ proot -b /bin/bash:/bin/sh! /bin/sh -c 'echo $0'
/bin/sh     # but executing bash, as a file named /bin/sh
```

## `-R` and `-S`: recommended/protected binding sets

A bare guest rootfs cannot see `/etc/resolv.conf`, `/dev`, `/proc`, …

- `-R dir` ≈ `-r dir` plus a recommended set of binds (`/etc/host*`,
  `/etc/passwd`, `/etc/resolv.conf`, `/dev`, `/sys`, `/proc`, `/tmp`,
  `/run`, `$HOME`, and the rootfs itself).
- `-S dir` ≈ `-R` **plus `-0`** (fake root), with a *smaller* bind list
  chosen so package managers cannot scribble on host files. Use `-S`
  to install packages into a guest rootfs.

```console
$ proot -R ~/alpine-rootfs /bin/sh
$ proot -S ~/alpine-rootfs /sbin/apk add build-base
```

## Fake root: `-0` and `-i uid:gid`

```console
$ proot -0 /usr/bin/id
uid=0(root) gid=0(root) groups=0(root)
```

`-0` intercepts identity syscalls (`getuid`, `geteuid`, `getresuid`,
`setuid`-family, `chown`-family, `chmod`/`mknod`/`faccessat` checks) and
reports success. `-i 1000:1000` does the same with explicit ids.
Recorded ownership/mode changes persist in `.proot-meta-file.*` helper
files next to the affected files.

## Hiding helper files: `-H`

`-0`/`-i` and `-l` create `.proot-meta-file.*` and `.proot.l2s.*` files
inside the guest rootfs. `-H` filters them out of `getdents` results so
guest programs (and `*` expansions) never see them.

## Hard links that aren't: `--link2symlink`

Some filesystems (SELinux-confined app storage on Android, FAT,
some FUSE mounts) deny `link(2)`. `--link2symlink` records emulated
hard links as symlinks named `.proot.l2s.*` and reports them to guest
programs as real links.

## Protected ports: `-p`

Kernels with paranoid networking refuse `bind()` to ports < 1024 for
unprivileged users. `-p` remaps bind/connect calls to `port + 1024` on
localhost sockets — a guest binding `:80` actually binds `:1080`.

## Spoofing the kernel release: `-k string`

Old rootfs + new glibc occasionally hits `FATAL: kernel too old`, or a
program inspects `uname`. `-k 6.1.0` rewrites the release field and
emulates selected newer-kernel syscalls (`kompat` extension).

## Symlink sizes on Bionic: `-L`

Android's `lstat` reports misleading symlink sizes; combined with `-l`,
`-L` rewrites `st_size`/`st_ino`/link counts so emulated links look
plausible to `tar`, `ls -l`, etc.

## System V IPC: `--sysvipc`

`shmget`/`semget`/`msgget` families are emulated inside the tracer (a
detached `--shm-helper` process backs shared memory with real fds).
Each `proot` instance is its own IPC namespace — two proot sessions do
not share SysV objects.

## Debugging runs

- `-v N` (or `PROOT_VERBOSE=N`): `-1` silent-but-fatal, `0` errors,
  `1` key decisions, up to `9` full syscall tracing.
- `--kill-on-exit`: kill all tracees when the main command exits —
  without it, orphaned/detached processes keep `proot` alive waiting.
- `-w dir`: initial working directory inside the guest.

## Environment variables

| Variable | Effect |
|---|---|
| `PROOT_VERBOSE` | same as `-v` |
| `PROOT_TMP_DIR` / `TMPDIR` | directory for internal temp files (default `/tmp`) |
| `PROOT_NO_SECCOMP` | disable the seccomp accelerator (debugging) |
| `PROOT_ASSUME_NEW_SECCOMP` | assume kernel ≥ 4.8 seccomp semantics |
| `PROOT_NO_MOUNTINFO` | disable `/proc/self/mountinfo` rewriting |
| `PROOT_IGNORE_MISSING_BINDINGS` | don't fail if a `-b` source is missing |
| `PROOT_DONT_POLLUTE_ROOTFS` | store link2symlink meta-files outside the rootfs |
| `PROOT_LOADER` | override the injected execve loader stub |
| `PROOT_USE_LOADER_FOR_QEMU` | route QEMU execs through the loader stub |
| `PROOT_FORCE_FOREIGN_BINARY` | force foreign-ABI handling (testing) |
| `PROOT_FORCE_KOMPAT` | force-enable the kompat extension (testing) |
| `LD_*` | glibc loader variables are parsed and forwarded by the ldso emulation |

## Things that will surprise you once

- Bindings apply to the *guest* path — `-b /proc` means host `/proc`
  shows up at guest `/proc`.
- `execve` of a script re-enters translation for its shebang
  interpreter — `-b` applies there too.
- Files written into a bound directory land on the *host* path. There
  is no copy-on-write layer.
- `sudo`, `ping`, real `mount(2)`, `setuid` binaries: still bound by
  host privileges. `-0` only fakes *reports* of privilege.
