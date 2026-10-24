# Mixed mode & QEMU user-mode

## Foreign-architecture rootfs

When the guest rootfs targets a different CPU than the host, `-q`
wraps every guest `execve` with a QEMU user-mode command:

```console
$ proot -R ~/armhf-rootfs -q qemu-arm /bin/uname -m
armv7l
```

The option takes a whole command line, not just a binary:

```console
$ proot -R ~/armhf-rootfs -q "qemu-arm -g 1234" /usr/bin/gdbserver-less-app
```

## How the runner is found

The QEMU command is resolved **on the host** — against the host `PATH`
and host filesystem — even though the wrapped programs run in the
guest namespace. This matches the C implementation's
`reconf.tracee == NULL` behavior: the runner is a host binary by
definition, so resolving it inside the guest rootfs would find nothing
(or worse, a foreign-architecture QEMU).

Practical consequence: `-q qemu-aarch64` requires `qemu-aarch64` on
your *host* `PATH`, not inside the rootfs.

## Mixed execution

With `-q` active, host and guest programs interoperate:

- Every ELF `execve` is class-checked. A foreign binary is wrapped in
  the QEMU command; a *host* binary (e.g. under `/host-rootfs`) runs
  natively.
- The entire host rootfs is bound at `/host-rootfs` inside the guest.
- Host tools can be bound over guest paths to accelerate builds
  (cross-compilers, host `make`, host interpreters):

```console
$ proot -R ~/armhf-rootfs -q qemu-arm -b /usr/bin/make
$ make --version    # executes the *host* x86-64 make at native speed
```

- `LD_LIBRARY_PATH` and friends are managed separately per side: the
  execve/ldso emulation restores the *guest* value when a host program
  execs a foreign one and rewrites it when QEMU must find the guest
  `ld.so` — the `-E`/`‑U` argument pairs QEMU consumes are emitted in
  the same order C produces.

## `PROOT_USE_LOADER_FOR_QEMU`

Normally QEMU handles ELF loading itself. Setting
`PROOT_USE_LOADER_FOR_QEMU` routes the exec through the injected
loader stub instead — useful for QEMU builds without `-lm`-free
`binfmt` handling or when the ELF `PT_INTERP` must be rewritten *by
proot* before QEMU sees it.

## ELF and shebang pipeline

`execve` handling (see [Architecture](architecture.md#execve-the-hardest-syscall))
classifies the target first:

1. ELF header parse → native vs foreign ABI (`execve/elf.rs`)
2. `#!` shebang → recurse with the interpreter (`execve/shebang.rs`)
3. `PT_INTERP` → the dynamic linker is rewritten to a translated path
   or QEMU's `ld.so` path list (`execve/ldso.rs`)
4. auxv is rebuilt (`AT_PHDR`, `AT_BASE`, `AT_SYSINFO_EHDR`, …) so the
   guest sees a coherent address space (`execve/auxv.rs`)

`file`-style inspection shows the split clearly:

```console
$ file /bin/echo                 # guest: ARM
$ file /host-rootfs/bin/echo     # host:  x86-64
$ /host-rootfs/bin/echo mixed    # runs natively, sees guest view
```

## Performance notes

- QEMU adds its own per-syscall cost on top of ptrace interception;
  syscall-heavy guest programs are the slowest configuration.
- The seccomp accelerator (`src/syscall/seccomp.rs`) still applies —
  it filters *host* syscalls the wrapped programs issue, so mixed mode
  keeps most of its speedup.
- Prefer binding a host build tool (`-b /usr/bin/make`,
  `-b /usr/bin/cc`) over running the guest copy under QEMU whenever
  correctness allows it.
