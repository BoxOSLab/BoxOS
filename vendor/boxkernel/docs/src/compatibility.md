# Compatibility with C PRoot

BoxKernel targets **behavioral parity with Termux PRoot 5.1.0** — not
just feature parity, but identical observable behavior: same option
parsing, same errno paths, same exit statuses, same verbose output
shape.

## What's identical

- The entire CLI option set except `--ashmem-memfd` (below)
- Guest-visible results of translated syscalls — the reference suite
  validates this end-to-end
- Exit status convention (last terminated program's status)
- `-v` verbosity levels and `note!` severity model
- Extension semantics including inheritance (`Kompat` shared config,
  `FakeId0` per-child)
- QEMU `-q` contract: runner resolved on the **host**, `-E`/`-U` env
  pairs emitted in C's order, `/host-rootfs` binding
- `.proot-meta-file.*`/`.l2s.*` helper-file formats — a rootfs written
  by C proot reads correctly under BoxKernel and vice versa
- `ptrace`/`wait` emulation for guest debuggers

## Known differences

| Difference | Detail | Status |
|---|---|---|
| `--ashmem-memfd` | Android-only `memfd_create`-via-ashmem emulation; needs Bionic `libandroid-shmem` machinery | **not ported** |
| Internal structure | C's `(callback,config,sysnums)` triples → typed `Event`/`AnyExtension` | deliberate — same dispatch order |
| Global state | C `static` vars → atomics/`thread_local!` | deliberate — same semantics |
| Memory allocation | talloc hierarchy → owned values/`Rc`/`Box` | deliberate — C ownership graph preserved |
| Build system | GNU make + libtalloc | Cargo; `build.rs` runs `rustc` for `loader/` |
| Version string | `proot 5.1.0` | `BoxKernel 5.1.0` (binary still named `proot`) |

## Things the Rust port does *better* (and why)

- **No libtalloc** → fully static-able; the two QEMU-runner suite
  tests that fail on the C binary under `unset LD_LIBRARY_PATH`
  *pass* on ours.
- **No `static mut`, no `transmute`** → whole classes of memory bugs
  eliminated rather than audited-around.
- **Typed extension events** → the C `intptr_t data1/data2` payloads
  (whose meaning depended on event type) become structured enums —
  mismatched-payload bugs are compile errors now.
- **`src/sys.rs` boundary** → a C-identical errno contract is
  *enforced by type*, not by convention.

## Filing parity bugs

If the Rust binary produces *different guest-visible behavior* than
the C binary for the same command/environment, that's a parity bug —
report it with both outputs:

```console
$ proot-c -v 2 <cmd>   2>c.log
$ proot   -v 2 <cmd>   2>rust.log
$ diff -u c.log rust.log
```

Include the suite test name if a reference test exposes it.
