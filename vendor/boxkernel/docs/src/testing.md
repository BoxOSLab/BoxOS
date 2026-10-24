# Testing

## Three layers

| Layer | What | Where | Command |
|---|---|---|---|
| Unit | Pure logic (path canonicalizer, `FixedPath`, `compare_paths`) | `#[cfg(test)]` in `src/` | `cargo test` |
| Smoke | Binary boots, binds, fakes root | CI `smoke test` step | `proot -0 id -u`, `proot -b …` |
| **Reference suite** | The C implementation's full integration suite run against the Rust binary | `proot/tests/` in the C checkout | `make -C tests` |

The third layer is the real contract — BoxKernel exists to be a
drop-in replacement, so the C suite *is* the specification.

## Running the reference suite

You need a checkout of the C reference next to this repo:

```console
$ git clone https://github.com/termux/proot.git ../proot
$ cargo build --release
$ cd ../proot/tests
$ make test PROOT=/abs/path/to/BoxKernel/target/release/proot
```

Expected result (x86-64 host):

- **113 tests `ok`**, **0 failed**
- 8 `skipped` — tests requiring QEMU/rootfs artifacts not present
- 9 `xfail`/`xpass` — upstream-expected anomalies, identical to C

A change is *done* only when this suite is green — the same suite the
C implementation passes.

## Unit tests

In-file `#[cfg(test)]` modules cover the pieces with real
specifications of their own:

- `fpath.rs` — `FixedPath` NUL semantics, `push`/`pop`/`chop`,
  `substitute_prefix` branches
- `path/canon.rs` — `compare_paths` (binding-prefix matching rules)

Add tests next to the code; keep them `safe` and fast. `cargo test`
runs in CI on every push/PR.

## Debugging a failing suite test

Each test is a shell or C program asserting a guest-visible behavior.
Workflow:

```console
$ cd ../proot/tests
$ ./test-0228fbe7.sh              # see the failure directly
$ PROOT=/path/to/proot ./test-0228fbe7.sh
$ PROOT_VERBOSE=9 …               # syscall-level trace if needed
```

Then bisect the pipeline: `tracee/event` stop → `syscall/enter`
translation → `path/canon` → write-back → `syscall/exit` post-
processing. The C source is the oracle for what each stage *should*
produce.

## Performance sanity

No formal benchmark yet. Quick sanity:

```console
$ time proot -r rootfs /bin/sh -c 'for i in $(seq 1000); do /bin/true; done'
$ time proot -r rootfs /bin/sh -c 'cat large_file >/dev/null'
```

I/O-bound work should be near-native; syscall storms show the ptrace
cost (seccomp helps where enabled).
