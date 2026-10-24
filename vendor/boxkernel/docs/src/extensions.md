# Extension framework

Extensions are BoxKernel's mechanism for *policy on top of
translation*. Everything the C code did with
`(callback, config, filtered_sysnums)` triples becomes a typed
`Event` + `AnyExtension` dispatch in `src/extension/mod.rs`.

## The interface

```rust
pub enum Event<'a> {
    GuestPath   { base: &'a mut FixedPath, path: &'a [u8] },
    HostPath    { path: &'a mut FixedPath, is_final: bool },
    SymlinkDeref{ link: &'a FixedPath, referree: &'a mut FixedPath },
    TranslatedPath { path: &'a mut FixedPath },
    SysEnterStart, SysEnterEnd   { status: i32 },
    SysExitStart,  SysExitEnd    { status: i32 },
    NewStatus     { status: i32 },
    InheritParent { child_pid: i32, clone_flags: Word },
    InheritChild  { clone_flags: Word },
    ChainedEnter, ChainedExit,
    Initialization { arg: &'a str },
    Removed, PrintConfig, PrintUsage { detailed: bool },
    SigsysOcc,
    Link2SymlinkRename{..}, Link2SymlinkUnlink{..},
    StatxSyscall{..}, ReadlinkProcFd{..}, ExecveProcExe{..},
}
```

One dispatch method per extension:

```rust
impl AnyExtension {
    pub fn notify(&mut self, tracee: &mut Tracee, event: Event) -> i32;
    pub fn clone_for_child(&self, clone_flags: Word) -> AnyExtension;
}
```

Return value convention follows C: `< 0` aborts the operation,
`0` continues, `> 0` requests the *child-side* inherit callback.

## Inheritance model

`fork`/`clone` stops call `inherit_extensions`, which for each
extension runs `InheritParent` then `InheritChild`:

- `0` from `InheritParent` → **shared config** (e.g. `Kompat` uses one
  `Rc<RefCell<Config>>` for all tracees — a child's
  `setdomainname` is visible to siblings, matching C)
- `> 0` → per-child cloned config (`FakeId0` deep-clones)
- `< 0` → not inherited

## Built-in extensions

| Extension | CLI | What it does |
|---|---|---|
| `FakeId0` | `-0`, `-i u:g` | Fakes uid/gid/`cap` answers; intercepts `chown`, `chmod`, `mknod`, `setxid`, `faccessat`, `statx`; persists metadata in `.proot-meta-file.*`; emulates `chroot` success |
| `Link2Symlink` | `-l` | `link(2)` → creates `.l2s.*`/`.proot.l2s.*` symlinks; fakes `st_nlink`; handles rename/unlink of emulated links (largest extension — boxed in the enum) |
| `HiddenFiles` | `-H` | Filters `.proot*` helper names out of `getdents` results |
| `Kompat` | `-k` | Rewrites `uname`/`setdomainname`-adjacent state; emulates missing newer-kernel syscalls; config is *shared* across tracees |
| `PortSwitch` | `-p` | `bind`/`connect` to localhost ports < 1024 get +1024 |
| `FixSymlinkSize` | `-L` | Corrects `st_size`/`st_ino`/`nlink` for emulated links (Bionic) |
| `Mountinfo` | always on | Rewrites `/proc/self/mountinfo` reads so bindings look like real mounts |
| `Sysvipc` | `--sysvipc` | `shmget/shmat/shmdt/shmctl`, `sem*`, `msg*` implemented in-tracer; `--shm-helper` daemon holds backing fds |

## Writing an extension

1. Create `src/extension/my_ext.rs` with a struct holding per-tracee
   (or shared) state.
2. Add a variant to `AnyExtension` and implement `notify` — pattern-
   match the `Event`s you need, ignore the rest.
3. Implement `clone_for_child` deciding shared vs per-child state.
4. Wire CLI: parse an option in `cli/mod.rs` and call
   `extension::initialize_extension(tracee, AnyExtension::MyExt(..), arg)`.
5. For syscall filtering, use the `StatxSyscall`/`SigsysOcc`-style
   events or the `filtered_sysnums` dispatch in the translator.

The event set is deliberately a superset of what any single extension
uses — the C code has the same shape (one `extension.c` handler
switching on an `ExtensionEvent` enum).

## Debugging extensions

- `-v 2`+ prints extension callbacks; `PrintConfig`/`PrintUsage`
  events feed `--help`/diagnostics.
- `PROOT_FORCE_KOMPAT`, `PROOT_DONT_POLLUTE_ROOTFS`,
  `PROOT_NO_MOUNTINFO` toggle specific extensions for testing.
