//! Test-only helpers shared by unit tests.
//!
//! - [`TempDir`]: RAII fixture directory (dirs/files/symlinks) under
//!   `PROOT_TMP_DIR`/`/tmp`, removed on drop.
//! - [`test_tracee`]: fabricate a `Tracee` (pid 0) with a cwd, a root
//!   binding and optional `-b` bindings — enough to drive the whole
//!   path engine (`translate_path`, `canonicalize`, `detranslate_path`,
//!   binding emulation) without a live process.
//! - [`Child`]: a `fork()`ed child parked in `pause()` sharing the
//!   address-space layout of the test binary, so `tracee::mem`
//!   (`process_vm_*` fast path and the ptrace fallback) runs against
//!   real remote memory.  Parent→child access is permitted at every
//!   `ptrace_scope` ≤ 1 and anywhere a ptrace attach is possible.
//! - [`Arena`]: a `MAP_SHARED` anonymous mapping — the same physical
//!   pages in parent and child, so the parent can verify remote writes
//!   by reading its own mapping.
//! - [`env_lock`]: serialize tests that mutate process env (setenv PWD,
//!   PROOT_* vars) since the runner is multi-threaded.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use crate::fpath::FixedPath;
use crate::path::binding;
use crate::tracee::Tracee;

// ------------------------------------------------------------------
// TempDir
// ------------------------------------------------------------------

static TEMP_COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// A temporary directory tree removed on drop.
pub struct TempDir {
    root: PathBuf,
}

impl TempDir {
    pub fn new(tag: &str) -> TempDir {
        let base = std::env::var("PROOT_TMP_DIR").unwrap_or_else(|_| "/tmp".into());
        for attempt in 0..100 {
            let n = TEMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let root = Path::new(&base).join(format!(
                "proot-test-{}-{}-{}{}",
                std::process::id(),
                n,
                tag,
                attempt
            ));
            match std::fs::create_dir(&root) {
                Ok(()) => return TempDir { root },
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => panic!("can't create test dir {}: {}", root.display(), e),
            }
        }
        panic!("can't create test dir after 100 attempts");
    }

    pub fn path(&self) -> &Path {
        &self.root
    }

    /// `mkdir -p` `rel` inside the fixture; returns the path.
    pub fn dir(&self, rel: &str) -> PathBuf {
        let p = self.root.join(rel);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    /// Create `rel` with `content`; returns the path.
    pub fn file(&self, rel: &str, content: &[u8]) -> PathBuf {
        let p = self.root.join(rel);
        if let Some(d) = p.parent() {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::write(&p, content).unwrap();
        p
    }

    /// `symlink(target → rel)`; `target` may be absolute or relative.
    pub fn symlink(&self, target: &str, rel: &str) -> PathBuf {
        let p = self.root.join(rel);
        if let Some(d) = p.parent() {
            std::fs::create_dir_all(d).unwrap();
        }
        std::os::unix::fs::symlink(target, &p).unwrap();
        p
    }

    /// Create `rel` chmod `mode`.
    pub fn file_mode(&self, rel: &str, content: &[u8], mode: u32) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let p = self.file(rel, content);
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        p
    }

    /// Absolute (canonicalized) path of `rel` as bytes — what the
    /// translator should produce for host-side paths.
    pub fn abs(&self, rel: &str) -> Vec<u8> {
        self.root
            .join(rel)
            .canonicalize()
            .unwrap()
            .to_string_lossy()
            .into_owned()
            .into_bytes()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

// ------------------------------------------------------------------
// Tracee fabrication
// ------------------------------------------------------------------

/// A `Tracee` with no process: cwd "/", a `root:/` root binding plus the
/// listed `host:guest` bindings, all canonicalized like `-r`/`-b` does.
/// `root` is typically `TempDir::path()` or "/".
pub fn test_tracee(root: &str, bindings: &[(&str, &str)]) -> Tracee {
    let mut t = Tracee::default();
    t.fs.borrow_mut().cwd.set(b"/");
    binding::new_binding(&mut t, root.as_bytes(), Some(b"/"), true).expect("root binding");
    for (host, guest) in bindings {
        binding::new_binding(&mut t, host.as_bytes(), Some(guest.as_bytes()), true)
            .unwrap_or_else(|| panic!("binding {}:{}", host, guest));
    }
    binding::initialize_bindings(&mut t);
    t
}

/// The host path `path` must translate to under `tracee`'s namespace.
pub fn translate(tracee: &mut Tracee, path: &str) -> Vec<u8> {
    let mut out = crate::fpath::FixedPath::new();
    crate::path::translate_path(tracee, &mut out, libc::AT_FDCWD, path.as_bytes(), true)
        .unwrap_or_else(|e| panic!("translate({}) -> {}", path, e));
    out.as_bytes().to_vec()
}

/// `detranslate_path` convenience: `host` → guest bytes.
pub fn detranslate(tracee: &mut Tracee, host: &[u8]) -> Result<Vec<u8>, i32> {
    let mut p = FixedPath::from_bytes(host);
    crate::path::detranslate_path(tracee, &mut p, None).map(|_| p.as_bytes().to_vec())
}

/// Point `tracee`'s stack pointer at the top of `arena` (in Current and
/// Original) so `alloc_mem` lands in writable remote memory.
pub fn use_arena_stack(tracee: &mut Tracee, arena: &Arena) {
    use crate::tracee::reg::{Reg, RegVersion};
    let top = arena.addr() + arena.len as u64;
    crate::tracee::reg::poke_reg(tracee, Reg::StackPointer, top);
    tracee.regs[RegVersion::Original.idx()] = tracee.regs[RegVersion::Current.idx()];
}

// ------------------------------------------------------------------
// Env serialization
// ------------------------------------------------------------------

static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Serialize tests that touch process env (`setenv`, `PROOT_*`) or other
/// process-global state.  Take the guard at the top of such a test.
pub fn env_lock() -> MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// Run `f` with `name` set to `value` (None unsets), restoring afterwards.
/// Caller must hold `env_lock()`.
pub fn with_env<V: AsRef<std::ffi::OsStr>>(name: &str, value: Option<V>, f: impl FnOnce()) {
    let key = std::ffi::OsString::from(name);
    let saved = std::env::var_os(&key);
    match &value {
        Some(v) => unsafe { std::env::set_var(&key, v) },
        None => unsafe { std::env::remove_var(&key) },
    }
    let restore = saved;
    struct RestoreGuard {
        key: std::ffi::OsString,
        saved: Option<std::ffi::OsString>,
    }
    impl Drop for RestoreGuard {
        fn drop(&mut self) {
            match &self.saved {
                Some(v) => unsafe { std::env::set_var(&self.key, v) },
                None => unsafe { std::env::remove_var(&self.key) },
            }
        }
    }
    let _g = RestoreGuard {
        key,
        saved: restore,
    };
    f();
}

// ------------------------------------------------------------------
// Forked child + shared arena (remote-memory tests)
// ------------------------------------------------------------------

/// An anonymous `MAP_SHARED` mapping: the same pages in parent and
/// forked child, address-identical after `fork()`.  `ptr` is the remote
/// (and local) address used in `mem` calls.
pub struct Arena {
    ptr: usize,
    pub len: usize,
}

impl Arena {
    /// `pages` pages of read/write shared memory, zero-filled.
    pub fn new(pages: usize) -> Arena {
        let len = pages * 4096;
        // SAFETY: anonymous mmap, no fd; pointer is valid for `len`.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(p, libc::MAP_FAILED, "arena mmap failed");
        Arena {
            ptr: p as usize,
            len,
        }
    }

    pub fn addr(&self) -> crate::Word {
        self.ptr as crate::Word
    }

    /// Parent-side view of the shared pages.
    #[allow(clippy::mut_from_ref)] // mmap region; exclusive per test thread
    pub fn local(&self) -> &mut [u8] {
        // SAFETY: mapping is live while `self` is.
        unsafe { std::slice::from_raw_parts_mut(self.ptr as *mut u8, self.len) }
    }
}

impl Drop for Arena {
    fn drop(&mut self) {
        // SAFETY: we own the mapping.
        unsafe {
            libc::munmap(self.ptr as *mut _, self.len);
        }
    }
}

/// A child parked in `pause()`.  `t` is a `Tracee` whose `pid` names it;
/// the child's address space is a fork snapshot of this test binary, so
/// `Arena` mappings (MAP_SHARED) and any `static` are at the same remote
/// addresses.
///
/// Command channel: write a byte to `cmd` to make the child act:
/// `b'0'..b'9'` = `mprotect(arena_page_n, PROT_NONE)`,
/// `b'a'..`     = `mprotect(arena_page_n, PROT_READ|PROT_WRITE)`.
pub struct Child {
    pub pid: i32,
    cmd: std::fs::File,
    arena_addr: crate::Word,
}

/// `None` when fork is unavailable.
pub fn fork_child(arena: &Arena) -> Option<Child> {
    let (r, w) = crate::sys::pipe_cloexec().ok()?;
    let pid = crate::sys::fork();
    match pid {
        -1 => None,
        0 => {
            // Child: only async-signal-safe-ish work — no allocation.
            let mut op = [0u8; 1];
            loop {
                // SAFETY: `op` is a valid stack buffer; blocking read.
                let n = unsafe { libc::read(r, op.as_mut_ptr() as *mut _, 1) };
                if n <= 0 {
                    unsafe { libc::_exit(0) };
                }
                let (page, prot) = match op[0] {
                    c @ b'0'..=b'9' => (c - b'0', libc::PROT_NONE),
                    c @ b'a'..=b'j' => (c - b'a', libc::PROT_READ | libc::PROT_WRITE),
                    _ => continue,
                };
                if page as usize * 4096 < arena.len {
                    // SAFETY: the arena mapping exists in the child too.
                    unsafe {
                        libc::mprotect((arena.ptr + page as usize * 4096) as *mut _, 4096, prot);
                    }
                }
            }
        }
        pid => {
            crate::sys::close(r);
            Some(Child {
                pid,
                cmd: unsafe { std::os::unix::io::FromRawFd::from_raw_fd(w) },
                arena_addr: arena.addr(),
            })
        }
    }
}

impl Child {
    /// A `Tracee` naming this child (registers are fabricated — `poke_reg`
    /// on the cache is all most paths need).
    pub fn tracee(&self) -> Tracee {
        Tracee {
            pid: self.pid,
            ..Tracee::default()
        }
    }

    /// Give the tracee a stack pointer inside `arena` so `alloc_mem`
    /// allocations land in writable remote memory.
    pub fn tracee_with_sp(&self, arena: &Arena) -> Tracee {
        let mut t = self.tracee();
        use_arena_stack(&mut t, arena);
        t
    }

    /// Make the child `mprotect` arena page `n` PROT_NONE.
    pub fn protect_page(&mut self, n: u8) {
        use std::io::Write;
        self.cmd.write_all(&[b'0' + n]).unwrap();
        // The child needs a moment; poll protection state via
        // process_vm_read which fails on PROT_NONE.
        let target = self.probe_addr(n);
        for _ in 0..1000 {
            let mut b = [0u8; 1];
            if crate::sys::process_vm_read(self.pid, &mut b, target) != 1 {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        panic!("child did not apply PROT_NONE");
    }

    /// Restore arena page `n` to read/write.
    pub fn unprotect_page(&mut self, n: u8) {
        use std::io::Write;
        self.cmd.write_all(&[b'a' + n]).unwrap();
        let target = self.probe_addr(n);
        for _ in 0..1000 {
            let mut b = [0u8; 1];
            if crate::sys::process_vm_read(self.pid, &mut b, target) == 1 {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        panic!("child did not restore page");
    }

    fn probe_addr(&self, n: u8) -> crate::Word {
        self.arena_addr + n as u64 * 4096 + 2048
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        crate::sys::kill(self.pid, libc::SIGKILL);
        let _ = crate::sys::waitpid(self.pid, 0);
    }
}
