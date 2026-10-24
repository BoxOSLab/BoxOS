//! Temporary files/dirs + placeholder cleanup — port of path/temp.c.
//! `talloc` destructors are replaced by a global registry of paths to remove
//! on exit (registered via `at_exit` style cleanup in the caller) — here they
//! are collected in a process-wide list the CLI calls `cleanup()` on.

use std::cell::RefCell;
use std::sync::Mutex;

use crate::fpath::FixedPath;

static PLACEHOLDERS: Mutex<Vec<std::path::PathBuf>> = Mutex::new(Vec::new());
static TEMP_PATHS: Mutex<Vec<std::path::PathBuf>> = Mutex::new(Vec::new());

/// `get_temp_directory()` — PROOT_TMP_DIR or /tmp, canonicalized.
pub fn get_temp_directory() -> String {
    thread_local! {
        static CACHED: RefCell<Option<String>> = const { RefCell::new(None) };
    }
    CACHED.with(|c| {
        if let Some(d) = c.borrow().as_ref() {
            return d.clone();
        }
        let dir = std::env::var("PROOT_TMP_DIR").unwrap_or_else(|_| "/tmp".to_string());
        let canon = std::fs::canonicalize(&dir)
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| {
                crate::note!(
                    crate::note::Severity::Warning,
                    crate::note::Origin::System,
                    "can't canonicalize {}",
                    dir
                );
                dir
            });
        *c.borrow_mut() = Some(canon.clone());
        canon
    })
}

fn random_suffix() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(0);
    nanos ^ (std::process::id() as u64) << 32 ^ rand_simple()
}

fn rand_simple() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEED: AtomicU64 = AtomicU64::new(0x9e3779b97f4a7c15);
    let x = SEED.fetch_add(0x9e3779b97f4a7c15, Ordering::Relaxed);
    let mut z = x.wrapping_add(std::process::id() as u64);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
    z ^ (z >> 31)
}

/// `create_temp_name()` — "/tmp/@prefix-$PID-XXXXXX".
pub fn create_temp_name(prefix: &str) -> Option<String> {
    Some(format!(
        "{}/{}-{}-{:06x}",
        get_temp_directory(),
        prefix,
        std::process::id(),
        random_suffix() & 0xffffff
    ))
}

/// `create_temp_directory()`.
pub fn create_temp_directory(_context: Option<&str>, prefix: &str) -> Option<String> {
    let name = create_temp_name(prefix)?;
    match std::fs::create_dir(&name) {
        Ok(()) => {
            TEMP_PATHS
                .lock()
                .unwrap()
                .push(std::path::PathBuf::from(&name));
            Some(name)
        }
        Err(_) => {
            crate::note!(
                crate::note::Severity::Error,
                crate::note::Origin::System,
                "can't create temporary directory"
            );
            crate::note!(
                crate::note::Severity::Info,
                crate::note::Origin::User,
                "Please set PROOT_TMP_DIR env. variable to an alternate location (with write permission)."
            );
            None
        }
    }
}

/// `create_temp_file()`.
pub fn create_temp_file(prefix: &str) -> Option<String> {
    let name = create_temp_name(prefix)?;
    match std::fs::File::create(&name) {
        Ok(_) => {
            TEMP_PATHS
                .lock()
                .unwrap()
                .push(std::path::PathBuf::from(&name));
            Some(name)
        }
        Err(_) => {
            crate::note!(
                crate::note::Severity::Error,
                crate::note::Origin::System,
                "can't create temporary file"
            );
            crate::note!(
                crate::note::Severity::Info,
                crate::note::Origin::User,
                "Please set PROOT_TMP_DIR env. variable to an alternate location (with write permission)."
            );
            None
        }
    }
}

/// `open_temp_file()` — returns a writable File + its path.
pub fn open_temp_file(prefix: &str) -> Option<(std::fs::File, String)> {
    let name = create_temp_name(prefix)?;
    match std::fs::File::create(&name) {
        Ok(f) => {
            TEMP_PATHS
                .lock()
                .unwrap()
                .push(std::path::PathBuf::from(&name));
            Some((f, name))
        }
        Err(_) => {
            crate::note!(
                crate::note::Severity::Error,
                crate::note::Origin::System,
                "can't create temporary file"
            );
            None
        }
    }
}

/// `set_placeholder_destructor()` — remove the path (if still an empty file
/// or dir) at exit.
pub fn set_placeholder_destructor(path: &FixedPath) {
    PLACEHOLDERS.lock().unwrap().push(std::path::PathBuf::from(
        String::from_utf8_lossy(path.as_bytes()).into_owned(),
    ));
}

/// `remove_placeholder` destructor.
fn remove_placeholder(path: &std::path::Path) {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(_) => return,
    };
    if !meta.is_dir() {
        if meta.len() != 0 {
            return;
        }
        let _ = std::fs::remove_file(path);
    } else {
        let _ = std::fs::remove_dir(path);
    }
}

/// Remove every registered temp path and placeholder; call at exit.
/// Reverse order matches talloc_autofree (children destroy newest-first),
/// so `dont/create` is removed before `dont`.
pub fn cleanup() {
    for p in PLACEHOLDERS.lock().unwrap().iter().rev() {
        remove_placeholder(p);
    }
    for p in TEMP_PATHS
        .lock()
        .unwrap()
        .drain(..)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
    {
        let meta = std::fs::symlink_metadata(&p);
        match meta {
            Ok(m) if m.is_dir() => {
                let _ = std::fs::remove_dir_all(&p);
            }
            Ok(_) => {
                let _ = std::fs::remove_file(&p);
            }
            Err(_) => {}
        }
    }
    for p in PLACEHOLDERS.lock().unwrap().drain(..) {
        remove_placeholder(&p);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;

    #[test]
    fn temp_names_are_unique_and_prefixed() {
        let a = create_temp_name("pfx").unwrap();
        let b = create_temp_name("pfx").unwrap();
        assert_ne!(a, b);
        let base = std::path::Path::new(&a)
            .file_name()
            .unwrap()
            .to_str()
            .unwrap();
        assert!(base.starts_with("pfx-"));
        assert!(a.starts_with(&get_temp_directory()));
    }

    /// TEMP_PATHS/PLACEHOLDERS are process-global — cleanup() touches
    /// every registered path, so all cleanup-dependent assertions live in
    /// this one test to avoid racing sibling tests.
    #[test]
    fn cleanup_lifecycle() {
        // Creation basics.
        let d0 = create_temp_directory(None, "ptd").unwrap();
        assert!(std::path::Path::new(&d0).is_dir());
        let f0 = create_temp_file("ptf").unwrap();
        assert!(std::path::Path::new(&f0).is_file());

        // Writable temp file.
        let (mut f, name) = open_temp_file("ptw").unwrap();
        use std::io::Write;
        f.write_all(b"hi").unwrap();
        drop(f);
        assert_eq!(std::fs::read(&name).unwrap(), b"hi");
        std::fs::remove_file(&name).unwrap();

        // Registered temp dir+file are removed by cleanup().
        let d = create_temp_directory(None, "ptcd").unwrap();
        let tf = create_temp_file("ptcf").unwrap();
        cleanup();
        assert!(!std::path::Path::new(&d).exists());
        assert!(!std::path::Path::new(&tf).exists());
        let td = TempDir::new("phold");
        // Empty file placeholder → removed by cleanup.
        let root = String::from_utf8(td.abs(".")).unwrap();
        let empty = std::path::PathBuf::from(format!("{root}/empty"));
        std::fs::write(&empty, b"").unwrap();
        let e = FixedPath::from_bytes(empty.to_str().unwrap().as_bytes());
        set_placeholder_destructor(&e);
        cleanup();
        assert!(!empty.exists());
        // Non-empty file placeholder → kept.
        let full = std::path::PathBuf::from(format!("{root}/full"));
        std::fs::write(&full, b"data").unwrap();
        let fp = FixedPath::from_bytes(full.to_str().unwrap().as_bytes());
        set_placeholder_destructor(&fp);
        cleanup();
        assert!(full.exists());
    }

    #[test]
    fn get_temp_directory_honors_env() {
        let _g = crate::testutil::env_lock();
        // Point PROOT_TMP_DIR at a persistent dir — other tests' temp
        // creations must keep working if they land inside it.
        let v = format!("/tmp/proot-envtest-{}", std::process::id());
        let _ = std::fs::create_dir(&v);
        unsafe { std::env::set_var("PROOT_TMP_DIR", &v) };
        // thread-local cache may already hold a value; force fresh thread.
        let h = std::thread::spawn(get_temp_directory).join().unwrap();
        assert_eq!(h, v);
        unsafe { std::env::remove_var("PROOT_TMP_DIR") };
        let _ = std::fs::remove_dir(&v);
    }
}
