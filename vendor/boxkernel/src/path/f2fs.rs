//! f2fs case-sensitivity bug workaround — port of path/f2fs-bug.c.

use std::sync::atomic::{AtomicU8, Ordering};

use crate::tracee::Tracee;

// 0 = unprobed, 1 = not detected, 2 = detected.
static F2FS_STATE: AtomicU8 = AtomicU8::new(0);

fn probe_f2fs_bug(tracee: &Tracee) -> bool {
    crate::verbose!(Some(tracee), 6, "Checking for f2fs case sensitivity bug");
    let dir = match crate::path::temp::create_temp_directory(None, "proot_f2fsbug") {
        Some(d) => d,
        None => return false,
    };
    let file1 = format!("{}/aa", dir);
    let file2 = format!("{}/Aa", dir);
    let file3 = format!("{}/aA", dir);

    let mut result = false;
    'probe: {
        use std::os::unix::fs::OpenOptionsExt;
        if std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&file1)
            .is_err()
        {
            break 'probe;
        }
        if std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&file2)
            .is_err()
        {
            break 'probe;
        }
        if std::path::Path::new(&file3).exists() {
            break 'probe;
        }
        match crate::sys::fork() {
            0 => {
                let r = std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(false)
                    .mode(0o600)
                    .open(&file3);
                match r {
                    Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {
                        crate::sys::exit_immediately(1)
                    }
                    Err(_) => crate::sys::exit_immediately(2),
                    Ok(_) => crate::sys::exit_immediately(0),
                }
            }
            -1 => break 'probe,
            pid => {
                let wstatus = crate::sys::waitpid(pid, 0).map(|(_, s)| s).unwrap_or(0);
                if libc::WIFEXITED(wstatus) && libc::WEXITSTATUS(wstatus) == 1 {
                    crate::verbose!(Some(tracee), 1, "enabling f2fs bug workaround");
                    result = true;
                }
            }
        }
    }

    let _ = std::fs::remove_file(&file1);
    let _ = std::fs::remove_file(&file2);
    let _ = std::fs::remove_file(&file3);
    let _ = std::fs::remove_dir(&dir);
    result
}

/// `should_skip_file_access_due_to_f2fs_bug()`.
pub fn should_skip_file_access_due_to_f2fs_bug(tracee: &Tracee, path: &[u8]) -> bool {
    if F2FS_STATE.load(Ordering::Relaxed) == 0 {
        let detected = match std::env::var("PROOT_F2FS_WORKAROUND").as_deref() {
            Ok("1") => true,
            Ok("0") => false,
            _ => probe_f2fs_bug(tracee),
        };
        F2FS_STATE.store(if detected { 2 } else { 1 }, Ordering::Relaxed);
    }
    if F2FS_STATE.load(Ordering::Relaxed) != 2 {
        return false;
    }

    let path = match std::str::from_utf8(path) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let dname = match std::path::Path::new(path).parent() {
        Some(d) => d,
        None => return false,
    };
    let bname = match std::path::Path::new(path).file_name() {
        Some(b) => b,
        None => return false,
    };
    let entries = match std::fs::read_dir(dname) {
        Ok(e) => e,
        Err(_) => return false, // unlistable dir: don't skip
    };
    for entry in entries.flatten() {
        if entry.file_name() == bname {
            return false;
        }
    }
    crate::verbose!(
        Some(tracee),
        4,
        "f2fs bug workaround did not find file {}",
        path
    );
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{TempDir, env_lock, test_tracee};

    #[test]
    fn workaround_disabled_never_skips() {
        let _g = env_lock();
        unsafe { std::env::set_var("PROOT_F2FS_WORKAROUND", "0") };
        let t = test_tracee("/", &[]);
        let td = TempDir::new("f2fs");
        // Literal path (abs() canonicalizes; file must not exist).
        let mut missing = td.abs(".");
        missing.extend_from_slice(b"/nope");
        assert!(!should_skip_file_access_due_to_f2fs_bug(&t, &missing));
        unsafe { std::env::remove_var("PROOT_F2FS_WORKAROUND") };
    }
}
