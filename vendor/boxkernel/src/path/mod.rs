//! Path virtualization: canonicalization, bindings, /proc emulation, glue,
//! temp files — port of src/path/*.

pub mod binding;
pub mod canon;
pub mod f2fs;
pub mod glue;
pub mod proc_emul;
pub mod temp;

use crate::PATH_MAX;
use crate::fpath::{FixedPath, PathGuard};

/// Result of `compare_paths()` (path.h `Comparison`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Comparison {
    PathsAreEqual,
    Path1IsPrefix,
    Path2IsPrefix,
    PathsAreNotComparable,
}

/// Which side of a binding a lookup walks (`Side` in binding.h).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Side {
    Pending,
    Guest,
    Host,
}

/// Final-component semantics of the canonicalizer.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Finality {
    NotFinal,
    Normal,
    Slash,
    Dot,
}

impl Finality {
    #[inline]
    pub fn is_final(self) -> bool {
        !matches!(self, Finality::NotFinal)
    }
}

/// `compare_paths()` on byte strings.
pub fn compare_paths(path1: &[u8], path2: &[u8]) -> Comparison {
    let mut length1 = path1.len();
    let mut length2 = path2.len();
    if length1 == 0 || length2 == 0 {
        return Comparison::PathsAreNotComparable;
    }
    if path1[length1 - 1] == b'/' {
        length1 -= 1;
    }
    if path2[length2 - 1] == b'/' {
        length2 -= 1;
    }
    // C reads the byte right after the shortest path — its NUL terminator
    // when lengths are equal.
    let (length_min, sentinel) = if length1 < length2 {
        (length1, path2[length1])
    } else {
        (length2, path1.get(length2).copied().unwrap_or(0))
    };
    if sentinel != b'/' && sentinel != 0 {
        return Comparison::PathsAreNotComparable;
    }
    if path1[..length_min] != path2[..length_min] {
        return Comparison::PathsAreNotComparable;
    }
    match length1.cmp(&length2) {
        std::cmp::Ordering::Equal => Comparison::PathsAreEqual,
        std::cmp::Ordering::Less => Comparison::Path1IsPrefix,
        std::cmp::Ordering::Greater => Comparison::Path2IsPrefix,
    }
}

/// `join_paths()` for two paths into `result`.
pub fn join_paths2(result: &mut FixedPath, p1: &[u8], p2: &[u8]) -> Result<(), i32> {
    result.set(b"");
    result.push_component(p1)?;
    result.push_component(p2)
}

/// `readlink(/proc/<pid>/fd/<fd>)`.
pub fn readlink_proc_pid_fd(pid: i32, fd: i32, path: &mut FixedPath) -> Result<(), i32> {
    let link = format!("/proc/{}/fd/{}", pid, fd);
    let c = match std::ffi::CString::new(link.as_bytes()) {
        Ok(c) => c,
        Err(_) => return Err(-libc::EBADF),
    };
    // PATH_MAX-1 keeps room for the terminator.
    let n = crate::sys::readlink(&c, &mut path.as_mut_bytes()[..PATH_MAX - 1]);
    if n < 0 {
        return Err(-libc::EBADF);
    }
    path.set_len_terminated(n as usize);
    Ok(())
}

/// `getcwd2()` — the tracee's virtual cwd (guest path) or host getcwd when
/// `tracee` is None.
pub fn getcwd2(
    tracee: Option<&crate::tracee::Tracee>,
    guest_path: &mut FixedPath,
) -> Result<(), i32> {
    match tracee {
        None => {
            let n = crate::sys::getcwd_into(guest_path.as_mut_bytes())
                .ok_or_else(|| -crate::sys::errno())?;
            guest_path.set_len_terminated(n);
            Ok(())
        }
        Some(t) => {
            let fs = t.fs.borrow();
            if fs.cwd.len() >= PATH_MAX {
                return Err(-libc::ENAMETOOLONG);
            }
            guest_path.set(fs.cwd.as_bytes());
            Ok(())
        }
    }
}

/// `realpath2()` — canonicalize `path` (in the tracee namespace when set).
pub fn realpath2(
    tracee: Option<&mut crate::tracee::Tracee>,
    host_path: &mut FixedPath,
    path: &[u8],
    deref_final: bool,
) -> Result<(), i32> {
    match tracee {
        None => {
            let c = std::ffi::CString::new(path).map_err(|_| -libc::EINVAL)?;
            if crate::sys::realpath(&c, host_path) {
                Ok(())
            } else {
                Err(-crate::sys::errno())
            }
        }
        Some(t) => crate::path::translate_path(t, host_path, libc::AT_FDCWD, path, deref_final),
    }
}

/// `belongs_to_guestfs()` — whether the translated host path lives inside the
/// guest rootfs (i.e. under the root binding, not a guest binding).
pub fn belongs_to_guestfs(tracee: &crate::tracee::Tracee, host_path: &[u8]) -> bool {
    binding::with_root(tracee, |root| {
        let c = compare_paths(root.as_bytes(), host_path);
        c == Comparison::PathsAreEqual || c == Comparison::Path1IsPrefix
    })
}

/// `which()` — resolve `command` using $PATH; within the tracee's namespace
/// when `tracee` is set, the host namespace otherwise (C NULL case).
pub fn which(
    mut tracee: Option<&mut crate::tracee::Tracee>,
    paths: Option<&str>,
    host_path: &mut FixedPath,
    command: &[u8],
) -> Result<(), i32> {
    let is_explicit = command.contains(&b'/');

    let mut found = false;
    if realpath2(tracee.as_deref_mut(), host_path, command, true).is_ok() {
        let c = std::ffi::CString::new(host_path.as_bytes()).unwrap();
        if let Ok(st) = crate::sys::stat(&c) {
            if is_explicit && (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
                crate::note!(
                    crate::note::Severity::Error,
                    crate::note::Origin::User,
                    "'{}' is not a regular file",
                    String::from_utf8_lossy(command)
                );
                return Err(-libc::EACCES);
            }
            if is_explicit && (st.st_mode & libc::S_IXUSR) == 0 {
                crate::note!(
                    crate::note::Severity::Error,
                    crate::note::Origin::User,
                    "'{}' is not executable",
                    String::from_utf8_lossy(command)
                );
                return Err(-libc::EACCES);
            }
            found = true;
            let _ = realpath2(tracee.as_deref_mut(), host_path, command, false);
        }
    }

    if is_explicit {
        if found {
            return Ok(());
        }
        return not_found(tracee, paths, command, found);
    }

    let paths_owned: String;
    let paths = match paths {
        Some(p) => p,
        None => match std::env::var("PATH") {
            Ok(p) => {
                paths_owned = p;
                &paths_owned
            }
            Err(_) => "",
        },
    };
    if paths.is_empty() {
        return not_found(tracee, Some(paths), command, found);
    }

    for dir in paths.split(':') {
        let dir = if dir.is_empty() { "." } else { dir };
        if dir.len() >= PATH_MAX || dir.len() + command.len() + 2 >= PATH_MAX {
            continue;
        }
        let mut cand = FixedPath::new();
        cand.set(dir.as_bytes());
        let _ = cand.push_component(command);
        if realpath2(tracee.as_deref_mut(), host_path, cand.as_bytes(), true).is_ok() {
            let c = std::ffi::CString::new(host_path.as_bytes()).unwrap();
            if let Ok(st) = crate::sys::stat(&c)
                && (st.st_mode & libc::S_IFMT) == libc::S_IFREG
                && (st.st_mode & libc::S_IXUSR) != 0
            {
                let _ = realpath2(tracee.as_deref_mut(), host_path, cand.as_bytes(), false);
                return Ok(());
            }
        }
    }
    not_found(tracee, Some(paths), command, found)
}

fn not_found(
    tracee: Option<&mut crate::tracee::Tracee>,
    paths: Option<&str>,
    command: &[u8],
    found: bool,
) -> Result<(), i32> {
    let mut cwd = FixedPath::new();
    let cwd_str = match getcwd2(tracee.as_deref(), &mut cwd) {
        Ok(()) => cwd.to_string(),
        Err(_) => "<unknown>".to_string(),
    };
    let root = match tracee {
        Some(t) => binding::with_root(t, |r| r.to_string()),
        None => "/".to_string(),
    };
    crate::note!(
        crate::note::Severity::Error,
        crate::note::Origin::User,
        "'{}' not found (root = {}, cwd = {}, $PATH={:?})",
        String::from_utf8_lossy(command),
        root,
        cwd_str,
        paths.unwrap_or("")
    );
    if found {
        crate::note!(
            crate::note::Severity::Error,
            crate::note::Origin::User,
            "to execute a local program, use the './' prefix, for example: ./{}",
            String::from_utf8_lossy(command)
        );
    }
    Err(-1)
}

/// `translate_path()` — the full guest→host canonicalization entry point.
pub fn translate_path(
    tracee: &mut crate::tracee::Tracee,
    result: &mut FixedPath,
    dir_fd: i32,
    user_path: &[u8],
    deref_final: bool,
) -> Result<(), i32> {
    let mut guest_path = PathGuard::new();

    if user_path.first() == Some(&b'/') {
        result.set(b"/");
    } else if dir_fd != libc::AT_FDCWD {
        readlink_proc_pid_fd(tracee.pid, dir_fd, result)?;
        if result.as_bytes().first() != Some(&b'/') {
            return Err(-libc::ENOTDIR);
        }
        detranslate_path(tracee, result, None)?;
    } else {
        getcwd2(Some(tracee), result)?;
    }

    crate::verbose!(
        Some(tracee),
        2,
        "vpid {}: translate(\"{}\" + \"{}\")",
        tracee.vpid,
        result,
        String::from_utf8_lossy(user_path)
    );

    // Extensions may reroute through `guest_path` (seeded with the base).
    guest_path.set(result.as_bytes());
    let status = crate::extension::notify_guest_path(tracee, &mut guest_path, user_path);
    if status < 0 {
        return Err(status);
    }
    if status > 0 {
        result.set(guest_path.as_bytes());
        return finish_translate(tracee, result);
    }

    debug_assert!(result.as_bytes().first() == Some(&b'/'));
    join_paths2(&mut guest_path, result.as_bytes(), user_path)?;
    result.set(b"/");

    canon::canonicalize(tracee, guest_path.as_bytes(), deref_final, result, 0)?;

    binding::substitute_binding(tracee, Side::Guest, result)?;

    finish_translate(tracee, result)
}

fn finish_translate(tracee: &mut crate::tracee::Tracee, result: &mut FixedPath) -> Result<(), i32> {
    crate::verbose!(
        Some(tracee),
        2,
        "vpid {}:          -> \"{}\"",
        tracee.vpid,
        result
    );
    crate::extension::notify_translated_path(tracee, result)
}

/// `detranslate_path()` — strip the root prefix or substitute a binding for a
/// host path so it looks like a guest path again.  `t_referrer` is the
/// translated path of the symlink *referrer* (used to keep /proc and
/// same-binding symlink targets consistent).
pub fn detranslate_path(
    tracee: &mut crate::tracee::Tracee,
    path: &mut FixedPath,
    t_referrer: Option<&FixedPath>,
) -> Result<i32, i32> {
    if path.len() >= PATH_MAX - 1 {
        return Err(-libc::ENAMETOOLONG);
    }
    if path.as_bytes().first() != Some(&b'/') {
        return Ok(0);
    }

    let mut sanity_check = false;
    let mut follow_binding = false;

    if let Some(t_referrer) = t_referrer {
        match compare_paths(b"/proc", t_referrer.as_bytes()) {
            Comparison::Path1IsPrefix => {
                let mut proc_path = path.clone();
                let new_length = proc_emul::readlink_proc2(tracee, &mut proc_path, t_referrer)?;
                if new_length != 0 {
                    path.set(proc_path.as_bytes());
                    return Ok(new_length as i32 + 1);
                }
                follow_binding = true;
            }
            _ => {
                if !belongs_to_guestfs(tracee, t_referrer.as_bytes()) {
                    let referree = binding::get_path_binding(tracee, Side::Host, path.as_bytes());
                    let referrer =
                        binding::get_path_binding(tracee, Side::Host, t_referrer.as_bytes());
                    if let (Some(ree), Some(rer)) = (referree, referrer) {
                        follow_binding = compare_paths(
                            ree.path(Side::Host).as_bytes(),
                            rer.path(Side::Host).as_bytes(),
                        ) == Comparison::PathsAreEqual;
                    }
                }
            }
        }
    } else {
        sanity_check = true;
        follow_binding = true;
    }

    if follow_binding {
        match binding::substitute_binding(tracee, Side::Host, path) {
            Ok(0) => return Ok(0),
            Ok(1) => return Ok(path.len() as i32 + 1),
            _ => {}
        }
    }

    let (cmp, root_len) = binding::with_root(tracee, |root| {
        (compare_paths(root.as_bytes(), path.as_bytes()), root.len())
    });
    match cmp {
        Comparison::Path1IsPrefix => {
            let prefix_length = if root_len == 1 { 0 } else { root_len };
            path.strip_prefix(prefix_length);
            Ok(path.len() as i32 + 1)
        }
        Comparison::PathsAreEqual => {
            path.set(b"/");
            Ok(2)
        }
        _ => {
            if sanity_check {
                Err(-libc::EPERM)
            } else {
                Ok(0)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{TempDir, detranslate, test_tracee, translate};

    #[test]
    fn compare_paths_basic() {
        use Comparison::*;
        assert_eq!(compare_paths(b"/a/b", b"/a/b"), PathsAreEqual);
        assert_eq!(compare_paths(b"/a", b"/a/b"), Path1IsPrefix);
        assert_eq!(compare_paths(b"/a/b", b"/a"), Path2IsPrefix);
        assert_eq!(compare_paths(b"/a/b", b"/a/c"), PathsAreNotComparable);
        // A name boundary is required: "/fo" vs "/foo" is not a prefix.
        assert_eq!(compare_paths(b"/fo", b"/foo"), PathsAreNotComparable);
        // Trailing slashes are normalized.
        assert_eq!(compare_paths(b"/a/", b"/a"), PathsAreEqual);
        assert_eq!(compare_paths(b"/a", b"/a/b/"), Path1IsPrefix);
        // Empty strings are never comparable.
        assert_eq!(compare_paths(b"", b"/"), PathsAreNotComparable);
        assert_eq!(compare_paths(b"/", b""), PathsAreNotComparable);
        assert_eq!(compare_paths(b"", b""), PathsAreNotComparable);
    }

    #[test]
    fn compare_paths_root_and_edges() {
        use Comparison::*;
        // "/" is a prefix of every absolute path.
        assert_eq!(compare_paths(b"/", b"/a"), Path1IsPrefix);
        assert_eq!(compare_paths(b"/a", b"/"), Path2IsPrefix);
        assert_eq!(compare_paths(b"/", b"/"), PathsAreEqual);
        // Byte-sharp boundary: "/a" vs "/a\0junk" — the slice ends.
        assert_eq!(compare_paths(b"/a", b"/a/"), PathsAreEqual);
        // Similar prefixes differ mid-component.
        assert_eq!(compare_paths(b"/ab", b"/ac"), PathsAreNotComparable);
        assert_eq!(compare_paths(b"/a1", b"/a1b"), PathsAreNotComparable);
    }

    #[test]
    fn join_paths2_variants() {
        let mut p = FixedPath::new();
        join_paths2(&mut p, b"/a", b"b").unwrap();
        assert_eq!(p.as_bytes(), b"/a/b");
        let mut p = FixedPath::new();
        join_paths2(&mut p, b"", b"/abs").unwrap();
        assert_eq!(p.as_bytes(), b"/abs");
        // Second path is appended relative to the first.
        let mut p = FixedPath::new();
        join_paths2(&mut p, b"/a/b", b"c/d").unwrap();
        assert_eq!(p.as_bytes(), b"/a/b/c/d");
        // Slash handling between parts.
        let mut p = FixedPath::new();
        join_paths2(&mut p, b"/a/", b"/b").unwrap();
        assert_eq!(p.as_bytes(), b"/a/b");
        // Empty second part leaves a trailing slash.
        let mut p = FixedPath::new();
        join_paths2(&mut p, b"/a", b"").unwrap();
        assert_eq!(p.as_bytes(), b"/a/");
        // Overflow -> ENAMETOOLONG.
        let big = vec![b'x'; PATH_MAX - 10];
        let mut p = FixedPath::new();
        assert_eq!(
            join_paths2(&mut p, &big, b"01234567890123"),
            Err(-libc::ENAMETOOLONG)
        );
    }

    #[test]
    fn getcwd2_none_uses_process_cwd() {
        let mut p = FixedPath::new();
        getcwd2(None, &mut p).unwrap();
        let want = std::env::current_dir()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        assert_eq!(p.as_bytes(), want.as_bytes());
    }

    #[test]
    fn getcwd2_tracee_uses_fs_cwd() {
        let t = crate::tracee::Tracee::default();
        t.fs.borrow_mut().cwd.set(b"/some/where");
        let mut p = FixedPath::new();
        getcwd2(Some(&t), &mut p).unwrap();
        assert_eq!(p.as_bytes(), b"/some/where");
    }

    #[test]
    fn readlink_proc_pid_fd_reads_own_fds() {
        // fd 1 (stdout of the test process) resolves to something.
        let mut p = FixedPath::new();
        let status = readlink_proc_pid_fd(std::process::id() as i32, 1, &mut p);
        // Under `cargo test` stdout is a pipe; still readlink-able.
        assert!(
            status.is_ok() && !p.is_empty(),
            "fd1 readlink: {status:?} {p}"
        );
        // A bogus fd fails.
        let mut p = FixedPath::new();
        assert!(readlink_proc_pid_fd(std::process::id() as i32, -1, &mut p).is_err());
        assert!(readlink_proc_pid_fd(std::process::id() as i32, 9999, &mut p).is_err());
    }

    #[test]
    fn realpath2_none_matches_host() {
        let td = TempDir::new("rp");
        td.dir("sub");
        let mut out = FixedPath::new();
        realpath2(
            None,
            &mut out,
            td.path().join("sub").to_str().unwrap().as_bytes(),
            true,
        )
        .unwrap();
        assert_eq!(out.as_bytes(), td.abs("sub").as_slice());
        // Missing path -> Err.
        let mut out = FixedPath::new();
        assert!(realpath2(None, &mut out, b"/no/such/dir/here", true).is_err());
    }

    // ---------------------------------------------------------
    // translate_path / detranslate_path (full engine)
    // ---------------------------------------------------------

    #[test]
    fn translate_absolute_through_root() {
        let td = TempDir::new("xlat");
        td.dir("sub");
        td.file("sub/f", b"");
        let mut t = test_tracee(td.path().to_str().unwrap(), &[]);
        assert_eq!(translate(&mut t, "/sub/f"), td.abs("sub/f"));
        assert_eq!(translate(&mut t, "/"), td.abs("."));
        // Missing leaf still translates (canonicalize allows it).
        assert_eq!(
            translate(&mut t, "/sub/missing"),
            [td.abs("sub").as_slice(), b"/missing"].concat()
        );
    }

    #[test]
    fn translate_relative_uses_tracee_cwd() {
        let td = TempDir::new("xlat");
        td.dir("wd/sub");
        let mut t = test_tracee(td.path().to_str().unwrap(), &[]);
        t.fs.borrow_mut().cwd.set(b"/wd");
        assert_eq!(
            translate(&mut t, "sub/f"),
            [td.abs("wd").as_slice(), b"/sub/f"].concat()
        );
        assert_eq!(
            translate(&mut t, "./sub"),
            [td.abs("wd").as_slice(), b"/sub"].concat()
        );
        assert_eq!(translate(&mut t, "../"), td.abs("."));
    }

    #[test]
    fn translate_through_guest_binding() {
        let td = TempDir::new("xlat");
        let host = TempDir::new("xlath");
        host.dir("deep");
        let mut t = test_tracee(
            td.path().to_str().unwrap(),
            &[(host.path().to_str().unwrap(), "/mnt")],
        );
        assert_eq!(
            translate(&mut t, "/mnt/deep"),
            [host.abs(".").as_slice(), b"/deep"].concat()
        );
    }

    #[test]
    fn translate_deref_final_controls_symlink() {
        let td = TempDir::new("xlat");
        td.file("real", b"x");
        td.symlink("real", "lnk");
        let mut t = test_tracee(td.path().to_str().unwrap(), &[]);
        // deref=true: resolves to the target's host path.
        assert_eq!(translate(&mut t, "/lnk"), td.abs("real"));
        // deref=false: the link path translates literally (abs() would
        // resolve the symlink, so build the literal host path).
        let mut out = FixedPath::new();
        translate_path(&mut t, &mut out, libc::AT_FDCWD, b"/lnk", false).unwrap();
        let want = [td.abs(".").as_slice(), b"/lnk"].concat();
        assert_eq!(out.as_bytes(), want.as_slice());
    }

    #[test]
    fn detranslate_strips_root_prefix() {
        let td = TempDir::new("dxlat");
        let mut t = test_tracee(td.path().to_str().unwrap(), &[]);
        let host = [td.abs(".").as_slice(), b"/a/b"].concat();
        assert_eq!(detranslate(&mut t, &host), Ok(b"/a/b".to_vec()));
        // The root itself detranslates to "/".
        assert_eq!(detranslate(&mut t, &td.abs(".")), Ok(b"/".to_vec()));
        // Host paths outside the root fail the sanity check.
        assert_eq!(detranslate(&mut t, b"/etc"), Err(-libc::EPERM));
        // Relative input is untouched.
        assert_eq!(detranslate(&mut t, b"rel/path"), Ok(b"rel/path".to_vec()));
    }

    #[test]
    fn detranslate_through_binding() {
        let td = TempDir::new("dxlat");
        let host = TempDir::new("dxlath");
        let mut t = test_tracee(
            td.path().to_str().unwrap(),
            &[(host.path().to_str().unwrap(), "/vb")],
        );
        let host_path = [host.abs(".").as_slice(), b"/x"].concat();
        assert_eq!(detranslate(&mut t, &host_path), Ok(b"/vb/x".to_vec()));
    }

    #[test]
    fn detranslate_readlink_regression_same_binding() {
        // Regression: readlink() output is detranslated through the *same
        // binding as the referrer* (the bug that broke test-0228f5cf).
        let td = TempDir::new("dxlat");
        let host = TempDir::new("dxlath");
        host.file("t", b"x");
        host.symlink("t", "l");
        let mut t = test_tracee(
            td.path().to_str().unwrap(),
            &[(host.path().to_str().unwrap(), "/vb")],
        );
        // Referrer = translated path of /vb/l; referree = readlink result.
        let mut referrer =
            FixedPath::from_bytes([host.abs(".").as_slice(), b"/l"].concat().as_slice());
        let mut target =
            FixedPath::from_bytes([host.abs(".").as_slice(), b"/t"].concat().as_slice());
        let n = detranslate_path(&mut t, &mut target, Some(&referrer)).unwrap();
        assert!(n > 0);
        assert_eq!(target.as_bytes(), b"/vb/t");
        // Sanity: the same path with no referrer also maps through the binding.
        let mut target2 =
            FixedPath::from_bytes([host.abs(".").as_slice(), b"/t"].concat().as_slice());
        detranslate_path(&mut t, &mut target2, None).unwrap();
        assert_eq!(target2.as_bytes(), b"/vb/t");
        let _ = &mut referrer;
    }

    #[test]
    fn detranslate_proc_referrer() {
        // A readlink under /proc returns emulated results — exercise the
        // /proc branch with a fabricated tracee.
        let mut t = test_tracee("/", &[]);
        t.pid = std::process::id() as i32;
        t.exe = Some(std::rc::Rc::from("/guest/exe"));
        let referrer = FixedPath::from_bytes(b"/proc/self/exe");
        let mut target = FixedPath::from_bytes(b"/proc/self/exe");
        let n = detranslate_path(&mut t, &mut target, Some(&referrer)).unwrap();
        assert!(n > 0);
        assert_eq!(target.as_bytes(), b"/guest/exe");
    }

    #[test]
    fn belongs_to_guestfs_checks_root() {
        let td = TempDir::new("bel");
        let t = test_tracee(td.path().to_str().unwrap(), &[]);
        let inside = [td.abs(".").as_slice(), b"/x"].concat();
        assert!(belongs_to_guestfs(&t, &inside));
        assert!(!belongs_to_guestfs(&t, b"/etc"));
    }

    #[test]
    fn which_finds_on_host() {
        let td = TempDir::new("which");
        td.file_mode("tool", b"#!/bin/sh\n", 0o755);
        td.file_mode("notexec", b"x", 0o644);
        let mut out = FixedPath::new();
        let path_str = td.path().to_str().unwrap();
        assert!(which(None, Some(path_str), &mut out, b"tool").is_ok());
        assert_eq!(out.as_bytes(), td.abs("tool").as_slice());
        // Not executable -> not found.
        let mut out = FixedPath::new();
        assert!(which(None, Some(path_str), &mut out, b"notexec").is_err());
        // Missing -> not found.
        assert!(which(None, Some(path_str), &mut out, b"absent").is_err());
        // Explicit path (contains '/') resolves directly.
        let mut out = FixedPath::new();
        let tool = td.path().join("tool").to_string_lossy().into_owned();
        assert!(which(None, None, &mut out, tool.as_bytes()).is_ok());
        // Explicit non-regular file -> EACCES.
        let mut out = FixedPath::new();
        let dir = td.path().to_string_lossy().into_owned();
        assert!(which(None, None, &mut out, dir.as_bytes()).is_err());
    }

    #[test]
    fn which_searches_path_entries() {
        let td = TempDir::new("which");
        let d1 = td.dir("d1");
        let d2 = td.dir("d2");
        td.file_mode("d2/t", b"#!/bin/sh\n", 0o755);
        let paths = format!("{}:{}", d1.display(), d2.display());
        let mut out = FixedPath::new();
        assert!(which(None, Some(&paths), &mut out, b"t").is_ok());
        assert_eq!(out.as_bytes(), td.abs("d2/t").as_slice());
        // Empty PATH segments mean cwd; nothing named "." works — just
        // ensure it doesn't panic and fails cleanly.
        let mut out = FixedPath::new();
        assert!(which(None, Some(""), &mut out, b"t").is_err());
    }
}
