//! /proc readlink emulation — port of path/proc.c.

use crate::PATH_MAX;
use crate::fpath::FixedPath;
use crate::path::{Comparison, compare_paths};
use crate::tracee::Tracee;

/// `Action` from proc.c.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Default,
    Canonicalize,
    DontCanonicalize,
}

/// `readlink_proc()` — emulate readlink("base/component") where base is under
/// /proc.  Returns Err(-errno) on error, Ok(action) otherwise; on
/// Canonicalize `result` holds the substituted path (nul handling via
/// FixedPath).
pub fn readlink_proc(
    tracee: &Tracee,
    result: &mut FixedPath,
    base: &FixedPath,
    component: &[u8],
    comparison: Comparison,
) -> Result<Action, i32> {
    match comparison {
        Comparison::PathsAreEqual => {
            // Substitute "/proc/self" with "/proc/<PID>".
            if component != b"self" {
                return Ok(Action::Default);
            }
            result.set(format!("/proc/{}", tracee.pid).as_bytes());
            return Ok(Action::Canonicalize);
        }
        Comparison::Path1IsPrefix => {}
        _ => return Ok(Action::Default),
    }

    // Normalize /proc/self/... to /proc/<pid>/... so bound paths like
    // "-b /proc/self/fd:/dev/fd" reach the fd handling below.

    // `base` may be "/proc" itself (e.g. referer "/proc/self"); the C code
    // reads past the NUL there, which always yields an empty tail.
    let base_len = base.len();
    let tail = &base.as_bytes()[b"/proc/".len().min(base_len)..];
    let normalized: Vec<u8>;
    let base: &[u8] = if tail.starts_with(b"self") && (tail.len() == 4 || tail[4] == b'/') {
        normalized = format!(
            "/proc/{}{}",
            tracee.pid,
            String::from_utf8_lossy(&tail[4..])
        )
        .into_bytes();
        &normalized
    } else {
        base.as_bytes()
    };

    let pid: i32 = atoi(if tail.is_empty() {
        tail
    } else {
        &base[b"/proc/".len()..]
    });
    if pid == 0 {
        return Ok(Action::Default);
    }

    // Handle links in "/proc/<PID>/".
    let proc_path = format!("/proc/{}", pid);
    let comparison = compare_paths(proc_path.as_bytes(), base);
    match comparison {
        Comparison::PathsAreEqual => {
            // Snapshot the referenced tracee's fields.  When `pid` names the
            // current tracee its RefCell may already be mutably borrowed by
            // the caller — use `tracee` directly in that case.
            let (exe_bytes, cwd_bytes, root_bytes);
            if pid == tracee.pid {
                exe_bytes = tracee
                    .exe
                    .as_ref()
                    .map(|s| s.as_bytes().to_vec())
                    .unwrap_or_default();
                cwd_bytes = tracee.fs.borrow().cwd.as_bytes().to_vec();
                root_bytes = crate::path::binding::with_root(tracee, |r| r.as_bytes().to_vec());
            } else {
                let known = match crate::tracee::get_tracee(pid, false) {
                    Some(t) => t,
                    None => return Ok(Action::Default),
                };
                let known = known.borrow();
                exe_bytes = known
                    .exe
                    .as_ref()
                    .map(|s| s.as_bytes().to_vec())
                    .unwrap_or_default();
                cwd_bytes = known.fs.borrow().cwd.as_bytes().to_vec();
                root_bytes = crate::path::binding::with_root(&known, |r| r.as_bytes().to_vec());
            }

            macro_rules! substitute {
                ($name:expr_2021, $string:expr_2021) => {
                    if component == $name {
                        let s: &[u8] = $string;
                        if s.len() >= PATH_MAX {
                            return Err(-libc::EPERM);
                        }
                        result.set(s);
                        return Ok(Action::Canonicalize);
                    }
                };
            }

            substitute!(b"exe", &exe_bytes);
            substitute!(b"cwd", &cwd_bytes);
            substitute!(b"root", &root_bytes);
            return Ok(Action::Default);
        }
        Comparison::Path1IsPrefix => {}
        _ => return Ok(Action::Default),
    }

    // Handle links in "/proc/<PID>/fd/".
    let proc_path = format!("/proc/{}/fd", pid);
    if compare_paths(proc_path.as_bytes(), base) == Comparison::PathsAreEqual {
        // Sanity check: a number is expected.
        let s = std::str::from_utf8(component).unwrap_or("");
        if s.parse::<i64>().is_err() || s.is_empty() {
            return Err(-libc::EPERM);
        }
        // Don't dereference: they can point to anonymous pipes/sockets.
        result.set(base);
        result.push_component(component)?;
        return Ok(Action::DontCanonicalize);
    }

    Ok(Action::Default)
}

/// `readlink_proc2()` — emulate readlink on `referer` (a strict /proc
/// subpath).  Returns Ok(len) when emulated, Ok(0) otherwise.
pub fn readlink_proc2(
    tracee: &Tracee,
    result: &mut FixedPath,
    referer: &FixedPath,
) -> Result<usize, i32> {
    if referer.len() >= PATH_MAX {
        return Err(-libc::ENAMETOOLONG);
    }
    debug_assert!(compare_paths(b"/proc", referer.as_bytes()) == Comparison::Path1IsPrefix);

    let mut base = referer.clone();
    let pos = match base.as_bytes().iter().rposition(|&c| c == b'/') {
        Some(p) if p != 0 => p,
        _ => return Ok(0),
    };
    let component = base.as_bytes()[pos + 1..].to_vec();
    base.truncate(pos);
    if component.is_empty() {
        return Ok(0);
    }

    match readlink_proc(tracee, result, &base, &component, Comparison::Path1IsPrefix)? {
        Action::Canonicalize => Ok(result.len()),
        _ => Ok(0),
    }
}

/// atoi() semantics: parse leading decimal digits.
fn atoi(bytes: &[u8]) -> i32 {
    let mut v: i64 = 0;
    let mut neg = false;
    let mut i = 0;
    while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
        i += 1;
    }
    if i < bytes.len() && bytes[i] == b'-' {
        neg = true;
        i += 1;
    } else if i < bytes.len() && bytes[i] == b'+' {
        i += 1;
    }
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        v = v * 10 + (bytes[i] - b'0') as i64;
        i += 1;
    }
    if neg {
        v = -v;
    }
    v as i32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{TempDir, test_tracee};

    #[test]
    fn atoi_parses_c_style() {
        assert_eq!(atoi(b"123"), 123);
        assert_eq!(atoi(b"  42"), 42);
        assert_eq!(atoi(b"\t7x"), 7);
        assert_eq!(atoi(b"-15"), -15);
        assert_eq!(atoi(b"+9"), 9);
        assert_eq!(atoi(b""), 0);
        assert_eq!(atoi(b"abc"), 0);
        assert_eq!(atoi(b"12abc"), 12);
        assert_eq!(atoi(b"-"), 0);
    }

    fn tracee(pid: i32) -> Tracee {
        let mut t = test_tracee("/", &[]);
        t.pid = pid;
        t
    }

    #[test]
    fn proc_self_component_substitutes_pid() {
        let t = tracee(4242);
        let mut out = FixedPath::new();
        let a = readlink_proc(
            &t,
            &mut out,
            &FixedPath::from_bytes(b"/proc"),
            b"self",
            Comparison::PathsAreEqual,
        )
        .unwrap();
        assert_eq!(a, Action::Canonicalize);
        assert_eq!(out.as_bytes(), b"/proc/4242");
        // Any other component of /proc is uninteresting.
        let mut out = FixedPath::new();
        let a = readlink_proc(
            &t,
            &mut out,
            &FixedPath::from_bytes(b"/proc"),
            b"1",
            Comparison::PathsAreEqual,
        )
        .unwrap();
        assert_eq!(a, Action::Default);
        // Non-/proc bases are uninteresting.
        let mut out = FixedPath::new();
        let a = readlink_proc(
            &t,
            &mut out,
            &FixedPath::from_bytes(b"/etc"),
            b"self",
            Comparison::PathsAreNotComparable,
        )
        .unwrap();
        assert_eq!(a, Action::Default);
        assert_eq!(out.as_bytes(), b"");
    }

    #[test]
    fn proc_pid_links_substitute_tracee_fields() {
        let td = TempDir::new("proc");
        let mut t = test_tracee(td.path().to_str().unwrap(), &[]);
        t.pid = 7777;
        t.exe = Some(std::rc::Rc::from("/guest/exe"));
        t.fs.borrow_mut().cwd.set(b"/work/dir");
        let base = FixedPath::from_bytes(b"/proc/7777");

        let mut out = FixedPath::new();
        let a = readlink_proc(&t, &mut out, &base, b"exe", Comparison::Path1IsPrefix).unwrap();
        assert_eq!(a, Action::Canonicalize);
        assert_eq!(out.as_bytes(), b"/guest/exe");

        let mut out = FixedPath::new();
        readlink_proc(&t, &mut out, &base, b"cwd", Comparison::Path1IsPrefix).unwrap();
        assert_eq!(out.as_bytes(), b"/work/dir");

        // root yields the host path of the guest root binding.
        let mut out = FixedPath::new();
        readlink_proc(&t, &mut out, &base, b"root", Comparison::Path1IsPrefix).unwrap();
        assert_eq!(out.as_bytes(), td.abs(".").as_slice());

        // Unknown link name under /proc/<pid> is Default.
        let mut out = FixedPath::new();
        let a = readlink_proc(&t, &mut out, &base, b"maps", Comparison::Path1IsPrefix).unwrap();
        assert_eq!(a, Action::Default);
    }

    #[test]
    fn proc_pid_of_other_tracee_via_registry() {
        // get_tracee misses for unknown pids -> Default.
        let t = tracee(1);
        let base = FixedPath::from_bytes(b"/proc/999999");
        let mut out = FixedPath::new();
        let a = readlink_proc(&t, &mut out, &base, b"exe", Comparison::Path1IsPrefix).unwrap();
        assert_eq!(a, Action::Default);
    }

    #[test]
    fn proc_self_normalizes_then_resolves() {
        // "/proc/self/cwd" must behave like "/proc/<pid>/cwd".
        let mut t = test_tracee("/", &[]);
        t.pid = std::process::id() as i32;
        t.fs.borrow_mut().cwd.set(b"/selfy");
        let base = FixedPath::from_bytes(b"/proc/self");
        let mut out = FixedPath::new();
        let a = readlink_proc(&t, &mut out, &base, b"cwd", Comparison::Path1IsPrefix).unwrap();
        assert_eq!(a, Action::Canonicalize);
        assert_eq!(out.as_bytes(), b"/selfy");
    }

    #[test]
    fn proc_fd_entries_dont_canonicalize() {
        let t = tracee(1234);
        let base = FixedPath::from_bytes(b"/proc/1234/fd");
        let mut out = FixedPath::new();
        let a = readlink_proc(&t, &mut out, &base, b"3", Comparison::Path1IsPrefix).unwrap();
        assert_eq!(a, Action::DontCanonicalize);
        assert_eq!(out.as_bytes(), b"/proc/1234/fd/3");
        // Non-numeric fd is rejected.
        let mut out = FixedPath::new();
        assert_eq!(
            readlink_proc(&t, &mut out, &base, b"bogus", Comparison::Path1IsPrefix),
            Err(-libc::EPERM)
        );
        let mut out = FixedPath::new();
        assert_eq!(
            readlink_proc(&t, &mut out, &base, b"", Comparison::Path1IsPrefix),
            Err(-libc::EPERM)
        );
    }

    #[test]
    fn proc_bogus_pid_is_default() {
        let t = tracee(1);
        // "abc" doesn't parse to a pid.
        let mut out = FixedPath::new();
        let a = readlink_proc(
            &t,
            &mut out,
            &FixedPath::from_bytes(b"/proc/abc"),
            b"exe",
            Comparison::Path1IsPrefix,
        )
        .unwrap();
        assert_eq!(a, Action::Default);
        // pid 0 parsed but kernel would never have it.
        let mut out = FixedPath::new();
        let a = readlink_proc(
            &t,
            &mut out,
            &FixedPath::from_bytes(b"/proc/0"),
            b"exe",
            Comparison::Path1IsPrefix,
        )
        .unwrap();
        assert_eq!(a, Action::Default);
    }

    #[test]
    fn readlink_proc2_dispatches_on_referer() {
        let mut t = test_tracee("/", &[]);
        t.pid = 31337;
        t.exe = Some(std::rc::Rc::from("/real/exe"));
        let mut out = FixedPath::new();
        let n = readlink_proc2(&t, &mut out, &FixedPath::from_bytes(b"/proc/31337/exe")).unwrap();
        assert_eq!(n, "/real/exe".len());
        assert_eq!(out.as_bytes(), b"/real/exe");
        // cwd path: base "/proc/31337", component "cwd" (fs.cwd empty).
        let t2 = t;
        // (reuse t; fs.cwd is "/" from test_tracee)
        let mut out = FixedPath::new();
        readlink_proc2(&t2, &mut out, &FixedPath::from_bytes(b"/proc/31337/cwd")).unwrap();
        assert_eq!(out.as_bytes(), b"/");
        // Deep non-fd path -> 0.
        let mut out = FixedPath::new();
        assert_eq!(
            readlink_proc2(&t2, &mut out, &FixedPath::from_bytes(b"/proc/31337/task/9")).unwrap(),
            0
        );
        // Referer at the top level ("/proc/x") has no component below a
        // pid dir -> still emulates through the pid-link table.
        let mut out = FixedPath::new();
        assert_eq!(
            readlink_proc2(&t2, &mut out, &FixedPath::from_bytes(b"/proc/self")).unwrap(),
            0
        );
    }
}
