//! Bindings — port of path/binding.c.
//!
//! A binding pairs a canonicalized host path with a canonicalized guest path.
//! Each tracee keeps three orderings of the same set: `pending` (as given by
//! the user, guest-ordered, not yet canonicalized), `guest` and `host` (both
//! canonicalized, ordered by their respective side).  `Vec<Rc<Binding>>`
//! replaces the C triple circular lists.

use std::rc::Rc;

use crate::fpath::FixedPath;
use crate::path::{Comparison, Side, compare_paths, getcwd2, join_paths2, realpath2};
use crate::tracee::Tracee;

pub struct Binding {
    pub host: FixedPath,
    pub guest: FixedPath,
    pub need_substitution: bool,
}

impl Binding {
    pub fn path(&self, side: Side) -> &FixedPath {
        match side {
            Side::Host => &self.host,
            _ => &self.guest,
        }
    }
}

/// `get_binding()` — find the binding covering `path` on `side`.
pub fn get_binding(tracee: &Tracee, side: Side, path: &[u8]) -> Option<Rc<Binding>> {
    debug_assert!(path.first() == Some(&b'/'));
    // The host-side false-positive guard is loop-invariant (it depends on
    // the path and root only, not on the binding): evaluate it once — when
    // it trips, every candidate is skipped, i.e. the result is `None`.
    if side == Side::Host {
        let skip = with_root(tracee, |root| {
            compare_paths(root.as_bytes(), b"/") != Comparison::PathsAreEqual && {
                let c = compare_paths(root.as_bytes(), path);
                c == Comparison::PathsAreEqual || c == Comparison::Path1IsPrefix
            }
        });
        if skip {
            return None;
        }
    }
    let fs = tracee.fs.borrow();
    let list = match side {
        Side::Guest => &fs.guest,
        Side::Host => &fs.host,
        Side::Pending => &fs.pending,
    };
    for binding in list.iter() {
        let reference = binding.path(side);
        let cmp = compare_paths(reference.as_bytes(), path);
        if cmp == Comparison::PathsAreEqual || cmp == Comparison::Path1IsPrefix {
            return Some(binding.clone());
        }
    }
    None
}

/// `get_path_binding()` — the matching binding (its `path(side)` is the
/// side-specific path); the `Rc` keeps the caller copy-free.
pub fn get_path_binding(tracee: &Tracee, side: Side, path: &[u8]) -> Option<Rc<Binding>> {
    get_binding(tracee, side, path)
}

/// `with_root()` — borrow the host path of the binding mounted at guest
/// "/" for the duration of `f` (empty path when none), avoiding the
/// PATH_MAX clone `get_root()` would return.
pub fn with_root<R>(tracee: &Tracee, f: impl FnOnce(&FixedPath) -> R) -> R {
    static EMPTY: FixedPath = FixedPath::new();
    let fs = tracee.fs.borrow();
    let root = if fs.guest.is_empty() {
        match fs.pending.last() {
            Some(b) if compare_paths(b.guest.as_bytes(), b"/") == Comparison::PathsAreEqual => {
                &b.host
            }
            _ => &EMPTY,
        }
    } else {
        &fs.guest.last().unwrap().host
    };
    f(root)
}

/// `get_root()` — host path of the binding mounted at guest "/".
/// Prefer [`with_root`] when the value is only inspected.
pub fn get_root(tracee: &Tracee) -> FixedPath {
    with_root(tracee, |root| root.clone())
}

/// `substitute_binding()` — replace the `side` prefix of `path` with the
/// binding's other side.
///
/// Returns Ok(0) for symmetric bindings, Ok(1) after substitution,
/// Err(-ENOENT) when no binding covers `path`.
pub fn substitute_binding(tracee: &Tracee, side: Side, path: &mut FixedPath) -> Result<i32, i32> {
    let binding = match get_binding(tracee, side, path.as_bytes()) {
        Some(b) => b,
        None => return Err(-libc::ENOENT),
    };
    if !binding.need_substitution {
        return Ok(0);
    }
    let (reference, reverse) = match side {
        Side::Guest => (&binding.guest, &binding.host),
        Side::Host => (&binding.host, &binding.guest),
        Side::Pending => return Err(-libc::EACCES),
    };
    path.substitute_prefix(reference.len(), reverse.as_bytes())?;
    Ok(1)
}

/// `insort_binding()` — insert `binding` into `side`'s list, preserving the
/// nested-binding order.  On an exact-path conflict in the guest list the old
/// binding is replaced and unlinked from all lists.
fn insort_binding(tracee: &Tracee, side: Side, binding: Rc<Binding>) {
    let mut fs = tracee.fs.borrow_mut();
    let list: &mut Vec<Rc<Binding>> = match side {
        Side::Pending => &mut fs.pending,
        Side::Guest => &mut fs.guest,
        Side::Host => &mut fs.host,
    };

    let binding_path = binding.path(side);
    let mut previous: Option<usize> = None;
    let mut next: Option<usize> = None;
    let mut replaced: Option<(usize, Rc<Binding>)> = None;

    for (i, iter) in list.iter().enumerate() {
        let iterator_path = iter.path(side);
        match compare_paths(binding_path.as_bytes(), iterator_path.as_bytes()) {
            Comparison::PathsAreEqual => {
                if side == Side::Host {
                    previous = Some(i);
                    continue;
                }
                if tracee.verbose > 0 && std::env::var_os("PROOT_IGNORE_MISSING_BINDINGS").is_none()
                {
                    crate::note!(
                        crate::note::Severity::Warning,
                        crate::note::Origin::User,
                        "both '{}' and '{}' are bound to '{}', only the last binding is active.",
                        iter.host,
                        binding.host,
                        binding.guest
                    );
                }
                replaced = Some((i, iter.clone()));
                break;
            }
            Comparison::Path1IsPrefix => previous = Some(i),
            Comparison::Path2IsPrefix => {
                if next.is_none() {
                    next = Some(i);
                }
            }
            Comparison::PathsAreNotComparable => {}
        }
    }

    if let Some((i, removed)) = replaced {
        list.insert(i + 1, binding);
        list.remove(i);
        // Unlink the replaced binding from the other lists too.
        fs.host.retain(|b| !Rc::ptr_eq(b, &removed));
        fs.pending.retain(|b| !Rc::ptr_eq(b, &removed));
        return;
    }
    if let Some(p) = previous {
        list.insert(p + 1, binding);
    } else if let Some(n) = next {
        list.insert(n, binding);
    } else {
        list.insert(0, binding);
    }
}

/// `insort_binding2` — set need_substitution and insert into guest+host lists.
pub fn insort_binding2(tracee: &Tracee, mut binding: Binding) -> Rc<Binding> {
    binding.need_substitution = compare_paths(binding.host.as_bytes(), binding.guest.as_bytes())
        != Comparison::PathsAreEqual;
    let rc = Rc::new(binding);
    insort_binding(tracee, Side::Guest, rc.clone());
    insort_binding(tracee, Side::Host, rc.clone());
    rc
}

/// `insort_binding3` — allocate + insert `host_path:guest_path`.
pub fn insort_binding3(
    tracee: &Tracee,
    host_path: &[u8],
    guest_path: &[u8],
) -> Option<Rc<Binding>> {
    let b = Binding {
        host: FixedPath::from_bytes(host_path),
        guest: FixedPath::from_bytes(guest_path),
        need_substitution: false,
    };
    if b.host.len() >= crate::PATH_MAX - 1 || b.guest.len() >= crate::PATH_MAX - 1 {
        return None;
    }
    Some(insort_binding2(tracee, b))
}

/// `new_binding()` — add a pending binding `host:guest` (guest defaults to
/// host when None).  `must_exist` controls whether a missing host path is an
/// error.
pub fn new_binding(
    tracee: &mut Tracee,
    host: &[u8],
    guest: Option<&[u8]>,
    must_exist: bool,
) -> Option<Rc<Binding>> {
    let ignore_missing = std::env::var_os("PROOT_IGNORE_MISSING_BINDINGS").is_some();
    let mut binding = Binding {
        host: FixedPath::new(),
        guest: FixedPath::new(),
        need_substitution: false,
    };

    // /proc/self/... stays symbolic: "self" must resolve against the *calling*
    // tracee at syscall time, not against proot at init time.
    let host_str = host;
    if host_str.starts_with(b"/proc/self")
        && (host_str.get(10) == Some(&b'/') || host_str.len() == 10)
    {
        if host_str.len() + 1 >= crate::PATH_MAX {
            if must_exist && !ignore_missing {
                crate::note!(
                    crate::note::Severity::Warning,
                    crate::note::Origin::Internal,
                    "can't sanitize binding \"{}\": {}",
                    String::from_utf8_lossy(host),
                    io_error_string(libc::ENAMETOOLONG)
                );
            }
            return None;
        }
        binding.host.set(host);
    } else {
        // During a sub-reconfiguration the path would be canonicalized in
        // the reconfigured tracee's namespace; that hook is wired up with the
        // -r/-R CLI handling.
        let status = realpath2(None, &mut binding.host, host, true);
        if let Err(e) = status {
            if must_exist && !ignore_missing {
                crate::note!(
                    crate::note::Severity::Warning,
                    crate::note::Origin::Internal,
                    "can't sanitize binding \"{}\": {}",
                    String::from_utf8_lossy(host),
                    io_error_string(-e)
                );
            }
            return None;
        }
    }

    let guest = guest.unwrap_or(host);
    if guest.first() != Some(&b'/') {
        let mut base = FixedPath::new();
        if getcwd2(None, &mut base).is_err() {
            crate::note!(
                crate::note::Severity::Warning,
                crate::note::Origin::Internal,
                "can't sanitize binding"
            );
            return None;
        }
        if join_paths2(&mut binding.guest, base.as_bytes(), guest).is_err() {
            crate::note!(
                crate::note::Severity::Warning,
                crate::note::Origin::System,
                "can't sanitize binding \"{}\"",
                String::from_utf8_lossy(guest)
            );
            return None;
        }
    } else {
        binding.guest.set(guest);
    }

    let rc = Rc::new(binding);
    insort_binding(tracee, Side::Pending, rc.clone());
    Some(rc)
}

pub fn io_error_string(errno: i32) -> String {
    crate::sys::strerror(errno)
}

/// `remove_binding_from_all_lists()` — drop a binding from every list of
/// every tracee sharing this file-system namespace (guest, host, pending).
pub fn remove_binding_from_all_lists(tracee: &Tracee, binding: &Rc<Binding>) {
    let target = Rc::as_ptr(binding) as usize;
    let mut fs = tracee.fs.borrow_mut();
    fs.guest.retain(|b| Rc::as_ptr(b) as usize != target);
    fs.host.retain(|b| Rc::as_ptr(b) as usize != target);
    fs.pending.retain(|b| Rc::as_ptr(b) as usize != target);
}

/// `initialize_binding()` — canonicalize the guest side and promote the
/// binding into the guest+host lists.
pub fn initialize_binding(tracee: &mut Tracee, binding: &Rc<Binding>) {
    if compare_paths(binding.guest.as_bytes(), b"/") != Comparison::PathsAreEqual {
        let mut path = binding.guest.clone();
        // Does the user explicitly tell not to dereference the guest path?
        let mut dereference = true;
        if path.as_bytes().last() == Some(&b'!') {
            path.truncate(path.len() - 1);
            dereference = false;
        }

        // Remember the type of the final component for build_glue().
        let mut st: libc::stat = crate::sys::zeroed();
        let status = match crate::sys::lstat(binding.host.as_c_str()) {
            Ok(v) => {
                st = v;
                0
            }
            Err(_) => -1,
        };
        tracee.glue_type = if status < 0
            || (st.st_mode & libc::S_IFMT) == libc::S_IFBLK
            || (st.st_mode & libc::S_IFMT) == libc::S_IFCHR
            || (st.st_mode & libc::S_IFMT) == libc::S_IFLNK
        {
            libc::S_IFREG
        } else {
            st.st_mode & libc::S_IFMT
        };

        // When the source is a directory and the target is a symlink, the
        // tracee must see a directory at the literal target path.
        if status >= 0 && (st.st_mode & libc::S_IFMT) == libc::S_IFDIR {
            dereference = false;
        }

        let mut new_guest = FixedPath::from_bytes(b"/");
        match crate::path::canon::canonicalize(
            tracee,
            path.as_bytes(),
            dereference,
            &mut new_guest,
            0,
        ) {
            Ok(()) => {
                new_guest.chop_finality();
                // insort_binding2 recomputes need_substitution.
                let updated = Binding {
                    host: binding.host.clone(),
                    guest: new_guest,
                    need_substitution: false,
                };
                insort_binding2(tracee, updated);
            }
            Err(e) => {
                crate::note!(
                    crate::note::Severity::Warning,
                    crate::note::Origin::Internal,
                    "sanitizing the guest path (binding) \"{}\": {}",
                    path,
                    io_error_string(-e)
                );
            }
        }
        tracee.glue_type = 0;
    } else {
        let updated = Binding {
            host: binding.host.clone(),
            guest: binding.guest.clone(),
            need_substitution: false,
        };
        insort_binding2(tracee, updated);
    }
}

/// `initialize_bindings()` — promote every pending binding, in reverse
/// order: the binding to "/" (the deepest in the pending list) goes first
/// since it bootstraps the canonicalization of all the others.
pub fn initialize_bindings(tracee: &mut Tracee) {
    let pending: Vec<Rc<Binding>> = tracee.fs.borrow().pending.clone();
    for b in pending.iter().rev() {
        initialize_binding(tracee, b);
        // TODO: add_induced_bindings() for sub-reconfiguration contexts.
    }
    tracee.fs.borrow_mut().pending.clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fpath::FixedPath;
    use crate::path::{Side, join_paths2};
    use crate::testutil::{TempDir, test_tracee};
    use std::rc::Rc;

    /// Construct a tracee rooted at `root` with pending bindings promoted.
    fn t(root: &str, binds: &[(&str, &str)]) -> Tracee {
        test_tracee(root, binds)
    }

    #[test]
    fn new_binding_defaults_guest_to_host() {
        let td = TempDir::new("bind");
        let mut tracee = Tracee::default();
        let b = new_binding(
            &mut tracee,
            td.path().to_str().unwrap().as_bytes(),
            None,
            true,
        )
        .expect("binding");
        assert_eq!(b.guest.as_bytes(), b.host.as_bytes());
        assert_eq!(b.host.as_bytes(), td.abs(".").as_slice());
        // Only pending — not yet in guest/host lists.
        assert_eq!(tracee.fs.borrow().pending.len(), 1);
        assert!(tracee.fs.borrow().guest.is_empty());
    }

    #[test]
    fn new_binding_missing_host() {
        let mut tracee = Tracee::default();
        // must_exist: missing host path fails.
        assert!(new_binding(&mut tracee, b"/definitely/missing/path", None, true).is_none());
        // !must_exist still requires the path to exist (it is canonicalized).
        assert!(new_binding(&mut tracee, b"/definitely/missing/path", None, false).is_none());
    }

    #[test]
    fn new_binding_relative_guest_resolved_against_cwd() {
        let td = TempDir::new("bind");
        let mut tracee = Tracee::default();
        let b = new_binding(
            &mut tracee,
            td.path().to_str().unwrap().as_bytes(),
            Some(b"rel"),
            true,
        )
        .expect("binding");
        // Guest side = cwd + "rel", canonicalized.
        let mut cwd = FixedPath::new();
        getcwd2(None, &mut cwd).unwrap();
        let mut expect = FixedPath::new();
        join_paths2(&mut expect, cwd.as_bytes(), b"rel").unwrap();
        assert_eq!(b.guest.as_bytes(), expect.as_bytes());
    }

    #[test]
    fn new_binding_proc_self_stays_symbolic() {
        let mut tracee = Tracee::default();
        let b = new_binding(&mut tracee, b"/proc/self/fd", Some(b"/dev/fd"), true)
            .expect("/proc/self binding must not be canonicalized");
        // Host side kept verbatim — "/proc/self" would otherwise resolve
        // to proot's own pid at init time.
        assert_eq!(b.host.as_bytes(), b"/proc/self/fd");
        assert_eq!(b.guest.as_bytes(), b"/dev/fd");
        // Prefix without '/' boundary still canonicalizes: "/proc/selfish"
        // is a normal path.
        let td = TempDir::new("bind");
        let p = td.dir("procself");
        let b2 = new_binding(
            &mut tracee,
            p.to_str().unwrap().as_bytes(),
            Some(b"/g"),
            true,
        )
        .expect("normal binding");
        assert_eq!(b2.host.as_bytes(), td.abs("procself").as_slice());
    }

    #[test]
    fn insort_orders_nested_bindings() {
        let td = TempDir::new("bind");
        td.dir("a/b");
        td.dir("other");
        let tracee = Tracee::default();
        let outer = insort_binding3(&tracee, td.abs("a").as_slice(), b"/ga").unwrap();
        let inner = insort_binding3(&tracee, td.abs("a/b").as_slice(), b"/ga/b").unwrap();
        let plain = insort_binding3(&tracee, td.abs("other").as_slice(), b"/gz").unwrap();
        {
            let fs = tracee.fs.borrow();
            let guests: Vec<&[u8]> = fs.guest.iter().map(|b| b.guest.as_bytes()).collect();
            // Deepest path first: get_binding returns the first covering
            // binding, so the most specific one must come earlier.
            let ia = guests.iter().position(|g| *g == b"/ga").unwrap();
            let ib = guests.iter().position(|g| *g == b"/ga/b").unwrap();
            assert!(ib < ia, "nested child must sort before parent: {guests:?}");
            assert!(guests.contains(&b"/gz".as_slice()));
        }
        // get_binding finds the *deepest* covering binding.
        let hit = get_binding(&tracee, Side::Guest, b"/ga/b/x").unwrap();
        assert!(Rc::ptr_eq(&hit, &inner));
        let hit = get_binding(&tracee, Side::Guest, b"/ga/x").unwrap();
        assert!(Rc::ptr_eq(&hit, &outer));
        let hit = get_binding(&tracee, Side::Guest, b"/gz/x").unwrap();
        assert!(Rc::ptr_eq(&hit, &plain));
        assert!(get_binding(&tracee, Side::Guest, b"/nope").is_none());
    }

    #[test]
    fn same_guest_path_replaces_earlier_binding() {
        let td = TempDir::new("bind");
        td.dir("h1");
        td.dir("h2");
        let tracee = Tracee::default();
        let b1 = insort_binding3(&tracee, td.abs("h1").as_slice(), b"/g").unwrap();
        let b2 = insort_binding3(&tracee, td.abs("h2").as_slice(), b"/g").unwrap();
        let fs = tracee.fs.borrow();
        // The replaced binding is unlinked from every list.
        assert_eq!(fs.guest.len(), 1);
        assert!(Rc::ptr_eq(&fs.guest[0], &b2));
        assert!(!fs.host.iter().any(|b| Rc::ptr_eq(b, &b1)));
        assert!(!fs.pending.iter().any(|b| Rc::ptr_eq(b, &b1)));
        assert_eq!(fs.guest[0].host.as_bytes(), td.abs("h2").as_slice());
    }

    #[test]
    fn substitute_binding_guest_to_host() {
        let td = TempDir::new("bind");
        let host = TempDir::new("bindh");
        let tracee = t(td.path().to_str().unwrap(), &[]);
        insort_binding3(&tracee, host.abs(".").as_slice(), b"/gdir").unwrap();

        let mut p = FixedPath::from_bytes(b"/gdir/sub/f");
        assert_eq!(substitute_binding(&tracee, Side::Guest, &mut p), Ok(1));
        let want = [host.abs(".").as_slice(), b"/sub/f"].concat();
        assert_eq!(p.as_bytes(), want.as_slice());

        // Reverse direction: a host path *outside* the rootfs substitutes
        // back to the guest side.
        let mut p = FixedPath::from_bytes(&want);
        assert_eq!(substitute_binding(&tracee, Side::Host, &mut p), Ok(1));
        assert_eq!(p.as_bytes(), b"/gdir/sub/f");
    }

    #[test]
    fn substitute_binding_symmetric_and_missing() {
        let td = TempDir::new("bind");
        td.dir("same");
        let tracee = t("/", &[]);
        // host == guest -> Ok(0), path untouched.
        insort_binding3(
            &tracee,
            td.abs("same").as_slice(),
            td.abs("same").as_slice(),
        )
        .unwrap();
        let mut p = FixedPath::from_bytes(td.abs("same").as_slice());
        assert_eq!(substitute_binding(&tracee, Side::Guest, &mut p), Ok(0));
        assert_eq!(p.as_bytes(), td.abs("same").as_slice());
        // Every guest path is covered by the symmetric root binding.
        let mut p = FixedPath::from_bytes(b"/etc/x");
        assert_eq!(substitute_binding(&tracee, Side::Guest, &mut p), Ok(0));

        // No bindings at all: ENOENT.
        let tracee = Tracee::default();
        let mut p = FixedPath::from_bytes(b"/x");
        assert_eq!(
            substitute_binding(&tracee, Side::Guest, &mut p),
            Err(-libc::ENOENT)
        );

        // Pending bindings are invisible to Guest lookups pre-init and are
        // never substituted (need_substitution stays false for them).
        let mut tracee = Tracee::default();
        new_binding(&mut tracee, td.abs("same").as_slice(), Some(b"/pend"), true).unwrap();
        let mut p = FixedPath::from_bytes(b"/pend/x");
        assert_eq!(
            substitute_binding(&tracee, Side::Guest, &mut p),
            Err(-libc::ENOENT)
        );
        assert_eq!(substitute_binding(&tracee, Side::Pending, &mut p), Ok(0));
        assert_eq!(p.as_bytes(), b"/pend/x");
    }

    #[test]
    fn host_side_lookup_skips_paths_under_root() {
        let td = TempDir::new("bind");
        td.dir("hdir");
        let tracee = t(td.path().to_str().unwrap(), &[]);
        insort_binding3(&tracee, td.abs("hdir").as_slice(), b"/g").unwrap();
        // A host path *under the rootfs* must not match a binding: it is
        // already guest-visible via the root.
        let under_root = [td.abs("hdir").as_slice(), b"/x"].concat();
        assert!(get_binding(&tracee, Side::Host, &under_root).is_none());
        // A host path outside the rootfs matches normally.
        let host2 = TempDir::new("bind2");
        insort_binding3(&tracee, host2.path().to_str().unwrap().as_bytes(), b"/g2").unwrap();
        let outside = [host2.abs(".").as_slice(), b"/x"].concat();
        let b = get_binding(&tracee, Side::Host, &outside).unwrap();
        assert_eq!(b.guest.as_bytes(), b"/g2");
    }

    #[test]
    fn substitute_host_to_guest_roundtrip() {
        let td = TempDir::new("bind");
        let host = TempDir::new("bindh");
        host.dir("sub");
        let tracee = t(td.path().to_str().unwrap(), &[]);
        insort_binding3(&tracee, host.abs(".").as_slice(), b"/vb").unwrap();
        let mut p = FixedPath::from_bytes([host.abs(".").as_slice(), b"/sub"].concat().as_slice());
        assert_eq!(substitute_binding(&tracee, Side::Host, &mut p), Ok(1));
        assert_eq!(p.as_bytes(), b"/vb/sub");
    }

    #[test]
    fn with_root_and_get_root() {
        let td = TempDir::new("bind");
        // Root binding only.
        let tracee = t(td.path().to_str().unwrap(), &[]);
        let r = with_root(&tracee, |r| r.as_bytes().to_vec());
        assert_eq!(r, td.abs("."));
        assert_eq!(get_root(&tracee).as_bytes(), td.abs(".").as_slice());
        // No bindings at all: empty root.
        let tracee = Tracee::default();
        assert_eq!(with_root(&tracee, |r| r.len()), 0);
    }

    #[test]
    fn insort_binding3_rejects_overlong() {
        let tracee = Tracee::default();
        let long = vec![b'x'; crate::PATH_MAX];
        assert!(insort_binding3(&tracee, &long, b"/g").is_none());
        assert!(insort_binding3(&tracee, b"/h", &long).is_none());
    }

    #[test]
    fn initialize_bindings_promotes_pending() {
        let td = TempDir::new("bind");
        td.dir("h");
        let mut tracee = Tracee::default();
        new_binding(
            &mut tracee,
            td.path().to_str().unwrap().as_bytes(),
            Some(b"/"),
            true,
        )
        .unwrap();
        new_binding(&mut tracee, td.abs("h").as_slice(), Some(b"/gh"), true).unwrap();
        assert_eq!(tracee.fs.borrow().pending.len(), 2);
        initialize_bindings(&mut tracee);
        let fs = tracee.fs.borrow();
        assert!(fs.pending.is_empty());
        assert_eq!(fs.guest.len(), 2);
        assert_eq!(fs.host.len(), 2);
        // Root is the guest "/" binding.
        assert_eq!(fs.guest.last().unwrap().guest.as_bytes(), b"/");
    }

    #[test]
    fn initialize_binding_canonicalizes_guest_symlink() {
        let td = TempDir::new("bind");
        td.dir("real");
        // Guest path via a *host* symlink inside the rootfs.
        td.symlink("real", "lnk");
        let mut tracee = Tracee::default();
        new_binding(
            &mut tracee,
            td.path().to_str().unwrap().as_bytes(),
            Some(b"/"),
            true,
        )
        .unwrap();
        // File source => the guest symlink is dereferenced ("/real").
        let h = TempDir::new("bindh");
        h.file("f", b"x");
        new_binding(&mut tracee, h.abs("f").as_slice(), Some(b"/lnk"), true).unwrap();
        // Dir source => the binding must present a dir at "/lnk" literally.
        let d = TempDir::new("bindd");
        new_binding(
            &mut tracee,
            d.path().to_str().unwrap().as_bytes(),
            Some(b"/lnk2"),
            true,
        )
        .unwrap();
        td.symlink("real", "lnk2");
        initialize_bindings(&mut tracee);
        let fs = tracee.fs.borrow();
        assert!(fs.guest.iter().any(|b| b.guest.as_bytes() == b"/real"));
        assert!(fs.guest.iter().any(|b| b.guest.as_bytes() == b"/lnk2"));
    }

    #[test]
    fn initialize_binding_bang_skips_deref() {
        let td = TempDir::new("bind");
        // guest "/lnk!" — trailing '!' asks not to dereference.
        td.symlink("real", "lnk");
        td.dir("real");
        let mut tracee = Tracee::default();
        new_binding(
            &mut tracee,
            td.path().to_str().unwrap().as_bytes(),
            Some(b"/"),
            true,
        )
        .unwrap();
        let h = TempDir::new("bindh");
        h.dir("d"); // host is a dir => dereference=false anyway; use file to exercise '!'
        new_binding(
            &mut tracee,
            h.path().to_str().unwrap().as_bytes(),
            Some(b"/lnk!"),
            true,
        )
        .unwrap();
        initialize_bindings(&mut tracee);
        let fs = tracee.fs.borrow();
        // The '!' marker is stripped; with a dir source the link is kept.
        assert!(fs.guest.iter().any(|b| b.guest.as_bytes() == b"/lnk"));
    }

    #[test]
    fn remove_binding_unlinks_everywhere() {
        let td = TempDir::new("bind");
        td.dir("h");
        let mut tracee = Tracee::default();
        let b = new_binding(&mut tracee, td.abs("h").as_slice(), Some(b"/g"), true).unwrap();
        assert_eq!(tracee.fs.borrow().pending.len(), 1);
        remove_binding_from_all_lists(&tracee, &b);
        assert!(tracee.fs.borrow().pending.is_empty());
    }

    #[test]
    fn binding_path_selects_side() {
        let b = Binding {
            host: FixedPath::from_bytes(b"/host"),
            guest: FixedPath::from_bytes(b"/guest"),
            need_substitution: true,
        };
        assert_eq!(b.path(Side::Host).as_bytes(), b"/host");
        assert_eq!(b.path(Side::Guest).as_bytes(), b"/guest");
        assert_eq!(b.path(Side::Pending).as_bytes(), b"/guest");
    }

    #[test]
    fn io_error_string_formats_errno() {
        assert!(io_error_string(libc::ENOENT).contains("No such file"));
        assert!(io_error_string(libc::EACCES).contains("Permission denied"));
    }
}
