//! Glue filesystem — port of path/glue.c.  When a binding's guest path can't
//! exist in the guest rootfs, intermediate components are created in a temp
//! rootfs ("glue") with a covering binding.

use std::rc::Rc;

use crate::PATH_MAX;
use crate::fpath::FixedPath;
use crate::path::{Comparison, Finality, binding, compare_paths};
use crate::tracee::Tracee;

/// `build_glue()` — returns the type (mode & S_IFMT) of the component, 0 on
/// error.
pub fn build_glue(
    tracee: &mut Tracee,
    guest_path: &FixedPath,
    host_path: &mut FixedPath,
    finality: Finality,
) -> u32 {
    debug_assert!(tracee.glue_type != 0);

    if tracee.glue.is_none() {
        match crate::path::temp::create_temp_directory(None, "proot") {
            Some(dir) => tracee.glue = Some(Rc::from(dir)),
            None => {
                crate::note!(
                    crate::note::Severity::Error,
                    crate::note::Origin::Internal,
                    "can't create glue rootfs"
                );
                return 0;
            }
        }
    }
    let glue = tracee.glue.as_ref().unwrap().clone();

    let comparison = compare_paths(glue.as_bytes(), host_path.as_bytes());
    let belongs_to_gluefs =
        comparison == Comparison::PathsAreEqual || comparison == Comparison::Path1IsPrefix;

    let (typ, mode) = if finality.is_final() {
        // Type propagated from initialize_binding().
        (tracee.glue_type, if belongs_to_gluefs { 0o777 } else { 0 })
    } else {
        (libc::S_IFDIR, 0o777)
    };

    let skip_create = std::env::var_os("PROOT_DONT_POLLUTE_ROOTFS").is_some() && !belongs_to_gluefs;

    if !skip_create {
        let c = host_path.as_c_str();
        let status = if (typ & libc::S_IFMT) == libc::S_IFDIR {
            crate::sys::mkdir(c, mode)
        } else {
            crate::sys::mknod(c, mode | typ, 0)
        };
        // Remove guest-rootfs placeholders on termination.
        if status >= 0 && !belongs_to_gluefs {
            crate::path::temp::set_placeholder_destructor(host_path);
        }

        if status >= 0 || crate::sys::errno() == libc::EEXIST || finality.is_final() {
            return typ;
        }

        if belongs_to_gluefs {
            crate::note!(
                crate::note::Severity::Warning,
                crate::note::Origin::System,
                "mkdir/mknod"
            );
            return 0;
        }
    }

    if glue.len() >= PATH_MAX - 1 || guest_path.len() >= PATH_MAX - 1 {
        crate::note!(
            crate::note::Severity::Warning,
            crate::note::Origin::Internal,
            "installing the binding: guest path too long"
        );
        return 0;
    }

    // From the example, create the binding "/black" -> "$GLUE".
    if binding::insort_binding3(tracee, glue.as_bytes(), guest_path.as_bytes()).is_none() {
        return 0;
    }

    typ
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::path::Side;
    use crate::testutil::{TempDir, test_tracee};

    /// A tracee whose rootfs is `root` and whose glue_type is preset (set
    /// by initialize_binding in production).
    fn glue_tracee(root: &str) -> Tracee {
        let mut t = test_tracee(root, &[]);
        t.glue_type = libc::S_IFREG;
        t
    }

    #[test]
    fn build_glue_creates_missing_dir_and_binding() {
        let td = TempDir::new("glue");
        let root = String::from_utf8(td.abs(".")).unwrap();
        let mut t = glue_tracee(&root);
        // guest "/a/b" — "a" missing in the rootfs.
        let guest = FixedPath::from_bytes(b"/a");
        let mut host = FixedPath::from_bytes(format!("{root}/a").as_bytes());
        let typ = build_glue(&mut t, &guest, &mut host, Finality::NotFinal);
        assert_eq!(typ, libc::S_IFDIR);
        assert!(std::path::Path::new(&format!("{root}/a")).is_dir());
        // A glue temp dir was created and a covering binding registered.
        assert!(t.glue.is_some());
        let b = binding::get_path_binding(&t, Side::Guest, b"/a");
        assert!(b.is_some());
    }

    #[test]
    fn build_glue_final_component_uses_glue_type() {
        let td = TempDir::new("glue-fin");
        let root = String::from_utf8(td.abs(".")).unwrap();
        let mut t = glue_tracee(&root);
        t.glue_type = libc::S_IFREG;
        let guest = FixedPath::from_bytes(b"/leaf");
        let mut host = FixedPath::from_bytes(format!("{root}/leaf").as_bytes());
        let typ = build_glue(&mut t, &guest, &mut host, Finality::Normal);
        // Final component: S_IFREG created (mknod).
        assert_eq!(typ, libc::S_IFREG);
        assert!(std::path::Path::new(&format!("{root}/leaf")).is_file());
    }
}
