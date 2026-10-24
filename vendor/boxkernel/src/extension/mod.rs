//! Extension framework — port of extension/extension.c.
//!
//! C uses `(callback, config, filtered_sysnums)` triples with untyped
//! `intptr_t` payloads.  Here each extension is a variant of
//! [`AnyExtension`] and events are a typed enum; dispatch happens via
//! [`AnyExtension::notify`].

use crate::Word;
use crate::fpath::FixedPath;
use crate::tracee::Tracee;

pub mod fake_id0;
pub mod fix_symlink_size;
pub mod hidden_files;
pub mod kompat;
pub mod link2symlink;
pub mod mountinfo;
pub mod port_switch;
pub mod sysvipc;

/// `CLONE_RECONF` — pseudo clone flag for sub-reconfiguration.
pub const CLONE_RECONF: Word = Word::MAX;

/// Typed extension events (extension.h `ExtensionEvent`).
pub enum Event<'a> {
    /// data1 = base (cwd) — may be replaced; data2 = user path.
    GuestPath {
        base: &'a mut FixedPath,
        path: &'a [u8],
    },
    /// data1 = canonicalized host path; data2 = last iteration.
    HostPath {
        path: &'a mut FixedPath,
        is_final: bool,
    },
    /// data1 = link host path; data2 = link content (mutable).
    SymlinkDeref {
        link: &'a FixedPath,
        referree: &'a mut FixedPath,
    },
    /// data1 = translated host path (mutable).
    TranslatedPath {
        path: &'a mut FixedPath,
    },
    SysEnterStart,
    SysEnterEnd {
        status: i32,
    },
    SysExitStart,
    SysExitEnd {
        status: i32,
    },
    /// data1 = new waitpid status.
    NewStatus {
        status: i32,
    },
    /// data1 = child tracee pid; data2 = clone flags.  Return <0 not
    /// inheritable, 0 shared config, >0 call InheritChild.
    InheritParent {
        child_pid: i32,
        clone_flags: Word,
    },
    /// data1 = parent's extension config, data2 = clone flags.
    InheritChild {
        clone_flags: Word,
    },
    ChainedEnter,
    ChainedExit,
    /// data1 = CLI argument.
    Initialization {
        arg: &'a str,
    },
    Removed,
    PrintConfig,
    PrintUsage {
        detailed: bool,
    },
    SigsysOcc,
    Link2SymlinkRename {
        link: &'a str,
        target: &'a str,
    },
    Link2SymlinkUnlink {
        link: &'a str,
    },
    StatxSyscall {
        state: &'a mut crate::tracee::statx::StatxSyscallState,
    },
    ReadlinkProcFd {
        state: &'a mut crate::syscall::ReadlinkProcFdState,
    },
    ExecveProcExe {
        state: &'a mut crate::execve::ExecveProcExeState,
    },
}

/// `AnyExtension` — one variant per built-in extension.
pub enum AnyExtension {
    FakeId0(fake_id0::FakeId0),
    // Boxed: this variant is ~8KB, dwarfing all the others.
    Link2Symlink(Box<link2symlink::Link2symlink>),
    HiddenFiles(hidden_files::HiddenFiles),
    PortSwitch(port_switch::PortSwitch),
    FixSymlinkSize(fix_symlink_size::FixSymlinkSize),
    Kompat(kompat::Kompat),
    Mountinfo(mountinfo::Mountinfo),
    Sysvipc(sysvipc::Sysvipc),
}

impl AnyExtension {
    /// Dispatch `event` to the wrapped extension's callback.
    pub fn notify(&mut self, tracee: &mut Tracee, event: &mut Event) -> i32 {
        match self {
            AnyExtension::FakeId0(e) => e.callback(tracee, event),
            AnyExtension::Link2Symlink(e) => e.callback(tracee, event),
            AnyExtension::HiddenFiles(e) => e.callback(tracee, event),
            AnyExtension::PortSwitch(e) => e.callback(tracee, event),
            AnyExtension::FixSymlinkSize(e) => e.callback(tracee, event),
            AnyExtension::Kompat(e) => e.callback(tracee, event),
            AnyExtension::Mountinfo(e) => e.callback(tracee, event),
            AnyExtension::Sysvipc(e) => e.callback(tracee, event),
        }
    }

    /// Sysnums this extension wants delivered when seccomp is used, with
    /// their `FILTER_*` flags (C's `FilteredSysnum` pairs).
    pub fn filtered_sysnums(&self) -> &'static [(crate::sysnum::Sysnum, crate::Word)] {
        match self {
            AnyExtension::FakeId0(e) => e.filtered_sysnums(),
            AnyExtension::Link2Symlink(e) => e.filtered_sysnums(),
            AnyExtension::HiddenFiles(e) => e.filtered_sysnums(),
            AnyExtension::PortSwitch(e) => e.filtered_sysnums(),
            AnyExtension::FixSymlinkSize(e) => e.filtered_sysnums(),
            AnyExtension::Kompat(e) => e.filtered_sysnums(),
            AnyExtension::Mountinfo(e) => e.filtered_sysnums(),
            AnyExtension::Sysvipc(e) => e.filtered_sysnums(),
        }
    }

    /// `INHERIT_CHILD` — produce the child's copy of this extension.
    pub fn clone_for_child(&self, clone_flags: Word) -> AnyExtension {
        match self {
            AnyExtension::FakeId0(e) => AnyExtension::FakeId0(e.clone_for_child(clone_flags)),
            AnyExtension::Link2Symlink(e) => {
                AnyExtension::Link2Symlink(Box::new(e.clone_for_child(clone_flags)))
            }
            AnyExtension::HiddenFiles(e) => {
                AnyExtension::HiddenFiles(e.clone_for_child(clone_flags))
            }
            AnyExtension::PortSwitch(e) => AnyExtension::PortSwitch(e.clone_for_child(clone_flags)),
            AnyExtension::FixSymlinkSize(e) => {
                AnyExtension::FixSymlinkSize(e.clone_for_child(clone_flags))
            }
            AnyExtension::Kompat(e) => AnyExtension::Kompat(e.clone_for_child(clone_flags)),
            AnyExtension::Mountinfo(e) => AnyExtension::Mountinfo(e.clone_for_child(clone_flags)),
            AnyExtension::Sysvipc(e) => AnyExtension::Sysvipc(e.clone_for_child(clone_flags)),
        }
    }
}

/// `notify_extensions()` — fire `event` on every extension of `tracee`;
/// return the first non-zero status.
pub fn notify(tracee: &mut Tracee, event: &mut Event) -> i32 {
    for i in 0..tracee.extensions.len() {
        let mut ext = match tracee.extensions[i].take() {
            Some(e) => e,
            None => continue,
        };
        let status = ext.notify(tracee, event);
        // The callback may have detached itself (e.g. Initialization <0).
        if tracee.extensions[i].is_none() {
            tracee.extensions[i] = Some(ext);
        }
        if status != 0 {
            return status;
        }
    }
    0
}

// ----- path-notification helpers used by path/canon.rs -----

pub fn notify_guest_path(tracee: &mut Tracee, base: &mut FixedPath, path: &[u8]) -> i32 {
    notify(tracee, &mut Event::GuestPath { base, path })
}

pub fn notify_host_path(tracee: &mut Tracee, path: &mut FixedPath, is_final: bool) -> i32 {
    notify(tracee, &mut Event::HostPath { path, is_final })
}

pub fn notify_symlink_deref(
    tracee: &mut Tracee,
    link: &FixedPath,
    referree: &mut FixedPath,
) -> i32 {
    notify(tracee, &mut Event::SymlinkDeref { link, referree })
}

pub fn notify_translated_path(tracee: &mut Tracee, path: &mut FixedPath) -> Result<(), i32> {
    match notify(tracee, &mut Event::TranslatedPath { path }) {
        0 => Ok(()),
        e => Err(e),
    }
}

/// `initialize_extension()` — run the INITIALIZATION event on `ext`, then
/// attach it to `tracee` unless it failed.
pub fn initialize_extension(tracee: &mut Tracee, mut ext: AnyExtension, cli_arg: &str) -> i32 {
    let status = ext.notify(tracee, &mut Event::Initialization { arg: cli_arg });
    if status < 0 {
        return status;
    }
    tracee.extensions.push(Some(ext));
    0
}

/// `get_extension()` — is an extension of this kind attached?
pub fn has_extension(tracee: &Tracee, pred: impl Fn(&AnyExtension) -> bool) -> bool {
    tracee.extensions.iter().flatten().any(pred)
}

/// `TALLOC_FREE(extension)` — fire REMOVED on matching extensions and drop
/// them from `tracee.extensions`.
pub fn remove_extension(tracee: &mut Tracee, pred: impl Fn(&AnyExtension) -> bool) {
    for i in 0..tracee.extensions.len() {
        let matches = tracee.extensions[i].as_ref().is_some_and(&pred);
        if matches {
            if let Some(mut ext) = tracee.extensions[i].take() {
                ext.notify(tracee, &mut Event::Removed);
            }
        }
    }
    tracee.extensions.retain(|e| e.is_some());
}

/// `inherit_extensions()` — clone-attach the parent's extensions to `child`
/// according to each extension's inheritability policy.
pub fn inherit_extensions(child: &mut Tracee, parent: &mut Tracee, clone_flags: Word) {
    for i in 0..parent.extensions.len() {
        let mut ext = match parent.extensions[i].take() {
            Some(e) => e,
            None => continue,
        };
        let status = ext.notify(
            parent,
            &mut Event::InheritParent {
                child_pid: child.pid,
                clone_flags,
            },
        );
        if status >= 0 {
            let mut cloned = ext.clone_for_child(clone_flags);
            if status > 0 {
                cloned.notify(child, &mut Event::InheritChild { clone_flags });
            }
            child.extensions.push(Some(cloned));
        }
        if parent.extensions[i].is_none() {
            parent.extensions[i] = Some(ext);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::test_tracee;

    fn fake() -> AnyExtension {
        AnyExtension::FakeId0(fake_id0::FakeId0::default())
    }

    #[test]
    fn initialize_has_remove_cycle() {
        let mut t = test_tracee("/", &[]);
        assert!(!has_extension(&t, |e| matches!(
            e,
            AnyExtension::FakeId0(_)
        )));
        assert_eq!(initialize_extension(&mut t, fake(), ""), 0);
        assert!(has_extension(&t, |e| matches!(e, AnyExtension::FakeId0(_))));
        remove_extension(&mut t, |e| matches!(e, AnyExtension::FakeId0(_)));
        assert!(!has_extension(&t, |e| matches!(
            e,
            AnyExtension::FakeId0(_)
        )));
    }

    #[test]
    fn inherit_clones_to_child() {
        let mut parent = test_tracee("/", &[]);
        let mut child = test_tracee("/", &[]);
        child.pid = 4242;
        assert_eq!(initialize_extension(&mut parent, fake(), ""), 0);
        inherit_extensions(&mut child, &mut parent, 0);
        assert!(has_extension(&child, |e| matches!(
            e,
            AnyExtension::FakeId0(_)
        )));
        // Parent keeps its extension.
        assert!(has_extension(&parent, |e| matches!(
            e,
            AnyExtension::FakeId0(_)
        )));
    }

    #[test]
    fn notify_sysexit_reaches_extensions() {
        let mut t = test_tracee("/", &[]);
        assert_eq!(initialize_extension(&mut t, fake(), ""), 0);
        // FakeId0 on SysExitStart may rewrite regs; we only assert the
        // dispatch itself doesn't error.
        let mut ev = Event::SysExitStart;
        assert!(notify(&mut t, &mut ev) >= 0);
    }

    #[test]
    fn notify_on_empty_extension_list() {
        let mut t = test_tracee("/", &[]);
        assert_eq!(notify(&mut t, &mut Event::SysEnterStart), 0);
    }
}
