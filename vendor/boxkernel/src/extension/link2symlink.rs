//! link2symlink extension — port of extension/link2symlink/link2symlink.c
//! (non-USERLAND build: PREFIX ".l2s.").
//!
//! Emulates hard links with symlinks for filesystems that don't support
//! them (e.g. FAT). A link(2) call moves the target into a backing file
//! `<PREFIX><name><NNNN>.<NNNN>` and replaces the original with a chain
//! of symlinks: original -> intermediate -> final.

use std::cell::RefCell;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;

use crate::PATH_MAX;
use crate::Word;
use crate::extension::Event;
use crate::fpath::FixedPath;
use crate::path::f2fs::should_skip_file_access_due_to_f2fs_bug;
use crate::path::{Comparison, compare_paths, detranslate_path, readlink_proc_pid_fd};
use crate::syscall::seccomp::FILTER_SYSEXIT;
use crate::sysnum::Sysnum;
use crate::tracee::Tracee;
use crate::tracee::mem::{read_path, write_data};
use crate::tracee::reg::{
    Reg, RegVersion, get_sysnum, is_32on64_mode, peek_reg, poke_reg, set_sysnum,
};
use crate::verbose;

const PREFIX: &[u8] = b".l2s.";
const DELETED_SUFFIX: &[u8] = b" (deleted)";

/// sizeof(struct stat) cut to only fields at the same addresses for 32-bit
/// and 64-bit tracees (st_dev..st_blocks).
const SIZEOF_RELEVANT_STRUCT_STAT: usize = 72;

/// Per-tracee state describing the syscall being processed.
#[derive(Default)]
struct L2sConfig {
    /// Host path of the last faked hard link the path being translated
    /// went through — the name the tracee reached the l2s file by.
    dereferenced_link: FixedPath,
    /// Host path of the faked hard link the syscall was redirected away
    /// from, when it is about to return a descriptor on it.
    pending_link: FixedPath,
}

#[derive(Default)]
pub struct Link2symlink {
    config: L2sConfig,
}

const FD_CACHE_SIZE: usize = 64;

#[derive(Clone)]
struct FdEntry {
    pid: i32,
    fd: i32,
    link: Vec<u8>,
}

thread_local! {
    /// Descriptors that were opened through a faked hard link.
    static FD_CACHE: RefCell<Vec<Option<FdEntry>>> =
        RefCell::new(vec![None; FD_CACHE_SIZE]);
    static FD_CACHE_INDEX: RefCell<usize> = const { RefCell::new(0) };

    /// The directory PROOT_L2S_DIR asks the backing files to be kept in.
    /// It is remembered as a descriptor because all operations are done by
    /// PRoot itself with raw host syscalls no translation applies to — a
    /// tracee that replaces the directory with a symbolic link would
    /// otherwise redirect every backing file creation.
    static L2S_DIR: RefCell<(bool, Vec<u8>, i32)> = const { RefCell::new((false, Vec::new(), -1)) };
}

/// `get_l2s_directory()` — configured l2s directory without trailing
/// slashes, or None when unset.
fn get_l2s_directory() -> Option<Vec<u8>> {
    L2S_DIR.with(|c| {
        let mut c = c.borrow_mut();
        if !c.0 {
            c.0 = true;
            if let Some(v) = std::env::var_os("PROOT_L2S_DIR") {
                let mut value = v.as_bytes().to_vec();
                if !value.is_empty() && value.len() < PATH_MAX {
                    while value.len() > 1 && value[value.len() - 1] == b'/' {
                        value.pop();
                    }
                    c.1 = value;
                }
            }
        }
        if c.1.is_empty() {
            None
        } else {
            Some(c.1.clone())
        }
    })
}

/// `open_l2s_directory()` — descriptor on the l2s directory, opened on
/// first use (O_NOFOLLOW: a symbolic link left under that name is a
/// refusal, not something to follow). Returns -errno.
fn open_l2s_directory() -> i32 {
    let cached = L2S_DIR.with(|c| c.borrow().2);
    if cached >= 0 {
        return cached;
    }
    let Some(dir) = get_l2s_directory() else {
        return -libc::ENOENT;
    };
    let c = match CString::new(dir) {
        Ok(c) => c,
        Err(_) => return -libc::ENOENT,
    };
    let fd = crate::sys::open(
        &c,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0,
    );
    if fd < 0 {
        let e = crate::sys::errno();
        return if e > 0 { -e } else { -libc::ENOENT };
    }
    L2S_DIR.with(|c| c.borrow_mut().2 = fd);
    fd
}

/// `l2s_entry()` — when `path` lies directly in the l2s directory, answer
/// a descriptor on it plus the entry name; otherwise (-1, path itself).
/// Returns -1 with errno set when the directory can't be opened — falling
/// back to the plain path there would defeat the whole point.
fn l2s_entry(path: &[u8]) -> Result<(i32, &[u8]), i32> {
    let Some(dir) = get_l2s_directory() else {
        return Ok((-1, path));
    };
    if path.len() <= dir.len() || &path[..dir.len()] != dir.as_slice() || path[dir.len()] != b'/' {
        return Ok((-1, path));
    }
    let base = &path[dir.len() + 1..];
    if base.is_empty() || base.contains(&b'/') {
        return Ok((-1, path));
    }
    let fd = open_l2s_directory();
    if fd < 0 {
        return Err(-fd); // caller's errno convention
    }
    Ok((fd, base))
}

fn path_errno() -> i32 {
    let e = crate::sys::errno();
    if e > 0 { e } else { libc::ENOENT }
}

/// `l2s_access()` — F_OK check, following symlinks (a dangling
/// intermediate counts as a free slot).
fn l2s_access(path: &[u8]) -> i32 {
    let (dir_fd, name) = match l2s_entry(path) {
        Ok(v) => v,
        Err(e) => return -e,
    };
    let c = CString::new(name).unwrap_or_default();
    let r = if dir_fd < 0 {
        crate::sys::access(&c, libc::F_OK)
    } else {
        crate::sys::faccessat(dir_fd, &c, libc::F_OK, 0)
    };
    if r < 0 { -path_errno() } else { 0 }
}

fn l2s_symlink(target: &[u8], path: &[u8]) -> i32 {
    let (dir_fd, name) = match l2s_entry(path) {
        Ok(v) => v,
        Err(e) => return -e,
    };
    let t = CString::new(target).unwrap_or_default();
    let n = CString::new(name).unwrap_or_default();
    let r = if dir_fd < 0 {
        crate::sys::symlink(&t, &n)
    } else {
        crate::sys::symlinkat(&t, dir_fd, &n)
    };
    if r < 0 { -path_errno() } else { 0 }
}

fn l2s_unlink(path: &[u8]) -> i32 {
    let (dir_fd, name) = match l2s_entry(path) {
        Ok(v) => v,
        Err(e) => return -e,
    };
    let c = CString::new(name).unwrap_or_default();
    let r = if dir_fd < 0 {
        crate::sys::unlink(&c)
    } else {
        crate::sys::unlinkat(dir_fd, &c, 0)
    };
    if r < 0 { -path_errno() } else { 0 }
}

fn l2s_rename(old_path: &[u8], new_path: &[u8]) -> i32 {
    let (old_dir, old_name) = match l2s_entry(old_path) {
        Ok(v) => v,
        Err(e) => return -e,
    };
    let (new_dir, new_name) = match l2s_entry(new_path) {
        Ok(v) => v,
        Err(e) => return -e,
    };
    let o = CString::new(old_name).unwrap_or_default();
    let n = CString::new(new_name).unwrap_or_default();
    let r = if old_dir < 0 && new_dir < 0 {
        crate::sys::rename(&o, &n)
    } else {
        // An absolute path with AT_FDCWD is the side that isn't in
        // the l2s directory.
        crate::sys::renameat(
            if old_dir < 0 { libc::AT_FDCWD } else { old_dir },
            &o,
            if new_dir < 0 { libc::AT_FDCWD } else { new_dir },
            &n,
        )
    };
    if r < 0 { -path_errno() } else { 0 }
}

/// `my_readlink()` — copy the contents of `symlink` into `value`.
fn my_readlink(symlink: &[u8], value: &mut [u8; PATH_MAX]) -> i32 {
    let (dir_fd, name) = match l2s_entry(symlink) {
        Ok(v) => v,
        Err(e) => return -e,
    };
    let c = CString::new(name).unwrap_or_default();
    let size = if dir_fd < 0 {
        crate::sys::readlink(&c, value)
    } else {
        crate::sys::readlinkat(dir_fd, &c, value)
    };
    if size < 0 {
        return -path_errno();
    }
    if size as usize >= PATH_MAX {
        return -libc::ENAMETOOLONG;
    }
    value[size as usize] = 0;
    0
}

fn readlink_to_vec(path: &[u8]) -> Result<Vec<u8>, i32> {
    let mut buf = [0u8; PATH_MAX];
    let status = my_readlink(path, &mut buf);
    if status < 0 {
        return Err(status);
    }
    let len = buf.iter().position(|&b| b == 0).unwrap_or(PATH_MAX);
    Ok(buf[..len].to_vec())
}

fn base_name(path: &[u8]) -> &[u8] {
    match path.iter().rposition(|&b| b == b'/') {
        Some(p) => &path[p + 1..],
        None => path,
    }
}

/// `is_open_syscall()` — syscalls that return a descriptor on the file
/// whose path they are given.
fn is_open_syscall(sysnum: Sysnum) -> bool {
    matches!(
        sysnum,
        Sysnum::creat | Sysnum::open | Sysnum::openat | Sysnum::openat2
    )
}

/// `is_l2s_file()` — does `host_path` name a file this extension moved
/// into the l2s directory: "<PREFIX><name><NNNN>.<NNNN>"?
fn is_l2s_file(host_path: &[u8]) -> bool {
    let name = base_name(host_path);
    if !name.starts_with(PREFIX) {
        return false;
    }
    // 5 = strlen(".0002")
    if name.len() < PREFIX.len() + 5 {
        return false;
    }
    if name[name.len() - 5] != b'.' {
        return false;
    }
    name[name.len() - 4..].iter().all(|b| b.is_ascii_digit())
}

/// `resolve_faked_hard_link()` — the file the faked hard link `link` (a
/// host path) refers to.  `Err(-errno)` if `link` isn't a faked hard
/// link or is broken.
fn resolve_faked_hard_link(link: &[u8]) -> Result<Vec<u8>, i32> {
    let intermediate = readlink_to_vec(link)?;
    let name = base_name(&intermediate);
    if !name.starts_with(PREFIX) {
        return Err(-libc::EINVAL);
    }
    readlink_to_vec(&intermediate)
}

/// `remember_fd()` — record that descriptor `fd` of `pid` was opened
/// through the faked hard link `link` (a host path). Entries outlive
/// their opener's bookkeeping (close/dup/fork are untracked); stale
/// entries are detected when used.
fn remember_fd(pid: i32, fd: i32, link: &[u8]) {
    FD_CACHE.with(|c| {
        let mut cache = c.borrow_mut();
        // An entry for the same (pid, fd) wins; otherwise the ring slot.
        let slot = cache
            .iter()
            .position(|e| e.as_ref().is_some_and(|e| e.pid == pid && e.fd == fd))
            .unwrap_or_else(|| {
                FD_CACHE_INDEX.with(|i| {
                    let mut i = i.borrow_mut();
                    let s = *i;
                    *i = (*i + 1) % FD_CACHE_SIZE;
                    s
                })
            });
        cache[slot] = Some(FdEntry {
            pid,
            fd,
            link: link.to_vec(),
        });
    });
}

/// `recall_fd()` — the faked hard link `fd` of `pid` was opened through,
/// if known. Threads share descriptors but not pids, so a sibling's
/// entry is a fallback; callers verify it still leads to the same file.
fn recall_fd(pid: i32, fd: i32) -> Option<Vec<u8>> {
    FD_CACHE.with(|c| {
        let cache = c.borrow();
        let mut fallback = None;
        for e in cache.iter().flatten() {
            if e.fd != fd {
                continue;
            }
            if e.pid == pid {
                return Some(e.link.clone());
            }
            fallback = Some(e.link.clone());
        }
        fallback
    })
}

/// `readlink_proc_fd()` — report the name the tracee used to open the
/// file rather than its l2s name.
fn readlink_proc_fd(state: &mut crate::syscall::ReadlinkProcFdState) {
    // Only files in the l2s directory are reported under a name no
    // tracee ever used.
    if !is_l2s_file(state.host_path.as_bytes()) {
        return;
    }
    let Some(link) = recall_fd(state.pid, state.fd) else {
        return;
    };
    // Descriptor numbers get reused and links get removed: ensure the
    // remembered name still leads to this very file.
    let Ok(final_path) = resolve_faked_hard_link(&link) else {
        return;
    };
    if final_path != state.host_path.as_bytes() {
        return;
    }
    state.host_path.set(&link);
    state.substituted = true;
}

/// `remember_dereferenced_link()` — remember `link` (a host path whose
/// content is `referee`) if it is a faked hard link, i.e. points to the
/// intermediate of a file of the l2s directory.
fn remember_dereferenced_link(config: &mut L2sConfig, link: &[u8], referee: &[u8]) {
    let name = base_name(referee);
    if !name.starts_with(PREFIX) {
        return;
    }
    // Both a faked hard link and its intermediate point to a name that
    // starts with PREFIX, but only the intermediate points to its own
    // name followed by the link count: "<name>.<NNNN>".
    let link_name = base_name(link);
    if name.len() == link_name.len() + 5
        && &name[..link_name.len()] == link_name
        && name[link_name.len()] == b'.'
    {
        let digits = &name[link_name.len() + 1..];
        if digits.iter().all(|b| b.is_ascii_digit()) {
            return;
        }
    }
    config.dereferenced_link.set(link);
}

/// `l2s_link_to_host_path()` — the faked hard link the path being
/// translated went through to reach `host_path`, or None.
fn l2s_link_to_host_path(config: &L2sConfig, host_path: &[u8]) -> Option<Vec<u8>> {
    if !is_l2s_file(host_path) {
        return None;
    }
    let link = config.dereferenced_link.as_bytes();
    if link.is_empty() {
        return None;
    }
    // Ensure this link is indeed a faked hard link to this very file:
    // the tracee may have named the l2s file directly.
    let final_path = resolve_faked_hard_link(link).ok()?;
    if final_path != host_path {
        return None;
    }
    Some(link.to_vec())
}

/// `execve_proc_exe()` — report the faked hard link the executed program
/// was reached through, rather than the l2s file PRoot loads.
fn execve_proc_exe(
    config: &L2sConfig,
    tracee: &mut Tracee,
    state: &mut crate::execve::ExecveProcExeState,
) {
    let Some(link) = l2s_link_to_host_path(config, state.host_path.as_bytes()) else {
        return;
    };
    let mut guest_link = FixedPath::default();
    guest_link.set(&link);
    if detranslate_path(tracee, &mut guest_link, None).is_err() {
        return;
    }
    state.guest_path.set(guest_link.as_bytes());
    state.substituted = true;
}

fn sprintf_counted(path: &[u8], count: i32) -> Vec<u8> {
    let mut v = path.to_vec();
    v.extend_from_slice(format!("{:04}", count).as_bytes());
    v
}

/// `move_and_symlink_path()` — move the path at `sysarg` to a new
/// location, symlink the original to it, and point `sysarg` at the new
/// location. Returns -errno or 0.
fn move_and_symlink_path(
    tracee: &mut Tracee,
    sysarg: Reg,
    link_target_sysarg: Reg,
    config: &L2sConfig,
) -> i32 {
    // `config` unused here — signature mirrors the call sites.
    let _ = config;
    let mut original = FixedPath::default();
    // Note: this path was already canonicalized.
    let addr = peek_reg(tracee, RegVersion::Current, sysarg);
    let size = read_path(tracee, &mut original, addr);
    if size < 0 {
        return size;
    }
    if size as usize >= PATH_MAX {
        return -libc::ENAMETOOLONG;
    }
    let original_b = original.as_bytes().to_vec();

    // Sanity check: directories can't be linked.
    let c = CString::new(original_b.as_slice()).unwrap_or_default();
    let statl = match crate::sys::lstat(&c) {
        Ok(s) => s,
        Err(e) => return -e,
    };
    if statl.st_mode & libc::S_IFMT == libc::S_IFDIR {
        return -libc::EPERM;
    }

    let mut intermediate: Vec<u8>;
    let mut final_path: Vec<u8>;
    let mut first_link = true;

    if statl.st_mode & libc::S_IFMT == libc::S_IFLNK {
        // Already a symlink — get the intermediate name.
        intermediate = match readlink_to_vec(&original_b) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let name = base_name(&intermediate);
        if name.starts_with(PREFIX) {
            first_link = false;
        }
    } else {
        // Compute a new intermediate name.
        let name = base_name(&original_b).to_vec();
        if let Some(dir) = get_l2s_directory() {
            // "<l2s>/<PREFIX><name>" plus the four digits of the suffix
            // and the ".0002" of the final file.
            if dir.len() + PREFIX.len() + name.len() + 11 >= PATH_MAX {
                return -libc::ENAMETOOLONG;
            }
            // Ask for the descriptor here so a directory that can't be
            // opened reports its own reason.
            let status = open_l2s_directory();
            if status < 0 {
                return status;
            }
            intermediate = dir;
            intermediate.push(b'/');
        } else {
            if PREFIX.len() + original_b.len() + 5 >= PATH_MAX {
                return -libc::ENAMETOOLONG;
            }
            intermediate = original_b[..original_b.len() - name.len()].to_vec();
        }
        intermediate.extend_from_slice(PREFIX);
        intermediate.extend_from_slice(&name);
    }

    if first_link {
        // Move the original content to the new path.
        let mut intermediate_suffix = 1;
        let mut new_intermediate;
        loop {
            new_intermediate = sprintf_counted(&intermediate, intermediate_suffix);
            intermediate_suffix += 1;
            if !(l2s_access(&new_intermediate) == 0 && intermediate_suffix < 1000) {
                break;
            }
        }
        intermediate = new_intermediate;

        final_path = intermediate.clone();
        final_path.extend_from_slice(b".0002");
        let status = l2s_rename(&original_b, &final_path);
        if status < 0 {
            return status;
        }
        let old = String::from_utf8_lossy(&original_b).into_owned();
        let new = String::from_utf8_lossy(&final_path).into_owned();
        let status = crate::extension::notify(
            tracee,
            &mut Event::Link2SymlinkRename {
                link: &old,
                target: &new,
            },
        );
        if status < 0 {
            return status;
        }

        // Symlink the intermediate to the final file.
        let status = l2s_symlink(&final_path, &intermediate);
        if status < 0 {
            return status;
        }

        // Symlink the original path to the intermediate one.
        let i_c = CString::new(intermediate.as_slice()).unwrap_or_default();
        let o_c = CString::new(original_b.as_slice()).unwrap_or_default();
        if crate::sys::symlink(&i_c, &o_c) < 0 {
            return -path_errno();
        }
    } else {
        // Move the original content to the new location by incrementing
        // the count at the end of the path.
        final_path = match readlink_to_vec(&intermediate) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let len = final_path.len();
        let link_count = std::str::from_utf8(&final_path[len - 4..])
            .ok()
            .and_then(|s| s.parse::<i32>().ok())
            .unwrap_or(0)
            + 1;
        let mut new_final = final_path[..len - 4].to_vec();
        new_final.extend_from_slice(format!("{:04}", link_count).as_bytes());

        let status = l2s_rename(&final_path, &new_final);
        if status < 0 {
            return status;
        }
        let old = String::from_utf8_lossy(&final_path).into_owned();
        let new = String::from_utf8_lossy(&new_final).into_owned();
        let status = crate::extension::notify(
            tracee,
            &mut Event::Link2SymlinkRename {
                link: &old,
                target: &new,
            },
        );
        if status < 0 {
            return status;
        }
        final_path = new_final;

        // Symlink the intermediate to the final file.
        let status = l2s_unlink(&intermediate);
        if status < 0 {
            return status;
        }
        let status = l2s_symlink(&final_path, &intermediate);
        if status < 0 {
            return status;
        }
    }

    // Perform the symlink() operation within PRoot.
    let mut final_arg = FixedPath::default();
    let target_addr = peek_reg(tracee, RegVersion::Current, link_target_sysarg);
    let mut status = read_path(tracee, &mut final_arg, target_addr);
    if status >= 0 {
        let i_c = CString::new(intermediate.as_slice()).unwrap_or_default();
        let f_c = CString::new(final_arg.as_bytes()).unwrap_or_default();
        if crate::sys::symlink(&i_c, &f_c) < 0 {
            status = -path_errno();
        }
    }
    if status < 0 {
        let status = if status < 0 { status } else { -path_errno() };
        decrement_link_count(tracee, sysarg);
        return status;
    }
    poke_reg(tracee, Reg::SysargResult, 0);
    set_sysnum(tracee, Sysnum::Void);
    0
}

/// `decrement_link_count()` — if `sysarg`'s path points to a converted
/// link, delete it and either decrement the trailing count or remove
/// the intermediate/final files when it reaches 0.
fn decrement_link_count(tracee: &mut Tracee, sysarg: Reg) -> i32 {
    let mut original = FixedPath::default();
    // Note: this path was already canonicalized.
    let size = read_path(
        tracee,
        &mut original,
        peek_reg(tracee, RegVersion::Current, sysarg),
    );
    if size < 0 {
        return size;
    }
    if size as usize >= PATH_MAX {
        return -libc::ENAMETOOLONG;
    }
    let original_b = original.as_bytes().to_vec();

    // Check if it is a converted link already.
    let c = CString::new(original_b.as_slice()).unwrap_or_default();
    let statl = match crate::sys::lstat(&c) {
        Ok(s) => s,
        Err(_) => return 0,
    };
    if statl.st_mode & libc::S_IFMT != libc::S_IFLNK {
        return 0;
    }

    let intermediate = match readlink_to_vec(&original_b) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let name = base_name(&intermediate);
    // Check if an l2s file is pointed to.
    if !name.starts_with(PREFIX) {
        return 0;
    }

    // Read the intermediate link — if this fails the link2symlink is
    // broken and we silently skip it since it was being removed anyway.
    let final_path = match readlink_to_vec(&intermediate) {
        Ok(v) => v,
        Err(_) => {
            verbose!(
                Some(tracee),
                1,
                "Skiping deref of broken link2symlink \"{}\" -> \"{}\"",
                String::from_utf8_lossy(&original_b),
                String::from_utf8_lossy(&intermediate)
            );
            return 0;
        }
    };
    let len = final_path.len();
    if len < 4 {
        return 0;
    }
    let link_count = std::str::from_utf8(&final_path[len - 4..])
        .ok()
        .and_then(|s| s.parse::<i32>().ok())
        .unwrap_or(0)
        - 1;

    // Check whether this is the last link to delete.
    if link_count > 0 {
        let mut new_final = final_path[..len - 4].to_vec();
        new_final.extend_from_slice(format!("{:04}", link_count).as_bytes());
        let status = l2s_rename(&final_path, &new_final);
        if status < 0 {
            return status;
        }
        let old = String::from_utf8_lossy(&final_path).into_owned();
        let new = String::from_utf8_lossy(&new_final).into_owned();
        let status = crate::extension::notify(
            tracee,
            &mut Event::Link2SymlinkRename {
                link: &old,
                target: &new,
            },
        );
        if status < 0 {
            return status;
        }
        // Symlink the intermediate to the new final file.
        let status = l2s_unlink(&intermediate);
        if status < 0 {
            return status;
        }
        let status = l2s_symlink(&new_final, &intermediate);
        if status < 0 {
            return status;
        }
    } else {
        // If it is the last, delete the intermediate and final.
        let status = l2s_unlink(&intermediate);
        if status < 0 {
            return status;
        }
        let status = l2s_unlink(&final_path);
        if status < 0 {
            return status;
        }
        let f = String::from_utf8_lossy(&final_path).into_owned();
        let status = crate::extension::notify(tracee, &mut Event::Link2SymlinkUnlink { link: &f });
        if status < 0 {
            return status;
        }
    }
    0
}

/// `handle_sysexit_end()` — make fake hard links look like real ones
/// (nlink, inode) in stat results, and record fds opened through them.
fn handle_sysexit_end(tracee: &mut Tracee, config: &mut L2sConfig) -> i32 {
    let sysnum = get_sysnum(tracee, RegVersion::Original);
    match sysnum {
        Sysnum::fstatat64
        | Sysnum::newfstatat
        | Sysnum::stat64
        | Sysnum::lstat64
        | Sysnum::fstat64
        | Sysnum::stat
        | Sysnum::lstat
        | Sysnum::fstat => {
            // Override only if it succeeded.
            let result = peek_reg(tracee, RegVersion::Current, Reg::SysargResult);
            if result != 0 {
                return 0;
            }

            let mut original = FixedPath::default();
            if sysnum == Sysnum::fstat64 || sysnum == Sysnum::fstat {
                // non-USERLAND: resolve the fd via /proc/<pid>/fd/<fd>.
                let fd = peek_reg(tracee, RegVersion::Modified, Reg::Sysarg1) as i32;
                if let Err(status) = readlink_proc_pid_fd(tracee.pid, fd, &mut original) {
                    verbose!(
                        Some(tracee),
                        3,
                        "link2symlink: readlink_proc_pid_fd failed, status={}",
                        status
                    );
                    return 0; // Don't alter syscall result.
                }
                let bytes = original.as_bytes().to_vec();
                if bytes.len() > DELETED_SUFFIX.len()
                    && &bytes[bytes.len() - DELETED_SUFFIX.len()..] == DELETED_SUFFIX
                {
                    original.set(&bytes[..bytes.len() - DELETED_SUFFIX.len()]);
                }
            } else {
                let sysarg_path = if sysnum == Sysnum::fstatat64 || sysnum == Sysnum::newfstatat {
                    Reg::Sysarg2
                } else {
                    Reg::Sysarg1
                };
                let size = read_path(
                    tracee,
                    &mut original,
                    peek_reg(tracee, RegVersion::Modified, sysarg_path),
                );
                if size < 0 {
                    return size;
                }
                if size as usize >= PATH_MAX {
                    return -libc::ENAMETOOLONG;
                }
            }
            let original_b = original.as_bytes().to_vec();

            // Check if it is a link.
            let c = CString::new(original_b.as_slice()).unwrap_or_default();
            let statl = crate::sys::lstat(&c).unwrap_or_else(|_| crate::sys::zeroed());

            let name = base_name(&original_b);
            let intermediate;
            let final_path;
            if name.starts_with(PREFIX) {
                if statl.st_mode & libc::S_IFMT == libc::S_IFLNK {
                    intermediate = original_b.clone();
                    final_path = match readlink_to_vec(&intermediate) {
                        Ok(v) => v,
                        Err(e) => return e,
                    };
                } else {
                    final_path = original_b.clone();
                }
            } else {
                if statl.st_mode & libc::S_IFMT != libc::S_IFLNK {
                    return 0;
                }
                intermediate = match readlink_to_vec(&original_b) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                if !base_name(&intermediate).starts_with(PREFIX) {
                    return 0;
                }
                final_path = match readlink_to_vec(&intermediate) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
            }

            let c = CString::new(final_path.as_slice()).unwrap_or_default();
            let mut final_stat = match crate::sys::lstat(&c) {
                Ok(s) => s,
                Err(e) => return -e,
            };
            let len = final_path.len();
            final_stat.st_nlink = std::str::from_utf8(&final_path[len - 4..])
                .ok()
                // st_nlink's width follows the kernel ABI, not nlink_t
                // (Bionic's x86_64 `struct stat` uses a 64-bit field).
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);

            // Get the address of the 'stat' structure.
            let sysarg_stat = if sysnum == Sysnum::fstatat64 || sysnum == Sysnum::newfstatat {
                Reg::Sysarg3
            } else {
                Reg::Sysarg2
            };
            // non-USERLAND: no mode/uid/gid re-merge.
            let stat_bytes = crate::sys::as_bytes(&final_stat);
            let size = if is_32on64_mode(tracee) {
                SIZEOF_RELEVANT_STRUCT_STAT
            } else {
                stat_bytes.len()
            };
            write_data(
                tracee,
                peek_reg(tracee, RegVersion::Original, sysarg_stat),
                &stat_bytes[..size],
            )
        }
        Sysnum::creat | Sysnum::open | Sysnum::openat | Sysnum::openat2 => {
            // Nothing to do unless this open was redirected to an l2s
            // file at the enter stage.
            if config.pending_link.as_bytes().is_empty() {
                return 0;
            }
            let result = peek_reg(tracee, RegVersion::Current, Reg::SysargResult);
            if (result as i64) >= 0 {
                remember_fd(tracee.pid, result as i32, config.pending_link.as_bytes());
            }
            config.pending_link.set(b"");
            0
        }
        _ => 0,
    }
}

/// `link2symlink_handle_statx()` — fix stx_nlink for l2s files.
fn handle_statx(state: &mut crate::tracee::statx::StatxSyscallState) {
    if state.statx_buf.stx_mask & (crate::tracee::statx::STATX_NLINK as u32) == 0 {
        return;
    }
    if !is_l2s_file(state.host_path.as_bytes()) {
        return;
    }
    let bytes = state.host_path.as_bytes();
    let len = bytes.len();
    if let Some(n) = std::str::from_utf8(&bytes[len - 4..])
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
    {
        state.statx_buf.stx_nlink = n;
    }
    // The statx() the kernel performed succeeded; its result was read
    // back and is not written again unless explicitly updated.
    state.updated_stats = true;
}

/// `remember_opened_link()` — remember the name the tracee used for the
/// file it is about to open when `host_path` is an l2s file.
fn remember_opened_link(tracee: &mut Tracee, config: &mut L2sConfig, host_path: &[u8]) {
    let Some(link) = l2s_link_to_host_path(config, host_path) else {
        return;
    };
    config.pending_link.set(&link);
    // The descriptor number is only known at the exit stage, which
    // seccomp lets PRoot skip by default.
    tracee.sysexit_pending = true;
    tracee.restart_how = crate::ptrace::ptc::PTRACE_SYSCALL;
}

/// `translated_path()` — when `translated_path` is a faked hard link,
/// replace it with the file it (internally) points to.
fn translated_path(tracee: &mut Tracee, config: &mut L2sConfig, translated_path: &mut FixedPath) {
    // The tracee is not started yet: PRoot is looking up the program to
    // launch (which()). Keep the name of a faked hard link so the first
    // execve's canonicalization goes through it and /proc/<pid>/exe
    // reports it (execve_proc_exe).
    if tracee.exe.is_none() {
        return;
    }
    // Don't translate l2s symlinks for (un)link/rename calls.
    let sysnum = get_sysnum(tracee, RegVersion::Original);
    if matches!(
        sysnum,
        Sysnum::unlink
            | Sysnum::unlinkat
            | Sysnum::link
            | Sysnum::linkat
            | Sysnum::rename
            | Sysnum::renameat
            | Sysnum::renameat2
    ) {
        return;
    }
    if should_skip_file_access_due_to_f2fs_bug(tracee, translated_path.as_bytes()) {
        return;
    }
    // The canonicalization dereferenced the faked hard links this path
    // was made of, except its last component when it was asked not to —
    // lstat(2), open(O_NOFOLLOW), ... — in which case that is done here.
    if let Ok(final_path) = resolve_faked_hard_link(translated_path.as_bytes()) {
        config.dereferenced_link.set(translated_path.as_bytes());
        translated_path.set(&final_path);
    }
    if is_open_syscall(sysnum) {
        remember_opened_link(tracee, config, translated_path.as_bytes());
    }
}

/// `handle_linkat_from_proc_fd()` — linkat(...,"/proc/X/fd/Y",...,
/// AT_SYMLINK_FOLLOW): copy the deleted file's contents to the target.
/// Returns 1 if handled, 0 to proceed with the usual link2symlink, or
/// -errno on failure.
fn handle_linkat_from_proc_fd(tracee: &mut Tracee) -> i32 {
    // Read the source path; bail if it doesn't belong to /proc.
    let mut proc_path = FixedPath::default();
    let size = read_path(
        tracee,
        &mut proc_path,
        peek_reg(tracee, RegVersion::Current, Reg::Sysarg2),
    );
    if size <= 0 || size >= 128 {
        return 0;
    }
    if compare_paths(proc_path.as_bytes(), b"/proc") != Comparison::Path2IsPrefix {
        return 0;
    }
    let proc_path_b = proc_path.as_bytes().to_vec();

    // Ensure the provided path is a symlink to a " (deleted)" file.
    let c = CString::new(proc_path_b.as_slice()).unwrap_or_default();
    let mut buf = [0u8; PATH_MAX];
    let status = crate::sys::readlink(&c, &mut buf);
    if status < 10 || status as usize >= PATH_MAX {
        return 0;
    }
    if &buf[status as usize - 10..status as usize] != DELETED_SUFFIX {
        return 0;
    }

    // Ensure the source is a regular file.
    let stats = match crate::sys::stat(&c) {
        Ok(s) => s,
        Err(_) => return 0,
    };
    if stats.st_mode & libc::S_IFMT != libc::S_IFREG {
        return 0;
    }

    // Read the target path (already translated by PRoot).
    let mut target_path = FixedPath::default();
    let size = read_path(
        tracee,
        &mut target_path,
        peek_reg(tracee, RegVersion::Current, Reg::Sysarg4),
    );
    if size < 0 || size as usize >= PATH_MAX {
        return 0;
    }
    let target_b = target_path.as_bytes().to_vec();

    // Open the source for reading.
    let source_fd = crate::sys::open(&c, libc::O_RDONLY, 0);
    if source_fd < 0 {
        return 0;
    }

    // Point of no return — errors below are propagated.
    let t_c = CString::new(target_b.as_slice()).unwrap_or_default();
    crate::sys::unlink(&t_c); // ignore result
    let target_fd = crate::sys::open(
        &t_c,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        stats.st_mode & 0o777,
    );
    if target_fd < 0 {
        let mut status = -crate::sys::errno();
        if status >= 0 {
            status = -libc::EPERM;
        }
        crate::sys::close(source_fd);
        return status;
    }

    // Copy the contents.
    let mut buf = [0u8; 4096];
    loop {
        let nread = crate::sys::read(source_fd, &mut buf);
        if nread == 0 {
            break;
        }
        if nread < 0 {
            let mut status = -crate::sys::errno();
            if status >= 0 {
                status = -libc::EPERM;
            }
            crate::sys::close(source_fd);
            crate::sys::close(target_fd);
            return status;
        }
        let mut pos = 0isize;
        while pos < nread {
            let nwrite = crate::sys::write(target_fd, &buf[pos as usize..nread as usize]);
            if nwrite <= 0 {
                let mut status = -crate::sys::errno();
                if status >= 0 {
                    status = -libc::EPERM;
                }
                crate::sys::close(source_fd);
                crate::sys::close(target_fd);
                return status;
            }
            pos += nwrite;
        }
    }
    crate::sys::close(source_fd);
    crate::sys::close(target_fd);
    1
}

impl Link2symlink {
    pub fn callback(&mut self, tracee: &mut Tracee, event: &mut Event) -> i32 {
        match event {
            Event::Initialization { .. } => 0,
            Event::SysEnterStart => {
                // Forget any dereference not consumed by the exit stage
                // of the syscall it was made for.
                self.config.pending_link.set(b"");
                0
            }
            Event::SysEnterEnd { .. } => {
                match get_sysnum(tracee, RegVersion::Original) {
                    Sysnum::rename => {
                        // If newpath is a pseudo hard link, decrement its
                        // link count.
                        decrement_link_count(tracee, Reg::Sysarg2)
                    }
                    Sysnum::renameat | Sysnum::renameat2 => {
                        decrement_link_count(tracee, Reg::Sysarg4)
                    }
                    Sysnum::unlink => decrement_link_count(tracee, Reg::Sysarg1),
                    Sysnum::unlinkat => {
                        // Directories can't be hard links.
                        if peek_reg(tracee, RegVersion::Current, Reg::Sysarg3)
                            & (libc::AT_REMOVEDIR as Word)
                            != 0
                        {
                            return 0;
                        }
                        decrement_link_count(tracee, Reg::Sysarg2)
                    }
                    Sysnum::link => {
                        // link(old, new) → move+symlink.
                        move_and_symlink_path(tracee, Reg::Sysarg1, Reg::Sysarg2, &self.config)
                    }
                    Sysnum::linkat => {
                        // linkat(..., "/proc/X/fd/Y", ..., AT_SYMLINK_FOLLOW)
                        if peek_reg(tracee, RegVersion::Current, Reg::Sysarg5)
                            & (libc::AT_SYMLINK_FOLLOW as Word)
                            != 0
                        {
                            let status = handle_linkat_from_proc_fd(tracee);
                            if status < 0 {
                                return status;
                            }
                            if status == 1 {
                                set_sysnum(tracee, Sysnum::Void);
                                poke_reg(tracee, Reg::SysargResult, 0);
                                return 0;
                            }
                        }
                        // linkat old/new paths were already canonicalized:
                        //   olddirfd + oldpath -> oldpath
                        //   newdirfd + newpath -> newpath
                        move_and_symlink_path(tracee, Reg::Sysarg2, Reg::Sysarg4, &self.config)
                    }
                    _ => 0,
                }
            }
            Event::SysExitEnd { .. } => handle_sysexit_end(tracee, &mut self.config),
            Event::GuestPath { .. } => {
                // A new path is about to be canonicalized.
                self.config.dereferenced_link.set(b"");
                0
            }
            Event::SymlinkDeref { link, referree } => {
                remember_dereferenced_link(&mut self.config, link.as_bytes(), referree.as_bytes());
                0
            }
            Event::TranslatedPath { path } => {
                translated_path(tracee, &mut self.config, path);
                0
            }
            Event::StatxSyscall { state } => {
                handle_statx(state);
                0
            }
            Event::ReadlinkProcFd { state } => {
                readlink_proc_fd(state);
                0
            }
            Event::ExecveProcExe { state } => {
                execve_proc_exe(&self.config, tracee, state);
                0
            }
            Event::InheritParent { .. } => {
                // The configuration only describes the syscall being
                // processed, hence it can't be shared with the child.
                1
            }
            Event::InheritChild { .. } => {
                // Nothing to inherit: the child's configuration is
                // allocated when needed.
                0
            }
            _ => 0,
        }
    }

    pub fn filtered_sysnums(&self) -> &'static [(Sysnum, Word)] {
        &[
            (Sysnum::link, FILTER_SYSEXIT),
            (Sysnum::linkat, FILTER_SYSEXIT),
            (Sysnum::unlink, FILTER_SYSEXIT),
            (Sysnum::unlinkat, FILTER_SYSEXIT),
            (Sysnum::fstat, FILTER_SYSEXIT),
            (Sysnum::fstat64, FILTER_SYSEXIT),
            (Sysnum::fstatat64, FILTER_SYSEXIT),
            (Sysnum::lstat, FILTER_SYSEXIT),
            (Sysnum::lstat64, FILTER_SYSEXIT),
            (Sysnum::newfstatat, FILTER_SYSEXIT),
            (Sysnum::stat, FILTER_SYSEXIT),
            (Sysnum::stat64, FILTER_SYSEXIT),
            (Sysnum::rename, FILTER_SYSEXIT),
            (Sysnum::renameat, FILTER_SYSEXIT),
            (Sysnum::renameat2, FILTER_SYSEXIT),
        ]
    }

    pub fn clone_for_child(&self, _clone_flags: Word) -> Self {
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;

    #[test]
    fn base_name_splits() {
        assert_eq!(base_name(b"/a/b/c"), b"c");
        assert_eq!(base_name(b"naked"), b"naked");
        assert_eq!(base_name(b"/"), b"");
    }

    #[test]
    fn is_l2s_file_shape() {
        // "<PREFIX><name>.<NNNN>" — four trailing digits after a dot.
        assert!(is_l2s_file(b"/x/.l2s.foo.0002"));
        assert!(is_l2s_file(b"/x/.l2s.a.1234"));
        assert!(!is_l2s_file(b"/x/.l2s.foo")); // no .NNNN
        assert!(!is_l2s_file(b"/x/.l2s.foo.12")); // too few digits
        assert!(!is_l2s_file(b"/x/.l2s.foo.123a")); // not all digits
        assert!(!is_l2s_file(b"/x/other.0002")); // no prefix
    }

    #[test]
    fn l2s_entry_outside_dir_returns_plain_path() {
        // Without PROOT_L2S_DIR the dir is unset -> (-1, path).
        let (fd, name) = l2s_entry(b"/some/path").unwrap();
        assert_eq!(fd, -1);
        assert_eq!(name, b"/some/path");
    }

    #[test]
    fn l2s_ops_on_plain_paths() {
        // With no l2s dir configured, ops run on the path itself.
        let td = TempDir::new("l2s");
        td.file("a", b"x");
        let a = td.abs("a");
        assert_eq!(l2s_access(&a), 0);
        // symlink + my_readlink round trip.
        let l = td
            .path()
            .join("l")
            .to_string_lossy()
            .into_owned()
            .into_bytes();
        assert_eq!(l2s_symlink(&a, &l), 0);
        let mut buf = [0u8; PATH_MAX];
        assert_eq!(my_readlink(&l, &mut buf), 0);
        assert_eq!(&buf[..a.len()], a.as_slice());
        // unlink removes it.
        assert_eq!(l2s_unlink(&l), 0);
        assert_eq!(l2s_access(&l), -libc::ENOENT);
        // rename works on plain paths.
        let b = td
            .path()
            .join("b")
            .to_string_lossy()
            .into_owned()
            .into_bytes();
        assert_eq!(l2s_rename(&a, &b), 0);
        assert_eq!(l2s_access(&a), -libc::ENOENT);
        assert_eq!(l2s_access(&b), 0);
    }

    #[test]
    fn resolve_faked_hard_link_chain() {
        // link -> intermediate (".l2s.name.NNNN") -> final.
        let td = TempDir::new("l2s");
        td.file("final", b"data");
        let dir = td.path().display().to_string();
        let inter = format!("{}/.l2s.final.0001", dir);
        std::os::unix::fs::symlink(format!("{}/final", dir), &inter).unwrap();
        let link = format!("{}/user_link", dir);
        std::os::unix::fs::symlink(&inter, &link).unwrap();
        let r = resolve_faked_hard_link(link.as_bytes()).unwrap();
        // readlink(intermediate) yields the final path bytes.
        assert_eq!(r, format!("{}/final", dir).as_bytes());
        // A link NOT pointing at a ".l2s.*" intermediate -> EINVAL.
        td.file("plain", b"");
        std::os::unix::fs::symlink(format!("{}/plain", dir), format!("{}/lnk2", dir)).unwrap();
        let lnk2 = format!("{}/lnk2", dir);
        assert_eq!(resolve_faked_hard_link(lnk2.as_bytes()), Err(-libc::EINVAL));
    }

    #[test]
    fn fd_cache_remember_recall() {
        // Same (pid, fd) replaces; other pid's same-fd is fallback only.
        remember_fd(100, 3, b"/link/a");
        remember_fd(100, 4, b"/link/b");
        remember_fd(200, 3, b"/link/c");
        assert_eq!(recall_fd(100, 3).unwrap(), b"/link/a");
        assert_eq!(recall_fd(100, 4).unwrap(), b"/link/b");
        // pid 300 fd 3 -> falls back to a sibling entry.
        assert_eq!(recall_fd(300, 3).unwrap(), b"/link/c");
        assert!(recall_fd(100, 99).is_none());
    }

    #[test]
    fn remember_dereferenced_link_shape() {
        let mut c = L2sConfig::default();
        // referee not an l2s name -> not remembered.
        remember_dereferenced_link(&mut c, b"/x/link", b"/x/ordinary");
        assert!(c.dereferenced_link.is_empty());
        // referee ".l2s.name.0001" where name == link name + ".NNNN"
        // (the intermediate) -> NOT the link itself; remembered.
        remember_dereferenced_link(&mut c, b"/x/mylink", b"/x/.l2s.mylink.0001");
        assert_eq!(c.dereferenced_link.as_bytes(), b"/x/mylink");
        // Referee ".l2s.name" (no count) still an l2s member -> remembered.
        let mut c = L2sConfig::default();
        remember_dereferenced_link(&mut c, b"/x/l", b"/x/.l2s.other.0001");
        assert_eq!(c.dereferenced_link.as_bytes(), b"/x/l");
    }

    #[test]
    fn sprintf_counted_names() {
        // Appends %04d directly to the path (C sprintf "%s%04d").
        assert_eq!(sprintf_counted(b"/dir/file", 7), b"/dir/file0007");
        assert_eq!(sprintf_counted(b"/dir/file", 12345), b"/dir/file12345");
    }
}
