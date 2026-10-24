//! fake_id0 extension — port of extension/fake_id0/*.c (USERLAND build).
//!
//! Emulates fake root: fakes uid/gid query+set syscalls, forces success of
//! permission-bound operations (chmod/chown/chroot/mknod/sethostname...),
//! patches stat results, and tracks ownership/permissions of created files
//! in `.proot-meta-file.*` sidecar files so later stat/chmod/chown calls see
//! consistent metadata.

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;

use crate::PATH_MAX;
use crate::Word;
use crate::extension::Event;
use crate::fpath::{FixedPath, PathGuard};
use crate::path::{Comparison, belongs_to_guestfs, compare_paths};
use crate::syscall::chain::register_chained_syscall;
use crate::syscall::set_sysarg_data;
use crate::sysnum::Sysnum;
use crate::tracee::Tracee;
use crate::tracee::mem::{
    alloc_mem, peek_uint32, poke_uint32, read_data, read_path, read_string, write_data,
};
use crate::tracee::reg::{Reg, RegVersion, is_32on64_mode, peek_reg, poke_reg};
use crate::tracee::reg::{get_sysnum, set_sysnum};

const META_TAG: &[u8] = b".proot-meta-file.";

/// Mirrors C's `#ifdef USERLAND`.  The Termux reference build leaves it
/// undefined: meta-file machinery, perm-check helpers, umask/getgroups
/// emulation and the fstat->readlinkat stat chains are compiled out, while
/// id patching, chown argument swap, the /proc/pid/fd dup trick, and the
/// perm-error/socket/chroot/getsockopt handlers stay.  Both paths are kept
/// type-checked here; flip to `true` for the USERLAND variant.
const USERLAND: bool = false;

/// `IGNORE_SYSARG` — a sysarg slot that doesn't exist for this syscall form.
const IGNORE: Option<Reg> = None;

// ==================================================================
// Config
// ==================================================================

/// `Config` — per-extension fake-id state.
#[derive(Clone)]
pub struct Config {
    pub ruid: u32,
    pub euid: u32,
    pub suid: u32,
    pub fsuid: u32,
    pub rgid: u32,
    pub egid: u32,
    pub sgid: u32,
    pub fsgid: u32,
    pub umask: u32,
    /// Whether the process effectively holds CAP_SETUID/CAP_SETGID under
    /// proot's fake-root model.
    pub caps_active: bool,
    /// Mirror of the tracee's prctl(PR_SET_KEEPCAPS) flag.
    pub keep_caps: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            ruid: 0,
            euid: 0,
            suid: 0,
            fsuid: 0,
            rgid: 0,
            egid: 0,
            sgid: 0,
            fsgid: 0,
            umask: 0o22,
            caps_active: false,
            keep_caps: false,
        }
    }
}

#[derive(Default)]
pub struct FakeId0 {
    config: Config,
}

/// `get_extension(tracee, fake_id0_callback)` — fetch this tracee's config.
pub fn config_of(tracee: &Tracee) -> Option<&Config> {
    tracee.extensions.iter().flatten().find_map(|e| match e {
        crate::extension::AnyExtension::FakeId0(f) => Some(&f.config),
        _ => None,
    })
}

/// `get_fake_id_for_pid()` — config of an arbitrary tracee, if it runs -0/-i.
fn config_of_pid(pid: i32) -> Option<Config> {
    crate::tracee::with_tracee(pid, |t| config_of(t).cloned()).flatten()
}

// ==================================================================
// Meta-file helpers (helper_functions.c)
// ==================================================================

/// Decimal→"octal-looking-decimal" (e.g. 0o755=493 → 755) — C dtoo().
fn dtoo(mut n: i32) -> i32 {
    let (mut i, mut octal) = (1i32, 0i32);
    while n != 0 {
        octal += (n % 8) * i;
        n /= 8;
        i *= 10;
    }
    octal
}

/// "octal-looking-decimal"→decimal (755 → 0o755=493) — C otod().
fn otod(mut n: i32) -> i32 {
    let (mut decimal, mut i) = (0i32, 0u32);
    while n != 0 {
        decimal += (n % 10) * (1 << (3 * i)); // 8^i == 1<<(3i)
        n /= 10;
        i += 1;
    }
    decimal
}

/// `path_exists()` — access(path, F_OK) == 0.
fn path_exists(path: &FixedPath) -> bool {
    crate::sys::access(path.as_c_str(), libc::F_OK) == 0
}

/// `get_name()` — final component of `path`.
fn get_name(path: &[u8]) -> &[u8] {
    match path.iter().rposition(|&c| c == b'/') {
        Some(p) => &path[p + 1..],
        None => path,
    }
}

/// `get_dir_path()` — `path` without its final component (borrowed).
/// Single-byte/empty paths return themselves, like the original.
fn get_dir_path(path: &[u8]) -> &[u8] {
    if path.len() <= 1 {
        return path;
    }
    let mut offset = path.len() - 1;
    while offset > 1 && path[offset] == b'/' {
        offset -= 1;
    }
    while offset > 1 && path[offset] != b'/' {
        offset -= 1;
    }
    &path[..offset]
}

/// `get_meta_path()` — insert META_TAG before the final component.
fn get_meta_path(orig_path: &[u8], meta_path: &mut FixedPath) -> Result<(), i32> {
    let dir = get_dir_path(orig_path);
    let filename = get_name(orig_path);
    if dir.len() + filename.len() + META_TAG.len() + 1 >= PATH_MAX {
        return Err(-libc::ENAMETOOLONG);
    }
    meta_path.set(dir);
    if dir != b"/" {
        meta_path.extend(b"/")?;
    }
    meta_path.extend(META_TAG)?;
    meta_path.extend(filename)?;
    Ok(())
}

/// `read_meta_file()` — fill (mode, owner, group) from a meta file; absent
/// meta files fall back to permissive defaults (755, euid/egid).
fn read_meta_file(path: &FixedPath, config: &Config) -> (u32, u32, u32) {
    // C reads `fscanf(fp, "%d %d %d ", ...)`; fields that fail to parse stay
    // at their defaults.
    let text = match std::fs::read_to_string(std::ffi::OsStr::from_bytes(path.as_bytes())) {
        Ok(t) => t,
        Err(_) => return (0o755, config.euid, config.egid),
    };
    let mut mode: i32 = 0;
    let mut owner: u32 = 0;
    let mut group: u32 = 0;
    let mut it = text.split_whitespace();
    if let Some(tok) = it.next() {
        match tok.parse::<i32>() {
            Ok(v) => mode = v,
            Err(_) => return (otod(mode) as u32, owner, group),
        }
    }
    if let Some(tok) = it.next() {
        match tok.parse::<u32>() {
            Ok(v) => owner = v,
            Err(_) => return (otod(mode) as u32, owner, group),
        }
    }
    if let Some(tok) = it.next() {
        match tok.parse::<u32>() {
            Ok(v) => group = v,
            Err(_) => return (otod(mode) as u32, owner, group),
        }
    }
    (otod(mode) as u32, owner, group)
}

/// `write_meta_file()` — record (mode, owner, group); `is_creat` applies the
/// emulated umask.
fn write_meta_file(
    path: &FixedPath,
    mode: u32,
    owner: u32,
    group: u32,
    is_creat: bool,
    config: &Config,
) -> Result<(), i32> {
    let mode = if is_creat {
        mode & !config.umask & 0o777
    } else {
        mode
    };
    let text = format!("{}\n{}\n{}\n", dtoo(mode as i32), owner, group);
    std::fs::write(std::ffi::OsStr::from_bytes(path.as_bytes()), text)
        .map_err(|e| -(e.raw_os_error().unwrap_or(libc::EIO)))
}

/// `get_permissions()` — the rwx class digit (as a decimal-looking octal
/// digit) applicable to the emulated uid/gid; root always gets `|6`.
fn get_permissions(meta_path: &FixedPath, config: &Config, uses_real: bool) -> Result<i32, i32> {
    if !path_exists(meta_path) && read_meta_file(meta_path, config).0 == 0o755 {
        // read_meta_file's default path means "no meta": fall through to the
        // permissive default like C does (owner=config->euid, mode=0755).
    }
    let (mode, owner, group) = read_meta_file(meta_path, config);
    if meta_path.is_empty() {
        return Err(-libc::ENOENT);
    }
    let (emulated_uid, emulated_gid) = if uses_real {
        (config.ruid, config.rgid)
    } else {
        (config.euid, config.egid)
    };

    let perms_class = if emulated_uid == owner || emulated_uid == 0 {
        0
    } else if emulated_gid == group {
        1
    } else {
        2
    };
    let mut omode = dtoo(mode as i32);
    // C switch fallthrough: OWNER shifts twice, GROUP once, OTHER never.
    for _ in 0..(2 - perms_class) {
        omode /= 10;
    }
    omode %= 10;
    // Root always has RW on every file.
    if emulated_uid == 0 {
        omode |= 6;
    }
    Ok(omode)
}

/// `check_dir_perms()` — walk each component of `path` down to `rel_path`,
/// requiring 'x' (or 'w' on the parent) from the matching meta files.
fn check_dir_perms(
    tracee: &Tracee,
    ty: u8,
    path: &[u8],
    rel_path: &[u8],
    config: &Config,
) -> Result<(), i32> {
    let x = 1;
    let w = 2;

    let mut shorten = get_dir_path(path);
    let mut meta = PathGuard::new();
    get_meta_path(shorten, &mut meta)?;

    let perms = get_permissions(&meta, config, false)?;
    if ty == b'w' && (perms & w) != w {
        return Err(-libc::EACCES);
    }
    if ty == b'r' && (perms & x) != x {
        return Err(-libc::EACCES);
    }

    while shorten != rel_path && rel_path.len() < shorten.len() {
        shorten = get_dir_path(shorten);
        if !belongs_to_guestfs(tracee, shorten) {
            break;
        }
        get_meta_path(shorten, &mut meta)?;
        let perms = get_permissions(&meta, config, false)?;
        if (perms & x) != x {
            return Err(-libc::EACCES);
        }
    }
    Ok(())
}

/// `get_fd_path()` — resolve the dirfd sysarg to a host path; None means the
/// guest root.  Returns Ok(1) when outside the guestfs ("skip" status).
fn get_fd_path(
    tracee: &mut Tracee,
    path: &mut FixedPath,
    fd_sysarg: Option<Reg>,
    version: RegVersion,
) -> Result<i32, i32> {
    match fd_sysarg {
        Some(reg) => {
            let fd = peek_reg(tracee, version, reg) as i64 as i32;
            if fd == libc::AT_FDCWD {
                crate::path::getcwd2(Some(tracee), path)?;
            } else {
                crate::path::readlink_proc_pid_fd(tracee.pid, fd, path)?;
            }
        }
        None => {
            crate::path::translate_path(tracee, path, libc::AT_FDCWD, b"/", true)?;
        }
    }
    if !belongs_to_guestfs(tracee, path.as_bytes()) {
        return Ok(1);
    }
    Ok(0)
}

/// `read_sysarg_path()` — read the path argument into `path`.  CURRENT =
/// already-translated host path; ORIGINAL = guest path translated here.
/// Returns Ok(1) when the path is outside the guestfs.
fn read_sysarg_path(
    tracee: &mut Tracee,
    path: &mut FixedPath,
    path_sysarg: Reg,
    version: RegVersion,
) -> Result<i32, i32> {
    let size;
    match version {
        RegVersion::Modified => {
            size = read_string(
                tracee,
                path.as_mut_bytes(),
                peek_reg(tracee, RegVersion::Modified, path_sysarg),
            );
            if size >= 0 {
                path.sync_len_from_nul();
            }
        }
        RegVersion::Current => {
            size = read_string(
                tracee,
                path.as_mut_bytes(),
                peek_reg(tracee, RegVersion::Current, path_sysarg),
            );
            if size >= 0 {
                path.sync_len_from_nul();
            }
        }
        RegVersion::Original => {
            let mut original = PathGuard::new();
            size = read_string(
                tracee,
                original.as_mut_bytes(),
                peek_reg(tracee, RegVersion::Original, path_sysarg),
            );
            if size >= 0 {
                original.sync_len_from_nul();
                crate::path::translate_path(
                    tracee,
                    path,
                    libc::AT_FDCWD,
                    original.as_bytes(),
                    true,
                )?;
            }
        }
        _ => {
            return Err(-libc::EINVAL);
        }
    }
    if size < 0 {
        return Err(size);
    }
    if size as usize >= PATH_MAX {
        return Err(-libc::ENAMETOOLONG);
    }
    if !path.as_bytes().is_empty() && !belongs_to_guestfs(tracee, path.as_bytes()) {
        return Ok(1);
    }
    Ok(0)
}

// ==================================================================
// Sysenter handlers (open/mk/unlink/rename/chmod/chown/utimensat/
// access/exec/link/symlink/stat)
// ==================================================================

/// `handle_open_enter_end()` — open/openat/creat: create meta files on
/// O_CREAT and check emulated permissions otherwise.
fn handle_open_enter(
    tracee: &mut Tracee,
    fd_sysarg: Option<Reg>,
    path_sysarg: Reg,
    flags_sysarg: Option<Reg>,
    mode_sysarg: Reg,
    config: &Config,
) -> i32 {
    let mut orig_path = PathGuard::new();
    match read_sysarg_path(tracee, &mut orig_path, path_sysarg, RegVersion::Current) {
        Err(e) => return e,
        Ok(1) => return 0,
        _ => {}
    }

    let mut meta_path = PathGuard::new();
    if let Err(e) = get_meta_path(orig_path.as_bytes(), &mut meta_path) {
        return e;
    }

    let flags = match flags_sysarg {
        Some(r) => peek_reg(tracee, RegVersion::Original, r),
        None => libc::O_CREAT as Word,
    };

    // No metafile + not creating → nothing to do.
    if !path_exists(&meta_path) && (flags & libc::O_CREAT as Word) != libc::O_CREAT as Word {
        return 0;
    }

    let mut rel_path = PathGuard::new();
    if let Err(e) = get_fd_path(tracee, &mut rel_path, fd_sysarg, RegVersion::Current) {
        return e;
    }

    if (flags & libc::O_CREAT as Word) == libc::O_CREAT as Word {
        if path_exists(&orig_path) {
            // File exists already → check its perms instead.
            return open_check(tracee, &meta_path, &rel_path, flags, config);
        }
        if let Err(e) = check_dir_perms(tracee, b'w', &meta_path, rel_path.as_bytes(), config) {
            return e;
        }
        let mode = peek_reg(tracee, RegVersion::Original, mode_sysarg) as u32;
        poke_reg(tracee, mode_sysarg, (mode | 0o700) as Word);
        return match write_meta_file(&meta_path, mode, config.euid, config.egid, true, config) {
            Ok(()) => 0,
            Err(e) => e,
        };
    }

    open_check(tracee, &meta_path, &rel_path, flags, config)
}

/// The `check:` label of handle_open_enter_end().
fn open_check(
    tracee: &Tracee,
    meta_path: &FixedPath,
    rel_path: &FixedPath,
    flags: Word,
    config: &Config,
) -> i32 {
    if let Err(e) = check_dir_perms(tracee, b'r', meta_path, rel_path.as_bytes(), config) {
        return e;
    }
    let perms = match get_permissions(meta_path, config, false) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let access_mode = flags & libc::O_ACCMODE as Word;
    if (access_mode == libc::O_WRONLY as Word && (perms & 2) != 2)
        || (access_mode == libc::O_RDONLY as Word && (perms & 4) != 4)
        || (access_mode == libc::O_RDWR as Word && (perms & 6) != 6)
    {
        return -libc::EACCES;
    }
    0
}

/// `handle_mk_enter_end()` — mkdir/mkdirat/mknod/mknodat.
fn handle_mk_enter(
    tracee: &mut Tracee,
    fd_sysarg: Option<Reg>,
    path_sysarg: Reg,
    mode_sysarg: Reg,
    config: &Config,
) -> i32 {
    let mut orig_path = PathGuard::new();
    match read_sysarg_path(tracee, &mut orig_path, path_sysarg, RegVersion::Current) {
        Err(e) => return e,
        Ok(1) => return 0,
        _ => {}
    }
    // Existing path → the syscall will return EEXIST itself.
    if path_exists(&orig_path) {
        return 0;
    }

    let mut meta_path = PathGuard::new();
    if let Err(e) = get_meta_path(orig_path.as_bytes(), &mut meta_path) {
        return e;
    }

    let mut rel_path = PathGuard::new();
    if let Err(e) = get_fd_path(tracee, &mut rel_path, fd_sysarg, RegVersion::Current) {
        return e;
    }
    if let Err(e) = check_dir_perms(
        tracee,
        b'w',
        orig_path.as_bytes(),
        rel_path.as_bytes(),
        config,
    ) {
        return e;
    }

    let mode = peek_reg(tracee, RegVersion::Original, mode_sysarg) as u32;
    poke_reg(tracee, mode_sysarg, (mode | 0o700) as Word);
    match write_meta_file(&meta_path, mode, config.euid, config.egid, true, config) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// `handle_unlink_enter_end()` — unlink/unlinkat/rmdir.
fn handle_unlink_enter(
    tracee: &mut Tracee,
    fd_sysarg: Option<Reg>,
    path_sysarg: Reg,
    config: &Config,
) -> i32 {
    let mut orig_path = PathGuard::new();
    match read_sysarg_path(tracee, &mut orig_path, path_sysarg, RegVersion::Current) {
        Err(e) => return e,
        Ok(1) => return 0,
        _ => {}
    }

    let mut meta_path = PathGuard::new();
    if let Err(e) = get_meta_path(orig_path.as_bytes(), &mut meta_path) {
        return e;
    }

    let mut rel_path = PathGuard::new();
    if let Err(e) = get_fd_path(tracee, &mut rel_path, fd_sysarg, RegVersion::Current) {
        return e;
    }
    if let Err(e) = check_dir_perms(
        tracee,
        b'w',
        orig_path.as_bytes(),
        rel_path.as_bytes(),
        config,
    ) {
        return e;
    }

    // If a meta file exists, unlink it as well.
    if path_exists(&meta_path) {
        crate::sys::unlink(meta_path.as_c_str());
    }
    0
}

/// `handle_rename_enter_end()` — rename/renameat.
fn handle_rename_enter(
    tracee: &mut Tracee,
    oldfd_sysarg: Option<Reg>,
    oldpath_sysarg: Reg,
    newfd_sysarg: Option<Reg>,
    newpath_sysarg: Reg,
    config: &Config,
) -> i32 {
    let mut oldpath = PathGuard::new();
    match read_sysarg_path(tracee, &mut oldpath, oldpath_sysarg, RegVersion::Current) {
        Err(e) => return e,
        Ok(1) => return 0,
        _ => {}
    }
    let mut newpath = PathGuard::new();
    match read_sysarg_path(tracee, &mut newpath, newpath_sysarg, RegVersion::Current) {
        Err(e) => return e,
        Ok(1) => return 0,
        _ => {}
    }
    let mut rel_oldpath = PathGuard::new();
    if let Err(e) = get_fd_path(tracee, &mut rel_oldpath, oldfd_sysarg, RegVersion::Current) {
        return e;
    }
    let mut rel_newpath = PathGuard::new();
    if let Err(e) = get_fd_path(tracee, &mut rel_newpath, newfd_sysarg, RegVersion::Current) {
        return e;
    }
    if let Err(e) = check_dir_perms(
        tracee,
        b'w',
        oldpath.as_bytes(),
        rel_oldpath.as_bytes(),
        config,
    ) {
        return e;
    }
    if let Err(e) = check_dir_perms(
        tracee,
        b'w',
        newpath.as_bytes(),
        rel_newpath.as_bytes(),
        config,
    ) {
        return e;
    }

    // If a meta file exists, "copy" it to the new path.
    let mut meta_path = PathGuard::new();
    if let Err(e) = get_meta_path(oldpath.as_bytes(), &mut meta_path) {
        return e;
    }
    if !path_exists(&meta_path) {
        return 0;
    }
    let (mode, uid, gid) = read_meta_file(&meta_path, config);
    crate::sys::unlink(meta_path.as_c_str());

    if let Err(e) = get_meta_path(newpath.as_bytes(), &mut meta_path) {
        return e;
    }
    match write_meta_file(&meta_path, mode, uid, gid, false, config) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// `handle_chmod_enter_end()` — chmod/fchmod/fchmodat.
fn handle_chmod_enter(
    tracee: &mut Tracee,
    path_sysarg: Option<Reg>,
    mode_sysarg: Reg,
    fd_sysarg: Option<Reg>,
    dirfd_sysarg: Option<Reg>,
    config: &Config,
) -> i32 {
    let mut path = PathGuard::new();
    let status = match path_sysarg {
        None => get_fd_path(tracee, &mut path, fd_sysarg, RegVersion::Current),
        Some(r) => read_sysarg_path(tracee, &mut path, r, RegVersion::Current),
    };
    match status {
        Err(e) => return e,
        Ok(1) => {
            // Outside the guestfs → drop the syscall.
            set_sysnum(tracee, Sysnum::getuid);
            return 0;
        }
        _ => {}
    }

    let mut meta_path = PathGuard::new();
    let _ = get_meta_path(path.as_bytes(), &mut meta_path);
    if !path_exists(&meta_path) {
        return 0;
    }

    let mut rel_path = PathGuard::new();
    if let Err(e) = get_fd_path(tracee, &mut rel_path, dirfd_sysarg, RegVersion::Current) {
        return e;
    }
    if let Err(e) = check_dir_perms(tracee, b'r', path.as_bytes(), rel_path.as_bytes(), config) {
        return e;
    }

    let (_read_mode, owner, group) = read_meta_file(&meta_path, config);
    if config.euid != owner && config.euid != 0 {
        return -libc::EPERM;
    }

    let call_mode = peek_reg(tracee, RegVersion::Original, mode_sysarg) as u32;
    set_sysnum(tracee, Sysnum::getuid);
    match write_meta_file(&meta_path, call_mode, owner, group, false, config) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// `handle_chown_enter_end()` — chown/lchown/fchown/fchownat (USERLAND).
fn handle_chown_enter(
    tracee: &mut Tracee,
    path_sysarg: Option<Reg>,
    owner_sysarg: Reg,
    group_sysarg: Reg,
    fd_sysarg: Option<Reg>,
    dirfd_sysarg: Option<Reg>,
    config: &Config,
) -> i32 {
    let mut path = PathGuard::new();
    let status = match path_sysarg {
        None => get_fd_path(tracee, &mut path, fd_sysarg, RegVersion::Current),
        Some(r) => read_sysarg_path(tracee, &mut path, r, RegVersion::Current),
    };
    match status {
        Err(e) => return e,
        Ok(1) => {
            set_sysnum(tracee, Sysnum::getuid);
            return 0;
        }
        _ => {}
    }

    let mut meta_path = PathGuard::new();
    if let Err(e) = get_meta_path(path.as_bytes(), &mut meta_path) {
        return e;
    }
    if !path_exists(&meta_path) {
        return 0;
    }

    let mut rel_path = PathGuard::new();
    if let Err(e) = get_fd_path(tracee, &mut rel_path, dirfd_sysarg, RegVersion::Current) {
        return e;
    }
    if let Err(e) = check_dir_perms(tracee, b'r', path.as_bytes(), rel_path.as_bytes(), config) {
        return e;
    }

    let (mode, read_owner, _read_group) = read_meta_file(&meta_path, config);
    let mut owner = peek_reg(tracee, RegVersion::Original, owner_sysarg) as u32;
    // chown without owner → owner arg is -1; use the meta owner.
    if owner == u32::MAX {
        owner = read_owner;
    }
    let group = peek_reg(tracee, RegVersion::Original, group_sysarg) as u32;

    if config.euid == 0 {
        let _ = write_meta_file(&meta_path, mode, owner, group, false, config);
    } else if config.euid == read_owner {
        let _ = write_meta_file(&meta_path, mode, read_owner, group, false, config);
        poke_reg(tracee, owner_sysarg, read_owner as Word);
    } else {
        return -libc::EPERM;
    }

    set_sysnum(tracee, Sysnum::getuid);
    0
}

/// `handle_utimensat_enter_end()`.
fn handle_utimensat_enter(
    tracee: &mut Tracee,
    dirfd_sysarg: Reg,
    path_sysarg: Reg,
    times_sysarg: Reg,
    config: &Config,
) -> i32 {
    // Only care about calls that attempt to change something.
    let times_addr = peek_reg(tracee, RegVersion::Original, times_sysarg);
    if times_addr != 0 {
        let mut times: [libc::timespec; 2] = crate::sys::zeroed();
        let raw = crate::sys::as_bytes_mut(&mut times);
        if read_data(tracee, raw, times_addr) < 0 {
            // C ignores the read error and proceeds to check permissions.
        }
        if times[0].tv_nsec != libc::UTIME_NOW && times[1].tv_nsec != libc::UTIME_NOW {
            return 0;
        }
    }

    let mut path = PathGuard::new();
    let fd = peek_reg(tracee, RegVersion::Original, dirfd_sysarg) as i64 as i32;
    if fd == libc::AT_FDCWD {
        match read_sysarg_path(tracee, &mut path, path_sysarg, RegVersion::Current) {
            Err(e) => return e,
            Ok(1) => return 0,
            _ => {}
        }
    } else {
        if let Err(e) = get_fd_path(tracee, &mut path, Some(dirfd_sysarg), RegVersion::Current) {
            return e;
        }
    }

    let mut meta_path = PathGuard::new();
    if let Err(e) = get_meta_path(path.as_bytes(), &mut meta_path) {
        return e;
    }

    // Current user must be owner of file or root.
    let (_m, owner, _g) = read_meta_file(&meta_path, config);
    if config.euid != owner && config.euid != 0 {
        return -libc::EACCES;
    }
    // If write permissions are on the file, continue.
    match get_permissions(&meta_path, config, false) {
        Ok(perms) if (perms & 2) == 2 => 0,
        Ok(_) => -libc::EACCES,
        Err(e) => e,
    }
}

/// `handle_access_enter_end()` — access/faccessat/faccessat2.
// `mode & F_OK` mirrors the C check verbatim even though F_OK == 0 makes it
// dead — it documents the intent ("skip pure existence probes").
#[allow(clippy::bad_bit_mask)]
fn handle_access_enter(
    tracee: &mut Tracee,
    path_sysarg: Reg,
    mode_sysarg: Reg,
    dirfd_sysarg: Option<Reg>,
    config: &Config,
) -> i32 {
    let mut path = PathGuard::new();
    match read_sysarg_path(tracee, &mut path, path_sysarg, RegVersion::Current) {
        Err(e) => return e,
        Ok(1) => return 0,
        _ => {}
    }
    let mut rel_path = PathGuard::new();
    if let Err(e) = get_fd_path(tracee, &mut rel_path, dirfd_sysarg, RegVersion::Current) {
        return e;
    }
    if let Err(e) = check_dir_perms(tracee, b'r', path.as_bytes(), rel_path.as_bytes(), config) {
        return e;
    }

    // Only care about calls checking permissions.
    let mode = peek_reg(tracee, RegVersion::Original, mode_sysarg) as i32;
    if mode & libc::F_OK != 0 {
        return 0;
    }

    let mut meta_path = PathGuard::new();
    if let Err(e) = get_meta_path(path.as_bytes(), &mut meta_path) {
        return e;
    }
    let mut mask = 0;
    if mode & libc::R_OK == libc::R_OK {
        mask += 4;
    }
    if mode & libc::W_OK == libc::W_OK {
        mask += 2;
    }
    if mode & libc::X_OK == libc::X_OK {
        mask += 1;
    }
    match get_permissions(&meta_path, config, true) {
        Ok(perms) if (perms & mask) == mask => 0,
        Ok(_) => -libc::EACCES,
        Err(e) => e,
    }
}

/// `handle_exec_enter_end()` — execve: check x permission + pick up
/// setuid/setgid bits from the meta file.
fn handle_exec_enter(tracee: &mut Tracee, filename_sysarg: Reg, config: &mut Config) -> i32 {
    let mut path = PathGuard::new();
    match read_sysarg_path(tracee, &mut path, filename_sysarg, RegVersion::Original) {
        Err(e) => return e,
        Ok(1) => return 0,
        _ => {}
    }

    let mut meta_path = PathGuard::new();
    if let Err(e) = get_meta_path(path.as_bytes(), &mut meta_path) {
        return e;
    }
    if !path_exists(&meta_path) {
        return 0;
    }

    if let Err(e) = check_dir_perms(tracee, b'r', meta_path.as_bytes(), b"/", config) {
        return e;
    }
    match get_permissions(&meta_path, config, false) {
        Ok(perms) if (perms & 1) == 1 => {}
        Ok(_) => return -libc::EACCES,
        Err(e) => return e,
    }

    let (mode, _uid, _gid) = read_meta_file(&meta_path, config);
    if (mode & libc::S_ISUID) != 0 {
        config.ruid = 0;
        config.euid = 0;
        config.suid = 0;
    }
    if (mode & libc::S_ISGID) != 0 {
        config.rgid = 0;
        config.egid = 0;
        config.sgid = 0;
    }
    0
}

/// `handle_link_enter_end()` — link/linkat.
fn handle_link_enter(
    tracee: &mut Tracee,
    olddirfd_sysarg: Option<Reg>,
    oldpath_sysarg: Reg,
    newdirfd_sysarg: Option<Reg>,
    newpath_sysarg: Reg,
    config: &Config,
) -> i32 {
    let mut oldpath = PathGuard::new();
    match read_sysarg_path(tracee, &mut oldpath, oldpath_sysarg, RegVersion::Original) {
        Err(e) => return e,
        Ok(1) => return 0,
        _ => {}
    }
    let mut newpath = PathGuard::new();
    match read_sysarg_path(tracee, &mut newpath, newpath_sysarg, RegVersion::Original) {
        Err(e) => return e,
        Ok(1) => return 0,
        _ => {}
    }
    let mut rel_oldpath = PathGuard::new();
    if let Err(e) = get_fd_path(
        tracee,
        &mut rel_oldpath,
        olddirfd_sysarg,
        RegVersion::Original,
    ) {
        return e;
    }
    let mut rel_newpath = PathGuard::new();
    if let Err(e) = get_fd_path(
        tracee,
        &mut rel_newpath,
        newdirfd_sysarg,
        RegVersion::Original,
    ) {
        return e;
    }
    if let Err(e) = check_dir_perms(
        tracee,
        b'r',
        oldpath.as_bytes(),
        rel_oldpath.as_bytes(),
        config,
    ) {
        return e;
    }
    if let Err(e) = check_dir_perms(
        tracee,
        b'w',
        newpath.as_bytes(),
        rel_newpath.as_bytes(),
        config,
    ) {
        return e;
    }
    0
}

/// `handle_symlink_enter_end()` — symlink/symlinkat.
fn handle_symlink_enter(
    tracee: &mut Tracee,
    _oldpath_sysarg: Reg,
    newdirfd_sysarg: Option<Reg>,
    newpath_sysarg: Reg,
    config: &Config,
) -> i32 {
    let mut _oldpath = PathGuard::new();
    if let Err(e) = read_sysarg_path(tracee, &mut _oldpath, _oldpath_sysarg, RegVersion::Current) {
        return e;
    }
    let mut newpath = PathGuard::new();
    match read_sysarg_path(tracee, &mut newpath, newpath_sysarg, RegVersion::Current) {
        Err(e) => return e,
        Ok(1) => return 0,
        _ => {}
    }
    let mut rel_newpath = PathGuard::new();
    if let Err(e) = get_fd_path(
        tracee,
        &mut rel_newpath,
        newdirfd_sysarg,
        RegVersion::Current,
    ) {
        return e;
    }
    if let Err(e) = check_dir_perms(
        tracee,
        b'w',
        newpath.as_bytes(),
        rel_newpath.as_bytes(),
        config,
    ) {
        return e;
    }
    0
}

/// `handle_stat_enter_end()` — fstat/fstat64 → readlinkat on /proc/pid/fd/N
/// so that the exit stage can locate the path through the fd.
fn handle_stat_enter(tracee: &mut Tracee, fd_sysarg: Reg) -> i32 {
    let link_path = format!(
        "/proc/{}/fd/{}",
        tracee.pid,
        peek_reg(tracee, RegVersion::Current, fd_sysarg) as i64
    );

    set_sysnum(tracee, Sysnum::readlinkat);
    let link_address = alloc_mem(tracee, 64);
    let path_address = alloc_mem(tracee, PATH_MAX as i64);
    if link_address == 0 || path_address == 0 {
        return -libc::ENOMEM;
    }
    let mut link_bytes = [0u8; 64];
    link_bytes[..link_path.len()].copy_from_slice(link_path.as_bytes());
    if write_data(tracee, link_address, &link_bytes) < 0 {
        return -libc::ENOMEM;
    }
    poke_reg(tracee, Reg::Sysarg1, libc::AT_FDCWD as Word);
    poke_reg(tracee, Reg::Sysarg2, link_address);
    poke_reg(tracee, Reg::Sysarg3, path_address);
    poke_reg(tracee, Reg::Sysarg4, PATH_MAX as Word);
    0
}

// ==================================================================
// Sendmsg / socket / getsockopt / chroot
// ==================================================================

const MAX_CONTROLLEN: usize = 1024;
const SCM_CREDENTIALS: i32 = 2;
const SYS_SOCKET: u64 = 1;
const SYS_SENDMSG: u64 = 16;
const AF_NETLINK: u64 = 16;
const NETLINK_AUDIT: u64 = 9;

/// `sendmsg_unpack_control_and_len()` — msghdr is different under 32on64.
fn sendmsg_unpack_control_and_len(tracee: &Tracee, msghdr: &[u8]) -> (Word, usize) {
    if is_32on64_mode(tracee) {
        let control = u64::from(u32::from_ne_bytes(msghdr[16..20].try_into().unwrap()));
        let len = u32::from_ne_bytes(msghdr[20..24].try_into().unwrap()) as usize;
        (control, len)
    } else {
        // struct msghdr { name(8), namelen(4), iov(8), iovlen(8), control(8), controllen(8), flags(4) }
        let control = u64::from_ne_bytes(msghdr[24..32].try_into().unwrap());
        let len = u64::from_ne_bytes(msghdr[32..40].try_into().unwrap()) as usize;
        (control, len)
    }
}

fn sendmsg_pack_control(tracee: &Tracee, msghdr: &mut [u8], control: Word) {
    if is_32on64_mode(tracee) {
        msghdr[16..20].copy_from_slice(&(control as u32).to_ne_bytes());
    } else {
        msghdr[24..32].copy_from_slice(&control.to_ne_bytes());
    }
}

/// `handle_sendmsg_enter_end()` — rewrite SCM_CREDENTIALS uid/gid to the
/// real ones.
fn handle_sendmsg_enter(tracee: &mut Tracee, sysnum: Sysnum) -> i32 {
    let is_socketcall = sysnum == Sysnum::socketcall;

    let (size_msghdr, size_cmsghdr, align_mask) = if is_32on64_mode(tracee) {
        (28usize, 12usize, 3usize)
    } else {
        (
            size_of::<libc::msghdr>(),
            size_of::<libc::cmsghdr>(),
            size_of::<u64>() - 1,
        )
    };

    let mut msg = vec![0u8; size_msghdr];
    let mut socketcall_args = [0u64; 3];

    if !is_socketcall {
        let status = read_data(
            tracee,
            &mut msg,
            peek_reg(tracee, RegVersion::Current, Reg::Sysarg2),
        );
        if status < 0 {
            return status;
        }
    } else {
        let call = peek_reg(tracee, RegVersion::Current, Reg::Sysarg1);

        if call == SYS_SOCKET {
            let status = read_data(
                tracee,
                crate::sys::as_bytes_mut(&mut socketcall_args),
                peek_reg(tracee, RegVersion::Current, Reg::Sysarg2),
            );
            if status >= 0
                && socketcall_args[0] == AF_NETLINK
                && socketcall_args[2] == NETLINK_AUDIT
            {
                return -libc::EPROTONOSUPPORT;
            }
        }

        if call != SYS_SENDMSG {
            return 0;
        }
        let status = read_data(
            tracee,
            crate::sys::as_bytes_mut(&mut socketcall_args),
            peek_reg(tracee, RegVersion::Current, Reg::Sysarg2),
        );
        if status < 0 {
            return status;
        }
        let status = read_data(tracee, &mut msg, socketcall_args[1]);
        if status < 0 {
            return status;
        }
    }

    let (msg_control, msg_controllen) = sendmsg_unpack_control_and_len(tracee, &msg);
    if msg_control == 0 || msg_controllen == 0 {
        return 0;
    }
    if msg_controllen > MAX_CONTROLLEN {
        crate::verbose!(
            Some(tracee),
            1,
            "sendmsg() with msg_controllen={}, is_32on64_mode={}, not doing fixup",
            msg_controllen,
            is_32on64_mode(tracee)
        );
        return 0;
    }

    let mut cmsg_buf = vec![0u8; msg_controllen];
    if read_data(tracee, &mut cmsg_buf, msg_control) < 0 {
        return -libc::EFAULT;
    }

    let mut did_modify = false;
    let mut msg_position = 0usize;
    while msg_position < msg_controllen {
        if msg_controllen - msg_position < size_cmsghdr {
            return 0; // malformed: header didn't fit
        }
        let (cmsg_len, cmsg_level, cmsg_type) = if is_32on64_mode(tracee) {
            let b = &cmsg_buf[msg_position..];
            (
                u32::from_ne_bytes(b[0..4].try_into().unwrap()) as usize,
                u32::from_ne_bytes(b[4..8].try_into().unwrap()) as i32,
                u32::from_ne_bytes(b[8..12].try_into().unwrap()) as i32,
            )
        } else {
            let b = &cmsg_buf[msg_position..];
            (
                u64::from_ne_bytes(b[0..8].try_into().unwrap()) as usize,
                u32::from_ne_bytes(b[8..12].try_into().unwrap()) as i32,
                u32::from_ne_bytes(b[12..16].try_into().unwrap()) as i32,
            )
        };
        if cmsg_len < size_cmsghdr || cmsg_len > msg_controllen - msg_position {
            return 0; // malformed
        }

        if cmsg_level == libc::SOL_SOCKET && cmsg_type == SCM_CREDENTIALS {
            if cmsg_len != size_cmsghdr + size_of::<libc::ucred>() {
                return 0;
            }
            // struct ucred { pid(4), uid(4), gid(4) }: patch uid/gid only.
            let off = msg_position + size_cmsghdr;
            let uid = crate::sys::getuid();
            let gid = crate::sys::getgid();
            cmsg_buf[off + 4..off + 8].copy_from_slice(&uid.to_ne_bytes());
            cmsg_buf[off + 8..off + 12].copy_from_slice(&gid.to_ne_bytes());
            did_modify = true;
        }

        msg_position += (cmsg_len + align_mask) & !align_mask;
    }

    if !did_modify {
        return 0;
    }

    // Write cmsg data into tracee.
    let new_control = alloc_mem(tracee, msg_controllen as i64);
    if new_control == 0 {
        return -libc::ENOMEM;
    }
    if write_data(tracee, new_control, &cmsg_buf) < 0 {
        return -libc::ENOMEM;
    }

    let new_msghdr = alloc_mem(tracee, size_msghdr as i64);
    if new_msghdr == 0 {
        return -libc::ENOMEM;
    }
    sendmsg_pack_control(tracee, &mut msg, new_control);
    if write_data(tracee, new_msghdr, &msg) < 0 {
        return -libc::ENOMEM;
    }

    if !is_socketcall {
        poke_reg(tracee, Reg::Sysarg2, new_msghdr);
    } else {
        socketcall_args[1] = new_msghdr;
        return set_sysarg_data(tracee, crate::sys::as_bytes(&socketcall_args), Reg::Sysarg2);
    }
    0
}

/// `handle_socket_exit_end()` — emulate missing AUDIT netlink.
fn handle_socket_exit(tracee: &mut Tracee, config: &Config) -> i32 {
    let result = peek_reg(tracee, RegVersion::Current, Reg::SysargResult) as i64;
    if result != -libc::EPERM as i64 && result != -libc::EACCES as i64 {
        return 0;
    }
    if peek_reg(tracee, RegVersion::Original, Reg::Sysarg1) == AF_NETLINK
        && peek_reg(tracee, RegVersion::Original, Reg::Sysarg3) == NETLINK_AUDIT
        && config.euid == 0
    {
        return -libc::EPROTONOSUPPORT;
    }
    0
}

/// `handle_getsockopt_exit_end()` — patch SO_PEERCRED uid/gid.
fn handle_getsockopt_exit(tracee: &mut Tracee) -> i32 {
    if peek_reg(tracee, RegVersion::Original, Reg::Sysarg2) == libc::SOL_SOCKET as Word
        && peek_reg(tracee, RegVersion::Original, Reg::Sysarg3) == libc::SO_PEERCRED as Word
        && peek_reg(tracee, RegVersion::Current, Reg::SysargResult) == 0
    {
        let cred_addr = peek_reg(tracee, RegVersion::Original, Reg::Sysarg4);
        let mut cred: libc::ucred = crate::sys::zeroed();
        if read_data(tracee, crate::sys::as_bytes_mut(&mut cred), cred_addr) != 0 {
            return 0;
        }
        if let Some(peer) = config_of_pid(cred.pid) {
            cred.uid = peer.euid;
            cred.gid = peer.egid;
            write_data(tracee, cred_addr, crate::sys::as_bytes(&cred));
        }
    }
    0
}

/// `handle_chroot_exit_end()` — emulate chroot() by rebinding the rootfs.
/// `from_sigsys` selects the SIGSYS variant.
fn handle_chroot_exit(tracee: &mut Tracee, config: &Config, from_sigsys: bool) -> i32 {
    if config.euid != 0 {
        return if from_sigsys { -libc::EPERM } else { 0 };
    }

    let mut path = PathGuard::new();
    let mut path_guest = PathGuard::new();
    let mut path_host_absolute = PathGuard::new();

    let input;
    if from_sigsys {
        input = peek_reg(tracee, RegVersion::Current, Reg::Sysarg1);
        poke_reg(tracee, Reg::SysargResult, -(libc::EPERM as i64) as Word);
    } else {
        let result = peek_reg(tracee, RegVersion::Current, Reg::SysargResult) as i64;
        if result != -libc::EPERM as i64 {
            return 0;
        }
        input = peek_reg(tracee, RegVersion::Modified, Reg::Sysarg1);
    }

    if from_sigsys {
        if read_path(tracee, &mut path_guest, input) < 0 {
            return -libc::EFAULT;
        }
        if crate::path::translate_path(
            tracee,
            &mut path,
            libc::AT_FDCWD,
            path_guest.as_bytes(),
            true,
        )
        .is_err()
        {
            return -libc::ENOENT;
        }
    } else {
        if read_path(tracee, &mut path, input) < 0 {
            return -libc::EFAULT;
        }
    }

    // realpath()
    if !crate::sys::realpath(path.as_c_str(), &mut path_host_absolute) {
        path_host_absolute.set(path.as_bytes());
    }

    // "new rootfs == current rootfs"?
    let same_root = crate::path::binding::with_root(tracee, |root| {
        compare_paths(root.as_bytes(), path_host_absolute.as_bytes()) == Comparison::PathsAreEqual
    });
    if same_root {
        if from_sigsys {
            return 1;
        }
        poke_reg(tracee, Reg::SysargResult, 0);
        return 0;
    }

    // Validate target.
    let statbuf = match crate::sys::stat(path_host_absolute.as_c_str()) {
        Ok(s) => s,
        Err(e) => return -e,
    };
    if (statbuf.st_mode & libc::S_IFMT) != libc::S_IFDIR {
        return -libc::ENOTDIR;
    }

    if !from_sigsys {
        let input = peek_reg(tracee, RegVersion::Original, Reg::Sysarg1);
        if read_path(tracee, &mut path_guest, input) < 0 {
            return -crate::sys::errno();
        }
    }

    // Check for bind mounts inside the chroot target.
    let mut seen_bind_under_new_root = false;
    {
        let fs = tracee.fs.borrow();
        for (i, b) in fs.guest.iter().enumerate() {
            let is_guest_root = i == fs.guest.len() - 1;
            if !is_guest_root
                && compare_paths(path_guest.as_bytes(), b.guest.as_bytes())
                    == Comparison::Path1IsPrefix
            {
                seen_bind_under_new_root = true;
                break;
            }
        }
    }

    if !seen_bind_under_new_root {
        // Save current dir (host-translated).
        let cwd = tracee.fs.borrow().cwd.clone();
        if crate::path::translate_path(tracee, &mut path, libc::AT_FDCWD, cwd.as_bytes(), true)
            .is_err()
        {
            return -libc::ENOENT;
        }

        // Replace the tracee's file-system namespace.
        let new_fs = crate::tracee::FileSystemNameSpace::default();
        drop(new_fs);
        tracee.fs = std::rc::Rc::new(std::cell::RefCell::new(
            crate::tracee::FileSystemNameSpace::default(),
        ));
        crate::path::binding::new_binding(tracee, path_host_absolute.as_bytes(), Some(b"/"), true);
        crate::path::binding::initialize_bindings(tracee);

        // Restore current dir.
        let mut p2 = path.clone();
        match crate::path::detranslate_path(tracee, &mut p2, None) {
            Ok(n) if n > 0 && !p2.as_bytes().is_empty() => {
                tracee.fs.borrow_mut().cwd = p2;
            }
            _ => {
                tracee.fs.borrow_mut().cwd = FixedPath::from_bytes(b"/");
            }
        }

        if from_sigsys {
            return 1;
        }
        poke_reg(tracee, Reg::SysargResult, 0);
        return 0;
    }

    if from_sigsys { -libc::ENOSYS } else { 0 }
}

// ==================================================================
// Sysexit machinery
// ==================================================================

/// `offsetof_stat_uid()`/`offsetof_stat_gid()` — stat layout by ABI.
fn offsetof_stat_uid(tracee: &Tracee) -> usize {
    if is_32on64_mode(tracee) {
        24
    } else {
        std::mem::offset_of!(libc::stat, st_uid)
    }
}

fn offsetof_stat_gid(tracee: &Tracee) -> usize {
    if is_32on64_mode(tracee) {
        28
    } else {
        std::mem::offset_of!(libc::stat, st_gid)
    }
}

/// `POKE_MEM_ID` — write a uid/gid (u32) into tracee memory at a sysarg pointer.
fn poke_mem_id(tracee: &mut Tracee, sysarg: Reg, field: u32) -> i32 {
    let addr = peek_reg(tracee, RegVersion::Original, sysarg);
    crate::tracee::mem::poke_uint32(tracee, addr, field);
    if crate::sys::errno() != 0 {
        return -crate::sys::errno();
    }
    0
}

fn handle_getresuid_exit(tracee: &mut Tracee, config: &Config) -> i32 {
    let r = poke_mem_id(tracee, Reg::Sysarg1, config.ruid);
    if r < 0 {
        return r;
    }
    let r = poke_mem_id(tracee, Reg::Sysarg2, config.euid);
    if r < 0 {
        return r;
    }
    poke_mem_id(tracee, Reg::Sysarg3, config.suid)
}

fn handle_getresgid_exit(tracee: &mut Tracee, config: &Config) -> i32 {
    let r = poke_mem_id(tracee, Reg::Sysarg1, config.rgid);
    if r < 0 {
        return r;
    }
    let r = poke_mem_id(tracee, Reg::Sysarg2, config.egid);
    if r < 0 {
        return r;
    }
    poke_mem_id(tracee, Reg::Sysarg3, config.sgid)
}

/// `override_permissions()` — force rwx on a path component during path
/// translation (CAP_DAC_OVERRIDE emulation); restoration is deferred.
fn override_permissions(tracee: &mut Tracee, path: &[u8], is_final: bool) {
    if crate::path::f2fs::should_skip_file_access_due_to_f2fs_bug(tracee, path) {
        return;
    }
    let c = match CString::new(path) {
        Ok(c) => c,
        Err(_) => return,
    };
    let perms = match crate::sys::stat(&c) {
        Ok(s) => s,
        Err(_) => return,
    };

    let mut new_mode = perms.st_mode & (libc::S_IRWXU | libc::S_IRWXG | libc::S_IRWXO);
    new_mode |= libc::S_IRUSR | libc::S_IWUSR;
    if (perms.st_mode & libc::S_IFMT) == libc::S_IFDIR {
        new_mode |= libc::S_IXUSR;
    }
    if new_mode == (perms.st_mode & (libc::S_IRWXU | libc::S_IRWXG | libc::S_IRWXO)) {
        return;
    }

    let restore_mode = if !is_final {
        perms.st_mode
    } else {
        match get_sysnum(tracee, RegVersion::Original) {
            Sysnum::chmod if USERLAND => {
                peek_reg(tracee, RegVersion::Original, Reg::Sysarg2) as u32
            }
            Sysnum::fchmodat if USERLAND => {
                peek_reg(tracee, RegVersion::Original, Reg::Sysarg3) as u32
            }
            Sysnum::fstatat64
            | Sysnum::lstat
            | Sysnum::lstat64
            | Sysnum::newfstatat
            | Sysnum::oldlstat
            | Sysnum::oldstat
            | Sysnum::stat
            | Sysnum::stat64
            | Sysnum::statfs
            | Sysnum::statfs64 => return,
            _ => perms.st_mode,
        }
    };

    let path_vec = path.to_vec();
    tracee.deferred.push(Box::new(move || {
        let c = CString::new(path_vec.as_slice()).unwrap_or_default();
        crate::sys::chmod(&c, restore_mode);
    }));

    let path_os = std::ffi::OsStr::from_bytes(path);
    let _ = path_os;
    crate::sys::chmod(&c, new_mode);
}

/// `adjust_elf_auxv()` — patch AT_UID/EUID/GID/EGID on the post-execve stack.
fn adjust_elf_auxv(tracee: &mut Tracee, config: &Config) {
    let address = crate::execve::auxv::get_elf_aux_vectors_address(tracee);
    if address == 0 {
        return;
    }
    let mut vectors = match crate::execve::auxv::fetch_elf_aux_vectors(tracee, address) {
        Some(v) => v,
        None => return,
    };
    for v in vectors.iter_mut() {
        match v.atype {
            a if a == libc::AT_UID as Word => v.value = config.ruid as Word,
            a if a == libc::AT_EUID as Word => v.value = config.euid as Word,
            a if a == libc::AT_GID as Word => v.value = config.rgid as Word,
            a if a == libc::AT_EGID as Word => v.value = config.egid as Word,
            _ => {}
        }
    }
    crate::execve::auxv::push_elf_aux_vectors(tracee, &vectors, address);
}

/// `handle_perm_err_exit_end()` — force success on EPERM/EACCES when the
/// tracee was supposed to have the capability.
fn handle_perm_err_exit(tracee: &mut Tracee, config: &Config, even_if_not_root: bool) -> i32 {
    let result = peek_reg(tracee, RegVersion::Current, Reg::SysargResult);

    // USERLAND: syscalls voided by an enter handler (or the getuid marker)
    // "succeeded" in altering a meta file.
    if USERLAND && get_sysnum(tracee, RegVersion::Current) == Sysnum::getuid && result != 0 {
        poke_reg(tracee, Reg::SysargResult, 0);
    }
    if USERLAND && get_sysnum(tracee, RegVersion::Current) == Sysnum::Void && result != 0 {
        poke_reg(tracee, Reg::SysargResult, 0);
    }

    let result = peek_reg(tracee, RegVersion::Current, Reg::SysargResult) as i64;
    if result != -libc::EPERM as i64 && result != -libc::EACCES as i64 {
        return 0;
    }
    if even_if_not_root || config.euid == 0 {
        poke_reg(tracee, Reg::SysargResult, 0);
    }
    0
}

// ==================================================================
// set*id emulation (SETXID/SETREXID/SETRESXID/SETFSXID)
// ==================================================================

const UNSET: u64 = u32::MAX as u64;

fn maybe_drop_caps(config: &mut Config, prev_root: bool) {
    if prev_root && !config.keep_caps && config.ruid != 0 && config.euid != 0 && config.suid != 0 {
        config.caps_active = false;
    }
}

/// `SETXID(id)` — setuid/setgid emulation.  `which` is 'u' or 'g'.
fn setxid(tracee: &mut Tracee, config: &mut Config, version: RegVersion, which: u8) -> i32 {
    let id = peek_reg(tracee, version, Reg::Sysarg1) as u32;
    let prev_root = config.ruid == 0 || config.euid == 0 || config.suid == 0;
    let (r, e, s, fs) = match which {
        b'u' => (
            &mut config.ruid,
            &mut config.euid,
            &mut config.suid,
            &mut config.fsuid,
        ),
        _ => (
            &mut config.rgid,
            &mut config.egid,
            &mut config.sgid,
            &mut config.fsgid,
        ),
    };
    let eid = *e;
    let allowed = eid == 0 || config.caps_active || id == *r || id == *e || id == *s;
    if !allowed {
        return -libc::EPERM;
    }
    if eid == 0 || config.caps_active {
        *r = id;
        *s = id;
    }
    *e = id;
    *fs = id;
    maybe_drop_caps(config, prev_root);
    poke_reg(tracee, Reg::SysargResult, 0);
    0
}

/// `SETREXID(id)` — setreuid/setregid emulation.
fn setrexid(tracee: &mut Tracee, config: &mut Config, version: RegVersion, which: u8) -> i32 {
    let rid = peek_reg(tracee, version, Reg::Sysarg1);
    let eid = peek_reg(tracee, version, Reg::Sysarg2);
    let prev_root = config.ruid == 0 || config.euid == 0 || config.suid == 0;
    let (r, e, s, fs) = match which {
        b'u' => (
            &mut config.ruid,
            &mut config.euid,
            &mut config.suid,
            &mut config.fsuid,
        ),
        _ => (
            &mut config.rgid,
            &mut config.egid,
            &mut config.sgid,
            &mut config.fsgid,
        ),
    };
    let (rv, ev, sv) = (*r as u64, *e as u64, *s as u64);
    let unchanged = |id: u64, cur: u64| id == UNSET || id == cur;
    let allowed = ev == 0
        || config.caps_active
        || (unchanged(eid, ev) && unchanged(rid, rv))
        || (rid == ev && (eid == rv || eid == UNSET))
        || (eid == rv && (rid == ev || rid == UNSET))
        || (eid == sv && rid == UNSET);
    if !allowed {
        return -libc::EPERM;
    }
    if eid != UNSET {
        if eid != rv {
            *s = eid as u32;
        }
        *e = eid as u32;
        *fs = eid as u32;
    }
    if rid != UNSET {
        if eid != UNSET {
            *s = eid as u32;
        }
        *r = rid as u32;
    }
    maybe_drop_caps(config, prev_root);
    poke_reg(tracee, Reg::SysargResult, 0);
    0
}

/// `SETRESXID(type)` — setresuid/setresgid emulation.
fn setresxid(tracee: &mut Tracee, config: &mut Config, version: RegVersion, which: u8) -> i32 {
    let rid = peek_reg(tracee, version, Reg::Sysarg1);
    let eid = peek_reg(tracee, version, Reg::Sysarg2);
    let sid = peek_reg(tracee, version, Reg::Sysarg3);
    let prev_root = config.ruid == 0 || config.euid == 0 || config.suid == 0;
    let (r, e, s, fs) = match which {
        b'u' => (
            &mut config.ruid,
            &mut config.euid,
            &mut config.suid,
            &mut config.fsuid,
        ),
        _ => (
            &mut config.rgid,
            &mut config.egid,
            &mut config.sgid,
            &mut config.fsgid,
        ),
    };
    let equals_any = |id: u64| id == *r as u64 || id == *e as u64 || id == *s as u64;
    let allowed = *e == 0
        || config.caps_active
        || ((rid == UNSET || equals_any(rid))
            && (eid == UNSET || equals_any(eid))
            && (sid == UNSET || equals_any(sid)));
    if !allowed {
        return -libc::EPERM;
    }
    if rid != UNSET {
        *r = rid as u32;
    }
    if eid != UNSET {
        *e = eid as u32;
        *fs = eid as u32;
    }
    if sid != UNSET {
        *s = sid as u32;
    }
    maybe_drop_caps(config, prev_root);
    poke_reg(tracee, Reg::SysargResult, 0);
    0
}

/// `SETFSXID(type)` — setfsuid/setfsgid emulation.
fn setfsxid(tracee: &mut Tracee, config: &mut Config, which: u8) -> i32 {
    let fsid = peek_reg(tracee, RegVersion::Original, Reg::Sysarg1) as u32;
    let (r, e, s, fs) = match which {
        b'u' => (
            &mut config.ruid,
            &mut config.euid,
            &mut config.suid,
            &mut config.fsuid,
        ),
        _ => (
            &mut config.rgid,
            &mut config.egid,
            &mut config.sgid,
            &mut config.fsgid,
        ),
    };
    let old = *fs;
    let allowed =
        *e == 0 || config.caps_active || fsid == *fs || fsid == *r || fsid == *e || fsid == *s;
    if allowed {
        *fs = fsid;
    }
    poke_reg(tracee, Reg::SysargResult, old as Word);
    0
}

// ==================================================================
// stat exit (USERLAND)
// ==================================================================

/// `handle_stat_exit_end()` (USERLAND variant).
fn handle_stat_exit(tracee: &mut Tracee, config: &Config, sysnum: Sysnum) -> i32 {
    let result = peek_reg(tracee, RegVersion::Current, Reg::SysargResult);
    if result != 0 {
        return 0;
    }

    // Get the pathname of the file being stat'ed.
    let mut path = PathGuard::new();
    let status = match sysnum {
        Sysnum::fstat | Sysnum::fstat64 if USERLAND => {
            read_sysarg_path(tracee, &mut path, Reg::Sysarg2, RegVersion::Current)
        }
        Sysnum::fstatat64 | Sysnum::newfstatat => {
            read_sysarg_path(tracee, &mut path, Reg::Sysarg2, RegVersion::Modified)
        }
        _ => read_sysarg_path(tracee, &mut path, Reg::Sysarg1, RegVersion::Modified),
    };
    match status {
        Err(e) => return e,
        Ok(1) => return 0,
        _ => {}
    }

    // Address of the 'stat' structure.
    let sysarg = match sysnum {
        Sysnum::fstatat64 | Sysnum::newfstatat => Reg::Sysarg3,
        _ => Reg::Sysarg2,
    };

    // If the meta file exists, merge its mode/uid/gid into the stat.
    let mut meta_path = PathGuard::new();
    if get_meta_path(path.as_bytes(), &mut meta_path).is_ok() && path_exists(&meta_path) {
        let (mode, uid, gid) = read_meta_file(&meta_path, config);
        let mut st: libc::stat = crate::sys::zeroed();
        let addr = peek_reg(tracee, RegVersion::Original, sysarg);
        if read_data(tracee, crate::sys::as_bytes_mut(&mut st), addr) < 0 {
            return 0;
        }
        st.st_mode = mode | ((st.st_mode & libc::S_IFMT) | (st.st_mode & 0o7000));
        st.st_uid = uid;
        st.st_gid = gid;
        write_data(tracee, addr, crate::sys::as_bytes(&st));
        return 0;
    }

    // Otherwise patch uid/gid for files owned by the real user.
    let address = peek_reg(tracee, RegVersion::Original, sysarg);
    let uid = peek_uint32(tracee, address + offsetof_stat_uid(tracee) as Word);
    let gid = peek_uint32(tracee, address + offsetof_stat_gid(tracee) as Word);
    if uid == crate::sys::getuid() {
        poke_uint32(
            tracee,
            address + offsetof_stat_uid(tracee) as Word,
            config.suid,
        );
    }
    if gid == crate::sys::getgid() {
        poke_uint32(
            tracee,
            address + offsetof_stat_gid(tracee) as Word,
            config.sgid,
        );
    }
    0
}

// ==================================================================
// Non-USERLAND handlers
// ==================================================================

/// `handle_chown_enter_end()` (non-USERLAND) — swap the emulated ids in
/// chown arguments back to the real ones so the kernel accepts the call.
fn handle_chown_swap(
    tracee: &mut Tracee,
    config: &Config,
    uid_sysarg: Reg,
    gid_sysarg: Reg,
) -> i32 {
    let uid = peek_reg(tracee, RegVersion::Original, uid_sysarg) as u32;
    let gid = peek_reg(tracee, RegVersion::Original, gid_sysarg) as u32;
    if uid == config.ruid {
        poke_reg(tracee, uid_sysarg, crate::sys::getuid() as Word);
    }
    if gid == config.rgid {
        poke_reg(tracee, gid_sysarg, crate::sys::getgid() as Word);
    }
    0
}

/// `handle_stat_exit_end()` (non-USERLAND) — patch uid/gid of a completed
/// stat structure when the file is owned by the real user.
fn handle_stat_exit_simple(tracee: &mut Tracee, config: &Config, stat_sysarg: Reg) -> i32 {
    let result = peek_reg(tracee, RegVersion::Current, Reg::SysargResult);
    if result != 0 {
        return 0;
    }
    let address = peek_reg(tracee, RegVersion::Original, stat_sysarg);
    let uid = peek_uint32(tracee, address + offsetof_stat_uid(tracee) as Word);
    let gid = peek_uint32(tracee, address + offsetof_stat_gid(tracee) as Word);
    if uid == crate::sys::getuid() {
        poke_uint32(
            tracee,
            address + offsetof_stat_uid(tracee) as Word,
            config.suid,
        );
    }
    if gid == crate::sys::getgid() {
        poke_uint32(
            tracee,
            address + offsetof_stat_gid(tracee) as Word,
            config.sgid,
        );
    }
    0
}

/// `PR_openat` (non-USERLAND) — reopening /proc/<pid>/fd/<N> (e.g.
/// /dev/std* links) fails for the real uid when the underlying fd target
/// isn't accessible; with fake root in effect, substitute dup(N).
fn handle_openat_dup_fd(tracee: &mut Tracee, config: &Config) -> i32 {
    if config.euid != 0 {
        return 0;
    }
    let mut buf = [0u8; PATH_MAX];
    let addr = peek_reg(tracee, RegVersion::Current, Reg::Sysarg2);
    if read_string(tracee, &mut buf, addr) < 0 {
        return 0;
    }
    let end = buf.iter().position(|&c| c == 0).unwrap_or(PATH_MAX);
    let bytes = &buf[..end];
    let prefix = format!("/proc/{}/fd/", tracee.pid);
    if !bytes.starts_with(prefix.as_bytes()) {
        return 0;
    }
    let num_str = &bytes[prefix.len()..];
    if num_str.is_empty() || !num_str.iter().all(|c| c.is_ascii_digit()) {
        return 0;
    }
    let fd_num: i32 = match std::str::from_utf8(num_str).unwrap_or("").parse() {
        Ok(v) if v >= 0 => v,
        _ => return 0,
    };
    // Skip when the fd was opened with O_PATH — dup() would inherit it and
    // real io on the duplicate returns EBADF.
    let fdinfo_path = format!("/proc/{}/fdinfo/{}", tracee.pid, fd_num);
    if let Ok(contents) = std::fs::read_to_string(&fdinfo_path) {
        let mut existing_flags = 0u32;
        for line in contents.lines() {
            if let Some(rest) = line.strip_prefix("flags:") {
                existing_flags = u32::from_str_radix(rest.trim(), 8).unwrap_or(0);
                break;
            }
        }
        if existing_flags & (libc::O_PATH as u32) != 0 {
            return 0;
        }
    }
    set_sysnum(tracee, Sysnum::dup);
    poke_reg(tracee, Reg::Sysarg1, fd_num as Word);
    0
}

// ==================================================================
// Enter/exit dispatch
// ==================================================================

fn handle_sysenter_end(tracee: &mut Tracee, config: &mut Config) -> i32 {
    let sysnum = get_sysnum(tracee, RegVersion::Original);
    match sysnum {
        // === USERLAND-only handlers (see C fake_id0.c #ifdef USERLAND) ===
        // open/openat/creat
        Sysnum::openat if USERLAND => handle_open_enter(
            tracee,
            Some(Reg::Sysarg1),
            Reg::Sysarg2,
            Some(Reg::Sysarg3),
            Reg::Sysarg4,
            config,
        ),
        Sysnum::open if USERLAND => handle_open_enter(
            tracee,
            IGNORE,
            Reg::Sysarg1,
            Some(Reg::Sysarg2),
            Reg::Sysarg3,
            config,
        ),
        Sysnum::creat if USERLAND => {
            handle_open_enter(tracee, IGNORE, Reg::Sysarg1, IGNORE, Reg::Sysarg2, config)
        }

        // mkdir/mkdirat, mknod/mknodat
        Sysnum::mkdirat if USERLAND => handle_mk_enter(
            tracee,
            Some(Reg::Sysarg1),
            Reg::Sysarg2,
            Reg::Sysarg3,
            config,
        ),
        Sysnum::mkdir if USERLAND => {
            handle_mk_enter(tracee, IGNORE, Reg::Sysarg1, Reg::Sysarg2, config)
        }
        Sysnum::mknodat if USERLAND => handle_mk_enter(
            tracee,
            Some(Reg::Sysarg1),
            Reg::Sysarg2,
            Reg::Sysarg3,
            config,
        ),
        Sysnum::mknod if USERLAND => {
            handle_mk_enter(tracee, IGNORE, Reg::Sysarg1, Reg::Sysarg2, config)
        }

        // unlink/unlinkat/rmdir
        Sysnum::unlinkat if USERLAND => {
            handle_unlink_enter(tracee, Some(Reg::Sysarg1), Reg::Sysarg2, config)
        }
        Sysnum::rmdir | Sysnum::unlink if USERLAND => {
            handle_unlink_enter(tracee, IGNORE, Reg::Sysarg1, config)
        }

        // rename/renameat
        Sysnum::renameat if USERLAND => handle_rename_enter(
            tracee,
            Some(Reg::Sysarg1),
            Reg::Sysarg2,
            Some(Reg::Sysarg3),
            Reg::Sysarg4,
            config,
        ),
        Sysnum::rename if USERLAND => {
            handle_rename_enter(tracee, IGNORE, Reg::Sysarg1, IGNORE, Reg::Sysarg2, config)
        }

        // chmod/fchmod/fchmodat
        Sysnum::chmod => handle_chmod_enter(
            tracee,
            Some(Reg::Sysarg1),
            Reg::Sysarg2,
            IGNORE,
            IGNORE,
            config,
        ),
        Sysnum::fchmod if USERLAND => handle_chmod_enter(
            tracee,
            IGNORE,
            Reg::Sysarg2,
            Some(Reg::Sysarg1),
            IGNORE,
            config,
        ),
        Sysnum::fchmodat => handle_chmod_enter(
            tracee,
            Some(Reg::Sysarg2),
            Reg::Sysarg3,
            IGNORE,
            Some(Reg::Sysarg1),
            config,
        ),

        // chown family
        Sysnum::chown | Sysnum::chown32 if USERLAND => handle_chown_enter(
            tracee,
            Some(Reg::Sysarg1),
            Reg::Sysarg2,
            Reg::Sysarg3,
            IGNORE,
            IGNORE,
            config,
        ),
        Sysnum::fchown | Sysnum::fchown32 if USERLAND => handle_chown_enter(
            tracee,
            IGNORE,
            Reg::Sysarg2,
            Reg::Sysarg3,
            Some(Reg::Sysarg1),
            IGNORE,
            config,
        ),
        Sysnum::lchown | Sysnum::lchown32 if USERLAND => handle_chown_enter(
            tracee,
            Some(Reg::Sysarg1),
            Reg::Sysarg2,
            Reg::Sysarg3,
            IGNORE,
            IGNORE,
            config,
        ),
        Sysnum::fchownat if USERLAND => handle_chown_enter(
            tracee,
            Some(Reg::Sysarg2),
            Reg::Sysarg3,
            Reg::Sysarg4,
            IGNORE,
            Some(Reg::Sysarg1),
            config,
        ),

        // utimensat
        Sysnum::utimensat if USERLAND => {
            handle_utimensat_enter(tracee, Reg::Sysarg1, Reg::Sysarg2, Reg::Sysarg3, config)
        }

        // access/faccessat
        Sysnum::access if USERLAND => {
            handle_access_enter(tracee, Reg::Sysarg1, Reg::Sysarg2, IGNORE, config)
        }
        Sysnum::faccessat | Sysnum::faccessat2 if USERLAND => handle_access_enter(
            tracee,
            Reg::Sysarg2,
            Reg::Sysarg3,
            Some(Reg::Sysarg1),
            config,
        ),

        // execve
        Sysnum::execve if USERLAND => handle_exec_enter(tracee, Reg::Sysarg1, config),

        // link/linkat
        Sysnum::link if USERLAND => {
            handle_link_enter(tracee, IGNORE, Reg::Sysarg1, IGNORE, Reg::Sysarg2, config)
        }
        Sysnum::linkat if USERLAND => handle_link_enter(
            tracee,
            Some(Reg::Sysarg1),
            Reg::Sysarg2,
            Some(Reg::Sysarg3),
            Reg::Sysarg4,
            config,
        ),

        // symlink/symlinkat
        Sysnum::symlink if USERLAND => {
            handle_symlink_enter(tracee, Reg::Sysarg1, IGNORE, Reg::Sysarg2, config)
        }
        Sysnum::symlinkat if USERLAND => handle_symlink_enter(
            tracee,
            Reg::Sysarg1,
            Some(Reg::Sysarg2),
            Reg::Sysarg3,
            config,
        ),

        // fstat/fstat64
        Sysnum::fstat | Sysnum::fstat64 if USERLAND => handle_stat_enter(tracee, Reg::Sysarg1),

        // === non-USERLAND handlers ===

        // chown/lchown/fchown/fchownat: swap emulated ids back to real ones
        // so the kernel accepts the call (C handle_chown_enter_end).
        Sysnum::fchownat => handle_chown_swap(tracee, config, Reg::Sysarg3, Reg::Sysarg4),
        Sysnum::chown
        | Sysnum::chown32
        | Sysnum::lchown
        | Sysnum::lchown32
        | Sysnum::fchown
        | Sysnum::fchown32 => handle_chown_swap(tracee, config, Reg::Sysarg2, Reg::Sysarg3),

        // openat of /proc/<pid>/fd/<N> (e.g. /dev/std*): dup() the fd when
        // fake-root is in effect — the kernel would deny the reopen for the
        // real uid (see C comment for details, incl. the O_PATH skip).
        Sysnum::openat => handle_openat_dup_fd(tracee, config),

        Sysnum::sendmsg | Sysnum::socketcall => handle_sendmsg_enter(tracee, sysnum),

        // Fully-emulated syscalls: void the real syscall.
        Sysnum::setuid
        | Sysnum::setuid32
        | Sysnum::setgid
        | Sysnum::setgid32
        | Sysnum::setreuid
        | Sysnum::setreuid32
        | Sysnum::setregid
        | Sysnum::setregid32
        | Sysnum::setresuid
        | Sysnum::setresuid32
        | Sysnum::setresgid
        | Sysnum::setresgid32
        | Sysnum::setfsuid
        | Sysnum::setfsuid32
        | Sysnum::setfsgid
        | Sysnum::setfsgid32 => {
            set_sysnum(tracee, Sysnum::Void);
            0
        }

        // USERLAND-only emulation (real calls pass through otherwise).
        Sysnum::umask
        | Sysnum::setgroups
        | Sysnum::setgroups32
        | Sysnum::getgroups
        | Sysnum::getgroups32
            if USERLAND =>
        {
            set_sysnum(tracee, Sysnum::Void);
            0
        }

        _ => 0,
    }
}

fn handle_sysexit_end(tracee: &mut Tracee, config: &mut Config) -> i32 {
    let sysnum = get_sysnum(tracee, RegVersion::Original);

    // === USERLAND-only chain completion ===
    // fstat was rewritten to readlinkat at enter: translate the result back.
    if USERLAND
        && matches!(
            get_sysnum(tracee, RegVersion::Current),
            Sysnum::fstat | Sysnum::fstat64
        )
    {
        let result = peek_reg(tracee, RegVersion::Current, Reg::SysargResult);
        if result != 0 {
            return 0;
        }
        let address = peek_reg(tracee, RegVersion::Original, Reg::Sysarg2);
        let uid = peek_uint32(tracee, address + offsetof_stat_uid(tracee) as Word);
        let gid = peek_uint32(tracee, address + offsetof_stat_gid(tracee) as Word);
        if uid == crate::sys::getuid() {
            poke_uint32(
                tracee,
                address + offsetof_stat_uid(tracee) as Word,
                config.suid,
            );
        }
        if gid == crate::sys::getgid() {
            poke_uint32(
                tracee,
                address + offsetof_stat_gid(tracee) as Word,
                config.sgid,
            );
        }
        return 0;
    }

    if USERLAND
        && matches!(sysnum, Sysnum::fstat | Sysnum::fstat64)
        && get_sysnum(tracee, RegVersion::Current) == Sysnum::readlinkat
    {
        let result = peek_reg(tracee, RegVersion::Current, Reg::SysargResult);
        poke_reg(tracee, Reg::SysargResult, 0);
        if (result as i64) <= 0 {
            return result as i32;
        }

        let mut path = PathGuard::new();
        let status = read_sysarg_path(tracee, &mut path, Reg::Sysarg3, RegVersion::Modified);
        if status.is_err() {
            return status.err().unwrap();
        }
        // NUL-terminate at result length.
        {
            let mut v = path.as_bytes().to_vec();
            if result as usize <= v.len() {
                v.truncate(result as usize);
            }
            path.set(&v);
        }

        let bytes = path.as_bytes();
        let deleted = bytes.len() >= b" (deleted)".len()
            && &bytes[bytes.len() - b" (deleted)".len()..] == b" (deleted)";
        let is_pipe = bytes.starts_with(b"pipe");
        if deleted || is_pipe {
            let fd = peek_reg(tracee, RegVersion::Original, Reg::Sysarg1);
            let buf = peek_reg(tracee, RegVersion::Original, Reg::Sysarg2);
            register_chained_syscall(tracee, sysnum, [fd, buf, 0, 0, 0, 0]);
        } else {
            write_data(
                tracee,
                peek_reg(tracee, RegVersion::Modified, Reg::Sysarg3),
                &{
                    let mut b = [0u8; PATH_MAX];
                    b[..path.len()].copy_from_slice(path.as_bytes());
                    b
                },
            );
            let buf = peek_reg(tracee, RegVersion::Original, Reg::Sysarg2);
            let path_addr = peek_reg(tracee, RegVersion::Modified, Reg::Sysarg3);
            register_chained_syscall(
                tracee,
                Sysnum::newfstatat,
                [libc::AT_FDCWD as Word, path_addr, buf, 0, 0, 0],
            );
        }
        return 0;
    }

    match sysnum {
        Sysnum::setuid | Sysnum::setuid32 => setxid(tracee, config, RegVersion::Original, b'u'),
        Sysnum::setgid | Sysnum::setgid32 => setxid(tracee, config, RegVersion::Original, b'g'),
        Sysnum::setreuid | Sysnum::setreuid32 => {
            setrexid(tracee, config, RegVersion::Original, b'u')
        }
        Sysnum::setregid | Sysnum::setregid32 => {
            setrexid(tracee, config, RegVersion::Original, b'g')
        }
        Sysnum::setresuid | Sysnum::setresuid32 => {
            setresxid(tracee, config, RegVersion::Original, b'u')
        }
        Sysnum::setresgid | Sysnum::setresgid32 => {
            setresxid(tracee, config, RegVersion::Original, b'g')
        }
        Sysnum::setfsuid | Sysnum::setfsuid32 => setfsxid(tracee, config, b'u'),
        Sysnum::setfsgid | Sysnum::setfsgid32 => setfsxid(tracee, config, b'g'),

        Sysnum::prctl => {
            // Mirror PR_SET_KEEPCAPS on successful calls.
            let op = peek_reg(tracee, RegVersion::Original, Reg::Sysarg1) as i32;
            let result = peek_reg(tracee, RegVersion::Current, Reg::SysargResult) as i64;
            if result == 0 && op == libc::PR_SET_KEEPCAPS {
                config.keep_caps = peek_reg(tracee, RegVersion::Original, Reg::Sysarg2) != 0;
            }
            0
        }

        Sysnum::getuid | Sysnum::getuid32 => {
            poke_reg(tracee, Reg::SysargResult, config.ruid as Word);
            0
        }
        Sysnum::getgid | Sysnum::getgid32 => {
            poke_reg(tracee, Reg::SysargResult, config.rgid as Word);
            0
        }
        Sysnum::geteuid | Sysnum::geteuid32 => {
            poke_reg(tracee, Reg::SysargResult, config.euid as Word);
            0
        }
        Sysnum::getegid | Sysnum::getegid32 => {
            poke_reg(tracee, Reg::SysargResult, config.egid as Word);
            0
        }
        Sysnum::getresuid | Sysnum::getresuid32 => handle_getresuid_exit(tracee, config),
        Sysnum::getresgid | Sysnum::getresgid32 => handle_getresgid_exit(tracee, config),

        Sysnum::umask if USERLAND => {
            poke_reg(tracee, Reg::SysargResult, config.umask as Word);
            config.umask = peek_reg(tracee, RegVersion::Modified, Reg::Sysarg1) as u32;
            0
        }

        Sysnum::setgroups | Sysnum::setgroups32 | Sysnum::getgroups | Sysnum::getgroups32
            if USERLAND =>
        {
            poke_reg(tracee, Reg::SysargResult, 0);
            0
        }

        // Non-USERLAND folds setgroups into the perm-error group.
        Sysnum::setgroups | Sysnum::setgroups32 if !USERLAND => {
            handle_perm_err_exit(tracee, config, false)
        }

        Sysnum::setdomainname
        | Sysnum::sethostname
        | Sysnum::mknod
        | Sysnum::mknodat
        | Sysnum::capset
        | Sysnum::chmod
        | Sysnum::chown
        | Sysnum::fchmod
        | Sysnum::fchown
        | Sysnum::lchown
        | Sysnum::chown32
        | Sysnum::fchown32
        | Sysnum::lchown32
        | Sysnum::fchmodat
        | Sysnum::fchownat => handle_perm_err_exit(tracee, config, false),

        Sysnum::setxattr | Sysnum::lsetxattr | Sysnum::fsetxattr => {
            handle_perm_err_exit(tracee, config, true)
        }

        Sysnum::socket => handle_socket_exit(tracee, config),

        Sysnum::fstatat64
        | Sysnum::newfstatat
        | Sysnum::stat64
        | Sysnum::lstat64
        | Sysnum::fstat64
        | Sysnum::stat
        | Sysnum::lstat
        | Sysnum::fstat
            if USERLAND =>
        {
            handle_stat_exit(tracee, config, sysnum)
        }

        Sysnum::fstatat64 | Sysnum::newfstatat => {
            handle_stat_exit_simple(tracee, config, Reg::Sysarg3)
        }
        Sysnum::stat64
        | Sysnum::lstat64
        | Sysnum::fstat64
        | Sysnum::stat
        | Sysnum::lstat
        | Sysnum::fstat => handle_stat_exit_simple(tracee, config, Reg::Sysarg2),

        Sysnum::chroot => handle_chroot_exit(tracee, config, false),

        Sysnum::getsockopt => handle_getsockopt_exit(tracee),

        // If a meta file was created for a file that no longer exists,
        // delete it (USERLAND only).
        Sysnum::open | Sysnum::openat | Sysnum::creat if USERLAND => {
            let sysarg = match sysnum {
                Sysnum::open | Sysnum::creat => Reg::Sysarg1,
                _ => Reg::Sysarg2,
            };
            let mut path = PathGuard::new();
            match read_sysarg_path(tracee, &mut path, sysarg, RegVersion::Modified) {
                Err(e) => return e,
                Ok(1) => return 0,
                _ => {}
            }
            if path_exists(&path) {
                return 0;
            }
            let mut meta_path = PathGuard::new();
            if get_meta_path(path.as_bytes(), &mut meta_path).is_err() {
                return -libc::ENAMETOOLONG;
            }
            if path_exists(&meta_path) {
                crate::sys::unlink(meta_path.as_c_str());
            }
            0
        }

        _ => 0,
    }
}

/// `handle_sigsys()` — seccomp'd syscalls emulated from the SIGSYS stop.
fn handle_sigsys(tracee: &mut Tracee, config: &mut Config) -> i32 {
    match get_sysnum(tracee, RegVersion::Current) {
        Sysnum::setuid | Sysnum::setuid32 => setxid(tracee, config, RegVersion::Current, b'u'),
        Sysnum::setgid | Sysnum::setgid32 => setxid(tracee, config, RegVersion::Current, b'g'),
        Sysnum::setreuid | Sysnum::setreuid32 => {
            setrexid(tracee, config, RegVersion::Current, b'u')
        }
        Sysnum::setregid | Sysnum::setregid32 => {
            setrexid(tracee, config, RegVersion::Current, b'g')
        }
        Sysnum::setresuid | Sysnum::setresuid32 => {
            setresxid(tracee, config, RegVersion::Current, b'u')
        }
        Sysnum::setresgid | Sysnum::setresgid32 => {
            setresxid(tracee, config, RegVersion::Current, b'g')
        }
        Sysnum::chroot => handle_chroot_exit(tracee, config, true),
        _ => 0,
    }
}

/// `handle_sysexit_start()` — on successful execve, adjust auxv + pick up
/// setuid/setgid bits on the *host* executable.
fn handle_sysexit_start(tracee: &mut Tracee, config: &mut Config) -> i32 {
    let result = peek_reg(tracee, RegVersion::Current, Reg::SysargResult) as i64;
    let sysnum = get_sysnum(tracee, RegVersion::Original);
    if result < 0 || tracee.status < 0 || sysnum != Sysnum::execve {
        return 0;
    }

    // Before PRoot pushes the load script onto the stack.
    if !tracee.skip_proot_loader {
        adjust_elf_auxv(tracee, config);
    }

    // Linux clears PR_SET_KEEPCAPS on execve.
    config.keep_caps = false;

    let host_exe = match &tracee.host_exe {
        Some(h) => h.clone(),
        None => return 0,
    };
    let c = CString::new(host_exe.as_str()).unwrap_or_default();
    let mode = match crate::sys::stat(&c) {
        Ok(s) => s,
        Err(_) => return 0, // not fatal
    };
    if (mode.st_mode & libc::S_ISUID) != 0 {
        config.euid = 0;
        config.suid = 0;
        // Setuid-root binary gives the process fake CAP_SETUID.
        config.caps_active = true;
    }
    if (mode.st_mode & libc::S_ISGID) != 0 {
        config.egid = 0;
        config.sgid = 0;
    }
    0
}

// ==================================================================
// Extension trait
// ==================================================================

impl FakeId0 {
    pub fn callback(&mut self, tracee: &mut Tracee, event: &mut Event) -> i32 {
        match event {
            Event::Initialization { arg } => {
                // Parse "uid:gid", falling back to the real ids on error.
                let uid_str = *arg;
                let uid = match uid_str.split(':').next().unwrap_or("").parse::<i64>() {
                    Ok(v) => v as u32,
                    Err(_) => crate::sys::getuid(),
                };
                let gid = match uid_str.find(':') {
                    Some(i) => match uid_str[i + 1..].parse::<i64>() {
                        Ok(v) => v as u32,
                        Err(_) => crate::sys::getgid(),
                    },
                    None => crate::sys::getgid(),
                };
                self.config.ruid = uid;
                self.config.euid = uid;
                self.config.suid = uid;
                self.config.fsuid = uid;
                self.config.rgid = gid;
                self.config.egid = gid;
                self.config.sgid = gid;
                self.config.fsgid = gid;
                self.config.caps_active = uid == 0;
                self.config.keep_caps = false;
                self.config.umask = 0o22;
                0
            }

            Event::InheritParent { .. } => 1,

            Event::InheritChild { .. } => 0, // config was cloned already

            Event::HostPath { path, is_final } => {
                if self.config.euid == 0 {
                    let p = path.as_bytes().to_vec();
                    override_permissions(tracee, &p, *is_final);
                }
                0
            }

            Event::Link2SymlinkRename { link, target } if USERLAND => {
                let mut old_meta = PathGuard::new();
                if let Err(e) = get_meta_path(link.as_bytes(), &mut old_meta) {
                    return e;
                }
                if !path_exists(&old_meta) {
                    return 0;
                }
                let mut new_meta = PathGuard::new();
                if let Err(e) = get_meta_path(target.as_bytes(), &mut new_meta) {
                    return e;
                }
                if crate::sys::rename(old_meta.as_c_str(), new_meta.as_c_str()) < 0 {
                    return -crate::sys::errno();
                }
                0
            }

            Event::Link2SymlinkUnlink { link } if USERLAND => {
                let mut meta = PathGuard::new();
                if let Err(e) = get_meta_path(link.as_bytes(), &mut meta) {
                    return e;
                }
                if !path_exists(&meta) {
                    return 0;
                }
                if crate::sys::unlink(meta.as_c_str()) < 0 {
                    return -crate::sys::errno();
                }
                0
            }

            Event::SysEnterEnd { .. } => {
                let mut config = self.config.clone();
                let status = handle_sysenter_end(tracee, &mut config);
                self.config = config;
                status
            }

            Event::ChainedExit if USERLAND => {
                let mut config = self.config.clone();
                let status = handle_sysexit_end(tracee, &mut config);
                self.config = config;
                status
            }

            Event::SysExitEnd { .. } => {
                let mut config = self.config.clone();
                let status = handle_sysexit_end(tracee, &mut config);
                self.config = config;
                status
            }

            Event::SigsysOcc => {
                let sysnum = get_sysnum(tracee, RegVersion::Current);
                match sysnum {
                    Sysnum::setuid
                    | Sysnum::setuid32
                    | Sysnum::setgid
                    | Sysnum::setgid32
                    | Sysnum::setreuid
                    | Sysnum::setreuid32
                    | Sysnum::setregid
                    | Sysnum::setregid32
                    | Sysnum::setresuid
                    | Sysnum::setresuid32
                    | Sysnum::setresgid
                    | Sysnum::setresgid32
                    | Sysnum::chroot => {
                        let mut config = self.config.clone();
                        let status = handle_sigsys(tracee, &mut config);
                        self.config = config;
                        if status < 0 {
                            return status;
                        }
                        1
                    }
                    _ => 0,
                }
            }

            Event::SysExitStart => {
                let mut config = self.config.clone();
                let status = handle_sysexit_start(tracee, &mut config);
                self.config = config;
                status
            }

            Event::StatxSyscall { state } => {
                if state.statx_buf.stx_mask & 0x0008 != 0 {
                    // STATX_UID
                    if state.statx_buf.stx_uid == crate::sys::getuid() {
                        state.statx_buf.stx_uid = self.config.suid;
                        state.updated_stats = true;
                    }
                }
                if state.statx_buf.stx_mask & 0x0010 != 0 {
                    // STATX_GID
                    if state.statx_buf.stx_gid == crate::sys::getuid() {
                        state.statx_buf.stx_gid = self.config.sgid;
                        state.updated_stats = true;
                    }
                }
                0
            }

            _ => 0,
        }
    }

    pub fn filtered_sysnums(&self) -> &'static [(Sysnum, Word)] {
        FILTERED_SYSNUMS
    }

    pub fn clone_for_child(&self, _clone_flags: Word) -> Self {
        FakeId0 {
            config: self.config.clone(),
        }
    }
}

/// `filtered_sysnums[]` — all syscalls this extension wants delivered under
/// seccomp (all use FILTER_SYSEXIT except sendmsg).
const FSE: Word = crate::syscall::seccomp::FILTER_SYSEXIT;
static FILTERED_SYSNUMS: &[(Sysnum, Word)] = &[
    (Sysnum::capset, FSE),
    (Sysnum::chmod, FSE),
    (Sysnum::chown, FSE),
    (Sysnum::chown32, FSE),
    (Sysnum::chroot, FSE),
    (Sysnum::execve, FSE),
    (Sysnum::fchmod, FSE),
    (Sysnum::fchmodat, FSE),
    (Sysnum::fchown, FSE),
    (Sysnum::fchown32, FSE),
    (Sysnum::fchownat, FSE),
    (Sysnum::fstat, FSE),
    (Sysnum::fstat64, FSE),
    (Sysnum::fstatat64, FSE),
    (Sysnum::getegid, FSE),
    (Sysnum::getegid32, FSE),
    (Sysnum::geteuid, FSE),
    (Sysnum::geteuid32, FSE),
    (Sysnum::getgid, FSE),
    (Sysnum::getgid32, FSE),
    (Sysnum::getgroups, FSE),
    (Sysnum::getgroups32, FSE),
    (Sysnum::getresgid, FSE),
    (Sysnum::getresgid32, FSE),
    (Sysnum::getresuid, FSE),
    (Sysnum::getresuid32, FSE),
    (Sysnum::getuid, FSE),
    (Sysnum::getuid32, FSE),
    (Sysnum::getsockopt, FSE),
    (Sysnum::lchown, FSE),
    (Sysnum::lchown32, FSE),
    (Sysnum::lstat, FSE),
    (Sysnum::lstat64, FSE),
    (Sysnum::mknod, FSE),
    (Sysnum::mknodat, FSE),
    (Sysnum::newfstatat, FSE),
    (Sysnum::oldlstat, FSE),
    (Sysnum::oldstat, FSE),
    (Sysnum::prctl, FSE),
    (Sysnum::setfsgid, FSE),
    (Sysnum::setfsgid32, FSE),
    (Sysnum::setfsuid, FSE),
    (Sysnum::setfsuid32, FSE),
    (Sysnum::setgid, FSE),
    (Sysnum::setgid32, FSE),
    (Sysnum::setgroups, FSE),
    (Sysnum::setgroups32, FSE),
    (Sysnum::setregid, FSE),
    (Sysnum::setregid32, FSE),
    (Sysnum::setreuid, FSE),
    (Sysnum::setreuid32, FSE),
    (Sysnum::setresgid, FSE),
    (Sysnum::setresgid32, FSE),
    (Sysnum::setresuid, FSE),
    (Sysnum::setresuid32, FSE),
    (Sysnum::setuid, FSE),
    (Sysnum::setuid32, FSE),
    (Sysnum::setxattr, FSE),
    (Sysnum::setdomainname, FSE),
    (Sysnum::sethostname, FSE),
    (Sysnum::socket, FSE),
    (Sysnum::lsetxattr, FSE),
    (Sysnum::fsetxattr, FSE),
    (Sysnum::stat, FSE),
    (Sysnum::stat64, FSE),
    (Sysnum::statfs, FSE),
    (Sysnum::statfs64, FSE),
    (Sysnum::sendmsg, 0),
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;

    #[test]
    fn dtoo_otod_roundtrip() {
        assert_eq!(dtoo(0o755), 755);
        assert_eq!(dtoo(0o644), 644);
        assert_eq!(dtoo(0o777), 777);
        assert_eq!(dtoo(0), 0);
        assert_eq!(otod(755), 0o755);
        assert_eq!(otod(644), 0o644);
        assert_eq!(otod(0), 0);
        for m in [0o1, 0o644, 0o755, 0o777, 0o4755, 0o1777] {
            assert_eq!(otod(dtoo(m)), m, "roundtrip {m:o}");
        }
    }

    #[test]
    fn get_name_last_component() {
        assert_eq!(get_name(b"/a/b/c"), b"c");
        assert_eq!(get_name(b"/a"), b"a");
        assert_eq!(get_name(b"file"), b"file");
        assert_eq!(get_name(b"/a/b/"), b"");
        assert_eq!(get_name(b"/"), b"");
        assert_eq!(get_name(b""), b"");
    }

    #[test]
    fn get_dir_path_strips_last() {
        assert_eq!(get_dir_path(b"/a/b/c"), b"/a/b");
        assert_eq!(get_dir_path(b"/a"), b"/");
        // Trailing slashes skipped before stripping.
        assert_eq!(get_dir_path(b"/a/b//"), b"/a");
        // Single-component and tiny paths return themselves (C parity).
        assert_eq!(get_dir_path(b"/"), b"/");
        assert_eq!(get_dir_path(b""), b"");
        assert_eq!(get_dir_path(b"x"), b"x");
    }

    #[test]
    fn get_meta_path_inserts_tag() {
        let mut m = FixedPath::new();
        get_meta_path(b"/d/f", &mut m).unwrap();
        assert_eq!(m.as_bytes(), b"/d/.proot-meta-file.f");
        // Root-level file.
        get_meta_path(b"/f", &mut m).unwrap();
        assert_eq!(m.as_bytes(), b"/.proot-meta-file.f");
    }

    #[test]
    fn meta_file_roundtrip() {
        let td = TempDir::new("meta");
        let meta = FixedPath::from_bytes(format!("{}/m", td.path().display()).as_bytes());
        let cfg = Config::default();
        // Round trip: write "750 1000 100" and read it back.
        write_meta_file(&meta, 0o750, 1000, 100, false, &cfg).unwrap();
        let (mode, owner, group) = read_meta_file(&meta, &cfg);
        assert_eq!((mode, owner, group), (0o750, 1000, 100));
    }

    #[test]
    fn meta_file_creat_applies_umask() {
        let td = TempDir::new("meta");
        let meta = FixedPath::from_bytes(format!("{}/m", td.path().display()).as_bytes());
        let cfg = Config {
            umask: 0o027,
            ..Default::default()
        };
        // 0o777 & !0o027 = 0o750.
        write_meta_file(&meta, 0o777, 1, 1, true, &cfg).unwrap();
        assert_eq!(read_meta_file(&meta, &cfg).0, 0o750);
    }

    #[test]
    fn meta_file_defaults_when_absent() {
        let td = TempDir::new("meta");
        let meta = FixedPath::from_bytes(format!("{}/absent", td.path().display()).as_bytes());
        let cfg = Config {
            euid: 1000,
            egid: 2000,
            ..Default::default()
        };
        let (mode, owner, group) = read_meta_file(&meta, &cfg);
        assert_eq!((mode, owner, group), (0o755, 1000, 2000));
    }

    #[test]
    fn meta_file_partial_parse() {
        let td = TempDir::new("meta");
        // Truncated meta file — missing fields stay at C defaults.
        td.file("m", b"640\n");
        let meta = FixedPath::from_bytes(format!("{}/m", td.path().display()).as_bytes());
        let (mode, owner, group) = read_meta_file(&meta, &Config::default());
        assert_eq!(mode, 0o640);
        assert_eq!((owner, group), (0, 0));
    }

    #[test]
    fn permissions_root_always_rw() {
        let td = TempDir::new("meta");
        td.file("m", b"000\n9999\n9999\n");
        let meta = FixedPath::from_bytes(format!("{}/m", td.path().display()).as_bytes());
        let cfg = Config {
            euid: 0,
            egid: 0,
            ..Default::default()
        };
        // Owner=9999, but emulated uid 0 -> class 0 then |6.
        let p = get_permissions(&meta, &cfg, false).unwrap();
        assert_eq!(p, 6); // mode 000 shifted to class -> 0, then |6
    }

    #[test]
    fn permissions_class_selection() {
        let td = TempDir::new("meta");
        // mode 764 (owner 7, group 6, other 4), owner 100, group 50.
        td.file("m", b"764\n100\n50\n");
        let meta = FixedPath::from_bytes(format!("{}/m", td.path().display()).as_bytes());
        // Emulated uid==owner -> owner class digit 7.
        let cfg = Config {
            euid: 100,
            egid: 1,
            ..Default::default()
        };
        assert_eq!(get_permissions(&meta, &cfg, false).unwrap() & 7, 7);
        // uid!=owner, gid==group -> group class digit 6.
        let cfg = Config {
            euid: 101,
            egid: 50,
            ..Default::default()
        };
        assert_eq!(get_permissions(&meta, &cfg, false).unwrap() & 7, 6);
        // Neither -> other class digit 4.
        let cfg = Config {
            euid: 101,
            egid: 51,
            ..Default::default()
        };
        assert_eq!(get_permissions(&meta, &cfg, false).unwrap() & 7, 4);
    }

    #[test]
    fn config_of_finds_fake_id0() {
        let mut t = crate::tracee::Tracee::default();
        assert!(config_of(&t).is_none());
        let _ = crate::extension::initialize_extension(
            &mut t,
            crate::extension::AnyExtension::FakeId0(Default::default()),
            "0:0",
        );
        let c = config_of(&t).unwrap();
        assert_eq!(c.euid, 0);
        assert_eq!(c.umask, 0o22);
    }
}
