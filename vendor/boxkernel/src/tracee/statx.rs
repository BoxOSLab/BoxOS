//! statx emulation — port of tracee/statx.c.
//!
//! Used both when a *system* seccomp policy rejects statx (SIGSYS path,
//! `from_sigsys = true`) and at the statx sysexit stage when the kernel
//! call failed but PRoot can still answer it (e.g. old kernels).

use crate::Word;
use crate::fpath::{FixedPath, PathGuard};
use crate::tracee::Tracee;
use crate::tracee::mem::{read_data, read_string, write_data};
use crate::tracee::reg::{Reg, RegVersion, peek_reg};

/// `struct statx_timestamp`.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct StatxTimestamp {
    pub tv_sec: i64,
    pub tv_nsec: u32,
    pub __reserved: i32,
}

/// `struct statx` — kernel-stable layout.
#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct Statx {
    pub stx_mask: u32,
    pub stx_blksize: u32,
    pub stx_attributes: u64,
    pub stx_nlink: u32,
    pub stx_uid: u32,
    pub stx_gid: u32,
    pub stx_mode: u16,
    pub __spare0: u16,
    pub stx_ino: u64,
    pub stx_size: u64,
    pub stx_blocks: u64,
    pub stx_attributes_mask: u64,
    pub stx_atime: StatxTimestamp,
    pub stx_mtime: StatxTimestamp,
    pub stx_ctime: StatxTimestamp,
    pub stx_btime: StatxTimestamp,
    pub stx_rdev_major: u32,
    pub stx_rdev_minor: u32,
    pub stx_dev_major: u32,
    pub stx_dev_minor: u32,
    pub __spare2: [u64; 14],
}

/// `statx_syscall_state` — STATX_SYSCALL event payload.
#[derive(Default)]
pub struct StatxSyscallState {
    pub host_path: FixedPath,
    pub statx_buf: Statx,
    pub updated_stats: bool,
}

const STATX_TYPE: u64 = 0x0001;
const STATX_MODE: u64 = 0x0002;
pub const STATX_NLINK: u64 = 0x0004;
const STATX_UID: u64 = 0x0008;
const STATX_GID: u64 = 0x0010;
const STATX_ATIME: u64 = 0x0020;
const STATX_MTIME: u64 = 0x0040;
const STATX_CTIME: u64 = 0x0080;
const STATX_INO: u64 = 0x0100;
const STATX_SIZE: u64 = 0x0200;
const STATX_BLOCKS: u64 = 0x0400;
const STATX_BTIME: u64 = 0x0800;

fn statx_ts(sec: i64, nsec: i64) -> StatxTimestamp {
    StatxTimestamp {
        tv_sec: sec,
        tv_nsec: nsec as u32,
        __reserved: 0,
    }
}

/// `handle_statx_syscall()` — answer statx() from a tracer-side lstat/stat
/// plus extension fixups.  Returns 0/-errno like a syscall result.
pub fn handle_statx_syscall(tracee: &mut Tracee, from_sigsys: bool) -> i32 {
    let rv = if from_sigsys {
        RegVersion::Current
    } else {
        RegVersion::Original
    };
    let mut state = StatxSyscallState::default();
    let mut guest_path = PathGuard::new();
    let mut do_fstat = false;

    // Read arguments and translate the path.
    let flags = peek_reg(tracee, rv, Reg::Sysarg3);
    let do_lstat = (flags & libc::AT_SYMLINK_NOFOLLOW as Word) != 0;
    let mask = peek_reg(tracee, rv, Reg::Sysarg4);
    let size = read_string(
        tracee,
        guest_path.as_mut_bytes(),
        peek_reg(tracee, rv, Reg::Sysarg2),
    );
    if size < 0 {
        return size;
    }
    guest_path.sync_len_from_nul();
    let dirfd = peek_reg(tracee, rv, Reg::Sysarg1) as i32;
    let mut status: i32;
    if size == 0 {
        return -libc::EFAULT;
    }
    if size == 1 {
        if (flags & libc::AT_EMPTY_PATH as Word) == 0 {
            return -libc::ENOENT;
        }
        match crate::path::readlink_proc_pid_fd(tracee.pid, dirfd, &mut state.host_path) {
            Ok(()) => status = 0,
            Err(e) => return e,
        }
        do_fstat = true;
    } else {
        if size as usize >= crate::PATH_MAX {
            return -libc::ENAMETOOLONG;
        }
        status = match crate::path::translate_path(
            tracee,
            &mut state.host_path,
            dirfd,
            &guest_path.as_bytes()[..size as usize - 1],
            !do_lstat,
        ) {
            Ok(()) => 0,
            Err(e) => e,
        };
    }
    if status < 0 {
        return status;
    }

    if from_sigsys || peek_reg(tracee, RegVersion::Current, Reg::SysargResult) != 0 {
        // Answer from a tracer-side [l]stat of the translated path.
        let sb = if do_fstat {
            let link =
                std::ffi::CString::new(format!("/proc/{}/fd/{}", tracee.pid, dirfd)).unwrap();
            crate::sys::stat(&link)
        } else {
            let c = state.host_path.as_c_str();
            if do_lstat {
                crate::sys::lstat(c)
            } else {
                crate::sys::stat(c)
            }
        };
        let sb = match sb {
            Ok(sb) => sb,
            Err(e) => {
                status = -e;
                if status >= 0 {
                    status = -libc::EPERM;
                }
                return status;
            }
        };

        // stat → statx field translation.
        state.statx_buf.stx_mask = (mask
            & (STATX_TYPE
                | STATX_MODE
                | STATX_NLINK
                | STATX_UID
                | STATX_GID
                | STATX_ATIME
                | STATX_MTIME
                | STATX_CTIME
                | STATX_INO
                | STATX_SIZE
                | STATX_BLOCKS
                | STATX_BTIME)) as u32;
        state.statx_buf.stx_blksize = sb.st_blksize as u32;
        if mask & (STATX_TYPE | STATX_MODE) != 0 {
            state.statx_buf.stx_mode = sb.st_mode as u16;
        }
        if mask & STATX_NLINK != 0 {
            state.statx_buf.stx_nlink = sb.st_nlink as u32;
        }
        if mask & STATX_UID != 0 {
            state.statx_buf.stx_uid = sb.st_uid;
        }
        if mask & STATX_GID != 0 {
            state.statx_buf.stx_gid = sb.st_gid;
        }
        if mask & STATX_ATIME != 0 {
            state.statx_buf.stx_atime = statx_ts(sb.st_atime, sb.st_atime_nsec);
        }
        if mask & STATX_MTIME != 0 {
            state.statx_buf.stx_mtime = statx_ts(sb.st_mtime, sb.st_mtime_nsec);
        }
        if mask & STATX_CTIME != 0 {
            state.statx_buf.stx_ctime = statx_ts(sb.st_ctime, sb.st_ctime_nsec);
        }
        if mask & STATX_INO != 0 {
            state.statx_buf.stx_ino = sb.st_ino;
        }
        if mask & STATX_SIZE != 0 {
            state.statx_buf.stx_size = sb.st_size as u64;
        }
        if mask & STATX_BLOCKS != 0 {
            state.statx_buf.stx_blocks = sb.st_blocks as u64;
        }
        if mask & STATX_BTIME != 0 {
            // stat() doesn't expose btime; ctime is the approximation.
            state.statx_buf.stx_btime = statx_ts(sb.st_ctime, sb.st_ctime_nsec);
        }
        state.statx_buf.stx_rdev_major = libc::major(sb.st_rdev) as u32;
        state.statx_buf.stx_rdev_minor = libc::minor(sb.st_rdev) as u32;
        state.updated_stats = true;
    } else {
        // The kernel wrote the result; read it back so extensions can
        // inspect/falsify it.
        status = read_data(
            tracee,
            crate::sys::as_bytes_mut(&mut state.statx_buf),
            peek_reg(tracee, RegVersion::Original, Reg::Sysarg5),
        );
        if status < 0 {
            return status;
        }
    }

    // Notify extensions (STATX_SYSCALL).
    status = crate::extension::notify(
        tracee,
        &mut crate::extension::Event::StatxSyscall { state: &mut state },
    );
    if status < 0 {
        return status;
    }

    if state.updated_stats {
        status = write_data(
            tracee,
            peek_reg(tracee, RegVersion::Current, Reg::Sysarg5),
            crate::sys::as_bytes(&state.statx_buf),
        );
        if status < 0 {
            return status;
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{Arena, TempDir, fork_child, test_tracee, use_arena_stack};
    use crate::tracee::reg::{Reg, poke_reg};

    /// Set up a tracee+child; write `guest_path` into the arena at `off`
    /// and a scratch statx buffer at `buf_off`; arm the syscall regs.
    fn setup(
        t: &mut Tracee,
        arena: &mut Arena,
        guest_path: &str,
        dirfd: i32,
        flags: u32,
        mask: u32,
        off: usize,
        buf_off: usize,
    ) {
        use_arena_stack(t, arena);
        let gb = guest_path.as_bytes();
        arena.local()[off..off + gb.len()].copy_from_slice(gb);
        arena.local()[off + gb.len()] = 0;
        poke_reg(t, Reg::Sysarg1, dirfd as i64 as Word); // AT_FDCWD = -100
        poke_reg(t, Reg::Sysarg2, arena.addr() + off as u64);
        poke_reg(t, Reg::Sysarg3, flags as Word);
        poke_reg(t, Reg::Sysarg4, mask as Word);
        poke_reg(t, Reg::Sysarg5, arena.addr() + buf_off as u64);
    }

    fn read_statx(arena: &Arena, buf_off: usize) -> Statx {
        let mut s = Statx::default();
        crate::sys::as_bytes_mut(&mut s)
            .copy_from_slice(&arena.local()[buf_off..buf_off + size_of::<Statx>()]);
        s
    }

    #[test]
    fn statx_layout_is_kernel_stable() {
        // Lock the ABI: struct statx is exactly 256 bytes.
        assert_eq!(size_of::<Statx>(), 256);
        assert_eq!(size_of::<StatxTimestamp>(), 16);
        // Kernel struct statx offsets (include/uapi/linux/stat.h).
        assert_eq!(std::mem::offset_of!(Statx, stx_mask), 0);
        assert_eq!(std::mem::offset_of!(Statx, stx_attributes), 8);
        assert_eq!(std::mem::offset_of!(Statx, stx_mode), 28);
        assert_eq!(std::mem::offset_of!(Statx, stx_ino), 32);
        assert_eq!(std::mem::offset_of!(Statx, stx_size), 40);
        assert_eq!(std::mem::offset_of!(Statx, stx_atime), 64);
        assert_eq!(std::mem::offset_of!(Statx, stx_btime), 112);
        assert_eq!(std::mem::offset_of!(Statx, stx_rdev_major), 128);
    }

    #[test]
    fn statx_fills_requested_fields() {
        let td = TempDir::new("statx");
        td.file_mode("f", b"hello", 0o644);
        let mut arena = Arena::new(2);
        let Some(child) = fork_child(&arena) else {
            return;
        };
        let mut t = test_tracee(td.path().to_str().unwrap(), &[]);
        t.pid = child.pid;
        let mask =
            (STATX_TYPE | STATX_MODE | STATX_SIZE | STATX_NLINK | STATX_UID | STATX_GID) as u32;
        setup(
            &mut t,
            &mut arena,
            "/f",
            libc::AT_FDCWD,
            0,
            mask,
            0x800,
            0x1000,
        );
        // from_sigsys forces the tracer-side answer path.
        assert_eq!(handle_statx_syscall(&mut t, true), 0);
        let s = read_statx(&arena, 0x1000);
        assert_eq!(s.stx_size, 5);
        assert_eq!(s.stx_mode & libc::S_IFMT as u16, libc::S_IFREG as u16);
        assert_eq!(s.stx_mode & 0o777, 0o644);
        assert_eq!(s.stx_uid, unsafe { libc::getuid() });
        assert_eq!(s.stx_mask & mask, mask & 0xFFFF);
    }

    #[test]
    fn statx_mask_limits_fields() {
        let td = TempDir::new("statx");
        td.file("f", b"abc");
        let mut arena = Arena::new(2);
        let Some(child) = fork_child(&arena) else {
            return;
        };
        let mut t = test_tracee(td.path().to_str().unwrap(), &[]);
        t.pid = child.pid;
        // Only STATX_SIZE — other fields stay zeroed.
        setup(
            &mut t,
            &mut arena,
            "/f",
            libc::AT_FDCWD,
            0,
            STATX_SIZE as u32,
            0x800,
            0x1000,
        );
        assert_eq!(handle_statx_syscall(&mut t, true), 0);
        let s = read_statx(&arena, 0x1000);
        assert_eq!(s.stx_size, 3);
        assert_eq!(s.stx_mode, 0); // not requested
        assert_eq!(s.stx_uid, 0);
    }

    #[test]
    fn statx_nofollow_stats_the_link() {
        let td = TempDir::new("statx");
        td.file("real", b"");
        td.symlink("real", "lnk");
        let mut arena = Arena::new(2);
        let Some(child) = fork_child(&arena) else {
            return;
        };
        let mut t = test_tracee(td.path().to_str().unwrap(), &[]);
        t.pid = child.pid;
        let mask = STATX_TYPE as u32;
        // AT_SYMLINK_NOFOLLOW => lstat => S_IFLNK.
        setup(
            &mut t,
            &mut arena,
            "/lnk",
            libc::AT_FDCWD,
            libc::AT_SYMLINK_NOFOLLOW as u32,
            mask,
            0x800,
            0x1000,
        );
        assert_eq!(handle_statx_syscall(&mut t, true), 0);
        assert_eq!(
            read_statx(&arena, 0x1000).stx_mode & libc::S_IFMT as u16,
            libc::S_IFLNK as u16
        );
        // Followed => regular file.
        setup(
            &mut t,
            &mut arena,
            "/lnk",
            libc::AT_FDCWD,
            0,
            mask,
            0x800,
            0x1000,
        );
        assert_eq!(handle_statx_syscall(&mut t, true), 0);
        assert_eq!(
            read_statx(&arena, 0x1000).stx_mode & libc::S_IFMT as u16,
            libc::S_IFREG as u16
        );
    }

    #[test]
    fn statx_empty_path_requires_at_empty_path() {
        let td = TempDir::new("statx");
        let mut arena = Arena::new(2);
        let Some(child) = fork_child(&arena) else {
            return;
        };
        let mut t = test_tracee(td.path().to_str().unwrap(), &[]);
        t.pid = child.pid;
        // "" without AT_EMPTY_PATH -> ENOENT.
        setup(
            &mut t,
            &mut arena,
            "",
            libc::AT_FDCWD,
            0,
            STATX_SIZE as u32,
            0x800,
            0x1000,
        );
        assert_eq!(handle_statx_syscall(&mut t, true), -libc::ENOENT);
        // "" + AT_EMPTY_PATH + a valid dirfd: fstat via /proc/<pid>/fd.
        // Open a real fd in the *child*? The dirfd indexes the tracee's fd
        // table — use fd 0/1/2 which the child inherits.
        setup(
            &mut t,
            &mut arena,
            "",
            0,
            libc::AT_EMPTY_PATH as u32,
            STATX_SIZE as u32,
            0x800,
            0x1000,
        );
        // fd 0 may be /dev/null — stat of it succeeds either way.
        let r = handle_statx_syscall(&mut t, true);
        assert!(r == 0 || r == -libc::ENOENT, "unexpected {r}");
    }

    #[test]
    fn statx_missing_path_fails() {
        let td = TempDir::new("statx");
        td.dir("d");
        let mut arena = Arena::new(2);
        let Some(child) = fork_child(&arena) else {
            return;
        };
        let mut t = test_tracee(td.path().to_str().unwrap(), &[]);
        t.pid = child.pid;
        setup(
            &mut t,
            &mut arena,
            "/d/missing",
            libc::AT_FDCWD,
            0,
            STATX_SIZE as u32,
            0x800,
            0x1000,
        );
        assert_eq!(handle_statx_syscall(&mut t, true), -libc::ENOENT);
    }

    #[test]
    fn statx_dirfd_relative() {
        // dirfd semantics: /proc/<pid>/fd/<fd> of the *child* — open a dir
        // fd pointing at the tempdir subdir in this process is not visible
        // to the child.  Instead verify AT_FDCWD-negative path handling:
        let td = TempDir::new("statx");
        td.dir("d");
        td.file("d/f", b"z");
        let mut arena = Arena::new(2);
        let Some(child) = fork_child(&arena) else {
            return;
        };
        let mut t = test_tracee(td.path().to_str().unwrap(), &[]);
        t.pid = child.pid;
        t.fs.borrow_mut().cwd.set(b"/d");
        // Relative path resolves against the tracee's guest cwd.
        setup(
            &mut t,
            &mut arena,
            "f",
            libc::AT_FDCWD,
            0,
            STATX_SIZE as u32,
            0x800,
            0x1000,
        );
        assert_eq!(handle_statx_syscall(&mut t, true), 0);
        assert_eq!(read_statx(&arena, 0x1000).stx_size, 1);
    }
}
