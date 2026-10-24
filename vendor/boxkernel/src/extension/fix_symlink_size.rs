//! fix_symlink_size extension — port of
//! extension/fix_symlink_size/fix_symlink_size.c.
//!
//! link2symlink's fake hard links are real symlinks on the host; lstat()
//! on them reports the target-path length, not the apparent file size.
//! This extension rewrites st_size to the symlink target length so the
//! fake link looks like the real file.
//!
//! Besides lstat/lstat64 it covers the forms lstat() takes on the way to
//! the kernel where those don't exist (arm64) or aren't used by the libc:
//! `newfstatat(…, AT_SYMLINK_NOFOLLOW)` and `statx(…, AT_SYMLINK_NOFOLLOW)`.

use crate::PATH_MAX;
use crate::Word;
use crate::extension::Event;
use crate::syscall::seccomp::FILTER_SYSEXIT;
use crate::sysnum::Sysnum;
use crate::tracee::Tracee;
use crate::tracee::mem::{read_data, read_string, write_data};
use crate::tracee::reg::{Reg, RegVersion, get_sysnum, peek_reg};

#[derive(Default)]
pub struct FixSymlinkSize;

/// Where a stat-like syscall keeps its path and its output buffer.
enum StatCall {
    /// `struct stat` filled by lstat()/newfstatat().
    Stat { path: Reg, buf: Reg },
    /// `struct statx` filled by statx().
    Statx { path: Reg, buf: Reg },
}

/// Offset of `stx_size` in `struct statx` (stable kernel ABI).
const STATX_SIZE_OFFSET: Word = 40;

fn nofollow(tracee: &Tracee, flags: Reg) -> bool {
    peek_reg(tracee, RegVersion::Original, flags) & libc::AT_SYMLINK_NOFOLLOW as Word != 0
}

/// `handle_sysexit_end()` — after a successful lstat on a symlink, set
/// `st_size` to the length of its target.
fn handle_sysexit_end(tracee: &mut Tracee) -> i32 {
    let call = match get_sysnum(tracee, RegVersion::Original) {
        Sysnum::lstat | Sysnum::lstat64 => StatCall::Stat {
            path: Reg::Sysarg1,
            buf: Reg::Sysarg2,
        },
        // newfstatat(dirfd, path, buf, flags)
        Sysnum::newfstatat if nofollow(tracee, Reg::Sysarg4) => StatCall::Stat {
            path: Reg::Sysarg2,
            buf: Reg::Sysarg3,
        },
        // statx(dirfd, path, flags, mask, buf)
        Sysnum::statx if nofollow(tracee, Reg::Sysarg3) => StatCall::Statx {
            path: Reg::Sysarg2,
            buf: Reg::Sysarg5,
        },
        _ => return 0,
    };
    let (sysarg_path, sysarg_buf) = match call {
        StatCall::Stat { path, buf } | StatCall::Statx { path, buf } => (path, buf),
    };

    // Override only on success.
    if peek_reg(tracee, RegVersion::Current, Reg::SysargResult) != 0 {
        return 0;
    }

    // Read the (translated) host path — link2symlink will already have
    // resolved any fake hard link, so a symlink here is a real one.
    let mut original = [0u8; PATH_MAX];
    let size = read_string(
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
    // An empty path (AT_EMPTY_PATH) stat'ed a file descriptor, not a link.
    if size <= 1 {
        return 0;
    }
    // `size` includes the terminator read_string wrote.
    let path = std::ffi::CStr::from_bytes_with_nul(&original[..size as usize]).unwrap_or_default();

    // Not a link → nothing to fix.
    let statl = match crate::sys::lstat(path) {
        Ok(s) => s,
        Err(e) => return -e,
    };
    if (statl.st_mode & libc::S_IFMT) != libc::S_IFLNK {
        return 0;
    }

    let mut target = [0u8; PATH_MAX];
    let size = crate::sys::readlink(path, &mut target);
    if size < 0 {
        return -crate::sys::errno();
    }

    // Overwrite st_size with the target length.
    let stat_addr = peek_reg(tracee, RegVersion::Original, sysarg_buf);
    if let StatCall::Statx { .. } = call {
        if write_data(
            tracee,
            stat_addr + STATX_SIZE_OFFSET,
            &(size as u64).to_ne_bytes(),
        ) < 0
        {
            return -libc::EIO;
        }
        return 0;
    }
    let mut st: libc::stat = crate::sys::zeroed();
    if read_data(tracee, crate::sys::as_bytes_mut(&mut st), stat_addr) < 0 {
        return 0;
    }
    st.st_size = size as i64;
    if write_data(tracee, stat_addr, crate::sys::as_bytes(&st)) < 0 {
        return -libc::EIO;
    }
    0
}

impl FixSymlinkSize {
    pub fn callback(&mut self, tracee: &mut Tracee, event: &mut Event) -> i32 {
        match event {
            Event::SysExitEnd { .. } => handle_sysexit_end(tracee),
            _ => 0,
        }
    }
    pub fn filtered_sysnums(&self) -> &'static [(Sysnum, Word)] {
        FILTERED_SYSNUMS
    }
    pub fn clone_for_child(&self, _clone_flags: Word) -> Self {
        Self
    }
}

static FILTERED_SYSNUMS: &[(Sysnum, Word)] = &[
    (Sysnum::lstat, FILTER_SYSEXIT),
    (Sysnum::lstat64, FILTER_SYSEXIT),
    (Sysnum::newfstatat, FILTER_SYSEXIT),
    (Sysnum::statx, FILTER_SYSEXIT),
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{Arena, TempDir, fork_child, test_tracee, use_arena_stack};
    use crate::tracee::reg::{poke_reg, save_current_regs, set_sysnum};

    /// The flavours of lstat() the extension recognizes.
    #[derive(Copy, Clone)]
    enum Kind {
        /// lstat(path, buf) — x86 only, arm64 has no such syscall.
        #[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
        Lstat,
        /// newfstatat(AT_FDCWD, path, buf, flags)
        Fstatat { flags: Word },
        /// statx(AT_FDCWD, path, flags, mask, buf)
        Statx { flags: Word },
    }

    const NOFOLLOW: Word = libc::AT_SYMLINK_NOFOLLOW as Word;

    /// Arm a synthetic successful stat call: path ptr + output buffer in
    /// the arena.  Returns the buffer offset.
    fn setup(t: &mut Tracee, arena: &mut Arena, host_path: &[u8], kind: Kind) -> usize {
        use_arena_stack(t, arena);
        let poff = 0x800usize;
        arena.local()[poff..poff + host_path.len()].copy_from_slice(host_path);
        arena.local()[poff + host_path.len()] = 0;
        let soff = 0x1000usize;
        let path = arena.addr() + poff as u64;
        let buf = arena.addr() + soff as u64;
        // Current bank holds result=0 + args; snapshot into the banks the
        // handler reads: Modified (path), Original (sysnum, flags, buf).
        match kind {
            Kind::Lstat => {
                set_sysnum(t, Sysnum::lstat);
                poke_reg(t, Reg::Sysarg1, path);
                poke_reg(t, Reg::Sysarg2, buf);
            }
            Kind::Fstatat { flags } => {
                set_sysnum(t, Sysnum::newfstatat);
                poke_reg(t, Reg::Sysarg2, path);
                poke_reg(t, Reg::Sysarg3, buf);
                poke_reg(t, Reg::Sysarg4, flags);
            }
            Kind::Statx { flags } => {
                set_sysnum(t, Sysnum::statx);
                poke_reg(t, Reg::Sysarg2, path);
                poke_reg(t, Reg::Sysarg3, flags);
                poke_reg(t, Reg::Sysarg4, 0x7ff); // STATX_BASIC_STATS
                poke_reg(t, Reg::Sysarg5, buf);
            }
        }
        // The result register may alias Sysarg1 (x0 on arm64): dirfd is
        // irrelevant to the handler, so set the result last.
        poke_reg(t, Reg::SysargResult, 0);
        save_current_regs(t, RegVersion::Modified);
        save_current_regs(t, RegVersion::Original);
        soff
    }

    /// A tracee in a temp dir holding `target_file` and a symlink to it.
    fn link_fixture() -> Option<(TempDir, Arena, Tracee, Vec<u8>, crate::testutil::Child)> {
        let td = TempDir::new("fixss");
        td.file("target_file", b"");
        td.symlink("target_file", "lnk");
        // Literal path — td.abs() would canonicalize the symlink away.
        let link = format!("{}/lnk", td.path().display()).into_bytes();
        let arena = Arena::new(2);
        let child = fork_child(&arena)?;
        let mut t = test_tracee(td.path().to_str().unwrap(), &[]);
        t.pid = child.pid;
        Some((td, arena, t, link, child))
    }

    fn write_stat_size(arena: &mut Arena, soff: usize, size: i64) {
        let mut st: libc::stat = crate::sys::zeroed();
        st.st_size = size;
        arena.local()[soff..soff + size_of::<libc::stat>()]
            .copy_from_slice(crate::sys::as_bytes(&st));
    }

    fn read_stat_size(arena: &Arena, soff: usize) -> i64 {
        let mut st: libc::stat = crate::sys::zeroed();
        crate::sys::as_bytes_mut(&mut st)
            .copy_from_slice(&arena.local()[soff..soff + size_of::<libc::stat>()]);
        st.st_size
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn lstat_symlink_size_becomes_target_len() {
        let Some((_td, mut arena, mut t, link, _child)) = link_fixture() else {
            return;
        };
        // Fake a successful lstat with st_size=9999.
        let soff = setup(&mut t, &mut arena, &link, Kind::Lstat);
        write_stat_size(&mut arena, soff, 9999);
        assert_eq!(handle_sysexit_end(&mut t), 0);
        // st_size now equals strlen("target_file").
        assert_eq!(read_stat_size(&arena, soff), "target_file".len() as i64);
    }

    #[test]
    fn fstatat_nofollow_symlink_size_becomes_target_len() {
        let Some((_td, mut arena, mut t, link, _child)) = link_fixture() else {
            return;
        };
        let soff = setup(&mut t, &mut arena, &link, Kind::Fstatat { flags: NOFOLLOW });
        write_stat_size(&mut arena, soff, 9999);
        assert_eq!(handle_sysexit_end(&mut t), 0);
        assert_eq!(read_stat_size(&arena, soff), "target_file".len() as i64);
    }

    #[test]
    fn fstatat_following_links_untouched() {
        let Some((_td, mut arena, mut t, link, _child)) = link_fixture() else {
            return;
        };
        // stat(), not lstat(): the kernel already followed the link.
        let soff = setup(&mut t, &mut arena, &link, Kind::Fstatat { flags: 0 });
        write_stat_size(&mut arena, soff, 9999);
        assert_eq!(handle_sysexit_end(&mut t), 0);
        assert_eq!(read_stat_size(&arena, soff), 9999);
    }

    #[test]
    fn statx_nofollow_symlink_size_becomes_target_len() {
        let Some((_td, mut arena, mut t, link, _child)) = link_fixture() else {
            return;
        };
        let soff = setup(&mut t, &mut arena, &link, Kind::Statx { flags: NOFOLLOW });
        let at = soff + STATX_SIZE_OFFSET as usize;
        arena.local()[at..at + 8].copy_from_slice(&9999u64.to_ne_bytes());
        assert_eq!(handle_sysexit_end(&mut t), 0);
        let size = u64::from_ne_bytes(arena.local()[at..at + 8].try_into().unwrap());
        assert_eq!(size, "target_file".len() as u64);
    }

    #[test]
    fn non_link_and_failure_untouched() {
        let td = TempDir::new("fixss");
        td.file("real", b"");
        let real = td.abs("real");
        let mut arena = Arena::new(2);
        let Some(child) = fork_child(&arena) else {
            return;
        };
        let mut t = test_tracee(td.path().to_str().unwrap(), &[]);
        t.pid = child.pid;
        let soff = setup(&mut t, &mut arena, &real, Kind::Fstatat { flags: NOFOLLOW });
        write_stat_size(&mut arena, soff, 4242);
        // Regular file -> st_size preserved.
        assert_eq!(handle_sysexit_end(&mut t), 0);
        assert_eq!(read_stat_size(&arena, soff), 4242);
        // Failed syscall (result != 0) -> untouched.
        poke_reg(&mut t, Reg::SysargResult, (-1i64) as Word);
        assert_eq!(handle_sysexit_end(&mut t), 0);
        // Wrong syscall -> untouched.
        set_sysnum(&mut t, Sysnum::getpid);
        save_current_regs(&mut t, RegVersion::Original);
        assert_eq!(handle_sysexit_end(&mut t), 0);
    }

    #[test]
    fn empty_path_fd_stat_untouched() {
        let td = TempDir::new("fixss");
        let mut arena = Arena::new(2);
        let Some(child) = fork_child(&arena) else {
            return;
        };
        let mut t = test_tracee(td.path().to_str().unwrap(), &[]);
        t.pid = child.pid;
        // fstatat(fd, "", buf, AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW).
        let flags = NOFOLLOW | libc::AT_EMPTY_PATH as Word;
        let soff = setup(&mut t, &mut arena, b"", Kind::Fstatat { flags });
        write_stat_size(&mut arena, soff, 77);
        assert_eq!(handle_sysexit_end(&mut t), 0);
        assert_eq!(read_stat_size(&arena, soff), 77);
    }
}
