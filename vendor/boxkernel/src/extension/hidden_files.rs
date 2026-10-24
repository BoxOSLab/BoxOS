//! hidden_files extension — port of
//! extension/hidden_files/hidden_files.c.
//!
//! Filters getdents/getdents64 results so files with `HIDDEN_PREFIX`
//! (`.proot`) are invisible to the guest — used to hide link2symlink's
//! metadata sidecars and glue artifacts.

use crate::Word;
use crate::extension::Event;
use crate::fpath::FixedPath;
use crate::path::belongs_to_guestfs;
use crate::syscall::chain::register_chained_syscall;
use crate::syscall::seccomp::FILTER_SYSEXIT;
use crate::sysnum::Sysnum;
use crate::tracee::Tracee;
use crate::tracee::mem::{read_data, write_data};
use crate::tracee::reg::{Reg, RegVersion, get_sysnum, peek_reg, poke_reg};

const HIDDEN_PREFIX: &[u8] = b".proot";

#[derive(Default)]
pub struct HiddenFiles;

/// `handle_getdents()` — copy the getdents buffer minus hidden entries
/// back over the tracee's buffer; when nothing survives, chain another
/// getdents call instead of returning 0 bytes early.
fn handle_getdents(tracee: &mut Tracee) -> i32 {
    let sysnum = get_sysnum(tracee, RegVersion::Original);
    let is_64 = match sysnum {
        Sysnum::getdents64 => true,
        Sysnum::getdents => false,
        _ => return 0,
    };

    let res = peek_reg(tracee, RegVersion::Current, Reg::SysargResult);
    if res == 0 || (res as i64) <= 0 {
        return 0;
    }
    let res = res as usize;

    let orig_start = peek_reg(tracee, RegVersion::Current, Reg::Sysarg2);
    let count = peek_reg(tracee, RegVersion::Current, Reg::Sysarg3);

    // Only filter directories inside the guest rootfs.
    let mut path = FixedPath::new();
    let fd = peek_reg(tracee, RegVersion::Original, Reg::Sysarg1) as i32;
    if crate::path::readlink_proc_pid_fd(tracee.pid, fd, &mut path).is_err() {
        return 0;
    }
    if !belongs_to_guestfs(tracee, path.as_bytes()) {
        return 0;
    }

    let mut orig = vec![0u8; count as usize];
    if read_data(tracee, &mut orig[..res], orig_start) < 0 {
        return -libc::EIO;
    }

    // Walk dirents; copy out non-hidden ones.
    //   linux_dirent64: ino(8) off(8) reclen(2) type(1) name[]
    //   linux_dirent:   ino(8) off(8) reclen(2) name[]
    let name_off = if is_64 { 19usize } else { 18usize };
    let mut copy: Vec<u8> = Vec::with_capacity(count as usize);
    let mut ptr = 0usize;
    while ptr + 18 <= res {
        let reclen = u16::from_ne_bytes([orig[ptr + 16], orig[ptr + 17]]) as usize;
        if reclen < 18 || ptr + reclen > res {
            break;
        }
        let name = &orig[ptr + name_off..ptr + reclen];
        let name = &name[..name.iter().position(|&c| c == 0).unwrap_or(name.len())];
        if !name.starts_with(HIDDEN_PREFIX) {
            copy.extend_from_slice(&orig[ptr..ptr + reclen]);
        }
        ptr += reclen;
    }

    if copy.is_empty() {
        // Everything was hidden: re-issue the syscall for the next batch.
        let fd = peek_reg(tracee, RegVersion::Original, Reg::Sysarg1);
        let s = if is_64 {
            Sysnum::getdents64
        } else {
            Sysnum::getdents
        };
        register_chained_syscall(tracee, s, [fd, orig_start, count, 0, 0, 0]);
    } else {
        if write_data(tracee, orig_start, &copy) < 0 {
            return -libc::EIO;
        }
        poke_reg(tracee, Reg::SysargResult, copy.len() as Word);
    }
    0
}

impl HiddenFiles {
    pub fn callback(&mut self, tracee: &mut Tracee, event: &mut Event) -> i32 {
        match event {
            Event::ChainedExit | Event::SysExitEnd { .. } => handle_getdents(tracee),
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
    (Sysnum::getdents, FILTER_SYSEXIT),
    (Sysnum::getdents64, FILTER_SYSEXIT),
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{Arena, TempDir, fork_child, test_tracee, use_arena_stack};
    use crate::tracee::reg::{save_current_regs, set_sysnum};

    /// linux_dirent64: ino(8) off(8) reclen(2) type(1) name\0 (8-aligned).
    fn dirent64(name: &[u8]) -> Vec<u8> {
        let reclen = (19 + name.len() + 1 + 7) & !7;
        let mut d = vec![0u8; reclen];
        d[16..18].copy_from_slice(&(reclen as u16).to_ne_bytes());
        d[18] = libc::DT_REG;
        d[19..19 + name.len()].copy_from_slice(name);
        d
    }

    /// A tracee whose fd `fd` is a directory inside the guest rootfs.
    fn dir_tracee(td: &TempDir, arena: &Arena) -> Option<(Tracee, i32, crate::testutil::Child)> {
        // The child inherits this fd; its /proc/<pid>/fd/N resolves into
        // the guest rootfs (the root is `td` itself).
        let f = std::fs::File::open(td.path()).ok()?;
        use std::os::unix::io::AsRawFd;
        let fd = f.as_raw_fd();
        let child = fork_child(arena)?;
        std::mem::forget(f); // keep the fd open in the parent too
        let mut t = test_tracee(td.path().to_str().unwrap(), &[]);
        t.pid = child.pid;
        use_arena_stack(&mut t, arena);
        Some((t, fd, child))
    }

    fn arm_getdents(t: &mut Tracee, buf: Word, res: usize, fd: i32, count: usize) {
        set_sysnum(t, Sysnum::getdents64);
        poke_reg(t, Reg::Sysarg1, fd as Word);
        poke_reg(t, Reg::Sysarg2, buf);
        poke_reg(t, Reg::Sysarg3, count as Word);
        poke_reg(t, Reg::SysargResult, res as Word);
        save_current_regs(t, RegVersion::Original);
    }

    #[test]
    fn getdents_filters_hidden_entries() {
        let td = TempDir::new("hf");
        let arena = Arena::new(1);
        let Some((mut t, fd, _child)) = dir_tracee(&td, &arena) else {
            return;
        };
        // Buffer: [".proot-meta" hidden]["visible"]["."][..].
        let mut buf = Vec::new();
        buf.extend_from_slice(&dirent64(b".proot-meta-x"));
        buf.extend_from_slice(&dirent64(b"visible"));
        buf.extend_from_slice(&dirent64(b"."));
        let res = buf.len();
        arena.local()[0x800..0x800 + res].copy_from_slice(&buf);
        arm_getdents(&mut t, arena.addr() + 0x800, res, fd, res);
        assert_eq!(handle_getdents(&mut t), 0);
        // Result shrunk to the two surviving entries.
        let new_res = peek_reg(&t, RegVersion::Current, Reg::SysargResult) as usize;
        assert_eq!(new_res, dirent64(b"visible").len() + dirent64(b".").len());
        // Survivor names present, hidden name gone.
        let out = &arena.local()[0x800..0x800 + res];
        let names: Vec<&[u8]> = {
            let mut v = Vec::new();
            let mut p = 0usize;
            while p + 19 <= new_res {
                let rl = u16::from_ne_bytes([out[p + 16], out[p + 17]]) as usize;
                if rl < 19 || p + rl > res {
                    break;
                }
                let n = &out[p + 19..p + rl];
                v.push(&n[..n.iter().position(|&b| b == 0).unwrap_or(n.len())]);
                p += rl;
            }
            v
        };
        assert!(names.contains(&b"visible".as_ref()));
        assert!(names.contains(&b".".as_ref()));
        assert!(!names.iter().any(|n| n.starts_with(b".proot")));
    }

    #[test]
    fn getdents_all_hidden_chains_again() {
        let td = TempDir::new("hf");
        let arena = Arena::new(1);
        let Some((mut t, fd, _child)) = dir_tracee(&td, &arena) else {
            return;
        };
        let buf = dirent64(b".proot-only");
        let res = buf.len();
        arena.local()[0x800..0x800 + res].copy_from_slice(&buf);
        arm_getdents(&mut t, arena.addr() + 0x800, res, fd, res);
        assert_eq!(handle_getdents(&mut t), 0);
        // All hidden -> a follow-up getdents64 was chained.
        let chained = t.chain.syscalls.as_ref().expect("chained syscall");
        assert_eq!(chained.len(), 1);
        assert_eq!(chained[0].sysnum, Sysnum::getdents64);
    }

    #[test]
    fn getdents_unrelated_syscall_and_empty_result() {
        let td = TempDir::new("hf");
        let arena = Arena::new(1);
        let Some((mut t, fd, _child)) = dir_tracee(&td, &arena) else {
            return;
        };
        // Non-getdents syscall -> no-op.
        arm_getdents(&mut t, arena.addr() + 0x800, 10, fd, 10);
        set_sysnum(&mut t, Sysnum::getpid);
        save_current_regs(&mut t, RegVersion::Original);
        assert_eq!(handle_getdents(&mut t), 0);
        assert_eq!(peek_reg(&t, RegVersion::Current, Reg::SysargResult), 10);
        // getdents64 with 0 result -> no-op.
        arm_getdents(&mut t, arena.addr() + 0x800, 0, fd, 0);
        assert_eq!(handle_getdents(&mut t), 0);
    }
}
