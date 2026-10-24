//! Tracer-side seccomp BPF filter — port of syscall/seccomp.c.
//!
//! The filter tells the kernel to stop (SECCOMP_RET_TRACE) only on syscalls
//! PRoot actually translates, letting everything else run untraced.

use crate::Word;
use crate::sysnum::{Sysnum, detranslate_sysnum};

/// Flags attached to filtered syscalls (readable via PTRACE_GETEVENTMSG).
pub const FILTER_SYSEXIT: Word = 0x1;

const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

const SECCOMP_RET_KILL: u32 = 0x0000_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_TRACE: u32 = 0x7ff0_0000;

const PR_SET_NO_NEW_PRIVS: i32 = 38;
const PR_SET_SECCOMP: i32 = 22;
const SECCOMP_MODE_FILTER: u64 = 2;

/// `struct sock_filter`.
#[derive(Copy, Clone, Default)]
#[repr(C)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

fn stmt(code: u16, k: u32) -> SockFilter {
    SockFilter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jump(code: u16, k: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter { code, jt, jf, k }
}

/// A filtered syscall + flag (C `FilteredSysnum`).
#[derive(Copy, Clone)]
struct FilteredSysnum {
    value: Sysnum,
    flags: Word,
}

/// `proot_sysnums[]` — every syscall PRoot translates (must match
/// enter.c/exit.c coverage).
static PROOT_SYSNUMS: &[FilteredSysnum] = &[
    FilteredSysnum {
        value: Sysnum::accept,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::accept4,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::access,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::acct,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::bind,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::brk,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::chdir,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::chmod,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::chown,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::chown32,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::chroot,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::clone,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::clone3,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::close,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::connect,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::creat,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::recvfrom,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::recvmsg,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::sendmsg,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::sendto,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::socket,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::execve,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::execveat,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::faccessat,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::faccessat2,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::fchdir,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::fchmodat,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::fchownat,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::fstatat64,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::futimesat,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::getcwd,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::getpeername,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::getsockname,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::getxattr,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::inotify_add_watch,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::ioctl,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::lchown,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::lchown32,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::lgetxattr,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::link,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::linkat,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::listxattr,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::llistxattr,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::lremovexattr,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::lsetxattr,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::lstat,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::lstat64,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::memfd_create,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::mkdir,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::mkdirat,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::mknod,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::mknodat,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::mount,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::name_to_handle_at,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::newfstatat,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::oldlstat,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::oldstat,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::open,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::openat,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::openat2,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::pivot_root,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::prctl,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::prlimit64,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::ptrace,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::readlink,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::readlinkat,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::removexattr,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::rename,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::renameat,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::renameat2,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::rmdir,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::setrlimit,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::setxattr,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::socketcall,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::stat,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::stat64,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::statfs,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::statfs64,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::statx,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::swapoff,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::swapon,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::symlink,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::symlinkat,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::truncate,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::truncate64,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::umount,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::umount2,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::uname,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::unshare,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::setns,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::unlink,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::unlinkat,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::uselib,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::utime,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::utimensat,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::utimes,
        flags: 0,
    },
    FilteredSysnum {
        value: Sysnum::wait4,
        flags: FILTER_SYSEXIT,
    },
    FilteredSysnum {
        value: Sysnum::waitpid,
        flags: FILTER_SYSEXIT,
    },
];

/// `merge_filtered_sysnums()`.
fn merge_filtered_sysnums(list: &mut Vec<FilteredSysnum>, new: &[FilteredSysnum]) {
    for n in new {
        match list.iter_mut().find(|e| e.value == n.value) {
            Some(e) => e.flags |= n.flags,
            None => list.push(*n),
        }
    }
}

/// `start_arch_section()` — per-arch dispatch: check `seccomp_data.arch`,
/// then load `nr`.
fn start_arch_section(prog: &mut Vec<SockFilter>, arch: u32, nb_traced: usize) {
    let arch_offset = 4u32; // offsetof(seccomp_data, arch)
    let nr_offset = 0u32; // offsetof(seccomp_data, nr)
    let section_length = 1 + nb_traced * 2; // END + trace stmts

    prog.push(stmt(BPF_LD + BPF_W + BPF_ABS, arch_offset));
    prog.push(jump(BPF_JMP + BPF_JEQ + BPF_K, arch, 1, 0));
    prog.push(stmt(
        BPF_JMP + 0x20 /* JA */ + BPF_K,
        (section_length + 1) as u32,
    ));
    prog.push(stmt(BPF_LD + BPF_W + BPF_ABS, nr_offset));
}

/// `end_arch_section()` — allow everything not matched.
fn end_arch_section(prog: &mut Vec<SockFilter>) {
    prog.push(stmt(BPF_RET + BPF_K, SECCOMP_RET_ALLOW));
}

fn add_trace_syscall(prog: &mut Vec<SockFilter>, syscall: Word, flag: Word) {
    if syscall > u32::MAX as Word {
        return;
    }
    prog.push(jump(BPF_JMP + BPF_JEQ + BPF_K, syscall as u32, 0, 1));
    prog.push(stmt(BPF_RET + BPF_K, SECCOMP_RET_TRACE + flag as u32));
}

/// `set_seccomp_filters()` — build & install:
/// for each arch { if arch → for each sysnum → trace }, else allow; kill
/// as the final catch-all.
fn set_seccomp_filters(sysnums: &[FilteredSysnum]) -> i32 {
    // (audit arch, [abis]) — e.g. x86_64 hosts trace x86_64+x32 under
    // AUDIT_ARCH_X86_64, i386 under AUDIT_ARCH_I386.
    let archs = crate::arch::SECCOMP_ARCHS.iter().map(|a| (a.value, a.abis));

    let mut prog: Vec<SockFilter> = Vec::new();

    for (arch, abis) in archs {
        let mut nb_traced = 0usize;
        for abi in abis {
            for s in sysnums {
                if detranslate_sysnum(*abi, s.value) != crate::arch::SYSCALL_AVOIDER {
                    nb_traced += 1;
                }
            }
        }

        start_arch_section(&mut prog, arch, nb_traced);
        for abi in abis {
            for s in sysnums {
                let syscall = detranslate_sysnum(*abi, s.value);
                if syscall == crate::arch::SYSCALL_AVOIDER {
                    continue;
                }
                add_trace_syscall(&mut prog, syscall, s.flags);
            }
        }
        end_arch_section(&mut prog);
    }

    prog.push(stmt(BPF_RET + BPF_K, SECCOMP_RET_KILL));

    let mut fprog = libc::sock_fprog {
        len: prog.len() as u16,
        filter: prog.as_ptr() as *const _ as *mut libc::sock_filter,
    };

    if crate::sys::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 {
        return -crate::sys::errno();
    }
    if crate::sys::prctl(
        PR_SET_SECCOMP,
        SECCOMP_MODE_FILTER as usize,
        &mut fprog as *mut _ as usize,
        0,
        0,
    ) < 0
    {
        return -crate::sys::errno();
    }
    0
}

/// `enable_syscall_filtering()` — merge PRoot's sysnums with the ones the
/// tracee's extensions need, then install the filter (called in the child
/// before exec).
pub fn enable_syscall_filtering(tracee: &crate::tracee::Tracee) -> i32 {
    let mut filtered = Vec::new();
    merge_filtered_sysnums(&mut filtered, PROOT_SYSNUMS);
    for ext in tracee.extensions.iter().flatten() {
        let tmp: Vec<FilteredSysnum> = ext
            .filtered_sysnums()
            .iter()
            .map(|&(value, flags)| FilteredSysnum { value, flags })
            .collect();
        merge_filtered_sysnums(&mut filtered, &tmp);
    }
    set_seccomp_filters(&filtered)
}

/// `filtered_sysnum_flags()` — flags the installed filter attaches to
/// @sysnum's PTRACE_EVENT_SECCOMP stops.
pub fn filtered_sysnum_flags(tracee: &crate::tracee::Tracee, sysnum: Sysnum) -> Word {
    let mut flags: Word = 0;
    for s in PROOT_SYSNUMS {
        if s.value == sysnum {
            flags |= s.flags;
        }
    }
    for ext in tracee.extensions.iter().flatten() {
        for &(value, f) in ext.filtered_sysnums() {
            if value == sysnum {
                flags |= f;
            }
        }
    }
    flags
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stmt_and_jump_layout() {
        let s = stmt(BPF_LD, 42);
        assert_eq!((s.code, s.jt, s.jf, s.k), (BPF_LD, 0, 0, 42));
        let j = jump(BPF_JMP, 7, 1, 2);
        assert_eq!((j.code, j.jt, j.jf, j.k), (BPF_JMP, 1, 2, 7));
        assert_eq!(size_of::<SockFilter>(), 8);
    }

    #[test]
    fn merge_filtered_sysnums_or_flags() {
        let mut list: Vec<FilteredSysnum> = Vec::new();
        let a = FilteredSysnum {
            value: Sysnum::openat,
            flags: 1,
        };
        let b = FilteredSysnum {
            value: Sysnum::read,
            flags: 2,
        };
        merge_filtered_sysnums(&mut list, &[a, b]);
        assert_eq!(list.len(), 2);
        // Merging the same sysnum again ORs the flags in place.
        let a2 = FilteredSysnum {
            value: Sysnum::openat,
            flags: 4,
        };
        merge_filtered_sysnums(&mut list, &[a2]);
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].flags, 1 | 4);
        assert_eq!(list[1].flags, 2);
    }
}
