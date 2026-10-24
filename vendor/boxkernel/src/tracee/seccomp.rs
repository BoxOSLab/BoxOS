//! Guest-side seccomp handling — port of tracee/seccomp.c.
//!
//! When a *system* seccomp policy (e.g. Android's outer sandbox) rejects a
//! syscall PRoot must translate, the tracee gets SIGSYS.  This module
//! rewrites the trapped syscall into an equivalent form the policy allows
//! (open → openat, stat → newfstatat, ...) and restarts it, or answers the
//! call itself (mount/umount/unshare emulation).

use crate::Word;
use crate::fpath::FixedPath;
use crate::path::{Comparison, compare_paths};
use crate::syscall::set_sysarg_data;
use crate::sysnum::{Sysnum, detranslate_sysnum};
use crate::tracee::Tracee;
use crate::tracee::mem::{alloc_mem, poke_word, read_data, read_string, write_data};
use crate::tracee::reg::{
    Reg, RegVersion, fetch_regs, get_abi, get_sysnum, get_systrap_size, peek_reg, poke_reg,
    push_specific_regs, save_current_regs, set_sysnum,
};

/// `restart_syscall_after_seccomp()` — rewind to the trap and re-run the
/// (rewritten) syscall so PRoot translates it on the way in.
pub fn restart_syscall_after_seccomp(tracee: &mut Tracee) {
    // Restore regs when the replaced call exits; also defers signals.
    tracee.restore_original_regs_after_seccomp_event = true;
    tracee.restart_how = crate::ptrace::ptc::PTRACE_SYSCALL;

    // Move the instruction pointer back onto the syscall trap.
    let ip = peek_reg(tracee, RegVersion::Current, Reg::InstrPointer);
    poke_reg(
        tracee,
        Reg::InstrPointer,
        ip.wrapping_sub(get_systrap_size(tracee)),
    );

    // x86: copy orig_rax back into rax (we're outside the syscall handler).
    copy_orig_to_effective(tracee);

    // Push registers (no sysnum-override path: we're queuing a new call).
    let _ = push_specific_regs(tracee, false);
}

/// `set_result_after_seccomp()` — answer the trapped syscall directly.
pub fn set_result_after_seccomp(tracee: &mut Tracee, result: Word) {
    crate::verbose!(
        Some(tracee),
        3,
        "Setting result after SIGSYS to 0x{:x}",
        result
    );
    poke_reg(tracee, Reg::SysargResult, result);
    let _ = push_specific_regs(tracee, false);
}

/// x86_64: `rax <- orig_rax` (resp. `eax <- orig_eax`); other archs no-op.
#[cfg(target_arch = "x86_64")]
fn copy_orig_to_effective(tracee: &mut Tracee) {
    // REG_OFFSET_X86_64: orig_rax (idx into Regs: 15), rax = SysargResult.
    // Use the Reg abstraction: SYSARG_RESULT == rax slot; ORIG_RAX has no
    // Reg name, write through the bank by index.
    let regs = &mut tracee.regs[RegVersion::Current.idx()];
    regs.rax = regs.orig_rax;
}

/// x86_64: `orig_rax <- rax` after a rejected syscall (kernel set it to -1).
#[cfg(target_arch = "x86_64")]
fn copy_effective_to_orig(tracee: &mut Tracee) {
    let regs = &mut tracee.regs[RegVersion::Current.idx()];
    regs.orig_rax = regs.rax;
}

/// aarch64: the syscall number lives in x8 (r7 for AArch32), which the
/// kernel leaves untouched when it rolls a trapped syscall back.
#[cfg(not(target_arch = "x86_64"))]
fn copy_orig_to_effective(_tracee: &mut Tracee) {}

#[cfg(not(target_arch = "x86_64"))]
fn copy_effective_to_orig(_tracee: &mut Tracee) {}

/// `handle_seccomp_event()` — SIGSYS raised by a system seccomp policy.
/// Returns 0 to swallow the signal, SIGSYS to deliver it.
pub fn handle_seccomp_event(tracee: &mut Tracee) -> i32 {
    // The next SIGTRAP|0x80 is a syscall entry again.
    tracee.status = 0;
    tracee.restore_original_regs = false;

    if fetch_regs(tracee) != 0 {
        crate::verbose!(Some(tracee), 1, "Couldn't fetch regs on seccomp SIGSYS");
        tracee.restore_sysarg1_after_sigsys = false;
        return libc::SIGSYS;
    }

    tracee.restore_sysarg1_after_sigsys = false;

    save_current_regs(tracee, RegVersion::OriginalSeccompRewrite);

    copy_effective_to_orig(tracee);

    crate::tracee::reg::print_current_regs(tracee, 3, "seccomp SIGSYS");

    handle_seccomp_event_common(tracee)
}

/// `fix_and_restart_enosys_syscall()` — restart a syscall that came back
/// -ENOSYS (e.g. utime on kernels that dropped it) as an equivalent call.
pub fn fix_and_restart_enosys_syscall(tracee: &mut Tracee) {
    tracee.status = 0;
    tracee.restore_original_regs = false;

    // Restore original regs, then snapshot for the rewrite.
    tracee.regs[RegVersion::Current.idx()] = tracee.regs[RegVersion::Original.idx()];
    save_current_regs(tracee, RegVersion::OriginalSeccompRewrite);

    handle_seccomp_event_common(tracee);
}

fn handle_seccomp_event_common(tracee: &mut Tracee) -> i32 {
    let status = crate::extension::notify(tracee, &mut crate::extension::Event::SigsysOcc);
    if status < 0 {
        set_result_after_seccomp(tracee, status as Word);
        return 0;
    }
    if status == 1 {
        set_result_after_seccomp(tracee, 0);
        return 0;
    }
    if status == 2 {
        return 0;
    }

    let sysnum = get_sysnum(tracee, RegVersion::Current);
    match sysnum {
        Sysnum::open => {
            set_sysnum(tracee, Sysnum::openat);
            let a3 = peek_reg(tracee, RegVersion::Current, Reg::Sysarg3);
            let a2 = peek_reg(tracee, RegVersion::Current, Reg::Sysarg2);
            let a1 = peek_reg(tracee, RegVersion::Current, Reg::Sysarg1);
            poke_reg(tracee, Reg::Sysarg4, a3);
            poke_reg(tracee, Reg::Sysarg3, a2);
            poke_reg(tracee, Reg::Sysarg2, a1);
            poke_reg(tracee, Reg::Sysarg1, libc::AT_FDCWD as Word);
            restart_syscall_after_seccomp(tracee);
        }
        Sysnum::openat2 => {
            // openat2(dirfd, path, how, size) → openat(dirfd, path,
            // how.flags, how.mode); RESOLVE_* flags dropped (PRoot already
            // confines resolution).
            let mut how = [0u8; 24];
            let mut how_size = peek_reg(tracee, RegVersion::Current, Reg::Sysarg4) as usize;
            if how_size > how.len() {
                how_size = how.len();
            }
            let ret = read_data(
                tracee,
                &mut how[..how_size],
                peek_reg(tracee, RegVersion::Current, Reg::Sysarg3),
            );
            if ret < 0 {
                set_result_after_seccomp(tracee, ret as Word);
            } else {
                set_sysnum(tracee, Sysnum::openat);
                poke_reg(
                    tracee,
                    Reg::Sysarg3,
                    u64::from_ne_bytes(how[0..8].try_into().unwrap()),
                );
                poke_reg(
                    tracee,
                    Reg::Sysarg4,
                    u64::from_ne_bytes(how[8..16].try_into().unwrap()),
                );
                restart_syscall_after_seccomp(tracee);
            }
        }
        Sysnum::accept => {
            set_sysnum(tracee, Sysnum::accept4);
            poke_reg(tracee, Reg::Sysarg4, 0);
            restart_syscall_after_seccomp(tracee);
        }
        Sysnum::setgroups | Sysnum::setgroups32 => {
            set_result_after_seccomp(tracee, 0);
        }
        Sysnum::mount => {
            crate::syscall::enter::apply_emulated_mount(tracee);
            set_result_after_seccomp(tracee, 0);
        }
        Sysnum::pivot_root => {
            crate::syscall::enter::apply_emulated_pivot_root(tracee);
            set_result_after_seccomp(tracee, 0);
        }
        Sysnum::umount | Sysnum::umount2 => {
            crate::syscall::enter::apply_emulated_umount(tracee);
            set_result_after_seccomp(tracee, 0);
        }
        Sysnum::unshare | Sysnum::setns => {
            set_result_after_seccomp(tracee, 0);
        }
        Sysnum::getpgrp => {
            let r = crate::sys::getpgid(tracee.pid);
            set_result_after_seccomp(tracee, r as Word);
        }
        Sysnum::symlink => {
            set_sysnum(tracee, Sysnum::symlinkat);
            let a2 = peek_reg(tracee, RegVersion::Current, Reg::Sysarg2);
            poke_reg(tracee, Reg::Sysarg3, a2);
            poke_reg(tracee, Reg::Sysarg2, libc::AT_FDCWD as Word);
            restart_syscall_after_seccomp(tracee);
        }
        Sysnum::link => {
            set_sysnum(tracee, Sysnum::linkat);
            let a2 = peek_reg(tracee, RegVersion::Current, Reg::Sysarg2);
            let a1 = peek_reg(tracee, RegVersion::Current, Reg::Sysarg1);
            poke_reg(tracee, Reg::Sysarg4, a2);
            poke_reg(tracee, Reg::Sysarg2, a1);
            poke_reg(tracee, Reg::Sysarg1, libc::AT_FDCWD as Word);
            poke_reg(tracee, Reg::Sysarg3, libc::AT_FDCWD as Word);
            poke_reg(tracee, Reg::Sysarg5, 0);
            restart_syscall_after_seccomp(tracee);
        }
        Sysnum::chmod => {
            set_sysnum(tracee, Sysnum::fchmodat);
            let a2 = peek_reg(tracee, RegVersion::Current, Reg::Sysarg2);
            let a1 = peek_reg(tracee, RegVersion::Current, Reg::Sysarg1);
            poke_reg(tracee, Reg::Sysarg3, a2);
            poke_reg(tracee, Reg::Sysarg2, a1);
            poke_reg(tracee, Reg::Sysarg1, libc::AT_FDCWD as Word);
            poke_reg(tracee, Reg::Sysarg4, 0);
            restart_syscall_after_seccomp(tracee);
        }
        Sysnum::chown | Sysnum::lchown | Sysnum::chown32 | Sysnum::lchown32 => {
            set_sysnum(tracee, Sysnum::fchownat);
            let a3 = peek_reg(tracee, RegVersion::Current, Reg::Sysarg3);
            let a2 = peek_reg(tracee, RegVersion::Current, Reg::Sysarg2);
            let a1 = peek_reg(tracee, RegVersion::Current, Reg::Sysarg1);
            poke_reg(tracee, Reg::Sysarg4, a3);
            poke_reg(tracee, Reg::Sysarg3, a2);
            poke_reg(tracee, Reg::Sysarg2, a1);
            poke_reg(tracee, Reg::Sysarg1, libc::AT_FDCWD as Word);
            let nofollow = sysnum == Sysnum::lchown || sysnum == Sysnum::lchown32;
            poke_reg(
                tracee,
                Reg::Sysarg5,
                if nofollow {
                    libc::AT_SYMLINK_NOFOLLOW as Word
                } else {
                    0
                },
            );
            restart_syscall_after_seccomp(tracee);
        }
        Sysnum::unlink | Sysnum::rmdir => {
            set_sysnum(tracee, Sysnum::unlinkat);
            let a1 = peek_reg(tracee, RegVersion::Current, Reg::Sysarg1);
            poke_reg(tracee, Reg::Sysarg2, a1);
            poke_reg(tracee, Reg::Sysarg1, libc::AT_FDCWD as Word);
            poke_reg(
                tracee,
                Reg::Sysarg3,
                if sysnum == Sysnum::rmdir {
                    libc::AT_REMOVEDIR as Word
                } else {
                    0
                },
            );
            restart_syscall_after_seccomp(tracee);
        }
        Sysnum::send => {
            set_sysnum(tracee, Sysnum::sendto);
            poke_reg(tracee, Reg::Sysarg5, 0);
            poke_reg(tracee, Reg::Sysarg6, 0);
            restart_syscall_after_seccomp(tracee);
        }
        Sysnum::recv => {
            set_sysnum(tracee, Sysnum::recvfrom);
            poke_reg(tracee, Reg::Sysarg5, 0);
            poke_reg(tracee, Reg::Sysarg6, 0);
            restart_syscall_after_seccomp(tracee);
        }
        Sysnum::waitpid => {
            set_sysnum(tracee, Sysnum::wait4);
            poke_reg(tracee, Reg::Sysarg4, 0);
            restart_syscall_after_seccomp(tracee);
        }
        Sysnum::statfs => {
            statfs_via_sigsys(tracee);
        }
        Sysnum::utimes => {
            // utimes(path, timeval[2]) → utimensat(AT_FDCWD, path,
            // timespec[2], 0); timeval has seconds+microseconds.
            let w = crate::tracee::reg::sizeof_word(tracee);
            let mut times_buf = [0u8; 64];
            let times = &mut times_buf[..w * 4];
            set_sysnum(tracee, Sysnum::utimensat);
            let mut ret: i64 = 0;
            if peek_reg(tracee, RegVersion::Current, Reg::Sysarg2) != 0 {
                if read_data(
                    tracee,
                    times,
                    peek_reg(tracee, RegVersion::Current, Reg::Sysarg2),
                ) < 0
                {
                    ret = -libc::EFAULT as i64;
                } else {
                    // timeval{sec,usec} ×2 → timespec{sec,nsec} ×2.
                    let mut timens_buf = [0u8; 64];
                    let timens = &mut timens_buf[..w * 4];
                    for i in 0..2 {
                        let (sec, usec) = read_2words(times, i * 2 * w, w);
                        write_2words(timens, i * 2 * w, w, sec, (usec as i64 * 1000) as u64);
                    }
                    let r = set_sysarg_data(tracee, timens, Reg::Sysarg2);
                    if r < 0 {
                        ret = r as i64;
                    }
                }
            }
            if ret < 0 {
                set_result_after_seccomp(tracee, ret as Word);
            } else {
                let a2 = peek_reg(tracee, RegVersion::Current, Reg::Sysarg2);
                let a1 = peek_reg(tracee, RegVersion::Current, Reg::Sysarg1);
                poke_reg(tracee, Reg::Sysarg4, 0);
                poke_reg(tracee, Reg::Sysarg3, a2);
                poke_reg(tracee, Reg::Sysarg2, a1);
                poke_reg(tracee, Reg::Sysarg1, libc::AT_FDCWD as Word);
                restart_syscall_after_seccomp(tracee);
            }
        }
        Sysnum::utime => {
            // utime(path, utimbuf{actime,modtime}) → utimensat(AT_FDCWD,
            // path, timespec[2]{sec,nsec=0}, 0).
            let w = crate::tracee::reg::sizeof_word(tracee);
            set_sysnum(tracee, Sysnum::utimensat);
            let mut ret: i64 = 0;
            if peek_reg(tracee, RegVersion::Current, Reg::Sysarg2) != 0 {
                let mut times_buf = [0u8; 16];
                let times = &mut times_buf[..w * 2];
                if read_data(
                    tracee,
                    times,
                    peek_reg(tracee, RegVersion::Current, Reg::Sysarg2),
                ) < 0
                {
                    ret = -libc::EFAULT as i64;
                } else {
                    let (actime, modtime) = read_2words(times, 0, w);
                    let mut timens_buf = [0u8; 64];
                    let timens = &mut timens_buf[..w * 4];
                    write_2words(timens, 0, w, actime, 0);
                    write_2words(timens, 2 * w, w, modtime, 0);
                    let r = set_sysarg_data(tracee, timens, Reg::Sysarg2);
                    if r < 0 {
                        ret = r as i64;
                    }
                }
            }
            if ret < 0 {
                set_result_after_seccomp(tracee, ret as Word);
            } else {
                let a2 = peek_reg(tracee, RegVersion::Current, Reg::Sysarg2);
                let a1 = peek_reg(tracee, RegVersion::Current, Reg::Sysarg1);
                poke_reg(tracee, Reg::Sysarg4, 0);
                poke_reg(tracee, Reg::Sysarg3, a2);
                poke_reg(tracee, Reg::Sysarg2, a1);
                poke_reg(tracee, Reg::Sysarg1, libc::AT_FDCWD as Word);
                restart_syscall_after_seccomp(tracee);
            }
        }
        Sysnum::sendmmsg => {
            // Convert to socketcall(SYS_SENDMMSG) — 32-bit bionic path.
            let w = crate::tracee::reg::sizeof_word(tracee);
            let mut args_buf = [0u8; 64];
            let args = &mut args_buf[..w * 4];
            write_word(
                args,
                0,
                w,
                peek_reg(tracee, RegVersion::Current, Reg::Sysarg1),
            );
            write_word(
                args,
                w,
                w,
                peek_reg(tracee, RegVersion::Current, Reg::Sysarg2),
            );
            write_word(
                args,
                2 * w,
                w,
                peek_reg(tracee, RegVersion::Current, Reg::Sysarg3),
            );
            write_word(
                args,
                3 * w,
                w,
                peek_reg(tracee, RegVersion::Current, Reg::Sysarg4),
            );
            let targs = alloc_mem(tracee, (w * 4) as i64);
            let _ = write_data(tracee, targs, args);
            set_sysnum(tracee, Sysnum::socketcall);
            poke_reg(tracee, Reg::Sysarg1, 19 /* SYS_SENDMMSG */ as Word);
            poke_reg(tracee, Reg::Sysarg2, targs);
            restart_syscall_after_seccomp(tracee);
        }
        Sysnum::stat | Sysnum::lstat => {
            set_sysnum(tracee, Sysnum::newfstatat);
            let nofollow = sysnum == Sysnum::lstat;
            let a2 = peek_reg(tracee, RegVersion::Current, Reg::Sysarg2);
            let a1 = peek_reg(tracee, RegVersion::Current, Reg::Sysarg1);
            poke_reg(
                tracee,
                Reg::Sysarg4,
                if nofollow {
                    libc::AT_SYMLINK_NOFOLLOW as Word
                } else {
                    0
                },
            );
            poke_reg(tracee, Reg::Sysarg3, a2);
            poke_reg(tracee, Reg::Sysarg2, a1);
            poke_reg(tracee, Reg::Sysarg1, libc::AT_FDCWD as Word);
            restart_syscall_after_seccomp(tracee);
        }
        Sysnum::pipe => {
            set_sysnum(tracee, Sysnum::pipe2);
            poke_reg(tracee, Reg::Sysarg2, 0);
            restart_syscall_after_seccomp(tracee);
        }
        Sysnum::dup2 => {
            set_sysnum(tracee, Sysnum::dup3);
            poke_reg(tracee, Reg::Sysarg3, 0);
            restart_syscall_after_seccomp(tracee);
        }
        Sysnum::access => {
            set_sysnum(tracee, Sysnum::faccessat);
            let a2 = peek_reg(tracee, RegVersion::Current, Reg::Sysarg2);
            let a1 = peek_reg(tracee, RegVersion::Current, Reg::Sysarg1);
            poke_reg(tracee, Reg::Sysarg4, 0);
            poke_reg(tracee, Reg::Sysarg3, a2);
            poke_reg(tracee, Reg::Sysarg2, a1);
            poke_reg(tracee, Reg::Sysarg1, libc::AT_FDCWD as Word);
            restart_syscall_after_seccomp(tracee);
        }
        Sysnum::mkdir => {
            set_sysnum(tracee, Sysnum::mkdirat);
            let a2 = peek_reg(tracee, RegVersion::Current, Reg::Sysarg2);
            let a1 = peek_reg(tracee, RegVersion::Current, Reg::Sysarg1);
            poke_reg(tracee, Reg::Sysarg3, a2);
            poke_reg(tracee, Reg::Sysarg2, a1);
            poke_reg(tracee, Reg::Sysarg1, libc::AT_FDCWD as Word);
            restart_syscall_after_seccomp(tracee);
        }
        Sysnum::rename => {
            set_sysnum(tracee, Sysnum::renameat);
            let a2 = peek_reg(tracee, RegVersion::Current, Reg::Sysarg2);
            let a1 = peek_reg(tracee, RegVersion::Current, Reg::Sysarg1);
            poke_reg(tracee, Reg::Sysarg4, a2);
            poke_reg(tracee, Reg::Sysarg3, libc::AT_FDCWD as Word);
            poke_reg(tracee, Reg::Sysarg2, a1);
            poke_reg(tracee, Reg::Sysarg1, libc::AT_FDCWD as Word);
            restart_syscall_after_seccomp(tracee);
        }
        Sysnum::select => {
            // select(nfds, r, w, e, timeval) → pselect6(nfds, r, w, e,
            // timespec, NULL).
            let w = crate::tracee::reg::sizeof_word(tracee);
            let timeval_arg = peek_reg(tracee, RegVersion::Current, Reg::Sysarg5);
            let mut timespec_arg: Word = 0;
            let mut fail: Option<i64> = None;
            if timeval_arg != 0 {
                let mut tv_buf = [0u8; 16];
                let tv = &mut tv_buf[..w * 2];
                if read_data(tracee, tv, timeval_arg) != 0 {
                    fail = Some(-libc::EFAULT as i64);
                } else {
                    let (sec, usec) = read_2words(tv, 0, w);
                    if usec as i64 >= 1_000_000 || (usec as i64) < 0 {
                        fail = Some(-libc::EINVAL as i64);
                    } else {
                        let mut ts_buf = [0u8; 16];
                        let ts = &mut ts_buf[..w * 2];
                        write_2words(ts, 0, w, sec, (usec as i64 * 1000) as u64);
                        timespec_arg = alloc_mem(tracee, (w * 2) as i64);
                        if write_data(tracee, timespec_arg, ts) != 0 {
                            fail = Some(-libc::EFAULT as i64);
                        }
                    }
                }
            }
            if let Some(f) = fail {
                set_result_after_seccomp(tracee, f as Word);
            } else {
                set_sysnum(tracee, Sysnum::pselect6);
                poke_reg(tracee, Reg::Sysarg5, timespec_arg);
                poke_reg(tracee, Reg::Sysarg6, 0);
                restart_syscall_after_seccomp(tracee);
            }
        }
        Sysnum::poll => {
            // poll(fds, nfds, ms) → ppoll(fds, nfds, timespec, NULL, 0).
            let w = crate::tracee::reg::sizeof_word(tracee);
            let ms_arg = peek_reg(tracee, RegVersion::Current, Reg::Sysarg3) as i64;
            let mut timespec_arg: Word = 0;
            let mut failed = false;
            if ms_arg >= 0 {
                let mut ts_buf = [0u8; 16];
                let ts = &mut ts_buf[..w * 2];
                write_2words(
                    ts,
                    0,
                    w,
                    (ms_arg / 1000) as u64,
                    ((ms_arg % 1000) * 1_000_000) as u64,
                );
                timespec_arg = alloc_mem(tracee, (w * 2) as i64);
                if write_data(tracee, timespec_arg, ts) != 0 {
                    set_result_after_seccomp(tracee, (-(libc::EFAULT as i64)) as Word);
                    failed = true;
                }
            }
            if !failed {
                set_sysnum(tracee, Sysnum::ppoll);
                poke_reg(tracee, Reg::Sysarg3, timespec_arg);
                poke_reg(tracee, Reg::Sysarg4, 0);
                poke_reg(tracee, Reg::Sysarg5, 0);
                restart_syscall_after_seccomp(tracee);
            }
        }
        Sysnum::epoll_wait => {
            set_sysnum(tracee, Sysnum::epoll_pwait);
            poke_reg(tracee, Reg::Sysarg5, 0);
            poke_reg(tracee, Reg::Sysarg6, 0);
            restart_syscall_after_seccomp(tracee);
        }
        Sysnum::time => {
            let t = crate::sys::time() as Word;
            let addr = peek_reg(tracee, RegVersion::Current, Reg::Sysarg1);
            crate::sys::clear_errno();
            if addr != 0 {
                poke_word(tracee, addr, t);
            }
            let e = crate::sys::errno();
            set_result_after_seccomp(
                tracee,
                if e != 0 {
                    (-(libc::EFAULT as i64)) as Word
                } else {
                    t
                },
            );
        }
        Sysnum::statx => {
            let r = crate::tracee::statx::handle_statx_syscall(tracee, true);
            set_result_after_seccomp(tracee, r as Word);
        }
        Sysnum::ftruncate => {
            if detranslate_sysnum(get_abi(tracee), Sysnum::ftruncate64)
                == crate::arch::SYSCALL_AVOIDER
            {
                set_result_after_seccomp(tracee, (-(libc::ENOSYS as i64)) as Word);
            } else {
                set_sysnum(tracee, Sysnum::ftruncate64);
                let a2 = peek_reg(tracee, RegVersion::Current, Reg::Sysarg2);
                poke_reg(tracee, Reg::Sysarg3, a2);
                poke_reg(tracee, Reg::Sysarg2, 0);
                poke_reg(tracee, Reg::Sysarg4, 0);
                restart_syscall_after_seccomp(tracee);
            }
        }
        Sysnum::setresuid | Sysnum::setresgid => {
            let rxid = peek_reg(tracee, RegVersion::Current, Reg::Sysarg1) as i64;
            let exid = peek_reg(tracee, RegVersion::Current, Reg::Sysarg2) as i64;
            let sxid = peek_reg(tracee, RegVersion::Current, Reg::Sysarg3) as i64;
            let (mut r_, mut e_, mut s_) = (0u32, 0u32, 0u32);
            let ret = if sysnum == Sysnum::setresuid {
                crate::sys::getresuid().map(|(r, e, s)| (r_, e_, s_) = (r, e, s))
            } else {
                crate::sys::getresgid().map(|(r, e, s)| (r_, e_, s_) = (r, e, s))
            };
            if ret.is_err() {
                set_result_after_seccomp(tracee, (-(libc::EPERM as i64)) as Word);
            } else {
                let mut out = 0i64;
                for (want, have) in [(rxid, r_), (exid, e_), (sxid, s_)] {
                    if want != have as i64 && want != -1 {
                        out = -(libc::EPERM as i64);
                    }
                }
                set_result_after_seccomp(tracee, out as Word);
            }
        }
        _ => {
            set_result_after_seccomp(tracee, (-(libc::ENOSYS as i64)) as Word);
        }
    }
    0
}

/// statfs() via tracer-side statfs64 + narrowing (C's PR_statfs case).
fn statfs_via_sigsys(tracee: &mut Tracee) {
    let mut original = FixedPath::new();
    let mut buf = [0u8; crate::PATH_MAX];
    let size = read_string(
        tracee,
        &mut buf,
        peek_reg(tracee, RegVersion::Current, Reg::Sysarg1),
    );
    if size < 0 {
        set_result_after_seccomp(tracee, size as Word);
        return;
    }
    if size as usize >= crate::PATH_MAX {
        set_result_after_seccomp(tracee, (-(libc::ENAMETOOLONG as i64)) as Word);
        return;
    }
    original.set(&buf[..size as usize]);

    let mut path = FixedPath::new();
    let _ =
        crate::path::translate_path(tracee, &mut path, libc::AT_FDCWD, original.as_bytes(), true);

    let c = path.as_c_str();
    // statfs64 exposes f_flags and f_spare publicly on this libc target;
    // plain statfs hides them behind private fields.
    let st = match crate::sys::statfs64(c) {
        Ok(st) => st,
        Err(e) => {
            set_result_after_seccomp(
                tracee,
                if e != 0 {
                    (-(e as i64)) as Word
                } else {
                    (-(libc::EPERM as i64)) as Word
                },
            );
            return;
        }
    };

    // Fake /dev/shm as tmpfs (see statfs in syscall/exit.c).
    let mut f_type = st.f_type;
    let mut devshm = FixedPath::new();
    if crate::path::translate_path(tracee, &mut devshm, libc::AT_FDCWD, b"/dev/shm", true).is_ok() {
        let c = compare_paths(devshm.as_bytes(), path.as_bytes());
        if c == Comparison::PathsAreEqual || c == Comparison::Path1IsPrefix {
            f_type = 0x01021994; // TMPFS_MAGIC
        }
    }

    // Narrow to 32-bit fields; -EOVERFLOW when any doesn't fit.
    let fields = [
        st.f_blocks,
        st.f_bfree,
        st.f_bavail,
        // Field types vary between libc flavours (glibc vs Bionic).
        st.f_bsize as _,
        st.f_frsize as _,
        st.f_files,
        st.f_ffree,
    ];
    if fields.iter().any(|&v| v & 0xffff_ffff_0000_0000 != 0) {
        set_result_after_seccomp(tracee, (-(libc::EOVERFLOW as i64)) as Word);
        return;
    }

    // struct compat_statfs: 12 × i32 + fsid + spare.
    let mut out = [0u8; 15 * 4];
    let put = |off: usize, v: i64, out: &mut [u8]| {
        out[off..off + 4].copy_from_slice(&(v as i32).to_ne_bytes());
    };
    put(0, f_type as _, &mut out);
    put(4, st.f_bsize as _, &mut out);
    put(8, st.f_blocks as i64, &mut out);
    put(12, st.f_bfree as i64, &mut out);
    put(16, st.f_bavail as i64, &mut out);
    put(20, st.f_files as i64, &mut out);
    put(24, st.f_ffree as i64, &mut out);
    // fsid_t is opaque in this libc binding but is always two i32s;
    // read it through the byte view instead of transmuting.
    let stb = crate::sys::as_bytes(&st);
    let fsid_off = std::mem::offset_of!(libc::statfs64, f_fsid);
    out[28..36].copy_from_slice(&stb[fsid_off..fsid_off + 8]);
    put(36, st.f_namelen as _, &mut out);
    put(40, st.f_frsize as _, &mut out);
    put(44, st.f_flags as _, &mut out);

    let _ = write_data(
        tracee,
        peek_reg(tracee, RegVersion::Current, Reg::Sysarg2),
        &out,
    );
    set_result_after_seccomp(tracee, 0);
}

fn read_2words(buf: &[u8], off: usize, w: usize) -> (u64, u64) {
    let (a, b) = if w == 8 {
        (
            u64::from_ne_bytes(buf[off..off + 8].try_into().unwrap()),
            u64::from_ne_bytes(buf[off + 8..off + 16].try_into().unwrap()),
        )
    } else {
        (
            u64::from(u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap())),
            u64::from(u32::from_ne_bytes(
                buf[off + 4..off + 8].try_into().unwrap(),
            )),
        )
    };
    (a, b)
}

fn write_2words(buf: &mut [u8], off: usize, w: usize, a: u64, b: u64) {
    write_word(buf, off, w, a);
    write_word(buf, off + w, w, b);
}

fn write_word(buf: &mut [u8], off: usize, w: usize, v: u64) {
    if w == 8 {
        buf[off..off + 8].copy_from_slice(&v.to_ne_bytes());
    } else {
        buf[off..off + 4].copy_from_slice(&(v as u32).to_ne_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tracee::reg::{Reg, RegVersion, peek_reg, poke_reg};

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn orig_effective_copy() {
        let mut t = Tracee::default();
        t.regs[RegVersion::Current.idx()].orig_rax = 0x1234;
        copy_orig_to_effective(&mut t);
        assert_eq!(t.regs[RegVersion::Current.idx()].rax, 0x1234);
        t.regs[RegVersion::Current.idx()].rax = 0xbeef;
        copy_effective_to_orig(&mut t);
        assert_eq!(t.regs[RegVersion::Current.idx()].orig_rax, 0xbeef);
    }

    #[test]
    fn restart_rewinds_ip_and_marks_restore() {
        let mut t = Tracee {
            // Keep push_specific_regs from consuming the restore flag.
            restore_original_regs: false,
            ..Default::default()
        };
        poke_reg(&mut t, Reg::InstrPointer, 0x1000);
        crate::tracee::reg::set_bank_reg(&mut t, RegVersion::Current, Reg::SysargNum, 42);
        restart_syscall_after_seccomp(&mut t);
        // IP rewound by SYSTRAP_SIZE (syscall insn = 2 on x86_64, 4 on arm64).
        assert_eq!(
            peek_reg(&t, RegVersion::Current, Reg::InstrPointer),
            0x1000 - crate::arch::SYSTRAP_SIZE
        );
        assert!(t.restore_original_regs_after_seccomp_event);
        assert_eq!(t.restart_how, crate::ptrace::ptc::PTRACE_SYSCALL);
        // The re-executed trap reads the number back (x86_64: rax copied
        // from orig_rax; aarch64: x8 untouched).
        assert_eq!(
            peek_reg(&t, RegVersion::Current, crate::tracee::reg::SYSTRAP_NUM),
            42
        );
    }

    #[test]
    fn set_result_writes_result_reg() {
        let mut t = Tracee::default();
        set_result_after_seccomp(&mut t, 0x77);
        assert_eq!(peek_reg(&t, RegVersion::Current, Reg::SysargResult), 0x77);
    }

    #[test]
    fn read_write_word_helpers() {
        let mut buf = [0u8; 32];
        write_word(&mut buf, 8, 8, 0xdeadbeef);
        assert_eq!(
            u64::from_ne_bytes(buf[8..16].try_into().unwrap()),
            0xdeadbeef
        );
        write_word(&mut buf, 8, 4, 0x1badb002);
        assert_eq!(
            u32::from_ne_bytes(buf[8..12].try_into().unwrap()),
            0x1badb002
        );
        write_2words(&mut buf, 16, 8, 0x11, 0x22);
        let (a, b) = read_2words(&buf, 16, 8);
        assert_eq!((a, b), (0x11, 0x22));
        write_2words(&mut buf, 0, 4, 0xaa, 0xbb);
        let (a, b) = read_2words(&buf, 0, 4);
        assert_eq!((a, b), (0xaa, 0xbb));
    }

    #[test]
    fn fix_enosys_restores_and_marks() {
        let mut t = Tracee::default();
        // Original regs hold a trapped syscall; Current diverged.
        poke_reg(&mut t, Reg::Sysarg1, 0x555);
        crate::tracee::reg::save_current_regs(&mut t, RegVersion::Original);
        poke_reg(&mut t, Reg::Sysarg1, 0x999);
        t.status = 1;
        fix_and_restart_enosys_syscall(&mut t);
        // Current restored from Original, status cleared, flags set.
        assert_eq!(t.status, 0);
        assert!(!t.restore_original_regs);
        assert_eq!(peek_reg(&t, RegVersion::Current, Reg::Sysarg1), 0x555);
    }
}
