//! `translate_syscall_exit()` — port of syscall/exit.c.
//!
//! Handles sysexit-stage result fixups: fake getcwd, sockaddr detranslation,
//! readlink detranslation (incl. the truncated-link re-read and /proc fd
//! substitutions), AT_EXECFN auxv patching, the rename-cwd chase, the
//! /dev/shm statfs lie, and netlink ack rewriting.

use crate::Word;
use crate::fpath::{FixedPath, PathGuard};
use crate::path::{Comparison, compare_paths};
use crate::syscall::{ReadlinkProcFdState, is_voided_syscall, netlink};
use crate::sysnum::Abi;
use crate::sysnum::Sysnum;
use crate::tracee::Tracee;
use crate::tracee::mem::{peek_word, poke_word, read_data, read_path, read_string, write_data};
use crate::tracee::reg::{Reg, RegVersion, get_sysnum, peek_reg, poke_reg};

const PR_SET_NO_NEW_PRIVS: Word = 38;
const PR_GET_AUXV: Word = 0x41555856;
const AT_NULL: Word = 0;
const AT_EXECFN: Word = 31;

/// Mirrors C control flow: `Result` writes status to SYSARG_RESULT (the C
/// `break`), `End` skips the write (the C `goto end`).
enum Flow {
    Result(i32),
    End,
}

/// `translate_syscall_exit()`.
pub fn translate_syscall_exit(tracee: &mut Tracee) {
    let status = crate::extension::notify(tracee, &mut crate::extension::Event::SysExitStart);
    if status < 0 {
        poke_reg(tracee, Reg::SysargResult, status as Word);
        return end(tracee);
    }
    if status > 0 {
        return;
    }

    // Propagate a translation-time error into the result.
    if tracee.status < 0 {
        let st = tracee.status;
        poke_reg(tracee, Reg::SysargResult, st as Word);
        return end(tracee);
    }

    // A syscall voided at enter keeps the result PRoot faked there.
    if is_voided_syscall(tracee, RegVersion::Modified) {
        let r = peek_reg(tracee, RegVersion::Modified, Reg::SysargResult);
        poke_reg(tracee, Reg::SysargResult, r);
    }

    let syscall_number = get_sysnum(tracee, RegVersion::Original);
    let syscall_result = peek_reg(tracee, RegVersion::Current, Reg::SysargResult);

    let flow = match syscall_number {
        Sysnum::brk => {
            crate::syscall::heap::translate_brk_exit(tracee);
            Flow::End
        }
        Sysnum::getcwd => {
            let size = peek_reg(tracee, RegVersion::Original, Reg::Sysarg2) as usize;
            if size == 0 {
                Flow::Result(-libc::EINVAL)
            } else {
                let mut p = PathGuard::new();
                match crate::path::translate_path(tracee, &mut p, libc::AT_FDCWD, b".", false) {
                    Err(e) => Flow::Result(e),
                    Ok(()) => {
                        let cwd = tracee.fs.borrow().cwd.clone();
                        let new_size = cwd.len() + 1;
                        if size < new_size {
                            Flow::Result(-libc::ERANGE)
                        } else {
                            let output = peek_reg(tracee, RegVersion::Original, Reg::Sysarg1);
                            let mut buf = cwd.as_bytes().to_vec();
                            buf.push(0);
                            match write_data(tracee, output, &buf) {
                                s if s < 0 => Flow::Result(s),
                                _ => Flow::Result(new_size as i32),
                            }
                        }
                    }
                }
            }
        }
        Sysnum::accept | Sysnum::accept4 => {
            if peek_reg(tracee, RegVersion::Original, Reg::Sysarg2) == 0 {
                Flow::End
            } else {
                sockname_exit(tracee, syscall_result)
            }
        }
        Sysnum::getsockname | Sysnum::getpeername => sockname_exit(tracee, syscall_result),
        Sysnum::socketcall => socketcall_exit(tracee, syscall_result),

        Sysnum::fchdir
        | Sysnum::chdir
        | Sysnum::unshare
        | Sysnum::setns
        | Sysnum::mount
        | Sysnum::umount
        | Sysnum::umount2
        | Sysnum::pivot_root => {
            // Fully emulated at enter; keep the fake result even when the
            // avoider leaks -ENOSYS.
            Flow::Result(0)
        }

        Sysnum::rename | Sysnum::renameat => {
            if (syscall_result as i64) < 0 {
                Flow::End
            } else {
                rename_exit(tracee)
            }
        }
        Sysnum::renameat2 => Flow::End,

        Sysnum::readlink | Sysnum::readlinkat => readlink_exit(tracee, syscall_result),

        Sysnum::uname => {
            // 32-bit-on-64 x86 tracees see "i686" — some 32-bit tools are
            // confused by "x86_64".  (arm64 kernels already report a
            // 32-bit machine to AArch32 tasks.)
            if !cfg!(target_arch = "x86_64")
                || crate::tracee::reg::get_abi(tracee) != Abi::Abi2
                || (syscall_result as i64) < 0
            {
                Flow::End
            } else {
                let address = peek_reg(tracee, RegVersion::Original, Reg::Sysarg1);
                let mut uts = [0u8; size_of::<libc::utsname>()];
                match read_data(tracee, &mut uts, address) {
                    s if s < 0 => Flow::Result(s),
                    _ => {
                        // struct utsname.machine is the 5th field of
                        // 6 x 65-byte fields.
                        let machine_off = 4 * 65;
                        let size = 65usize;
                        uts[machine_off..machine_off + size].fill(0);
                        uts[machine_off..machine_off + 4].copy_from_slice(b"i686");
                        match write_data(tracee, address, &uts) {
                            s if s < 0 => Flow::Result(s),
                            _ => Flow::Result(0),
                        }
                    }
                }
            }
        }

        Sysnum::execve | Sysnum::execveat => {
            crate::execve::translate_execve_exit(tracee);
            Flow::End
        }

        Sysnum::openat2 | Sysnum::openat | Sysnum::open => {
            // Track /proc/self/auxv opens so read() can patch AT_EXECFN.
            let path_reg = if syscall_number == Sysnum::open {
                Reg::Sysarg1
            } else {
                Reg::Sysarg2
            };
            if (syscall_result as i64) < 0 || tracee.execfn_addr == 0 {
                Flow::End
            } else {
                let mut buf = [0u8; "/proc/self/auxv".len()];
                let n = read_string(
                    tracee,
                    &mut buf,
                    peek_reg(tracee, RegVersion::Original, path_reg),
                );
                if n <= 0 || buf != *b"/proc/self/auxv" {
                    Flow::End
                } else {
                    tracee.auxv_fd = syscall_result as i32;
                    tracee.sysexit_pending = true;
                    tracee.restart_how = crate::ptrace::ptc::PTRACE_SYSCALL;
                    Flow::End
                }
            }
        }

        Sysnum::read => {
            // Patch AT_EXECFN in data read from /proc/self/auxv.
            if tracee.auxv_fd < 0 || tracee.execfn_addr == 0 {
                Flow::End
            } else {
                let result = syscall_result;
                if result == 0
                    || (result as i64) < 0
                    || peek_reg(tracee, RegVersion::Original, Reg::Sysarg1) as i32 != tracee.auxv_fd
                {
                    Flow::End
                } else {
                    patch_execfn_in_auxv(tracee, result);
                    tracee.sysexit_pending = true;
                    tracee.restart_how = crate::ptrace::ptc::PTRACE_SYSCALL;
                    Flow::End
                }
            }
        }

        Sysnum::prctl => {
            let option = peek_reg(tracee, RegVersion::Original, Reg::Sysarg1);
            if option == PR_SET_NO_NEW_PRIVS {
                // Latch the tracee's own no_new_privs request.
                if tracee.seen_execve && syscall_result as i64 == 0 {
                    tracee.no_new_privs = true;
                }
                Flow::End
            } else if option != PR_GET_AUXV
                || (syscall_result as i64) < 0
                || tracee.execfn_addr == 0
            {
                Flow::End
            } else {
                let buf_max = peek_reg(tracee, RegVersion::Original, Reg::Sysarg3);
                if syscall_result > buf_max {
                    Flow::End
                } else {
                    patch_execfn_in_auxv(tracee, syscall_result);
                    Flow::End
                }
            }
        }

        Sysnum::ptrace => Flow::Result(crate::ptrace::translate_ptrace_exit(tracee)),

        Sysnum::wait4 | Sysnum::waitpid => {
            if tracee.as_ptracer.waits_in != crate::tracee::WaitsIn::Proot {
                Flow::End
            } else {
                Flow::Result(crate::ptrace::wait::translate_wait_exit(tracee))
            }
        }

        Sysnum::setrlimit | Sysnum::prlimit64 => {
            if (syscall_result as i64) < 0 {
                Flow::End
            } else {
                match crate::syscall::rlimit::translate_setrlimit_exit(
                    tracee,
                    syscall_number == Sysnum::prlimit64,
                ) {
                    s if s < 0 => Flow::Result(s),
                    _ => Flow::End,
                }
            }
        }

        Sysnum::utime => {
            if syscall_result as i64 == -libc::ENOSYS as i64 {
                crate::tracee::seccomp::fix_and_restart_enosys_syscall(tracee);
            }
            Flow::End
        }

        Sysnum::statfs | Sysnum::statfs64 => {
            // Pretend /dev/shm lives on tmpfs.
            if syscall_result != 0 {
                Flow::End
            } else {
                let mut devshm = PathGuard::new();
                if crate::path::translate_path(
                    tracee,
                    &mut devshm,
                    libc::AT_FDCWD,
                    b"/dev/shm",
                    true,
                )
                .is_err()
                {
                    crate::verbose!(
                        Some(tracee),
                        5,
                        "/dev/shm is not mounted, not changing statfs() result"
                    );
                    Flow::End
                } else {
                    let mut statfs_path = PathGuard::new();
                    if read_path(
                        tracee,
                        &mut statfs_path,
                        peek_reg(tracee, RegVersion::Modified, Reg::Sysarg1),
                    ) < 0
                    {
                        Flow::End
                    } else {
                        let c = compare_paths(devshm.as_bytes(), statfs_path.as_bytes());
                        if c == Comparison::PathsAreEqual || c == Comparison::Path1IsPrefix {
                            let reg = if syscall_number == Sysnum::statfs64 {
                                Reg::Sysarg3
                            } else {
                                Reg::Sysarg2
                            };
                            let stat_addr = peek_reg(tracee, RegVersion::Original, reg);
                            // TMPFS_MAGIC, little-endian.
                            let _ = write_data(tracee, stat_addr, &[0x94, 0x19, 0x02, 0x01]);
                        }
                        Flow::End
                    }
                }
            }
        }

        Sysnum::statx => Flow::Result(crate::tracee::statx::handle_statx_syscall(tracee, false)),

        Sysnum::ioctl => {
            // FICLONE denied by the host (Android) → EOPNOTSUPP so cp(1)
            // falls back to copying instead of aborting.
            if peek_reg(tracee, RegVersion::Original, Reg::Sysarg2)
                == 0x40049409 // _IOW(0x94, 9, int)
                && peek_reg(tracee, RegVersion::Current, Reg::SysargResult) as i64
                    == -libc::EACCES as i64
            {
                poke_reg(
                    tracee,
                    Reg::SysargResult,
                    (-(libc::EOPNOTSUPP as i64)) as Word,
                );
            }
            Flow::End
        }

        Sysnum::socket => {
            // Record fds created for the AF_NETLINK emulation.
            if tracee.pending_fake_netlink_socket {
                let fd = peek_reg(tracee, RegVersion::Current, Reg::SysargResult) as i32;
                if fd >= 0
                    && tracee.fake_netlink_fds.len() < crate::tracee::MAX_FAKE_NETLINK_FDS
                    && !tracee.fake_netlink_fds.iter().any(|s| s.fd == fd)
                {
                    netlink::mark_fake_netlink_fd(tracee, fd);
                }
                tracee.pending_fake_netlink_socket = false;
            }
            if tracee.pending_real_netlink_socket {
                let fd = peek_reg(tracee, RegVersion::Current, Reg::SysargResult) as i32;
                if fd >= 0 && tracee.netlink_route_fds.len() < crate::tracee::MAX_NETLINK_ROUTE_FDS
                {
                    netlink::mark_netlink_route_fd(tracee, fd);
                }
                tracee.pending_real_netlink_socket = false;
            }
            Flow::End
        }

        Sysnum::recvfrom | Sysnum::recvmsg => {
            netlink::handle_netlink_reply_exit(tracee, syscall_number == Sysnum::recvfrom);
            Flow::End
        }

        _ => Flow::End,
    };

    if let Flow::Result(status) = flow {
        poke_reg(tracee, Reg::SysargResult, status as Word);
    }

    end(tracee)
}

fn end(tracee: &mut Tracee) {
    let status = crate::extension::notify(
        tracee,
        &mut crate::extension::Event::SysExitEnd { status: 0 },
    );
    if status < 0 {
        poke_reg(tracee, Reg::SysargResult, status as Word);
    }
}

/// accept*/getsockname/getpeername exit: detranslate the sockaddr back.
fn sockname_exit(tracee: &mut Tracee, syscall_result: Word) -> Flow {
    if (syscall_result as i64) < 0 {
        return Flow::End;
    }
    let sock_addr = peek_reg(tracee, RegVersion::Original, Reg::Sysarg2);
    let size_addr = peek_reg(tracee, RegVersion::Modified, Reg::Sysarg3);
    let max_size = peek_reg(tracee, RegVersion::Modified, Reg::Sysarg6);
    match crate::syscall::socket::translate_socketcall_exit(tracee, sock_addr, size_addr, max_size)
    {
        s if s < 0 => Flow::Result(s),
        _ => Flow::End,
    }
}

/// i386 PR_socketcall exit.
fn socketcall_exit(tracee: &mut Tracee, syscall_result: Word) -> Flow {
    let w = crate::tracee::reg::sizeof_word(tracee) as Word;
    let args_addr = peek_reg(tracee, RegVersion::Original, Reg::Sysarg2);
    let arg = |n: Word| -> Word { args_addr + (n - 1) * w };

    macro_rules! peekw {
        ($addr:expr_2021) => {{
            crate::sys::clear_errno();
            let v = peek_word(tracee, $addr);
            let e = crate::sys::errno();
            if e != 0 {
                return Flow::Result(-e);
            }
            v
        }};
    }
    macro_rules! pokew {
        ($addr:expr_2021, $val:expr_2021) => {{
            crate::sys::clear_errno();
            poke_word(tracee, $addr, $val);
            let e = crate::sys::errno();
            if e != 0 {
                return Flow::Result(-e);
            }
        }};
    }

    const SYS_BIND: Word = 2;
    const SYS_CONNECT: Word = 3;
    const SYS_ACCEPT: Word = 5;
    const SYS_GETSOCKNAME: Word = 6;
    const SYS_GETPEERNAME: Word = 7;
    const SYS_ACCEPT4: Word = 18;

    let status = match peek_reg(tracee, RegVersion::Original, Reg::Sysarg1) {
        n if n == SYS_ACCEPT || n == SYS_ACCEPT4 => {
            let sock_addr = peekw!(arg(2));
            if sock_addr == 0 {
                return Flow::End;
            }
            1
        }
        n if n == SYS_GETSOCKNAME || n == SYS_GETPEERNAME => 1,
        n if n == SYS_BIND || n == SYS_CONNECT => {
            // Restore args overwritten at enter.
            let s5 = peek_reg(tracee, RegVersion::Modified, Reg::Sysarg5);
            let s6 = peek_reg(tracee, RegVersion::Modified, Reg::Sysarg6);
            pokew!(arg(2), s5);
            pokew!(arg(3), s6);
            return Flow::End;
        }
        _ => return Flow::End,
    };

    if (syscall_result as i64) < 0 || status == 0 {
        return Flow::End;
    }

    let sock_addr = peekw!(arg(2));
    let size_addr = peekw!(arg(3));
    let max_size = peek_reg(tracee, RegVersion::Modified, Reg::Sysarg6);
    match crate::syscall::socket::translate_socketcall_exit(tracee, sock_addr, size_addr, max_size)
    {
        s if s < 0 => Flow::Result(s),
        _ => Flow::End,
    }
}

/// rename(2)/renameat(2): chase the tracee's virtual cwd when it was moved.
fn rename_exit(tracee: &mut Tracee) -> Flow {
    let (old_reg, new_reg) = if get_sysnum(tracee, RegVersion::Original) == Sysnum::rename {
        (Reg::Sysarg1, Reg::Sysarg2)
    } else {
        (Reg::Sysarg2, Reg::Sysarg4)
    };

    let mut old_path = PathGuard::new();
    let mut new_path = PathGuard::new();

    let r = read_path(
        tracee,
        &mut old_path,
        peek_reg(tracee, RegVersion::Modified, old_reg),
    );
    if r < 0 {
        return Flow::Result(r);
    }
    let old_length = match crate::path::detranslate_path(tracee, &mut old_path, None) {
        Err(e) => return Flow::Result(e),
        Ok(s) => {
            if s > 0 {
                s as usize - 1
            } else {
                old_path.len()
            }
        }
    };

    let cwd = tracee.fs.borrow().cwd.clone();
    let comparison = compare_paths(old_path.as_bytes(), cwd.as_bytes());
    if comparison != Comparison::Path1IsPrefix && comparison != Comparison::PathsAreEqual {
        return Flow::Result(0);
    }

    let r = read_path(
        tracee,
        &mut new_path,
        peek_reg(tracee, RegVersion::Modified, new_reg),
    );
    if r < 0 {
        return Flow::Result(r);
    }
    let new_length = match crate::path::detranslate_path(tracee, &mut new_path, None) {
        Err(e) => return Flow::Result(e),
        Ok(s) => {
            if s > 0 {
                s as usize - 1
            } else {
                new_path.len()
            }
        }
    };

    if cwd.len() >= crate::PATH_MAX {
        return Flow::Result(0);
    }

    let mut updated = FixedPath::from_bytes(cwd.as_bytes());
    let _ = updated.substitute_prefix(old_length, &new_path.as_bytes()[..new_length]);
    tracee.fs.borrow_mut().cwd.set(updated.as_bytes());
    Flow::Result(0)
}

/// readlink(2)/readlinkat(2) exit: detranslate the symlink target.
fn readlink_exit(tracee: &mut Tracee, syscall_result: Word) -> Flow {
    if (syscall_result as i64) < 0 {
        return Flow::End;
    }
    let old_size = syscall_result as usize;

    let is_readlink = get_sysnum(tracee, RegVersion::Original) == Sysnum::readlink;
    let (output, max_size, input) = if is_readlink {
        (
            peek_reg(tracee, RegVersion::Original, Reg::Sysarg2),
            peek_reg(tracee, RegVersion::Original, Reg::Sysarg3),
            peek_reg(tracee, RegVersion::Modified, Reg::Sysarg1),
        )
    } else {
        (
            peek_reg(tracee, RegVersion::Original, Reg::Sysarg3),
            peek_reg(tracee, RegVersion::Original, Reg::Sysarg4),
            peek_reg(tracee, RegVersion::Modified, Reg::Sysarg2),
        )
    };

    let max_size = (max_size as usize).min(crate::PATH_MAX);
    if max_size == 0 {
        return Flow::Result(-libc::EINVAL);
    }

    // The kernel does not NUL-terminate readlink's output.  Read straight
    // into the path buffer (read_data is all-or-error, so the fetched span
    // is fully populated on success).
    let mut referee = PathGuard::new();
    let cap = old_size.min(crate::PATH_MAX);
    let s = read_data(tracee, &mut referee.as_mut_bytes()[..cap], output);
    if s < 0 {
        return Flow::Result(s);
    }
    referee.set_len_terminated(cap);

    let mut referer = PathGuard::new();
    let status = read_path(tracee, &mut referer, input);
    if status < 0 {
        return Flow::Result(status);
    }
    if status as usize >= crate::PATH_MAX {
        return Flow::Result(-libc::ENAMETOOLONG);
    }

    let mut proc_fd = ReadlinkProcFdState {
        pid: 0,
        fd: -1,
        host_path: FixedPath::new(),
        referer: FixedPath::new(),
        substituted: false,
    };

    if status == 1 {
        // Empty path — the target is the fd given as arg1 (readlinkat).
        let dirfd = peek_reg(tracee, RegVersion::Original, Reg::Sysarg1) as i32;
        if is_readlink || dirfd < 0 {
            return Flow::Result(-libc::EBADF);
        }
        proc_fd.pid = tracee.pid;
        proc_fd.fd = dirfd;
        if let Err(e) = crate::path::readlink_proc_pid_fd(tracee.pid, dirfd, &mut referer) {
            return Flow::Result(e);
        }
    } else if let Some((fd_pid, fd_number)) = parse_proc_fd(referer.as_bytes()) {
        proc_fd.pid = fd_pid;
        proc_fd.fd = fd_number;
    }

    // Full-buffer readlink truncation: re-read the target with PATH_MAX so
    // detranslation sees the real host path (guest targets truncate easily).
    if old_size == max_size {
        // PATH_MAX-1 keeps room for the terminator.
        let full = crate::sys::readlink(
            referer.as_c_str(),
            &mut referee.as_mut_bytes()[..crate::PATH_MAX - 1],
        );
        if full > 0 {
            referee.set_len_terminated(full as usize);
        }
    }

    // Extensions may rename the target (e.g. link2symlink).
    let mut substituted = false;
    if proc_fd.fd >= 0 {
        proc_fd.host_path.set(referee.as_bytes());
        proc_fd.referer.set(referer.as_bytes());
        let mut ev = crate::extension::Event::ReadlinkProcFd {
            state: &mut proc_fd,
        };
        let status = crate::extension::notify(tracee, &mut ev);
        if status < 0 {
            return Flow::Result(status);
        }
        referee.set(proc_fd.host_path.as_bytes());
        substituted = proc_fd_substituted(&proc_fd);
    }

    let status = match crate::path::detranslate_path(tracee, &mut referee, Some(&referer)) {
        Err(e) => return Flow::Result(e),
        Ok(s) => s,
    };

    let mut status = status as usize;
    if status == 0 {
        if !substituted {
            return Flow::End;
        }
        status = referee.len() + 1;
    }

    // `referee` is conceptually NUL-terminated (status counts the NUL).
    let mut out = referee.as_bytes().to_vec();
    out.push(0);
    let new_size;
    if status < max_size {
        new_size = status - 1;
        let r = write_data(tracee, output, &out[..status.min(out.len())]);
        if r < 0 {
            return Flow::Result(r);
        }
    } else {
        new_size = max_size;
        let r = write_data(tracee, output, &out[..max_size.min(out.len())]);
        if r < 0 {
            return Flow::Result(r);
        }
    }
    Flow::Result(new_size as i32)
}

fn proc_fd_substituted(s: &ReadlinkProcFdState) -> bool {
    s.substituted
}

/// sscanf("/proc/%d/fd/%d%c") — detect "/proc/<pid>/fd/<fd>" referers.
fn parse_proc_fd(referer: &[u8]) -> Option<(i32, i32)> {
    let rest = referer.strip_prefix(b"/proc/")?;
    let digits1 = rest.iter().take_while(|c| c.is_ascii_digit()).count();
    if digits1 == 0 {
        return None;
    }
    let pid: i32 = std::str::from_utf8(&rest[..digits1]).ok()?.parse().ok()?;
    let rest = rest[digits1..].strip_prefix(b"/fd/")?;
    let digits2 = rest.iter().take_while(|c| c.is_ascii_digit()).count();
    if digits2 == 0 {
        return None;
    }
    let fd: i32 = std::str::from_utf8(&rest[..digits2]).ok()?.parse().ok()?;
    if fd < 0 {
        return None;
    }
    // sscanf requires the end or a non-digit trailing char.
    match rest.get(digits2) {
        None => Some((pid, fd)),
        Some(&c) if !c.is_ascii_digit() => Some((pid, fd)),
        _ => Some((pid, fd)),
    }
}

/// Scan an auxv buffer in tracee memory and patch AT_EXECFN.
fn patch_execfn_in_auxv(tracee: &mut Tracee, result: Word) {
    let buf_addr = match get_sysnum(tracee, RegVersion::Original) {
        Sysnum::read => peek_reg(tracee, RegVersion::Original, Reg::Sysarg2),
        _ => peek_reg(tracee, RegVersion::Original, Reg::Sysarg2), // prctl arg2
    };
    let w = crate::tracee::reg::sizeof_word(tracee) as Word;
    let entry = 2 * w;
    let mut offset: Word = 0;
    while offset + entry <= result {
        crate::sys::clear_errno();
        let ty = peek_word(tracee, buf_addr + offset);
        if crate::sys::errno() != 0 {
            break;
        }
        if ty == AT_NULL {
            break;
        }
        if ty == AT_EXECFN {
            poke_word(tracee, buf_addr + offset + w, tracee.execfn_addr);
            break;
        }
        offset += entry;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_fd_referer_parsing() {
        assert_eq!(parse_proc_fd(b"/proc/12/fd/3"), Some((12, 3)));
        assert_eq!(parse_proc_fd(b"/proc/1/fd/0"), Some((1, 0)));
        assert_eq!(parse_proc_fd(b"/proc/1/fd/999"), Some((1, 999)));
        assert_eq!(parse_proc_fd(b"/proc/self/fd/3"), None);
        assert_eq!(parse_proc_fd(b"/proc/12/fd/"), None);
        assert_eq!(parse_proc_fd(b"/proc/12/fdx/3"), None);
        assert_eq!(parse_proc_fd(b"/proc/12/fd"), None);
        assert_eq!(parse_proc_fd(b"/etc/fd/3"), None);
        assert_eq!(parse_proc_fd(b"/proc/-1/fd/3"), None);
        // Trailing junk after digits: sscanf still consumed the fd.
        assert_eq!(parse_proc_fd(b"/proc/12/fd/3x"), Some((12, 3)));
    }

    // ------ readlink_exit arena tests ------
    use crate::sysnum::detranslate_sysnum;
    use crate::testutil::{Arena, TempDir, fork_child};
    use crate::tracee::mem::write_data;
    use crate::tracee::reg::get_abi;

    /// Tracee rooted at `root` with extra bindings, backed by a live child.
    fn live_tracee(
        root: &[u8],
        bindings: &[(&[u8], &[u8])],
        arena: &Arena,
        child: &crate::testutil::Child,
    ) -> Tracee {
        let mut t = child.tracee_with_sp(arena);
        t.fs.borrow_mut().cwd.set(b"/");
        crate::path::binding::new_binding(&mut t, root, Some(b"/"), true).unwrap();
        for (h, g) in bindings {
            crate::path::binding::new_binding(&mut t, h, Some(g), true).unwrap();
        }
        crate::path::binding::initialize_bindings(&mut t);
        t
    }

    fn set_readlink_regs(t: &mut Tracee, input: Word, output: Word, max: Word) {
        // readlink(path, buf, size) where it exists, else (arm64)
        // readlinkat(AT_FDCWD, path, buf, size).
        let readlink = detranslate_sysnum(get_abi(t), Sysnum::readlink);
        let (sysnum, path, buf, size) = if readlink != crate::arch::SYSCALL_AVOIDER {
            (readlink, Reg::Sysarg1, Reg::Sysarg2, Reg::Sysarg3)
        } else {
            poke_reg(t, Reg::Sysarg1, libc::AT_FDCWD as Word);
            (
                detranslate_sysnum(get_abi(t), Sysnum::readlinkat),
                Reg::Sysarg2,
                Reg::Sysarg3,
                Reg::Sysarg4,
            )
        };
        // Original bank: the syscall + args as the guest issued them.
        poke_reg(t, Reg::SysargNum, sysnum);
        poke_reg(t, buf, output);
        poke_reg(t, size, max);
        t.regs[RegVersion::Original.idx()] = t.regs[RegVersion::Current.idx()];
        // Modified bank: the path argument holds the *translated* host path.
        poke_reg(t, path, input);
        t.regs[RegVersion::Modified.idx()] = t.regs[RegVersion::Current.idx()];
    }

    #[test]
    fn readlink_detranslates_through_binding() {
        // Regression for the bug the C suite caught: a symlink reached via
        // /ced/L whose content is the host path must print /ced/t.
        let root = TempDir::new("rl-root");
        root.dir("bin");
        let host = TempDir::new("rl-host");
        host.dir("hdir");
        let hdir = host.abs("hdir");
        let mut t_path = hdir.clone();
        t_path.extend_from_slice(b"/t");

        let arena = Arena::new(2);
        let child = fork_child(&arena).unwrap();
        let mut t = live_tracee(&root.abs("."), &[(&hdir, b"/ced")], &arena, &child);

        // Remote: input=host path of the link, output=raw link content.
        let input = arena.addr() + 0x800;
        let output = arena.addr() + 0x1000;
        let mut link_host = hdir.clone();
        link_host.extend_from_slice(b"/L\0");
        write_data(&t, input, &link_host);
        write_data(&t, output, &t_path);
        let out_len = t_path.len() as Word;
        set_readlink_regs(&mut t, input, output, 4096);

        let flow = readlink_exit(&mut t, out_len);
        assert!(matches!(flow, Flow::Result(6)));
        let mut buf = vec![0u8; 64];
        assert_eq!(read_data(&t, &mut buf, output), 0);
        assert_eq!(&buf[..6], b"/ced/t");
    }

    #[test]
    fn readlink_negative_result_passthrough() {
        let arena = Arena::new(1);
        let child = fork_child(&arena).unwrap();
        let mut t = live_tracee(b"/", &[], &arena, &child);
        let flow = readlink_exit(&mut t, (-libc::ENOENT as i64) as Word);
        assert!(matches!(flow, Flow::End));
    }

    #[test]
    fn readlink_zero_maxsize_is_einval() {
        let arena = Arena::new(1);
        let child = fork_child(&arena).unwrap();
        let mut t = live_tracee(b"/", &[], &arena, &child);
        set_readlink_regs(&mut t, 0, arena.addr() + 0x100, 0);
        let flow = readlink_exit(&mut t, 5);
        assert!(matches!(flow, Flow::Result(s) if s == -libc::EINVAL));
    }

    #[test]
    fn readlink_plain_path_untouched() {
        // Referer inside the guestfs → no binding detranslation; the
        // buffer stays as the kernel wrote it.
        let root = TempDir::new("rl-plain");
        root.dir("d");
        let arena = Arena::new(2);
        let child = fork_child(&arena).unwrap();
        let mut t = live_tracee(&root.abs("."), &[], &arena, &child);
        // Link lives inside the rootfs, content = guest-abs path that
        // stays within the rootfs → host path = root+content.
        let mut referer = root.abs(".");
        referer.extend_from_slice(b"/d/L\0");
        let target_content = b"/d/t"; // guest path; host = root + /d/t
        let input = arena.addr() + 0x800;
        let output = arena.addr() + 0x1000;
        write_data(&t, input, &referer);
        let mut host_target = root.abs(".");
        host_target.extend_from_slice(target_content);
        write_data(&t, output, &host_target);
        set_readlink_regs(&mut t, input, output, 4096);
        let flow = readlink_exit(&mut t, host_target.len() as Word);
        // Detranslation strips the root prefix → guest "/d/t".
        assert!(matches!(flow, Flow::Result(4)));
        let mut buf = vec![0u8; 64];
        assert_eq!(read_data(&t, &mut buf, output), 0);
        assert_eq!(&buf[..4], b"/d/t");
    }
}
