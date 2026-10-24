//! ptrace(2) emulation — port of ptrace/ptrace.c.
//!
//! Real ptrace can't be nested: when a tracee calls ptrace(), PRoot
//! performs the operation itself and projects the result back.

#[cfg(target_arch = "x86_64")]
pub mod user;
pub mod wait;

use crate::Word;
use crate::sysnum::Sysnum;
use crate::tracee::mem::{peek_word, poke_word, read_data, write_data};
use crate::tracee::reg::{Reg, RegVersion, is_32on64_mode, peek_reg, set_sysnum};
use crate::tracee::{Seccomp, Tracee, WaitsIn, get_tracee};

/// PTrace request/option constants as `i32` (libc exposes them as `u32`
/// on Linux/glibc, while all our bookkeeping is `i32`/`Word`), plus the
/// requests libc lacks on this platform (Bionic and non-x86 targets miss
/// the x86 register requests and the PTRACE_SEIZE family, so those are
/// spelled out numerically). The table mirrors the complete request
/// vocabulary even where this port uses only a subset.
#[allow(dead_code)]
pub mod ptc {
    macro_rules! c {
        ($name:ident) => {
            pub const $name: i32 = libc::$name as i32;
        };
        ($name:ident = $v:expr_2021) => {
            pub const $name: i32 = $v;
        };
    }
    c!(PTRACE_TRACEME);
    c!(PTRACE_PEEKTEXT);
    c!(PTRACE_PEEKDATA);
    c!(PTRACE_PEEKUSER);
    c!(PTRACE_POKETEXT);
    c!(PTRACE_POKEDATA);
    c!(PTRACE_POKEUSER);
    c!(PTRACE_CONT);
    c!(PTRACE_KILL);
    c!(PTRACE_SINGLESTEP);
    c!(PTRACE_ATTACH);
    c!(PTRACE_DETACH);
    c!(PTRACE_GETREGS = 12);
    c!(PTRACE_SETREGS = 13);
    c!(PTRACE_GETFPREGS = 14);
    c!(PTRACE_SETFPREGS = 15);
    c!(PTRACE_GETSIGINFO);
    c!(PTRACE_SETSIGINFO);
    c!(PTRACE_GETREGSET);
    c!(PTRACE_SETREGSET);
    c!(PTRACE_SEIZE = 0x4206);
    c!(PTRACE_INTERRUPT = 0x4207);
    c!(PTRACE_LISTEN = 0x4208);
    c!(PTRACE_SYSCALL);
    c!(PTRACE_SETOPTIONS);
    c!(PTRACE_GETEVENTMSG);
    c!(PTRACE_EVENT_FORK);
    c!(PTRACE_EVENT_VFORK);
    c!(PTRACE_EVENT_VFORK_DONE);
    c!(PTRACE_EVENT_CLONE);
    c!(PTRACE_EVENT_EXEC);
    c!(PTRACE_EVENT_EXIT);
    c!(PTRACE_EVENT_SECCOMP2 = 0x08);
    c!(PTRACE_EVENT_SECCOMP);
    c!(PTRACE_O_TRACESYSGOOD);
    c!(PTRACE_O_TRACEFORK);
    c!(PTRACE_O_TRACEVFORK);
    c!(PTRACE_O_TRACEVFORKDONE);
    c!(PTRACE_O_TRACECLONE);
    c!(PTRACE_O_TRACEEXEC);
    c!(PTRACE_O_TRACEEXIT);
    c!(PTRACE_O_TRACESECCOMP);
    // Not in this libc's tables.
    c!(PTRACE_SET_SYSCALL = 23);
    c!(PTRACE_GET_THREAD_AREA = 25);
    c!(PTRACE_SET_THREAD_AREA = 26);
    c!(PTRACE_SINGLEBLOCK = 33);
}

/// `translate_ptrace_enter()` — void the syscall; the work happens at the
/// exit stage.
pub fn translate_ptrace_enter(tracee: &mut Tracee) -> i32 {
    set_sysnum(tracee, Sysnum::Void);
    0
}

/// `attach_to_ptracer()` — register `ptracer_pid` as the ptracee's tracer.
pub fn attach_to_ptracer(ptracee: &mut Tracee, ptracer_pid: i32) {
    let keep_zombies = std::mem::take(&mut ptracee.as_ptracee); // bzero
    let _ = keep_zombies;
    ptracee.as_ptracee.ptracer = ptracer_pid;
    crate::tracee::with_tracee_mut(ptracer_pid, |p| p.as_ptracer.nb_ptracees += 1);
}

/// `detach_from_ptracer()` — drop the relation from both sides.
pub fn detach_from_ptracer(ptracee: &mut Tracee, held_ptracer: Option<&mut Tracee>) {
    let ptracer_pid = ptracee.as_ptracee.ptracer;
    ptracee.as_ptracee.ptracer = 0;
    if ptracer_pid == 0 {
        return;
    }
    // `held_ptracer` lets callers that already hold `&mut` on the ptracer
    // avoid a re-entrant registry borrow (C mutates through raw pointers).
    if let Some(p) = held_ptracer {
        if p.pid == ptracer_pid {
            debug_assert!(p.as_ptracer.nb_ptracees > 0);
            p.as_ptracer.nb_ptracees = p.as_ptracer.nb_ptracees.saturating_sub(1);
            return;
        }
    }
    crate::tracee::with_tracee_mut_try(ptracer_pid, |p| {
        debug_assert!(p.as_ptracer.nb_ptracees > 0);
        p.as_ptracer.nb_ptracees = p.as_ptracer.nb_ptracees.saturating_sub(1);
    });
}

fn ptrace_req(request: Word, pid: i32, addr: usize, data: usize) -> i32 {
    crate::sys::clear_errno();
    crate::sys::ptrace(request as u32, pid, addr, data) as i32
}

/// `translate_ptrace_exit()` — emulate the ptrace request the tracee
/// issued.  `ptracer` is the current tracee.
pub fn translate_ptrace_exit(ptracer: &mut Tracee) -> i32 {
    let request = peek_reg(ptracer, RegVersion::Original, Reg::Sysarg1);
    let mut pid = peek_reg(ptracer, RegVersion::Original, Reg::Sysarg2);
    #[cfg_attr(not(target_arch = "x86_64"), allow(unused_mut))]
    let mut address = peek_reg(ptracer, RegVersion::Original, Reg::Sysarg3);
    let data = peek_reg(ptracer, RegVersion::Original, Reg::Sysarg4);
    let mut forced_signal: i32 = -1;

    if is_32on64_mode(ptracer) && pid == 0xFFFF_FFFF {
        pid = Word::MAX; // (word_t) -1
    }

    // TRACEME — issued by the ptracee itself.
    if request == crate::ptrace::ptc::PTRACE_TRACEME as Word {
        let ptracer_pid = ptracer.parent;
        if ptracer.as_ptracee.ptracer != 0 || ptracer.pid == ptracer_pid {
            return -libc::EPERM;
        }
        attach_to_ptracer(ptracer, ptracer_pid);

        // Wake a ptracer that entered wait before we attached.
        let waiting =
            crate::tracee::with_tracee(ptracer_pid, |p| p.as_ptracer.waits_in == WaitsIn::Kernel)
                .unwrap_or(false);
        if waiting {
            let status = crate::sys::kill(ptracer_pid, libc::SIGSTOP);
            if status < 0 {
                crate::note!(
                    Some(ptracer),
                    crate::note::Severity::Warning,
                    crate::note::Origin::Internal,
                    "can't wake ptracer {}",
                    ptracer_pid
                );
            } else {
                crate::tracee::with_tracee_mut(ptracer_pid, |p| {
                    p.sigstop = crate::tracee::Sigstop::Ignored;
                    p.as_ptracer.waits_in = WaitsIn::Proot;
                });
            }
        }

        // Seccomp acceleration can't coexist with ptrace emulation.
        if ptracer.seccomp == Seccomp::Enabled {
            ptracer.seccomp = Seccomp::Disabling;
        }
        return 0;
    }

    // ATTACH — the only request where the ptracee's state is unknown.
    if request == crate::ptrace::ptc::PTRACE_ATTACH as Word {
        let ptracee_rc = match get_tracee(pid as i32, false) {
            Some(t) => t,
            None => return -libc::ESRCH,
        };
        {
            let mut ptracee = ptracee_rc.borrow_mut();
            if ptracee.as_ptracee.ptracer != 0 || ptracee.pid == ptracer.pid {
                return -libc::EPERM;
            }
            attach_to_ptracer(&mut ptracee, ptracer.pid);
        }
        crate::sys::kill(pid as i32, libc::SIGSTOP);
        return 0;
    }

    // Every other request needs a stopped ptracee owned by this ptracer.
    let ptracer_pid = ptracer.pid;
    let ptracee_rc =
        match wait::get_stopped_ptracee(ptracer, pid as i32, false, libc::__WALL as Word) {
            Some(t) => t,
            None => {
                // Report the odd case of a still-initializing tracee.
                if let Some(other) = get_tracee(pid as i32, false) {
                    if other.borrow().exe.is_none() {
                        crate::note!(
                            Some(ptracer),
                            crate::note::Severity::Warning,
                            crate::note::Origin::Internal,
                            "ptrace request to an unexpected ptracee"
                        );
                    }
                }
                return -libc::ESRCH;
            }
        };
    let mut ptracee = ptracee_rc.borrow_mut();
    if ptracee.as_ptracee.is_zombie || ptracee.as_ptracee.ptracer != ptracer_pid || pid == Word::MAX
    {
        return -libc::ESRCH;
    }

    let ptracee_pid = ptracee.pid;
    let mut status = 0i32;
    match request as i32 {
        crate::ptrace::ptc::PTRACE_SYSCALL => {
            ptracee.as_ptracee.ignore_syscalls = false;
            forced_signal = data as i32;
        }
        crate::ptrace::ptc::PTRACE_CONT => {
            ptracee.as_ptracee.ignore_syscalls = true;
            forced_signal = data as i32;
        }
        crate::ptrace::ptc::PTRACE_SINGLESTEP => {
            ptracee.restart_how = crate::ptrace::ptc::PTRACE_SINGLESTEP;
            forced_signal = data as i32;
        }
        33 /* PTRACE_SINGLEBLOCK */ => {
            ptracee.restart_how = 33;
            forced_signal = data as i32;
        }
        crate::ptrace::ptc::PTRACE_DETACH => {
            detach_from_ptracer(&mut ptracee, Some(ptracer));
        }
        crate::ptrace::ptc::PTRACE_KILL => {
            status = ptrace_req(request, ptracee_pid, 0, 0);
        }
        crate::ptrace::ptc::PTRACE_SETOPTIONS => {
            ptracee.as_ptracee.options = data;
            return 0; // Don't restart the ptracee.
        }
        crate::ptrace::ptc::PTRACE_GETEVENTMSG => {
            let mut result: Word = 0;
            let st = ptrace_req(request, ptracee_pid, 0, &mut result as *mut Word as usize);
            if st < 0 {
                return -crate::sys::errno();
            }
            crate::sys::clear_errno();
            poke_word(ptracer, data, result);
            if crate::sys::errno() != 0 {
                return -crate::sys::errno();
            }
            return 0;
        }
        crate::ptrace::ptc::PTRACE_PEEKUSER => {
            #[cfg(target_arch = "x86_64")]
            if is_32on64_mode(ptracer) {
                address = user::convert_user_offset(address);
                if address == Word::MAX {
                    return -libc::EIO;
                }
            }
            return peek_data(ptracer, request, ptracee_pid, address, data);
        }
        crate::ptrace::ptc::PTRACE_PEEKTEXT | crate::ptrace::ptc::PTRACE_PEEKDATA => {
            return peek_data(ptracer, request, ptracee_pid, address, data);
        }
        crate::ptrace::ptc::PTRACE_POKEUSER => {
            #[cfg(target_arch = "x86_64")]
            if is_32on64_mode(ptracer) {
                address = user::convert_user_offset(address);
                if address == Word::MAX {
                    return -libc::EIO;
                }
            }
            let st = ptrace_req(request, ptracee_pid, address as usize, data as usize);
            if st < 0 {
                return -crate::sys::errno();
            }
            return 0;
        }
        crate::ptrace::ptc::PTRACE_POKETEXT | crate::ptrace::ptc::PTRACE_POKEDATA => {
            let mut data = data;
            if is_32on64_mode(ptracer) {
                crate::sys::clear_errno();
                let tmp = crate::sys::ptrace(
                    crate::ptrace::ptc::PTRACE_PEEKDATA as u32,
                    ptracee_pid,
                    address as usize,
                    0,
                ) as Word;
                if crate::sys::errno() != 0 {
                    return -crate::sys::errno();
                }
                data |= tmp & 0xFFFF_FFFF_0000_0000;
            }
            let st = ptrace_req(request, ptracee_pid, address as usize, data as usize);
            if st < 0 {
                return -crate::sys::errno();
            }
            return 0;
        }
        crate::ptrace::ptc::PTRACE_GETSIGINFO => {
            let mut siginfo: libc::siginfo_t = crate::sys::zeroed();
            let st = ptrace_req(
                request,
                ptracee_pid,
                0,
                &mut siginfo as *mut _ as usize,
            );
            if st < 0 {
                return -crate::sys::errno();
            }
            let raw = crate::sys::as_bytes(&siginfo);
            return write_data(ptracer, data, raw);
        }
        crate::ptrace::ptc::PTRACE_SETSIGINFO => {
            let mut siginfo: libc::siginfo_t = crate::sys::zeroed();
            let raw = crate::sys::as_bytes_mut(&mut siginfo);
            let st = read_data(ptracer, raw, data);
            if st < 0 {
                return st;
            }
            let st = ptrace_req(request, ptracee_pid, 0, &mut siginfo as *mut _ as usize);
            if st < 0 {
                return -crate::sys::errno();
            }
            return 0;
        }
        #[cfg(target_arch = "x86_64")]
        crate::ptrace::ptc::PTRACE_GETREGS => {
            let mut buffer = vec![0u8; size_of::<libc::user_regs_struct>()];
            let st = ptrace_req(
                request,
                ptracee_pid,
                0,
                buffer.as_mut_ptr() as usize,
            );
            if st < 0 {
                return -crate::sys::errno();
            }
            let size = if is_32on64_mode(ptracer) {
                let mut regs32 = [0u32; user::USER32_NB_REGS];
                let mut regs64: Vec<u64> = buffer
                    .chunks_exact(8)
                    .map(|c| u64::from_ne_bytes(c.try_into().unwrap()))
                    .collect();
                user::convert_user_regs_struct(false, &mut regs64, &mut regs32);
                let raw = crate::sys::as_bytes(&regs32);
                buffer[..raw.len()].copy_from_slice(raw);
                regs32.len() * 4
            } else {
                buffer.len()
            };
            return write_data(ptracer, data, &buffer[..size]);
        }
        #[cfg(target_arch = "x86_64")]
        crate::ptrace::ptc::PTRACE_SETREGS => {
            let size = if is_32on64_mode(ptracer) {
                user::USER32_NB_REGS * 4
            } else {
                size_of::<libc::user_regs_struct>()
            };
            let mut buffer = vec![0u8; size_of::<libc::user_regs_struct>().max(size)];
            let st = read_data(ptracer, &mut buffer[..size], data);
            if st < 0 {
                return st;
            }
            if is_32on64_mode(ptracer) {
                let mut regs32 = [0u32; user::USER32_NB_REGS];
                for (i, c) in buffer[..size].chunks_exact(4).enumerate() {
                    regs32[i] = u32::from_ne_bytes(c.try_into().unwrap());
                }
                let mut regs64 = vec![0u64; size_of::<libc::user_regs_struct>() / 8];
                user::convert_user_regs_struct(true, &mut regs64, &mut regs32);
                for (i, v) in regs64.iter().enumerate() {
                    buffer[i * 8..i * 8 + 8].copy_from_slice(&v.to_ne_bytes());
                }
            }
            let st = ptrace_req(
                request,
                ptracee_pid,
                0,
                buffer.as_mut_ptr() as usize,
            );
            if st < 0 {
                return -crate::sys::errno();
            }
            return 0;
        }
        #[cfg(target_arch = "x86_64")]
        crate::ptrace::ptc::PTRACE_GETFPREGS => {
            let fp_sz = size_of::<libc::user_fpregs_struct>()
                .max(user::USER32_NB_FPREGS * 4);
            let mut buffer = vec![0u8; fp_sz];
            let st = ptrace_req(request, ptracee_pid, 0, buffer.as_mut_ptr() as usize);
            if st < 0 {
                return -crate::sys::errno();
            }
            let size = if is_32on64_mode(ptracer) {
                crate::note!(
                    Some(ptracer),
                    crate::note::Severity::Warning,
                    crate::note::Origin::Internal,
                    "ptrace 32-bit request 'PTRACE_GETFPREGS' not supported on 64-bit yet"
                );
                buffer.iter_mut().for_each(|b| *b = 0);
                user::USER32_NB_FPREGS * 4
            } else {
                size_of::<libc::user_fpregs_struct>()
            };
            return write_data(ptracer, data, &buffer[..size]);
        }
        #[cfg(target_arch = "x86_64")]
        crate::ptrace::ptc::PTRACE_SETFPREGS => {
            if is_32on64_mode(ptracer) {
                crate::note!(
                    Some(ptracer),
                    crate::note::Severity::Warning,
                    crate::note::Origin::Internal,
                    "ptrace 32-bit request 'PTRACE_SETFPREGS' not supported on 64-bit yet"
                );
                return -libc::ENOTSUP;
            }
            let size = size_of::<libc::user_fpregs_struct>();
            let mut buffer = vec![0u8; size];
            let st = read_data(ptracer, &mut buffer, data);
            if st < 0 {
                return st;
            }
            let st = ptrace_req(request, ptracee_pid, 0, buffer.as_mut_ptr() as usize);
            if st < 0 {
                return -crate::sys::errno();
            }
            return 0;
        }
        #[cfg(target_arch = "x86_64")]
        25 /* PTRACE_GET_THREAD_AREA */ => {
            let mut user_desc = [0u8; 16];
            let st = ptrace_req(
                request,
                ptracee_pid,
                address as usize,
                user_desc.as_mut_ptr() as usize,
            );
            if st < 0 {
                return -crate::sys::errno();
            }
            return write_data(ptracer, data, &user_desc);
        }
        #[cfg(target_arch = "x86_64")]
        26 /* PTRACE_SET_THREAD_AREA */ => {
            let mut user_desc = [0u8; 16];
            let st = read_data(ptracer, &mut user_desc, data);
            if st < 0 {
                return st;
            }
            let st = ptrace_req(
                request,
                ptracee_pid,
                address as usize,
                user_desc.as_mut_ptr() as usize,
            );
            if st < 0 {
                return -crate::sys::errno();
            }
            return 0;
        }
        crate::ptrace::ptc::PTRACE_GETREGSET => {
            crate::sys::clear_errno();
            let remote_base = peek_word(ptracer, data);
            if crate::sys::errno() != 0 {
                return -crate::sys::errno();
            }
            let remote_len = peek_word(ptracer, data + crate::tracee::reg::sizeof_word(ptracer) as Word);
            if crate::sys::errno() != 0 {
                return -crate::sys::errno();
            }
            let mut buf = vec![0u8; remote_len as usize];
            let mut local = libc::iovec {
                iov_base: buf.as_mut_ptr() as *mut libc::c_void,
                iov_len: remote_len as usize,
            };
            let st = ptrace_req(
                request,
                ptracee_pid,
                address as usize,
                &mut local as *mut _ as usize,
            );
            if st < 0 {
                return st;
            }
            let remote_len = remote_len.min(local.iov_len as Word);
            local.iov_len = remote_len as usize;
            let st = write_data(ptracer, remote_base, &buf[..local.iov_len]);
            if st < 0 {
                return st;
            }
            crate::sys::clear_errno();
            poke_word(
                ptracer,
                data + crate::tracee::reg::sizeof_word(ptracer) as Word,
                remote_len,
            );
            if crate::sys::errno() != 0 {
                return -crate::sys::errno();
            }
            return 0;
        }
        crate::ptrace::ptc::PTRACE_SETREGSET => {
            crate::sys::clear_errno();
            let remote_base = peek_word(ptracer, data);
            if crate::sys::errno() != 0 {
                return -crate::sys::errno();
            }
            let remote_len = peek_word(ptracer, data + crate::tracee::reg::sizeof_word(ptracer) as Word);
            if crate::sys::errno() != 0 {
                return -crate::sys::errno();
            }
            let mut buf = vec![0u8; remote_len as usize];
            let mut local = libc::iovec {
                iov_base: buf.as_mut_ptr() as *mut libc::c_void,
                iov_len: remote_len as usize,
            };
            let st = read_data(ptracer, &mut buf, remote_base);
            if st < 0 {
                return st;
            }
            let st = ptrace_req(
                request,
                ptracee_pid,
                address as usize,
                &mut local as *mut _ as usize,
            );
            if st < 0 {
                return st;
            }
            return 0;
        }
        _ => {}
    }

    // Requests handled below restart the ptracee.
    match request as i32 {
        crate::ptrace::ptc::PTRACE_SYSCALL
        | crate::ptrace::ptc::PTRACE_CONT
        | crate::ptrace::ptc::PTRACE_SINGLESTEP
        | 33 // SINGLEBLOCK
        | crate::ptrace::ptc::PTRACE_DETACH
        | crate::ptrace::ptc::PTRACE_KILL => {}
        _ => {
            crate::note!(
                Some(ptracer),
                crate::note::Severity::Warning,
                crate::note::Origin::Internal,
                "ptrace request '{}' not supported yet",
                stringify_ptrace(request)
            );
            return -libc::ENOTSUP;
        }
    }

    // Handle the ptracee's pending event, then restart it.
    let mut signal = if ptracee.as_ptracee.event4.proot.pending {
        let v = ptracee.as_ptracee.event4.proot.value;
        drop(ptracee);
        crate::tracee::event::handle_tracee_event(&ptracee_rc, v)
    } else {
        let v = ptracee.as_ptracee.event4.proot.value;
        drop(ptracee);
        v
    };
    if forced_signal != -1 {
        signal = forced_signal;
    }
    let _ = crate::tracee::event::restart_tracee(&ptracee_rc, signal);
    status
}

fn peek_data(ptracer: &mut Tracee, request: Word, pid: i32, address: Word, data: Word) -> i32 {
    crate::sys::clear_errno();
    let result = crate::sys::ptrace(request as u32, pid, address as usize, 0) as Word;
    let e = crate::sys::errno();
    if e != 0 {
        return -e;
    }
    crate::sys::clear_errno();
    poke_word(ptracer, data, result);
    if crate::sys::errno() != 0 {
        return -crate::sys::errno();
    }
    0
}

/// `stringify_ptrace()` — debug name for a request.
fn stringify_ptrace(request: Word) -> &'static str {
    match request as i32 {
        crate::ptrace::ptc::PTRACE_TRACEME => "PTRACE_TRACEME",
        crate::ptrace::ptc::PTRACE_PEEKTEXT => "PTRACE_PEEKTEXT",
        crate::ptrace::ptc::PTRACE_PEEKDATA => "PTRACE_PEEKDATA",
        crate::ptrace::ptc::PTRACE_PEEKUSER => "PTRACE_PEEKUSER",
        crate::ptrace::ptc::PTRACE_POKETEXT => "PTRACE_POKETEXT",
        crate::ptrace::ptc::PTRACE_POKEDATA => "PTRACE_POKEDATA",
        crate::ptrace::ptc::PTRACE_POKEUSER => "PTRACE_POKEUSER",
        crate::ptrace::ptc::PTRACE_CONT => "PTRACE_CONT",
        crate::ptrace::ptc::PTRACE_KILL => "PTRACE_KILL",
        crate::ptrace::ptc::PTRACE_SINGLESTEP => "PTRACE_SINGLESTEP",
        crate::ptrace::ptc::PTRACE_GETREGS => "PTRACE_GETREGS",
        crate::ptrace::ptc::PTRACE_SETREGS => "PTRACE_SETREGS",
        crate::ptrace::ptc::PTRACE_GETFPREGS => "PTRACE_GETFPREGS",
        crate::ptrace::ptc::PTRACE_SETFPREGS => "PTRACE_SETFPREGS",
        crate::ptrace::ptc::PTRACE_ATTACH => "PTRACE_ATTACH",
        crate::ptrace::ptc::PTRACE_DETACH => "PTRACE_DETACH",
        crate::ptrace::ptc::PTRACE_SYSCALL => "PTRACE_SYSCALL",
        crate::ptrace::ptc::PTRACE_SETOPTIONS => "PTRACE_SETOPTIONS",
        crate::ptrace::ptc::PTRACE_GETEVENTMSG => "PTRACE_GETEVENTMSG",
        crate::ptrace::ptc::PTRACE_GETSIGINFO => "PTRACE_GETSIGINFO",
        crate::ptrace::ptc::PTRACE_SETSIGINFO => "PTRACE_SETSIGINFO",
        crate::ptrace::ptc::PTRACE_GETREGSET => "PTRACE_GETREGSET",
        crate::ptrace::ptc::PTRACE_SETREGSET => "PTRACE_SETREGSET",
        crate::ptrace::ptc::PTRACE_SEIZE => "PTRACE_SEIZE",
        crate::ptrace::ptc::PTRACE_INTERRUPT => "PTRACE_INTERRUPT",
        crate::ptrace::ptc::PTRACE_LISTEN => "PTRACE_LISTEN",
        crate::ptrace::ptc::PTRACE_SET_SYSCALL => "PTRACE_SET_SYSCALL",
        33 => "PTRACE_SINGLEBLOCK",
        25 => "PTRACE_GET_THREAD_AREA",
        26 => "PTRACE_SET_THREAD_AREA",
        _ => "PTRACE_???",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stringify_ptrace_names() {
        use crate::ptrace::ptc::*;
        assert_eq!(stringify_ptrace(PTRACE_TRACEME as Word), "PTRACE_TRACEME");
        assert_eq!(stringify_ptrace(PTRACE_SYSCALL as Word), "PTRACE_SYSCALL");
        assert_eq!(stringify_ptrace(PTRACE_ATTACH as Word), "PTRACE_ATTACH");
        assert_eq!(stringify_ptrace(PTRACE_DETACH as Word), "PTRACE_DETACH");
        assert_eq!(stringify_ptrace(PTRACE_SEIZE as Word), "PTRACE_SEIZE");
        assert_eq!(
            stringify_ptrace(PTRACE_SETOPTIONS as Word),
            "PTRACE_SETOPTIONS"
        );
        assert_eq!(stringify_ptrace(0x7FFF as Word), "PTRACE_???");
    }
}
