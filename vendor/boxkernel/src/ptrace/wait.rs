//! wait(2) emulation for emulated ptrace relations — port of
//! ptrace/wait.c.

use crate::Word;
use crate::sysnum::Sysnum;
use crate::tracee::event::TraceeRef;
use crate::tracee::mem::poke_int32;
use crate::tracee::reg::{Reg, RegVersion, peek_reg, poke_reg, push_regs, set_sysnum};
use crate::tracee::{Tracee, WaitsIn, get_tracee};

/// `EXPECTED_WAIT_CLONE` — whether @tracee matches @wait_options'
/// clone-ness filter.
fn expected_wait_clone(wait_options: Word, tracee: &Tracee) -> bool {
    (wait_options & libc::__WALL as Word) != 0
        || ((wait_options & libc::__WCLONE as Word) != 0 && tracee.is_clone)
        || ((wait_options & libc::__WCLONE as Word) == 0 && !tracee.is_clone)
}

/// `get_ptracee()` — find a ptracee of `ptracer` matching pid/stopped/
/// pending-event/wait-kind constraints.  Zombies are returned first.
fn get_ptracee(
    ptracer: &mut Tracee,
    pid: i32,
    only_stopped: bool,
    only_with_pevent: bool,
    wait_options: Word,
) -> Option<TraceeRef> {
    // Zombies first.
    let zombies = ptracer.as_ptracer.zombies.clone();
    for zombie in zombies {
        let z = zombie.borrow();
        if pid != z.pid && pid != -1 {
            continue;
        }
        if !expected_wait_clone(wait_options, &z) {
            continue;
        }
        drop(z);
        return Some(zombie);
    }

    for p in crate::tracee::all_pids() {
        let rc = match get_tracee(p, false) {
            Some(r) => r,
            None => continue,
        };
        // `ptracer` itself is already mutably borrowed up the call chain;
        // it can never be its own ptracee, so skip it.
        let t = match rc.try_borrow() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if t.as_ptracee.ptracer != ptracer.pid {
            continue;
        }
        if pid != t.pid && pid != -1 {
            continue;
        }
        if !expected_wait_clone(wait_options, &t) {
            continue;
        }
        if !only_stopped {
            drop(t);
            return Some(rc);
        }
        if t.running {
            continue;
        }
        if t.as_ptracee.event4.ptracer.pending || !only_with_pevent {
            drop(t);
            return Some(rc);
        }
        if pid == t.pid {
            return None;
        }
    }
    None
}

/// `get_stopped_ptracee()`.
pub fn get_stopped_ptracee(
    ptracer: &mut Tracee,
    pid: i32,
    only_with_pevent: bool,
    wait_options: Word,
) -> Option<TraceeRef> {
    get_ptracee(ptracer, pid, true, only_with_pevent, wait_options)
}

/// `has_ptracees()`.
pub fn has_ptracees(ptracer: &mut Tracee, pid: i32, wait_options: Word) -> bool {
    get_ptracee(ptracer, pid, false, false, wait_options).is_some()
}

/// `translate_wait_enter()` — void the wait when the ptracer is waiting
/// for one of its ptracees.
pub fn translate_wait_enter(ptracer: &mut Tracee) -> i32 {
    ptracer.as_ptracer.waits_in = WaitsIn::Kernel;

    if ptracer.as_ptracer.nb_ptracees == 0 {
        return 0;
    }

    let pid = peek_reg(ptracer, RegVersion::Original, Reg::Sysarg1) as i64 as i32;
    if pid != -1 {
        let ok = match get_tracee(pid, false) {
            Some(rc) => rc.borrow().as_ptracee.ptracer == ptracer.pid,
            None => false,
        };
        if !ok {
            return 0;
        }
    }

    set_sysnum(ptracer, Sysnum::Void);
    ptracer.as_ptracer.waits_in = WaitsIn::Proot;
    0
}

/// `update_wait_status()` — write the pending event into the ptracer's
/// wstatus out-param.  Returns the ptracee pid, -errno, or 0 to restart
/// the original wait.
fn update_wait_status(ptracer: &mut Tracee, ptracee_rc: &TraceeRef) -> i32 {
    let ptracee_pid = ptracee_rc.borrow().pid;

    // Kernel reports the terminating event to both parent and tracer —
    // unless they're the same process (PRoot-as-parent): pass it to the
    // real wait once, via the original syscall.
    let terminate_once = {
        let p = ptracee_rc.borrow();
        p.as_ptracee.ptracer == p.parent
            && (libc::WIFEXITED(p.as_ptracee.event4.ptracer.value)
                || libc::WIFSIGNALED(p.as_ptracee.event4.ptracer.value))
    };
    if terminate_once {
        crate::syscall::chain::restart_original_syscall(ptracer);

        {
            let mut p = ptracee_rc.borrow_mut();
            crate::ptrace::detach_from_ptracer(&mut p, Some(ptracer));
        }
        // Zombies rest in peace once notified.
        let is_zombie = ptracee_rc.borrow().as_ptracee.is_zombie;
        if is_zombie {
            remove_zombie(ptracer, ptracee_pid);
        }
        return 0;
    }

    let event_value;
    let is_zombie;
    {
        let mut p = ptracee_rc.borrow_mut();
        event_value = p.as_ptracee.event4.ptracer.value;
        is_zombie = p.as_ptracee.is_zombie;
        p.as_ptracee.event4.ptracer.pending = false;
    }

    let address = peek_reg(ptracer, RegVersion::Original, Reg::Sysarg2);
    if address != 0 {
        crate::sys::clear_errno();
        poke_int32(ptracer, address, event_value);
        if crate::sys::errno() != 0 {
            return -crate::sys::errno();
        }
    }

    if is_zombie {
        let mut p = ptracee_rc.borrow_mut();
        crate::ptrace::detach_from_ptracer(&mut p, Some(ptracer));
        drop(p);
        remove_zombie(ptracer, ptracee_pid);
    }

    ptracee_pid
}

/// Remove a zombie from the ptracer's zombie list (C's TALLOC_FREE +
/// remove_zombie destructor).
fn remove_zombie(ptracer: &mut Tracee, zombie_pid: i32) {
    ptracer
        .as_ptracer
        .zombies
        .retain(|z| z.borrow().pid != zombie_pid);
}

/// `translate_wait_exit()` — resolve the voided wait.
pub fn translate_wait_exit(ptracer: &mut Tracee) -> i32 {
    debug_assert!(ptracer.as_ptracer.waits_in == WaitsIn::Proot);
    ptracer.as_ptracer.waits_in = WaitsIn::DoesntWait;

    let pid = peek_reg(ptracer, RegVersion::Original, Reg::Sysarg1) as i64 as i32;
    let options = peek_reg(ptracer, RegVersion::Original, Reg::Sysarg3);

    let ptracee_rc = get_stopped_ptracee(ptracer, pid, true, options);
    match ptracee_rc {
        None => {
            if ptracer.as_ptracer.nb_ptracees == 0 {
                return -libc::ECHILD;
            }
            if (options & libc::WNOHANG as Word) != 0 {
                return if has_ptracees(ptracer, pid, options) {
                    0
                } else {
                    -libc::ECHILD
                };
            }
            // Sleep until a ptracee event wakes us (handle_ptracee_event).
            ptracer.as_ptracer.wait_pid = pid;
            ptracer.as_ptracer.wait_options = options;
            0
        }
        Some(rc) => update_wait_status(ptracer, &rc),
    }
}

/// `handle_ptracee_event()` — forward a wait status to the ptracee's
/// emulated ptracer; returns whether the ptracee stays stopped.
pub fn handle_ptracee_event(ptracee_rc: &TraceeRef, event: i32) -> bool {
    let mut event = event;
    let mut keep_stopped = true;
    let mut handled_by_proot_first = false;
    let mut handled_by_proot_first_may_suppress = false;

    let ptracer_pid = ptracee_rc.borrow().as_ptracee.ptracer;
    debug_assert!(ptracer_pid != 0);
    let ptracer_rc = match get_tracee(ptracer_pid, false) {
        Some(r) => r,
        None => return false,
    };

    {
        let mut ptracee = ptracee_rc.borrow_mut();
        // Remember the event for PRoot's own later handling.
        ptracee.as_ptracee.event4.proot.value = event;
        ptracee.as_ptracee.event4.proot.pending = true;

        if libc::WIFSTOPPED(event) {
            let sig = (event & 0xfff00) >> 8;
            // PTRACE_EVENT_* names share (SIGTRAP | event << 8).
            let opt_for_event = match sig {
                s if s == libc::SIGTRAP | (crate::ptrace::ptc::PTRACE_EVENT_FORK << 8) => {
                    Some(crate::ptrace::ptc::PTRACE_O_TRACEFORK)
                }
                s if s == libc::SIGTRAP | (crate::ptrace::ptc::PTRACE_EVENT_VFORK << 8) => {
                    Some(crate::ptrace::ptc::PTRACE_O_TRACEVFORK)
                }
                s if s == libc::SIGTRAP | (crate::ptrace::ptc::PTRACE_EVENT_VFORK_DONE << 8) => {
                    Some(crate::ptrace::ptc::PTRACE_O_TRACEVFORKDONE)
                }
                s if s == libc::SIGTRAP | (crate::ptrace::ptc::PTRACE_EVENT_CLONE << 8) => {
                    Some(crate::ptrace::ptc::PTRACE_O_TRACECLONE)
                }
                s if s == libc::SIGTRAP | (crate::ptrace::ptc::PTRACE_EVENT_EXIT << 8) => {
                    Some(crate::ptrace::ptc::PTRACE_O_TRACEEXIT)
                }
                s if s == libc::SIGTRAP | (crate::ptrace::ptc::PTRACE_EVENT_EXEC << 8) => {
                    Some(crate::ptrace::ptc::PTRACE_O_TRACEEXEC)
                }
                _ => None,
            };
            if sig == libc::SIGTRAP | 0x80 {
                if ptracee.as_ptracee.ignore_syscalls || ptracee.as_ptracee.ignore_loader_syscalls {
                    return false;
                }
                if (ptracee.as_ptracee.options & crate::ptrace::ptc::PTRACE_O_TRACESYSGOOD as Word)
                    == 0
                {
                    event &= !(0x80 << 8);
                }
                handled_by_proot_first = crate::tracee::is_in_sysexit(&ptracee);
            } else if let Some(opt) = opt_for_event {
                if (ptracee.as_ptracee.options & opt as Word) == 0 {
                    return false;
                }
                ptracee.as_ptracee.tracing_started = true;
                handled_by_proot_first = true;
            } else if sig == libc::SIGTRAP | (crate::ptrace::ptc::PTRACE_EVENT_SECCOMP << 8)
                || sig == libc::SIGTRAP | (0x08 << 8)
            {
                // Seccomp events aren't supported under ptrace emulation.
                return false;
            } else if sig == libc::SIGSYS {
                handled_by_proot_first = true;
                handled_by_proot_first_may_suppress = true;
            } else {
                ptracee.as_ptracee.tracing_started = true;
            }
        } else if libc::WIFEXITED(event) || libc::WIFSIGNALED(event) {
            // The ptracee isn't really alive: always restart it.
            ptracee.as_ptracee.tracing_started = true;
            keep_stopped = false;
        }

        if !ptracee.as_ptracee.tracing_started {
            return false;
        }
    }

    // Some events must be handled by PRoot before reaching the ptracer.
    if handled_by_proot_first {
        let proot_value = ptracee_rc.borrow().as_ptracee.event4.proot.value;
        let signal = crate::tracee::event::handle_tracee_event(ptracee_rc, proot_value);
        ptracee_rc.borrow_mut().as_ptracee.event4.proot.value = signal;

        if handled_by_proot_first_may_suppress {
            if signal == 0 {
                if crate::tracee::event::seccomp_event_happens_after_enter_sigtrap() {
                    if ptracee_rc.borrow().as_ptracee.ignore_syscalls {
                        crate::tracee::event::restart_tracee(ptracee_rc, 0);
                        return true;
                    }
                    // Notify the ptracer about the syscall exit anyway.
                    ptracee_rc.borrow_mut().as_ptracee.event4.proot.value = 0;
                    event = if (ptracee_rc.borrow().as_ptracee.options
                        & crate::ptrace::ptc::PTRACE_O_TRACESYSGOOD as Word)
                        != 0
                    {
                        (libc::SIGTRAP | 0x80) << 8 | 0x7f
                    } else {
                        libc::SIGTRAP << 8 | 0x7f
                    };
                } else {
                    crate::tracee::event::restart_tracee(ptracee_rc, 0);
                    return true;
                }
            }
        } else {
            debug_assert_eq!(signal, 0);
        }
    }

    {
        let mut ptracee = ptracee_rc.borrow_mut();
        ptracee.as_ptracee.event4.ptracer.value = event;
        ptracee.as_ptracee.event4.ptracer.pending = true;
    }

    // Notify the ptracer asynchronously, like the kernel would.
    crate::sys::kill(ptracer_pid, libc::SIGCHLD);

    let (wait_pid, wait_options) = {
        let p = ptracer_rc.borrow();
        (p.as_ptracer.wait_pid, p.as_ptracer.wait_options)
    };
    let matches = (wait_pid == -1 || wait_pid == ptracee_rc.borrow().pid)
        && expected_wait_clone(wait_options, &ptracee_rc.borrow());

    if matches {
        let mut ptracer = ptracer_rc.borrow_mut();
        let status = update_wait_status(&mut ptracer, ptracee_rc);
        if status == 0 {
            crate::syscall::chain::chain_next_syscall(&mut ptracer);
        } else {
            poke_reg(&mut ptracer, Reg::SysargResult, status as Word);
        }
        let _ = push_regs(&mut ptracer);
        ptracer.as_ptracer.wait_pid = 0;
        drop(ptracer);

        let restarted = crate::tracee::event::restart_tracee(&ptracer_rc, 0);
        if !restarted {
            keep_stopped = false;
        }
    }

    keep_stopped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wait_clone_filter() {
        let mut t = Tracee {
            is_clone: false,
            ..Default::default()
        };
        // No flags -> non-clone matches, clone doesn't.
        assert!(expected_wait_clone(0, &t));
        assert!(!expected_wait_clone(libc::__WCLONE as Word, &t));
        // __WALL matches everything.
        assert!(expected_wait_clone(libc::__WALL as Word, &t));
        t.is_clone = true;
        assert!(!expected_wait_clone(0, &t));
        assert!(expected_wait_clone(libc::__WCLONE as Word, &t));
        assert!(expected_wait_clone(libc::__WALL as Word, &t));
        assert!(expected_wait_clone(
            (libc::__WCLONE | libc::__WALL) as Word,
            &t
        ));
    }

    #[test]
    fn remove_zombie_removes_by_pid() {
        let mut p = Tracee::default();
        let z1 = TraceeRef::new(std::cell::RefCell::new(Tracee::default()));
        let z2 = TraceeRef::new(std::cell::RefCell::new(Tracee::default()));
        z1.borrow_mut().pid = 111;
        z2.borrow_mut().pid = 222;
        p.as_ptracer.zombies.push(z1);
        p.as_ptracer.zombies.push(z2.clone());
        remove_zombie(&mut p, 111);
        assert_eq!(p.as_ptracer.zombies.len(), 1);
        assert_eq!(p.as_ptracer.zombies[0].borrow().pid, 222);
        // Removing a non-member is a no-op.
        remove_zombie(&mut p, 999);
        assert_eq!(p.as_ptracer.zombies.len(), 1);
    }

    #[test]
    fn wait_enter_no_ptracees_is_plain() {
        let mut t = Tracee::default();
        // No ptracees -> kernel wait proceeds unmodified.
        assert_eq!(translate_wait_enter(&mut t), 0);
        assert_eq!(t.as_ptracer.waits_in, WaitsIn::Kernel);
    }
}
