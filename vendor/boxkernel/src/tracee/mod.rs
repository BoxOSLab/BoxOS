//! Tracee process model — port of tracee/tracee.h + tracee.c.
//!
//! A [`Tracee`] is one instrumented process: its ptrace state, register
//! snapshots, ABI word size, memory accessors, pending syscalls and
//! extensions.  The global registry maps host pid → tracee; the
//! [`event`] module runs the `waitpid`/`ptrace` stop loop that drives
//! everything else.

pub mod abi;
pub mod event;
pub mod mem;
pub mod reg;
pub mod seccomp;
pub mod statx;

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use crate::Word;
use crate::extension::AnyExtension;
use crate::syscall::chain::Chain;
use crate::syscall::heap::Heap;
use crate::sysnum::Sysnum;

pub use reg::{Reg, RegVersion, Regs};

/// File-system name-space shared between tracees that cloned with CLONE_FS.
#[derive(Default)]
pub struct FileSystemNameSpace {
    pub pending: Vec<Rc<crate::path::binding::Binding>>,
    pub guest: Vec<Rc<crate::path::binding::Binding>>,
    pub host: Vec<Rc<crate::path::binding::Binding>>,
    /// Canonicalized *guest* cwd (`/proc/self/pwd` equivalent).
    pub cwd: crate::fpath::FixedPath,
}

/// ptrace emulation: this tracee acting as a tracer.
#[derive(Default)]
pub struct AsPtracer {
    pub nb_ptracees: usize,
    /// Dummy tracees standing in for dead ptracees until the ptracer
    /// collects their exit event (not registered in the tracee map).
    pub zombies: Vec<Rc<RefCell<Tracee>>>,
    pub wait_pid: i32,
    pub wait_options: Word,
    pub waits_in: WaitsIn,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum WaitsIn {
    #[default]
    DoesntWait = 0,
    Kernel,
    Proot,
}

/// ptrace emulation: this tracee being traced by another tracee.
#[derive(Default)]
pub struct AsPtracee {
    /// pid of the ptracing tracee (0 = none).
    pub ptracer: i32,
    pub event4: Event4,
    pub tracing_started: bool,
    pub ignore_loader_syscalls: bool,
    pub ignore_syscalls: bool,
    pub options: Word,
    pub is_zombie: bool,
}

#[derive(Default)]
pub struct Event4 {
    pub proot: PEvent,
    pub ptracer: PEvent,
}

#[derive(Default)]
pub struct PEvent {
    pub value: i32,
    pub pending: bool,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum Seccomp {
    #[default]
    Disabled = 0,
    Disabling,
    Enabled,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum Sigstop {
    #[default]
    Ignored = 0,
    Allowed,
    Pending,
}

/// pid → internal index.  Tracees are stored in a global arena so that
/// cross-references stay cheap keys rather than borrowed pointers.
pub type TraceeId = usize;

#[derive(Default)]
pub struct FakeNetlinkSocket {
    pub fd: i32,
    pub reply: Vec<u8>,
    pub reply_off: usize,
}

pub const MAX_FAKE_NETLINK_FDS: usize = 8;
pub const MAX_FAKE_NETLINK_REPLY: usize = 8192;
pub const MAX_NETLINK_ROUTE_FDS: usize = 8;

pub struct Tracee {
    pub pid: i32,
    pub vpid: u64,
    pub running: bool,
    pub terminated: bool,
    pub killall_on_exit: bool,

    /// pid of the tracee that created this one (0 = none).
    pub parent: i32,
    pub is_clone: bool,
    pub clone_stripped_newns: bool,
    pub clone_stripped_newnet: bool,
    pub fake_netns: bool,

    pub fake_netlink_fds: Vec<FakeNetlinkSocket>,
    pub pending_fake_netlink_socket: bool,
    pub netlink_route_fds: Vec<i32>,
    pub pending_real_netlink_socket: bool,
    pub netlink_ack_pending: bool,
    pub netlink_ack_fd: i32,
    pub netlink_ack_seq: u32,

    pub as_ptracer: AsPtracer,
    pub as_ptracee: AsPtracee,

    /// 0: sysenter, 1: sysexit-ok, -errno: sysexit-error.
    pub status: i32,

    pub restart_how: i32,
    pub last_restart_how: i32,

    /// Register banks: [CURRENT, ORIGINAL, MODIFIED, ORIGINAL_SECCOMP_REWRITE].
    pub regs: [Regs; 4],
    pub regs_were_changed: bool,
    pub restore_original_regs: bool,
    pub restore_original_regs_after_seccomp_event: bool,

    pub sigstop: Sigstop,
    pub skip_next_seccomp_signal: bool,
    pub voided_syscall_cancelled: bool,
    pub restore_sysarg1_after_sigsys: bool,

    /// Type of the final component while initializing a binding (glue).
    pub glue_type: u32,

    /// Sub-reconfiguration context: tracee + $PATH.
    pub reconf_tracee: Option<TraceeId>,
    pub reconf_paths: Option<String>,

    /// Chained syscalls inserted after an actual syscall.
    pub chain: Chain,

    /// Load info generated during execve sysenter (used at sysexit).
    pub load_info: Option<Box<crate::execve::LoadInfo>>,

    /// Address of `argv[0]` on the initial stack (AT_EXECFN fixup).
    pub execfn_addr: Word,

    /// fd the tracee used to open /proc/self/auxv (-1 = inactive).
    pub auxv_fd: i32,

    // ---- inherited private resources ----
    pub verbose: i32,
    pub seccomp: Seccomp,
    pub sysexit_pending: bool,
    pub pending_child: bool,
    pub pending_clone_flags: Word,
    pub pending_child_sp: Word,
    pub seccomp_already_handled_enter: bool,
    pub no_new_privs: bool,
    pub seen_execve: bool,

    // ---- CLONE_FS/VM-shared resources ----
    pub fs: Rc<RefCell<FileSystemNameSpace>>,
    pub heap: Rc<RefCell<Heap>>,

    // ---- shared until execve ----
    /// Path to the executable, a'la /proc/self/exe (guest canonical).
    pub exe: Option<Rc<str>>,
    pub new_exe: Option<String>,
    pub host_exe: Option<String>,

    // ---- configuration ----
    pub qemu: Option<Rc<[String]>>,
    pub skip_proot_loader: bool,
    pub glue: Option<Rc<str>>,
    pub extensions: Vec<Option<AnyExtension>>,

    // ---- read-only shared ----
    pub host_ldso_paths: Option<Rc<str>>,
    pub guest_ldso_paths: Option<Rc<str>>,

    /// Scratch storage for the "still in sysenter" execve bookkeeping.
    pub execve_pending: Option<ExecvePending>,

    /// Deferred cleanups scheduled during an event — the Rust equivalent
    /// of talloc destructors hung off `tracee->ctx`.  Flushed by
    /// [`get_tracee`] when the tracee is fetched for a new event (the C
    /// code frees `tracee->ctx` at the same boundary).
    pub deferred: Vec<Box<dyn FnOnce()>>,
}

/// Bookkeeping saved between execve sysenter and sysexit.
pub struct ExecvePending {
    pub load_info: Box<crate::execve::LoadInfo>,
}

impl Default for Tracee {
    fn default() -> Self {
        Tracee {
            pid: 0,
            vpid: 0,
            running: false,
            terminated: false,
            killall_on_exit: false,
            parent: 0,
            is_clone: false,
            clone_stripped_newns: false,
            clone_stripped_newnet: false,
            fake_netns: false,
            fake_netlink_fds: Vec::new(),
            pending_fake_netlink_socket: false,
            netlink_route_fds: Vec::new(),
            pending_real_netlink_socket: false,
            netlink_ack_pending: false,
            netlink_ack_fd: -1,
            netlink_ack_seq: 0,
            as_ptracer: AsPtracer::default(),
            as_ptracee: AsPtracee::default(),
            status: 0,
            restart_how: 0,
            last_restart_how: 0,
            regs: crate::sys::zeroed(),
            regs_were_changed: false,
            restore_original_regs: true,
            restore_original_regs_after_seccomp_event: false,
            sigstop: Sigstop::Ignored,
            skip_next_seccomp_signal: false,
            voided_syscall_cancelled: false,
            restore_sysarg1_after_sigsys: false,
            glue_type: 0,
            reconf_tracee: None,
            reconf_paths: None,
            chain: Chain::default(),
            load_info: None,
            execfn_addr: 0,
            auxv_fd: -1,
            verbose: 0,
            seccomp: Seccomp::Disabled,
            sysexit_pending: false,
            pending_child: false,
            pending_clone_flags: 0,
            pending_child_sp: 0,
            seccomp_already_handled_enter: false,
            no_new_privs: false,
            seen_execve: false,
            fs: Rc::new(RefCell::new(FileSystemNameSpace::default())),
            heap: Rc::new(RefCell::new(Heap::default())),
            exe: None,
            new_exe: None,
            host_exe: None,
            qemu: None,
            skip_proot_loader: false,
            glue: None,
            extensions: Vec::new(),
            host_ldso_paths: None,
            guest_ldso_paths: None,
            execve_pending: None,
            deferred: Vec::new(),
        }
    }
}

// ==================================================================
// Global tracee registry
// ==================================================================

thread_local! {
    static TRACEES: RefCell<HashMap<i32, Rc<RefCell<Tracee>>>> = RefCell::new(HashMap::new());
    static TRACEE_ORDER: RefCell<Vec<i32>> = const { RefCell::new(Vec::new()) };
    static NEXT_VPID: RefCell<u64> = const { RefCell::new(1) };
    /// Pid of the first tracee (for "-k" / last exit status reporting).
    pub static FIRST_TRACEE_PID: RefCell<i32> = const { RefCell::new(0) };
}

/// Borrow the tracee map immutably for `f`.
pub fn with_tracee<R>(pid: i32, f: impl FnOnce(&Tracee) -> R) -> Option<R> {
    TRACEES.with(|t| t.borrow().get(&pid).map(|rc| f(&rc.borrow())))
}

/// Borrow the tracee map mutably for `f`.
pub fn with_tracee_mut<R>(pid: i32, f: impl FnOnce(&mut Tracee) -> R) -> Option<R> {
    TRACEES.with(|t| t.borrow().get(&pid).map(|rc| f(&mut rc.borrow_mut())))
}

/// Like `with_tracee_mut` but returns `None` instead of panicking when the
/// tracee's `RefCell` is already borrowed (it is a raw pointer in C, where
/// aliasing is fine; here we must degrade gracefully).
pub fn with_tracee_mut_try<R>(pid: i32, f: impl FnOnce(&mut Tracee) -> R) -> Option<R> {
    TRACEES
        .try_with(|t| t.borrow().get(&pid).cloned())
        .ok()
        .flatten()
        .and_then(|rc| rc.try_borrow_mut().ok().map(|mut t| f(&mut t)))
}

/// Get an `Rc` handle on the tracee with @pid, creating+registering a fresh
/// one when `create` is true.
pub fn get_tracee(pid: i32, create: bool) -> Option<Rc<RefCell<Tracee>>> {
    TRACEES.with(|map| {
        if let Some(rc) = map.borrow().get(&pid) {
            let rc = rc.clone();
            // Flush the per-event scratch (C frees tracee->ctx here).  Skip
            // when the tracee is already borrowed — the caller owns it and
            // the actions run at the next boundary instead.
            if let Ok(mut t) = rc.try_borrow_mut() {
                let actions = std::mem::take(&mut t.deferred);
                drop(t);
                for action in actions {
                    action();
                }
            }
            return Some(rc);
        }
        if !create {
            return None;
        }
        let vpid = NEXT_VPID.with(|v| {
            let v = &mut *v.borrow_mut();
            let cur = *v;
            *v += 1;
            cur
        });
        let t = Tracee {
            pid,
            vpid,
            ..Tracee::default()
        };
        let rc = Rc::new(RefCell::new(t));
        map.borrow_mut().insert(pid, rc.clone());
        TRACEE_ORDER.with(|o| o.borrow_mut().push(pid));
        Some(rc)
    })
}

/// Iterating helper: runs `f` on each live tracee (snapshot of pids).
/// Safe to call from atexit/signal contexts: no-ops once TLS is dead.
pub fn for_each_tracee(mut f: impl FnMut(Rc<RefCell<Tracee>>)) {
    let pids: Vec<i32> = match TRACEE_ORDER.try_with(|o| o.borrow().clone()) {
        Ok(p) => p,
        Err(_) => return,
    };
    for pid in pids {
        if let Ok(Some(rc)) = TRACEES.try_with(|t| t.borrow().get(&pid).cloned()) {
            f(rc);
        }
    }
}

/// Register an already-allocated tracee Rc under `pid` (used at launch, when
/// the tracee object exists before its pid is known).
pub fn register_existing(rc: &Rc<RefCell<Tracee>>, pid: i32) {
    TRACEES.with(|m| m.borrow_mut().insert(pid, rc.clone()));
    TRACEE_ORDER.with(|o| o.borrow_mut().push(pid));
}

/// Remove the registry entry for `pid` without terminating the tracee
/// (used when re-keying the placeholder pid at launch).
pub fn unregister(pid: i32) {
    TRACEES.with(|m| m.borrow_mut().remove(&pid));
    TRACEE_ORDER.with(|o| o.borrow_mut().retain(|&p| p != pid));
}

/// Snapshot of all registered tracee pids.
pub fn all_pids() -> Vec<i32> {
    TRACEE_ORDER.with(|o| o.borrow().clone())
}

pub fn tracee_count() -> usize {
    TRACEES.with(|t| t.borrow().len())
}

pub fn verbose_of(tracee: Option<&Tracee>) -> i32 {
    match tracee {
        Some(t) => t.verbose,
        None => crate::note::global_verbose(),
    }
}

/// Shortcut for `tracee.status == 0` (IS_IN_SYSENTER).
#[inline]
pub fn is_in_sysenter(tracee: &Tracee) -> bool {
    tracee.status == 0
}

#[inline]
pub fn is_in_sysexit(tracee: &Tracee) -> bool {
    !is_in_sysenter(tracee)
}

#[inline]
pub fn is_in_sysexit2(tracee: &Tracee, sysnum: Sysnum) -> bool {
    is_in_sysexit(tracee) && crate::tracee::reg::get_sysnum(tracee, RegVersion::Original) == sysnum
}

// ==================================================================
// Lifecycle
// ==================================================================

/// `terminate_tracee()` — mark a tracee dead; actual removal happens in
/// `free_terminated_tracees()` at a safe point in the event loop.
pub fn terminate_tracee(pid: i32) {
    let kill_all = with_tracee_mut(pid, |t| {
        t.terminated = true;
        t.running = false;
        t.killall_on_exit
    })
    .unwrap_or(false);

    // Case where the terminated tracee is marked to kill all tracees on exit.
    if kill_all {
        if let Some(rc) = get_tracee(pid, false) {
            crate::verbose!(Some(&rc.borrow()), 1, "terminating all tracees on exit");
        }
        kill_all_tracees();
    }
}

/// Reap terminated tracees — port of `remove_tracee()` + the
/// `free_terminated_tracees()` sweep.  Besides dropping registry entries
/// this orphans children, releases ptracees, zombifies dead ptracees that
/// still owe their ptracer an event, and wakes idle ptracers.
pub fn free_terminated_tracees() {
    // Runs every event-loop iteration; skip the snapshot allocation in
    // the common case where nobody has terminated.
    let any_dead = TRACEES.with(|map| map.borrow().values().any(|rc| rc.borrow().terminated));
    if !any_dead {
        return;
    }
    let dead: Vec<Rc<RefCell<Tracee>>> = TRACEES.with(|map| {
        map.borrow()
            .values()
            .filter(|rc| rc.borrow().terminated)
            .cloned()
            .collect()
    });
    for rc in dead {
        remove_tracee(&rc);
        TRACEES.with(|m| m.borrow_mut().remove(&rc.borrow().pid));
        TRACEE_ORDER.with(|o| o.borrow_mut().retain(|&p| p != rc.borrow().pid));
    }
}

/// `remove_tracee()` — the C talloc destructor.
fn remove_tracee(tracee_rc: &Rc<RefCell<Tracee>>) {
    let dead_pid = tracee_rc.borrow().pid;

    // Orphan this tracee's children and free the processes it traced.
    let pids = all_pids();
    for pid in pids {
        if pid == dead_pid {
            continue;
        }
        let relative_rc = match get_tracee(pid, false) {
            Some(r) => r,
            None => continue,
        };
        let mut relative = relative_rc.borrow_mut();

        // Its children are now orphan.
        if relative.parent == dead_pid {
            relative.parent = 0;
        }

        // Its tracees are now free.
        if relative.as_ptracee.ptracer == dead_pid {
            relative.as_ptracee.ptracer = 0;
            if relative.as_ptracee.event4.proot.pending {
                let event = relative.as_ptracee.event4.proot.value;
                drop(relative);
                let ev = crate::tracee::event::handle_tracee_event(&relative_rc, event);
                crate::tracee::event::restart_tracee(&relative_rc, ev);
            } else if relative.as_ptracee.event4.ptracer.pending {
                let event = relative.as_ptracee.event4.proot.value;
                drop(relative);
                crate::tracee::event::restart_tracee(&relative_rc, event);
            }
        }
    }

    let ptracer_pid = tracee_rc.borrow().as_ptracee.ptracer;
    if ptracer_pid == 0 {
        // Give extensions a chance to release per-tracee state.
        let mut t = tracee_rc.borrow_mut();
        let exts = std::mem::take(&mut t.extensions);
        drop(t);
        drop(exts);
        return;
    }

    // Zombify this ptracee until its ptracer collects its death event.
    {
        let t = tracee_rc.borrow();
        let ev = t.as_ptracee.event4.ptracer.value;
        if t.as_ptracee.event4.ptracer.pending && (libc::WIFEXITED(ev) || libc::WIFSIGNALED(ev)) {
            if let Some(ptracer_rc) = get_tracee(ptracer_pid, false) {
                let zombie = Rc::new(RefCell::new(Tracee {
                    pid: dead_pid,
                    parent: t.parent,
                    is_clone: t.is_clone,
                    ..Tracee::default()
                }));
                detach_from_ptracer(dead_pid);
                zombie.borrow_mut().as_ptracee.ptracer = ptracer_pid;
                {
                    let mut p = ptracer_rc.borrow_mut();
                    p.as_ptracer.zombies.push(zombie.clone());
                    p.as_ptracer.nb_ptracees += 1;
                }
                let mut z = zombie.borrow_mut();
                z.as_ptracee.event4.ptracer.pending = true;
                z.as_ptracee.event4.ptracer.value = ev;
                z.as_ptracee.is_zombie = true;
                drop(z);
                drop(t);
                // Extensions are dropped with the tracee below.
                let mut t2 = tracee_rc.borrow_mut();
                drop(std::mem::take(&mut t2.extensions));
                return;
            }
        }
    }

    detach_from_ptracer(dead_pid);

    // Wake its ptracer if there's nothing else to wait for.
    if let Some(ptracer_rc) = get_tracee(ptracer_pid, false) {
        let mut ptracer = ptracer_rc.borrow_mut();
        if ptracer.as_ptracer.nb_ptracees == 0 && ptracer.as_ptracer.wait_pid != 0 {
            crate::tracee::reg::poke_reg(
                &mut ptracer,
                Reg::SysargResult,
                (-(libc::ECHILD as i64)) as Word,
            );
            let _ = crate::tracee::reg::push_regs(&mut ptracer);
            ptracer.as_ptracer.wait_pid = 0;
            drop(ptracer);
            crate::tracee::event::restart_tracee(&ptracer_rc, 0);
        }
    }

    let mut t = tracee_rc.borrow_mut();
    drop(std::mem::take(&mut t.extensions));
}

/// `detach_from_ptracer()` — clear the ptracee's tracer and decrement
/// the tracer's ptracee count (no-op when the tracer is gone).
pub fn detach_from_ptracer(ptracee_pid: i32) {
    let ptracer_pid = with_tracee(ptracee_pid, |t| t.as_ptracee.ptracer).unwrap_or(0);
    with_tracee_mut_try(ptracee_pid, |t| t.as_ptracee.ptracer = 0);
    if ptracer_pid != 0 {
        with_tracee_mut_try(ptracer_pid, |p| {
            if p.as_ptracer.nb_ptracees > 0 {
                p.as_ptracer.nb_ptracees -= 1;
            }
        });
    }
}

/// `kill_all_tracees()` — SIGKILL everything still registered.
pub fn kill_all_tracees() {
    for_each_tracee(|rc| {
        let pid = rc.borrow().pid;
        crate::sys::kill(pid, libc::SIGKILL);
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{Arena, fork_child};

    #[test]
    fn registry_create_lookup_unregister() {
        // Fresh TLS registry per test thread.
        let pid = 424242;
        assert!(get_tracee(pid, false).is_none());
        let rc = get_tracee(pid, true).unwrap();
        assert_eq!(rc.borrow().pid, pid);
        assert!(all_pids().contains(&pid));
        assert!(get_tracee(pid, false).is_some());
        unregister(pid);
        assert!(get_tracee(pid, false).is_none());
        assert!(!all_pids().contains(&pid));
    }

    #[test]
    fn registry_assigns_increasing_vpids() {
        let a = get_tracee(424243, true).unwrap().borrow().vpid;
        let b = get_tracee(424244, true).unwrap().borrow().vpid;
        assert!(b > a);
        unregister(424243);
        unregister(424244);
    }

    #[test]
    fn deferred_actions_flush_on_next_lookup() {
        let pid = 424245;
        let rc = get_tracee(pid, true).unwrap();
        let ran = Rc::new(std::cell::Cell::new(false));
        let ran2 = ran.clone();
        rc.borrow_mut()
            .deferred
            .push(Box::new(move || ran2.set(true)));
        drop(rc);
        let _ = get_tracee(pid, false); // lookup runs deferred work
        assert!(ran.get());
        unregister(pid);
    }

    #[test]
    fn sysenter_sysexit_helpers() {
        let mut t = Tracee::default();
        assert!(is_in_sysenter(&t));
        assert!(!is_in_sysexit(&t));
        t.status = 1;
        assert!(is_in_sysexit(&t));
        let getpid =
            crate::sysnum::detranslate_sysnum(crate::tracee::reg::get_abi(&t), Sysnum::getpid);
        crate::tracee::reg::set_bank_reg(
            &mut t,
            crate::tracee::reg::RegVersion::Original,
            crate::tracee::reg::Reg::SysargNum,
            getpid,
        );
        assert!(is_in_sysexit2(&t, Sysnum::getpid));
        assert!(!is_in_sysexit2(&t, Sysnum::openat));
    }

    #[test]
    fn terminate_marks_and_free_removes() {
        let arena = Arena::new(1);
        let child = fork_child(&arena).unwrap();
        let pid = child.pid;
        let rc = get_tracee(pid, true).unwrap();
        rc.borrow_mut().terminated = false;
        drop(rc);
        terminate_tracee(pid);
        assert!(get_tracee(pid, false).unwrap().borrow().terminated);
        free_terminated_tracees();
        assert!(get_tracee(pid, false).is_none());
    }

    #[test]
    fn free_terminated_noops_when_all_alive() {
        let pid = 424246;
        get_tracee(pid, true);
        free_terminated_tracees(); // nothing dead
        assert!(get_tracee(pid, false).is_some());
        unregister(pid);
    }

    #[test]
    fn detach_updates_ptracer_count() {
        let ptracer = get_tracee(424247, true).unwrap();
        let ptracee = get_tracee(424248, true).unwrap();
        ptracer.borrow_mut().as_ptracer.nb_ptracees = 3;
        ptracee.borrow_mut().as_ptracee.ptracer = 424247;
        drop((ptracer, ptracee));
        detach_from_ptracer(424248);
        assert_eq!(
            get_tracee(424248, false)
                .unwrap()
                .borrow()
                .as_ptracee
                .ptracer,
            0
        );
        assert_eq!(
            get_tracee(424247, false)
                .unwrap()
                .borrow()
                .as_ptracer
                .nb_ptracees,
            2
        );
        unregister(424247);
        unregister(424248);
    }

    #[test]
    fn verbose_of_falls_back_to_global() {
        assert_eq!(verbose_of(None), crate::note::global_verbose());
        let t = Tracee {
            verbose: 7,
            ..Default::default()
        };
        assert_eq!(verbose_of(Some(&t)), 7);
    }
}
