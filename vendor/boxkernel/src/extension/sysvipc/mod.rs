//! sysvipc extension — port of extension/sysvipc/sysvipc.c.
//!
//! Emulates SysV IPC (message queues, semaphores, shared memory) in
//! user space for kernels that lack it. Blocked syscalls are parked by
//! rewriting them into `ppoll`, and `shmat` uses a chained
//! socket/connect/recvmsg/mmap sequence against a helper process to get
//! the backing fd into the tracee via SCM_RIGHTS.

pub mod msg;
pub mod sem;
pub mod shm;

use std::cell::RefCell;
use std::rc::Rc;

use crate::Word;
use crate::extension::Event;
use crate::sysnum::Sysnum;
use crate::tracee::reg::{Reg, RegVersion, get_sysnum, peek_reg, poke_reg, set_sysnum};
use crate::tracee::seccomp::{restart_syscall_after_seccomp, set_result_after_seccomp};
use crate::tracee::{Sigstop, Tracee};

pub const SYSVIPC_IPC_64: i32 = 0x100;

/// `SysVIpcSembuf` — guest semop buffer layout (packed 6 bytes).
#[derive(Clone, Copy, Default)]
pub struct Sembuf {
    pub sem_num: u16,
    pub sem_op: i16,
    pub sem_flg: i16,
}

/// glibc `struct ipc_perm` — 48 bytes, shared by msqid_ds/semtid_ds/shmid_ds.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct IpcPerm {
    pub key: i32,
    pub uid: u32,
    pub gid: u32,
    pub cuid: u32,
    pub cgid: u32,
    pub mode: u16,
    pub pad1: u16,
    pub seq: u16,
    pub pad2: u16,
    pub reserved1: u64,
    pub reserved2: u64,
}

/// `SysVIpcShmidDs` — guest-visible shmctl stats (glibc `struct shmid_ds`).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ShmidDs {
    pub shm_perm: IpcPerm,
    pub shm_segsz: u64,
    pub shm_atime: i64,
    pub shm_dtime: i64,
    pub shm_ctime: i64,
    pub shm_cpid: i32,
    pub shm_lpid: i32,
    pub shm_nattch: u64,
    pub reserved5: u64,
    pub reserved6: u64,
}

/// `msqid_ds` — guest-visible msgctl IPC_STAT.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct MsqidDs {
    pub msg_perm: IpcPerm,
    pub msg_stime: i64,
    pub msg_rtime: i64,
    pub msg_ctime: i64,
    pub msg_cbytes: u64,
    pub msg_qnum: u64,
    pub msg_qbytes: u64,
    pub msg_lspid: i32,
    pub msg_lrpid: i32,
    pub unused4: u64,
    pub unused5: u64,
}

// Message queues

pub struct MsgQueueItem {
    pub mtype: i64,
    pub mtext: Vec<u8>,
}

#[derive(Default)]
pub struct MsgQueue {
    pub key: i32,
    pub generation: i16,
    pub valid: bool,
    pub items: Vec<MsgQueueItem>,
    pub stats: MsqidDs,
}

// Semaphores

#[derive(Default)]
pub struct Semaphore {
    pub key: i32,
    pub generation: i16,
    pub valid: bool,
    pub sems: Vec<u16>,
}

// Shared memory

/// `SysVIpcSharedMemMap` — a currently mapped region.
#[derive(Clone)]
pub struct SharedMemMap {
    pub addr: Word,
    /// Size of the mmap'ed region, 0 while mmap is scheduled in a chain.
    pub size: usize,
    pub shm_index: usize,
}

#[derive(Default)]
pub struct SharedMem {
    pub key: i32,
    pub generation: i16,
    pub valid: bool,
    pub rmid_pending: bool,
    pub fd: i32,
    pub stats: ShmidDs,
    /// `SysVIpcSharedMemMaps` — indices into `Process::mapped_shms`.
    /// In Rust the mappings live per-process; this list cross-references
    /// them for nattch/rmid accounting.
    pub mappings: Vec<MapRef>,
}

/// Identifies one `SharedMemMap` uniquely across processes.
#[derive(Clone, Copy, PartialEq)]
pub struct MapRef {
    pub process: usize, // ProcRef id — see `proc_id()`
    pub index: usize,   // slot inside Process::mapped_shms
}

#[derive(Default)]
pub struct SysVIpcNamespace {
    /// queues[id-1] (queues are 1-indexed).
    pub queues: Vec<MsgQueue>,
    pub semaphores: Vec<Semaphore>,
    pub shms: Vec<SharedMem>,
    /// WITH_LIBANDROID_SHMEM mode — not built on Linux targets.
    pub shm_use_libandroid: bool,
}

pub type NsRef = Rc<RefCell<SysVIpcNamespace>>;
pub type ProcRef = Rc<RefCell<SysVIpcProcess>>;

/// Stable id for a `ProcRef` (the Rc allocation address).
pub fn proc_id(p: &ProcRef) -> usize {
    Rc::as_ptr(p) as usize
}

/// `SysVIpcProcess` — per-process (thread group) state.
#[derive(Default)]
pub struct SysVIpcProcess {
    pub pgid: i32,
    /// Slots in this list may be `None` after removal (indices are
    /// referenced by `SharedMem::mappings`).
    pub mapped_shms: Vec<Option<SharedMemMap>>,
}

impl SysVIpcProcess {
    /// `LIST_INSERT_HEAD` equivalent — reuse a free slot or append.
    pub fn insert_mapping(&mut self, m: SharedMemMap) -> usize {
        if let Some(i) = self.mapped_shms.iter().position(|s| s.is_none()) {
            self.mapped_shms[i] = Some(m);
            i
        } else {
            self.mapped_shms.push(Some(m));
            self.mapped_shms.len() - 1
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub enum WaitReason {
    #[default]
    NotWaiting,
    QueueRecv,
    Semop,
    ShmatHelperBusy,
}

#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub enum WaitState {
    #[default]
    NotWaiting,
    RestartedIntoPpollCanceled,
    RestartedIntoPpoll,
    EnteredPpoll,
    SignaledPpoll,
    EnteredGetpid,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum ChainState {
    #[default]
    NotChained = 0,
    Single,
    ShmatSocket,
    ShmatConnect,
    ShmatRecvmsg,
    ShmatMmap,
    MsgrcvRetry,
}

/// `SysVIpcConfig` — per-tracee (thread) extension state.
pub struct Sysvipc {
    pub ipc_namespace: Option<NsRef>,
    pub process: Option<ProcRef>,
    /// Parent's process, carried from `clone_for_child` to `InheritChild`.
    pub parent_process: Option<ProcRef>,

    /// Why this tracee should wait (WR_*); reset only by `wake_tracee`.
    pub wait_reason: WaitReason,
    /// Internal wait state machine (WSTATE_*).
    pub wait_state: WaitState,
    /// Syscall-chain state for shmat sequencing (CSTATE_*).
    pub chain_state: ChainState,
    /// Result reported after waiting.
    pub status_after_wait: Word,

    pub waiting_object_index: usize,

    pub msgrcv_msgp: Word,
    pub msgrcv_msgsz: usize,
    pub msgrcv_msgtyp: i32,
    pub msgrcv_msgflg: i32,

    pub semop_sops: Option<Vec<Sembuf>>,

    pub shmat_guest_buf: Word,
    pub shmat_socket_fd: i32,
    pub shmat_mem_fd: i32,
}

impl Default for Sysvipc {
    fn default() -> Self {
        Self {
            ipc_namespace: None,
            process: None,
            parent_process: None,
            wait_reason: WaitReason::NotWaiting,
            wait_state: WaitState::NotWaiting,
            chain_state: ChainState::NotChained,
            status_after_wait: 0,
            waiting_object_index: 0,
            msgrcv_msgp: 0,
            msgrcv_msgsz: 0,
            msgrcv_msgtyp: 0,
            msgrcv_msgflg: 0,
            semop_sops: None,
            shmat_guest_buf: 0,
            shmat_socket_fd: -1,
            shmat_mem_fd: -1,
        }
    }
}

/// `IPC_OBJECT_ID(index, object)` — 1-based slot + generation tag.
pub fn ipc_object_id(index: usize, generation: i16) -> i32 {
    (index as i32 + 1) | ((generation as i32) << 12)
}

/// `LOOKUP_IPC_OBJECT` — resolve the tracee's SYSARG_1 id to an index,
/// validating generation. Returns Err(-EINVAL) or the 0-based index.
pub fn lookup_ipc_object(
    tracee: &Tracee,
    objects_len: usize,
    valid_at: impl Fn(usize) -> (bool, i16),
) -> Result<usize, i32> {
    let object_id = peek_reg(tracee, RegVersion::Current, Reg::Sysarg1) as i32;
    let object_index = (object_id & 0xFFF) as usize;
    if object_index == 0 || object_index > objects_len {
        return Err(-libc::EINVAL);
    }
    let idx = object_index - 1;
    let (valid, generation) = valid_at(idx);
    if !valid || generation != ((object_id >> 12) & 0xFFFF) as i16 {
        return Err(-libc::EINVAL);
    }
    Ok(idx)
}

/// `sysvipc_get_config()` — borrow the Sysvipc extension of `tracee`.
pub fn get_config(tracee: &mut Tracee) -> Option<&mut Sysvipc> {
    for ext in tracee.extensions.iter_mut().flatten() {
        if let crate::extension::AnyExtension::Sysvipc(e) = ext {
            return Some(e);
        }
    }
    None
}

/// `sysvipc_wake_tracee()` — finish a parked wait with `status`.
pub fn wake_tracee(tracee: &mut Tracee, config: &mut Sysvipc, status: i32) {
    debug_assert!(config.wait_reason != WaitReason::NotWaiting);
    config.wait_reason = WaitReason::NotWaiting;
    config.status_after_wait = status as u64;
    match config.wait_state {
        WaitState::EnteredPpoll => {
            config.wait_state = WaitState::SignaledPpoll;
            crate::sys::tkill(tracee.pid, libc::SIGSTOP);
            tracee.sigstop = Sigstop::Ignored;
        }
        WaitState::RestartedIntoPpoll => {
            config.wait_state = WaitState::RestartedIntoPpollCanceled;
        }
        _ => debug_assert!(false, "Bad wait_state in sysvipc_wake_tracee"),
    }
}

/// `SYSVIPC_FOREACH_TRACEE` — call `f` on every tracee (except `skip_pid`)
/// whose sysvipc config belongs to `ns` (or any namespace when `ns` is
/// None), passing `(&mut Tracee, &mut Sysvipc)`.
pub fn for_each_tracee_in_ns(
    ns: Option<&NsRef>,
    skip_pid: i32,
    mut f: impl FnMut(&mut Tracee, &mut Sysvipc),
) {
    crate::tracee::for_each_tracee(|rc| {
        let Ok(mut t) = rc.try_borrow_mut() else {
            return;
        };
        if t.pid == skip_pid || t.pid <= 0 {
            return;
        }
        let Some(config) = get_config(&mut t) else {
            return;
        };
        let matches = match (ns, &config.ipc_namespace) {
            (None, Some(_)) => true,
            (Some(a), Some(b)) => Rc::ptr_eq(a, b),
            _ => false,
        };
        if !matches {
            return;
        }
        // Split the borrow: `config` and `t` are disjoint — but config is
        // reached through t.extensions, so reborrow.
        let pid = t.pid;
        let _ = pid;
        // SAFETY-free approach: take the extension out, use it, put it back.
        let idx = t
            .extensions
            .iter()
            .position(|e| matches!(e, Some(crate::extension::AnyExtension::Sysvipc(_))));
        let Some(idx) = idx else { return };
        let mut ext = t.extensions[idx].take().unwrap();
        if let crate::extension::AnyExtension::Sysvipc(c) = &mut ext {
            f(&mut t, c);
        }
        t.extensions[idx] = Some(ext);
    });
}

/// `sysvipc_syscall_common()` — dispatch the emulated syscall and park
/// the tracee (ppoll rewrite) when the handler asked to wait.
fn syscall_common(tracee: &mut Tracee, config: &mut Sysvipc, from_sigsys: bool) -> i32 {
    let mut timeout: Word = 0;
    debug_assert!(config.wait_state == WaitState::NotWaiting);

    let status: i32 = match get_sysnum(tracee, RegVersion::Current) {
        Sysnum::msgget => msg::msgget(tracee, config),
        Sysnum::msgsnd => msg::msgsnd(tracee, config),
        Sysnum::msgrcv => msg::msgrcv(tracee, config),
        Sysnum::msgctl => msg::msgctl(tracee, config),
        Sysnum::semget => sem::semget(tracee, config),
        Sysnum::semtimedop => {
            timeout = peek_reg(tracee, RegVersion::Current, Reg::Sysarg4);
            sem::semop(tracee, config)
        }
        Sysnum::semop => sem::semop(tracee, config),
        Sysnum::semctl => sem::semctl(tracee, config),
        Sysnum::shmget => shm::shmget(tracee, config),
        Sysnum::shmat => shm::shmat(tracee, config),
        Sysnum::shmdt => shm::shmdt(tracee, config),
        Sysnum::shmctl => shm::shmctl(tracee, config),
        _ => return 0,
    };

    if config.chain_state != ChainState::NotChained {
        // Only initial chain states reach SYSCALL_ENTER_START.
        debug_assert!(
            config.chain_state == ChainState::Single
                || config.chain_state == ChainState::ShmatSocket
        );
        if config.chain_state == ChainState::Single {
            config.chain_state = ChainState::NotChained;
        }
        tracee.restart_how = crate::ptrace::ptc::PTRACE_SYSCALL;
        if from_sigsys {
            restart_syscall_after_seccomp(tracee);
            2
        } else {
            1
        }
    } else if config.wait_reason != WaitReason::NotWaiting {
        poke_reg(tracee, Reg::Sysarg1, 0);
        poke_reg(tracee, Reg::Sysarg2, 0);
        poke_reg(tracee, Reg::Sysarg3, timeout);
        poke_reg(tracee, Reg::Sysarg4, 0);
        set_sysnum(tracee, Sysnum::ppoll);
        tracee.restart_how = crate::ptrace::ptc::PTRACE_SYSCALL;
        if from_sigsys {
            config.wait_state = WaitState::RestartedIntoPpoll;
            restart_syscall_after_seccomp(tracee);
            2
        } else {
            config.wait_state = WaitState::EnteredPpoll;
            1
        }
    } else {
        if from_sigsys {
            set_result_after_seccomp(tracee, status as u64);
            2
        } else {
            config.status_after_wait = status as u64;
            config.wait_state = WaitState::EnteredGetpid;
            set_sysnum(tracee, Sysnum::getpid);
            tracee.restart_how = crate::ptrace::ptc::PTRACE_SYSCALL;
            1
        }
    }
}

/// `sysvipc_proc_handler()` — materialize "/proc/sysvipc/*" as a temp
/// file and redirect the translated path at it.
fn proc_handler(
    out_path: &mut crate::fpath::FixedPath,
    config: &Sysvipc,
    fill: impl Fn(&mut dyn std::io::Write, &SysVIpcNamespace),
) -> i32 {
    let Some(path) = crate::path::temp::create_temp_file("prootseq") else {
        return -libc::ENOMEM;
    };
    let Ok(mut fp) = std::fs::File::create(&path) else {
        return -libc::ENOMEM;
    };
    if let Some(ns) = &config.ipc_namespace {
        fill(&mut fp, &ns.borrow());
    }
    out_path.set(path.as_bytes());
    1
}

impl Sysvipc {
    pub fn callback(&mut self, tracee: &mut Tracee, event: &mut Event) -> i32 {
        match event {
            Event::Initialization { .. } => {
                self.ipc_namespace = Some(Rc::new(RefCell::new(SysVIpcNamespace::default())));
                let process = SysVIpcProcess {
                    pgid: tracee.pid,
                    ..Default::default()
                };
                self.process = Some(Rc::new(RefCell::new(process)));
                0
            }
            Event::InheritParent { .. } => 1,
            Event::InheritChild { clone_flags } => {
                let Some(parent_process) = self.parent_process.take() else {
                    return 0;
                };
                if (*clone_flags & libc::CLONE_THREAD as Word) != 0 {
                    self.process = Some(parent_process);
                } else {
                    let child_process = SysVIpcProcess {
                        pgid: tracee.pid,
                        ..Default::default()
                    };
                    let child_rc = Rc::new(RefCell::new(child_process));
                    shm::inherit_process(
                        &parent_process.borrow(),
                        &mut child_rc.borrow_mut(),
                        self.ipc_namespace.as_ref().unwrap(),
                        &child_rc,
                    );
                    self.process = Some(child_rc);
                }
                0
            }
            Event::SysEnterEnd { status } => {
                // If we've just finished execve, remove mapped shms from
                // this process.
                if *status == 0 && get_sysnum(tracee, RegVersion::Current) == Sysnum::execve {
                    if let Some(process) = &self.process {
                        shm::remove_mappings_from_process(
                            &mut process.borrow_mut(),
                            self.ipc_namespace.as_ref(),
                            process,
                        );
                    }
                }
                0
            }
            Event::SysEnterStart => match self.wait_state {
                WaitState::NotWaiting => syscall_common(tracee, self, false),
                WaitState::RestartedIntoPpoll => {
                    debug_assert!(get_sysnum(tracee, RegVersion::Current) == Sysnum::ppoll);
                    self.wait_state = WaitState::EnteredPpoll;
                    tracee.restart_how = crate::ptrace::ptc::PTRACE_SYSCALL;
                    1
                }
                WaitState::RestartedIntoPpollCanceled => {
                    let mut status = self.status_after_wait as i64 as i32;
                    if self.chain_state == ChainState::MsgrcvRetry {
                        status = msg::msgrcv_retry(tracee, self);
                    }
                    poke_reg(tracee, Reg::SysargResult, status as u64);
                    set_sysnum(tracee, Sysnum::Void);
                    self.wait_state = WaitState::NotWaiting;
                    1
                }
                _ => {
                    debug_assert!(false, "Bad wait_state on SYSCALL_ENTER_START");
                    0
                }
            },
            Event::SigsysOcc => syscall_common(tracee, self, true),
            Event::SysExitStart => {
                if self.chain_state >= ChainState::ShmatSocket
                    && self.chain_state <= ChainState::ShmatMmap
                {
                    debug_assert!(self.chain_state == ChainState::ShmatSocket);
                    return shm::shmat_chain(tracee, self);
                }
                match self.wait_state {
                    WaitState::NotWaiting => 0,
                    WaitState::EnteredPpoll => {
                        self.wait_state = WaitState::NotWaiting;
                        match self.wait_reason {
                            WaitReason::Semop => sem::semop_timedout(self),
                            WaitReason::NotWaiting => {
                                debug_assert!(false, "wait_reason NOT_WAITING in ENTERED_PPOLL")
                            }
                            _ => self.wait_reason = WaitReason::NotWaiting,
                        }
                        debug_assert!(self.wait_reason == WaitReason::NotWaiting);
                        let ppoll_status =
                            peek_reg(tracee, RegVersion::Current, Reg::SysargResult) as i64 as i32;
                        if ppoll_status == -libc::EFAULT || ppoll_status == -libc::EINTR {
                            1
                        } else {
                            -libc::EINTR
                        }
                    }
                    WaitState::SignaledPpoll | WaitState::EnteredGetpid => {
                        debug_assert!(self.wait_reason == WaitReason::NotWaiting);
                        self.wait_state = WaitState::NotWaiting;
                        let mut status = self.status_after_wait as i64 as i32;
                        if self.chain_state == ChainState::MsgrcvRetry {
                            status = msg::msgrcv_retry(tracee, self);
                        }
                        poke_reg(tracee, Reg::SysargResult, status as u64);
                        1
                    }
                    _ => {
                        debug_assert!(false, "Bad wait_state on SYSCALL_EXIT_START");
                        0
                    }
                }
            }
            Event::ChainedEnter => {
                match self.wait_state {
                    WaitState::NotWaiting => {}
                    WaitState::RestartedIntoPpollCanceled => {
                        poke_reg(tracee, Reg::Sysarg3, 1);
                        self.wait_state = WaitState::SignaledPpoll;
                    }
                    _ => debug_assert!(false, "Bad wait_state on SYSCALL_CHAINED_ENTER"),
                }
                0
            }
            Event::ChainedExit => {
                match self.wait_state {
                    WaitState::NotWaiting => {}
                    WaitState::SignaledPpoll => {
                        self.wait_state = WaitState::NotWaiting;
                        // Don't run chain handlers.
                        return 0;
                    }
                    _ => debug_assert!(false, "Bad wait_state on SYSCALL_CHAINED_EXIT"),
                }
                if self.chain_state >= ChainState::ShmatSocket
                    && self.chain_state <= ChainState::ShmatMmap
                {
                    shm::shmat_chain(tracee, self);
                }
                0
            }
            Event::GuestPath { base, path } => {
                if *path == b"/proc/sysvipc/shm" {
                    return proc_handler(base, self, |fp, ns| shm::fill_proc(fp, ns));
                }
                0
            }
            Event::Removed => {
                // talloc destructor equivalent: drop this process's shm
                // mappings when the last holder of the shared process
                // object (CLONE_THREAD threads share it) goes away.
                if let Some(process) = &self.process {
                    if Rc::strong_count(process) == 1 {
                        shm::remove_mappings_from_process(
                            &mut process.borrow_mut(),
                            self.ipc_namespace.as_ref(),
                            process,
                        );
                    }
                }
                0
            }
            _ => 0,
        }
    }

    pub fn filtered_sysnums(&self) -> &'static [(Sysnum, Word)] {
        &[
            (Sysnum::msgget, 0),
            (Sysnum::msgsnd, 0),
            (Sysnum::msgrcv, 0),
            (Sysnum::msgctl, 0),
            (Sysnum::semget, 0),
            (Sysnum::semop, 0),
            (Sysnum::semtimedop, 0),
            (Sysnum::semctl, 0),
            (Sysnum::shmget, 0),
            (Sysnum::shmat, 0),
            (Sysnum::shmdt, 0),
            (Sysnum::shmctl, 0),
        ]
    }

    pub fn clone_for_child(&self, clone_flags: Word) -> Self {
        let mut child = Sysvipc {
            ipc_namespace: self.ipc_namespace.clone(),
            parent_process: self.process.clone(),
            ..Default::default()
        };
        if (clone_flags & libc::CLONE_THREAD as Word) != 0 {
            // Threads share the process state directly.
            child.process = self.process.clone();
            child.parent_process = None;
        }
        child
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::test_tracee;
    use crate::tracee::reg::{Reg, poke_reg};

    #[test]
    fn ipc_object_id_packs_index_and_generation() {
        // index is 1-based low 12 bits; generation in high bits.
        assert_eq!(ipc_object_id(0, 0), 1);
        assert_eq!(ipc_object_id(0, 1), 1 | (1 << 12));
        assert_eq!(ipc_object_id(5, 0x123), 6 | (0x123 << 12));
        assert_eq!(ipc_object_id(4095, 0), 4096);
    }

    #[test]
    fn lookup_ipc_object_validates_slot_and_generation() {
        let mut t = test_tracee("/", &[]);
        // 3 objects, generation 7 on slot 1.
        let valid = |i: usize| (i != 2, 7i16);
        // id for (index=0, gen=7) = 1 | 7<<12.
        poke_reg(&mut t, Reg::Sysarg1, (1 | (7 << 12)) as Word);
        assert_eq!(lookup_ipc_object(&t, 3, valid), Ok(0));
        // index 0 is invalid (ids are 1-based).
        poke_reg(&mut t, Reg::Sysarg1, (7 << 12) as Word);
        assert_eq!(lookup_ipc_object(&t, 3, valid), Err(-libc::EINVAL));
        // index beyond len.
        poke_reg(&mut t, Reg::Sysarg1, (4 | (7 << 12)) as Word);
        assert_eq!(lookup_ipc_object(&t, 3, valid), Err(-libc::EINVAL));
        // generation mismatch.
        poke_reg(&mut t, Reg::Sysarg1, (1 | (8 << 12)) as Word);
        assert_eq!(lookup_ipc_object(&t, 3, valid), Err(-libc::EINVAL));
        // slot invalid (i==2 => slot index 2, id 3).
        poke_reg(&mut t, Reg::Sysarg1, (3 | (7 << 12)) as Word);
        assert_eq!(lookup_ipc_object(&t, 3, valid), Err(-libc::EINVAL));
    }

    #[test]
    fn insert_mapping_reuses_freed_slots() {
        let mut p = SysVIpcProcess::default();
        let mk = || SharedMemMap {
            addr: 0,
            size: 0,
            shm_index: 0,
        };
        let i0 = p.insert_mapping(mk());
        let i1 = p.insert_mapping(mk());
        assert_eq!((i0, i1), (0, 1));
        p.mapped_shms[0] = None;
        let i2 = p.insert_mapping(mk());
        assert_eq!(i2, 0); // reused the hole
        assert_eq!(p.mapped_shms.len(), 2);
    }

    #[test]
    fn wait_and_chain_defaults() {
        let c = Sysvipc::default();
        assert!(c.wait_reason == WaitReason::NotWaiting);
        assert!(c.wait_state == WaitState::NotWaiting);
        assert!(c.chain_state == ChainState::NotChained);
        assert_eq!(c.shmat_socket_fd, -1);
        assert_eq!(c.shmat_mem_fd, -1);
    }
}
