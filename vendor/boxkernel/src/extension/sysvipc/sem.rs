//! Semaphores — port of extension/sysvipc/sysvipc_sem.c.

use super::*;
use crate::tracee::Tracee;
use crate::tracee::mem::{read_data, write_data};
use crate::tracee::reg::{Reg, RegVersion, peek_reg};

const SYSVIPC_MAX_SEMS: usize = 512;
const SYSVIPC_MAX_NSEMS: usize = 512;
const SYSVIPC_MAX_NSOPS: usize = 512;
const SYSVIPC_MAX_SEMVAL: i32 = 0x7000;

const IPC_PRIVATE: i32 = 0;
const IPC_CREAT: i32 = 0o1000;
const IPC_EXCL: i32 = 0o2000;
const IPC_NOWAIT: i16 = 0o4000;
const IPC_RMID: i32 = 0;

const GETVAL: i32 = 12;
const GETALL: i32 = 13;
const SETVAL: i32 = 16;
const IPC_INFO: i32 = 3;
const SEM_INFO: i32 = 19;

/// `SysVIpcSeminfo` — IPC_INFO/SEM_INFO payload.
#[derive(Default)]
#[repr(C)]
struct Seminfo {
    semmap: i32,
    semmni: i32,
    semmns: i32,
    semmnu: i32,
    semmsl: i32,
    semopm: i32,
    semume: i32,
    semusz: i32,
    semvmx: i32,
    semaem: i32,
}

pub fn semget(tracee: &mut Tracee, config: &mut Sysvipc) -> i32 {
    let semaphore_id = peek_reg(tracee, RegVersion::Current, Reg::Sysarg1) as i32;
    let nsems = peek_reg(tracee, RegVersion::Current, Reg::Sysarg2) as i32;
    let semflg = peek_reg(tracee, RegVersion::Current, Reg::Sysarg3) as i32;

    if nsems <= 0 || nsems as usize > SYSVIPC_MAX_NSEMS {
        return -libc::EINVAL;
    }

    let ns = config.ipc_namespace.as_ref().unwrap().clone();
    let mut nsb = ns.borrow_mut();
    let semaphores = &mut nsb.semaphores;

    let mut unused_slot = 0usize;
    let mut found_unused_slot = false;
    let mut found_semaphore = false;
    let mut semaphore_index = 0usize;
    for (i, s) in semaphores.iter().enumerate() {
        if s.valid {
            if semaphore_id != IPC_PRIVATE && s.key == semaphore_id {
                semaphore_index = i;
                found_semaphore = true;
                break;
            }
        } else if !found_unused_slot {
            unused_slot = i;
            found_unused_slot = true;
        }
    }

    if !found_semaphore {
        if (semflg & IPC_CREAT) == 0 {
            return -libc::ENOENT;
        }
        let idx = if found_unused_slot {
            unused_slot
        } else {
            if semaphores.len() >= SYSVIPC_MAX_SEMS {
                return -libc::ENOSPC;
            }
            semaphores.push(Semaphore::default());
            semaphores.len() - 1
        };
        let semaphore = &mut semaphores[idx];
        semaphore.key = semaphore_id;
        semaphore.valid = true;
        semaphore.sems = vec![0u16; nsems as usize];
        semaphore_index = idx;
    } else {
        if (semflg & IPC_CREAT) != 0 && (semflg & IPC_EXCL) != 0 {
            return -libc::EEXIST;
        }
        if semaphores[semaphore_index].sems.len() < nsems as usize {
            return -libc::EINVAL;
        }
    }
    ipc_object_id(semaphore_index, semaphores[semaphore_index].generation)
}

/// `sysvipc_sem_check()` — 1 if the tracee should still wait, otherwise
/// the result semop shall return. `out_wait_type` receives 'n'/'z' for
/// GETNCNT/GETZCNT accounting.
fn sem_check(config: &Sysvipc, semaphore: &mut Semaphore, out_wait_type: Option<&mut u8>) -> i32 {
    debug_assert!(config.wait_reason == WaitReason::Semop);
    let sops = config.semop_sops.as_ref().unwrap();

    let nsems = semaphore.sems.len();
    let mut new_sems = semaphore.sems.clone();

    for sop in sops.iter() {
        let op = sop.sem_op as i32;
        let sem_num = sop.sem_num as usize;
        let _ = sem_num < nsems; // validated at semop entry
        if op == 0 {
            if new_sems[sem_num] != 0 {
                if (sop.sem_flg & IPC_NOWAIT) != 0 {
                    return -libc::EAGAIN;
                }
                if let Some(t) = out_wait_type {
                    *t = b'z';
                }
                return 1;
            }
        } else {
            let new_value = new_sems[sem_num] as i32 + op;
            if new_value < 0 {
                if (sop.sem_flg & IPC_NOWAIT) != 0 {
                    return -libc::EAGAIN;
                }
                if let Some(t) = out_wait_type {
                    *t = b'n';
                }
                return 1;
            }
            if new_value > SYSVIPC_MAX_SEMVAL {
                return -libc::ERANGE;
            }
            new_sems[sem_num] = new_value as u16;
        }
    }
    semaphore.sems = new_sems;
    0
}

pub fn semop(tracee: &mut Tracee, config: &mut Sysvipc) -> i32 {
    // Lookup semaphore.
    let ns = config.ipc_namespace.as_ref().unwrap().clone();
    let semaphore_index = match lookup_ipc_object(tracee, ns.borrow().semaphores.len(), |i| {
        let s = &ns.borrow().semaphores[i];
        (s.valid, s.generation)
    }) {
        Ok(i) => i,
        Err(e) => return e,
    };

    // Read and check arguments.
    let sops_ptr = peek_reg(tracee, RegVersion::Current, Reg::Sysarg2);
    let nsops = peek_reg(tracee, RegVersion::Current, Reg::Sysarg3) as usize;

    if nsops > SYSVIPC_MAX_NSOPS {
        return -libc::E2BIG;
    }
    if nsops == 0 {
        return -libc::EINVAL;
    }

    let mut raw = vec![0u8; 6 * nsops];
    let status = read_data(tracee, &mut raw, sops_ptr);
    if status < 0 {
        return status;
    }
    let mut sops = Vec::with_capacity(nsops);
    for i in 0..nsops {
        let b = &raw[i * 6..i * 6 + 6];
        sops.push(Sembuf {
            sem_num: u16::from_ne_bytes([b[0], b[1]]),
            sem_op: i16::from_ne_bytes([b[2], b[3]]),
            sem_flg: i16::from_ne_bytes([b[4], b[5]]),
        });
    }

    {
        let nsb = ns.borrow();
        let nsems = nsb.semaphores[semaphore_index].sems.len();
        for sop in &sops {
            if sop.sem_num as usize >= nsems {
                return -libc::EFBIG;
            }
        }
    }

    config.wait_reason = WaitReason::Semop;
    config.waiting_object_index = semaphore_index;
    config.semop_sops = Some(sops);

    let this_semop_status = {
        let mut nsb = ns.borrow_mut();
        let semaphore = &mut nsb.semaphores[semaphore_index];
        sem_check(config, semaphore, None)
    };

    let ns_ptr = ns.clone();
    for_each_tracee_in_ns(Some(&ns_ptr), tracee.pid, |other_tracee, other_config| {
        if other_config.wait_reason == WaitReason::Semop
            && other_config.waiting_object_index == semaphore_index
        {
            let other_status = {
                let mut nsb = ns.borrow_mut();
                let semaphore = &mut nsb.semaphores[semaphore_index];
                sem_check(other_config, semaphore, None)
            };
            if other_status != 1 {
                other_config.semop_sops = None;
                wake_tracee(other_tracee, other_config, other_status);
            }
        }
    });

    if this_semop_status == 1 {
        debug_assert!(config.wait_reason == WaitReason::Semop);
        0
    } else {
        config.semop_sops = None;
        config.wait_reason = WaitReason::NotWaiting;
        this_semop_status
    }
}

/// `sysvipc_semop_timedout()` — drop the pending ops and clear the wait.
pub fn semop_timedout(config: &mut Sysvipc) {
    config.semop_sops = None;
    config.wait_reason = WaitReason::NotWaiting;
}

pub fn semctl(tracee: &mut Tracee, config: &mut Sysvipc) -> i32 {
    let ns = config.ipc_namespace.as_ref().unwrap().clone();
    let semaphore_index = match lookup_ipc_object(tracee, ns.borrow().semaphores.len(), |i| {
        let s = &ns.borrow().semaphores[i];
        (s.valid, s.generation)
    }) {
        Ok(i) => i,
        Err(e) => return e,
    };

    let semnum = peek_reg(tracee, RegVersion::Current, Reg::Sysarg2) as i32;
    let cmd = peek_reg(tracee, RegVersion::Current, Reg::Sysarg3) as i32;
    let cmdarg = peek_reg(tracee, RegVersion::Current, Reg::Sysarg4);

    match cmd & !SYSVIPC_IPC_64 {
        GETVAL => {
            let nsb = ns.borrow();
            let semaphore = &nsb.semaphores[semaphore_index];
            if semnum < 0 || semnum as usize >= semaphore.sems.len() {
                return -libc::EINVAL;
            }
            semaphore.sems[semnum as usize] as i32
        }
        SETVAL => {
            if cmdarg > SYSVIPC_MAX_SEMVAL as Word {
                return -libc::ERANGE;
            }
            let mut nsb = ns.borrow_mut();
            let semaphore = &mut nsb.semaphores[semaphore_index];
            if semnum < 0 || semnum as usize >= semaphore.sems.len() {
                return -libc::EINVAL;
            }
            semaphore.sems[semnum as usize] = cmdarg as u16;
            0
        }
        GETALL => {
            let nsb = ns.borrow();
            let semaphore = &nsb.semaphores[semaphore_index];
            let mut bytes = Vec::with_capacity(semaphore.sems.len() * 2);
            for s in &semaphore.sems {
                bytes.extend_from_slice(&s.to_ne_bytes());
            }
            write_data(tracee, cmdarg, &bytes)
        }
        IPC_RMID => {
            let ns_ptr = ns.clone();
            for_each_tracee_in_ns(
                Some(&ns_ptr),
                tracee.pid,
                |waiting_tracee, waiting_config| {
                    if waiting_config.wait_reason == WaitReason::Semop
                        && waiting_config.waiting_object_index == semaphore_index
                    {
                        wake_tracee(waiting_tracee, waiting_config, -libc::EIDRM);
                    }
                },
            );
            let mut nsb = ns.borrow_mut();
            let semaphore = &mut nsb.semaphores[semaphore_index];
            semaphore.valid = false;
            semaphore.generation = semaphore.generation.wrapping_add(1);
            semaphore.sems = Vec::new();
            0
        }
        IPC_INFO | SEM_INFO => {
            let mut info = Seminfo {
                semmni: SYSVIPC_MAX_SEMS as i32,
                semmns: (SYSVIPC_MAX_SEMS * SYSVIPC_MAX_NSEMS) as i32,
                semmsl: SYSVIPC_MAX_NSEMS as i32,
                semopm: SYSVIPC_MAX_NSOPS as i32,
                semvmx: SYSVIPC_MAX_SEMVAL,
                ..Default::default()
            };
            if cmd == SEM_INFO {
                let nsb = ns.borrow();
                info.semusz = nsb.semaphores.len() as i32;
                info.semaem = nsb.semaphores.iter().map(|s| s.sems.len() as i32).sum();
            }
            let bytes = crate::sys::as_bytes(&info);
            write_data(tracee, cmdarg, bytes)
        }
        _ => -libc::EINVAL,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_with_sops(ops: &[(u16, i16, i16)]) -> Sysvipc {
        Sysvipc {
            wait_reason: crate::extension::sysvipc::WaitReason::Semop,
            semop_sops: Some(
                ops.iter()
                    .map(|&(sem_num, sem_op, sem_flg)| Sembuf {
                        sem_num,
                        sem_op,
                        sem_flg,
                    })
                    .collect(),
            ),
            ..Sysvipc::default()
        }
    }

    #[test]
    fn sem_check_applies_ops() {
        let mut sem = Semaphore {
            sems: vec![1, 0],
            ..Default::default()
        };
        // sem0: -1 → 0; sem1: +1 → 1. All fit → returns 0 and commits.
        let c = cfg_with_sops(&[(0, -1, 0), (1, 1, 0)]);
        assert_eq!(sem_check(&c, &mut sem, None), 0);
        assert_eq!(sem.sems, vec![0, 1]);
    }

    #[test]
    fn sem_check_blocks_on_negative() {
        let mut sem = Semaphore {
            sems: vec![0],
            ..Default::default()
        };
        let c = cfg_with_sops(&[(0, -1, 0)]);
        let mut wt = 0u8;
        assert_eq!(sem_check(&c, &mut sem, Some(&mut wt)), 1); // keep waiting
        assert_eq!(wt, b'n');
        // With IPC_NOWAIT → EAGAIN instead.
        const IPC_NOWAIT: i16 = 0o4000; // Not exported by libc for Bionic.
        let c2 = cfg_with_sops(&[(0, -1, IPC_NOWAIT)]);
        assert_eq!(sem_check(&c2, &mut sem, None), -libc::EAGAIN);
    }

    #[test]
    fn sem_check_wait_for_zero() {
        let mut sem = Semaphore {
            sems: vec![5],
            ..Default::default()
        };
        let c = cfg_with_sops(&[(0, 0, 0)]); // wait-for-zero
        let mut wt = 0u8;
        assert_eq!(sem_check(&c, &mut sem, Some(&mut wt)), 1);
        assert_eq!(wt, b'z');
        // Zero sem: wait-for-zero passes.
        sem.sems[0] = 0;
        assert_eq!(sem_check(&c, &mut sem, None), 0);
    }

    #[test]
    fn sem_check_erange_on_overflow() {
        let mut sem = Semaphore {
            sems: vec![SYSVIPC_MAX_SEMVAL as u16],
            ..Default::default()
        };
        let c = cfg_with_sops(&[(0, 1, 0)]);
        assert_eq!(sem_check(&c, &mut sem, None), -libc::ERANGE);
    }
}
