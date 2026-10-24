//! Message queues — port of extension/sysvipc/sysvipc_msg.c.

use super::*;
use crate::tracee::Tracee;
use crate::tracee::mem::{read_data, write_data};
use crate::tracee::reg::{Reg, RegVersion, peek_reg};

const SYSVIPC_MAX_MSG_SIZE: usize = 0xFFFF;

const IPC_PRIVATE: i32 = 0;
const IPC_CREAT: i32 = 0o1000;
const IPC_EXCL: i32 = 0o2000;
const IPC_NOWAIT: i32 = 0o4000;
const IPC_RMID: i32 = 0;
const IPC_STAT: i32 = 2;
const MSG_NOERROR: i32 = 0o10000;
const MSG_EXCEPT: i32 = 0o20000;
const MSG_COPY: i32 = 0o40000;

fn now() -> i64 {
    crate::sys::time()
}

pub fn msgget(tracee: &mut Tracee, config: &mut Sysvipc) -> i32 {
    let queue_id = peek_reg(tracee, RegVersion::Current, Reg::Sysarg1) as i32;
    let msgflg = peek_reg(tracee, RegVersion::Current, Reg::Sysarg2) as i32;

    let ns = config.ipc_namespace.as_ref().unwrap().clone();
    let mut nsb = ns.borrow_mut();
    let queues = &mut nsb.queues;

    let mut unused_slot = 0usize;
    let mut found_unused_slot = false;
    let mut found_queue = false;
    let mut queue_index = 0usize;
    for (i, q) in queues.iter().enumerate() {
        if q.valid {
            if queue_id != IPC_PRIVATE && q.key == queue_id {
                queue_index = i;
                found_queue = true;
                break;
            }
        } else if !found_unused_slot {
            unused_slot = i;
            found_unused_slot = true;
        }
    }

    if !found_queue {
        if (msgflg & IPC_CREAT) == 0 {
            return -libc::ENOENT;
        }
        let idx = if found_unused_slot {
            unused_slot
        } else {
            queues.push(MsgQueue::default());
            queues.len() - 1
        };
        let queue = &mut queues[idx];
        queue.key = queue_id;
        queue.valid = true;
        queue.items = Vec::new();
        queue.stats = MsqidDs::default();
        queue.stats.msg_qbytes = 1024 * 64; // Not enforced limit.
        queue_index = idx;
    } else {
        if (msgflg & IPC_CREAT) != 0 && (msgflg & IPC_EXCL) != 0 {
            return -libc::EEXIST;
        }
    }
    ipc_object_id(queue_index, queues[queue_index].generation)
}

fn msg_match(sender_type: i64, receiver_filter: i32, receiver_flag: i32) -> bool {
    let mut matched = receiver_filter == 0
        || sender_type == receiver_filter as i64
        || (receiver_filter < 0 && sender_type <= -(receiver_filter as i64));
    if (receiver_flag & MSG_EXCEPT) != 0 {
        matched = !matched;
    }
    matched
}

fn msg_deliver(
    recipent_tracee: &mut Tracee,
    recipent_config: &Sysvipc,
    queue: &mut MsgQueue,
    msg: &MsgQueueItem,
    delivery_time: i64,
) -> i32 {
    let mut msgsz = recipent_config.msgrcv_msgsz;
    if msg.mtext.len() > msgsz {
        if (recipent_config.msgrcv_msgflg & MSG_NOERROR) == 0 {
            return -libc::E2BIG;
        }
    } else {
        msgsz = msg.mtext.len();
    }
    let mtype = msg.mtype.to_ne_bytes();
    let status = write_data(recipent_tracee, recipent_config.msgrcv_msgp, &mtype);
    if status < 0 {
        return status;
    }
    let status = write_data(
        recipent_tracee,
        recipent_config.msgrcv_msgp + mtype.len() as Word,
        &msg.mtext[..msgsz],
    );
    if status < 0 {
        return status;
    }
    queue.stats.msg_lrpid = recipent_tracee.pid;
    queue.stats.msg_rtime = delivery_time;
    msgsz as i32
}

pub fn msgsnd(tracee: &mut Tracee, config: &mut Sysvipc) -> i32 {
    // Lookup queue.
    let ns = config.ipc_namespace.as_ref().unwrap().clone();
    let queue_index = match lookup_ipc_object(tracee, ns.borrow().queues.len(), |i| {
        let q = &ns.borrow().queues[i];
        (q.valid, q.generation)
    }) {
        Ok(i) => i,
        Err(e) => return e,
    };

    // Read and check arguments.
    let msgp = peek_reg(tracee, RegVersion::Current, Reg::Sysarg2);
    let msgsz = peek_reg(tracee, RegVersion::Current, Reg::Sysarg3) as usize;
    if msgsz > SYSVIPC_MAX_MSG_SIZE {
        return -libc::EINVAL;
    }
    let mut mtype = [0u8; 8];
    let status = read_data(tracee, &mut mtype, msgp);
    if status < 0 {
        return status;
    }
    let mtype = i64::from_ne_bytes(mtype);
    if mtype < 1 {
        return -libc::EINVAL;
    }

    // Create the queue item.
    let mut mtext = vec![0u8; msgsz];
    let status = read_data(tracee, &mut mtext, msgp + 8);
    if status < 0 {
        return status;
    }
    let item = MsgQueueItem { mtype, mtext };

    // Update stats.
    let current_time = now();
    {
        let mut nsb = ns.borrow_mut();
        let queue = &mut nsb.queues[queue_index];
        queue.stats.msg_lspid = tracee.pid;
        queue.stats.msg_stime = current_time;
    }

    // Deliver to a waiting msgrcv.
    let mut woke = false;
    let ns_ptr = ns.clone();
    for_each_tracee_in_ns(
        Some(&ns_ptr),
        tracee.pid,
        |receiver_tracee, receiver_config| {
            if woke {
                return;
            }
            if receiver_config.wait_reason == WaitReason::QueueRecv
                && receiver_config.waiting_object_index == queue_index
                && msg_match(
                    item.mtype,
                    receiver_config.msgrcv_msgtyp,
                    receiver_config.msgrcv_msgflg,
                )
            {
                receiver_config.chain_state = ChainState::MsgrcvRetry;
                wake_tracee(receiver_tracee, receiver_config, -libc::EAGAIN);
                woke = true;
            }
        },
    );

    let mut nsb = ns.borrow_mut();
    let queue = &mut nsb.queues[queue_index];
    queue.stats.msg_qnum += 1;
    queue.stats.msg_cbytes += item.mtext.len() as u64;
    queue.items.push(item);
    0
}

fn do_msgrcv(
    tracee: &mut Tracee,
    config: &mut Sysvipc,
    queue_index: usize,
    queue: &mut MsgQueue,
) -> i32 {
    if (config.msgrcv_msgsz as i64) < 0 {
        return -libc::EINVAL;
    }
    if (config.msgrcv_msgflg & !(IPC_NOWAIT | MSG_NOERROR | MSG_COPY | MSG_EXCEPT)) != 0 {
        return -libc::EINVAL;
    }

    let copy = (config.msgrcv_msgflg & MSG_COPY) != 0;
    if copy {
        if (config.msgrcv_msgflg & IPC_NOWAIT) == 0 {
            return -libc::EINVAL;
        }
        if (config.msgrcv_msgflg & MSG_EXCEPT) != 0 {
            return -libc::EINVAL;
        }
    }

    let found_index = if copy {
        // MSG_COPY picks the msgtyp-th entry in the queue, no matching.
        let index = config.msgrcv_msgtyp as usize;
        if index < queue.items.len() {
            Some(index)
        } else {
            None
        }
    } else {
        queue
            .items
            .iter()
            .position(|item| msg_match(item.mtype, config.msgrcv_msgtyp, config.msgrcv_msgflg))
    };

    let Some(found_index) = found_index else {
        if (config.msgrcv_msgflg & IPC_NOWAIT) != 0 {
            return -libc::ENOMSG;
        }
        config.wait_reason = WaitReason::QueueRecv;
        config.waiting_object_index = queue_index;
        return 0;
    };

    let current_time = now();
    // Deliver without holding the queue borrow conflicts: copy the mtext.
    let (mtype, mtext) = {
        let item = &queue.items[found_index];
        (item.mtype, item.mtext.clone())
    };
    let item = MsgQueueItem { mtype, mtext };
    let status = msg_deliver(tracee, config, queue, &item, current_time);

    if status >= 0 && !copy {
        queue.stats.msg_qnum -= 1;
        queue.stats.msg_cbytes -= queue.items[found_index].mtext.len() as u64;
        queue.items.remove(found_index);
    }
    status
}

pub fn msgrcv(tracee: &mut Tracee, config: &mut Sysvipc) -> i32 {
    let ns = config.ipc_namespace.as_ref().unwrap().clone();
    let queue_index = match lookup_ipc_object(tracee, ns.borrow().queues.len(), |i| {
        let q = &ns.borrow().queues[i];
        (q.valid, q.generation)
    }) {
        Ok(i) => i,
        Err(e) => return e,
    };

    config.msgrcv_msgp = peek_reg(tracee, RegVersion::Current, Reg::Sysarg2);
    config.msgrcv_msgsz = peek_reg(tracee, RegVersion::Current, Reg::Sysarg3) as usize;
    config.msgrcv_msgtyp = peek_reg(tracee, RegVersion::Current, Reg::Sysarg4) as i32;
    config.msgrcv_msgflg = peek_reg(tracee, RegVersion::Current, Reg::Sysarg5) as i32;

    let mut nsb = ns.borrow_mut();
    let queue = &mut nsb.queues[queue_index];
    do_msgrcv(tracee, config, queue_index, queue)
}

pub fn msgrcv_retry(tracee: &mut Tracee, config: &mut Sysvipc) -> i32 {
    debug_assert!(config.chain_state == ChainState::MsgrcvRetry);

    let mut status = config.status_after_wait as i64 as i32;
    if status == -libc::EAGAIN {
        let queue_index = config.waiting_object_index;
        let ns = config.ipc_namespace.as_ref().unwrap().clone();
        let mut nsb = ns.borrow_mut();
        debug_assert!(queue_index < nsb.queues.len());
        let queue = &mut nsb.queues[queue_index];
        debug_assert!(queue.valid);
        status = do_msgrcv(tracee, config, queue_index, queue);

        // Retry handler requested wait? Uncommon path (a concurrent
        // msgrcv consumed the message) — do a spurious wakeup.
        if config.wait_reason != WaitReason::NotWaiting {
            status = -libc::EINTR;
            config.wait_reason = WaitReason::NotWaiting;
        }
    }
    config.chain_state = ChainState::NotChained;
    status
}

pub fn msgctl(tracee: &mut Tracee, config: &mut Sysvipc) -> i32 {
    let ns = config.ipc_namespace.as_ref().unwrap().clone();
    let queue_index = match lookup_ipc_object(tracee, ns.borrow().queues.len(), |i| {
        let q = &ns.borrow().queues[i];
        (q.valid, q.generation)
    }) {
        Ok(i) => i,
        Err(e) => return e,
    };

    let cmd = peek_reg(tracee, RegVersion::Current, Reg::Sysarg2) as i32;
    let buf = peek_reg(tracee, RegVersion::Current, Reg::Sysarg3);

    match cmd {
        c if c == IPC_RMID || c == IPC_RMID | SYSVIPC_IPC_64 => {
            let ns_ptr = ns.clone();
            for_each_tracee_in_ns(
                Some(&ns_ptr),
                tracee.pid,
                |waiting_tracee, waiting_config| {
                    if waiting_config.wait_reason == WaitReason::QueueRecv
                        && waiting_config.waiting_object_index == queue_index
                    {
                        wake_tracee(waiting_tracee, waiting_config, -libc::EIDRM);
                    }
                },
            );
            let mut nsb = ns.borrow_mut();
            let queue = &mut nsb.queues[queue_index];
            queue.valid = false;
            queue.generation = queue.generation.wrapping_add(1);
            queue.items = Vec::new();
            0
        }
        c if c == IPC_STAT || c == IPC_STAT | SYSVIPC_IPC_64 => {
            let nsb = ns.borrow();
            let stats = &nsb.queues[queue_index].stats;
            let bytes = crate::sys::as_bytes(stats);
            write_data(tracee, buf, bytes)
        }
        _ => -libc::EINVAL,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msg_match_type_filters() {
        // filter 0 → any.
        assert!(msg_match(5, 0, 0));
        // positive → exact match.
        assert!(msg_match(3, 3, 0));
        assert!(!msg_match(3, 4, 0));
        // negative → sender_type <= |filter|.
        assert!(msg_match(2, -5, 0));
        assert!(msg_match(5, -5, 0));
        assert!(!msg_match(6, -5, 0));
        // MSG_EXCEPT inverts.
        assert!(!msg_match(3, 3, MSG_EXCEPT));
        assert!(msg_match(3, 4, MSG_EXCEPT));
        assert!(!msg_match(5, 0, MSG_EXCEPT));
    }
}
