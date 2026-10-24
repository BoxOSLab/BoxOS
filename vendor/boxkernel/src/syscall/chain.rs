//! Chained syscalls — port of syscall/chain.c.

use std::collections::VecDeque;

use crate::Word;
use crate::sysnum::Sysnum;
use crate::tracee::Tracee;
use crate::tracee::reg::{Reg, RegVersion, get_sysnum, peek_reg, poke_reg};

#[derive(Copy, Clone)]
pub struct ChainedSyscall {
    pub sysnum: Sysnum,
    pub sysargs: [Word; 6],
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum SysnumWorkaround {
    #[default]
    Inactive,
    ProcessFaultyCall,
    ProcessReplacedCall,
}

#[derive(Default)]
pub struct Chain {
    /// Mirrors C's `STAILQ` head pointer: `None` == "no chain at all"
    /// (head freed), `Some` == chain in progress (even once drained).
    /// The distinction matters: a queued-but-empty list still suppresses
    /// ORIGINAL-reg snapshotting and triggers one final
    /// `chain_next_syscall` call.
    pub syscalls: Option<VecDeque<ChainedSyscall>>,
    pub force_final_result: bool,
    pub final_result: Word,
    pub sysnum_workaround_state: SysnumWorkaround,
    pub suppressed_signal: i32,
}

impl Chain {
    /// C `tracee->chain.syscalls == NULL`.
    pub fn inactive(&self) -> bool {
        self.syscalls.is_none()
    }
}

/// `register_chained_syscall()` — queue an unrequested syscall to run after
/// the current one completes.
pub fn register_chained_syscall(tracee: &mut Tracee, sysnum: Sysnum, sysargs: [Word; 6]) -> i32 {
    tracee
        .chain
        .syscalls
        .get_or_insert_with(VecDeque::new)
        .push_back(ChainedSyscall { sysnum, sysargs });
    0
}

fn register_at_front(tracee: &mut Tracee, sysnum: Sysnum, sysargs: [Word; 6]) -> i32 {
    tracee
        .chain
        .syscalls
        .get_or_insert_with(VecDeque::new)
        .push_front(ChainedSyscall { sysnum, sysargs });
    0
}

/// `chain_next_syscall()` — pop the next chained syscall and arm it: move the
/// instruction pointer back onto the trap and rewrite sysargs.
pub fn chain_next_syscall(tracee: &mut Tracee) {
    debug_assert!(tracee.chain.syscalls.is_some());
    let popped = tracee.chain.syscalls.as_mut().and_then(|q| q.pop_front());
    match popped {
        None => {
            // Drained: free the queue head (C's TALLOC_FREE) and force the
            // original syscall's result if requested.
            tracee.chain.syscalls = None;
            if tracee.chain.force_final_result {
                let r = tracee.chain.final_result;
                poke_reg(tracee, Reg::SysargResult, r);
            }
            tracee.chain.force_final_result = false;
            tracee.chain.final_result = 0;
            crate::verbose!(Some(tracee), 2, "chain_next_syscall finish");
        }
        Some(syscall) => {
            crate::verbose!(Some(tracee), 2, "chain_next_syscall continue");
            // Original registers are restored after the last chained syscall.
            tracee.restore_original_regs = false;
            for (i, arg) in syscall.sysargs.iter().enumerate() {
                poke_reg(tracee, crate::tracee::reg::sysarg(i + 1), *arg);
            }
            // The re-executed trap takes its number from SYSTRAP_NUM: the
            // *result* register on x86_64 (rax), x8 on aarch64.
            let n = crate::sysnum::detranslate_sysnum(
                crate::tracee::reg::get_abi(tracee),
                syscall.sysnum,
            );
            poke_reg(tracee, crate::tracee::reg::SYSTRAP_NUM, n);
            let ip = peek_reg(tracee, RegVersion::Current, Reg::InstrPointer);
            poke_reg(
                tracee,
                Reg::InstrPointer,
                ip.wrapping_sub(crate::tracee::reg::get_systrap_size(tracee)),
            );
            // Break after exit from this syscall; more may be chained.
            tracee.restart_how = crate::ptrace::ptc::PTRACE_SYSCALL;
        }
    }
}

/// `force_chain_final_result()`.
pub fn force_chain_final_result(tracee: &mut Tracee, forced_result: Word) {
    tracee.chain.force_final_result = true;
    tracee.chain.final_result = forced_result;
}

/// `restart_original_syscall()` — re-run the syscall the tracee requested.
pub fn restart_original_syscall(tracee: &mut Tracee) -> i32 {
    let sysargs = [
        peek_reg(tracee, RegVersion::Original, Reg::Sysarg1),
        peek_reg(tracee, RegVersion::Original, Reg::Sysarg2),
        peek_reg(tracee, RegVersion::Original, Reg::Sysarg3),
        peek_reg(tracee, RegVersion::Original, Reg::Sysarg4),
        peek_reg(tracee, RegVersion::Original, Reg::Sysarg5),
        peek_reg(tracee, RegVersion::Original, Reg::Sysarg6),
    ];
    register_chained_syscall(tracee, get_sysnum(tracee, RegVersion::Original), sysargs)
}

/// `restart_current_syscall_as_chained()`.
pub fn restart_current_syscall_as_chained(tracee: &mut Tracee) -> i32 {
    debug_assert_eq!(
        tracee.chain.sysnum_workaround_state,
        SysnumWorkaround::Inactive
    );
    tracee.chain.sysnum_workaround_state = SysnumWorkaround::ProcessFaultyCall;
    let sysargs = [
        peek_reg(tracee, RegVersion::Current, Reg::Sysarg1),
        peek_reg(tracee, RegVersion::Current, Reg::Sysarg2),
        peek_reg(tracee, RegVersion::Current, Reg::Sysarg3),
        peek_reg(tracee, RegVersion::Current, Reg::Sysarg4),
        peek_reg(tracee, RegVersion::Current, Reg::Sysarg5),
        peek_reg(tracee, RegVersion::Current, Reg::Sysarg6),
    ];
    register_at_front(tracee, get_sysnum(tracee, RegVersion::Current), sysargs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sysnum::{Abi, detranslate_sysnum};
    use crate::tracee::reg::{SYSTRAP_NUM, set_bank_compat, set_bank_reg};

    fn t() -> Tracee {
        let mut t = Tracee::default();
        // Give it a sane instruction pointer.
        set_bank_reg(&mut t, RegVersion::Current, Reg::InstrPointer, 0x1000);
        t
    }

    #[test]
    fn chain_starts_inactive() {
        let t = t();
        assert!(t.chain.inactive());
        assert_eq!(t.chain.sysnum_workaround_state, SysnumWorkaround::Inactive);
    }

    #[test]
    fn register_creates_queue_and_preserves_fifo() {
        let mut t = t();
        assert_eq!(
            register_chained_syscall(&mut t, Sysnum::read, [1, 0, 0, 0, 0, 0]),
            0
        );
        assert_eq!(
            register_chained_syscall(&mut t, Sysnum::write, [2, 0, 0, 0, 0, 0]),
            0
        );
        assert!(!t.chain.inactive());
        assert_eq!(t.chain.syscalls.as_ref().unwrap().len(), 2);
        assert_eq!(t.chain.syscalls.as_ref().unwrap()[0].sysnum, Sysnum::read);
        assert_eq!(t.chain.syscalls.as_ref().unwrap()[1].sysnum, Sysnum::write);
    }

    #[test]
    fn chain_next_arms_registers_and_rewinds_ip() {
        let mut t = t();
        set_bank_compat(&mut t, RegVersion::Original, false);
        set_bank_compat(&mut t, RegVersion::Current, false);
        register_chained_syscall(&mut t, Sysnum::write, [10, 20, 30, 40, 50, 60]);
        chain_next_syscall(&mut t);
        let c = RegVersion::Current;
        assert_eq!(peek_reg(&t, c, Reg::Sysarg1), 10);
        assert_eq!(peek_reg(&t, c, Reg::Sysarg6), 60);
        // The number goes where the trap reads it (rax on x86_64, x8 on
        // aarch64) without clobbering the arguments.
        assert_eq!(
            peek_reg(&t, c, SYSTRAP_NUM),
            detranslate_sysnum(Abi::Default, Sysnum::write)
        );
        // IP stepped back over the syscall instruction.
        assert_eq!(
            peek_reg(&t, c, Reg::InstrPointer),
            0x1000 - crate::arch::SYSTRAP_SIZE
        );
        assert!(!t.restore_original_regs);
        assert_eq!(t.restart_how, crate::ptrace::ptc::PTRACE_SYSCALL);
    }

    #[test]
    fn chain_drains_then_forces_result() {
        let mut t = t();
        register_chained_syscall(&mut t, Sysnum::read, [0; 6]);
        force_chain_final_result(&mut t, 0xABCD);
        chain_next_syscall(&mut t); // pops the only entry
        assert!(t.chain.syscalls.is_some());
        chain_next_syscall(&mut t); // drains: queue freed
        assert!(t.chain.inactive());
        assert_eq!(peek_reg(&t, RegVersion::Current, Reg::SysargResult), 0xABCD);
        assert!(!t.chain.force_final_result);
        assert_eq!(t.chain.final_result, 0);
    }

    #[test]
    fn drain_without_forced_result() {
        let mut t = t();
        register_chained_syscall(&mut t, Sysnum::read, [0; 6]);
        chain_next_syscall(&mut t);
        // Poke a result the drain must *not* overwrite.
        poke_reg(&mut t, Reg::SysargResult, 0x7777);
        chain_next_syscall(&mut t);
        assert!(t.chain.inactive());
        assert_eq!(peek_reg(&t, RegVersion::Current, Reg::SysargResult), 0x7777);
    }

    #[test]
    fn restart_original_uses_original_bank() {
        let mut t = t();
        let o = RegVersion::Original;
        t.regs[o.idx()] = t.regs[RegVersion::Current.idx()];
        poke_reg(&mut t, Reg::Sysarg1, 99); // current differs
        set_bank_reg(&mut t, o, Reg::Sysarg1, 7);
        set_bank_reg(
            &mut t,
            o,
            Reg::SysargNum,
            detranslate_sysnum(Abi::Default, Sysnum::read),
        );
        assert_eq!(restart_original_syscall(&mut t), 0);
        let q = t.chain.syscalls.as_ref().unwrap();
        assert_eq!(q[0].sysnum, Sysnum::read);
        assert_eq!(q[0].sysargs[0], 7);
    }

    #[test]
    fn restart_current_as_chained_goes_to_front() {
        let mut t = t();
        register_chained_syscall(&mut t, Sysnum::read, [1, 0, 0, 0, 0, 0]);
        assert_eq!(restart_current_syscall_as_chained(&mut t), 0);
        assert_eq!(
            t.chain.sysnum_workaround_state,
            SysnumWorkaround::ProcessFaultyCall
        );
        let q = t.chain.syscalls.as_ref().unwrap();
        // Current-sysnum is what the (bogus) regs say; pushed to the front.
        assert_eq!(q.len(), 2);
        assert_eq!(q[1].sysnum, Sysnum::read);
    }

    #[test]
    fn chain_under_compat_abi_detranslates_number() {
        let mut t = t();
        set_bank_compat(&mut t, RegVersion::Original, true);
        set_bank_compat(&mut t, RegVersion::Current, true);
        register_chained_syscall(&mut t, Sysnum::write, [0; 6]);
        chain_next_syscall(&mut t);
        // i386 and ARM EABI write == 4.
        assert_eq!(peek_reg(&t, RegVersion::Current, SYSTRAP_NUM), 4);
    }
}
