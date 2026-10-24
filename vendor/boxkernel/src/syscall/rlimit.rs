//! rlimit handling — port of syscall/rlimit.c.
//!
//! When a tracee raises RLIMIT_STACK past the tracer's own soft limit, the
//! kernel refuses the tracer access to tracee stack pages beyond that
//! point (kernel bug 91791).  Raising PRoot's soft limit to match keeps
//! stack accesses working.

use crate::Word;
use crate::tracee::Tracee;
use crate::tracee::mem::{peek_uint64, peek_word};
use crate::tracee::reg::{Reg, RegVersion, is_32on64_mode, peek_reg};

/// `translate_setrlimit_exit()` — mirror a tracee's RLIMIT_STACK raise.
pub fn translate_setrlimit_exit(tracee: &Tracee, is_prlimit: bool) -> i32 {
    // SYSARG_2/3 for prlimit64, SYSARG_1/2 for setrlimit.
    let (sysarg_r, sysarg_a) = if is_prlimit {
        (Reg::Sysarg2, Reg::Sysarg3)
    } else {
        (Reg::Sysarg1, Reg::Sysarg2)
    };

    let resource = peek_reg(tracee, RegVersion::Original, sysarg_r);
    let address = peek_reg(tracee, RegVersion::Original, sysarg_a);

    if resource != libc::RLIMIT_STACK as Word {
        return 0;
    }

    let mut tracee_stack_limit: Word;
    if is_prlimit {
        if address == 0 {
            return 0;
        }
        tracee_stack_limit = peek_uint64(tracee, address);
    } else {
        tracee_stack_limit = peek_word(tracee, address);
        if is_32on64_mode(tracee) && tracee_stack_limit == u32::MAX as Word {
            tracee_stack_limit = libc::RLIM_INFINITY;
        }
    }
    if crate::sys::errno() != 0 {
        return -crate::sys::errno();
    }

    // prlimit64(0, RLIMIT_STACK, …) on ourselves.
    let mut proot_stack = libc::rlimit64 {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if crate::sys::prlimit64(0, libc::RLIMIT_STACK as _, None, Some(&mut proot_stack)) < 0 {
        crate::verbose!(Some(tracee), 1, "can't get stack limit.");
        return 0; // Not fatal.
    }

    if proot_stack.rlim_cur >= tracee_stack_limit {
        return 0;
    }
    proot_stack.rlim_cur = tracee_stack_limit;

    if crate::sys::prlimit64(0, libc::RLIMIT_STACK as _, Some(&proot_stack), None) < 0 {
        crate::verbose!(Some(tracee), 1, "can't set stack limit.");
        return 0; // Not fatal.
    }

    crate::verbose!(
        Some(tracee),
        1,
        "stack soft limit increased to {} bytes",
        proot_stack.rlim_cur
    );
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{Arena, fork_child};
    use crate::tracee::reg::save_current_regs;

    #[test]
    fn non_stack_resource_is_noop() {
        let arena = Arena::new(1);
        let Some(child) = fork_child(&arena) else {
            return;
        };
        let mut t = crate::testutil::test_tracee("/", &[]);
        t.pid = child.pid;
        // setrlimit(RLIMIT_NOFILE, addr) -> early return.
        let r = peek_reg(&t, RegVersion::Original, Reg::Sysarg1);
        let _ = r;
        crate::tracee::reg::poke_reg(&mut t, Reg::Sysarg1, libc::RLIMIT_NOFILE as Word);
        poke_reg_addr(&mut t, Reg::Sysarg2, arena.addr() + 0x800);
        save_current_regs(&mut t, RegVersion::Original);
        assert_eq!(translate_setrlimit_exit(&t, false), 0);
    }

    #[test]
    fn stack_resource_smaller_is_noop() {
        let arena = Arena::new(1);
        let Some(child) = fork_child(&arena) else {
            return;
        };
        let mut t = crate::testutil::test_tracee("/", &[]);
        t.pid = child.pid;
        // setrlimit(RLIMIT_STACK, &rlim) with rlim_cur=4096 (< ours) -> no raise.
        // struct rlimit { rlim_cur=8, rlim_max=8 }.
        arena.local()[0x800..0x808].copy_from_slice(&4096u64.to_ne_bytes());
        arena.local()[0x808..0x810].copy_from_slice(&u64::MAX.to_ne_bytes());
        poke_reg_addr(&mut t, Reg::Sysarg1, libc::RLIMIT_STACK as Word);
        poke_reg_addr(&mut t, Reg::Sysarg2, arena.addr() + 0x800);
        save_current_regs(&mut t, RegVersion::Original);
        let before = current_stack_cur();
        assert_eq!(translate_setrlimit_exit(&t, false), 0);
        assert_eq!(current_stack_cur(), before); // unchanged
    }

    #[test]
    fn prlimit_null_new_is_noop() {
        let arena = Arena::new(1);
        let Some(child) = fork_child(&arena) else {
            return;
        };
        let mut t = crate::testutil::test_tracee("/", &[]);
        t.pid = child.pid;
        // prlimit64(., RLIMIT_STACK, NULL, .) -> early return.
        poke_reg_addr(&mut t, Reg::Sysarg2, libc::RLIMIT_STACK as Word);
        poke_reg_addr(&mut t, Reg::Sysarg3, 0);
        save_current_regs(&mut t, RegVersion::Original);
        assert_eq!(translate_setrlimit_exit(&t, true), 0);
    }

    fn poke_reg_addr(t: &mut Tracee, reg: Reg, v: Word) {
        crate::tracee::reg::poke_reg(t, reg, v);
    }

    fn current_stack_cur() -> u64 {
        let mut rl = libc::rlimit64 {
            rlim_cur: 0,
            rlim_max: 0,
        };
        assert_eq!(
            crate::sys::prlimit64(0, libc::RLIMIT_STACK as _, None, Some(&mut rl)),
            0
        );
        rl.rlim_cur
    }
}
