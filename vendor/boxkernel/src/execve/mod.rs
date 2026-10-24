//! execve(2) subsystem — port of src/execve/*.
//!
//! `execve` is the hardest intercepted syscall: it replaces the tracee
//! wholesale.  [`enter`] classifies the target (ELF via [`elf`], `#!`
//! via [`shebang`], QEMU wrapping), loads the `loader/` stub into the
//! tracee, and plants a trap; [`exit`] runs at `PTRACE_EVENT_EXEC` to
//! unpoison state.  [`ldso`] rewrites `PT_INTERP`, [`auxv`]/[`aoxp`]
//! rebuild the auxiliary vector on the new stack.

pub mod aoxp;
pub mod auxv;
pub mod elf;
pub mod enter;
pub mod exit;
pub mod ldso;
pub mod shebang;

pub use elf::{ElfHeader, ProgramHeader};
pub use enter::translate_execve_enter;
pub use exit::translate_execve_exit;

use crate::Word;
use crate::fpath::FixedPath;
use crate::tracee::Tracee;

/// `struct mapping` — one file-backed or anonymous mapping the loader
/// creates for the program/interpreter.
#[derive(Copy, Clone, Default)]
pub struct Mapping {
    pub addr: Word,
    pub length: Word,
    pub clear_length: Word,
    pub prot: Word,
    pub flags: Word,
    pub fd: Word,
    pub offset: Word,
}

/// `struct load_info` — everything execve-enter computes and execve-exit
/// (or the embedded loader) consumes.
#[derive(Clone)]
pub struct LoadInfo {
    pub host_path: String,
    pub user_path: String,
    pub raw_path: String,
    pub mappings: Vec<Mapping>,
    pub elf_header: ElfHeader,
    pub needs_executable_stack: bool,
    pub interp: Option<Box<LoadInfo>>,
}

/// `struct execve_proc_exe_state` — EXECVE_PROC_EXE event payload.
pub struct ExecveProcExeState {
    pub host_path: FixedPath,
    pub guest_path: FixedPath,
    pub substituted: bool,
}

/// `IS_NOTIFICATION_PTRACED_LOAD_DONE`.
pub fn is_notification_ptraced_load_done(tracee: &Tracee) -> bool {
    use crate::tracee::reg::{Reg, RegVersion, peek_reg};
    tracee.as_ptracee.ptracer != 0
        && peek_reg(tracee, RegVersion::Original, Reg::Sysarg1) == 1
        && peek_reg(tracee, RegVersion::Original, Reg::Sysarg4) == 2
        && peek_reg(tracee, RegVersion::Original, Reg::Sysarg5) == 3
        && peek_reg(tracee, RegVersion::Original, Reg::Sysarg6) == 4
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::test_tracee;
    use crate::tracee::reg::{Reg, RegVersion, poke_reg};

    #[test]
    fn load_done_notification_pattern() {
        let mut t = test_tracee("/", &[]);
        assert!(!is_notification_ptraced_load_done(&t)); // no ptracer
        t.as_ptracee.ptracer = 999;
        for (reg, v) in [
            (Reg::Sysarg1, 1),
            (Reg::Sysarg4, 2),
            (Reg::Sysarg5, 3),
            (Reg::Sysarg6, 4),
        ] {
            poke_reg(&mut t, reg, v);
        }
        // The check reads the Original bank.
        t.regs[RegVersion::Original.idx()] = t.regs[RegVersion::Current.idx()];
        assert!(is_notification_ptraced_load_done(&t));
        // Any deviation breaks the pattern.
        poke_reg(&mut t, Reg::Sysarg6, 5);
        t.regs[RegVersion::Original.idx()] = t.regs[RegVersion::Current.idx()];
        assert!(!is_notification_ptraced_load_done(&t));
    }
}
