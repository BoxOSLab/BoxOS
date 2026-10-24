//! Virtual heap — port of syscall/heap.c.  brk() is rewritten in place into
//! mmap/mremap against a private anonymous mapping at a controlled address.

use crate::Word;
use crate::arch::SYSCALL_AVOIDER;
use crate::sysnum::{Sysnum, detranslate_sysnum};
use crate::tracee::Tracee;
use crate::tracee::reg::{Reg, RegVersion, get_abi, get_sysnum, peek_reg, poke_reg, set_sysnum};

/// The size of the heap can be zero, unlike a memory mapping: the first page
/// of the heap mapping is discarded so an empty heap is representable.
fn heap_offset() -> Word {
    crate::sys::page_size()
}

#[derive(Default)]
pub struct Heap {
    pub base: Word,
    pub size: usize,
    pub disabled: bool,
}

impl Heap {
    /// `talloc_memdup` equivalent for the non-CLONE_VM fork case.
    pub fn clone_heap(&self) -> Heap {
        Heap {
            base: self.base,
            size: self.size,
            disabled: self.disabled,
        }
    }
}

/// `translate_brk_enter()`.
pub fn translate_brk_enter(tracee: &mut Tracee) {
    if tracee.heap.borrow().disabled {
        return;
    }
    let offset = heap_offset();
    let mut new_brk_address = peek_reg(tracee, RegVersion::Current, Reg::Sysarg1);

    // Allocate a new mapping for the emulated heap.
    if tracee.heap.borrow().base == 0 {
        // This tracee might be PRoot's first child before its first execve:
        // a non-zero argument then is suspicious.
        if new_brk_address != 0 {
            if tracee.verbose > 0 {
                crate::note!(
                    crate::note::Severity::Warning,
                    crate::note::Origin::Internal,
                    "process {} is doing suspicious brk()",
                    tracee.pid
                );
            }
            return;
        }

        // Put the heap as close to the BSS as possible — some programs
        // assume the gap stays small.  bss->addr + bss->length is already
        // page aligned per add_mapping() in execve::enter.
        if let Some(li) = &tracee.load_info {
            if let Some(bss) = li.mappings.last() {
                new_brk_address = bss.addr + bss.length;
            }
        }

        let sysnum = if detranslate_sysnum(get_abi(tracee), Sysnum::mmap2) != SYSCALL_AVOIDER {
            Sysnum::mmap2
        } else {
            Sysnum::mmap
        };

        set_sysnum(tracee, sysnum);
        poke_reg(tracee, Reg::Sysarg1, new_brk_address);
        poke_reg(tracee, Reg::Sysarg2, offset);
        poke_reg(
            tracee,
            Reg::Sysarg3,
            (libc::PROT_READ | libc::PROT_WRITE) as Word,
        );
        poke_reg(
            tracee,
            Reg::Sysarg4,
            (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as Word,
        );
        poke_reg(tracee, Reg::Sysarg5, Word::MAX); // fd = -1
        poke_reg(tracee, Reg::Sysarg6, 0);
        return;
    }

    let base = tracee.heap.borrow().base;

    // The heap size can't be negative.
    if new_brk_address < base {
        set_sysnum(tracee, Sysnum::Void);
        return;
    }

    let new_heap_size = new_brk_address - base;
    let old_heap_size = tracee.heap.borrow().size as Word;

    // Actually resizing.
    set_sysnum(tracee, Sysnum::mremap);
    poke_reg(tracee, Reg::Sysarg1, base - offset);
    poke_reg(tracee, Reg::Sysarg2, old_heap_size + offset);
    poke_reg(tracee, Reg::Sysarg3, new_heap_size + offset);
    poke_reg(tracee, Reg::Sysarg4, 0);
    poke_reg(tracee, Reg::Sysarg5, 0);
}

/// `translate_brk_exit()`.
pub fn translate_brk_exit(tracee: &mut Tracee) {
    if tracee.heap.borrow().disabled {
        return;
    }
    let offset = heap_offset();

    let sysnum = get_sysnum(tracee, RegVersion::Modified);
    let result = peek_reg(tracee, RegVersion::Current, Reg::SysargResult);
    let tracee_errno = result as i64;

    match sysnum {
        Sysnum::Void => {
            let r = tracee.heap.borrow().base + tracee.heap.borrow().size as Word;
            poke_reg(tracee, Reg::SysargResult, r);
        }
        Sysnum::mmap | Sysnum::mmap2 => {
            // mmap reports -errno; brk reports the previous value.
            if tracee_errno < 0 && tracee_errno > -4096 {
                poke_reg(tracee, Reg::SysargResult, 0);
                return;
            }
            let mut h = tracee.heap.borrow_mut();
            h.base = result + offset;
            h.size = 0;
            let r = h.base + h.size as Word;
            drop(h);
            poke_reg(tracee, Reg::SysargResult, r);
        }
        Sysnum::mremap => {
            let base = tracee.heap.borrow().base;
            let size = tracee.heap.borrow().size as Word;
            if (tracee_errno < 0 && tracee_errno > -4096) || base != result + offset {
                poke_reg(tracee, Reg::SysargResult, base + size);
                return;
            }
            let new_size = peek_reg(tracee, RegVersion::Modified, Reg::Sysarg3) - offset;
            tracee.heap.borrow_mut().size = new_size as usize;
            let r = base + new_size;
            poke_reg(tracee, Reg::SysargResult, r);
        }
        Sysnum::brk => {
            // Confirmed legit pre-execve brk: stop emulating.
            if result == peek_reg(tracee, RegVersion::Original, Reg::Sysarg1) {
                tracee.heap.borrow_mut().disabled = true;
            }
        }
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t() -> Tracee {
        let mut t = Tracee::default();
        crate::tracee::reg::set_bank_compat(&mut t, RegVersion::Original, false);
        crate::tracee::reg::set_bank_compat(&mut t, RegVersion::Current, false);
        t
    }

    fn set_arg1(t: &mut Tracee, v: Word) {
        poke_reg(t, Reg::Sysarg1, v);
    }

    #[test]
    fn disabled_heap_is_noop() {
        let mut t = t();
        t.heap.borrow_mut().disabled = true;
        translate_brk_enter(&mut t);
        assert_eq!(peek_reg(&t, RegVersion::Current, Reg::SysargNum), 0);
    }

    #[test]
    fn first_brk_with_suspicious_arg_is_left_alone() {
        let mut t = t();
        set_arg1(&mut t, 0x1000); // nonzero brk before execve
        translate_brk_enter(&mut t);
        // Not rewritten (no load_info): stays whatever was there.
        assert_ne!(get_sysnum(&t, RegVersion::Current), Sysnum::mmap);
    }

    #[test]
    fn first_brk_zero_becomes_mmap() {
        let mut t = t();
        set_arg1(&mut t, 0);
        translate_brk_enter(&mut t);
        let sysnum = get_sysnum(&t, RegVersion::Current);
        assert!(sysnum == Sysnum::mmap || sysnum == Sysnum::mmap2);
        assert_eq!(
            peek_reg(&t, RegVersion::Current, Reg::Sysarg2),
            heap_offset()
        );
        assert_eq!(
            peek_reg(&t, RegVersion::Current, Reg::Sysarg3),
            (libc::PROT_READ | libc::PROT_WRITE) as Word
        );
        assert_eq!(
            peek_reg(&t, RegVersion::Current, Reg::Sysarg4),
            (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as Word
        );
        assert_eq!(peek_reg(&t, RegVersion::Current, Reg::Sysarg5), Word::MAX);
        assert_eq!(peek_reg(&t, RegVersion::Current, Reg::Sysarg6), 0);
    }

    #[test]
    fn brk_below_base_is_voided() {
        let mut t = t();
        t.heap.borrow_mut().base = 0x9000;
        t.heap.borrow_mut().size = 0x100;
        set_arg1(&mut t, 0x8000); // below base
        translate_brk_enter(&mut t);
        assert_eq!(get_sysnum(&t, RegVersion::Current), Sysnum::Void);
    }

    #[test]
    fn brk_resize_becomes_mremap() {
        let mut t = t();
        let base = 0x7000_0000u64;
        t.heap.borrow_mut().base = base;
        t.heap.borrow_mut().size = 0x2000;
        set_arg1(&mut t, base + 0x5000); // grow by 0x3000
        translate_brk_enter(&mut t);
        assert_eq!(get_sysnum(&t, RegVersion::Current), Sysnum::mremap);
        let c = RegVersion::Current;
        assert_eq!(peek_reg(&t, c, Reg::Sysarg1), base - heap_offset());
        assert_eq!(peek_reg(&t, c, Reg::Sysarg2), 0x2000 + heap_offset());
        assert_eq!(peek_reg(&t, c, Reg::Sysarg3), 0x5000 + heap_offset());
        assert_eq!(peek_reg(&t, c, Reg::Sysarg4), 0);
    }

    #[test]
    fn brk_exit_mmap_success_sets_base() {
        let mut t = t();
        // Simulate: Modified bank holds the rewritten sysnum (mmap).
        let n = detranslate_sysnum(get_abi(&t), Sysnum::mmap);
        poke_reg(&mut t, Reg::SysargNum, n);
        crate::tracee::reg::save_current_regs(&mut t, RegVersion::Modified);
        poke_reg(&mut t, Reg::SysargResult, 0x4000_0000);
        translate_brk_exit(&mut t);
        assert_eq!(t.heap.borrow().base, 0x4000_0000 + heap_offset());
        assert_eq!(t.heap.borrow().size, 0);
        assert_eq!(
            peek_reg(&t, RegVersion::Current, Reg::SysargResult),
            0x4000_0000 + heap_offset()
        );
    }

    #[test]
    fn brk_exit_mmap_failure_reports_zero() {
        let mut t = t();
        let n = detranslate_sysnum(get_abi(&t), Sysnum::mmap);
        poke_reg(&mut t, Reg::SysargNum, n);
        crate::tracee::reg::save_current_regs(&mut t, RegVersion::Modified);
        poke_reg(&mut t, Reg::SysargResult, (-(libc::ENOMEM as i64)) as Word);
        translate_brk_exit(&mut t);
        assert_eq!(peek_reg(&t, RegVersion::Current, Reg::SysargResult), 0);
        assert_eq!(t.heap.borrow().base, 0);
    }

    #[test]
    fn brk_exit_mremap_updates_size() {
        let mut t = t();
        let base = 0x5000_0000u64;
        t.heap.borrow_mut().base = base;
        t.heap.borrow_mut().size = 0x1000;
        let n = detranslate_sysnum(get_abi(&t), Sysnum::mremap);
        poke_reg(&mut t, Reg::SysargNum, n);
        poke_reg(&mut t, Reg::Sysarg3, 0x8000 + heap_offset());
        crate::tracee::reg::save_current_regs(&mut t, RegVersion::Modified);
        // mremap returned the same base (base - offset was requested).
        poke_reg(&mut t, Reg::SysargResult, base - heap_offset());
        translate_brk_exit(&mut t);
        assert_eq!(t.heap.borrow().size, 0x8000);
        assert_eq!(
            peek_reg(&t, RegVersion::Current, Reg::SysargResult),
            base + 0x8000
        );
    }

    #[test]
    fn brk_exit_mremap_relocation_keeps_old_size() {
        let mut t = t();
        let base = 0x5000_0000u64;
        t.heap.borrow_mut().base = base;
        t.heap.borrow_mut().size = 0x1000;
        let n = detranslate_sysnum(get_abi(&t), Sysnum::mremap);
        poke_reg(&mut t, Reg::SysargNum, n);
        crate::tracee::reg::save_current_regs(&mut t, RegVersion::Modified);
        // mremap moved the mapping (result != base-offset) — treated as failure.
        poke_reg(&mut t, Reg::SysargResult, 0x9999_0000);
        translate_brk_exit(&mut t);
        assert_eq!(
            peek_reg(&t, RegVersion::Current, Reg::SysargResult),
            base + 0x1000
        );
        assert_eq!(t.heap.borrow().size, 0x1000);
    }

    #[test]
    fn brk_exit_void_returns_current_brk() {
        let mut t = t();
        t.heap.borrow_mut().base = 0x8000;
        t.heap.borrow_mut().size = 0x600;
        let n = detranslate_sysnum(get_abi(&t), Sysnum::Void);
        poke_reg(&mut t, Reg::SysargNum, n);
        crate::tracee::reg::save_current_regs(&mut t, RegVersion::Modified);
        translate_brk_exit(&mut t);
        assert_eq!(
            peek_reg(&t, RegVersion::Current, Reg::SysargResult),
            0x8000 + 0x600
        );
    }

    #[test]
    fn brk_exit_real_brk_disables_emulation() {
        let mut t = t();
        let n = detranslate_sysnum(get_abi(&t), Sysnum::brk);
        poke_reg(&mut t, Reg::SysargNum, n);
        crate::tracee::reg::save_current_regs(&mut t, RegVersion::Modified);
        // Result equals the originally requested brk -> legit, stop emulating.
        crate::tracee::reg::set_bank_reg(&mut t, RegVersion::Original, Reg::Sysarg1, 0xDEAD);
        poke_reg(&mut t, Reg::SysargResult, 0xDEAD);
        translate_brk_exit(&mut t);
        assert!(t.heap.borrow().disabled);
    }

    #[test]
    fn clone_heap_copies_state() {
        let h = Heap {
            base: 0x1111,
            size: 0x222,
            disabled: true,
        };
        let c = h.clone_heap();
        assert_eq!(c.base, 0x1111);
        assert_eq!(c.size, 0x222);
        assert!(c.disabled);
    }
}
