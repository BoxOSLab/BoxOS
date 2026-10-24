//! ELF auxiliary vectors — port of execve/auxv.c.

use crate::Word;
use crate::tracee::Tracee;
use crate::tracee::mem::{peek_word, poke_word};
use crate::tracee::reg::{Reg, RegVersion, peek_reg, sizeof_word};

pub const AT_NULL: Word = 0;
pub const AT_IGNORE: Word = 1;
pub const AT_PHENT: Word = 4;
pub const AT_PHNUM: Word = 5;
pub const AT_PAGESZ: Word = 6;
pub const AT_BASE: Word = 7;
pub const AT_FLAGS: Word = 8;
pub const AT_ENTRY: Word = 9;
pub const AT_UID: Word = 11;
pub const AT_EUID: Word = 12;
pub const AT_GID: Word = 13;
pub const AT_EGID: Word = 14;
pub const AT_HWCAP: Word = 16;
pub const AT_CLKTCK: Word = 17;
pub const AT_SECURE: Word = 23;
pub const AT_RANDOM: Word = 25;
pub const AT_EXECFN: Word = 31;
pub const AT_SYSINFO: Word = 32;
pub const AT_SYSINFO_EHDR: Word = 33;

#[derive(Copy, Clone, Default)]
pub struct ElfAuxVector {
    pub atype: Word,
    pub value: Word,
}

/// `get_elf_aux_vectors_address()` — locate the auxv table on the initial
/// stack right after a successful execve (valid only in execve sysexit).
/// Returns 0 on error.
pub fn get_elf_aux_vectors_address(tracee: &Tracee) -> Word {
    let w = sizeof_word(tracee) as Word;
    let mut address = peek_reg(tracee, RegVersion::Current, Reg::StackPointer);
    crate::sys::clear_errno();

    // argc, then argv[] + NULL.
    let argc = peek_word(tracee, address);
    if crate::sys::errno() != 0 {
        return 0;
    }
    address += (1 + argc + 1) * w;

    // envp[] + NULL.
    loop {
        let data = peek_word(tracee, address);
        if crate::sys::errno() != 0 {
            return 0;
        }
        address += w;
        if data == 0 {
            break;
        }
    }
    address
}

/// `fetch_elf_aux_vectors()` — read the AT_NULL-terminated vector list.
pub fn fetch_elf_aux_vectors(tracee: &Tracee, address: Word) -> Option<Vec<ElfAuxVector>> {
    let w = sizeof_word(tracee) as Word;
    let mut address = address;
    let mut vectors = Vec::new();
    loop {
        crate::sys::clear_errno();
        let atype = peek_word(tracee, address);
        if crate::sys::errno() != 0 {
            return None;
        }
        address += w;
        if atype == AT_NULL {
            break;
        }
        let value = peek_word(tracee, address);
        if crate::sys::errno() != 0 {
            return None;
        }
        address += w;
        vectors.push(ElfAuxVector { atype, value });
    }
    vectors.push(ElfAuxVector {
        atype: AT_NULL,
        value: 0,
    });
    Some(vectors)
}

/// `push_elf_aux_vectors()` — write the vector list back to `address`.
pub fn push_elf_aux_vectors(tracee: &Tracee, vectors: &[ElfAuxVector], address: Word) -> i32 {
    let w = sizeof_word(tracee) as Word;
    let mut address = address;
    for v in vectors
        .iter()
        .chain(std::iter::once(&ElfAuxVector::default()))
    {
        crate::sys::clear_errno();
        poke_word(tracee, address, v.atype);
        if crate::sys::errno() != 0 {
            return -crate::sys::errno();
        }
        address += w;
        poke_word(tracee, address, v.value);
        if crate::sys::errno() != 0 {
            return -crate::sys::errno();
        }
        address += w;
        if v.atype == AT_NULL {
            break;
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{Arena, fork_child};
    use crate::tracee::mem::poke_word;

    /// Build a fake initial process stack in the arena:
    ///   [argc][argv0][NULL][envp0][NULL][auxv pairs][AT_NULL]
    /// `sp` points at argc.
    fn fake_stack(
        t: &mut Tracee,
        arena: &Arena,
        argc: u64,
        nenvp: u64,
        auxv: &[(u64, u64)],
    ) -> Word {
        let sp = arena.addr() + 0x800;
        let w = 8u64;
        let mut a = sp;
        poke_word(t, a, argc);
        a += w;
        for i in 0..argc {
            poke_word(t, a, 0x1000 + i);
            a += w;
        }
        poke_word(t, a, 0);
        a += w;
        for i in 0..nenvp {
            poke_word(t, a, 0x2000 + i);
            a += w;
        }
        poke_word(t, a, 0);
        a += w;
        let auxv_addr = a;
        for (k, v) in auxv {
            poke_word(t, a, *k);
            a += w;
            poke_word(t, a, *v);
            a += w;
        }
        poke_word(t, a, AT_NULL);
        // Keep everything within one page.
        assert!(a + w < arena.addr() + 0x800 + 4096);
        auxv_addr
    }

    #[test]
    fn auxv_address_lands_after_envp() {
        let arena = Arena::new(2);
        let child = fork_child(&arena).unwrap();
        let mut t = child.tracee();
        let expected = fake_stack(&mut t, &arena, 2, 3, &[(AT_PHENT, 56), (AT_PAGESZ, 4096)]);
        poke_reg_sp(&mut t, arena.addr() + 0x800);
        assert_eq!(get_elf_aux_vectors_address(&t), expected);
    }

    #[test]
    fn auxv_address_zero_argc_and_envp() {
        let arena = Arena::new(2);
        let child = fork_child(&arena).unwrap();
        let mut t = child.tracee();
        let expected = fake_stack(&mut t, &arena, 0, 0, &[(AT_ENTRY, 0x401000)]);
        poke_reg_sp(&mut t, arena.addr() + 0x800);
        assert_eq!(get_elf_aux_vectors_address(&t), expected);
    }

    #[test]
    fn auxv_address_bad_sp_returns_zero() {
        let arena = Arena::new(2);
        let mut child = fork_child(&arena).unwrap();
        let mut t = child.tracee();
        child.protect_page(1); // fault the page containing the stack
        poke_reg_sp(&mut t, arena.addr() + 0x1000);
        assert_eq!(get_elf_aux_vectors_address(&t), 0);
    }

    #[test]
    fn fetch_push_auxv_roundtrip() {
        let arena = Arena::new(2);
        let child = fork_child(&arena).unwrap();
        let mut t = child.tracee();
        let auxv_addr = fake_stack(
            &mut t,
            &arena,
            1,
            1,
            &[(AT_PHENT, 56), (AT_PHNUM, 9), (AT_RANDOM, 0xBEEF)],
        );
        let v = fetch_elf_aux_vectors(&t, auxv_addr).unwrap();
        assert_eq!(v.len(), 4); // 3 + terminating AT_NULL
        assert_eq!(v[0].atype, AT_PHENT);
        assert_eq!(v[0].value, 56);
        assert_eq!(v[2].value, 0xBEEF);
        assert_eq!(v[3].atype, AT_NULL);

        // Push a modified list to a different region and fetch it back.
        let dst = arena.addr() + 0x1800;
        assert_eq!(push_elf_aux_vectors(&t, &v, dst), 0);
        let v2 = fetch_elf_aux_vectors(&t, dst).unwrap();
        assert_eq!(v2.len(), 4);
        assert_eq!(v2[2].value, 0xBEEF);
    }

    #[test]
    fn fetch_auxv_stops_at_null_and_fails_on_fault() {
        let arena = Arena::new(2);
        let mut child = fork_child(&arena).unwrap();
        let t = child.tracee();
        // Auxv on page 1 without AT_NULL before the protected part.
        let a = arena.addr() + 0x1000;
        poke_word(&t, a, AT_PHENT);
        poke_word(&t, a + 8, 56);
        child.protect_page(1); // fault — fetch must give up, not loop
        assert!(fetch_elf_aux_vectors(&t, a).is_none());
    }

    fn poke_reg_sp(t: &mut Tracee, sp: Word) {
        crate::tracee::reg::poke_reg(t, crate::tracee::reg::Reg::StackPointer, sp);
    }
}
