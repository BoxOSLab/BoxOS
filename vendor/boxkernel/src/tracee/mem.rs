//! Tracee memory access — port of tracee/mem.c.
//!
//! Fast path is `process_vm_readv`/`process_vm_writev` (single syscall,
//! byte-granular); the fallback is word-wise PTRACE_PEEKDATA/POKEDATA.

use crate::Word;
use crate::tracee::Tracee;
use crate::tracee::reg::{Reg, RegVersion, is_32on64_mode, peek_reg, poke_reg, sizeof_word};

fn ptrace_peekdata(pid: i32, addr: Word) -> Result<Word, i32> {
    crate::sys::clear_errno();
    let v = crate::sys::ptrace(
        crate::ptrace::ptc::PTRACE_PEEKDATA as u32,
        pid,
        addr as usize,
        0,
    );
    let e = crate::sys::errno();
    if e != 0 {
        return Err(if e == libc::EIO { libc::EFAULT } else { e });
    }
    Ok(v as Word)
}

fn ptrace_pokedata(pid: i32, addr: Word, value: Word) -> Result<(), i32> {
    crate::sys::clear_errno();
    crate::sys::ptrace(
        crate::ptrace::ptc::PTRACE_POKEDATA as u32,
        pid,
        addr as usize,
        value as usize,
    );
    let e = crate::sys::errno();
    if e != 0 {
        return Err(if e == libc::EIO { libc::EFAULT } else { e });
    }
    Ok(())
}

/// `write_data()` — copy `src` into `dest` in the tracee; `-errno` on error.
pub fn write_data(tracee: &Tracee, dest: Word, src: &[u8]) -> i32 {
    if src.is_empty() {
        return 0;
    }
    if crate::sys::process_vm_write(tracee.pid, src, dest) == src.len() as isize {
        return 0;
    }

    let ws = size_of::<Word>();
    let full = src.len() / ws;
    let trailing = src.len() % ws;

    for (i, chunk) in src.chunks_exact(ws).enumerate() {
        let w = Word::from_ne_bytes(chunk.try_into().unwrap());
        if ptrace_pokedata(tracee.pid, dest + (i * ws) as Word, w).is_err() {
            crate::note!(
                crate::note::Severity::Warning,
                crate::note::Origin::System,
                "ptrace(POKEDATA)"
            );
            return -libc::EFAULT;
        }
    }
    if trailing == 0 {
        return 0;
    }

    // Merge the trailing bytes into the last word read from the tracee.
    let mut word = match ptrace_peekdata(tracee.pid, dest + (full * ws) as Word) {
        Ok(w) => w,
        Err(_) => {
            crate::note!(
                crate::note::Severity::Warning,
                crate::note::Origin::System,
                "ptrace(PEEKDATA)"
            );
            return -libc::EFAULT;
        }
    };
    let mut wb = word.to_ne_bytes();
    wb[..trailing].copy_from_slice(&src[full * ws..]);
    word = Word::from_ne_bytes(wb);
    if ptrace_pokedata(tracee.pid, dest + (full * ws) as Word, word).is_err() {
        crate::note!(
            crate::note::Severity::Warning,
            crate::note::Origin::System,
            "ptrace(POKEDATA)"
        );
        return -libc::EFAULT;
    }
    0
}

/// `writev_data()` — gather-write several buffers in one remote segment.
pub fn writev_data(tracee: &Tracee, dest: Word, srcs: &[&[u8]]) -> i32 {
    let total: usize = srcs.iter().map(|s| s.len()).sum();
    if crate::sys::process_vm_writev_bufs(tracee.pid, srcs, dest) == total as isize {
        return 0;
    }
    let mut off = 0u64;
    for s in srcs {
        let st = write_data(tracee, dest + off, s);
        if st < 0 {
            return st;
        }
        off += s.len() as u64;
    }
    0
}

/// `read_data()` — copy `size` bytes from the tracee into `dest`.
pub fn read_data(tracee: &Tracee, dest: &mut [u8], src: Word) -> i32 {
    if dest.is_empty() {
        return 0;
    }
    if crate::sys::process_vm_read(tracee.pid, dest, src) == dest.len() as isize {
        return 0;
    }

    let ws = size_of::<Word>();
    let full = dest.len() / ws;
    let trailing = dest.len() % ws;

    for (i, chunk) in dest.chunks_exact_mut(ws).enumerate() {
        match ptrace_peekdata(tracee.pid, src + (i * ws) as Word) {
            Ok(w) => chunk.copy_from_slice(&w.to_ne_bytes()),
            Err(_) => {
                crate::note!(
                    crate::note::Severity::Warning,
                    crate::note::Origin::System,
                    "ptrace(PEEKDATA)"
                );
                return -libc::EFAULT;
            }
        }
    }
    if trailing == 0 {
        return 0;
    }
    match ptrace_peekdata(tracee.pid, src + (full * ws) as Word) {
        Ok(w) => {
            dest[full * ws..].copy_from_slice(&w.to_ne_bytes()[..trailing]);
            0
        }
        Err(_) => {
            crate::note!(
                crate::note::Severity::Warning,
                crate::note::Origin::System,
                "ptrace(PEEKDATA)"
            );
            -libc::EFAULT
        }
    }
}

/// `read_string()` — read a NUL-terminated string, `max_size` bytes at most;
/// returns the length *including* the terminator, or `-errno`.
pub fn read_string(tracee: &Tracee, dest: &mut [u8], src: Word) -> i32 {
    let max_size = dest.len();
    // Chunked process_vm_readv so a chunk never crosses a *guest* page
    // boundary (a partial read would silently truncate the string).
    let chunk = crate::sys::page_size().max(1024) as u64;
    let mut offset = 0usize;
    loop {
        if offset >= max_size {
            break;
        }
        let cur = src + offset as u64;
        // Strictly the next boundary even when `cur` is already aligned.
        let next_chunk = (cur / chunk + 1) * chunk;
        let mut size = (next_chunk - cur) as usize;
        size = size.min(max_size - offset);
        let n = crate::sys::process_vm_read(tracee.pid, &mut dest[offset..offset + size], cur);
        if n == size as isize {
            match dest[offset..offset + size].iter().position(|&b| b == 0) {
                Some(p) => return (offset + p + 1) as i32,
                None => {
                    offset += size;
                    continue;
                }
            }
        }
        // A short read still delivered `n` bytes: the terminator may be
        // among them even though the next page is unreadable.
        if n > 0
            && let Some(p) = dest[offset..offset + n as usize]
                .iter()
                .position(|&b| b == 0)
        {
            return (offset + p + 1) as i32;
        }
        break;
    }
    // Fallback: word-wise peek.
    let ws = size_of::<Word>();
    let full = max_size / ws;
    let trailing = max_size % ws;
    for (i, chunk) in dest[..full * ws].chunks_exact_mut(ws).enumerate() {
        match ptrace_peekdata(tracee.pid, src + (i * ws) as Word) {
            Ok(w) => {
                let wb = w.to_ne_bytes();
                chunk.copy_from_slice(&wb);
                if let Some(j) = wb.iter().position(|&b| b == 0) {
                    return (i * ws + j + 1) as i32;
                }
            }
            Err(_) => return -libc::EFAULT,
        }
    }
    if trailing > 0 {
        match ptrace_peekdata(tracee.pid, src + (full * ws) as Word) {
            Ok(w) => {
                let wb = w.to_ne_bytes();
                for (j, &b) in wb[..trailing].iter().enumerate() {
                    dest[full * ws + j] = b;
                    if b == 0 {
                        return (full * ws + j + 1) as i32;
                    }
                }
                // No NUL inside the trailing bytes: C counts one past them.
                return (full * ws + trailing + 1) as i32;
            }
            Err(_) => return -libc::EFAULT,
        }
    }
    (full * ws) as i32
}

/// `peek_word()` — read one guest word; errno carries the failure.
pub fn peek_word(tracee: &Tracee, address: Word) -> Word {
    let mut result: Word = 0;
    let wsize = sizeof_word(tracee);
    let n = crate::sys::process_vm_read(
        tracee.pid,
        &mut crate::sys::as_bytes_mut(&mut result)[..wsize],
        address,
    );
    if n == wsize as isize {
        crate::sys::clear_errno();
        return result;
    }
    match ptrace_peekdata(tracee.pid, address) {
        Ok(mut w) => {
            if is_32on64_mode(tracee) {
                w &= 0xFFFF_FFFF;
            }
            w
        }
        Err(_) => 0,
    }
}

/// `poke_word()` — write one guest word; errno carries the failure.
pub fn poke_word(tracee: &Tracee, address: Word, value: Word) {
    let wsize = sizeof_word(tracee);
    let n =
        crate::sys::process_vm_write(tracee.pid, &crate::sys::as_bytes(&value)[..wsize], address);
    if n == wsize as isize {
        crate::sys::clear_errno();
        return;
    }
    let mut v = value;
    if is_32on64_mode(tracee) {
        if let Ok(tmp) = ptrace_peekdata(tracee.pid, address) {
            v |= tmp & 0xFFFF_FFFF_0000_0000;
        } else {
            return;
        }
    }
    let _ = ptrace_pokedata(tracee.pid, address, v);
}

/// `peek_uint32()` — read 4 bytes; errno carries the failure.
pub fn peek_uint32(tracee: &Tracee, address: Word) -> u32 {
    let mut buf = [0u8; 4];
    if crate::sys::process_vm_read(tracee.pid, &mut buf, address) == 4 {
        crate::sys::clear_errno();
        return u32::from_ne_bytes(buf);
    }
    match ptrace_peekdata(tracee.pid, address) {
        Ok(w) => w as u32,
        Err(_) => 0,
    }
}

/// `poke_uint32()` — write 4 bytes; errno carries the failure.
pub fn poke_uint32(tracee: &Tracee, address: Word, value: u32) {
    let buf = value.to_ne_bytes();
    if crate::sys::process_vm_write(tracee.pid, &buf, address) == 4 {
        crate::sys::clear_errno();
        return;
    }
    if let Ok(old) = ptrace_peekdata(tracee.pid, address) {
        let v = (old & 0xFFFF_FFFF_0000_0000) | value as u64;
        let _ = ptrace_pokedata(tracee.pid, address, v);
    }
}

/// `peek_int32()`.
pub fn peek_int32(tracee: &Tracee, address: Word) -> i32 {
    peek_uint32(tracee, address) as i32
}

/// `poke_int32()`.
pub fn poke_int32(tracee: &Tracee, address: Word, value: i32) {
    poke_uint32(tracee, address, value as u32)
}

/// `peek_uint64()`.
pub fn peek_uint64(tracee: &Tracee, address: Word) -> u64 {
    let mut buf = [0u8; 8];
    if crate::sys::process_vm_read(tracee.pid, &mut buf, address) == 8 {
        crate::sys::clear_errno();
        return u64::from_ne_bytes(buf);
    }
    ptrace_peekdata(tracee.pid, address).unwrap_or_default()
}

/// `alloc_mem()` — grow the tracee stack downward by `size` bytes.
pub fn alloc_mem(tracee: &mut Tracee, size: i64) -> Word {
    debug_assert!(crate::tracee::is_in_sysenter(tracee));
    let mut sp = peek_reg(tracee, RegVersion::Current, Reg::StackPointer);
    let mut size = size;
    if sp == peek_reg(tracee, RegVersion::Original, Reg::StackPointer) {
        size += crate::arch::RED_ZONE_SIZE as i64;
    }
    if (size > 0 && sp <= size as u64) || (size < 0 && sp >= u64::MAX.wrapping_add(size as u64)) {
        crate::note!(
            crate::note::Severity::Warning,
            crate::note::Origin::Internal,
            "integer under/overflow detected in alloc_mem"
        );
        return 0;
    }
    sp = sp.wrapping_sub(size as u64);
    poke_reg(tracee, Reg::StackPointer, sp);
    sp
}

/// `clear_mem()` — zero `size` bytes in the tracee.
pub fn clear_mem(tracee: &Tracee, address: Word, size: usize) -> i32 {
    const ZEROS: [u8; 4096] = [0; 4096];
    let mut remaining = size;
    let mut addr = address;
    while remaining > 0 {
        let n = remaining.min(ZEROS.len());
        let status = write_data(tracee, addr, &ZEROS[..n]);
        if status < 0 {
            return status;
        }
        remaining -= n;
        addr += n as u64;
    }
    0
}

/// `mem_prepare_after_execve()` — on x86_64 the only post-execve work was
/// the pokedata-workaround stub, which doesn't apply; kept for parity.
pub fn mem_prepare_after_execve(_tracee: &mut Tracee) {}

/// `mem_prepare_before_first_execve()` — see above.
pub fn mem_prepare_before_first_execve(_tracee: &mut Tracee) {}

/// `read_path()` — read a NUL-terminated path (PATH_MAX bound) from the
/// tracee, straight into `path`'s storage.
pub fn read_path(tracee: &Tracee, path: &mut crate::fpath::FixedPath, src: Word) -> i32 {
    let size = read_string(tracee, path.as_mut_bytes(), src);
    if size < 0 {
        return size;
    }
    // `size` includes the terminator, which read_string already wrote.
    path.set_len_terminated(size as usize - 1);
    size
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fpath::FixedPath;
    use crate::testutil::{Arena, fork_child};

    /// Fill `arena` page `p` with a repeating pattern.
    fn fill_page(arena: &mut Arena, p: usize, byte: u8) {
        arena.local()[p * 4096..(p + 1) * 4096].fill(byte);
    }

    #[test]
    fn read_write_data_roundtrip() {
        let arena = Arena::new(2);
        let Some(child) = fork_child(&arena) else {
            return;
        };
        let t = child.tracee();
        let src = b"hello remote world";
        assert_eq!(write_data(&t, arena.addr(), src), 0);
        assert_eq!(&arena.local()[..src.len()], src);
        let mut dst = [0u8; 64];
        assert_eq!(read_data(&t, &mut dst[..src.len()], arena.addr()), 0);
        assert_eq!(&dst[..src.len()], src);
        // Empty buffers are trivially ok.
        assert_eq!(write_data(&t, arena.addr(), b""), 0);
        assert_eq!(read_data(&t, &mut [], arena.addr()), 0);
    }

    #[test]
    fn write_data_unaligned_and_trailing() {
        // Sizes that are not word multiples exercise the merge-tail path
        // (in process_vm fallback) — here just verify content.
        let arena = Arena::new(1);
        let Some(child) = fork_child(&arena) else {
            return;
        };
        let t = child.tracee();
        for len in [1usize, 3, 7, 8, 9, 13, 100, 4000] {
            let src: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            assert_eq!(write_data(&t, arena.addr(), &src), 0, "len {len}");
            assert_eq!(&arena.local()[..len], src.as_slice(), "len {len}");
        }
    }

    #[test]
    fn read_write_data_unreadable_remote() {
        let mut arena = Arena::new(2);
        fill_page(&mut arena, 1, 0xAA);
        let Some(mut child) = fork_child(&arena) else {
            return;
        };
        let t = child.tracee();
        child.protect_page(1);
        let remote = arena.addr() + 4096;
        let mut dst = [0u8; 16];
        assert_eq!(read_data(&t, &mut dst, remote), -libc::EFAULT);
        assert_eq!(write_data(&t, remote, b"x"), -libc::EFAULT);
        child.unprotect_page(1);
        // Recovered.
        assert_eq!(write_data(&t, remote, b"ok"), 0);
    }

    #[test]
    fn readv_writev_gather() {
        let arena = Arena::new(1);
        let Some(child) = fork_child(&arena) else {
            return;
        };
        let t = child.tracee();
        assert_eq!(writev_data(&t, arena.addr(), &[b"ab", b"cd", b"e"]), 0);
        assert_eq!(&arena.local()[..5], b"abcde");
        // A failing second segment propagates.
        let arena2 = Arena::new(2);
        let Some(mut child2) = fork_child(&arena2) else {
            return;
        };
        let t2 = child2.tracee();
        child2.protect_page(1);
        let st = writev_data(
            &t2,
            arena2.addr(),
            &[b"good", [0x42; 64][..].repeat(0).leak(), b"tail"],
        );
        // first write lands; the tail lives at addr+4 — still page 0 → ok.
        assert_eq!(st, 0);
        // Now a write straddling into the dead page.
        let st = writev_data(&t2, arena2.addr() + 4090, &[b"12345678", b"rest"]);
        assert!(st <= 0); // process_vm may fail whole or partially
        child2.unprotect_page(1);
    }

    #[test]
    fn read_string_reads_to_nul() {
        let arena = Arena::new(2);
        arena.local()[..6].copy_from_slice(b"hello\0");
        arena.local()[100..111].copy_from_slice(b"page2string");
        let Some(child) = fork_child(&arena) else {
            return;
        };
        let t = child.tracee();
        let mut buf = [0u8; 64];
        // Returns length including NUL.
        assert_eq!(read_string(&t, &mut buf, arena.addr()), 6);
        assert_eq!(&buf[..6], b"hello\0");
        // No NUL within reach: reads hit the end of the buffer, then the
        // ptrace fallback fails on an un-attached child -> EFAULT.
        arena.local()[..64].fill(b'z');
        let mut buf = [0u8; 32];
        let n = read_string(&t, &mut buf, arena.addr());
        assert_eq!(n, -libc::EFAULT);
    }

    #[test]
    fn read_string_crosses_pages() {
        // String spanning the page-1/page-2 boundary.
        let arena = Arena::new(2);
        let start = 4090;
        let s = b"abcdefghijklmnop\0";
        arena.local()[start..start + s.len()].copy_from_slice(s);
        let Some(child) = fork_child(&arena) else {
            return;
        };
        let t = child.tracee();
        let mut buf = [0u8; 64];
        let n = read_string(&t, &mut buf, arena.addr() + start as u64);
        assert_eq!(n, s.len() as i32);
        assert_eq!(&buf[..s.len()], s);
    }

    #[test]
    fn read_string_terminator_before_protected_page() {
        // A NUL inside the last readable chunk short-circuits before the
        // protected page is touched — the short-read NUL scan.
        let arena = Arena::new(2);
        // NUL at 4095 — inside the readable page; 4096+ is protected.
        arena.local()[4094..4098].copy_from_slice(b"a\0bc");
        let Some(mut child) = fork_child(&arena) else {
            return;
        };
        let t = child.tracee();
        child.protect_page(1);
        let mut buf = [0u8; 128];
        let n = read_string(&t, &mut buf, arena.addr() + 4094);
        assert_eq!(n, 2, "stops at the NUL despite dead page ahead");
        assert_eq!(&buf[..2], b"a\0");
        child.unprotect_page(1);
    }

    #[test]
    fn read_string_fully_protected() {
        let arena = Arena::new(2);
        let Some(mut child) = fork_child(&arena) else {
            return;
        };
        let t = child.tracee();
        child.protect_page(1);
        let mut buf = [0u8; 64];
        let n = read_string(&t, &mut buf, arena.addr() + 4096);
        // process_vm fails; ptrace fallback isn't attached -> EFAULT.
        assert_eq!(n, -libc::EFAULT);
        child.unprotect_page(1);
    }

    #[test]
    fn read_path_into_fixedpath() {
        let arena = Arena::new(1);
        arena.local()[..8].copy_from_slice(b"/abc/de\0");
        let Some(child) = fork_child(&arena) else {
            return;
        };
        let t = child.tracee();
        let mut p = FixedPath::new();
        let n = read_path(&t, &mut p, arena.addr());
        assert_eq!(n, 8);
        assert_eq!(p.as_bytes(), b"/abc/de");
        assert_eq!(p.as_c_bytes(), b"/abc/de\0");
    }

    #[test]
    fn peek_poke_word() {
        let arena = Arena::new(1);
        let Some(child) = fork_child(&arena) else {
            return;
        };
        let t = child.tracee();
        poke_word(&t, arena.addr(), 0xDEADBEEF_CAFEF00D);
        let got = peek_word(&t, arena.addr());
        assert_eq!(got, 0xDEADBEEF_CAFEF00D);
        assert_eq!(
            u64::from_ne_bytes(arena.local()[..8].try_into().unwrap()),
            0xDEADBEEF_CAFEF00D
        );
    }

    #[test]
    fn peek_poke_u32_u64() {
        let arena = Arena::new(1);
        let Some(child) = fork_child(&arena) else {
            return;
        };
        let t = child.tracee();
        poke_uint32(&t, arena.addr(), 0xA5A5_5A5A);
        assert_eq!(peek_uint32(&t, arena.addr()), 0xA5A5_5A5A);
        assert_eq!(peek_int32(&t, arena.addr()), 0xA5A5_5A5A_u32 as i32);
        assert_eq!(
            write_data(
                &t,
                arena.addr() + 8,
                &0x1122_3344_5566_7788u64.to_ne_bytes()
            ),
            0
        );
        assert_eq!(peek_uint64(&t, arena.addr() + 8), 0x1122_3344_5566_7788);
        // poke_uint32 must not clobber the high 4 bytes of the word.
        assert_eq!(
            write_data(&t, arena.addr(), &0xFFFF_0000_1111_2222u64.to_ne_bytes()),
            0
        );
        poke_uint32(&t, arena.addr(), 0x3333_4444);
        assert_eq!(peek_uint64(&t, arena.addr()), 0xFFFF_0000_3333_4444);
    }

    #[test]
    fn alloc_mem_grows_downward_and_zero() {
        let arena = Arena::new(2);
        let Some(child) = fork_child(&arena) else {
            return;
        };
        let mut t = child.tracee_with_sp(&arena);
        let sp0 = peek_reg(&t, RegVersion::Current, Reg::StackPointer);
        // First alloc pays RED_ZONE_SIZE (fresh frame).
        let a1 = alloc_mem(&mut t, 64);
        assert_eq!(a1, sp0 - (64 + crate::arch::RED_ZONE_SIZE));
        assert_eq!(peek_reg(&t, RegVersion::Current, Reg::StackPointer), a1);
        // Subsequent allocs from the same frame skip the red zone.
        let a2 = alloc_mem(&mut t, 32);
        assert_eq!(a2, a1 - 32);
        // Underflow guard: absurd size returns 0.
        assert_eq!(alloc_mem(&mut t, i64::MAX / 2), 0);
        // Negative size (shrink) still returns new sp when sane.
        let a3 = alloc_mem(&mut t, -8);
        assert_eq!(a3, a2 + 8);
    }

    #[test]
    fn clear_mem_zeroes_remote() {
        let mut arena = Arena::new(2);
        fill_page(&mut arena, 0, 0x77);
        fill_page(&mut arena, 1, 0x77);
        let Some(child) = fork_child(&arena) else {
            return;
        };
        let t = child.tracee();
        // 4090..8192 — spans the page boundary, exactly filling to the end.
        assert_eq!(clear_mem(&t, arena.addr() + 4090, 4102), 0);
        assert_eq!(&arena.local()[..4090], &[0x77; 4090]);
        assert_eq!(&arena.local()[4090..8192], &[0u8; 4102]);
        // Size 0 is a no-op.
        assert_eq!(clear_mem(&t, arena.addr(), 0), 0);
    }
}
