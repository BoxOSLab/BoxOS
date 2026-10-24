//! ELF structures and helpers — port of execve/elf.c.

use std::os::unix::io::RawFd;

use crate::tracee::Tracee;

pub const EI_NIDENT: usize = 16;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct ElfHeader32 {
    pub e_ident: [u8; EI_NIDENT],
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u32,
    pub e_phoff: u32,
    pub e_shoff: u32,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct ElfHeader64 {
    pub e_ident: [u8; EI_NIDENT],
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_shoff: u64,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

#[derive(Copy, Clone)]
pub union ElfHeader {
    pub class32: ElfHeader32,
    pub class64: ElfHeader64,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct ProgramHeader32 {
    pub p_type: u32,
    pub p_offset: u32,
    pub p_vaddr: u32,
    pub p_paddr: u32,
    pub p_filesz: u32,
    pub p_memsz: u32,
    pub p_flags: u32,
    pub p_align: u32,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct ProgramHeader64 {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

#[derive(Copy, Clone)]
pub union ProgramHeader {
    pub class32: ProgramHeader32,
    pub class64: ProgramHeader64,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct DynamicEntry32 {
    pub d_tag: i32,
    pub d_val: u32,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct DynamicEntry64 {
    pub d_tag: i64,
    pub d_val: u64,
}

#[derive(Copy, Clone)]
pub union DynamicEntry {
    pub class32: DynamicEntry32,
    pub class64: DynamicEntry64,
}

pub const ET_REL: u16 = 1;
pub const ET_EXEC: u16 = 2;
pub const ET_DYN: u16 = 3;
pub const ET_CORE: u16 = 4;

pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;

pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_INTERP: u32 = 3;
pub const PT_GNU_STACK: u32 = 0x6474_e551;

pub const DT_STRTAB: i64 = 5;
pub const DT_RPATH: i64 = 15;
pub const DT_RUNPATH: i64 = 29;

impl ElfHeader {
    /// POD-union views. Both variants are plain-data layouts sharing the
    /// same storage; every bit pattern is a valid value for either, so
    /// a mis-guessed read is a logic error, never UB.
    #[inline]
    fn as32(&self) -> &ElfHeader32 {
        // SAFETY: ElfHeader32 is all-POD; any stored bit pattern is valid.
        unsafe { &self.class32 }
    }
    #[inline]
    fn as64(&self) -> &ElfHeader64 {
        // SAFETY: ElfHeader64 is all-POD; any stored bit pattern is valid.
        unsafe { &self.class64 }
    }
    #[inline]
    fn as32_mut(&mut self) -> &mut ElfHeader32 {
        // SAFETY: ElfHeader32 is all-POD; any stored bit pattern is valid.
        unsafe { &mut self.class32 }
    }
    #[inline]
    fn as64_mut(&mut self) -> &mut ElfHeader64 {
        // SAFETY: ElfHeader64 is all-POD; any stored bit pattern is valid.
        unsafe { &mut self.class64 }
    }
    /// Mutate `e_entry` in the active class.
    pub fn set_entry_bias(&mut self, delta: u64) {
        if self.is_class64() {
            let e = self.as64_mut().e_entry;
            self.as64_mut().e_entry = e.wrapping_add(delta);
        } else {
            let e = self.as32_mut().e_entry;
            self.as32_mut().e_entry = e.wrapping_add(delta as u32);
        }
    }
    #[inline]
    pub fn ident(&self, index: usize) -> u8 {
        self.as32().e_ident[index]
    }
    #[inline]
    pub fn is_class32(&self) -> bool {
        self.ident(4) == 1
    }
    #[inline]
    pub fn is_class64(&self) -> bool {
        self.ident(4) == 2
    }
    /// `ELF_FIELD()` — 64-bit when class64.
    #[inline]
    pub fn field64(
        &self,
        f32: impl Fn(&ElfHeader32) -> u32,
        f64: impl Fn(&ElfHeader64) -> u64,
    ) -> u64 {
        if self.is_class64() {
            f64(self.as64())
        } else {
            f32(self.as32()) as u64
        }
    }
    pub fn e_type(&self) -> u16 {
        self.as64().e_type
    }
    pub fn e_machine(&self) -> u16 {
        self.as64().e_machine
    }
    pub fn e_entry(&self) -> u64 {
        self.field64(|h| h.e_entry, |h| h.e_entry)
    }
    pub fn e_phoff(&self) -> u64 {
        self.field64(|h| h.e_phoff, |h| h.e_phoff)
    }
    pub fn e_phentsize(&self) -> u16 {
        self.as64().e_phentsize
    }
    pub fn e_phnum(&self) -> u16 {
        self.as64().e_phnum
    }
    pub fn is_position_independent(&self) -> bool {
        self.e_type() == ET_DYN
    }
}

impl ProgramHeader {
    /// POD-union views — see `ElfHeader::as32`.
    #[inline]
    fn as32(&self) -> &ProgramHeader32 {
        // SAFETY: all-POD variant; any stored bit pattern is valid.
        unsafe { &self.class32 }
    }
    #[inline]
    fn as64(&self) -> &ProgramHeader64 {
        // SAFETY: all-POD variant; any stored bit pattern is valid.
        unsafe { &self.class64 }
    }
    #[inline]
    pub fn field(
        &self,
        ehdr: &ElfHeader,
        f32: impl Fn(&ProgramHeader32) -> u32,
        f64: impl Fn(&ProgramHeader64) -> u64,
    ) -> u64 {
        if ehdr.is_class64() {
            f64(self.as64())
        } else {
            f32(self.as32()) as u64
        }
    }
    pub fn p_type(&self, ehdr: &ElfHeader) -> u64 {
        self.field(ehdr, |p| p.p_type, |p| p.p_type as u64)
    }
    pub fn p_offset(&self, ehdr: &ElfHeader) -> u64 {
        self.field(ehdr, |p| p.p_offset, |p| p.p_offset)
    }
    pub fn p_vaddr(&self, ehdr: &ElfHeader) -> u64 {
        self.field(ehdr, |p| p.p_vaddr, |p| p.p_vaddr)
    }
    pub fn p_filesz(&self, ehdr: &ElfHeader) -> u64 {
        self.field(ehdr, |p| p.p_filesz, |p| p.p_filesz)
    }
    pub fn p_memsz(&self, ehdr: &ElfHeader) -> u64 {
        self.field(ehdr, |p| p.p_memsz, |p| p.p_memsz)
    }
    pub fn p_flags(&self, ehdr: &ElfHeader) -> u64 {
        self.field(ehdr, |p| p.p_flags, |p| p.p_flags as u64)
    }
}

impl DynamicEntry {
    /// POD-union views — see `ElfHeader::as32`.
    #[inline]
    fn as32(&self) -> &DynamicEntry32 {
        // SAFETY: all-POD variant; any stored bit pattern is valid.
        unsafe { &self.class32 }
    }
    #[inline]
    fn as64(&self) -> &DynamicEntry64 {
        // SAFETY: all-POD variant; any stored bit pattern is valid.
        unsafe { &self.class64 }
    }
    #[inline]
    pub fn field(
        &self,
        ehdr: &ElfHeader,
        f32: impl Fn(&DynamicEntry32) -> u32,
        f64: impl Fn(&DynamicEntry64) -> u64,
    ) -> u64 {
        if ehdr.is_class64() {
            f64(self.as64())
        } else {
            f32(self.as32()) as u64
        }
    }
    pub fn d_tag(&self, ehdr: &ElfHeader) -> i64 {
        self.field(ehdr, |d| d.d_tag as u32, |d| d.d_tag as u64) as i64
    }
    pub fn d_val(&self, ehdr: &ElfHeader) -> u64 {
        self.field(ehdr, |d| d.d_val, |d| d.d_val)
    }
}

pub fn known_phentsize(header: &ElfHeader, size: u64) -> bool {
    (header.is_class32() && size == size_of::<ProgramHeader32>() as u64)
        || (header.is_class64() && size == size_of::<ProgramHeader64>() as u64)
}

/// `open_elf()` — open `t_path` and read+validate its ELF header.  On success
/// returns Ok((fd, header)); the fd is left open at offset 0.
pub fn open_elf(t_path: &std::ffi::CStr) -> Result<(RawFd, ElfHeader), i32> {
    let fd = crate::sys::open(t_path, libc::O_RDONLY, 0);
    if fd < 0 {
        return Err(-crate::sys::errno());
    }
    let mut ehdr: ElfHeader = crate::sys::zeroed();
    let n = crate::sys::read(fd, crate::sys::as_bytes_mut(&mut ehdr));
    if n < size_of::<ElfHeader32>() as isize {
        crate::sys::close(fd);
        return Err(-libc::ENOEXEC);
    }
    if ehdr.ident(0) != 0x7f
        || ehdr.ident(1) != b'E'
        || ehdr.ident(2) != b'L'
        || ehdr.ident(3) != b'F'
    {
        crate::sys::close(fd);
        return Err(-libc::ENOEXEC);
    }
    if !ehdr.is_class32() && !ehdr.is_class64() {
        crate::sys::close(fd);
        return Err(-libc::ENOEXEC);
    }
    Ok((fd, ehdr))
}

/// `is_host_elf()` — whether `t_path` is an ELF for the *host* machine
/// (relevant under QEMU mixed mode).
pub fn is_host_elf(tracee: &Tracee, t_path: &crate::fpath::FixedPath) -> bool {
    static FORCE_FOREIGN: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    let force_foreign =
        *FORCE_FOREIGN.get_or_init(|| std::env::var_os("PROOT_FORCE_FOREIGN_BINARY").is_some());
    if force_foreign || tracee.qemu.is_none() {
        return false;
    }
    match open_elf(t_path.as_c_str()) {
        Ok((fd, ehdr)) => {
            crate::sys::close(fd);
            if crate::arch::HOST_ELF_MACHINE.contains(&ehdr.e_machine()) {
                crate::verbose!(
                    Some(tracee),
                    1,
                    "'{}' is a host ELF",
                    String::from_utf8_lossy(t_path.as_bytes())
                );
                true
            } else {
                false
            }
        }
        Err(_) => false,
    }
}

/// `iterate_program_headers()` — walk program headers of `fd`, calling `cb`
/// on each.  The callback returns <0 to abort iteration.
pub fn iterate_program_headers(
    fd: RawFd,
    elf_header: &ElfHeader,
    mut cb: impl FnMut(&ElfHeader, &ProgramHeader) -> i32,
) -> i32 {
    let phoff = elf_header.e_phoff();
    let phentsize = elf_header.e_phentsize() as u64;
    let phnum = elf_header.e_phnum() as u64;
    if !known_phentsize(elf_header, phentsize) {
        return -libc::EINVAL;
    }
    for i in 0..phnum {
        let mut phdr: ProgramHeader = crate::sys::zeroed();
        let off = phoff + i * phentsize;
        let n = crate::sys::pread(
            fd,
            &mut crate::sys::as_bytes_mut(&mut phdr)[..phentsize as usize],
            off as i64,
        );
        if n != phentsize as isize {
            return -libc::EIO;
        }
        let status = cb(elf_header, &phdr);
        if status != 0 {
            return status;
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;

    /// Build a minimal ELF file: header (class given) + `n` program
    /// headers of `ptype`, laid out per the kernel format.
    fn make_elf(class64: bool, e_type: u16, machine: u16, ptypes: &[u32]) -> Vec<u8> {
        let mut buf = Vec::new();
        if class64 {
            let phoff = size_of::<ElfHeader64>() as u64;
            let mut h: ElfHeader64 = crate::sys::zeroed();
            h.e_ident = [0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            h.e_type = e_type;
            h.e_machine = machine;
            h.e_version = 1;
            h.e_entry = 0x401000;
            h.e_phoff = phoff;
            h.e_ehsize = size_of::<ElfHeader64>() as u16;
            h.e_phentsize = size_of::<ProgramHeader64>() as u16;
            h.e_phnum = ptypes.len() as u16;
            buf.extend_from_slice(crate::sys::as_bytes(&h));
            for &pt in ptypes {
                let mut p: ProgramHeader64 = crate::sys::zeroed();
                p.p_type = pt;
                p.p_offset = 0x1000;
                p.p_vaddr = 0x400000;
                p.p_filesz = 0x100;
                p.p_memsz = 0x200;
                p.p_flags = PF_R | PF_X;
                buf.extend_from_slice(crate::sys::as_bytes(&p));
            }
        } else {
            let phoff = size_of::<ElfHeader32>() as u64;
            let mut h: ElfHeader32 = crate::sys::zeroed();
            h.e_ident = [0x7f, b'E', b'L', b'F', 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            h.e_type = e_type;
            h.e_machine = machine;
            h.e_version = 1;
            h.e_entry = 0x8048000;
            h.e_phoff = phoff as u32;
            h.e_ehsize = size_of::<ElfHeader32>() as u16;
            h.e_phentsize = size_of::<ProgramHeader32>() as u16;
            h.e_phnum = ptypes.len() as u16;
            buf.extend_from_slice(crate::sys::as_bytes(&h));
            for &pt in ptypes {
                let mut p: ProgramHeader32 = crate::sys::zeroed();
                p.p_type = pt;
                p.p_offset = 0x800;
                p.p_vaddr = 0x8000000;
                p.p_filesz = 0x80;
                p.p_memsz = 0x90;
                p.p_flags = PF_R;
                buf.extend_from_slice(crate::sys::as_bytes(&p));
            }
        }
        buf
    }

    #[test]
    fn header_class_detection() {
        let td = TempDir::new("elf");
        td.file("e64", &make_elf(true, ET_EXEC, 62, &[]));
        td.file("e32", &make_elf(false, ET_EXEC, 40, &[]));
        let c64 = std::ffi::CString::new(td.abs("e64")).unwrap();
        let c32 = std::ffi::CString::new(td.abs("e32")).unwrap();
        let (fd, h) = open_elf(&c64).unwrap();
        assert!(h.is_class64() && !h.is_class32());
        crate::sys::close(fd);
        let (fd, h) = open_elf(&c32).unwrap();
        assert!(h.is_class32() && !h.is_class64());
        crate::sys::close(fd);
    }

    #[test]
    fn header_field_accessors() {
        let td = TempDir::new("elf");
        td.file("e64", &make_elf(true, ET_DYN, 62, &[]));
        let c = std::ffi::CString::new(td.abs("e64")).unwrap();
        let (fd, h) = open_elf(&c).unwrap();
        crate::sys::close(fd);
        assert_eq!(h.e_type(), ET_DYN);
        assert_eq!(h.e_machine(), 62);
        assert_eq!(h.e_entry(), 0x401000);
        assert_eq!(h.e_phoff(), size_of::<ElfHeader64>() as u64);
        assert!(h.is_position_independent());
    }

    #[test]
    fn open_elf_rejects_garbage() {
        let td = TempDir::new("elf");
        td.file("junk", b"not an elf at all, way too short");
        let c = std::ffi::CString::new(td.abs("junk")).unwrap();
        assert_eq!(open_elf(&c).err(), Some(-libc::ENOEXEC));
        // Right size, wrong magic.
        td.file("fake", &[b'X'; 64]);
        let c = std::ffi::CString::new(td.abs("fake")).unwrap();
        assert_eq!(open_elf(&c).err(), Some(-libc::ENOEXEC));
        // Bad class byte.
        let mut bad = make_elf(true, ET_EXEC, 62, &[]);
        bad[4] = 9;
        td.file("badcls", &bad);
        let c = std::ffi::CString::new(td.abs("badcls")).unwrap();
        assert_eq!(open_elf(&c).err(), Some(-libc::ENOEXEC));
        // Missing file — construct a literal (non-canonicalized) path.
        let missing = format!("{}/nope", td.path().display());
        let c = std::ffi::CString::new(missing).unwrap();
        assert!(matches!(open_elf(&c), Err(e) if e == -libc::ENOENT));
    }

    #[test]
    fn iterate_program_headers_visits_each() {
        let td = TempDir::new("elf");
        td.file(
            "e64",
            &make_elf(true, ET_EXEC, 62, &[PT_LOAD, PT_INTERP, PT_LOAD]),
        );
        let c = std::ffi::CString::new(td.abs("e64")).unwrap();
        let (fd, h) = open_elf(&c).unwrap();
        let mut seen = Vec::new();
        let r = iterate_program_headers(fd, &h, |eh, ph| {
            seen.push(ph.p_type(eh));
            0
        });
        crate::sys::close(fd);
        assert_eq!(r, 0);
        assert_eq!(seen, vec![PT_LOAD as u64, PT_INTERP as u64, PT_LOAD as u64]);
    }

    #[test]
    fn iterate_program_headers_aborts_on_cb_status() {
        let td = TempDir::new("elf");
        td.file(
            "e64",
            &make_elf(true, ET_EXEC, 62, &[PT_LOAD, PT_LOAD, PT_LOAD]),
        );
        let c = std::ffi::CString::new(td.abs("e64")).unwrap();
        let (fd, h) = open_elf(&c).unwrap();
        let mut n = 0;
        let r = iterate_program_headers(fd, &h, |_, _| {
            n += 1;
            if n == 2 { -libc::ELOOP } else { 0 }
        });
        crate::sys::close(fd);
        assert_eq!(r, -libc::ELOOP);
        assert_eq!(n, 2);
    }

    #[test]
    fn iterate_program_headers_reads_fields() {
        let td = TempDir::new("elf");
        td.file("e64", &make_elf(true, ET_EXEC, 62, &[PT_LOAD]));
        let c = std::ffi::CString::new(td.abs("e64")).unwrap();
        let (fd, h) = open_elf(&c).unwrap();
        let mut got = None;
        let r = iterate_program_headers(fd, &h, |eh, ph| {
            got = Some((
                ph.p_type(eh),
                ph.p_offset(eh),
                ph.p_vaddr(eh),
                ph.p_filesz(eh),
                ph.p_memsz(eh),
                ph.p_flags(eh),
            ));
            0
        });
        crate::sys::close(fd);
        assert_eq!(r, 0);
        assert_eq!(
            got,
            Some((1, 0x1000, 0x400000, 0x100, 0x200, (PF_R | PF_X) as u64))
        );
    }

    #[test]
    fn known_phentsize_matches_class() {
        let td = TempDir::new("elf");
        td.file("e64", &make_elf(true, ET_EXEC, 62, &[]));
        td.file("e32", &make_elf(false, ET_EXEC, 40, &[]));
        let c = std::ffi::CString::new(td.abs("e64")).unwrap();
        let (fd, h64) = open_elf(&c).unwrap();
        crate::sys::close(fd);
        let c = std::ffi::CString::new(td.abs("e32")).unwrap();
        let (fd, h32) = open_elf(&c).unwrap();
        crate::sys::close(fd);
        assert!(known_phentsize(&h64, size_of::<ProgramHeader64>() as u64));
        assert!(!known_phentsize(&h64, size_of::<ProgramHeader32>() as u64));
        assert!(known_phentsize(&h32, size_of::<ProgramHeader32>() as u64));
        assert!(!known_phentsize(&h32, 999));
    }

    #[test]
    fn entry_bias_wraps_in_class() {
        let td = TempDir::new("elf");
        td.file("e64", &make_elf(true, ET_EXEC, 62, &[]));
        td.file("e32", &make_elf(false, ET_EXEC, 40, &[]));
        let c = std::ffi::CString::new(td.abs("e64")).unwrap();
        let (fd, mut h64) = open_elf(&c).unwrap();
        crate::sys::close(fd);
        h64.set_entry_bias(0x1000);
        assert_eq!(h64.e_entry(), 0x401000 + 0x1000);
        let c = std::ffi::CString::new(td.abs("e32")).unwrap();
        let (fd, mut h32) = open_elf(&c).unwrap();
        crate::sys::close(fd);
        // 32-bit entry wraps at u32.
        h32.set_entry_bias(u64::MAX);
        assert_eq!(
            h32.e_entry(),
            (0x8048000u64 + u64::from(u32::MAX)) & u64::from(u32::MAX)
        );
    }

    #[test]
    fn is_host_elf_false_without_qemu() {
        let t = crate::testutil::test_tracee("/", &[]);
        let p = crate::fpath::FixedPath::from_bytes(b"/bin/true");
        // No QEMU configured -> never a "host" ELF.
        assert!(!is_host_elf(&t, &p));
    }
}
