//! Dynamic-linker environment handling — port of execve/ldso.c.
//!
//! When QEMU is used, `LD_*` variables must apply to the guest program
//! (`qemu -E VAR=...`) rather than to QEMU itself; and host binaries need
//! `LD_LIBRARY_PATH` rewritten through the `/host-rootfs` binding.

use std::io::{Read, Seek, SeekFrom};
use std::os::unix::io::{AsRawFd, RawFd};

use crate::HOST_ROOTFS;
use crate::execve::aoxp::{
    XPointerArray, find_xpointee_env, is_env_name, read_xpointee_as_string,
    resize_array_of_xpointers, write_xpointee_string, write_xpointees,
};
use crate::execve::elf::{
    DT_RPATH, DT_RUNPATH, DT_STRTAB, DynamicEntry, ElfHeader, PT_DYNAMIC, PT_LOAD, ProgramHeader,
    iterate_program_headers, open_elf,
};
use crate::tracee::Tracee;

/// `ARG_MAX`.
const ARG_MAX: usize = 131072;

/// `ldso_env_passthru()` — move every `LD_*` env into `define env`-prefixed
/// runner arguments and blank them from `envp`.  `offset` is where to insert
/// in `argv`; `undefine`/`define` are the runner flags ("-U"/"-E" for QEMU).
pub fn ldso_env_passthru(
    tracee: &Tracee,
    envp: &mut XPointerArray,
    argv: &mut XPointerArray,
    define: &str,
    undefine: &str,
    offset: usize,
) -> i32 {
    let mut has_seen_library_path = false;

    for i in 0..envp.entries.len() {
        let env = match read_xpointee_as_string(tracee, envp, i) {
            Ok(Some(e)) => e,
            Ok(None) => continue,
            Err(e) => return e,
        };
        if !env.starts_with(b"LD_") {
            continue;
        }
        let mut env = env;

        // When a host program execs a guest program, restore the guest's
        // LD_LIBRARY_PATH (swapped out by the mixed-mode support).
        if let (Some(host), Some(guest)) = (&tracee.host_ldso_paths, &tracee.guest_ldso_paths) {
            if is_env_name(&env, "LD_LIBRARY_PATH")
                && env[..env.len().saturating_sub(1)] == *host.as_bytes()
            {
                env = guest.as_bytes().to_vec();
            }
        }

        // Errors are not fatal here (per the C code).  Each pair is inserted
        // at `offset` so later entries push earlier ones right, like the C code.
        macro_rules! passthru {
            ($name:expr_2021) => {{
                if !is_env_name(&env, $name) {
                    false
                } else {
                    if resize_array_of_xpointers(argv, offset, 2) >= 0 {
                        let mut v = env.clone();
                        while v.last() == Some(&0) {
                            v.pop();
                        }
                        write_xpointees(argv, offset, &[define.as_bytes(), &v]);
                    }
                    write_xpointee_string(envp, i, b"");
                    true
                }
            }};
        }

        // First matching name wins (an else-if chain in the C code).
        for name in [
            "LD_LIBRARY_PATH",
            "LD_PRELOAD",
            "LD_BIND_NOW",
            "LD_TRACE_LOADED_OBJECTS",
            "LD_AOUT_LIBRARY_PATH",
            "LD_AOUT_PRELOAD",
            "LD_AUDIT",
            "LD_BIND_NOT",
            "LD_DEBUG",
            "LD_DEBUG_OUTPUT",
            "LD_DYNAMIC_WEAK",
            "LD_HWCAP_MASK",
            "LD_KEEPDIR",
            "LD_NOWARN",
            "LD_ORIGIN_PATH",
            "LD_POINTER_GUARD",
            "LD_PROFILE",
            "LD_PROFILE_OUTPUT",
            "LD_SHOW_AUXV",
            "LD_USE_LOAD_BIAS",
            "LD_VERBOSE",
            "LD_WARN",
        ] {
            if passthru!(name) {
                has_seen_library_path |= name == "LD_LIBRARY_PATH";
                break;
            }
        }
    }

    if !has_seen_library_path && resize_array_of_xpointers(argv, offset, 2) >= 0 {
        write_xpointees(argv, offset, &[undefine.as_bytes(), b"LD_LIBRARY_PATH"]);
    }
    0
}

/// `add_host_ldso_paths()` — append each entry of the ':'-separated `paths`
/// to `host_ldso_paths`, prefixing absolute paths with the HOST_ROOTFS
/// binding (host binaries under QEMU see libraries through it).
fn add_host_ldso_paths(host_ldso_paths: &mut Vec<u8>, paths: &str) -> i32 {
    // The C loop walks the ':'-separated string including a possible
    // trailing empty component ("a:" appends ':' as well).
    for entry in paths.split(':') {
        let is_absolute = entry.starts_with('/');
        let mut piece: Vec<u8> = Vec::new();
        if !host_ldso_paths.is_empty() {
            piece.push(b':');
        }
        if is_absolute {
            piece.extend_from_slice(HOST_ROOTFS.as_bytes());
        }
        piece.extend_from_slice(entry.as_bytes());
        if host_ldso_paths.len() + piece.len() >= ARG_MAX {
            return -libc::ENOEXEC;
        }
        host_ldso_paths.extend_from_slice(&piece);
    }
    0
}

/// `find_program_header` callback — locate the first phdr of `ptype`
/// (optionally containing `address`).
fn find_program_header(
    elf_header: &ElfHeader,
    phdr: &ProgramHeader,
    ptype: u32,
    address: u64,
) -> Option<ProgramHeader> {
    if phdr.p_type(elf_header) as u32 != ptype {
        return None;
    }
    if address == u64::MAX {
        return Some(*phdr);
    }
    let start = phdr.p_vaddr(elf_header);
    let end = start + phdr.p_memsz(elf_header);
    if start < end && address >= start && address <= end {
        return Some(*phdr);
    }
    None
}

/// `add_xpaths()` — read the NUL-terminated ':'-separated string at `offset`
/// of `fd`, and append it to `xpaths` (':'-joined).
fn add_xpaths(file: &mut std::fs::File, offset: u64, xpaths: &mut Option<Vec<u8>>) -> i32 {
    if file.seek(SeekFrom::Start(offset)).is_err() {
        return -crate::sys::errno();
    }
    let mut paths = Vec::new();
    // Read until the NUL-terminated string ends (or EOF).
    let mut buf = [0u8; 1024];
    loop {
        let n = match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => return -crate::sys::errno(),
        };
        let mut end = n;
        if let Some(nul) = buf[..n].iter().position(|b| *b == 0) {
            end = nul;
        }
        paths.extend_from_slice(&buf[..end]);
        if end < n {
            break;
        }
    }
    match xpaths {
        None => *xpaths = Some(paths),
        Some(x) => {
            x.push(b':');
            x.extend_from_slice(&paths);
        }
    }
    0
}

/// DT_RPATH and DT_RUNPATH payload strings extracted from an ELF binary.
type Rpaths = (Option<Vec<u8>>, Option<Vec<u8>>);

/// `read_ldso_rpaths()` — extract DT_RPATH/DT_RUNPATH strings.
fn read_ldso_rpaths(
    file: &mut std::fs::File,
    fd: RawFd,
    elf_header: &ElfHeader,
) -> Result<Rpaths, i32> {
    // Find PT_DYNAMIC.
    let mut dynamic: Option<ProgramHeader> = None;
    let st = iterate_program_headers(fd, elf_header, |eh, ph| {
        if let Some(found) = find_program_header(eh, ph, PT_DYNAMIC, u64::MAX) {
            dynamic = Some(found);
            return 1;
        }
        0
    });
    if st < 0 {
        return Err(st);
    }
    let dynamic = match dynamic {
        Some(d) => d,
        None => return Ok((None, None)),
    };

    let dyn_off = dynamic.p_offset(elf_header);
    let dyn_size = dynamic.p_filesz(elf_header);
    let entry_size = if elf_header.is_class32() {
        size_of::<crate::execve::elf::DynamicEntry32>()
    } else {
        size_of::<crate::execve::elf::DynamicEntry64>()
    } as u64;
    if dyn_size % entry_size != 0 {
        return Err(-libc::ENOEXEC);
    }
    let n_entries = dyn_size / entry_size;

    let read_entry = |file: &std::fs::File, i: u64| -> Result<DynamicEntry, i32> {
        let mut de: DynamicEntry = crate::sys::zeroed();
        let n = crate::sys::pread(
            file.as_raw_fd(),
            &mut crate::sys::as_bytes_mut(&mut de)[..entry_size as usize],
            (dyn_off + i * entry_size) as i64,
        );
        if n != entry_size as isize {
            return Err(-libc::EIO);
        }
        Ok(de)
    };

    let mut strtab_address = u64::MAX;
    for i in 0..n_entries {
        let de = read_entry(file, i)?;
        if de.d_tag(elf_header) == DT_STRTAB {
            strtab_address = de.d_val(elf_header);
            break;
        }
    }
    if strtab_address == u64::MAX {
        return Ok((None, None));
    }

    // Locate the PT_LOAD containing the string table.
    let mut strtab_seg: Option<ProgramHeader> = None;
    let st = iterate_program_headers(fd, elf_header, |eh, ph| {
        if let Some(found) = find_program_header(eh, ph, PT_LOAD, strtab_address) {
            strtab_seg = Some(found);
            return 1;
        }
        0
    });
    if st < 0 {
        return Err(st);
    }
    let strtab_seg = match strtab_seg {
        Some(s) => s,
        None => return Ok((None, None)),
    };
    let strtab_offset =
        strtab_seg.p_offset(elf_header) + (strtab_address - strtab_seg.p_vaddr(elf_header));

    let mut rpaths: Option<Vec<u8>> = None;
    let mut runpaths: Option<Vec<u8>> = None;
    for i in 0..n_entries {
        let de = read_entry(file, i)?;
        let tag = de.d_tag(elf_header);
        if tag != DT_RPATH && tag != DT_RUNPATH {
            continue;
        }
        let val = de.d_val(elf_header);
        if val > u64::MAX - strtab_offset {
            return Err(-libc::ENOEXEC);
        }
        let target = if tag == DT_RPATH {
            &mut rpaths
        } else {
            &mut runpaths
        };
        let st = add_xpaths(file, strtab_offset + val, target);
        if st < 0 {
            return Err(st);
        }
    }
    Ok((rpaths, runpaths))
}

/// `rebuild_host_ldso_paths()` — rewrite `LD_LIBRARY_PATH` in `envp` so the
/// *host* dynamic linker finds the host binary's libraries (through
/// `/host-rootfs` when QEMU is active, else directly).
pub fn rebuild_host_ldso_paths(
    tracee: &mut Tracee,
    host_path: &crate::fpath::FixedPath,
    envp: &mut XPointerArray,
) -> i32 {
    static INITIAL_LDSO_PATHS: std::sync::OnceLock<String> = std::sync::OnceLock::new();

    let (fd, elf_header) = match open_elf(host_path.as_c_str()) {
        Ok(x) => x,
        Err(e) => return e,
    };
    let mut file = crate::sys::file_from_fd(fd);
    let parsed = read_ldso_rpaths(&mut file, fd, &elf_header);
    drop(file); // closes fd
    let (rpaths, runpaths) = match parsed {
        Ok(x) => x,
        Err(e) => return e,
    };

    let mut host_ldso_paths: Vec<u8> = Vec::new();
    let mut rpath_found = false;

    // 1. DT_RPATH (only when no RUNPATH — RUNPATH supersedes it).
    if runpaths.is_none() {
        if let Some(rp) = &rpaths {
            let r = String::from_utf8_lossy(rp).into_owned();
            if add_host_ldso_paths(&mut host_ldso_paths, &r) < 0 {
                return 0; // not fatal
            }
            rpath_found = true;
        }
    }

    // 2. Initial LD_LIBRARY_PATH.
    let initial = INITIAL_LDSO_PATHS
        .get_or_init(|| std::env::var("LD_LIBRARY_PATH").unwrap_or_else(|_| "/".to_string()));
    if !initial.is_empty() && add_host_ldso_paths(&mut host_ldso_paths, initial) < 0 {
        return 0;
    }

    // 3. DT_RUNPATH.
    if let Some(r) = &runpaths {
        let r = String::from_utf8_lossy(r).into_owned();
        if add_host_ldso_paths(&mut host_ldso_paths, &r) < 0 {
            return 0;
        }
        rpath_found = true;
    }

    // 4./5./6. Default library paths per ELF class.
    let defaults = if elf_header.is_class32() {
        "/lib/i386-linux-gnu:/usr/lib/i386-linux-gnu:\
         /lib32:/usr/lib32:/usr/local/lib32:\
         /lib:/usr/lib:/usr/local/lib"
    } else {
        "/lib/x86_64-linux-gnu:/usr/lib/x86_64-linux-gnu:\
         /lib64:/usr/lib64:/usr/local/lib64:\
         /lib:/usr/lib:/usr/local/lib"
    };
    if add_host_ldso_paths(&mut host_ldso_paths, defaults) < 0 {
        return 0;
    }

    let index = match find_xpointee_env(tracee, envp, "LD_LIBRARY_PATH") {
        Ok(i) => i,
        Err(_) => return 0,
    };
    let index = if index == envp.entries.len() {
        // Allocate a new slot right before the trailing NULL.
        let idx = envp.entries.len().saturating_sub(1);
        if resize_array_of_xpointers(envp, idx, 1) < 0 {
            return 0;
        }
        idx
    } else {
        if tracee.guest_ldso_paths.is_none() {
            if let Ok(Some(env)) = read_xpointee_as_string(tracee, envp, index) {
                tracee.guest_ldso_paths = Some(std::rc::Rc::from(
                    String::from_utf8_lossy(&env).into_owned(),
                ));
            }
        }
        index
    };

    let mut var = b"LD_LIBRARY_PATH=".to_vec();
    var.extend_from_slice(&host_ldso_paths);
    write_xpointee_string(envp, index, &var);

    if tracee.host_ldso_paths.is_none() {
        tracee.host_ldso_paths = Some(std::rc::Rc::from(
            String::from_utf8_lossy(&var).into_owned(),
        ));
    }
    rpath_found as i32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execve::elf::*;
    use crate::testutil::TempDir;

    #[test]
    fn add_host_ldso_paths_joins_and_prefixes() {
        let mut v = Vec::new();
        assert_eq!(add_host_ldso_paths(&mut v, "/lib:/usr/lib"), 0);
        // Absolute entries get the host-rootfs prefix.
        let s = String::from_utf8(v.clone()).unwrap();
        assert_eq!(s, format!("{0}/lib:{0}/usr/lib", HOST_ROOTFS));
        // Appending keeps ':'-joining.
        assert_eq!(add_host_ldso_paths(&mut v, "/x"), 0);
        let s = String::from_utf8(v).unwrap();
        assert_eq!(s, format!("{0}/lib:{0}/usr/lib:{0}/x", HOST_ROOTFS));
        // Relative entries get no prefix.
        let mut v = Vec::new();
        assert_eq!(add_host_ldso_paths(&mut v, "rel/lib"), 0);
        assert_eq!(v, b"rel/lib");
    }

    #[test]
    fn add_host_ldso_paths_trailing_colon_keeps_empty() {
        // "a:" produces a trailing empty component, like the C loop.
        let mut v = Vec::new();
        assert_eq!(add_host_ldso_paths(&mut v, "/a:"), 0);
        let s = String::from_utf8(v).unwrap();
        assert_eq!(s, format!("{0}/a:", HOST_ROOTFS));
    }

    #[test]
    fn add_host_ldso_paths_overflow() {
        let mut v = vec![b'x'; ARG_MAX - 2];
        assert_eq!(add_host_ldso_paths(&mut v, "/a"), -libc::ENOEXEC);
    }

    /// Build an ELF64 with a PT_LOAD segment carrying a string table and a
    /// PT_DYNAMIC segment listing DT_STRTAB + given rpath/runpath offsets.
    fn make_dyn_elf(rpath: Option<&str>, runpath: Option<&str>) -> Vec<u8> {
        // Layout: [ehdr][phdrs][dyn][strtab]
        let ehsize = size_of::<ElfHeader64>();
        let phsize = size_of::<ProgramHeader64>();
        let phoff = ehsize;
        let nph = 2;
        let dyn_off = (phoff + nph * phsize) as u64;
        // String table at vaddr 0x600000, mapped by PT_LOAD p_offset=strtab_off.
        let strtab_vaddr = 0x600000u64;
        let mut strtab = vec![0u8]; // index 0 = ""
        let mut dyn_ents: Vec<(i64, u64)> = vec![(DT_STRTAB, strtab_vaddr)];
        for (tag, s) in [(DT_RPATH, rpath), (DT_RUNPATH, runpath)] {
            if let Some(s) = s {
                // d_val is a byte offset *into* the string table.
                let off = strtab.len() as u64;
                strtab.extend_from_slice(s.as_bytes());
                strtab.push(0);
                dyn_ents.push((tag, off));
            }
        }
        dyn_ents.push((0, 0)); // DT_NULL
        let strtab_off = dyn_off + dyn_ents.len() as u64 * size_of::<DynamicEntry64>() as u64;
        let mut buf = Vec::new();
        let mut h: ElfHeader64 = crate::sys::zeroed();
        h.e_ident = [0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        h.e_type = ET_DYN;
        h.e_machine = 62;
        h.e_phoff = phoff as u64;
        h.e_phentsize = phsize as u16;
        h.e_phnum = nph as u16;
        buf.extend_from_slice(crate::sys::as_bytes(&h));
        // PT_LOAD covering the strtab.
        let mut p: ProgramHeader64 = crate::sys::zeroed();
        p.p_type = PT_LOAD;
        p.p_offset = strtab_off;
        p.p_vaddr = strtab_vaddr;
        p.p_filesz = strtab.len() as u64;
        p.p_memsz = strtab.len() as u64;
        buf.extend_from_slice(crate::sys::as_bytes(&p));
        // PT_DYNAMIC.
        let mut d: ProgramHeader64 = crate::sys::zeroed();
        d.p_type = PT_DYNAMIC;
        d.p_offset = dyn_off;
        d.p_filesz = (dyn_ents.len() * size_of::<DynamicEntry64>()) as u64;
        d.p_memsz = d.p_filesz;
        buf.extend_from_slice(crate::sys::as_bytes(&d));
        while buf.len() < dyn_off as usize {
            buf.push(0);
        }
        for (tag, val) in &dyn_ents {
            let de = DynamicEntry64 {
                d_tag: *tag,
                d_val: *val,
            };
            buf.extend_from_slice(crate::sys::as_bytes(&de));
        }
        while buf.len() < strtab_off as usize {
            buf.push(0);
        }
        buf.extend_from_slice(&strtab);
        buf
    }

    fn rpaths_of(bytes: &[u8]) -> Result<Rpaths, i32> {
        let td = TempDir::new("ldso");
        let p = td.file("e", bytes);
        let c = std::ffi::CString::new(p.to_str().unwrap()).unwrap();
        let (fd, eh) = open_elf(&c).unwrap();
        let mut f = crate::sys::file_from_fd(fd);
        let r = read_ldso_rpaths(&mut f, fd, &eh);
        drop(f);
        r
    }

    #[test]
    fn rpaths_extracted() {
        let elf = make_dyn_elf(Some("/opt/lib"), Some("/run/lib"));
        let (rp, run) = rpaths_of(&elf).unwrap();
        assert_eq!(rp.unwrap(), b"/opt/lib");
        assert_eq!(run.unwrap(), b"/run/lib");
    }

    #[test]
    fn no_dynamic_no_rpaths() {
        // Plain ELF with only PT_LOADs -> no rpaths.
        let mut buf = Vec::new();
        let mut h: ElfHeader64 = crate::sys::zeroed();
        h.e_ident = [0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        h.e_type = ET_EXEC;
        h.e_machine = 62;
        h.e_phoff = size_of::<ElfHeader64>() as u64;
        h.e_phentsize = size_of::<ProgramHeader64>() as u16;
        h.e_phnum = 1;
        buf.extend_from_slice(crate::sys::as_bytes(&h));
        let p: ProgramHeader64 = crate::sys::zeroed();
        buf.extend_from_slice(crate::sys::as_bytes(&p));
        let (rp, run) = rpaths_of(&buf).unwrap();
        assert!(rp.is_none() && run.is_none());
    }
}
