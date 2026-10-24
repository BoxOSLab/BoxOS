//! Unix-socket path translation — port of syscall/socket.c.
//!
//! `sockaddr_un` has the same layout on every architecture.

use crate::Word;
use crate::fpath::{FixedPath, PathGuard};
use crate::tracee::Tracee;
use crate::tracee::mem::{alloc_mem, peek_int32, poke_int32, read_data, write_data};

const OFFSETOF_PATH: usize = std::mem::offset_of!(libc::sockaddr_un, sun_path);
const SIZEOF_PATH: usize = 108; // sizeof(sun_path)
const SIZEOF_SOCKADDR_UN: usize = size_of::<libc::sockaddr_un>();

/// `read_sockaddr_un()` — copy the sockaddr_un at @address out of the
/// tracee; 1 if it's a named AF_UNIX socket, 0 if not applicable,
/// -errno on error.
fn read_sockaddr_un(
    tracee: &Tracee,
    sockaddr: &mut libc::sockaddr_un,
    max_size: Word,
    path: &mut FixedPath,
    address: Word,
    size: i32,
) -> i32 {
    debug_assert!(max_size <= SIZEOF_SOCKADDR_UN as Word);

    if size <= OFFSETOF_PATH as i32 || size as Word > max_size {
        return 0;
    }

    *sockaddr = crate::sys::zeroed();
    let raw = crate::sys::as_bytes_mut(sockaddr);
    let status = read_data(tracee, &mut raw[..size as usize], address);
    if status < 0 {
        return status;
    }

    if sockaddr.sun_family != libc::AF_UNIX as u16 || sockaddr.sun_path[0] == 0 {
        return 0;
    }

    // sun_path doesn't have to be NUL-terminated.
    let sun: &[u8] = crate::sys::as_bytes(&sockaddr.sun_path);
    let end = sun.iter().position(|&c| c == 0).unwrap_or(SIZEOF_PATH);
    let mut p = [0u8; crate::PATH_MAX];
    p[..end].copy_from_slice(&sun[..end]);
    path.set(&p[..end]);
    1
}

/// `translate_socketcall_enter()` — translate the sun_path at @*address
/// and move the rewritten sockaddr to tracer-allocated memory.
/// Returns 1 when a translation happened, 0 when not applicable,
/// -errno on error.
pub fn translate_socketcall_enter(tracee: &mut Tracee, address: &mut Word, size: Word) -> i32 {
    let mut sockaddr: libc::sockaddr_un = crate::sys::zeroed();
    let mut user_path = PathGuard::new();
    let mut host_path = PathGuard::new();

    if *address == 0 {
        return 0;
    }

    let status = read_sockaddr_un(
        tracee,
        &mut sockaddr,
        SIZEOF_SOCKADDR_UN as Word,
        &mut user_path,
        *address,
        size as i32,
    );
    if status <= 0 {
        return status;
    }

    let status = match crate::path::translate_path(
        tracee,
        &mut host_path,
        libc::AT_FDCWD,
        user_path.as_bytes(),
        true,
    ) {
        Ok(()) => 0,
        Err(e) => e,
    };
    if status < 0 {
        return status;
    }

    if host_path.len() > SIZEOF_PATH {
        // The translated path doesn't fit: bind it to a short temp path.
        let shorter = match crate::path::temp::create_temp_name("proot") {
            Some(s) => s,
            None => return -libc::EINVAL,
        };
        if shorter.len() > SIZEOF_PATH {
            return -libc::EINVAL;
        }

        // The guest side of the new binding must be canonicalized.
        let mut guest = host_path.clone();
        if crate::path::detranslate_path(tracee, &mut guest, None).is_err() {
            return -libc::EINVAL;
        }

        if crate::path::binding::insort_binding3(tracee, shorter.as_bytes(), guest.as_bytes())
            .is_none()
        {
            return -libc::EINVAL;
        }

        host_path.set(shorter.as_bytes());
    }

    // Copy host_path into sun_path (not NUL-terminated if it fills).
    let hb = host_path.as_bytes();
    let n = hb.len().min(SIZEOF_PATH);
    for (dst, src) in sockaddr.sun_path.iter_mut().zip(hb.iter().take(n)) {
        *dst = *src as libc::c_char;
    }
    if n < SIZEOF_PATH {
        sockaddr.sun_path[n] = 0;
    }

    *address = alloc_mem(tracee, SIZEOF_SOCKADDR_UN as i64);
    if *address == 0 {
        return -libc::EFAULT;
    }

    let raw = crate::sys::as_bytes(&sockaddr);
    let status = write_data(tracee, *address, raw);
    if status < 0 {
        return status;
    }
    1
}

/// `translate_socketcall_exit()` — detranslate the sun_path written by
/// the kernel into the tracee's buffer.
pub fn translate_socketcall_exit(
    tracee: &mut Tracee,
    sock_addr: Word,
    size_addr: Word,
    max_size: Word,
) -> i32 {
    let mut sockaddr: libc::sockaddr_un = crate::sys::zeroed();
    let mut path = PathGuard::new();

    if sock_addr == 0 {
        return 0;
    }

    crate::sys::clear_errno();
    let mut size = peek_int32(tracee, size_addr);
    if crate::sys::errno() != 0 {
        return -crate::sys::errno();
    }

    let max_size = max_size.min(SIZEOF_SOCKADDR_UN as Word);
    let status = read_sockaddr_un(tracee, &mut sockaddr, max_size, &mut path, sock_addr, size);
    if status <= 0 {
        return status;
    }

    if let Err(e) = crate::path::detranslate_path(tracee, &mut path, None) {
        return e;
    }

    let mut is_truncated = false;
    size = (OFFSETOF_PATH + path.len() + 1) as i32;
    if size < 0 || size as Word > max_size {
        size = max_size as i32;
        is_truncated = true;
    }

    let pb = path.as_bytes();
    let n = pb.len().min(SIZEOF_PATH - 1);
    for (dst, src) in sockaddr.sun_path.iter_mut().zip(pb.iter().take(n)) {
        *dst = *src as libc::c_char;
    }
    sockaddr.sun_path[n] = 0;

    let raw = crate::sys::as_bytes(&sockaddr);
    let status = write_data(tracee, sock_addr, &raw[..size as usize]);
    if status < 0 {
        return status;
    }

    // If the sockaddr was truncated, addrlen reports one byte more than
    // was supplied (see accept(2)).
    if is_truncated {
        size = max_size as i32 + 1;
    }

    crate::sys::clear_errno();
    poke_int32(tracee, size_addr, size);
    if crate::sys::errno() != 0 {
        return -crate::sys::errno();
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{Arena, TempDir, fork_child, test_tracee};

    /// Write a sockaddr_un for `path` (NUL-terminated) into the arena,
    /// return (sock_addr, size).
    fn put_sockaddr(arena: &mut Arena, off: usize, path: &[u8]) -> (u64, i32) {
        let mut sa: libc::sockaddr_un = crate::sys::zeroed();
        sa.sun_family = libc::AF_UNIX as u16;
        for (d, s) in sa.sun_path.iter_mut().zip(path.iter()) {
            *d = *s as libc::c_char;
        }
        let size = (OFFSETOF_PATH + path.len() + 1).min(SIZEOF_SOCKADDR_UN);
        let raw = crate::sys::as_bytes(&sa);
        arena.local()[off..off + size].copy_from_slice(&raw[..size]);
        (arena.addr() + off as u64, size as i32)
    }

    #[test]
    fn read_sockaddr_un_skips_short_and_non_unix() {
        let mut arena = Arena::new(1);
        let Some(child) = fork_child(&arena) else {
            return;
        };
        let t = child.tracee();
        let mut sa: libc::sockaddr_un = crate::sys::zeroed();
        let mut path = FixedPath::new();

        // size smaller than the path offset -> 0.
        let (addr, _sz) = put_sockaddr(&mut arena, 0, b"/x");
        let st = read_sockaddr_un(
            &t,
            &mut sa,
            SIZEOF_SOCKADDR_UN as Word,
            &mut path,
            addr,
            OFFSETOF_PATH as i32,
        );
        assert_eq!(st, 0);
        // size > max_size -> 0.
        let st = read_sockaddr_un(&t, &mut sa, 8, &mut path, addr, 100);
        assert_eq!(st, 0);
        // AF_INET family -> 0.
        let mut sa2: libc::sockaddr_un = crate::sys::zeroed();
        sa2.sun_family = libc::AF_INET as u16;
        arena.local()[..4].copy_from_slice(&crate::sys::as_bytes(&sa2)[..4]);
        let st = read_sockaddr_un(
            &t,
            &mut sa,
            SIZEOF_SOCKADDR_UN as Word,
            &mut path,
            arena.addr(),
            SIZEOF_SOCKADDR_UN as i32,
        );
        assert_eq!(st, 0);
        // Abstract socket (leading NUL sun_path) -> 0.
        let mut sa3: libc::sockaddr_un = crate::sys::zeroed();
        sa3.sun_family = libc::AF_UNIX as u16;
        sa3.sun_path[0] = 0;
        sa3.sun_path[1] = b'a' as _;
        let raw = crate::sys::as_bytes(&sa3);
        arena.local()[..raw.len()].copy_from_slice(raw);
        let st = read_sockaddr_un(
            &t,
            &mut sa,
            SIZEOF_SOCKADDR_UN as Word,
            &mut path,
            arena.addr(),
            SIZEOF_SOCKADDR_UN as i32,
        );
        assert_eq!(st, 0);
    }

    #[test]
    fn read_sockaddr_un_extracts_path() {
        let mut arena = Arena::new(1);
        let Some(child) = fork_child(&arena) else {
            return;
        };
        let t = child.tracee();
        let (addr, size) = put_sockaddr(&mut arena, 0, b"/tmp/sock");
        let mut sa: libc::sockaddr_un = crate::sys::zeroed();
        let mut path = FixedPath::new();
        let st = read_sockaddr_un(
            &t,
            &mut sa,
            SIZEOF_SOCKADDR_UN as Word,
            &mut path,
            addr,
            size,
        );
        assert_eq!(st, 1);
        assert_eq!(path.as_bytes(), b"/tmp/sock");
        // A sun_path that fills the field is still handled (no NUL needed).
        let long = vec![b'p'; SIZEOF_PATH];
        let (addr, size) = put_sockaddr(&mut arena, 256, &long);
        let st = read_sockaddr_un(
            &t,
            &mut sa,
            SIZEOF_SOCKADDR_UN as Word,
            &mut path,
            addr,
            size,
        );
        assert_eq!(st, 1);
        assert_eq!(path.as_bytes(), long.as_slice());
    }

    #[test]
    fn socketcall_enter_translates_path() {
        let td = TempDir::new("sock");
        let mut arena = Arena::new(2);
        let Some(child) = fork_child(&arena) else {
            return;
        };
        let mut t = test_tracee(td.path().to_str().unwrap(), &[]);
        t.pid = child.pid;
        crate::testutil::use_arena_stack(&mut t, &arena);
        let (addr, size) = put_sockaddr(&mut arena, 0, b"/my.sock");
        let mut address = addr;
        let st = translate_socketcall_enter(&mut t, &mut address, size as Word);
        assert_eq!(st, 1);
        assert_ne!(address, addr, "sockaddr must move to translated copy");
        // Read back the written sockaddr: sun_path holds the host path.
        let off = (address - arena.addr()) as usize;
        let sa_raw = &arena.local()[off..off + SIZEOF_SOCKADDR_UN];
        let family = u16::from_ne_bytes(sa_raw[..2].try_into().unwrap());
        assert_eq!(family, libc::AF_UNIX as u16);
        let want = [td.abs(".").as_slice(), b"/my.sock\0"].concat();
        assert_eq!(
            &sa_raw[OFFSETOF_PATH..OFFSETOF_PATH + want.len()],
            want.as_slice()
        );
        // NULL address -> 0.
        let mut null_addr = 0;
        assert_eq!(
            translate_socketcall_enter(&mut t, &mut null_addr, size as Word),
            0
        );
    }

    #[test]
    fn socketcall_enter_writes_to_free_remote_mem() {
        // The translated sockaddr lands in alloc_mem'd tracee memory;
        // with_sp points the stack at the arena so that write succeeds.
        let td = TempDir::new("sock");
        let mut arena = Arena::new(3);
        let Some(child) = fork_child(&arena) else {
            return;
        };
        let mut t = test_tracee(td.path().to_str().unwrap(), &[]);
        t.pid = child.pid;
        crate::testutil::use_arena_stack(&mut t, &arena);
        let (addr, size) = put_sockaddr(&mut arena, 0, b"/s");
        let mut address = addr;
        assert_eq!(
            translate_socketcall_enter(&mut t, &mut address, size as Word),
            1
        );
        let off = (address - arena.addr()) as usize;
        assert!(off < arena.len);
        assert_eq!(
            &arena.local()[off + OFFSETOF_PATH..][..2],
            td.abs(".").as_slice().get(..2).unwrap()
        );
    }

    #[test]
    fn socketcall_exit_detranslates() {
        let td = TempDir::new("sock");
        let mut arena = Arena::new(2);
        let Some(child) = fork_child(&arena) else {
            return;
        };
        let mut t = test_tracee(td.path().to_str().unwrap(), &[]);
        t.pid = child.pid;
        // Kernel wrote a host path; exit must detranslate to the guest view.
        let host_sock = [td.abs(".").as_slice(), b"/s"].concat();
        let (addr, size) = put_sockaddr(&mut arena, 0, &host_sock);
        let size_addr = arena.addr() + 1024;
        arena.local()[1024..1028].copy_from_slice(&size.to_ne_bytes());
        let st = translate_socketcall_exit(&mut t, addr, size_addr, SIZEOF_SOCKADDR_UN as Word);
        assert_eq!(st, 0);
        // sun_path now holds the guest path.
        let sa_raw = &arena.local()[..SIZEOF_SOCKADDR_UN];
        assert_eq!(&sa_raw[OFFSETOF_PATH..OFFSETOF_PATH + 3], b"/s\0");
        // addrlen updated to cover path+NUL.
        let new_len = i32::from_ne_bytes(arena.local()[1024..1028].try_into().unwrap());
        assert_eq!(new_len, OFFSETOF_PATH as i32 + 3);
        // NULL sock_addr -> 0.
        assert_eq!(translate_socketcall_exit(&mut t, 0, size_addr, 128), 0);
    }
}
