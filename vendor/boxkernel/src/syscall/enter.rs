//! `translate_syscall_enter()` — port of syscall/enter.c.
//!
//! Rewrites the input arguments of the tracee's current syscall: guest→host
//! path translation for every path-bearing syscall, bind/connect sockaddr
//! translation, mount/pivot_root/umount emulation as binding edits, and the
//! AF_NETLINK substitution handled by `netlink.rs`.

use crate::Word;
use crate::fpath::{FixedPath, PathGuard};
use crate::path::{Comparison, Side, binding, compare_paths, join_paths2};
use crate::syscall::{get_sysarg_path, netlink, set_sysarg_path};
use crate::sysnum::Sysnum;
use crate::tracee::Tracee;
use crate::tracee::mem::{peek_word, poke_word, read_data, read_string, write_data};
use crate::tracee::reg::{Reg, RegVersion, get_sysnum, peek_reg, poke_reg, set_sysnum};

pub const CLONE_NEWTIME: Word = 0x0000_0080;
pub const CLONE_NEWCGROUP: Word = 0x0200_0000;
pub const CLONE_NS_MASK: Word = libc::CLONE_NEWNS as Word
    | libc::CLONE_NEWUTS as Word
    | libc::CLONE_NEWIPC as Word
    | libc::CLONE_NEWUSER as Word
    | libc::CLONE_NEWPID as Word
    | libc::CLONE_NEWNET as Word
    | CLONE_NEWCGROUP
    | CLONE_NEWTIME;

const PR_SET_DUMPABLE: Word = 4;
const PR_SET_SECCOMP: Word = 22;
const SECCOMP_MODE_FILTER: Word = 2;
const PR_GET_AUXV: Word = 0x41555856;
const PR_GET_NO_NEW_PRIVS: Word = 39;
const PR_SET_NO_NEW_PRIVS: Word = 38;

/// REGULAR vs SYMLINK — C's `Type`: whether the final component is
/// dereferenced during translation.
#[derive(Copy, Clone, PartialEq, Eq)]
enum PType {
    Regular,
    Symlink,
}

/// `force_fork_sysexit()` — keep the exit stage of a fork-family syscall:
/// on some kernels a forking syscall restarted with PTRACE_CONT after its
/// seccomp stop never runs; forcing PTRACE_SYSCALL keeps it proceeding.
fn force_fork_sysexit(tracee: &mut Tracee) {
    tracee.sysexit_pending = true;
    tracee.restart_how = crate::ptrace::ptc::PTRACE_SYSCALL;
}

/// `translate_path2()` — translate `path` and write the host path back into
/// the tracee's `reg` argument.
fn translate_path2(tracee: &mut Tracee, dir_fd: i32, path: &FixedPath, reg: Reg, ty: PType) -> i32 {
    if path.is_empty() {
        return 0;
    }
    let mut new_path = PathGuard::new();
    match crate::path::translate_path(
        tracee,
        &mut new_path,
        dir_fd,
        path.as_bytes(),
        ty == PType::Regular,
    ) {
        Err(e) => e,
        Ok(()) => set_sysarg_path(tracee, new_path.as_bytes(), reg),
    }
}

/// `translate_path2_parent()` — translate the parent directory only; the
/// final component is created by the kernel (link/rename/mkdir targets).
fn translate_path2_parent(tracee: &mut Tracee, dir_fd: i32, path: &FixedPath, reg: Reg) -> i32 {
    if path.is_empty() {
        return 0;
    }
    let bytes = path.as_bytes();
    if bytes.last() == Some(&b'/') {
        return translate_path2(tracee, dir_fd, path, reg, PType::Symlink);
    }
    let last_slash = bytes.iter().rposition(|&b| b == b'/');
    let (parent, leaf): (FixedPath, &[u8]) = match last_slash {
        None => (FixedPath::from_bytes(b"."), bytes),
        Some(0) => (FixedPath::from_bytes(b"/"), &bytes[1..]),
        Some(i) => (FixedPath::from_bytes(&bytes[..i]), &bytes[i + 1..]),
    };
    if leaf.is_empty() || leaf == b"." || leaf == b".." {
        return translate_path2(tracee, dir_fd, path, reg, PType::Symlink);
    }
    let mut translated_parent = PathGuard::new();
    if let Err(e) = crate::path::translate_path(
        tracee,
        &mut translated_parent,
        dir_fd,
        parent.as_bytes(),
        true,
    ) {
        return e;
    }
    let mut translated_path = PathGuard::new();
    if join_paths2(&mut translated_path, translated_parent.as_bytes(), leaf).is_err() {
        return -libc::ENAMETOOLONG;
    }
    set_sysarg_path(tracee, translated_path.as_bytes(), reg)
}

/// `translate_sysarg()` — translate the path argument `reg`.
fn translate_sysarg(tracee: &mut Tracee, reg: Reg, ty: PType) -> i32 {
    let mut path = PathGuard::new();
    let status = get_sysarg_path(tracee, &mut path, reg);
    if status < 0 {
        return status;
    }
    translate_path2(tracee, libc::AT_FDCWD, &path, reg, ty)
}

/// `guest_canonicalize()` — canonicalize `user_path` as a guest path (for
/// use as a binding key), stripping trailing "/" or "/.".
fn guest_canonicalize(
    tracee: &mut Tracee,
    user_path: &[u8],
    guest_path: &mut FixedPath,
) -> Result<(), i32> {
    if user_path.first() == Some(&b'/') {
        guest_path.set(b"/");
    } else {
        crate::path::getcwd2(Some(tracee), guest_path)?;
    }
    crate::path::canon::canonicalize(tracee, user_path, true, guest_path, 0)?;
    guest_path.chop_finality();
    Ok(())
}

/// `emulate_mount()` — turn mount(2) into a PRoot binding.
fn emulate_mount(
    tracee: &mut Tracee,
    src_user: &[u8],
    target_user: &[u8],
    fstype: &[u8],
    flags: Word,
) {
    if (flags & libc::MS_REMOUNT as Word) != 0 {
        return;
    }

    let mut host_path = PathGuard::new();
    if (flags & libc::MS_BIND as Word) != 0 {
        if crate::path::translate_path(tracee, &mut host_path, libc::AT_FDCWD, src_user, true)
            .is_err()
        {
            return;
        }
    } else if fstype == b"proc" {
        host_path.set(b"/proc");
    } else if fstype == b"sysfs" {
        host_path.set(b"/sys");
    } else if fstype == b"devtmpfs" {
        host_path.set(b"/dev");
    } else if fstype == b"devpts" {
        host_path.set(b"/dev/pts");
    } else if fstype == b"tmpfs" {
        match crate::path::temp::create_temp_directory(None, "proot-tmpfs-") {
            Some(d) => host_path.set(d.as_bytes()),
            None => return,
        }
    } else {
        return;
    }
    host_path.chop_finality();

    let mut guest_path = PathGuard::new();
    if guest_canonicalize(tracee, target_user, &mut guest_path).is_err() {
        return;
    }

    let _ = binding::insort_binding3(tracee, host_path.as_bytes(), guest_path.as_bytes());
}

/// `emulate_pivot_root()` — move the root binding to `new_root` and
/// re-expose the old root under `put_old`.
fn emulate_pivot_root(tracee: &mut Tracee, new_root_user: &[u8], put_old_user: &[u8]) {
    let mut new_root_host = PathGuard::new();
    if crate::path::translate_path(
        tracee,
        &mut new_root_host,
        libc::AT_FDCWD,
        new_root_user,
        true,
    )
    .is_err()
    {
        return;
    }
    new_root_host.chop_finality();

    let mut new_root_guest = PathGuard::new();
    if guest_canonicalize(tracee, new_root_user, &mut new_root_guest).is_err() {
        return;
    }

    // put_old resolves against new_root (it's inside the new root).
    let mut put_old_guest = PathGuard::new();
    if put_old_user.first() == Some(&b'/') {
        put_old_guest.set(b"/");
    } else {
        put_old_guest.set(new_root_guest.as_bytes());
    }
    if crate::path::canon::canonicalize(tracee, put_old_user, true, &mut put_old_guest, 0).is_err()
    {
        return;
    }

    let root_binding = match binding::get_binding(tracee, Side::Guest, b"/") {
        Some(b) => b,
        None => return,
    };
    let old_root_host = root_binding.host.clone();

    let new_root_len = new_root_guest.len();

    // Where the previous root becomes reachable, e.g. "/oldroot".
    let mut put_old_after = PathGuard::new();
    let mut have_put_old = false;
    if new_root_len > 0
        && put_old_guest
            .as_bytes()
            .starts_with(new_root_guest.as_bytes())
        && (put_old_guest.as_bytes().get(new_root_len) == Some(&b'/')
            || (new_root_len == 1 && new_root_guest.as_bytes() == b"/"))
    {
        let after = &put_old_guest.as_bytes()[if new_root_len == 1 { 0 } else { new_root_len }..];
        if after.first() == Some(&b'/') && after.len() > 1 {
            put_old_after.set(after);
            have_put_old = true;
        }
    }
    let put_old_len = put_old_after.len();

    // Snapshot the guest-ordered bindings: the loop below mutates the lists.
    let snapshot: Vec<std::rc::Rc<binding::Binding>> = tracee.fs.borrow().guest.clone();

    // Switch the root; re-expose the previous root at put_old.
    binding::remove_binding_from_all_lists(tracee, &root_binding);
    let _ = binding::insort_binding3(tracee, new_root_host.as_bytes(), b"/");
    if have_put_old {
        let _ =
            binding::insort_binding3(tracee, old_root_host.as_bytes(), put_old_after.as_bytes());
    }

    for b in &snapshot {
        if std::rc::Rc::ptr_eq(b, &root_binding) || b.guest.as_bytes() == b"/" {
            continue;
        }
        let bguest = b.guest.as_bytes();
        let blen = bguest.len();

        // Bindings under the new root move with the pivot:
        // "/newroot/usr" becomes "/usr".
        if new_root_len > 0
            && blen > new_root_len
            && bguest.starts_with(new_root_guest.as_bytes())
            && bguest[new_root_len] == b'/'
        {
            let _ = binding::insort_binding3(tracee, b.host.as_bytes(), &bguest[new_root_len..]);
            binding::remove_binding_from_all_lists(tracee, b);
            continue;
        }

        // Others belonged to the previous root: re-expose under put_old.
        if have_put_old {
            if bguest.starts_with(put_old_after.as_bytes())
                && (bguest.get(put_old_len).is_none() || bguest.get(put_old_len) == Some(&b'/'))
            {
                continue;
            }
            let mut aliased = PathGuard::new();
            if join_paths2(&mut aliased, put_old_after.as_bytes(), bguest).is_err() {
                continue;
            }
            let _ = binding::insort_binding3(tracee, b.host.as_bytes(), aliased.as_bytes());
        }
    }
}

/// `emulate_umount()` — drop the binding matching `target_user` exactly
/// (never the root binding).
fn emulate_umount(tracee: &mut Tracee, target_user: &[u8]) {
    let mut guest_path = PathGuard::new();
    if guest_canonicalize(tracee, target_user, &mut guest_path).is_err() {
        return;
    }
    if guest_path.as_bytes() == b"/" {
        return;
    }
    let binding_rc = match binding::get_binding(tracee, Side::Guest, guest_path.as_bytes()) {
        Some(b) => b,
        None => return,
    };
    if compare_paths(binding_rc.guest.as_bytes(), guest_path.as_bytes())
        != Comparison::PathsAreEqual
    {
        return;
    }
    binding::remove_binding_from_all_lists(tracee, &binding_rc);
}

/// `apply_emulated_umount()`.
pub fn apply_emulated_umount(tracee: &mut Tracee) {
    let mut target = PathGuard::new();
    if get_sysarg_path(tracee, &mut target, Reg::Sysarg1) < 0 {
        return;
    }
    emulate_umount(tracee, target.as_bytes());
}

/// `apply_emulated_mount()` — usable both from the normal sysenter path and
/// the SIGSYS handler (outer seccomp may trap mount before its sysenter).
pub fn apply_emulated_mount(tracee: &mut Tracee) {
    let mut src = PathGuard::new();
    let mut target = PathGuard::new();
    if get_sysarg_path(tracee, &mut src, Reg::Sysarg1) < 0 {
        return;
    }
    if get_sysarg_path(tracee, &mut target, Reg::Sysarg2) < 0 {
        return;
    }
    let mut fstype = [0u8; 256];
    let fstype_addr = peek_reg(tracee, RegVersion::Current, Reg::Sysarg3);
    if fstype_addr != 0 {
        let _ = read_string(tracee, &mut fstype[..255], fstype_addr);
        fstype[255] = 0;
    }
    let fstype_len = fstype.iter().position(|&b| b == 0).unwrap_or(255);
    let flags = peek_reg(tracee, RegVersion::Current, Reg::Sysarg4);
    emulate_mount(
        tracee,
        src.as_bytes(),
        target.as_bytes(),
        &fstype[..fstype_len],
        flags,
    );
}

/// `apply_emulated_pivot_root()`.
pub fn apply_emulated_pivot_root(tracee: &mut Tracee) {
    let mut new_root = PathGuard::new();
    let mut put_old = PathGuard::new();
    if get_sysarg_path(tracee, &mut new_root, Reg::Sysarg1) < 0 {
        return;
    }
    if get_sysarg_path(tracee, &mut put_old, Reg::Sysarg2) < 0 {
        return;
    }
    emulate_pivot_root(tracee, new_root.as_bytes(), put_old.as_bytes());
}

// ==================================================================
// /proc/<pid>/{uid_map,gid_map,setgroups} redirect
// ==================================================================

/// `is_proc_userns_file()`.
fn is_proc_userns_file(path: &[u8]) -> bool {
    let p = match path.strip_prefix(b"/proc/") {
        Some(p) => p,
        None => return false,
    };
    let p = if p.starts_with(b"self/") {
        &p[5..]
    } else {
        let digits = p.iter().take_while(|c| c.is_ascii_digit()).count();
        if digits == 0 || p.get(digits) != Some(&b'/') {
            return false;
        }
        &p[digits + 1..]
    };
    p == b"uid_map" || p == b"gid_map" || p == b"setgroups"
}

/// `maybe_redirect_userns_file()` — writes to the userns setup files are
/// silently redirected to /dev/null (the tracee can't really create them).
fn maybe_redirect_userns_file(tracee: &mut Tracee, reg: Reg) {
    let mut host_path = PathGuard::new();
    if get_sysarg_path(tracee, &mut host_path, reg) < 0 {
        return;
    }
    if !is_proc_userns_file(host_path.as_bytes()) {
        return;
    }
    let _ = set_sysarg_path(tracee, b"/dev/null", reg);
}

// ==================================================================
// The dispatch
// ==================================================================

/// `translate_syscall_enter()`.
pub fn translate_syscall_enter(tracee: &mut Tracee) -> i32 {
    let mut path = PathGuard::new();
    let mut oldpath = PathGuard::new();
    let mut newpath = PathGuard::new();
    let mut special = false;

    let mut status = crate::extension::notify(tracee, &mut crate::extension::Event::SysEnterStart);
    if status < 0 {
        return end(tracee, status);
    }
    if status > 0 {
        return 0;
    }

    status = 0;
    let syscall_number = get_sysnum(tracee, RegVersion::Original);

    macro_rules! path_arg {
        // translate_sysarg(tracee, SYSARG_n, TYPE)
        ($reg:expr_2021, $ty:expr_2021) => {{
            status = translate_sysarg(tracee, $reg, $ty);
        }};
    }

    match syscall_number {
        Sysnum::execve => {
            status = crate::execve::translate_execve_enter(tracee);
        }
        Sysnum::execveat => {
            if peek_reg(tracee, RegVersion::Current, Reg::Sysarg1) as i32 == libc::AT_FDCWD {
                set_sysnum(tracee, Sysnum::execve);
                let a2 = peek_reg(tracee, RegVersion::Current, Reg::Sysarg2);
                let a3 = peek_reg(tracee, RegVersion::Current, Reg::Sysarg3);
                let a4 = peek_reg(tracee, RegVersion::Current, Reg::Sysarg4);
                poke_reg(tracee, Reg::Sysarg1, a2);
                poke_reg(tracee, Reg::Sysarg2, a3);
                poke_reg(tracee, Reg::Sysarg3, a4);
                status = crate::execve::translate_execve_enter(tracee);
            } else {
                crate::note!(
                    crate::note::Severity::Error,
                    crate::note::Origin::System,
                    "execveat() with non-AT_FDCWD fd is not currently supported"
                );
                status = -libc::ENOSYS;
            }
        }
        Sysnum::ptrace => {
            status = crate::ptrace::translate_ptrace_enter(tracee);
        }
        Sysnum::wait4 | Sysnum::waitpid => {
            status = crate::ptrace::wait::translate_wait_enter(tracee);
        }
        Sysnum::brk => {
            crate::syscall::heap::translate_brk_enter(tracee);
            status = 0;
        }
        Sysnum::getcwd => {
            poke_reg(tracee, Reg::SysargResult, 0);
            set_sysnum(tracee, Sysnum::Void);
            status = 0;
        }
        Sysnum::fchdir | Sysnum::chdir => {
            let dirfd;
            if syscall_number == Sysnum::chdir {
                status = get_sysarg_path(tracee, &mut path, Reg::Sysarg1);
                if status >= 0 {
                    match join_paths2(&mut oldpath, path.as_bytes(), b".") {
                        Ok(()) => dirfd = libc::AT_FDCWD,
                        Err(e) => {
                            status = e;
                            dirfd = 0;
                        }
                    }
                } else {
                    dirfd = 0;
                }
            } else {
                oldpath.set(b".");
                dirfd = peek_reg(tracee, RegVersion::Current, Reg::Sysarg1) as i32;
            }

            if status >= 0 {
                if let Err(e) =
                    crate::path::translate_path(tracee, &mut path, dirfd, oldpath.as_bytes(), true)
                {
                    status = e;
                } else {
                    match crate::sys::lstat(path.as_c_str()) {
                        Err(e) => status = -e,
                        Ok(st) if (st.st_mode & libc::S_IXUSR) == 0 => return -libc::EACCES,
                        Ok(_) => match crate::path::detranslate_path(tracee, &mut path, None) {
                            Err(e) => status = e,
                            Ok(_) => {
                                path.chop_finality();
                                tracee.fs.borrow_mut().cwd.set(path.as_bytes());
                                poke_reg(tracee, Reg::SysargResult, 0);
                                set_sysnum(tracee, Sysnum::Void);
                                status = 0;
                            }
                        },
                    }
                }
            }
        }
        Sysnum::bind | Sysnum::connect => {
            // AF_NETLINK substitution: bind() on a fake netlink fd is faked.
            if syscall_number == Sysnum::bind
                && netlink::is_fake_netlink_fd(
                    tracee,
                    peek_reg(tracee, RegVersion::Current, Reg::Sysarg1) as i32,
                )
            {
                poke_reg(tracee, Reg::SysargResult, 0);
                set_sysnum(tracee, Sysnum::Void);
                status = 0;
            } else {
                let mut address = peek_reg(tracee, RegVersion::Current, Reg::Sysarg2);
                let size = peek_reg(tracee, RegVersion::Current, Reg::Sysarg3);
                status =
                    crate::syscall::socket::translate_socketcall_enter(tracee, &mut address, size);
                if status > 0 {
                    poke_reg(tracee, Reg::Sysarg2, address);
                    poke_reg(tracee, Reg::Sysarg3, size_of::<libc::sockaddr_un>() as Word);
                    status = 0;
                }
            }
        }
        Sysnum::accept | Sysnum::accept4 => {
            if peek_reg(tracee, RegVersion::Original, Reg::Sysarg2) == 0 {
                status = 0;
            } else {
                special = true;
                status = sockname_size_capture(tracee, special);
            }
        }
        Sysnum::getsockname | Sysnum::getpeername => {
            if netlink::is_fake_netlink_fd(
                tracee,
                peek_reg(tracee, RegVersion::Current, Reg::Sysarg1) as i32,
            ) {
                let addr_ptr = peek_reg(tracee, RegVersion::Current, Reg::Sysarg2);
                let size_ptr = peek_reg(tracee, RegVersion::Current, Reg::Sysarg3);
                let rc = netlink::write_fake_netlink_sockname(
                    tracee,
                    addr_ptr,
                    size_ptr,
                    tracee.pid as u32,
                );
                poke_reg(tracee, Reg::SysargResult, rc as Word);
                set_sysnum(tracee, Sysnum::Void);
                status = 0;
            } else {
                status = sockname_size_capture(tracee, special);
            }
        }
        Sysnum::socket => {
            let domain = peek_reg(tracee, RegVersion::Current, Reg::Sysarg1);
            let protocol = peek_reg(tracee, RegVersion::Current, Reg::Sysarg3);
            if domain == libc::AF_NETLINK as Word && protocol == 0
            // NETLINK_ROUTE
            {
                if netlink::host_blocks_af_netlink(tracee) {
                    let ty = peek_reg(tracee, RegVersion::Current, Reg::Sysarg2);
                    poke_reg(tracee, Reg::Sysarg1, libc::AF_UNIX as Word);
                    poke_reg(
                        tracee,
                        Reg::Sysarg2,
                        (libc::SOCK_DGRAM | (ty as i32 & libc::SOCK_CLOEXEC)) as Word,
                    );
                    poke_reg(tracee, Reg::Sysarg3, 0);
                    tracee.pending_fake_netlink_socket = true;
                } else {
                    tracee.pending_real_netlink_socket = true;
                }
                tracee.sysexit_pending = true;
                tracee.restart_how = crate::ptrace::ptc::PTRACE_SYSCALL;
            }
            status = 0;
        }
        Sysnum::sendto => {
            let fd = peek_reg(tracee, RegVersion::Current, Reg::Sysarg1) as i32;
            let buf = peek_reg(tracee, RegVersion::Current, Reg::Sysarg2);
            let len = peek_reg(tracee, RegVersion::Current, Reg::Sysarg3);
            match netlink::fake_netlink_idx(tracee, fd) {
                Some(idx) => {
                    netlink::build_fake_netlink_reply(tracee, idx, buf, len);
                    poke_reg(tracee, Reg::SysargResult, len);
                    set_sysnum(tracee, Sysnum::Void);
                }
                None => netlink::note_netns_netlink_request(tracee, fd, buf, len),
            }
            status = 0;
        }
        Sysnum::sendmsg => {
            let fd = peek_reg(tracee, RegVersion::Current, Reg::Sysarg1) as i32;
            let msghdr_addr = peek_reg(tracee, RegVersion::Current, Reg::Sysarg2);
            match netlink::fake_netlink_idx(tracee, fd) {
                Some(idx) => {
                    let mut total = 0;
                    if let Some((base, len)) = netlink::msghdr_first_iovec(tracee, msghdr_addr) {
                        netlink::build_fake_netlink_reply(tracee, idx, base, len);
                        total = len;
                    }
                    poke_reg(tracee, Reg::SysargResult, total);
                    set_sysnum(tracee, Sysnum::Void);
                }
                None => {
                    if netlink::is_netns_netlink_fd(tracee, fd) {
                        if let Some((base, len)) = netlink::msghdr_first_iovec(tracee, msghdr_addr)
                        {
                            netlink::note_netns_netlink_request(tracee, fd, base, len);
                        }
                    }
                }
            }
            status = 0;
        }
        Sysnum::recvfrom => {
            let fd = peek_reg(tracee, RegVersion::Current, Reg::Sysarg1) as i32;
            match netlink::fake_netlink_idx(tracee, fd) {
                Some(idx) => {
                    let buf = peek_reg(tracee, RegVersion::Current, Reg::Sysarg2);
                    let len = peek_reg(tracee, RegVersion::Current, Reg::Sysarg3);
                    let flags = peek_reg(tracee, RegVersion::Current, Reg::Sysarg4) as i32;
                    let addr_ptr = peek_reg(tracee, RegVersion::Current, Reg::Sysarg5);
                    let size_ptr = peek_reg(tracee, RegVersion::Current, Reg::Sysarg6);

                    // Copy reply slice out before borrowing mutably.
                    let (datagram, reply): (usize, Vec<u8>) = {
                        match netlink::pending_fake_netlink_datagram(&tracee.fake_netlink_fds[idx])
                        {
                            Some((r, l)) => (l, r[..l].to_vec()),
                            None => (0, Vec::new()),
                        }
                    };
                    if datagram != 0 {
                        let mut copied = 0usize;
                        if buf != 0 {
                            copied = (len as usize).min(datagram);
                            if copied > 0 && write_data(tracee, buf, &reply[..copied]) < 0 {
                                copied = 0;
                            }
                        }
                        if (flags & libc::MSG_PEEK) == 0 {
                            netlink::consume_fake_netlink_datagram(
                                &mut tracee.fake_netlink_fds[idx],
                                datagram,
                            );
                        }
                        let result = if (flags & libc::MSG_TRUNC) != 0 {
                            datagram
                        } else {
                            copied
                        };
                        if addr_ptr != 0 && size_ptr != 0 {
                            let _ =
                                netlink::write_fake_netlink_sockname(tracee, addr_ptr, size_ptr, 0);
                        }
                        crate::sys::clear_errno();
                        poke_reg(tracee, Reg::SysargResult, result as Word);
                        set_sysnum(tracee, Sysnum::Void);
                    }
                }
                None => netlink::note_netns_netlink_reply(tracee, fd),
            }
            status = 0;
        }
        Sysnum::recvmsg => {
            let fd = peek_reg(tracee, RegVersion::Current, Reg::Sysarg1) as i32;
            match netlink::fake_netlink_idx(tracee, fd) {
                Some(idx) => {
                    let msghdr_addr = peek_reg(tracee, RegVersion::Current, Reg::Sysarg2);
                    let flags = peek_reg(tracee, RegVersion::Current, Reg::Sysarg3) as i32;
                    let w = crate::tracee::reg::sizeof_word(tracee) as Word;

                    let (datagram, reply): (usize, Vec<u8>) = {
                        match netlink::pending_fake_netlink_datagram(&tracee.fake_netlink_fds[idx])
                        {
                            Some((r, l)) => (l, r[..l].to_vec()),
                            None => (0, Vec::new()),
                        }
                    };
                    if datagram != 0 {
                        let (mut msg_name, mut iov_ptr, mut iov_count) = (0, 0, 0);
                        if msghdr_addr != 0 {
                            crate::sys::clear_errno();
                            msg_name = peek_word(tracee, msghdr_addr);
                            if crate::sys::errno() != 0 {
                                crate::sys::clear_errno();
                                msg_name = 0;
                            }
                            iov_ptr = peek_word(tracee, msghdr_addr + 2 * w);
                            if crate::sys::errno() != 0 {
                                crate::sys::clear_errno();
                                iov_ptr = 0;
                            }
                            iov_count = peek_word(tracee, msghdr_addr + 3 * w);
                            if crate::sys::errno() != 0 {
                                crate::sys::clear_errno();
                                iov_count = 0;
                            }
                        }

                        let mut scattered = 0usize;
                        if iov_ptr != 0 && iov_count > 0 {
                            scattered = netlink::scatter_fake_netlink_reply(
                                tracee, iov_ptr, iov_count, &reply,
                            );
                        }
                        if (flags & libc::MSG_PEEK) == 0 {
                            netlink::consume_fake_netlink_datagram(
                                &mut tracee.fake_netlink_fds[idx],
                                datagram,
                            );
                        }
                        let result = if (flags & libc::MSG_TRUNC) != 0 {
                            datagram
                        } else {
                            scattered
                        };

                        // sockaddr_nl (nl_pid == 0) source for getifaddrs.
                        if msg_name != 0 && msghdr_addr != 0 {
                            crate::sys::clear_errno();
                            let in_namelen =
                                crate::tracee::mem::peek_uint32(tracee, msghdr_addr + w);
                            if crate::sys::errno() == 0 && in_namelen > 0 {
                                let mut snl = [0u8; 12];
                                snl[0..2].copy_from_slice(&(libc::AF_NETLINK as u16).to_ne_bytes());
                                let copy = (in_namelen as usize).min(snl.len());
                                let _ = write_data(tracee, msg_name, &snl[..copy]);
                                crate::tracee::mem::poke_uint32(
                                    tracee,
                                    msghdr_addr + w,
                                    snl.len() as u32,
                                );
                            }
                            crate::sys::clear_errno();
                        }

                        // msg_flags (word 6): MSG_TRUNC iff truncated.
                        if msghdr_addr != 0 {
                            crate::tracee::mem::poke_uint32(
                                tracee,
                                msghdr_addr + 6 * w,
                                if scattered < datagram {
                                    libc::MSG_TRUNC as u32
                                } else {
                                    0
                                },
                            );
                            crate::sys::clear_errno();
                        }

                        poke_reg(tracee, Reg::SysargResult, result as Word);
                        set_sysnum(tracee, Sysnum::Void);
                    }
                }
                None => netlink::note_netns_netlink_reply(tracee, fd),
            }
            status = 0;
        }
        Sysnum::socketcall => {
            status = socketcall_enter(tracee, special);
        }

        Sysnum::access
        | Sysnum::acct
        | Sysnum::chmod
        | Sysnum::chown
        | Sysnum::chown32
        | Sysnum::chroot
        | Sysnum::getxattr
        | Sysnum::listxattr
        | Sysnum::mknod
        | Sysnum::oldstat
        | Sysnum::creat
        | Sysnum::removexattr
        | Sysnum::setxattr
        | Sysnum::stat
        | Sysnum::stat64
        | Sysnum::statfs
        | Sysnum::statfs64
        | Sysnum::swapoff
        | Sysnum::swapon
        | Sysnum::truncate
        | Sysnum::truncate64
        | Sysnum::uselib
        | Sysnum::utime
        | Sysnum::utimes => {
            path_arg!(Reg::Sysarg1, PType::Regular);
        }

        Sysnum::unshare => {
            if (peek_reg(tracee, RegVersion::Current, Reg::Sysarg1) & libc::CLONE_NEWNET as Word)
                != 0
            {
                tracee.fake_netns = true;
            }
            poke_reg(tracee, Reg::SysargResult, 0);
            set_sysnum(tracee, Sysnum::Void);
            status = 0;
        }
        Sysnum::setns => {
            poke_reg(tracee, Reg::SysargResult, 0);
            set_sysnum(tracee, Sysnum::Void);
            status = 0;
        }
        Sysnum::umount | Sysnum::umount2 => {
            apply_emulated_umount(tracee);
            poke_reg(tracee, Reg::SysargResult, 0);
            set_sysnum(tracee, Sysnum::Void);
            status = 0;
        }
        Sysnum::clone => {
            let flags = peek_reg(tracee, RegVersion::Current, Reg::Sysarg1);
            if (flags & CLONE_NS_MASK) != 0 {
                if (flags & libc::CLONE_NEWNS as Word) != 0 {
                    tracee.clone_stripped_newns = true;
                }
                if (flags & libc::CLONE_NEWNET as Word) != 0 {
                    tracee.clone_stripped_newnet = true;
                }
                poke_reg(tracee, Reg::Sysarg1, flags & !CLONE_NS_MASK);
            }
            force_fork_sysexit(tracee);
            status = 0;
        }
        Sysnum::clone3 => {
            let args_addr = peek_reg(tracee, RegVersion::Current, Reg::Sysarg1);
            if args_addr != 0 {
                crate::sys::clear_errno();
                let flags = peek_word(tracee, args_addr);
                if crate::sys::errno() == 0 && (flags & CLONE_NS_MASK) != 0 {
                    if (flags & libc::CLONE_NEWNS as Word) != 0 {
                        tracee.clone_stripped_newns = true;
                    }
                    if (flags & libc::CLONE_NEWNET as Word) != 0 {
                        tracee.clone_stripped_newnet = true;
                    }
                    poke_word(tracee, args_addr, flags & !CLONE_NS_MASK);
                }
            }
            force_fork_sysexit(tracee);
            status = 0;
        }
        Sysnum::fork | Sysnum::vfork => {
            force_fork_sysexit(tracee);
            status = 0;
        }
        Sysnum::mount => {
            apply_emulated_mount(tracee);
            poke_reg(tracee, Reg::SysargResult, 0);
            set_sysnum(tracee, Sysnum::Void);
            status = 0;
        }
        Sysnum::pivot_root => {
            apply_emulated_pivot_root(tracee);
            poke_reg(tracee, Reg::SysargResult, 0);
            set_sysnum(tracee, Sysnum::Void);
            status = 0;
        }
        Sysnum::open => {
            let flags = peek_reg(tracee, RegVersion::Current, Reg::Sysarg2);
            if tracee.execfn_addr != 0 {
                let mut p = PathGuard::new();
                let n = read_string(
                    tracee,
                    p.as_mut_bytes(),
                    peek_reg(tracee, RegVersion::Current, Reg::Sysarg1),
                );
                if n > 0 {
                    p.sync_len_from_nul();
                }
                if n > 0 && p.as_bytes() == b"/proc/self/auxv" {
                    tracee.sysexit_pending = true;
                    tracee.restart_how = crate::ptrace::ptc::PTRACE_SYSCALL;
                }
            }
            if (flags & libc::O_NOFOLLOW as Word) != 0
                || ((flags & libc::O_EXCL as Word) != 0 && (flags & libc::O_CREAT as Word) != 0)
            {
                status = translate_sysarg(tracee, Reg::Sysarg1, PType::Symlink);
            } else {
                status = translate_sysarg(tracee, Reg::Sysarg1, PType::Regular);
            }
            if status >= 0 {
                maybe_redirect_userns_file(tracee, Reg::Sysarg1);
            }
        }
        Sysnum::fchownat
        | Sysnum::fstatat64
        | Sysnum::newfstatat
        | Sysnum::utimensat
        | Sysnum::name_to_handle_at => {
            let dirfd = peek_reg(tracee, RegVersion::Current, Reg::Sysarg1) as i32;
            status = get_sysarg_path(tracee, &mut path, Reg::Sysarg2);
            if status >= 0 {
                let flags = if syscall_number == Sysnum::fchownat
                    || syscall_number == Sysnum::name_to_handle_at
                {
                    peek_reg(tracee, RegVersion::Current, Reg::Sysarg5)
                } else {
                    peek_reg(tracee, RegVersion::Current, Reg::Sysarg4)
                };
                let ty = if (flags & libc::AT_SYMLINK_NOFOLLOW as Word) != 0 {
                    PType::Symlink
                } else {
                    PType::Regular
                };
                status = translate_path2(tracee, dirfd, &path, Reg::Sysarg2, ty);
            }
        }
        Sysnum::fchmodat
        | Sysnum::faccessat
        | Sysnum::faccessat2
        | Sysnum::futimesat
        | Sysnum::mknodat => {
            let dirfd = peek_reg(tracee, RegVersion::Current, Reg::Sysarg1) as i32;
            status = get_sysarg_path(tracee, &mut path, Reg::Sysarg2);
            if status >= 0 {
                status = translate_path2(tracee, dirfd, &path, Reg::Sysarg2, PType::Regular);
            }
        }
        Sysnum::inotify_add_watch => {
            let flags = peek_reg(tracee, RegVersion::Current, Reg::Sysarg3);
            let ty = if (flags & libc::IN_DONT_FOLLOW as Word) != 0 {
                PType::Symlink
            } else {
                PType::Regular
            };
            status = translate_sysarg(tracee, Reg::Sysarg2, ty);
        }
        Sysnum::readlink
        | Sysnum::lchown
        | Sysnum::lchown32
        | Sysnum::lgetxattr
        | Sysnum::llistxattr
        | Sysnum::lremovexattr
        | Sysnum::lsetxattr
        | Sysnum::lstat
        | Sysnum::lstat64
        | Sysnum::oldlstat
        | Sysnum::unlink
        | Sysnum::rmdir => {
            status = translate_sysarg(tracee, Reg::Sysarg1, PType::Symlink);
        }
        Sysnum::mkdir => {
            // Created destination: translate the parent only.
            status = get_sysarg_path(tracee, &mut path, Reg::Sysarg1);
            if status >= 0 {
                status = translate_path2_parent(tracee, libc::AT_FDCWD, &path, Reg::Sysarg1);
            }
        }
        Sysnum::linkat => {
            let olddirfd = peek_reg(tracee, RegVersion::Current, Reg::Sysarg1) as i32;
            let newdirfd = peek_reg(tracee, RegVersion::Current, Reg::Sysarg3) as i32;
            let flags = peek_reg(tracee, RegVersion::Current, Reg::Sysarg5);

            status = get_sysarg_path(tracee, &mut oldpath, Reg::Sysarg2);
            if status >= 0 {
                status = get_sysarg_path(tracee, &mut newpath, Reg::Sysarg4);
            }
            if status >= 0 {
                let ty = if (flags & libc::AT_SYMLINK_FOLLOW as Word) != 0 {
                    PType::Regular
                } else {
                    PType::Symlink
                };
                status = translate_path2(tracee, olddirfd, &oldpath, Reg::Sysarg2, ty);
            }
            if status >= 0 {
                status = translate_path2_parent(tracee, newdirfd, &newpath, Reg::Sysarg4);
            }
        }
        Sysnum::openat2 => {
            // int openat2(dirfd, path, struct open_how *how, size_t size):
            // rewrite as openat() moving how.flags/how.mode into arg3/arg4.
            let mut how = [0u8; 24];
            let mut how_size = peek_reg(tracee, RegVersion::Current, Reg::Sysarg4) as usize;
            if how_size > how.len() {
                how_size = how.len();
            }
            status = read_data(
                tracee,
                &mut how[..how_size],
                peek_reg(tracee, RegVersion::Current, Reg::Sysarg3),
            );
            if status >= 0 {
                let hflags = u64::from_ne_bytes(how[0..8].try_into().unwrap());
                let hmode = u64::from_ne_bytes(how[8..16].try_into().unwrap());
                set_sysnum(tracee, Sysnum::openat);
                poke_reg(tracee, Reg::Sysarg3, hflags);
                poke_reg(tracee, Reg::Sysarg4, hmode);
                status = openat_enter(tracee, &mut path);
            }
        }
        Sysnum::openat => {
            status = openat_enter(tracee, &mut path);
        }
        Sysnum::readlinkat | Sysnum::unlinkat => {
            let dirfd = peek_reg(tracee, RegVersion::Current, Reg::Sysarg1) as i32;
            status = get_sysarg_path(tracee, &mut path, Reg::Sysarg2);
            if status >= 0 {
                status = translate_path2(tracee, dirfd, &path, Reg::Sysarg2, PType::Symlink);
            }
        }
        Sysnum::mkdirat => {
            let dirfd = peek_reg(tracee, RegVersion::Current, Reg::Sysarg1) as i32;
            status = get_sysarg_path(tracee, &mut path, Reg::Sysarg2);
            if status >= 0 {
                status = translate_path2_parent(tracee, dirfd, &path, Reg::Sysarg2);
            }
        }
        Sysnum::link | Sysnum::rename => {
            status = translate_sysarg(tracee, Reg::Sysarg1, PType::Symlink);
            if status >= 0 {
                if syscall_number == Sysnum::link {
                    status = get_sysarg_path(tracee, &mut path, Reg::Sysarg2);
                    if status >= 0 {
                        status =
                            translate_path2_parent(tracee, libc::AT_FDCWD, &path, Reg::Sysarg2);
                    }
                } else {
                    status = translate_sysarg(tracee, Reg::Sysarg2, PType::Symlink);
                }
            }
        }
        Sysnum::renameat | Sysnum::renameat2 => {
            let olddirfd = peek_reg(tracee, RegVersion::Current, Reg::Sysarg1) as i32;
            let newdirfd = peek_reg(tracee, RegVersion::Current, Reg::Sysarg3) as i32;
            status = get_sysarg_path(tracee, &mut oldpath, Reg::Sysarg2);
            if status >= 0 {
                status = get_sysarg_path(tracee, &mut newpath, Reg::Sysarg4);
            }
            if status >= 0 {
                status = translate_path2(tracee, olddirfd, &oldpath, Reg::Sysarg2, PType::Symlink);
            }
            if status >= 0 {
                status = translate_path2(tracee, newdirfd, &newpath, Reg::Sysarg4, PType::Symlink);
            }
        }
        Sysnum::symlink => {
            // SYSARG_1 is the link's *contents*, not a path.
            status = get_sysarg_path(tracee, &mut newpath, Reg::Sysarg2);
            if status >= 0 {
                status = translate_path2_parent(tracee, libc::AT_FDCWD, &newpath, Reg::Sysarg2);
            }
        }
        Sysnum::symlinkat => {
            let newdirfd = peek_reg(tracee, RegVersion::Current, Reg::Sysarg2) as i32;
            status = get_sysarg_path(tracee, &mut newpath, Reg::Sysarg3);
            if status >= 0 {
                status = translate_path2_parent(tracee, newdirfd, &newpath, Reg::Sysarg3);
            }
        }
        Sysnum::statx => {
            let dirfd = peek_reg(tracee, RegVersion::Current, Reg::Sysarg1) as i32;
            status = get_sysarg_path(tracee, &mut newpath, Reg::Sysarg2);
            if status >= 0 {
                let ty = if (peek_reg(tracee, RegVersion::Current, Reg::Sysarg3)
                    & libc::AT_SYMLINK_NOFOLLOW as Word)
                    != 0
                {
                    PType::Symlink
                } else {
                    PType::Regular
                };
                status = translate_path2(tracee, dirfd, &newpath, Reg::Sysarg2, ty);
            }
        }
        Sysnum::prctl => {
            let arg1 = peek_reg(tracee, RegVersion::Current, Reg::Sysarg1);
            if arg1 == PR_SET_DUMPABLE {
                // Prevent tracees from clearing dumpable: it would break
                // process_vm_* access.
                poke_reg(tracee, Reg::SysargResult, 0);
                set_sysnum(tracee, Sysnum::Void);
                status = 0;
            }
            if arg1 == PR_SET_SECCOMP
                && peek_reg(tracee, RegVersion::Current, Reg::Sysarg2) == SECCOMP_MODE_FILTER
                && !crate::tracee::event::seccomp_ptrace_event_is_supported()
            {
                crate::verbose!(
                    Some(tracee),
                    1,
                    "blocking tracee prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER): kernel lacks PTRACE_EVENT_SECCOMP support"
                );
                poke_reg(tracee, Reg::SysargResult, (-libc::EPERM) as Word);
                set_sysnum(tracee, Sysnum::Void);
                status = 0;
            }
            if arg1 == PR_GET_AUXV {
                // Sysexit patches AT_EXECFN in the returned buffer.
                tracee.sysexit_pending = true;
                tracee.restart_how = crate::ptrace::ptc::PTRACE_SYSCALL;
            }
            if arg1 == PR_GET_NO_NEW_PRIVS {
                // PRoot sets no_new_privs itself before execve; report the
                // guest's own intent instead.
                poke_reg(
                    tracee,
                    Reg::SysargResult,
                    if tracee.no_new_privs { 1 } else { 0 },
                );
                set_sysnum(tracee, Sysnum::Void);
                status = 0;
            }
            if arg1 == PR_SET_NO_NEW_PRIVS {
                // Observe the tracee's own PR_SET_NO_NEW_PRIVS at sysexit.
                tracee.sysexit_pending = true;
                tracee.restart_how = crate::ptrace::ptc::PTRACE_SYSCALL;
            }
        }
        Sysnum::ioctl => {
            let cmd = peek_reg(tracee, RegVersion::Current, Reg::Sysarg2);
            let arg = peek_reg(tracee, RegVersion::Current, Reg::Sysarg3);
            if cmd == libc::SIOCGIFINDEX as Word
                && netlink::maybe_fake_siocgifindex(tracee, cmd, arg)
            {
                poke_reg(tracee, Reg::SysargResult, 0);
                set_sysnum(tracee, Sysnum::Void);
            }
        }
        Sysnum::memfd_create => {
            let mut name = [0u8; 20];
            if read_string(
                tracee,
                &mut name[..19],
                peek_reg(tracee, RegVersion::Current, Reg::Sysarg1),
            ) >= 0
            {
                name[19] = 0;
                let len = name.iter().position(|&b| b == 0).unwrap_or(19);
                let name = &name[..len];
                // Deny memfds used for exec-from-memfd tricks PRoot can't
                // support (Qt JIT, php opcache locks, apk execveat).
                if name.starts_with(b"JITCode:")
                    || name == b"opcache_lock"
                    || name.starts_with(b"lib/apk/exec/")
                {
                    status = -libc::EACCES;
                }
            }
        }
        Sysnum::close => {
            let closed_fd = peek_reg(tracee, RegVersion::Current, Reg::Sysarg1) as i32;
            if tracee.auxv_fd >= 0 && closed_fd == tracee.auxv_fd {
                tracee.auxv_fd = -1;
            }
            netlink::unmark_fake_netlink_fd(tracee, closed_fd);
            netlink::unmark_netlink_route_fd(tracee, closed_fd);
            crate::syscall::pipe_shadow::shadow_pipe_read_end(tracee.pid, closed_fd);
            status = 0;
        }
        _ => {
            status = 0;
        }
    }

    end(tracee, status)
}

/// The `accept*/getsockname/getpeername` body: capture the in/out size into
/// SYSARG_6 (unused) so the exit stage knows the buffer bound.
fn sockname_size_capture(tracee: &mut Tracee, special: bool) -> i32 {
    crate::sys::clear_errno();
    let size_addr = peek_reg(tracee, RegVersion::Original, Reg::Sysarg3);
    let size = peek_word(tracee, size_addr) as i32;
    if crate::sys::errno() != 0 {
        return if special {
            -libc::EINVAL
        } else {
            -crate::sys::errno()
        };
    }
    poke_reg(tracee, Reg::Sysarg6, size as Word);
    0
}

/// The PR_openat body (shared with openat2's rewrite).
fn openat_enter(tracee: &mut Tracee, path: &mut FixedPath) -> i32 {
    let dirfd = peek_reg(tracee, RegVersion::Current, Reg::Sysarg1) as i32;
    let flags = peek_reg(tracee, RegVersion::Current, Reg::Sysarg3);

    let status = get_sysarg_path(tracee, path, Reg::Sysarg2);
    if status < 0 {
        return status;
    }
    if tracee.execfn_addr != 0 && path.as_bytes() == b"/proc/self/auxv" {
        tracee.sysexit_pending = true;
        tracee.restart_how = crate::ptrace::ptc::PTRACE_SYSCALL;
    }

    let ty = if (flags & libc::O_NOFOLLOW as Word) != 0
        || ((flags & libc::O_EXCL as Word) != 0 && (flags & libc::O_CREAT as Word) != 0)
    {
        PType::Symlink
    } else {
        PType::Regular
    };
    let status = translate_path2(tracee, dirfd, path, Reg::Sysarg2, ty);
    if status >= 0 {
        maybe_redirect_userns_file(tracee, Reg::Sysarg2);
    }
    status
}

/// i386 PR_socketcall: SYS_* demultiplexing.  `special` mirrors the C var.
fn socketcall_enter(tracee: &mut Tracee, mut special: bool) -> i32 {
    let w = crate::tracee::reg::sizeof_word(tracee) as Word;
    let args_addr = peek_reg(tracee, RegVersion::Current, Reg::Sysarg2);
    let arg = |n: Word| -> Word { args_addr + (n - 1) * w };

    macro_rules! peekw {
        ($addr:expr_2021, $forced:expr_2021) => {{
            crate::sys::clear_errno();
            let v = peek_word(tracee, $addr);
            let e = crate::sys::errno();
            if e != 0 {
                return if $forced != 0 { $forced } else { -e };
            }
            v
        }};
    }
    macro_rules! pokew {
        ($addr:expr_2021, $val:expr_2021) => {{
            crate::sys::clear_errno();
            poke_word(tracee, $addr, $val);
            let e = crate::sys::errno();
            if e != 0 {
                return -e;
            }
        }};
    }

    const SYS_BIND: Word = 2;
    const SYS_CONNECT: Word = 3;
    const SYS_ACCEPT: Word = 5;
    const SYS_GETSOCKNAME: Word = 6;
    const SYS_GETPEERNAME: Word = 7;
    const SYS_ACCEPT4: Word = 18;

    let mut status;
    match peek_reg(tracee, RegVersion::Current, Reg::Sysarg1) {
        n if n == SYS_BIND || n == SYS_CONNECT => status = 1,
        n if n == SYS_ACCEPT || n == SYS_ACCEPT4 => {
            let sock_addr = peekw!(arg(2), 0);
            if sock_addr == 0 {
                return 0;
            }
            special = true;
            let size_addr = peekw!(arg(3), 0);
            let size = peekw!(size_addr, if special { -libc::EINVAL } else { 0 }) as i32;
            poke_reg(tracee, Reg::Sysarg6, size as Word);
            return 0;
        }
        n if n == SYS_GETSOCKNAME || n == SYS_GETPEERNAME => {
            let size_addr = peekw!(arg(3), 0);
            let size = peekw!(size_addr, if special { -libc::EINVAL } else { 0 }) as i32;
            poke_reg(tracee, Reg::Sysarg6, size as Word);
            return 0;
        }
        _ => return 0,
    }
    let _ = special;

    if status <= 0 {
        return status;
    }

    let sock_addr = peekw!(arg(2), 0);
    let size = peekw!(arg(3), 0);
    let saved = sock_addr;
    let mut new_addr = sock_addr;
    status = crate::syscall::socket::translate_socketcall_enter(tracee, &mut new_addr, size);
    if status <= 0 {
        return status;
    }

    poke_reg(tracee, Reg::Sysarg5, saved);
    poke_reg(tracee, Reg::Sysarg6, size);
    pokew!(arg(2), new_addr);
    pokew!(arg(3), size_of::<libc::sockaddr_un>() as Word);
    0
}

fn end(tracee: &mut Tracee, mut status: i32) -> i32 {
    let status2 =
        crate::extension::notify(tracee, &mut crate::extension::Event::SysEnterEnd { status });
    if status2 < 0 {
        status = status2;
    }
    status
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{Arena, TempDir, fork_child, test_tracee};
    use crate::tracee::mem::{read_string, write_data};

    #[test]
    fn proc_userns_file_detection() {
        assert!(is_proc_userns_file(b"/proc/self/uid_map"));
        assert!(is_proc_userns_file(b"/proc/self/gid_map"));
        assert!(is_proc_userns_file(b"/proc/self/setgroups"));
        assert!(is_proc_userns_file(b"/proc/1234/uid_map"));
        assert!(!is_proc_userns_file(b"/proc/self/maps"));
        assert!(!is_proc_userns_file(b"/proc/self"));
        assert!(!is_proc_userns_file(b"/proc//uid_map"));
        assert!(!is_proc_userns_file(b"/proc/abc/uid_map"));
        assert!(!is_proc_userns_file(b"/etc/passwd"));
        assert!(!is_proc_userns_file(b"/proc"));
        assert!(!is_proc_userns_file(b"/proc/self/uid_map_extra"));
    }

    /// A live tracee with `root` bound at guest "/" and an arena stack.
    fn rooted_tracee(root: &[u8], arena: &Arena, child: &crate::testutil::Child) -> Tracee {
        let mut t = child.tracee_with_sp(arena);
        t.fs.borrow_mut().cwd.set(b"/");
        crate::path::binding::new_binding(&mut t, root, Some(b"/"), true).unwrap();
        crate::path::binding::initialize_bindings(&mut t);
        t
    }

    fn remote_str(t: &Tracee, addr: Word) -> Vec<u8> {
        let mut buf = vec![0u8; 4096];
        let n = read_string(t, &mut buf, addr);
        assert!(n > 0, "read_string at {addr:#x} -> {n}");
        buf[..n as usize - 1].to_vec()
    }

    #[test]
    fn translate_sysarg_rewrites_register_to_host_path() {
        let f = TempDir::new("targ");
        f.file("inside.txt", b"x");
        let arena = Arena::new(2);
        let child = fork_child(&arena).unwrap();
        let mut t = rooted_tracee(&f.abs("."), &arena, &child);
        // Guest path /inside.txt at remote addr; Sysarg1 points at it.
        let src = arena.addr();
        write_data(&t, src, b"/inside.txt\0");
        poke_reg(&mut t, Reg::Sysarg1, src);
        assert_eq!(translate_sysarg(&mut t, Reg::Sysarg1, PType::Regular), 0);
        let dst = peek_reg(&t, RegVersion::Current, Reg::Sysarg1);
        assert_ne!(dst, src);
        let mut expected = f.abs(".");
        expected.extend_from_slice(b"/inside.txt");
        assert_eq!(remote_str(&t, dst), expected);
    }

    #[test]
    fn translate_sysarg_null_arg_is_noop() {
        let arena = Arena::new(1);
        let child = fork_child(&arena).unwrap();
        let mut t = rooted_tracee(b"/", &arena, &child);
        poke_reg(&mut t, Reg::Sysarg1, 0);
        assert_eq!(translate_sysarg(&mut t, Reg::Sysarg1, PType::Regular), 0);
        assert_eq!(peek_reg(&t, RegVersion::Current, Reg::Sysarg1), 0);
    }

    #[test]
    fn translate_sysarg_missing_file_fails() {
        let f = TempDir::new("targ-miss");
        let arena = Arena::new(2);
        let child = fork_child(&arena).unwrap();
        let mut t = rooted_tracee(&f.abs("."), &arena, &child);
        let src = arena.addr();
        write_data(&t, src, b"/definitely/missing\0");
        poke_reg(&mut t, Reg::Sysarg1, src);
        let st = translate_sysarg(&mut t, Reg::Sysarg1, PType::Regular);
        assert!(st < 0);
    }

    #[test]
    fn translate_parent_appends_leaf_after_parent_translation() {
        let f = TempDir::new("tparent");
        f.dir("dir");
        let arena = Arena::new(2);
        let child = fork_child(&arena).unwrap();
        let mut t = rooted_tracee(&f.abs("."), &arena, &child);
        let src = arena.addr();
        write_data(&t, src, b"/dir/newleaf\0");
        poke_reg(&mut t, Reg::Sysarg2, src);
        assert_eq!(
            translate_path2_parent(
                &mut t,
                libc::AT_FDCWD,
                &FixedPath::from_bytes(b"/dir/newleaf"),
                Reg::Sysarg2
            ),
            0
        );
        let dst = peek_reg(&t, RegVersion::Current, Reg::Sysarg2);
        let mut expected = f.abs(".");
        expected.extend_from_slice(b"/dir/newleaf");
        assert_eq!(remote_str(&t, dst), expected);
    }

    #[test]
    fn translate_parent_keeps_dotdot_targets_full() {
        // mkdir("a/..") must translate the whole path, not just "a".
        let f = TempDir::new("tparent-dd");
        f.dir("a");
        let arena = Arena::new(2);
        let child = fork_child(&arena).unwrap();
        let mut t = rooted_tracee(&f.abs("."), &arena, &child);
        let path = FixedPath::from_bytes(b"/a/..");
        assert_eq!(
            translate_path2_parent(&mut t, libc::AT_FDCWD, &path, Reg::Sysarg1),
            0
        );
        let dst = peek_reg(&t, RegVersion::Current, Reg::Sysarg1);
        // Whole path translated as a symlink-deref of the final "..".
        let expected = f.abs(".");
        assert!(remote_str(&t, dst).starts_with(&expected));
    }

    #[test]
    fn guest_canonicalize_strips_frivolous_components() {
        let f = TempDir::new("gcanon");
        f.dir("d");
        f.file("d/f", b"x");
        let mut t = test_tracee(std::str::from_utf8(&f.abs(".")).unwrap(), &[]);
        let mut out = FixedPath::new();
        assert!(guest_canonicalize(&mut t, b"/d/./f/", &mut out).is_ok());
        assert_eq!(out.as_bytes(), b"/d/f");
        // Relative path canonicalizes against cwd.
        let mut out2 = FixedPath::new();
        assert!(guest_canonicalize(&mut t, b"d/f", &mut out2).is_ok());
        assert_eq!(out2.as_bytes(), b"/d/f");
    }
}
