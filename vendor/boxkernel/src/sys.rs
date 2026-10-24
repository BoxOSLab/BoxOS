//! Thin safe wrappers over `libc`.
//!
//! Every raw syscall/libc call in the codebase is funneled through this
//! module so that `unsafe` stays confined to FFI boundary functions instead
//! of being scattered through the translation/extension logic. Wrappers
//! return the raw libc status (`< 0` on error, inspect `errno`) so call
//! sites keep C-identical errno semantics.

use std::ffi::{CStr, CString};
use std::os::unix::io::RawFd;

// ==================================================================
// errno
// ==================================================================

#[cfg(target_os = "android")]
use libc::__errno as errno_location;
#[cfg(not(target_os = "android"))]
use libc::__errno_location as errno_location;

/// Read the thread-local `errno`.
pub(crate) fn errno() -> i32 {
    // SAFETY: __errno_location() (Bionic: __errno()) always returns a valid
    // pointer to the thread-local errno.
    unsafe { *errno_location() }
}

/// Write the thread-local `errno`.
pub(crate) fn set_errno(value: i32) {
    // SAFETY: see `errno`.
    unsafe { *errno_location() = value }
}

/// Reset `errno` to 0 (the pre-syscall convention used throughout).
pub(crate) fn clear_errno() {
    set_errno(0);
}

// ==================================================================
// POD helpers
// ==================================================================

/// A zero-initialized instance of `T`. Intended for C structs that are
/// filled by the kernel (stat, siginfo_t, utsname, ...).
pub(crate) fn zeroed<T>() -> T {
    // SAFETY: all uses are `#[repr(C)]` FFI structs for which the
    // all-zero bit pattern is a valid, fully-initialized value.
    unsafe { std::mem::zeroed() }
}

/// Byte view of a POD value (for pushing structs into tracee memory).
pub(crate) fn as_bytes<T>(value: &T) -> &[u8] {
    // SAFETY: any initialized `&T` is readable as `size_of::<T>()` bytes;
    // callers only use this on #[repr(C)] structs that are fully initialized
    // (built via `zeroed()` or with every field set).
    unsafe { std::slice::from_raw_parts(value as *const T as *const u8, size_of::<T>()) }
}

/// Mutable byte view of a POD value (for reading structs out of tracee
/// memory into a typed value).
pub(crate) fn as_bytes_mut<T>(value: &mut T) -> &mut [u8] {
    // SAFETY: see `as_bytes`. Mutating padding is harmless here: the
    // written-back regions are produced by the kernel or by `read_data`.
    unsafe { std::slice::from_raw_parts_mut(value as *mut T as *mut u8, size_of::<T>()) }
}

// ==================================================================
// Process identity
// ==================================================================

pub(crate) fn getuid() -> libc::uid_t {
    // SAFETY: getuid() has no failure modes.
    unsafe { libc::getuid() }
}
pub(crate) fn getgid() -> libc::gid_t {
    // SAFETY: getgid() has no failure modes.
    unsafe { libc::getgid() }
}
pub(crate) fn getpid() -> libc::pid_t {
    // SAFETY: getpid() has no failure modes.
    unsafe { libc::getpid() }
}

pub(crate) fn getpgid(pid: libc::pid_t) -> libc::pid_t {
    // SAFETY: standard libc call; errno reports failure.
    unsafe { libc::getpgid(pid) }
}

/// `(real, effective, saved)` uids, or `Err(errno)`.
pub(crate) fn getresuid() -> Result<(libc::uid_t, libc::uid_t, libc::uid_t), i32> {
    let (mut r, mut e, mut s) = (0, 0, 0);
    // SAFETY: out params point at live locals.
    if unsafe { libc::getresuid(&mut r, &mut e, &mut s) } != 0 {
        return Err(errno());
    }
    Ok((r, e, s))
}

/// `(real, effective, saved)` gids, or `Err(errno)`.
pub(crate) fn getresgid() -> Result<(libc::gid_t, libc::gid_t, libc::gid_t), i32> {
    let (mut r, mut e, mut s) = (0, 0, 0);
    // SAFETY: out params point at live locals.
    if unsafe { libc::getresgid(&mut r, &mut e, &mut s) } != 0 {
        return Err(errno());
    }
    Ok((r, e, s))
}

// ==================================================================
// Process control
// ==================================================================

pub(crate) fn fork() -> libc::pid_t {
    // SAFETY: the tracer is single-threaded; both parent and child
    // continue with a valid process image.
    unsafe { libc::fork() }
}

/// `waitpid`; returns `(pid, raw_status)` or `Err(errno)`.
pub(crate) fn waitpid(pid: libc::pid_t, flags: i32) -> Result<(libc::pid_t, i32), i32> {
    let mut status: i32 = 0;
    // SAFETY: &mut status is a valid out-pointer.
    let ret = unsafe { libc::waitpid(pid, &mut status, flags) };
    if ret < 0 {
        Err(errno())
    } else {
        Ok((ret, status))
    }
}

pub(crate) fn kill(pid: libc::pid_t, sig: i32) -> i32 {
    // SAFETY: standard libc call; errno reports failure.
    unsafe { libc::kill(pid, sig) }
}

pub(crate) fn tkill(pid: libc::pid_t, sig: i32) -> i32 {
    // SAFETY: variadic syscall with fixed args; errno reports failure.
    unsafe { libc::syscall(libc::SYS_tkill, pid, sig) as i32 }
}

/// Install `handler` via the legacy `signal()` interface. Returns the
/// previous handler (as a usize).
pub(crate) fn signal(signum: i32, handler: usize) -> usize {
    // SAFETY: standard libc call; handler is a valid `sighandler_t`
    // (SIG_DFL/SIG_IGN or a function address, per libc's representation).
    unsafe { libc::signal(signum, handler) as usize }
}

/// `strerror(errno)` → owned message string.
pub(crate) fn strerror(errno: i32) -> String {
    // SAFETY: strerror returns a pointer to a static, NUL-terminated
    // string for any input on glibc.
    unsafe { CStr::from_ptr(libc::strerror(errno)) }
        .to_string_lossy()
        .into_owned()
}

/// `prlimit64(pid, resource, new, old)` → 0 or -1.
pub(crate) fn prlimit64(
    pid: libc::pid_t,
    resource: u32,
    new: Option<&libc::rlimit64>,
    old: Option<&mut libc::rlimit64>,
) -> i32 {
    let newp = new.map_or(std::ptr::null(), |r| r as *const _);
    let oldp = old.map_or(std::ptr::null_mut(), |r| r as *mut _);
    // SAFETY: both pointers are valid or NULL per the prlimit64 contract.
    // Bionic declares the resource as `int`, glibc as `unsigned int`.
    unsafe { libc::prlimit64(pid, resource as _, newp, oldp) }
}

/// `sigaction(signum, act, oldact)`.
pub(crate) fn sigaction(
    signum: i32,
    act: &libc::sigaction,
    oldact: Option<&mut libc::sigaction>,
) -> i32 {
    let old_ptr = match oldact {
        Some(o) => o as *mut libc::sigaction,
        None => std::ptr::null_mut(),
    };
    // SAFETY: act/oldact pointers are valid for the call duration.
    unsafe { libc::sigaction(signum, act, old_ptr) }
}

/// Fill every bit of `set`.
pub(crate) fn sigfillset(set: &mut libc::sigset_t) {
    // SAFETY: standard libc call on a valid set.
    unsafe {
        libc::sigfillset(set);
    }
}

/// Register `f` to run at process exit (libc `atexit`).
pub fn at_exit(f: extern "C" fn()) {
    // SAFETY: f is a plain function pointer, valid for atexit.
    unsafe {
        libc::atexit(f);
    }
}

pub(crate) fn exit_immediately(code: i32) -> ! {
    // SAFETY: _exit never returns.
    unsafe { libc::_exit(code) }
}

/// `execvp`; only returns the errno on failure.
pub(crate) fn execvp(path: &CStr, argv: &[*const libc::c_char]) -> i32 {
    // SAFETY: path/argv are NUL-terminated argv-style arrays for the
    // duration of the call; on success the image is replaced.
    unsafe {
        libc::execvp(path.as_ptr(), argv.as_ptr());
    }
    errno()
}

pub(crate) fn sysconf(name: i32) -> i64 {
    // SAFETY: standard libc call.
    unsafe { libc::sysconf(name) }
}

/// Host page size, cached (0x1000 when sysconf fails).
pub(crate) fn page_size() -> crate::Word {
    static PAGE: std::sync::OnceLock<crate::Word> = std::sync::OnceLock::new();
    *PAGE.get_or_init(|| {
        let v = sysconf(libc::_SC_PAGESIZE);
        if v > 0 { v as crate::Word } else { 0x1000 }
    })
}

/// `uname`, or `Err(errno)`.
pub(crate) fn uname() -> Result<libc::utsname, i32> {
    let mut uts: libc::utsname = zeroed();
    // SAFETY: &mut uts is a valid out-pointer.
    if unsafe { libc::uname(&mut uts) } < 0 {
        return Err(errno());
    }
    Ok(uts)
}

/// CStr view of a utsname char-array field (NUL-terminated per POSIX).
///
/// # Safety
/// `field` must come from a `libc::utsname` populated by `uname()` —
/// its fields are always NUL-terminated.
pub unsafe fn cstr_from_field(field: &[libc::c_char]) -> &CStr {
    // SAFETY: upheld by caller contract (kernel fills with
    // NUL-terminated strings).
    unsafe { CStr::from_ptr(field.as_ptr()) }
}

/// `clock_gettime`, or `Err(errno)`.
pub(crate) fn clock_gettime(clk: libc::clockid_t) -> Result<libc::timespec, i32> {
    let mut ts: libc::timespec = zeroed();
    // SAFETY: &mut ts is a valid out-pointer.
    if unsafe { libc::clock_gettime(clk, &mut ts) } < 0 {
        return Err(errno());
    }
    Ok(ts)
}

pub(crate) fn time() -> libc::time_t {
    // SAFETY: passing NULL is supported.
    unsafe { libc::time(std::ptr::null_mut()) }
}

pub(crate) fn prctl(option: i32, a2: usize, a3: usize, a4: usize, a5: usize) -> i32 {
    // SAFETY: standard libc call; errno reports failure.
    unsafe { libc::prctl(option, a2, a3, a4, a5) }
}

/// `setitimer(which, new, NULL)`.
pub(crate) fn setitimer(which: i32, new: &libc::itimerval) -> i32 {
    // SAFETY: standard libc call; errno reports failure.
    unsafe { libc::setitimer(which, new, std::ptr::null_mut()) }
}

/// `poll(&mut fds[..], nfds, timeout)` over a slice.
pub(crate) fn poll(fds: &mut [libc::pollfd], timeout: i32) -> i32 {
    // SAFETY: fds is a valid slice of pollfds.
    unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout) }
}

// ==================================================================
// File system
// ==================================================================

/// `open(path, flags, mode)` → raw fd or -1 (errno set).
pub(crate) fn open(path: &CStr, flags: i32, mode: libc::mode_t) -> RawFd {
    // SAFETY: path is NUL-terminated for the call duration.
    unsafe { libc::open(path.as_ptr(), flags, mode) }
}

pub(crate) fn close(fd: RawFd) -> i32 {
    // SAFETY: closing an fd the caller owns is safe; double-close is the
    // caller's logic concern, not a memory-safety issue.
    unsafe { libc::close(fd) }
}

/// `read(fd, buf)`.
pub(crate) fn read(fd: RawFd, buf: &mut [u8]) -> isize {
    // SAFETY: buf is a valid writable slice for the call.
    unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) }
}

/// `write(fd, buf)`.
pub(crate) fn write(fd: RawFd, buf: &[u8]) -> isize {
    // SAFETY: buf is a valid readable slice for the call.
    unsafe { libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len()) }
}

/// `pread(fd, buf, off)`.
pub(crate) fn pread(fd: RawFd, buf: &mut [u8], off: libc::off_t) -> isize {
    // SAFETY: buf is a valid writable slice for the call.
    unsafe { libc::pread(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), off) }
}

/// `ftruncate(fd, len)`.
pub(crate) fn ftruncate(fd: RawFd, len: libc::off_t) -> i32 {
    // SAFETY: standard libc call; errno reports failure.
    unsafe { libc::ftruncate(fd, len) }
}
/// `dup2(fd, fd2)` → fd2 or -1.
pub(crate) fn dup2(fd: RawFd, fd2: RawFd) -> RawFd {
    // SAFETY: standard libc call; errno reports failure.
    unsafe { libc::dup2(fd, fd2) }
}

/// Wrap a raw fd as an owned `File` (the fd must be uniquely owned).
pub(crate) fn file_from_fd(fd: RawFd) -> std::fs::File {
    use std::os::unix::io::FromRawFd;
    // SAFETY: the caller transfers unique ownership of `fd`.
    unsafe { std::fs::File::from_raw_fd(fd) }
}

/// Anonymous temp-file fd, like `tmpfile()` but returning a bare fd:
/// `O_TMPFILE` on $TMPDIR (then /tmp), falling back to create+unlink.
pub(crate) fn tmpfile_fd() -> RawFd {
    use std::os::unix::ffi::OsStrExt;
    let mut dirs: Vec<CString> = Vec::new();
    if let Some(d) = std::env::var_os("TMPDIR") {
        dirs.push(CString::new(d.as_os_str().as_bytes()).unwrap_or_default());
    }
    dirs.push(c"/tmp".to_owned());
    for dir in &dirs {
        if dir.as_bytes().is_empty() {
            continue;
        }
        // SAFETY: standard libc call; errno reports failure.
        let fd = unsafe { libc::open(dir.as_ptr(), libc::O_TMPFILE | libc::O_RDWR, 0o600) };
        if fd >= 0 {
            return fd;
        }
    }
    -1
}

/// `fcntl(fd, cmd, arg)`.
pub(crate) fn fcntl(fd: RawFd, cmd: i32, arg: i32) -> i32 {
    // SAFETY: standard variadic call with an integer arg; errno reports
    // failure.
    unsafe { libc::fcntl(fd, cmd, arg) }
}

/// `ioctl(fd, request, argp)` over a POD in/out value.
pub(crate) fn ioctl_val<T>(fd: RawFd, request: libc::c_ulong, arg: &mut T) -> i32 {
    // SAFETY: arg is a valid pointer for the request's in/out struct;
    // callers pass the right struct type for `request`.
    // Bionic declares the request as `int`, glibc as `unsigned long`.
    unsafe { libc::ioctl(fd, request as _, arg as *mut T) }
}

/// `stat(path)`, or `Err(errno)`.
pub(crate) fn stat(path: &CStr) -> Result<libc::stat, i32> {
    let mut st: libc::stat = zeroed();
    // SAFETY: &mut st is a valid out-pointer.
    if unsafe { libc::stat(path.as_ptr(), &mut st) } < 0 {
        return Err(errno());
    }
    Ok(st)
}

/// `lstat(path)`, or `Err(errno)`.
pub(crate) fn lstat(path: &CStr) -> Result<libc::stat, i32> {
    let mut st: libc::stat = zeroed();
    // SAFETY: &mut st is a valid out-pointer.
    if unsafe { libc::lstat(path.as_ptr(), &mut st) } < 0 {
        return Err(errno());
    }
    Ok(st)
}

/// `statfs64(path)` → filled `statfs64`, or `Err(errno)` (errno may be
/// 0 on failure — the C reference maps that to -EPERM at call sites).
pub(crate) fn statfs64(path: &CStr) -> Result<libc::statfs64, i32> {
    let mut st: libc::statfs64 = zeroed();
    clear_errno();
    // SAFETY: &mut st is a valid out-pointer.
    if unsafe { libc::statfs64(path.as_ptr(), &mut st) } != 0 {
        return Err(errno());
    }
    Ok(st)
}
/// `access(path, mode)` → 0 or -1.
pub(crate) fn access(path: &CStr, mode: i32) -> i32 {
    // SAFETY: path is NUL-terminated for the call duration.
    unsafe { libc::access(path.as_ptr(), mode) }
}

/// `faccessat(dirfd, path, mode, flags)` → 0 or -1.
pub(crate) fn faccessat(dirfd: i32, path: &CStr, mode: i32, flags: i32) -> i32 {
    // SAFETY: path is NUL-terminated for the call duration.
    unsafe { libc::faccessat(dirfd, path.as_ptr(), mode, flags) }
}

pub(crate) fn chmod(path: &CStr, mode: libc::mode_t) -> i32 {
    // SAFETY: path is NUL-terminated for the call duration.
    unsafe { libc::chmod(path.as_ptr(), mode) }
}

pub(crate) fn fchmod(fd: RawFd, mode: libc::mode_t) -> i32 {
    // SAFETY: standard libc call; errno reports failure.
    unsafe { libc::fchmod(fd, mode) }
}

pub(crate) fn unlink(path: &CStr) -> i32 {
    // SAFETY: path is NUL-terminated for the call duration.
    unsafe { libc::unlink(path.as_ptr()) }
}

pub(crate) fn unlinkat(dirfd: i32, path: &CStr, flags: i32) -> i32 {
    // SAFETY: path is NUL-terminated for the call duration.
    unsafe { libc::unlinkat(dirfd, path.as_ptr(), flags) }
}

pub(crate) fn rename(old: &CStr, new: &CStr) -> i32 {
    // SAFETY: both paths are NUL-terminated for the call duration.
    unsafe { libc::rename(old.as_ptr(), new.as_ptr()) }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn renameat(old_dir: i32, old: &CStr, new_dir: i32, new: &CStr) -> i32 {
    // SAFETY: both paths are NUL-terminated for the call duration.
    unsafe { libc::renameat(old_dir, old.as_ptr(), new_dir, new.as_ptr()) }
}

pub(crate) fn symlink(target: &CStr, linkpath: &CStr) -> i32 {
    // SAFETY: both paths are NUL-terminated for the call duration.
    unsafe { libc::symlink(target.as_ptr(), linkpath.as_ptr()) }
}

pub(crate) fn symlinkat(target: &CStr, dirfd: i32, linkpath: &CStr) -> i32 {
    // SAFETY: both paths are NUL-terminated for the call duration.
    unsafe { libc::symlinkat(target.as_ptr(), dirfd, linkpath.as_ptr()) }
}

pub(crate) fn mkdir(path: &CStr, mode: libc::mode_t) -> i32 {
    // SAFETY: path is NUL-terminated for the call duration.
    unsafe { libc::mkdir(path.as_ptr(), mode) }
}

pub(crate) fn mknod(path: &CStr, mode: libc::mode_t, dev: libc::dev_t) -> i32 {
    // SAFETY: path is NUL-terminated for the call duration.
    unsafe { libc::mknod(path.as_ptr(), mode, dev) }
}

/// `readlink(path, buf)` → bytes written, or -1.
pub(crate) fn readlink(path: &CStr, buf: &mut [u8]) -> isize {
    // SAFETY: buf is a valid writable slice for the call.
    unsafe { libc::readlink(path.as_ptr(), buf.as_mut_ptr() as *mut _, buf.len()) }
}

/// `readlinkat(dirfd, path, buf)` → bytes written, or -1.
pub(crate) fn readlinkat(dirfd: i32, path: &CStr, buf: &mut [u8]) -> isize {
    // SAFETY: buf is a valid writable slice for the call.
    unsafe { libc::readlinkat(dirfd, path.as_ptr(), buf.as_mut_ptr() as *mut _, buf.len()) }
}

/// `realpath(path)` → resolved path written to `out`; false on failure
/// (errno set).
pub(crate) fn realpath(path: &CStr, out: &mut crate::fpath::FixedPath) -> bool {
    // SAFETY: the buffer is PATH_MAX bytes, the size realpath requires.
    let ret = unsafe { libc::realpath(path.as_ptr(), out.as_mut_bytes().as_mut_ptr() as *mut _) };
    if ret.is_null() {
        return false;
    }
    out.sync_len_from_nul();
    true
}

/// `getcwd` into a caller-provided buffer → bytes written (excl. NUL).
pub(crate) fn getcwd_into(buf: &mut [u8]) -> Option<usize> {
    // SAFETY: buf is a valid writable slice.
    let ret = unsafe { libc::getcwd(buf.as_mut_ptr() as *mut _, buf.len()) };
    if ret.is_null() {
        return None;
    }
    Some(
        buf.iter()
            .position(|&b| b == 0)
            .unwrap_or(buf.len().saturating_sub(1)),
    )
}

/// `pipe2(O_CLOEXEC)` → `(read_end, write_end)`, or `Err(errno)`.
pub(crate) fn pipe_cloexec() -> Result<(RawFd, RawFd), i32> {
    let mut fds = [0i32; 2];
    // SAFETY: fds is a valid 2-int out-array.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(errno());
    }
    Ok((fds[0], fds[1]))
}

/// `setenv(name, value, overwrite)`.
pub(crate) fn setenv(name: &CStr, value: &CStr, overwrite: bool) -> i32 {
    // SAFETY: name/value are NUL-terminated for the call duration.
    unsafe { libc::setenv(name.as_ptr(), value.as_ptr(), overwrite as i32) }
}

// ==================================================================
// Sockets
// ==================================================================

/// `socket(domain, type, protocol)` → fd or -1.
pub(crate) fn socket(domain: i32, ty: i32, protocol: i32) -> RawFd {
    // SAFETY: standard libc call; errno reports failure.
    unsafe { libc::socket(domain, ty, protocol) }
}
/// Borrow `sa` as a generic `sockaddr` pointer + length pair.
fn sockaddr_parts<T>(sa: &T) -> (*const libc::sockaddr, libc::socklen_t) {
    (
        sa as *const T as *const libc::sockaddr,
        size_of::<T>() as libc::socklen_t,
    )
}

/// `bind(fd, sa, size_of::<S>())` — `S` is the concrete sockaddr type.
pub(crate) fn bind<S>(fd: RawFd, sa: &S) -> i32 {
    let (ptr, len) = sockaddr_parts(sa);
    // SAFETY: ptr/len describe the live struct `sa`.
    unsafe { libc::bind(fd, ptr, len) }
}
pub(crate) fn listen(fd: RawFd, backlog: i32) -> i32 {
    // SAFETY: standard libc call; errno reports failure.
    unsafe { libc::listen(fd, backlog) }
}

/// `accept(fd, NULL, NULL)` → fd or -1.
pub(crate) fn accept(fd: RawFd) -> RawFd {
    // SAFETY: NULL peer address is supported.
    unsafe { libc::accept(fd, std::ptr::null_mut(), std::ptr::null_mut()) }
}

/// `sendto(fd, buf, flags, dest)`.
pub(crate) fn sendto<S>(fd: RawFd, buf: &[u8], flags: i32, dest: Option<&S>) -> isize {
    let (ptr, len) = match dest {
        Some(sa) => sockaddr_parts(sa),
        None => (std::ptr::null(), 0),
    };
    // SAFETY: buf (and dest when given) are valid for the call duration.
    unsafe {
        libc::sendto(
            fd,
            buf.as_ptr() as *const libc::c_void,
            buf.len(),
            flags,
            ptr,
            len,
        )
    }
}

/// `sendmsg(fd, msg, flags)`.
pub(crate) fn sendmsg(fd: RawFd, msg: &libc::msghdr, flags: i32) -> isize {
    // SAFETY: msg describes valid buffers built by the caller.
    unsafe { libc::sendmsg(fd, msg, flags) }
}
/// `recv(fd, buf, flags)`.
pub(crate) fn recv(fd: RawFd, buf: &mut [u8], flags: i32) -> isize {
    // SAFETY: buf is a valid writable slice for the call.
    unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), flags) }
}

/// `setsockopt(fd, level, name, &value, size_of::<T>())`.
pub(crate) fn setsockopt_val<T>(fd: RawFd, level: i32, name: i32, value: &T) -> i32 {
    // SAFETY: value is a valid pointer of size_of::<T>() bytes.
    unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            value as *const T as *const libc::c_void,
            size_of::<T>() as libc::socklen_t,
        )
    }
}
/// `if_nametoindex(name)` → index or 0.
pub(crate) fn if_nametoindex(name: &CStr) -> libc::c_uint {
    // SAFETY: name is NUL-terminated for the call duration.
    unsafe { libc::if_nametoindex(name.as_ptr()) }
}

// ==================================================================
// getifaddrs
// ==================================================================

/// Owned `getifaddrs` list; frees on drop.
pub(crate) struct IfAddrs {
    head: *mut libc::ifaddrs,
}

impl IfAddrs {
    /// `getifaddrs()` → list, or `Err(errno)`.
    pub(crate) fn get() -> Result<IfAddrs, i32> {
        let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
        // SAFETY: head is a valid out-pointer.
        if unsafe { libc::getifaddrs(&mut head) } != 0 {
            return Err(errno());
        }
        Ok(IfAddrs { head })
    }

    /// Iterate over the interface addresses.
    pub(crate) fn iter(&self) -> IfAddrsIter<'_> {
        IfAddrsIter {
            cur: self.head,
            _list: std::marker::PhantomData,
        }
    }
}

impl Drop for IfAddrs {
    fn drop(&mut self) {
        // SAFETY: head came from getifaddrs and is freed once.
        unsafe { libc::freeifaddrs(self.head) }
    }
}

pub(crate) struct IfAddrsIter<'a> {
    cur: *const libc::ifaddrs,
    _list: std::marker::PhantomData<&'a IfAddrs>,
}

impl<'a> Iterator for IfAddrsIter<'a> {
    type Item = IfAddr<'a>;

    fn next(&mut self) -> Option<IfAddr<'a>> {
        if self.cur.is_null() {
            return None;
        }
        // SAFETY: nodes from getifaddrs are valid while `self` (the list)
        // is alive; the iterator borrows it for 'a.
        let inner = unsafe { &*self.cur };
        self.cur = inner.ifa_next;
        Some(IfAddr { inner })
    }
}

/// One interface-address entry.
pub(crate) struct IfAddr<'a> {
    inner: &'a libc::ifaddrs,
}

impl<'a> IfAddr<'a> {
    /// Interface name (NUL-terminated by the kernel).
    pub(crate) fn name(&self) -> &'a CStr {
        // SAFETY: getifaddrs fills ifa_name with a valid C string.
        unsafe { CStr::from_ptr(self.inner.ifa_name) }
    }

    pub(crate) fn flags(&self) -> libc::c_uint {
        self.inner.ifa_flags
    }

    /// Generic `sockaddr` for `ifa_addr`, if present.
    fn addr(&self) -> Option<&'a libc::sockaddr> {
        if self.inner.ifa_addr.is_null() {
            return None;
        }
        // SAFETY: getifaddrs-provided pointer, valid for 'a.
        Some(unsafe { &*self.inner.ifa_addr })
    }

    /// `ifa_netmask` as a generic `sockaddr`, if present.
    fn netmask(&self) -> Option<&'a libc::sockaddr> {
        if self.inner.ifa_netmask.is_null() {
            return None;
        }
        // SAFETY: getifaddrs-provided pointer, valid for 'a.
        Some(unsafe { &*self.inner.ifa_netmask })
    }

    /// `ifa_addr` viewed as `sockaddr_in` when the family is AF_INET.
    pub(crate) fn addr_in(&self) -> Option<&'a libc::sockaddr_in> {
        sockaddr_as_in(self.addr()?)
    }

    /// `ifa_addr` viewed as `sockaddr_in6` when the family is AF_INET6.
    pub(crate) fn addr_in6(&self) -> Option<&'a libc::sockaddr_in6> {
        sockaddr_as_in6(self.addr()?)
    }

    /// `ifa_addr` viewed as `sockaddr_ll` when the family is AF_PACKET.
    pub(crate) fn addr_ll(&self) -> Option<&'a libc::sockaddr_ll> {
        sockaddr_as_ll(self.addr()?)
    }

    /// `ifa_netmask` viewed as `sockaddr_in` when the family is AF_INET.
    pub(crate) fn netmask_in(&self) -> Option<&'a libc::sockaddr_in> {
        sockaddr_as_in(self.netmask()?)
    }

    /// `ifa_netmask` viewed as `sockaddr_in6` when the family is
    /// AF_INET6.
    pub(crate) fn netmask_in6(&self) -> Option<&'a libc::sockaddr_in6> {
        sockaddr_as_in6(self.netmask()?)
    }
}

/// Family-checked view of a `sockaddr` as `sockaddr_in`.
pub(crate) fn sockaddr_as_in(sa: &libc::sockaddr) -> Option<&libc::sockaddr_in> {
    if sa.sa_family as i32 != libc::AF_INET {
        return None;
    }
    // SAFETY: family-checked cast; the underlying object is a
    // sockaddr_in when sa_family is AF_INET.
    Some(unsafe { &*(sa as *const libc::sockaddr as *const libc::sockaddr_in) })
}

/// Family-checked view of a `sockaddr` as `sockaddr_in6`.
pub(crate) fn sockaddr_as_in6(sa: &libc::sockaddr) -> Option<&libc::sockaddr_in6> {
    if sa.sa_family as i32 != libc::AF_INET6 {
        return None;
    }
    // SAFETY: family-checked cast.
    Some(unsafe { &*(sa as *const libc::sockaddr as *const libc::sockaddr_in6) })
}

/// Family-checked view of a `sockaddr` as `sockaddr_ll` (AF_PACKET).
pub(crate) fn sockaddr_as_ll(sa: &libc::sockaddr) -> Option<&libc::sockaddr_ll> {
    if sa.sa_family as i32 != libc::AF_PACKET {
        return None;
    }
    // SAFETY: family-checked cast.
    Some(unsafe { &*(sa as *const libc::sockaddr as *const libc::sockaddr_ll) })
}

// ==================================================================
// ptrace
// ==================================================================

/// `ptrace(request, pid, addr, data)` — addr/data are taken as raw
/// `usize` words since most requests use them as scalars or opaque
/// remote addresses; pointer-valued callers cast with `as usize`.
pub(crate) fn ptrace(request: libc::c_uint, pid: libc::pid_t, addr: usize, data: usize) -> i64 {
    // SAFETY: standard ptrace call; addr/data semantics are per-request
    // and provided by the caller. errno reports failure.
    unsafe {
        libc::ptrace(
            // Bionic declares the request as `int`, glibc as `unsigned int`.
            request as _,
            pid,
            addr as *mut libc::c_void,
            data as *mut libc::c_void,
        ) as i64
    }
}

/// `process_vm_readv` single-iovec: copy `local.len()` bytes from
/// `remote` in `pid`'s address space → bytes read or -1.
pub(crate) fn process_vm_read(pid: libc::pid_t, local: &mut [u8], remote: u64) -> isize {
    let liovec = libc::iovec {
        iov_base: local.as_mut_ptr() as *mut _,
        iov_len: local.len(),
    };
    let riovec = libc::iovec {
        iov_base: remote as usize as *mut _,
        iov_len: local.len(),
    };
    // SAFETY: `local` is a valid writable slice; the remote range is
    // kernel-validated. Partial/failed reads are reported by status.
    unsafe { libc::process_vm_readv(pid, &liovec, 1, &riovec, 1, 0) }
}

/// `process_vm_writev` single-iovec: write `local` into `remote` in
/// `pid`'s address space → bytes written or -1.
pub(crate) fn process_vm_write(pid: libc::pid_t, local: &[u8], remote: u64) -> isize {
    let liovec = libc::iovec {
        iov_base: local.as_ptr() as *mut _,
        iov_len: local.len(),
    };
    let riovec = libc::iovec {
        iov_base: remote as usize as *mut _,
        iov_len: local.len(),
    };
    // SAFETY: `local` is a valid readable slice; the remote range is
    // kernel-validated.
    unsafe { libc::process_vm_writev(pid, &liovec, 1, &riovec, 1, 0) }
}

/// `process_vm_writev` scatter-gather: write `srcs` concatenated at
/// `remote` in `pid`'s address space → bytes written or -1.
pub(crate) fn process_vm_writev_bufs(pid: libc::pid_t, srcs: &[&[u8]], remote: u64) -> isize {
    let local: Vec<libc::iovec> = srcs
        .iter()
        .map(|s| libc::iovec {
            iov_base: s.as_ptr() as *mut _,
            iov_len: s.len(),
        })
        .collect();
    let remote_iov = libc::iovec {
        iov_base: remote as usize as *mut _,
        iov_len: srcs.iter().map(|s| s.len()).sum(),
    };
    // SAFETY: every slice in `srcs` outlives the call; the remote range
    // is kernel-validated.
    unsafe { libc::process_vm_writev(pid, local.as_ptr(), local.len() as _, &remote_iov, 1, 0) }
}

/// `PTRACE_GETSIGINFO` → filled `siginfo_t`, or `Err(errno)`.
pub(crate) fn ptrace_getsiginfo(pid: libc::pid_t) -> Result<libc::siginfo_t, i32> {
    let mut si: libc::siginfo_t = zeroed();
    let status = ptrace(
        crate::ptrace::ptc::PTRACE_GETSIGINFO as u32,
        pid,
        0,
        &mut si as *mut libc::siginfo_t as usize,
    );
    if status < 0 { Err(errno()) } else { Ok(si) }
}

/// `PTRACE_GETEVENTMSG` → message word, or `Err(errno)`.
pub(crate) fn ptrace_geteventmsg(pid: libc::pid_t) -> Result<libc::c_ulong, i32> {
    let mut msg: libc::c_ulong = 0;
    let status = ptrace(
        crate::ptrace::ptc::PTRACE_GETEVENTMSG as u32,
        pid,
        0,
        &mut msg as *mut libc::c_ulong as usize,
    );
    if status < 0 { Err(errno()) } else { Ok(msg) }
}

/// `PTRACE_SETOPTIONS(pid, mask)`.
pub(crate) fn ptrace_setoptions(pid: libc::pid_t, mask: usize) -> i64 {
    ptrace(crate::ptrace::ptc::PTRACE_SETOPTIONS as u32, pid, 0, mask)
}

/// `si_pid` of a signal's `siginfo_t`.
///
/// # Safety
/// `si` must point to a valid `libc::siginfo_t` — e.g. the pointer a
/// `SA_SIGINFO` handler receives from the kernel, or one filled by
/// `ptrace_getsiginfo`.
pub unsafe fn siginfo_si_pid(si: *const libc::siginfo_t) -> libc::pid_t {
    // SAFETY: caller guarantees `si` is valid.
    unsafe { (*si).si_pid() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Word;

    #[test]
    fn errno_roundtrip() {
        set_errno(42);
        assert_eq!(errno(), 42);
        clear_errno();
        assert_eq!(errno(), 0);
    }

    #[test]
    fn zeroed_and_as_bytes() {
        #[repr(C)]
        #[derive(Copy, Clone)]
        struct S {
            a: u32,
            b: [u8; 8],
        }
        let mut s: S = zeroed();
        assert_eq!(s.a, 0);
        assert_eq!(as_bytes(&s).len(), 12);
        let m = as_bytes_mut(&mut s);
        m[0] = 0xAA;
        assert_eq!(s.a, 0xAA);
    }

    #[test]
    fn identity_calls_match_libc() {
        assert_eq!(getpid(), unsafe { libc::getpid() });
        assert_eq!(getuid(), unsafe { libc::getuid() });
        assert_eq!(getgid(), unsafe { libc::getgid() });
        assert!(getpgid(0) > 0);
    }

    #[test]
    fn getresuid_three_ids() {
        let (r, e, s) = getresuid().unwrap();
        assert_eq!(r, unsafe { libc::getuid() });
        assert_eq!(e, unsafe { libc::geteuid() });
        assert_eq!(s, unsafe { libc::getuid() }); // typical non-setuid
    }

    #[test]
    fn pipe_cloexec_and_rw() {
        let (r, w) = pipe_cloexec().unwrap();
        assert_ne!(r, w);
        // FD_CLOEXEC set on both ends.
        assert!(fcntl_getfd(r) & libc::FD_CLOEXEC != 0);
        assert!(fcntl_getfd(w) & libc::FD_CLOEXEC != 0);
        write(w, b"xy");
        let mut b = [0u8; 2];
        assert_eq!(read(r, &mut b), 2);
        assert_eq!(&b, b"xy");
        close(r);
        close(w);
    }

    fn fcntl_getfd(fd: RawFd) -> i32 {
        unsafe { libc::fcntl(fd, libc::F_GETFD) }
    }

    #[test]
    fn tmpfile_fd_is_readwrite() {
        let fd = tmpfile_fd();
        assert!(fd >= 0);
        assert_eq!(write(fd, b"abc"), 3);
        let mut b = [0u8; 3];
        assert_eq!(pread(fd, &mut b, 0), 3);
        assert_eq!(&b, b"abc");
        close(fd);
    }

    #[test]
    fn strerror_and_page_size() {
        assert!(strerror(libc::ENOENT).len() > 3);
        let p = page_size();
        assert!(p >= 4096 && p.is_power_of_two());
        assert_eq!(sysconf(libc::_SC_PAGESIZE) as Word, p);
    }

    #[test]
    // c_char is i8 on x86_64 but u8 on aarch64.
    #[allow(clippy::unnecessary_cast)]
    fn uname_and_clock() {
        let u = uname().unwrap();
        let sysname: String = u
            .sysname
            .iter()
            .take_while(|c| **c != 0)
            .map(|c| *c as u8 as char)
            .collect();
        assert_eq!(sysname, "Linux");
        let ts = clock_gettime(libc::CLOCK_REALTIME).unwrap();
        assert!(ts.tv_sec > 1_600_000_000);
        assert!(time() > 0);
    }
}
