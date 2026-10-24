//! Shadow pipe read ends — port of syscall/pipe_shadow.c.
//!
//! When a tracee closes the read end of an anonymous pipe while a child
//! still holds the write end, ptrace serialization can make the parent
//! close first — the child's write() then gets EPIPE.  The tracer opens a
//! shadow read reference via `/proc/<pid>/fd/<fd>` and releases it once the
//! race window is over (POLLHUP, would-block writer, or max age).
//!
//! All state is thread-local: the event loop is single-threaded, so plain
//! `Cell`/`RefCell` covers it without `static mut`.

use std::cell::{Cell, RefCell};

const MAX_SHADOW_PIPES: usize = 32;
const SHADOW_MAX_AGE_MS: i64 = 1000;
const SHADOW_TIMER_MS: i64 = 50;
const SHADOW_REAP_INTERVAL_MS: i64 = SHADOW_TIMER_MS / 2;
const F_GETPIPE_SZ: i32 = 1032;
const ITIMER_REAL: i32 = 0; // Not exported by libc for Bionic.

#[derive(Copy, Clone)]
struct Shadow {
    fd: i32,
    birth: libc::timespec,
}

const EMPTY_SHADOW: Shadow = Shadow {
    fd: -1,
    birth: libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    },
};

thread_local! {
    static SHADOWS: RefCell<[Shadow; MAX_SHADOW_PIPES]> =
        const { RefCell::new([EMPTY_SHADOW; MAX_SHADOW_PIPES]) };
    static SHADOWS_HELD: Cell<i32> = const { Cell::new(0) };
    static LAST_REAP: Cell<libc::timespec> = const {
        Cell::new(libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        })
    };
    static TIMER_ARMED: Cell<bool> = const { Cell::new(false) };
}

fn elapsed_ms(since: &libc::timespec) -> i64 {
    let now = match crate::sys::clock_gettime(libc::CLOCK_MONOTONIC) {
        Ok(t) => t,
        Err(_) => return 0,
    };
    (now.tv_sec - since.tv_sec) * 1000 + (now.tv_nsec - since.tv_nsec) / 1_000_000
}

/// `writer_would_block()` — the pipe is too full for a writer to proceed.
fn writer_would_block(fd: i32) -> bool {
    let capacity = crate::sys::fcntl(fd, F_GETPIPE_SZ, 0);
    if capacity <= 0 {
        return false;
    }
    let mut buffered: libc::c_int = 0;
    if crate::sys::ioctl_val(fd, libc::FIONREAD as libc::c_ulong, &mut buffered) < 0 {
        return false;
    }
    buffered as i64
        > if capacity as i64 > libc::PIPE_BUF as i64 {
            capacity as i64 - libc::PIPE_BUF as i64
        } else {
            0
        }
}

/// `shadow_pipe_read_end()` — open a tracer-side read reference to the
/// tracee's pipe-read fd about to be closed.
pub fn shadow_pipe_read_end(tracee_pid: i32, tracee_fd: i32) {
    // Anonymous pipe?
    let path = format!("/proc/{}/fd/{}", tracee_pid, tracee_fd);
    let link = match std::fs::read_link(&path) {
        Ok(l) => l,
        Err(_) => return,
    };
    if !link.as_os_str().as_encoded_bytes().starts_with(b"pipe:[") {
        return;
    }

    // Read end only (O_RDONLY in O_ACCMODE).
    let info = match std::fs::read_to_string(format!("/proc/{}/fdinfo/{}", tracee_pid, tracee_fd)) {
        Ok(t) => t,
        Err(_) => return,
    };
    let mut flags: u64 = 1;
    for line in info.lines() {
        if let Some(v) = line.strip_prefix("flags:") {
            flags = u64::from_str_radix(v.trim(), 8).unwrap_or(1);
            break;
        }
    }
    if (flags & libc::O_ACCMODE as u64) != libc::O_RDONLY as u64 {
        return;
    }

    let slot = match SHADOWS.with(|s| s.borrow().iter().position(|sh| sh.fd == -1)) {
        Some(s) => s,
        None => return,
    };

    let c = std::ffi::CString::new(path).unwrap();
    let fd = crate::sys::open(&c, libc::O_RDONLY | libc::O_CLOEXEC, 0);
    if fd < 0 {
        return;
    }
    SHADOWS.with(|s| {
        let mut shadows = s.borrow_mut();
        shadows[slot].fd = fd;
        shadows[slot].birth = crate::sys::clock_gettime(libc::CLOCK_MONOTONIC)
            .unwrap_or_else(|_| crate::sys::zeroed());
    });
    SHADOWS_HELD.with(|h| h.set(h.get() + 1));
}

/// `shadow_pipes_reap()` — release shadows that can no longer help.
pub fn reap() {
    if SHADOWS_HELD.with(|h| h.get()) == 0 {
        return;
    }
    if LAST_REAP.with(|l| elapsed_ms(&l.get())) < SHADOW_REAP_INTERVAL_MS {
        return;
    }
    if let Ok(now) = crate::sys::clock_gettime(libc::CLOCK_MONOTONIC) {
        LAST_REAP.with(|l| l.set(now));
    }

    SHADOWS.with(|s| {
        let mut shadows = s.borrow_mut();
        for shadow in shadows.iter_mut() {
            if shadow.fd < 0 {
                continue;
            }
            let mut pfd = libc::pollfd {
                fd: shadow.fd,
                events: 0,
                revents: 0,
            };
            let hup = crate::sys::poll(std::slice::from_mut(&mut pfd), 0) > 0
                && (pfd.revents & libc::POLLHUP) != 0;
            if hup
                || writer_would_block(shadow.fd)
                || elapsed_ms(&shadow.birth) >= SHADOW_MAX_AGE_MS
            {
                crate::sys::close(shadow.fd);
                shadow.fd = -1;
                SHADOWS_HELD.with(|h| h.set(h.get() - 1));
            }
        }
    });
}

/// `shadow_pipes_held()`.
pub fn held() -> bool {
    SHADOWS_HELD.with(|h| h.get()) > 0
}

/// `shadow_pipes_set_timer()` — arm/disarm the SIGALRM wakeup.
pub fn set_timer(enabled: bool) {
    if !enabled && !TIMER_ARMED.with(|a| a.get()) {
        return;
    }
    let mut timer: libc::itimerval = crate::sys::zeroed();
    if enabled {
        timer.it_value.tv_usec = SHADOW_TIMER_MS * 1000;
    }
    if crate::sys::setitimer(ITIMER_REAL, &timer) < 0 {
        return;
    }
    TIMER_ARMED.with(|a| a.set(enabled));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::io::AsRawFd;

    fn pipe_pair() -> (std::fs::File, std::fs::File) {
        let mut fds = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        unsafe {
            (
                std::fs::File::from_raw_fd(fds[0]),
                std::fs::File::from_raw_fd(fds[1]),
            )
        }
    }

    use std::os::unix::io::FromRawFd;

    #[test]
    fn shadow_holds_read_end_until_hup() {
        let (r, w) = pipe_pair();
        let pid = std::process::id() as i32;
        shadow_pipe_read_end(pid, r.as_raw_fd());
        assert!(held());
        // Writer still open: reap must not drop the shadow.
        // (LAST_REAP starts at 0 -> elapsed is huge, so first reap runs.)
        reap();
        assert!(held());
        // Close the writer -> POLLHUP -> next reap releases.  Sleep past
        // the 25ms reap interval so the second reap isn't throttled.
        drop(w);
        std::thread::sleep(std::time::Duration::from_millis(
            SHADOW_REAP_INTERVAL_MS as u64 + 10,
        ));
        reap();
        assert!(!held());
        drop(r);
    }

    #[test]
    fn non_pipe_fds_ignored() {
        let pid = std::process::id() as i32;
        // Regular file fd.
        let f = std::fs::File::open("/dev/null").unwrap();
        shadow_pipe_read_end(pid, f.as_raw_fd());
        assert!(!held());
        // Pipe WRITE end (not a read fd).
        let (r, w) = pipe_pair();
        shadow_pipe_read_end(pid, w.as_raw_fd());
        assert!(!held());
        drop((r, w, f));
        // Bogus pid/fd.
        shadow_pipe_read_end(-1, 999);
        assert!(!held());
    }

    #[test]
    fn writer_would_block_full_pipe() {
        let (r, w) = pipe_pair();
        // Fill the pipe: FIONREAD > capacity - PIPE_BUF when nearly full.
        let cap = unsafe { libc::fcntl(w.as_raw_fd(), F_GETPIPE_SZ) } as usize;
        assert!(cap > 0);
        let chunk = vec![0u8; cap];
        let n = unsafe {
            libc::write(
                w.as_raw_fd(),
                chunk.as_ptr() as *const libc::c_void,
                cap - libc::PIPE_BUF + 1,
            )
        };
        assert!(n > 0);
        assert!(writer_would_block(r.as_raw_fd()));
        // Drain half -> not blocking.
        let mut buf = vec![0u8; cap];
        let _ = unsafe {
            libc::read(
                r.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                cap / 2,
            )
        };
        assert!(!writer_would_block(r.as_raw_fd()));
        // Bad fd -> false.
        assert!(!writer_would_block(-1));
        drop((r, w));
    }

    #[test]
    fn set_timer_toggles() {
        // Disarm when never armed is a no-op; arming installs SIGALRM
        // (harmless: fires once 50ms later, default disposition would kill
        // the process! So don't actually arm — just verify disarm works.)
        set_timer(false);
        assert!(!TIMER_ARMED.with(|a| a.get()));
    }
}
