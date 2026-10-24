//! BoxKernel loader: a freestanding, position-dependent static ELF that the
//! kernel execve()s in place of the real guest program.  PRoot then pokes a
//! "load script" onto the tracee stack (see execve/exit) and hands its address
//! to `_start` through the first argument register.
//!
//! The loader replays the script: open the real binary / its ELF interpreter,
//! mmap() every PT_LOAD segment, fix the auxv entries on the initial stack and
//! finally branch to the true entry point.

#![no_std]
#![no_main]
#![allow(internal_features)]
#![allow(non_camel_case_types)]

use core::arch::asm;

type word_t = usize;
type byte_t = u8;

/* Load script wire format (mirrors loader/script.h): a sequence of
 * variable-size statements, each starting with a word-sized action tag
 * followed by the action's payload (`LOAD_STATEMENT_SIZE` = word + payload). */
#[repr(C)]
#[derive(Copy, Clone)]
struct LoadStatement {
    action: word_t,
    payload: Payload,
}

#[repr(C)]
#[derive(Copy, Clone)]
union Payload {
    open: Open,
    mmap: Mmap,
    make_stack_exec: MakeStackExec,
    start: Start,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct Open {
    string_address: word_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct Mmap {
    addr: word_t,
    length: word_t,
    prot: word_t,
    offset: word_t,
    clear_length: word_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct MakeStackExec {
    start: word_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct Start {
    stack_pointer: word_t,
    entry_point: word_t,
    at_phdr: word_t,
    at_phent: word_t,
    at_phnum: word_t,
    at_entry: word_t,
    at_execfn: word_t,
}

const LOAD_ACTION_OPEN_NEXT: word_t = 0;
const LOAD_ACTION_OPEN: word_t = 1;
const LOAD_ACTION_MMAP_FILE: word_t = 2;
const LOAD_ACTION_MMAP_ANON: word_t = 3;
const LOAD_ACTION_MAKE_STACK_EXEC: word_t = 4;
const LOAD_ACTION_START_TRACED: word_t = 5;
const LOAD_ACTION_START: word_t = 6;

const O_RDONLY: word_t = 0;
const MAP_PRIVATE: word_t = 0x02;
const MAP_FIXED: word_t = 0x10;
const MAP_ANONYMOUS: word_t = 0x20;
const PROT_READ: word_t = 1;
const PROT_WRITE: word_t = 2;
const PROT_EXEC: word_t = 4;
const PROT_GROWSDOWN: word_t = 0x0100_0000;
const PR_SET_NAME: word_t = 15;

const AT_NULL: word_t = 0;
const AT_PHDR: word_t = 3;
const AT_PHENT: word_t = 4;
const AT_PHNUM: word_t = 5;
const AT_BASE: word_t = 7;
const AT_ENTRY: word_t = 9;
const AT_EXECFN: word_t = 31;

#[cfg(target_arch = "x86_64")]
mod imp {
    use super::*;

    pub const NR_OPEN: word_t = 2;
    pub const NR_CLOSE: word_t = 3;
    pub const NR_MMAP: word_t = 9;
    pub const NR_MPROTECT: word_t = 10;
    pub const NR_EXECVE: word_t = 59;
    pub const NR_EXIT: word_t = 60;
    pub const NR_PRCTL: word_t = 157;

    #[inline(always)]
    pub unsafe fn syscall1(n: word_t, a1: word_t) -> word_t {
        let ret: word_t;
        asm!("syscall", inlateout("rax") n => ret, in("rdi") a1,
             out("rcx") _, out("r11") _, options(nostack));
        ret
    }

    #[inline(always)]
    pub unsafe fn syscall3(n: word_t, a1: word_t, a2: word_t, a3: word_t) -> word_t {
        let ret: word_t;
        asm!("syscall", inlateout("rax") n => ret, in("rdi") a1, in("rsi") a2,
             in("rdx") a3, out("rcx") _, out("r11") _, options(nostack));
        ret
    }

    #[inline(always)]
    pub unsafe fn syscall6(n: word_t, a1: word_t, a2: word_t, a3: word_t,
                           a4: word_t, a5: word_t, a6: word_t) -> word_t {
        let ret: word_t;
        asm!("syscall", inlateout("rax") n => ret, in("rdi") a1, in("rsi") a2,
             in("rdx") a3, in("r10") a4, in("r8") a5, in("r9") a6,
             out("rcx") _, out("r11") _, options(nostack));
        ret
    }

    #[inline(always)]
    pub unsafe fn open_rdonly(path: word_t) -> word_t {
        syscall3(NR_OPEN, path, O_RDONLY, 0)
    }

    /// Restore the initial stack pointer, clear state flags and rtld_fini,
    /// then jump to the program entry point.
    ///
    /// # Safety
    /// Diverges; `stack_pointer` must denote a valid initial stack image.
    #[unsafe(naked)]
    pub unsafe extern "C" fn branch(stack_pointer: word_t, destination: word_t) -> ! {
        core::arch::naked_asm!(
            "mov rsp, rdi",
            "push 0",
            "popfq",
            "xor edx, edx",
            "jmp rsi",
        )
    }
}

#[cfg(target_arch = "aarch64")]
mod imp {
    use super::*;

    pub const NR_OPENAT: word_t = 56;
    pub const NR_CLOSE: word_t = 57;
    pub const NR_MMAP: word_t = 222;
    pub const NR_MPROTECT: word_t = 226;
    pub const NR_EXECVE: word_t = 221;
    pub const NR_EXIT: word_t = 93;
    pub const NR_PRCTL: word_t = 167;

    const AT_FDCWD: word_t = -100isize as word_t;

    #[inline(always)]
    pub unsafe fn syscall1(n: word_t, a1: word_t) -> word_t {
        let ret: word_t;
        asm!("svc #0", in("x8") n, inlateout("x0") a1 => ret, options(nostack));
        ret
    }

    #[inline(always)]
    pub unsafe fn syscall3(n: word_t, a1: word_t, a2: word_t, a3: word_t) -> word_t {
        let ret: word_t;
        asm!("svc #0", in("x8") n, inlateout("x0") a1 => ret, in("x1") a2,
             in("x2") a3, options(nostack));
        ret
    }

    #[inline(always)]
    pub unsafe fn syscall6(n: word_t, a1: word_t, a2: word_t, a3: word_t,
                           a4: word_t, a5: word_t, a6: word_t) -> word_t {
        let ret: word_t;
        asm!("svc #0", in("x8") n, inlateout("x0") a1 => ret, in("x1") a2,
             in("x2") a3, in("x3") a4, in("x4") a5, in("x5") a6, options(nostack));
        ret
    }

    /// There is no open(2) on arm64; PRoot translates the openat() path.
    #[inline(always)]
    pub unsafe fn open_rdonly(path: word_t) -> word_t {
        syscall6(NR_OPENAT, AT_FDCWD, path, O_RDONLY, 0, 0, 0)
    }

    /// Restore the initial stack pointer, clear rtld_fini (x0), then jump to
    /// the program entry point.
    ///
    /// # Safety
    /// Diverges; `stack_pointer` must denote a valid initial stack image.
    #[unsafe(naked)]
    pub unsafe extern "C" fn branch(stack_pointer: word_t, destination: word_t) -> ! {
        core::arch::naked_asm!(
            "mov sp, x0",
            "mov x0, xzr",
            "br x1",
        )
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("loader is implemented for x86_64 and aarch64 only");

use imp::*;

#[inline(always)]
fn fatal() -> ! {
    unsafe { syscall1(NR_EXIT, 182) };
    loop {}
}

#[inline(always)]
unsafe fn clear(mut start: word_t, end: word_t) {
    while start < end {
        (start as *mut byte_t).write_volatile(0);
        start += 1;
    }
}

#[inline(always)]
unsafe fn basename(s: word_t) -> word_t {
    let mut cur = s;
    while *(cur as *const byte_t) != 0 {
        cur += 1;
    }
    while cur > s && *(cur as *const byte_t) != b'/' {
        cur -= 1;
    }
    if cur != s {
        cur += 1;
    }
    cur
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn _start(cursor: word_t) -> ! {
    let mut cursor = cursor as *const byte_t;
    let mut traced = false;
    let mut reset_at_base = true;
    let mut at_base: word_t = 0;
    let mut fd: word_t = usize::MAX;

    loop {
        let stmt = cursor as *const LoadStatement;
        let action = (*stmt).action;
        let payload = &(*stmt).payload;
        let advance;

        match action {
            LOAD_ACTION_OPEN_NEXT | LOAD_ACTION_OPEN => {
                if action == LOAD_ACTION_OPEN_NEXT {
                    if (syscall1(NR_CLOSE, fd) as isize) < 0 {
                        fatal();
                    }
                }
                fd = open_rdonly(payload.open.string_address);
                if (fd as isize) < 0 {
                    fatal();
                }
                reset_at_base = true;
                advance = core::mem::size_of::<word_t>() + core::mem::size_of::<Open>();
            }
            LOAD_ACTION_MMAP_FILE | LOAD_ACTION_MMAP_ANON => {
                let m = payload.mmap;
                let anon = action == LOAD_ACTION_MMAP_ANON;
                let ret = syscall6(
                    NR_MMAP,
                    m.addr,
                    m.length,
                    m.prot,
                    MAP_PRIVATE | MAP_FIXED | if anon { MAP_ANONYMOUS } else { 0 },
                    if anon { usize::MAX } else { fd },
                    if anon { 0 } else { m.offset },
                );
                if ret != m.addr {
                    fatal();
                }
                if m.clear_length != 0 {
                    clear(
                        m.addr + m.length - m.clear_length,
                        m.addr + m.length,
                    );
                }
                if reset_at_base {
                    at_base = m.addr;
                    reset_at_base = false;
                }
                advance = core::mem::size_of::<word_t>() + core::mem::size_of::<Mmap>();
            }
            LOAD_ACTION_MAKE_STACK_EXEC => {
                syscall3(
                    NR_MPROTECT,
                    payload.make_stack_exec.start,
                    1,
                    PROT_READ | PROT_WRITE | PROT_EXEC | PROT_GROWSDOWN,
                );
                advance =
                    core::mem::size_of::<word_t>() + core::mem::size_of::<MakeStackExec>();
            }
            LOAD_ACTION_START | LOAD_ACTION_START_TRACED => {
                let s = payload.start;
                if action == LOAD_ACTION_START_TRACED {
                    traced = true;
                }

                if (syscall1(NR_CLOSE, fd) as isize) < 0 {
                    fatal();
                }

                // Walk the initial process stack: argc, argv[], envp[], auxv[].
                let mut sp = s.stack_pointer as *mut word_t;
                let argc = *sp;
                let at_execfn_slot = *sp.add(1);
                sp = sp.add(argc + 1);
                loop {
                    sp = sp.add(1);
                    if *sp == 0 {
                        break;
                    }
                }
                sp = sp.add(1);
                while *sp != AT_NULL {
                    match *sp {
                        AT_PHDR => *sp.add(1) = s.at_phdr,
                        AT_PHENT => *sp.add(1) = s.at_phent,
                        AT_PHNUM => *sp.add(1) = s.at_phnum,
                        AT_ENTRY => *sp.add(1) = s.at_entry,
                        AT_BASE => *sp.add(1) = at_base,
                        AT_EXECFN => *sp.add(1) = at_execfn_slot,
                        _ => {}
                    }
                    sp = sp.add(2);
                }

                let name = basename(s.at_execfn);
                syscall3(NR_PRCTL, PR_SET_NAME, name, 0);

                if traced {
                    // Fake execve syscall: the only purpose is to notify the
                    // ptracer through a syscall-enter stop.
                    syscall6(NR_EXECVE, 1, s.stack_pointer, s.entry_point, 2, 3, 4);
                } else {
                    branch(s.stack_pointer, s.entry_point);
                }
                fatal();
            }
            _ => fatal(),
        }

        cursor = cursor.add(advance);
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    fatal()
}
