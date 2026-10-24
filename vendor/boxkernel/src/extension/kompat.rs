//! kompat extension — port of extension/kompat/kompat.c.
//!
//! Emulates a kernel newer (or older) than the host kernel: newer syscalls
//! are rewritten to their older equivalents, unsupported flags are stripped,
//! and `uname`/auxv/hostname values are virtualized.

use crate::Word;
use crate::arch::SYSCALL_AVOIDER;
use crate::execve::auxv::{
    AT_HWCAP, AT_IGNORE, AT_NULL, AT_RANDOM, AT_SYSINFO, AT_SYSINFO_EHDR, ElfAuxVector,
    fetch_elf_aux_vectors, get_elf_aux_vectors_address, push_elf_aux_vectors,
};
use crate::extension::Event;
use crate::note;
use crate::note::{Origin, Severity};
use crate::syscall::chain::{force_chain_final_result, register_chained_syscall};
use crate::syscall::seccomp::FILTER_SYSEXIT;
use crate::sysnum::{Abi, Sysnum, detranslate_sysnum};
use crate::tracee::Tracee;
use crate::tracee::mem::{read_data, write_data};
use crate::tracee::reg::{
    Reg, RegVersion, get_abi, get_sysnum, peek_reg, poke_reg, set_sysnum, sizeof_word, sysarg,
};

const MAX_ARG_SHIFT: usize = 2;

fn kernel_version(major: u64, minor: u64, revision: u64) -> i32 {
    ((major << 16) + (minor << 8) + if revision > 255 { 255 } else { revision }) as i32
}

#[derive(Default, Clone, Copy)]
struct Shift {
    /// 1-based SYSARG index (SYSARG_1 => 1).
    sysarg: usize,
    nb_args: usize,
    offset: i32,
}

#[derive(Default)]
struct Modif {
    expected_release: i32,
    new_sysnum: Option<Sysnum>,
    shifts: [Shift; MAX_ARG_SHIFT],
}

/// `struct utsname` — six 65-byte fields, layout stable since < 2.6.0.
#[derive(Clone)]
pub struct Utsname {
    pub fields: [[u8; 65]; 6],
}

impl Utsname {
    const NODENAME: usize = 1;
    const RELEASE: usize = 2;
    const DOMAINNAME: usize = 5;

    fn get(&self, i: usize) -> &[u8] {
        let f = &self.fields[i];
        let len = f.iter().position(|&b| b == 0).unwrap_or(f.len());
        &f[..len]
    }

    fn set(&mut self, i: usize, s: &[u8]) {
        let len = s.len().min(64);
        self.fields[i] = [0; 65];
        self.fields[i][..len].copy_from_slice(&s[..len]);
    }
}

impl Default for Utsname {
    fn default() -> Self {
        Self {
            fields: [[0; 65]; 6],
        }
    }
}

#[derive(Clone)]
struct Config {
    actual_release: i32,
    virtual_release: i32,
    utsname: Utsname,
    hwcap: Word,
    warned_futex: bool,
}

/// Config is shared with every child tracee, like the C version where
/// `INHERIT_PARENT` returns 0 (`talloc_reference` on the same config).
#[derive(Default)]
pub struct Kompat {
    config: Option<std::rc::Rc<std::cell::RefCell<Config>>>,
}

/// `strtoul` on a byte cursor — parses the digit prefix, advances `pos`.
fn strtoul(bytes: &[u8], pos: &mut usize) -> u64 {
    let mut value: u64 = 0;
    while *pos < bytes.len() && bytes[*pos].is_ascii_digit() {
        value = value
            .saturating_mul(10)
            .saturating_add((bytes[*pos] - b'0') as u64);
        *pos += 1;
    }
    value
}

/// `parse_kernel_release()` — "major.minor.revision" → KERNEL_VERSION int.
fn parse_kernel_release(release: &[u8]) -> i32 {
    let mut pos = 0;
    let major = strtoul(release, &mut pos);
    let mut minor = 0;
    let mut revision = 0;
    if pos < release.len() && release[pos] == b'.' {
        pos += 1;
        minor = strtoul(release, &mut pos);
    }
    if pos < release.len() && release[pos] == b'.' {
        pos += 1;
        revision = strtoul(release, &mut pos);
    }
    kernel_version(major, minor, revision)
}

/// `needs_kompat()` — expected release is newer than the actual kernel but
/// covered by the virtual one.
fn needs_kompat(config: &Config, expected_release: i32) -> bool {
    expected_release > config.actual_release && expected_release <= config.virtual_release
}

/// `modify_syscall()` — replace the syscall and shift its arguments.
fn modify_syscall(tracee: &mut Tracee, config: &Config, modif: &Modif) -> bool {
    if !needs_kompat(config, modif.expected_release) {
        return false;
    }
    let Some(new_sysnum) = modif.new_sysnum else {
        return false;
    };
    if detranslate_sysnum(get_abi(tracee), new_sysnum) == SYSCALL_AVOIDER {
        return false;
    }
    set_sysnum(tracee, new_sysnum);
    for shift in &modif.shifts {
        for j in 0..shift.nb_args {
            let arg = peek_reg(tracee, RegVersion::Current, sysarg(shift.sysarg + j));
            let dest = ((shift.sysarg + j) as i32 + shift.offset) as usize;
            poke_reg(tracee, sysarg(dest), arg);
        }
    }
    true
}

/// `discard_fd_flags()` — strip flags the (virtual) kernel doesn't support.
fn discard_fd_flags(
    tracee: &mut Tracee,
    config: &Config,
    discarded_flags: Word,
    expected_release: i32,
    sysarg_idx: usize,
) {
    if !needs_kompat(config, expected_release) {
        return;
    }
    let flags = peek_reg(tracee, RegVersion::Current, sysarg(sysarg_idx));
    poke_reg(tracee, sysarg(sysarg_idx), flags & !discarded_flags);
}

/// `emulate_fd_flags()` — chain fcntl() calls to set emulated fd flags.
fn emulate_fd_flags(tracee: &mut Tracee, fd: Word, sysarg_idx: usize, emulated_flags: Word) {
    let flags = peek_reg(tracee, RegVersion::Original, sysarg(sysarg_idx));
    if flags == 0 {
        return;
    }
    if (emulated_flags & flags & (libc::O_CLOEXEC as Word)) != 0 {
        register_chained_syscall(
            tracee,
            Sysnum::fcntl,
            [fd, libc::F_SETFD as Word, libc::FD_CLOEXEC as Word, 0, 0, 0],
        );
    }
    if (emulated_flags & flags & (libc::O_NONBLOCK as Word)) != 0 {
        register_chained_syscall(
            tracee,
            Sysnum::fcntl,
            [fd, libc::F_SETFL as Word, libc::O_NONBLOCK as Word, 0, 0, 0],
        );
    }
    let result = peek_reg(tracee, RegVersion::Current, Reg::SysargResult);
    force_chain_final_result(tracee, result);
}

const F_DUPFD_CLOEXEC: Word = libc::F_DUPFD_CLOEXEC as Word;
const F_DUPFD: Word = libc::F_DUPFD as Word;
const FUTEX_PRIVATE_FLAG: Word = 128;

/// `handle_sysenter_end()` — the per-syscall rewrite switch.
fn handle_sysenter_end(
    tracee: &mut Tracee,
    config: &std::rc::Rc<std::cell::RefCell<Config>>,
) -> i32 {
    let config = &mut *config.borrow_mut();
    match get_sysnum(tracee, RegVersion::Original) {
        Sysnum::accept4 => {
            let modif = Modif {
                expected_release: kernel_version(2, 6, 28),
                new_sysnum: Some(Sysnum::accept),
                ..Default::default()
            };
            modify_syscall(tracee, config, &modif);
            0
        }
        Sysnum::dup3 => {
            let oldfd = peek_reg(tracee, RegVersion::Current, Reg::Sysarg1);
            let newfd = peek_reg(tracee, RegVersion::Current, Reg::Sysarg2);
            if oldfd == newfd {
                return -libc::EINVAL;
            }
            let modif = Modif {
                expected_release: kernel_version(2, 6, 27),
                new_sysnum: Some(Sysnum::dup2),
                ..Default::default()
            };
            modify_syscall(tracee, config, &modif);
            0
        }
        Sysnum::epoll_create1 => {
            let modif = Modif {
                expected_release: kernel_version(2, 6, 27),
                new_sysnum: Some(Sysnum::epoll_create),
                ..Default::default()
            };
            if modify_syscall(tracee, config, &modif) {
                // epoll_create() requires a positive size.
                poke_reg(tracee, Reg::Sysarg1, 1);
            }
            0
        }
        Sysnum::epoll_pwait => {
            let modif = Modif {
                expected_release: kernel_version(2, 6, 19),
                new_sysnum: Some(Sysnum::epoll_wait),
                ..Default::default()
            };
            modify_syscall(tracee, config, &modif);
            0
        }
        Sysnum::eventfd2 => {
            let flags = peek_reg(tracee, RegVersion::Current, Reg::Sysarg2);
            if (flags & (libc::EFD_SEMAPHORE as Word)) != 0 {
                return -libc::EINVAL;
            }
            let modif = Modif {
                expected_release: kernel_version(2, 6, 27),
                new_sysnum: Some(Sysnum::eventfd),
                ..Default::default()
            };
            modify_syscall(tracee, config, &modif);
            0
        }
        Sysnum::faccessat => {
            let modif = Modif {
                expected_release: kernel_version(2, 6, 16),
                new_sysnum: Some(Sysnum::access),
                shifts: [
                    Shift {
                        sysarg: 2,
                        nb_args: 2,
                        offset: -1,
                    },
                    Shift::default(),
                ],
            };
            modify_syscall(tracee, config, &modif);
            0
        }
        Sysnum::fchmodat => {
            let modif = Modif {
                expected_release: kernel_version(2, 6, 16),
                new_sysnum: Some(Sysnum::chmod),
                shifts: [
                    Shift {
                        sysarg: 2,
                        nb_args: 2,
                        offset: -1,
                    },
                    Shift::default(),
                ],
            };
            modify_syscall(tracee, config, &modif);
            0
        }
        Sysnum::fchownat => {
            let mut modif = Modif {
                expected_release: kernel_version(2, 6, 16),
                shifts: [
                    Shift {
                        sysarg: 2,
                        nb_args: 3,
                        offset: -1,
                    },
                    Shift::default(),
                ],
                ..Default::default()
            };
            let flags = peek_reg(tracee, RegVersion::Current, Reg::Sysarg5);
            modif.new_sysnum = Some(if (flags & (libc::AT_SYMLINK_NOFOLLOW as Word)) != 0 {
                Sysnum::lchown
            } else {
                Sysnum::chown
            });
            modify_syscall(tracee, config, &modif);
            0
        }
        Sysnum::fcntl => {
            if !needs_kompat(config, kernel_version(2, 6, 24)) {
                return 0;
            }
            let command = peek_reg(tracee, RegVersion::Original, Reg::Sysarg2);
            if command == F_DUPFD_CLOEXEC {
                poke_reg(tracee, Reg::Sysarg2, F_DUPFD);
            }
            0
        }
        Sysnum::newfstatat | Sysnum::fstatat64 => {
            let mut modif = Modif {
                expected_release: kernel_version(2, 6, 16),
                shifts: [
                    Shift {
                        sysarg: 2,
                        nb_args: 2,
                        offset: -1,
                    },
                    Shift::default(),
                ],
                ..Default::default()
            };
            let flags = peek_reg(tracee, RegVersion::Current, Reg::Sysarg4);
            let allowed = libc::AT_SYMLINK_NOFOLLOW as Word
                | libc::AT_NO_AUTOMOUNT as Word
                | libc::AT_EMPTY_PATH as Word
                | 0x6000; // AT_STATX_SYNC_TYPE aka. KSTAT_QUERY_FLAGS
            if (flags & !allowed) != 0 {
                return -libc::EINVAL; // Exposed by LTP.
            }
            #[cfg(target_arch = "x86_64")]
            let nofollow = get_abi(tracee) != Abi::Abi2;
            #[cfg(not(target_arch = "x86_64"))]
            let nofollow = false;
            modif.new_sysnum = Some(
                match (nofollow, flags & (libc::AT_SYMLINK_NOFOLLOW as Word)) {
                    (true, 0) => Sysnum::stat,
                    (true, _) => Sysnum::lstat,
                    (false, 0) => Sysnum::stat64,
                    (false, _) => Sysnum::lstat64,
                },
            );
            modify_syscall(tracee, config, &modif);
            0
        }
        Sysnum::futex => {
            if !needs_kompat(config, kernel_version(2, 6, 22)) || config.actual_release == 0 {
                return 0;
            }
            let operation = peek_reg(tracee, RegVersion::Current, Reg::Sysarg2);
            if (operation & FUTEX_PRIVATE_FLAG) == 0 {
                return 0;
            }
            if !config.warned_futex {
                config.warned_futex = true;
                note!(
                    Severity::Warning,
                    Origin::User,
                    "kompat: this kernel doesn't support private futexes \
and PRoot can't emulate them.  Expect some troubles..."
                );
            }
            poke_reg(tracee, Reg::Sysarg2, operation & !FUTEX_PRIVATE_FLAG);
            0
        }
        Sysnum::futimesat => {
            let modif = Modif {
                expected_release: kernel_version(2, 6, 16),
                new_sysnum: Some(Sysnum::utimes),
                shifts: [
                    Shift {
                        sysarg: 2,
                        nb_args: 2,
                        offset: -1,
                    },
                    Shift::default(),
                ],
            };
            modify_syscall(tracee, config, &modif);
            0
        }
        Sysnum::inotify_init1 => {
            let modif = Modif {
                expected_release: kernel_version(2, 6, 27),
                new_sysnum: Some(Sysnum::inotify_init),
                ..Default::default()
            };
            modify_syscall(tracee, config, &modif);
            0
        }
        Sysnum::linkat => {
            let flags = peek_reg(tracee, RegVersion::Current, Reg::Sysarg5);
            if (flags & !(libc::AT_SYMLINK_FOLLOW as Word)) != 0 {
                return -libc::EINVAL; // Exposed by LTP.
            }
            let modif = Modif {
                expected_release: kernel_version(2, 6, 16),
                new_sysnum: Some(Sysnum::link),
                shifts: [
                    Shift {
                        sysarg: 2,
                        nb_args: 1,
                        offset: -1,
                    },
                    Shift {
                        sysarg: 4,
                        nb_args: 1,
                        offset: -2,
                    },
                ],
            };
            modify_syscall(tracee, config, &modif);
            0
        }
        Sysnum::mkdirat => {
            let modif = Modif {
                expected_release: kernel_version(2, 6, 16),
                new_sysnum: Some(Sysnum::mkdir),
                shifts: [
                    Shift {
                        sysarg: 2,
                        nb_args: 2,
                        offset: -1,
                    },
                    Shift::default(),
                ],
            };
            modify_syscall(tracee, config, &modif);
            0
        }
        Sysnum::mknodat => {
            let modif = Modif {
                expected_release: kernel_version(2, 6, 16),
                new_sysnum: Some(Sysnum::mknod),
                shifts: [
                    Shift {
                        sysarg: 2,
                        nb_args: 3,
                        offset: -1,
                    },
                    Shift::default(),
                ],
            };
            modify_syscall(tracee, config, &modif);
            0
        }
        Sysnum::openat => {
            let modif = Modif {
                expected_release: kernel_version(2, 6, 16),
                new_sysnum: Some(Sysnum::open),
                shifts: [
                    Shift {
                        sysarg: 2,
                        nb_args: 3,
                        offset: -1,
                    },
                    Shift::default(),
                ],
            };
            let modified = modify_syscall(tracee, config, &modif);
            discard_fd_flags(
                tracee,
                config,
                libc::O_CLOEXEC as Word,
                kernel_version(2, 6, 23),
                if modified { 2 } else { 3 },
            );
            0
        }
        Sysnum::open => {
            discard_fd_flags(
                tracee,
                config,
                libc::O_CLOEXEC as Word,
                kernel_version(2, 6, 23),
                2,
            );
            0
        }
        Sysnum::pipe2 => {
            let modif = Modif {
                expected_release: kernel_version(2, 6, 27),
                new_sysnum: Some(Sysnum::pipe),
                ..Default::default()
            };
            modify_syscall(tracee, config, &modif);
            0
        }
        Sysnum::pselect6 => {
            let modif = Modif {
                expected_release: kernel_version(2, 6, 16),
                new_sysnum: Some(if get_abi(tracee) != Abi::Abi2 {
                    Sysnum::select
                } else {
                    Sysnum::_newselect
                }),
                ..Default::default()
            };
            modify_syscall(tracee, config, &modif);
            0
        }
        Sysnum::readlinkat => {
            let modif = Modif {
                expected_release: kernel_version(2, 6, 16),
                new_sysnum: Some(Sysnum::readlink),
                shifts: [
                    Shift {
                        sysarg: 2,
                        nb_args: 3,
                        offset: -1,
                    },
                    Shift::default(),
                ],
            };
            modify_syscall(tracee, config, &modif);
            0
        }
        Sysnum::renameat => {
            let modif = Modif {
                expected_release: kernel_version(2, 6, 16),
                new_sysnum: Some(Sysnum::rename),
                shifts: [
                    Shift {
                        sysarg: 2,
                        nb_args: 1,
                        offset: -1,
                    },
                    Shift {
                        sysarg: 4,
                        nb_args: 1,
                        offset: -2,
                    },
                ],
            };
            modify_syscall(tracee, config, &modif);
            0
        }
        Sysnum::signalfd4 => {
            let modif = Modif {
                expected_release: kernel_version(2, 6, 27),
                new_sysnum: Some(Sysnum::signalfd),
                ..Default::default()
            };
            if modify_syscall(tracee, config, &modif) {
                // In Linux up to 2.6.26 the flags argument must be 0.
                poke_reg(tracee, Reg::Sysarg4, 0);
            }
            0
        }
        Sysnum::socket | Sysnum::socketpair | Sysnum::timerfd_create => {
            discard_fd_flags(
                tracee,
                config,
                (libc::O_CLOEXEC | libc::O_NONBLOCK) as Word,
                kernel_version(2, 6, 27),
                2,
            );
            0
        }
        Sysnum::symlinkat => {
            let modif = Modif {
                expected_release: kernel_version(2, 6, 16),
                new_sysnum: Some(Sysnum::symlink),
                shifts: [
                    Shift {
                        sysarg: 3,
                        nb_args: 1,
                        offset: -1,
                    },
                    Shift::default(),
                ],
            };
            modify_syscall(tracee, config, &modif);
            0
        }
        Sysnum::unlinkat => {
            let mut modif = Modif {
                expected_release: kernel_version(2, 6, 16),
                shifts: [
                    Shift {
                        sysarg: 2,
                        nb_args: 1,
                        offset: -1,
                    },
                    Shift::default(),
                ],
                ..Default::default()
            };
            let flags = peek_reg(tracee, RegVersion::Current, Reg::Sysarg3);
            modif.new_sysnum = Some(if (flags & (libc::AT_REMOVEDIR as Word)) != 0 {
                Sysnum::rmdir
            } else {
                Sysnum::unlink
            });
            modify_syscall(tracee, config, &modif);
            0
        }
        _ => 0,
    }
}

/// `adjust_elf_auxv()` — virtualize AT_HWCAP / AT_RANDOM / AT_SYSINFO vectors.
fn adjust_elf_auxv(tracee: &mut Tracee, config: &Config) {
    let vectors_address = get_elf_aux_vectors_address(tracee);
    if vectors_address == 0 {
        return;
    }
    let Some(mut vectors) = fetch_elf_aux_vectors(tracee, vectors_address) else {
        return;
    };

    for vector in vectors.iter_mut() {
        if vector.atype == AT_NULL {
            break;
        }
        match vector.atype {
            // Discard AT_SYSINFO*: they can leak the real OS release.
            AT_SYSINFO_EHDR | AT_SYSINFO => {
                vector.atype = AT_IGNORE;
                vector.value = 0;
            }
            AT_HWCAP => {
                if config.hwcap != Word::MAX {
                    vector.value = config.hwcap;
                }
            }
            AT_RANDOM
                // Skip only if not in forced mode.
                if config.actual_release != 0 => {
                    push_elf_aux_vectors(tracee, &vectors, vectors_address);
                    return;
                }
            _ => {}
        }
    }

    // Add AT_RANDOM only if the virtual kernel is >= 2.6.29.
    if !needs_kompat(config, kernel_version(2, 6, 29)) {
        push_elf_aux_vectors(tracee, &vectors, vectors_address);
        return;
    }

    // add_elf_aux_vector(AT_RANDOM, vectors_address) — insert before sentinel.
    let insert_at = vectors
        .iter()
        .position(|v| v.atype == AT_NULL)
        .unwrap_or(vectors.len());
    vectors.insert(
        insert_at,
        ElfAuxVector {
            atype: AT_RANDOM,
            value: vectors_address,
        },
    );

    // Since a new vector was added, argv[]/envp[] are moved one vector
    // downward to make room for the new auxv array:
    //     argv[], envp[], auxv[]
    let w = sizeof_word(tracee) as Word;
    let mut stack_pointer = peek_reg(tracee, RegVersion::Current, Reg::StackPointer);
    let size = vectors_address.wrapping_sub(stack_pointer) as usize;
    let mut argv_envp = vec![0u8; size];
    if read_data(tracee, &mut argv_envp, stack_pointer) < 0 {
        push_elf_aux_vectors(tracee, &vectors, vectors_address);
        return;
    }
    stack_pointer -= 2 * w;
    let vectors_address = vectors_address - 2 * w;
    // Safe to update the stack pointer manually in execve sysexit; do it
    // before transferring data since the kernel might not allow page faults
    // below the stack pointer.
    poke_reg(tracee, Reg::StackPointer, stack_pointer);
    if write_data(tracee, stack_pointer, &argv_envp) < 0 {
        return;
    }
    push_elf_aux_vectors(tracee, &vectors, vectors_address);
}

/// `handle_sysexit_end()` — adjust results of modified syscalls.
fn handle_sysexit_end(
    tracee: &mut Tracee,
    config: &std::rc::Rc<std::cell::RefCell<Config>>,
) -> i32 {
    let config = &mut *config.borrow_mut();
    let result = peek_reg(tracee, RegVersion::Current, Reg::SysargResult);
    let sysnum = get_sysnum(tracee, RegVersion::Original);

    // Error reported by the kernel.
    if (result as i64) < 0 {
        return 0;
    }

    match sysnum {
        Sysnum::uname => {
            let address = peek_reg(tracee, RegVersion::Original, Reg::Sysarg1);
            // utsname layout is arch-independent and stable since < 2.6.0.
            let mut data = [0u8; 6 * 65];
            for (i, f) in config.utsname.fields.iter().enumerate() {
                data[i * 65..i * 65 + 65].copy_from_slice(f);
            }
            write_data(tracee, address, &data)
        }
        Sysnum::setdomainname | Sysnum::sethostname => {
            let field = if sysnum == Sysnum::setdomainname {
                Utsname::DOMAINNAME
            } else {
                Utsname::NODENAME
            };
            let length = peek_reg(tracee, RegVersion::Original, Reg::Sysarg2);
            if length > 64 {
                return -libc::EINVAL;
            }
            let address = peek_reg(tracee, RegVersion::Original, Reg::Sysarg1);
            let mut name = [0u8; 65];
            let status = read_data(tracee, &mut name[..length as usize], address);
            if status < 0 {
                return status;
            }
            // "name does not require a terminating null byte." -- man 2
            name[length as usize] = 0;
            config.utsname.set(field, &name);
            0
        }
        Sysnum::accept4 => {
            if needs_kompat(config, kernel_version(2, 6, 28)) {
                emulate_fd_flags(
                    tracee,
                    result,
                    4,
                    (libc::O_CLOEXEC | libc::O_NONBLOCK) as Word,
                );
            }
            0
        }
        Sysnum::dup3 => {
            if needs_kompat(config, kernel_version(2, 6, 27)) {
                let fd = peek_reg(tracee, RegVersion::Original, Reg::Sysarg2);
                emulate_fd_flags(tracee, fd, 3, libc::O_CLOEXEC as Word);
            }
            0
        }
        Sysnum::epoll_create1 => {
            if needs_kompat(config, kernel_version(2, 6, 27)) {
                emulate_fd_flags(
                    tracee,
                    result,
                    1,
                    (libc::O_CLOEXEC | libc::O_NONBLOCK) as Word,
                );
            }
            0
        }
        Sysnum::eventfd2 => {
            if needs_kompat(config, kernel_version(2, 6, 27)) {
                emulate_fd_flags(
                    tracee,
                    result,
                    2,
                    (libc::O_CLOEXEC | libc::O_NONBLOCK) as Word,
                );
            }
            0
        }
        Sysnum::fcntl => {
            if !needs_kompat(config, kernel_version(2, 6, 24)) {
                return 0;
            }
            let command = peek_reg(tracee, RegVersion::Original, Reg::Sysarg2);
            if command != F_DUPFD_CLOEXEC {
                return 0;
            }
            register_chained_syscall(
                tracee,
                Sysnum::fcntl,
                [
                    result,
                    libc::F_SETFD as Word,
                    libc::FD_CLOEXEC as Word,
                    0,
                    0,
                    0,
                ],
            );
            let r = peek_reg(tracee, RegVersion::Current, Reg::SysargResult);
            force_chain_final_result(tracee, r);
            0
        }
        Sysnum::inotify_init1 => {
            if needs_kompat(config, kernel_version(2, 6, 27)) {
                emulate_fd_flags(
                    tracee,
                    result,
                    1,
                    (libc::O_CLOEXEC | libc::O_NONBLOCK) as Word,
                );
            }
            0
        }
        Sysnum::open => {
            if needs_kompat(config, kernel_version(2, 6, 23)) {
                emulate_fd_flags(tracee, result, 2, libc::O_CLOEXEC as Word);
            }
            0
        }
        Sysnum::openat => {
            if needs_kompat(config, kernel_version(2, 6, 23)) {
                emulate_fd_flags(tracee, result, 3, libc::O_CLOEXEC as Word);
            }
            0
        }
        Sysnum::pipe2 => {
            if !needs_kompat(config, kernel_version(2, 6, 27)) {
                return 0;
            }
            let mut fds = [0u8; 2 * size_of::<Word>()];
            let addr = peek_reg(tracee, RegVersion::Modified, Reg::Sysarg1);
            if read_data(tracee, &mut fds, addr) < 0 {
                return 0;
            }
            let fd0 = Word::from_ne_bytes(fds[..8].try_into().unwrap());
            let fd1 = Word::from_ne_bytes(fds[8..].try_into().unwrap());
            let emulated = (libc::O_CLOEXEC | libc::O_NONBLOCK) as Word;
            emulate_fd_flags(tracee, fd0, 2, emulated);
            emulate_fd_flags(tracee, fd1, 2, emulated);
            0
        }
        Sysnum::signalfd4 => {
            if needs_kompat(config, kernel_version(2, 6, 27)) {
                emulate_fd_flags(
                    tracee,
                    result,
                    4,
                    (libc::O_CLOEXEC | libc::O_NONBLOCK) as Word,
                );
            }
            0
        }
        Sysnum::socket | Sysnum::timerfd_create => {
            if needs_kompat(config, kernel_version(2, 6, 27)) {
                emulate_fd_flags(
                    tracee,
                    result,
                    2,
                    (libc::O_CLOEXEC | libc::O_NONBLOCK) as Word,
                );
            }
            0
        }
        Sysnum::socketpair => {
            if !needs_kompat(config, kernel_version(2, 6, 27)) {
                return 0;
            }
            let mut fds = [0u8; 2 * size_of::<Word>()];
            let addr = peek_reg(tracee, RegVersion::Modified, Reg::Sysarg4);
            if read_data(tracee, &mut fds, addr) < 0 {
                return 0;
            }
            let fd0 = Word::from_ne_bytes(fds[..8].try_into().unwrap());
            let fd1 = Word::from_ne_bytes(fds[8..].try_into().unwrap());
            let emulated = (libc::O_CLOEXEC | libc::O_NONBLOCK) as Word;
            emulate_fd_flags(tracee, fd0, 2, emulated);
            emulate_fd_flags(tracee, fd1, 2, emulated);
            0
        }
        _ => 0,
    }
}

/// `parse_utsname()` — fill `config` from a `-k` argument string.
fn parse_utsname(config: &mut Config, string: &str) -> i32 {
    let mut host_uts: libc::utsname = crate::sys::zeroed();
    let status = match crate::sys::uname() {
        Ok(u) => {
            host_uts = u;
            0
        }
        Err(_) => -1,
    };
    if status >= 0 {
        // c_char is i8 on x86_64 but u8 on aarch64.
        #[allow(clippy::unnecessary_cast)]
        let field = |f: &[libc::c_char; 65]| f.iter().map(|&c| c as u8).collect::<Vec<u8>>();
        let mut host = Utsname::default();
        host.set(0, &field(&host_uts.sysname));
        host.set(1, &field(&host_uts.nodename));
        host.set(2, &field(&host_uts.release));
        host.set(3, &field(&host_uts.version));
        host.set(4, &field(&host_uts.machine));
        host.set(5, &field(&host_uts.domainname));
        config.utsname = host;
    }
    if status < 0 || std::env::var_os("PROOT_FORCE_KOMPAT").is_some() {
        config.actual_release = 0;
    } else {
        config.actual_release = parse_kernel_release(config.utsname.get(Utsname::RELEASE));
    }

    let bytes = string.as_bytes();
    if bytes.first() == Some(&b'\\') {
        // Complex format (not for direct user consumption):
        //     \sysname\nodename\release\version\machine\domainname\hwcap\
        let names = [
            "sysname",
            "nodename",
            "release",
            "version",
            "machine",
            "domainname",
        ];
        let mut cursor: &[u8] = bytes;
        for (i, name) in names.iter().enumerate() {
            let rest = &cursor[1..];
            let Some(p) = rest.iter().position(|&b| b == b'\\') else {
                note!(
                    Severity::Error,
                    Origin::User,
                    "can't find {} field in '{}'",
                    name,
                    string
                );
                return -1;
            };
            config.utsname.set(i, &rest[..p]);
            cursor = &rest[p..];
        }
        // The hwcap field is parsed as an hexadecimal value; C's strtol
        // accepts an empty field as 0 when followed by the '\'.
        let rest = &cursor[1..];
        let Some(p) = rest.iter().position(|&b| b == b'\\') else {
            note!(
                Severity::Error,
                Origin::User,
                "can't find hwcap field in '{}'",
                string
            );
            return -1;
        };
        let hex = std::str::from_utf8(&rest[..p]).unwrap_or("");
        config.hwcap = if hex.is_empty() {
            0
        } else {
            match Word::from_str_radix(hex, 16) {
                Ok(v) => v,
                Err(_) => {
                    note!(
                        Severity::Error,
                        Origin::User,
                        "can't find hwcap field in '{}'",
                        string
                    );
                    return -1;
                }
            }
        };
    } else {
        let release: Vec<u8> = bytes.to_vec();
        config.utsname.set(Utsname::RELEASE, &release);
        config.hwcap = Word::MAX;
    }

    config.virtual_release = parse_kernel_release(config.utsname.get(Utsname::RELEASE));
    0
}

impl Kompat {
    pub fn callback(&mut self, tracee: &mut Tracee, event: &mut Event) -> i32 {
        match event {
            Event::Initialization { arg } => {
                let mut config = Config {
                    actual_release: 0,
                    virtual_release: 0,
                    utsname: Utsname::default(),
                    hwcap: 0,
                    warned_futex: false,
                };
                if parse_utsname(&mut config, arg) < 0 {
                    return -1;
                }
                self.config = Some(std::rc::Rc::new(std::cell::RefCell::new(config)));
                0
            }
            Event::SysEnterEnd { status } => {
                // Nothing to do if this syscall is being discarded
                // (because of an error detected by PRoot).
                if *status < 0 {
                    return 0;
                }
                let Some(config) = &self.config else { return 0 };
                handle_sysenter_end(tracee, config)
            }
            Event::SysExitEnd { .. } => {
                let Some(config) = &self.config else { return 0 };
                handle_sysexit_end(tracee, config)
            }
            Event::SysExitStart => {
                // This can be done only before PRoot pushes the load
                // script into the tracee's stack.
                let result = peek_reg(tracee, RegVersion::Current, Reg::SysargResult);
                if (result as i64) >= 0
                    && get_sysnum(tracee, RegVersion::Original) == Sysnum::execve
                {
                    if let Some(config) = &self.config {
                        adjust_elf_auxv(tracee, &config.borrow());
                    }
                }
                0
            }
            _ => 0,
        }
    }

    pub fn filtered_sysnums(&self) -> &'static [(Sysnum, Word)] {
        &[
            (Sysnum::accept4, FILTER_SYSEXIT),
            (Sysnum::dup3, FILTER_SYSEXIT),
            (Sysnum::epoll_create1, FILTER_SYSEXIT),
            (Sysnum::epoll_pwait, 0),
            (Sysnum::eventfd2, FILTER_SYSEXIT),
            (Sysnum::execve, FILTER_SYSEXIT),
            (Sysnum::faccessat, 0),
            (Sysnum::fchmodat, 0),
            (Sysnum::fchownat, 0),
            (Sysnum::fcntl, FILTER_SYSEXIT),
            (Sysnum::fstatat64, 0),
            (Sysnum::futimesat, 0),
            (Sysnum::futex, 0),
            (Sysnum::inotify_init1, FILTER_SYSEXIT),
            (Sysnum::linkat, 0),
            (Sysnum::mkdirat, 0),
            (Sysnum::mknodat, 0),
            (Sysnum::newfstatat, 0),
            (Sysnum::open, FILTER_SYSEXIT),
            (Sysnum::openat, FILTER_SYSEXIT),
            (Sysnum::pipe2, FILTER_SYSEXIT),
            (Sysnum::pselect6, 0),
            (Sysnum::readlinkat, 0),
            (Sysnum::renameat, 0),
            (Sysnum::setdomainname, FILTER_SYSEXIT),
            (Sysnum::sethostname, FILTER_SYSEXIT),
            (Sysnum::signalfd4, FILTER_SYSEXIT),
            (Sysnum::socket, FILTER_SYSEXIT),
            (Sysnum::socketpair, FILTER_SYSEXIT),
            (Sysnum::symlinkat, 0),
            (Sysnum::timerfd_create, FILTER_SYSEXIT),
            (Sysnum::uname, FILTER_SYSEXIT),
            (Sysnum::unlinkat, 0),
        ]
    }

    pub fn clone_for_child(&self, _clone_flags: Word) -> Self {
        Self {
            config: self.config.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::env_lock;
    use crate::tracee::reg::{get_sysnum, peek_reg, poke_reg, sysarg};

    fn mkconfig(actual: (u64, u64, u64), virtual_: (u64, u64, u64)) -> Config {
        Config {
            actual_release: kernel_version(actual.0, actual.1, actual.2),
            virtual_release: kernel_version(virtual_.0, virtual_.1, virtual_.2),
            utsname: Utsname::default(),
            hwcap: 0,
            warned_futex: false,
        }
    }

    #[test]
    fn kernel_version_packs_major_minor_rev() {
        assert_eq!(kernel_version(3, 10, 0), 0x30a00);
        assert_eq!(kernel_version(4, 19, 124), (4 << 16) + (19 << 8) + 124);
        // Revision clamps at 255.
        assert_eq!(kernel_version(5, 0, 300), (5 << 16) + 255);
    }

    #[test]
    fn strtoul_digit_prefix() {
        let mut pos = 0;
        assert_eq!(strtoul(b"123abc", &mut pos), 123);
        assert_eq!(pos, 3);
        let mut pos = 0;
        assert_eq!(strtoul(b"x", &mut pos), 0);
        assert_eq!(pos, 0);
        let mut pos = 0;
        assert_eq!(strtoul(b"", &mut pos), 0);
    }

    #[test]
    fn parse_kernel_release_versions() {
        assert_eq!(parse_kernel_release(b"3.10.0"), 0x30a00);
        assert_eq!(parse_kernel_release(b"4.19"), (4 << 16) + (19 << 8));
        assert_eq!(parse_kernel_release(b"5"), 5 << 16);
        // Garbage suffix after revision is ignored.
        assert_eq!(
            parse_kernel_release(b"4.4.302-generic"),
            (4 << 16) + (4 << 8) + 255
        );
        assert_eq!(parse_kernel_release(b""), 0);
    }

    #[test]
    fn needs_kompat_window() {
        let c = mkconfig((3, 0, 0), (5, 0, 0));
        assert!(needs_kompat(&c, kernel_version(4, 0, 0)));
        assert!(!needs_kompat(&c, kernel_version(3, 0, 0))); // actual covers it
        assert!(!needs_kompat(&c, kernel_version(6, 0, 0))); // beyond virtual
    }

    #[test]
    fn utsname_get_set_nul_terminated() {
        let mut u = Utsname::default();
        u.set(0, b"Linux");
        assert_eq!(u.get(0), b"Linux");
        // Truncates to 64 chars.
        u.set(1, &[b'x'; 100]);
        assert_eq!(u.get(1).len(), 64);
        // Empty field reads as empty.
        assert_eq!(u.get(5), b"");
    }

    #[test]
    fn parse_utsname_simple_release() {
        let _g = env_lock();
        crate::testutil::with_env("PROOT_FORCE_KOMPAT", Option::<&str>::None, || {
            let mut c = mkconfig((0, 0, 0), (0, 0, 0));
            assert_eq!(parse_utsname(&mut c, "5.4.0-fake"), 0);
            assert_eq!(c.virtual_release, kernel_version(5, 4, 0));
            assert_eq!(c.utsname.get(Utsname::RELEASE), b"5.4.0-fake");
            assert_eq!(c.hwcap, Word::MAX);
            // sysname etc. come from the real uname.
            assert_eq!(c.utsname.get(0), b"Linux");
        });
    }

    #[test]
    fn parse_utsname_complex_format() {
        let _g = env_lock();
        crate::testutil::with_env("PROOT_FORCE_KOMPAT", Option::<&str>::None, || {
            let mut c = mkconfig((0, 0, 0), (0, 0, 0));
            let s = "\\FreeBSD\\node\\9.0-RELEASE\\v1\\amd64\\dom\\1a2b\\";
            assert_eq!(parse_utsname(&mut c, s), 0);
            assert_eq!(c.utsname.get(0), b"FreeBSD");
            assert_eq!(c.utsname.get(1), b"node");
            assert_eq!(c.utsname.get(2), b"9.0-RELEASE");
            assert_eq!(c.utsname.get(3), b"v1");
            assert_eq!(c.utsname.get(4), b"amd64");
            assert_eq!(c.utsname.get(5), b"dom");
            assert_eq!(c.hwcap, 0x1a2b);
            // Missing trailing fields -> error.
            let mut c = mkconfig((0, 0, 0), (0, 0, 0));
            assert_eq!(parse_utsname(&mut c, "\\sys\\node"), -1);
        });
    }

    #[test]
    fn modify_syscall_shifts_args() {
        let mut t = Tracee::default();
        crate::tracee::reg::set_bank_compat(&mut t, RegVersion::Current, false); // native ABI
        poke_reg(&mut t, sysarg(1), 0x111);
        poke_reg(&mut t, sysarg(2), 0x222);
        let c = mkconfig((3, 0, 0), (5, 0, 0));
        let mut m = Modif {
            expected_release: kernel_version(4, 0, 0),
            new_sysnum: Some(Sysnum::getpid),
            ..Default::default()
        };
        m.shifts[0] = Shift {
            sysarg: 1,
            nb_args: 1,
            offset: 1,
        }; // arg1 -> arg2
        assert!(modify_syscall(&mut t, &c, &m));
        assert_eq!(get_sysnum(&t, RegVersion::Current), Sysnum::getpid);
        assert_eq!(peek_reg(&t, RegVersion::Current, sysarg(2)), 0x111);
        // Not needed when virtual <= expected.
        let c2 = mkconfig((9, 0, 0), (9, 0, 0));
        let mut t2 = Tracee::default();
        assert!(!modify_syscall(&mut t2, &c2, &m));
    }
}
