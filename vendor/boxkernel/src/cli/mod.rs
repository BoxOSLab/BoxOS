//! Command-line front-end — port of src/cli/cli.c + cli/proot.c + cli/proot.h.
//!
//! The option table is data-driven exactly like the C version: each option
//! owns a list of aliases, a separator convention and a handler.

use std::sync::atomic::{AtomicBool, Ordering};

use crate::HOST_ROOTFS;
use crate::extension::{self, AnyExtension};
use crate::fpath::{FixedPath, PathGuard};
use crate::note::{Origin, Severity, note};
use crate::path::{self, binding, canon};
use crate::tracee::event::TraceeRef;
use crate::tracee::{self, Tracee};

/// `exit_failure` in C: toggled by -V/-h so the "-1 means exit" protocol
/// still reports success.
pub static EXIT_FAILURE: AtomicBool = AtomicBool::new(true);

pub const VERSION: &str = "5.1.0";

/// `Cli` — the static tool descriptor.
pub struct Cli {
    pub version: &'static str,
    pub name: &'static str,
    pub subtitle: &'static str,
    pub synopsis: &'static str,
    pub colophon: &'static str,
    pub logo: &'static str,
    pub options: &'static [Opt],
}

/// `get_proot_cli()`.
pub static PROOT_CLI: Cli = Cli {
    version: VERSION,
    name: "proot",
    subtitle: "chroot, mount --bind, and binfmt_misc without privilege/setup",
    synopsis: "proot [option] ... [command]",
    colophon: "Visit https://github.com/termux/proot for help, bug reports, suggestions, patches, ...\n\
Copyright (C) 2015 STMicroelectronics, licensed under GPL v2 or later.",
    logo: "BoxKernel",
    options: PROOT_OPTIONS,
};

// ------------------------------------------------------------------
// Option table
// ------------------------------------------------------------------

pub struct Argument {
    pub name: &'static str,
    /// `None` means the option takes no value.
    pub separator: Option<char>,
    pub value: Option<&'static str>,
}

pub type Handler = fn(&mut Tracee, Option<&str>) -> i32;

pub struct Opt {
    pub class: &'static str,
    pub arguments: &'static [Argument],
    pub handler: Handler,
    pub description: &'static str,
    pub detail: &'static str,
}

const RECOMMENDED_BINDINGS: &[&str] = &[
    "/etc/host.conf",
    "/etc/hosts",
    "/etc/hosts.equiv",
    "/etc/mtab",
    "/etc/netgroup",
    "/etc/networks",
    "/etc/passwd",
    "/etc/group",
    "/etc/nsswitch.conf",
    "/etc/resolv.conf",
    "/etc/localtime",
    "/dev/",
    "/sys/",
    "/proc/",
    "/tmp/",
    "/run/",
    "/var/run/dbus/system_bus_socket",
    "$HOME",
    "*path*",
];

const RECOMMENDED_SU_BINDINGS: &[&str] = &[
    "/etc/host.conf",
    "/etc/hosts",
    "/etc/nsswitch.conf",
    "/etc/resolv.conf",
    "/dev/",
    "/sys/",
    "/proc/",
    "/tmp/",
    "/run/shm",
    "$HOME",
    "*path*",
];

static PROOT_OPTIONS: &[Opt] = &[
    Opt {
        class: "Regular options",
        arguments: &[
            Argument {
                name: "-r",
                separator: Some(' '),
                value: Some("path"),
            },
            Argument {
                name: "--rootfs",
                separator: Some('='),
                value: Some("path"),
            },
        ],
        handler: handle_option_r,
        description: "Use *path* as the new guest root file-system, default is /.",
        detail: "\tThe specified path typically contains a Linux distribution where\n\
\tall new programs will be confined.  The default rootfs is /\n\
\twhen none is specified, this makes sense when the bind mechanism\n\
\tis used to relocate host files and directories, see the -b\n\
\toption and the Examples section for details.\n\
\t\n\
\tIt is recommended to use the -R or -S options instead.",
    },
    Opt {
        class: "Regular options",
        arguments: &[
            Argument {
                name: "-b",
                separator: Some(' '),
                value: Some("path"),
            },
            Argument {
                name: "--bind",
                separator: Some('='),
                value: Some("path"),
            },
            Argument {
                name: "-m",
                separator: Some(' '),
                value: Some("path"),
            },
            Argument {
                name: "--mount",
                separator: Some('='),
                value: Some("path"),
            },
        ],
        handler: handle_option_b,
        description: "Make the content of *path* accessible in the guest rootfs.",
        detail: "\tThis option makes any file or directory of the host rootfs\n\
\taccessible in the confined environment just as if it were part of\n\
\tthe guest rootfs.  By default the host path is bound to the same\n\
\tpath in the guest rootfs but users can specify any other location\n\
\twith the syntax: -b *host_path*:*guest_location*.  If the\n\
\tguest location is a symbolic link, it is dereferenced to ensure\n\
\tthe new content is accessible through all the symbolic links that\n\
\tpoint to the overlaid content.  In most cases this default\n\
\tbehavior shouldn't be a problem, although it is possible to\n\
\texplicitly not dereference the guest location by appending it the\n\
\t! character: -b *host_path*:*guest_location!*.",
    },
    Opt {
        class: "Regular options",
        arguments: &[
            Argument {
                name: "-q",
                separator: Some(' '),
                value: Some("command"),
            },
            Argument {
                name: "--qemu",
                separator: Some('='),
                value: Some("command"),
            },
        ],
        handler: handle_option_q,
        description: "Execute guest programs through QEMU as specified by *command*.",
        detail: "\tEach time a guest program is going to be executed, PRoot inserts\n\
\tthe QEMU user-mode command in front of the initial request.\n\
\tThat way, guest programs actually run on a virtual guest CPU\n\
\temulated by QEMU user-mode.  The native execution of host programs\n\
\tis still effective and the whole host rootfs is bound to\n\
\t/host-rootfs in the guest environment.",
    },
    Opt {
        class: "Regular options",
        arguments: &[
            Argument {
                name: "-w",
                separator: Some(' '),
                value: Some("path"),
            },
            Argument {
                name: "--pwd",
                separator: Some('='),
                value: Some("path"),
            },
            Argument {
                name: "--cwd",
                separator: Some('='),
                value: Some("path"),
            },
        ],
        handler: handle_option_w,
        description: "Set the initial working directory to *path*.",
        detail: "\tSome programs expect to be launched from a given directory but do\n\
\tnot perform any chdir by themselves.  This option avoids the\n\
\tneed for running a shell and then entering the directory manually.",
    },
    Opt {
        class: "Regular options",
        arguments: &[Argument {
            name: "--kill-on-exit",
            separator: None,
            value: None,
        }],
        handler: handle_option_kill_on_exit,
        description: "Kill all processes on command exit.",
        detail: "\tWhen the executed command leaves orphean or detached processes\n\
\taround, proot waits until all processes possibly terminate. This option forces\n\
\tthe immediate termination of all tracee processes when the main command exits.",
    },
    Opt {
        class: "Regular options",
        arguments: &[
            Argument {
                name: "-v",
                separator: Some(' '),
                value: Some("value"),
            },
            Argument {
                name: "--verbose",
                separator: Some('='),
                value: Some("value"),
            },
        ],
        handler: handle_option_v,
        description: "Set the level of debug information to *value*.",
        detail: "\tThe higher the integer value is, the more detailed debug\n\
\tinformation is printed to the standard error stream.  A negative\n\
\tvalue makes PRoot quiet except on fatal errors.",
    },
    Opt {
        class: "Regular options",
        arguments: &[
            Argument {
                name: "-V",
                separator: None,
                value: None,
            },
            Argument {
                name: "--version",
                separator: None,
                value: None,
            },
            Argument {
                name: "--about",
                separator: None,
                value: None,
            },
        ],
        handler: handle_option_v_upper,
        description: "Print version, copyright, license and contact, then exit.",
        detail: "",
    },
    Opt {
        class: "Regular options",
        arguments: &[
            Argument {
                name: "-h",
                separator: None,
                value: None,
            },
            Argument {
                name: "--help",
                separator: None,
                value: None,
            },
            Argument {
                name: "--usage",
                separator: None,
                value: None,
            },
        ],
        handler: handle_option_h,
        description: "Print the version and the command-line usage, then exit.",
        detail: "",
    },
    Opt {
        class: "Extension options",
        arguments: &[
            Argument {
                name: "-k",
                separator: Some(' '),
                value: Some("string"),
            },
            Argument {
                name: "--kernel-release",
                separator: Some('='),
                value: Some("string"),
            },
        ],
        handler: handle_option_k,
        description: "Make current kernel appear as kernel release *string*.",
        detail: "\tIf a program is run on a kernel older than the one expected by its\n\
\tGNU C library, the following error is reported: \"FATAL: kernel too\n\
\told\".  To be able to run such programs, PRoot can emulate some of\n\
\tthe features that are available in the kernel release specified by\n\
\t*string* but that are missing in the current kernel.",
    },
    Opt {
        class: "Extension options",
        arguments: &[
            Argument {
                name: "-0",
                separator: None,
                value: None,
            },
            Argument {
                name: "--root-id",
                separator: None,
                value: None,
            },
        ],
        handler: handle_option_0,
        description: "Make current user appear as \"root\" and fake its privileges.",
        detail: "\tSome programs will refuse to work if they are not run with \"root\"\n\
\tprivileges, even if there is no technical reason for that.  This\n\
\tis typically the case with package managers.  This option allows\n\
\tusers to bypass this kind of limitation by faking the user/group\n\
\tidentity, and by faking the success of some operations like\n\
\tchanging the ownership of files, changing the root directory to\n\
\t/, ...  Note that this option is quite limited compared to\n\
\tfakeroot.",
    },
    Opt {
        class: "Extension options",
        arguments: &[
            Argument {
                name: "-i",
                separator: Some(' '),
                value: Some("string"),
            },
            Argument {
                name: "--change-id",
                separator: Some('='),
                value: Some("string"),
            },
        ],
        handler: handle_option_i,
        description: "Make current user and group appear as *string* \"uid:gid\".",
        detail: "\tThis option makes the current user and group appear as uid and\n\
\tgid.  Likewise, files actually owned by the current user and\n\
\tgroup appear as if they were owned by uid and gid instead.\n\
\tNote that the -0 option is the same as -i 0:0.",
    },
    Opt {
        class: "Extension options",
        arguments: &[
            Argument {
                name: "--link2symlink",
                separator: None,
                value: None,
            },
            Argument {
                name: "-l",
                separator: None,
                value: None,
            },
        ],
        handler: handle_option_link2symlink,
        description: "Replace hard links with symlinks, pretending they are really hardlinks",
        detail: "\tEmulates hard links with symbolic links when SELinux policies\n\
\tdo not allow hard links.",
    },
    Opt {
        class: "Extension options",
        arguments: &[Argument {
            name: "--sysvipc",
            separator: None,
            value: None,
        }],
        handler: handle_option_sysvipc,
        description: "Handle System V IPC syscalls in proot",
        detail: "\tHandles System V IPC syscalls (shmget, semget, msgget, etc.)\n\
\tsyscalls inside proot. IPC is handled inside proot and launching 2 proot instances\n\
\twill lead to 2 different IPC Namespaces",
    },
    Opt {
        class: "Extension options",
        arguments: &[Argument {
            name: "-H",
            separator: None,
            value: None,
        }],
        handler: handle_option_h_upper,
        description: "Hide files and directories starting with '.proot.' .",
        detail: "\tHides helper files from directory listings (getdents) so\n\
\tthat guest programs and wildcard expressions do not see or\n\
\tdelete them.  This covers the permission meta files created by\n\
\t-0/-i (prefix .proot-meta-file.) and the links created by -l\n\
\t(prefix .proot.l2s.).",
    },
    Opt {
        class: "Extension options",
        arguments: &[Argument {
            name: "-p",
            separator: None,
            value: None,
        }],
        handler: handle_option_p,
        description: "Modify bindings to protected ports to use a higher port number.",
        detail: "\tPorts below 1024 cannot be bound on kernels with\n\
\tparanoid networking (Android).  This option adds 1024 to the\n\
\tport number of bind(2)/connect(2)-like calls on localhost\n\
\tsockets, so a guest program binding port 80 actually binds\n\
\tport 1080.",
    },
    Opt {
        class: "Extension options",
        arguments: &[Argument {
            name: "-L",
            separator: None,
            value: None,
        }],
        handler: handle_option_l_upper,
        description: "Correct the size returned from lstat for symbolic links.",
        detail: "\tBionic's lstat(2) returns misleading sizes for symlinks.\n\
\tCombined with -l, this makes emulated links report plausible\n\
\tmetadata (size, link count, inode) to guest programs.",
    },
    Opt {
        class: "Alias options",
        arguments: &[Argument {
            name: "-R",
            separator: Some(' '),
            value: Some("path"),
        }],
        handler: handle_option_r_upper,
        description: "Alias: -r *path* + a couple of recommended -b.",
        detail: "\tPrograms isolated in *path*, a guest rootfs, might still need to\n\
\taccess information about the host system, as it is illustrated in\n\
\tthe Examples section of the manual.  These host information\n\
\tare typically: user/group definition, network setup, run-time\n\
\tinformation, users' files, ...  On all Linux distributions, they\n\
\tall lie in a couple of host files and directories that are\n\
\tautomatically bound by this option:\n\
\t\n\
\t    * /etc/host.conf\n\
\t    * /etc/hosts\n\
\t    * /etc/hosts.equiv\n\
\t    * /etc/mtab\n\
\t    * /etc/netgroup\n\
\t    * /etc/networks\n\
\t    * /etc/passwd\n\
\t    * /etc/group\n\
\t    * /etc/nsswitch.conf\n\
\t    * /etc/resolv.conf\n\
\t    * /etc/localtime\n\
\t    * /dev/\n\
\t    * /sys/\n\
\t    * /proc/\n\
\t    * /tmp/\n\
\t    * /run/\n\
\t    * /var/run/dbus/system_bus_socket\n\
\t    * $HOME",
    },
    Opt {
        class: "Alias options",
        arguments: &[Argument {
            name: "-S",
            separator: Some(' '),
            value: Some("path"),
        }],
        handler: handle_option_s_upper,
        description: "Alias: -0 -r *path* + a couple of recommended -b.",
        detail: "\tThis option is useful to safely create and install packages into\n\
\tthe guest rootfs.  It is similar to the -R option expect it\n\
\tenables the -0 option and binds only the following minimal set\n\
\tof paths to avoid unexpected changes on host files:\n\
\t\n\
\t    * /etc/host.conf\n\
\t    * /etc/hosts\n\
\t    * /etc/nsswitch.conf\n\
\t    * /etc/resolv.conf\n\
\t    * /dev/\n\
\t    * /sys/\n\
\t    * /proc/\n\
\t    * /tmp/\n\
\t    * /run/shm\n\
\t    * $HOME",
    },
];

// ------------------------------------------------------------------
// Option handlers
// ------------------------------------------------------------------

fn handle_option_r(tracee: &mut Tracee, value: Option<&str>) -> i32 {
    // `chroot $PATH` == `mount --bind $PATH /`.
    if binding::new_binding(tracee, value.unwrap_or("").as_bytes(), Some(b"/"), true).is_none() {
        return -1;
    }
    0
}

fn handle_option_b(tracee: &mut Tracee, value: Option<&str>) -> i32 {
    let value = value.unwrap_or("");
    let (host, guest) = match value.find(':') {
        Some(i) => (&value[..i], Some(&value[i + 1..])),
        None => (value, None),
    };
    binding::new_binding(tracee, host.as_bytes(), guest.map(|g| g.as_bytes()), true);
    0
}

fn handle_option_q(tracee: &mut Tracee, value: Option<&str>) -> i32 {
    let value = value.unwrap_or("");
    let qemu: Vec<String> = value
        .split(' ')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();
    tracee.qemu = Some(std::rc::Rc::from(qemu));

    binding::new_binding(tracee, b"/", Some(HOST_ROOTFS.as_bytes()), true);
    binding::new_binding(tracee, b"/dev/null", Some(b"/etc/ld.so.preload"), false);
    0
}

fn handle_option_w(tracee: &mut Tracee, value: Option<&str>) -> i32 {
    let mut p = FixedPath::new();
    if p.try_set(value.unwrap_or("").as_bytes()).is_err() {
        return -1;
    }
    tracee.fs.borrow_mut().cwd = p;
    0
}

fn handle_option_kill_on_exit(tracee: &mut Tracee, _value: Option<&str>) -> i32 {
    tracee.killall_on_exit = true;
    0
}

fn handle_option_v(tracee: &mut Tracee, value: Option<&str>) -> i32 {
    let v = match parse_integer_option(value, "-v") {
        Ok(v) => v,
        Err(e) => return e,
    };
    tracee.verbose = v;
    crate::note::GLOBAL_VERBOSE_LEVEL.store(v, Ordering::Relaxed);
    0
}

fn handle_option_v_upper(_tracee: &mut Tracee, _value: Option<&str>) -> i32 {
    print_version(&PROOT_CLI);
    println!("\n{}", PROOT_CLI.colophon);
    EXIT_FAILURE.store(false, Ordering::Relaxed);
    -1
}

fn handle_option_h(tracee: &mut Tracee, _value: Option<&str>) -> i32 {
    print_usage(tracee, &PROOT_CLI, true);
    EXIT_FAILURE.store(false, Ordering::Relaxed);
    -1
}

fn handle_option_k(tracee: &mut Tracee, value: Option<&str>) -> i32 {
    if extension::has_extension(tracee, |e| matches!(e, AnyExtension::Kompat(_))) {
        note(
            Severity::Warning,
            Origin::User,
            format_args!("option -k was already specified"),
        );
        note(
            Severity::Info,
            Origin::User,
            format_args!("only the last -k option is enabled"),
        );
        extension::remove_extension(tracee, |e| matches!(e, AnyExtension::Kompat(_)));
    }
    let status = extension::initialize_extension(
        tracee,
        AnyExtension::Kompat(Default::default()),
        value.unwrap_or(""),
    );
    if status < 0 {
        note(
            Severity::Warning,
            Origin::Internal,
            format_args!("option \"-k {}\" discarded", value.unwrap_or("")),
        );
    }
    0
}

fn handle_option_i(tracee: &mut Tracee, value: Option<&str>) -> i32 {
    if extension::has_extension(tracee, |e| matches!(e, AnyExtension::FakeId0(_))) {
        note(
            Severity::Warning,
            Origin::User,
            format_args!("option -i/-0/-S was already specified"),
        );
        note(
            Severity::Info,
            Origin::User,
            format_args!("only the last -i/-0/-S option is enabled"),
        );
        extension::remove_extension(tracee, |e| matches!(e, AnyExtension::FakeId0(_)));
    }
    let _ = extension::initialize_extension(
        tracee,
        AnyExtension::FakeId0(Default::default()),
        value.unwrap_or(""),
    );
    0
}

fn handle_option_0(tracee: &mut Tracee, _value: Option<&str>) -> i32 {
    handle_option_i(tracee, Some("0:0"))
}

fn handle_option_link2symlink(tracee: &mut Tracee, _value: Option<&str>) -> i32 {
    let status =
        extension::initialize_extension(tracee, AnyExtension::Link2Symlink(Box::default()), "");
    if status < 0 {
        note(
            Severity::Warning,
            Origin::Internal,
            format_args!("link2symlink not initialized"),
        );
    }
    0
}

fn handle_option_sysvipc(tracee: &mut Tracee, _value: Option<&str>) -> i32 {
    let status =
        extension::initialize_extension(tracee, AnyExtension::Sysvipc(Default::default()), "");
    if status < 0 {
        note(
            Severity::Warning,
            Origin::Internal,
            format_args!("sysvipc not initialized"),
        );
    }
    0
}

fn handle_option_l_upper(tracee: &mut Tracee, _value: Option<&str>) -> i32 {
    let _ = extension::initialize_extension(
        tracee,
        AnyExtension::FixSymlinkSize(Default::default()),
        "",
    );
    0
}

fn handle_option_h_upper(tracee: &mut Tracee, _value: Option<&str>) -> i32 {
    let _ =
        extension::initialize_extension(tracee, AnyExtension::HiddenFiles(Default::default()), "");
    0
}

fn handle_option_p(tracee: &mut Tracee, _value: Option<&str>) -> i32 {
    let _ =
        extension::initialize_extension(tracee, AnyExtension::PortSwitch(Default::default()), "");
    0
}

fn new_bindings(tracee: &mut Tracee, bindings: &[&str], value: &str) {
    for b in bindings {
        let path = if *b == "*path*" {
            value.to_string()
        } else {
            expand_front_variable(b)
        };
        binding::new_binding(tracee, path.as_bytes(), None, false);
    }
}

fn handle_option_r_upper(tracee: &mut Tracee, value: Option<&str>) -> i32 {
    let status = handle_option_r(tracee, value);
    if status < 0 {
        return status;
    }
    new_bindings(tracee, RECOMMENDED_BINDINGS, value.unwrap_or(""));
    0
}

fn handle_option_s_upper(tracee: &mut Tracee, value: Option<&str>) -> i32 {
    let status = handle_option_0(tracee, value);
    if status < 0 {
        return status;
    }
    let status = handle_option_r(tracee, value);
    if status < 0 {
        return status;
    }
    new_bindings(tracee, RECOMMENDED_SU_BINDINGS, value.unwrap_or(""));
    0
}

// ------------------------------------------------------------------
// Usage / version
// ------------------------------------------------------------------

/// `print_usage()`.
pub fn print_usage(tracee: &mut Tracee, cli: &Cli, detailed: bool) {
    if detailed {
        println!("{} {}: {}.\n", cli.name, cli.version, cli.subtitle);
    }
    println!("Usage:\n  {}", cli.synopsis);
    if detailed {
        println!();
    }

    let mut current_class = "none";
    for option in cli.options {
        let mut j = 0;
        loop {
            let argument = &option.arguments[j];

            if !detailed && j != 0 {
                println!("\t{}", option.description);
                break;
            }
            if detailed {
                println!("\n\t{}", option.description);
                if !option.detail.is_empty() {
                    println!("\n{}\n", option.detail);
                } else {
                    println!();
                }
                break;
            }
            if option.class != current_class {
                current_class = option.class;
                println!("\n{}:", current_class);
            }
            if j == 0 {
                print!("  {}", argument.name);
            } else {
                print!(", {}", argument.name);
            }
            if let Some(sep) = argument.separator {
                print!("{}*{}*", sep, argument.value.unwrap_or(""));
            } else {
                print!("\t");
            }
            j += 1;
            if j >= option.arguments.len() {
                println!("\n\t{}", option.description);
                break;
            }
        }
    }

    let _ = extension::notify(tracee, &mut extension::Event::PrintUsage { detailed });

    if detailed {
        println!("{}", cli.colophon);
    }
}

/// `print_version()`.
pub fn print_version(cli: &Cli) {
    println!("{} {}\n", cli.logo, cli.version);
    println!("built-in accelerators: process_vm = yes, seccomp_filter = yes");
}

fn print_execve_help(argv0: &str, status: i32) {
    note(
        Severity::Error,
        Origin::System,
        format_args!("execve(\"{}\")", argv0),
    );

    // termux-exec can prepend a prefix that doesn't exist inside proot.
    if status == -libc::ENOENT {
        if let Ok(ld) = std::env::var("LD_PRELOAD") {
            if ld.contains("libtermux-exec.so") {
                note(
                    Severity::Info,
                    Origin::User,
                    format_args!(
"It seems that termux-exec is active and is prepending /data/data/com.termux/... to executable paths
If this is path is not available inside proot, please \"unset LD_PRELOAD\""),
                );
                return;
            }
        }
    }

    if status == -libc::EPERM && std::env::var_os("PROOT_NO_SECCOMP").is_none() {
        note(Severity::Info, Origin::User, format_args!(
"It seems your kernel contains this bug: https://bugs.launchpad.net/ubuntu/+source/linux/+bug/1202161
To workaround it, set the env. variable PROOT_NO_SECCOMP to 1."));
        return;
    }

    note(
        Severity::Info,
        Origin::User,
        format_args!(
            "possible causes:
  * the program is a script but its interpreter (eg. /bin/sh) was not found;
  * the program is an ELF but its interpreter (eg. ld-linux.so) was not found;
  * the program is a foreign binary but qemu was not specified;
  * qemu does not work correctly (if specified);
  * the loader was not found or doesn't work."
        ),
    );
}

fn print_argv(prompt: &str, argv: &[String]) {
    let mut string = String::with_capacity(4096);
    string.push_str(prompt);
    string.push_str(" =");
    for a in argv {
        if string.len() + a.len() + 1 >= 4096 {
            break;
        }
        string.push(' ');
        string.push_str(a);
    }
    note(Severity::Info, Origin::User, format_args!("{}", string));
}

fn print_config(tracee: &Tracee, argv: &[String]) {
    if tracee.verbose <= 0 {
        return;
    }
    if tracee.qemu.is_some() {
        note(
            Severity::Info,
            Origin::User,
            format_args!("host rootfs = {}", HOST_ROOTFS),
        );
    }
    if let Some(glue) = &tracee.glue {
        note(
            Severity::Info,
            Origin::User,
            format_args!("glue rootfs = {}", glue),
        );
    }
    if let Some(exe) = &tracee.exe {
        note(Severity::Info, Origin::User, format_args!("exe = {}", exe));
    }
    print_argv("argv", argv);
    if let Some(qemu) = &tracee.qemu {
        print_argv("qemu", qemu);
    }
    note(
        Severity::Info,
        Origin::User,
        format_args!("initial cwd = {}", tracee.fs.borrow().cwd),
    );
    note(
        Severity::Info,
        Origin::User,
        format_args!("verbose level = {}", tracee.verbose),
    );
}

// ------------------------------------------------------------------
// Initialization helpers
// ------------------------------------------------------------------

/// `initialize_cwd()` — canonicalize fs.cwd in the guest namespace.
fn initialize_cwd(tracee: &mut Tracee) -> Result<(), i32> {
    let cwd = tracee.fs.borrow().cwd.clone();

    let mut base = PathGuard::new();
    if cwd.as_bytes().first() != Some(&b'/') {
        // Relative cwd: resolved against the (reconfigured) tracee's cwd.
        match tracee
            .reconf_tracee
            .and_then(|id| tracee::get_tracee(id as i32, false))
        {
            Some(rc) => {
                let t = rc.borrow();
                path::getcwd2(Some(&t), &mut base)?;
            }
            None => path::getcwd2(None, &mut base)?,
        }
    } else {
        base.set(b"/");
    }

    // The trailing "." forces canonicalize() to check it's a real directory.
    let mut path2 = FixedPath::new();
    path2.push_component(base.as_bytes())?;
    path2.push_component(cwd.as_bytes())?;
    path2.push_component(b".")?;

    let mut path = FixedPath::from_bytes(b"/");
    if let Err(e) = canon::canonicalize(tracee, path2.as_bytes(), true, &mut path, 0) {
        note(
            Severity::Warning,
            Origin::User,
            format_args!(
                "can't chdir(\"{}\") in the guest rootfs: {}",
                path2,
                crate::path::binding::io_error_string(-e)
            ),
        );
        note(
            Severity::Info,
            Origin::User,
            format_args!("default working directory is now \"/\""),
        );
        path.set(b"/");
    }
    path.chop_finality();

    tracee.fs.borrow_mut().cwd.set(path.as_bytes());
    let value = path.as_c_str();
    crate::sys::setenv(c"PWD", value, true);
    Ok(())
}

/// `initialize_exe()` — resolve `exe` guest-side and store it.
fn initialize_exe(tracee: &mut Tracee, exe: Option<&str>) -> Result<(), i32> {
    let exe = exe.unwrap_or("/bin/sh");
    let reconf_paths = tracee.reconf_paths.clone();
    let mut path = PathGuard::new();
    path::which(
        Some(tracee),
        reconf_paths.as_deref(),
        &mut path,
        exe.as_bytes(),
    )?;
    path::detranslate_path(tracee, &mut path, None)?;
    tracee.exe = Some(std::rc::Rc::from(
        String::from_utf8_lossy(path.as_bytes()).into_owned(),
    ));
    Ok(())
}

/// `post_initialize_exe()` — resolve tracee.qemu[0] to a host path.
fn post_initialize_exe(tracee: &mut Tracee) -> Result<(), i32> {
    if tracee.qemu.is_none() {
        return Ok(());
    }
    let qemu0 = tracee.qemu.as_ref().unwrap()[0].clone();
    let reconf_paths = tracee.reconf_paths.clone();
    let mut path = PathGuard::new();
    // With no sub-reconfiguration, resolve against the host namespace.
    match tracee
        .reconf_tracee
        .and_then(|id| tracee::get_tracee(id as i32, false))
    {
        Some(rc) => {
            let mut t = rc.borrow_mut();
            path::which(
                Some(&mut t),
                reconf_paths.as_deref(),
                &mut path,
                qemu0.as_bytes(),
            )?;
            path::detranslate_path(&mut t, &mut path, None)?;
        }
        None => {
            path::which(None, reconf_paths.as_deref(), &mut path, qemu0.as_bytes())?;
        }
    }
    if let Some(qemu) = &tracee.qemu {
        let mut q = qemu.to_vec();
        q[0] = String::from_utf8_lossy(path.as_bytes()).into_owned();
        tracee.qemu = Some(std::rc::Rc::from(q));
    }
    Ok(())
}

/// `pre_initialize_bindings()` — default -w "." and -r "/".
fn pre_initialize_bindings(tracee: &mut Tracee) -> Result<(), i32> {
    if tracee.fs.borrow().cwd.is_empty() {
        handle_option_w(tracee, Some("."));
    }
    if binding::with_root(tracee, |r| r.is_empty()) {
        handle_option_r(tracee, Some("/"));
    }
    Ok(())
}

// ------------------------------------------------------------------
// parse_config()
// ------------------------------------------------------------------

/// Returns the index of the command in `argv`, or an error.
pub fn parse_config(tracee: &mut Tracee, args: &[String]) -> Result<usize, i32> {
    let cli = &PROOT_CLI;
    crate::note::set_tool_name("proot");

    if args.len() == 1 {
        print_usage(tracee, cli, false);
        return Err(-1);
    }

    let argc = args.len();
    let mut i = 1usize;
    let mut pending: Option<(&str, Handler)> = None;

    'outer: while i < argc {
        let arg = args[i].as_str();

        if let Some((_, handler)) = pending.take() {
            if handler(tracee, Some(arg)) < 0 {
                return Err(-1);
            }
            i += 1;
            continue;
        }

        if !arg.starts_with('-') {
            break;
        }

        for option in cli.options {
            for argument in option.arguments {
                let name = argument.name;
                if !arg.starts_with(name) {
                    continue;
                }

                let rest = &arg[name.len()..];
                let sep = argument.separator.map_or(b'\0', |c| c as u8);
                // Ambiguity: extra characters that aren't the separator.
                if !rest.is_empty() && rest.as_bytes()[0] != sep {
                    print_error_separator(argument);
                    return Err(-1);
                }

                if argument.value.is_none() {
                    if (option.handler)(tracee, None) < 0 {
                        return Err(-1);
                    }
                    i += 1;
                    continue 'outer;
                }

                if !rest.is_empty() && rest.as_bytes()[0] == sep {
                    if (option.handler)(tracee, Some(&rest[1..])) < 0 {
                        return Err(-1);
                    }
                    i += 1;
                    continue 'outer;
                }

                if argument.separator != Some(' ') {
                    print_error_separator(argument);
                    return Err(-1);
                }

                // Value comes from the next argument.
                pending = Some((name, option.handler));
                if i == argc - 1 {
                    note(
                        Severity::Error,
                        Origin::User,
                        format_args!("missing value for option '{}'.", arg),
                    );
                    return Err(-1);
                }
                i += 1;
                continue 'outer;
            }
        }

        note(
            Severity::Error,
            Origin::User,
            format_args!("unknown option '{}'.", arg),
        );
        return Err(-1);
    }
    let argc_offset = i;

    // The guest rootfs is known: user bindings can be canonicalized.
    pre_initialize_bindings(tracee)?;
    binding::initialize_bindings(tracee);
    initialize_cwd(tracee)?;
    initialize_exe(tracee, args.get(argc_offset).map(|s| s.as_str()))?;
    post_initialize_exe(tracee)?;

    if tracee.verbose > 0 {
        print_config(tracee, &args[argc_offset.min(argc)..]);
    }

    Ok(argc_offset)
}

fn print_error_separator(argument: &Argument) {
    match argument.separator {
        None => note(
            Severity::Error,
            Origin::User,
            format_args!("option '{}' expects no value.", argument.name),
        ),
        Some(sep) => note(
            Severity::Error,
            Origin::User,
            format_args!(
                "option '{}' and its value must be separated by '{}'.",
                argument.name, sep
            ),
        ),
    }
}

/// `parse_integer_option()`.
fn parse_integer_option(value: Option<&str>, option: &str) -> Result<i32, i32> {
    match value.unwrap_or("").parse::<i32>() {
        Ok(v) => Ok(v),
        Err(_) => {
            note(
                Severity::Error,
                Origin::User,
                format_args!("option `{}` expects an integer value.", option),
            );
            Err(-1)
        }
    }
}

/// `expand_front_variable()` — expand a leading `$VAR` from the environment.
fn expand_front_variable(string: &str) -> String {
    if !string.starts_with('$') {
        return string.to_string();
    }
    match string.find('/') {
        None => std::env::var(&string[1..]).unwrap_or_else(|_| string.to_string()),
        Some(pos) => {
            if pos <= 1 {
                return string.to_string();
            }
            match std::env::var(&string[1..pos]) {
                Ok(v) => format!("{}{}", v, &string[pos..]),
                Err(_) => string.to_string(),
            }
        }
    }
}

// ------------------------------------------------------------------
// Entry point
// ------------------------------------------------------------------

/// `main()` — port of cli/cli.c's main.
pub fn run(tracee_rc: &TraceeRef, args: &[String]) -> i32 {
    {
        let mut t = tracee_rc.borrow_mut();
        let pid = crate::sys::getpid();
        let old_key = t.pid;
        t.pid = pid;
        drop(t);
        // Re-key the placeholder (pid 0) under the real pid — a stale pid-0
        // entry would make kill_all_tracees() signal our whole process group.
        tracee::unregister(old_key);
        tracee::register_existing(tracee_rc, pid);

        let mut t = tracee_rc.borrow_mut();
        if let Ok(v) = std::env::var("PROOT_VERBOSE") {
            if let Ok(v) = v.parse::<i32>() {
                t.verbose = v;
                crate::note::GLOBAL_VERBOSE_LEVEL.store(v, Ordering::Relaxed);
            }
        }
    }

    let status = {
        let mut t = tracee_rc.borrow_mut();
        match parse_config(&mut t, args) {
            Ok(i) => i as i32,
            Err(e) => e,
        }
    };
    if status < 0 {
        return -1;
    }
    let argc_offset = status as usize;

    if std::env::var_os("PROOT_NO_MOUNTINFO").is_none() {
        let mut t = tracee_rc.borrow_mut();
        let _ = extension::initialize_extension(
            &mut t,
            AnyExtension::Mountinfo(Default::default()),
            "",
        );
    }

    let argv_tail: Vec<String> = args[argc_offset..].to_vec();
    let status = tracee::event::launch_process(tracee_rc, &argv_tail);
    if status < 0 {
        let exe = tracee_rc.borrow().exe.clone();
        print_execve_help(exe.as_deref().unwrap_or(""), status);
        return -1;
    }

    tracee::event::event_loop()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{TempDir, env_lock};

    #[test]
    fn parse_integer_option_values() {
        assert_eq!(parse_integer_option(Some("3"), "-v"), Ok(3));
        assert_eq!(parse_integer_option(Some("-1"), "-v"), Ok(-1));
        assert_eq!(parse_integer_option(Some("abc"), "-v"), Err(-1));
        assert_eq!(parse_integer_option(None, "-v"), Err(-1));
    }

    #[test]
    fn expand_front_variable_cases() {
        let _g = env_lock();
        crate::testutil::with_env("PROOT_TEST_EFV", Some("/BASE"), || {
            assert_eq!(expand_front_variable("$PROOT_TEST_EFV/sub"), "/BASE/sub");
            assert_eq!(expand_front_variable("$PROOT_TEST_EFV"), "/BASE");
        });
        crate::testutil::with_env("PROOT_TEST_EFV", Option::<&str>::None, || {
            // Unset -> literal passthrough.
            assert_eq!(
                expand_front_variable("$PROOT_TEST_EFV/x"),
                "$PROOT_TEST_EFV/x"
            );
            assert_eq!(expand_front_variable("$PROOT_TEST_EFV"), "$PROOT_TEST_EFV");
        });
        // No '$' -> unchanged.
        assert_eq!(expand_front_variable("/plain/path"), "/plain/path");
        // "$" alone -> unchanged (pos<=1 guard).
        assert_eq!(expand_front_variable("$/x"), "$/x");
        assert_eq!(expand_front_variable("$"), "$");
    }

    #[test]
    fn handle_option_b_splits_host_guest() {
        let td = TempDir::new("cli");
        td.dir("h");
        let mut t = Tracee::default();
        let host = td.abs("h");
        let v = format!("{}:/g", String::from_utf8_lossy(&host));
        assert_eq!(handle_option_b(&mut t, Some(&v)), 0);
        // The binding lands in the pending list with the right endpoints.
        let p = t.fs.borrow().pending.clone();
        assert!(
            p.iter()
                .any(|b| b.guest.as_bytes() == b"/g" && b.host.as_bytes() == host.as_slice())
        );
        // "host:" with empty guest part.
        let v = format!("{}:", String::from_utf8_lossy(&host));
        assert_eq!(handle_option_b(&mut t, Some(&v)), 0);
    }

    #[test]
    fn handle_option_w_sets_cwd() {
        let mut t = Tracee::default();
        assert_eq!(handle_option_w(&mut t, Some("/work")), 0);
        assert_eq!(t.fs.borrow().cwd.as_bytes(), b"/work");
    }

    #[test]
    fn handle_option_q_sets_qemu_and_rootfs_binding() {
        let mut t = Tracee::default();
        assert_eq!(handle_option_q(&mut t, Some("qemu-arm -0")), 0);
        let q = t.qemu.as_ref().unwrap();
        assert_eq!(&**q, &["qemu-arm".to_string(), "-0".to_string()]);
        // /host-rootfs + ld.so.preload bindings are queued.
        let p = t.fs.borrow().pending.clone();
        assert!(
            p.iter()
                .any(|b| b.guest.as_bytes() == HOST_ROOTFS.as_bytes())
        );
        assert!(
            p.iter()
                .any(|b| b.guest.as_bytes() == b"/etc/ld.so.preload")
        );
    }

    #[test]
    fn handle_option_i_registers_fake_id0() {
        let mut t = Tracee::default();
        assert_eq!(handle_option_i(&mut t, Some("1000:1000")), 0);
        assert!(extension::has_extension(&t, |e| matches!(
            e,
            AnyExtension::FakeId0(_)
        )));
        // Second -i replaces rather than stacks.
        assert_eq!(handle_option_i(&mut t, Some("0:0")), 0);
        let n = t
            .extensions
            .iter()
            .filter(|e| matches!(e, Some(AnyExtension::FakeId0(_))))
            .count();
        assert_eq!(n, 1);
    }

    #[test]
    fn handle_option_0_implies_root() {
        let mut t = Tracee::default();
        assert_eq!(handle_option_0(&mut t, None), 0);
        assert!(extension::has_extension(&t, |e| matches!(
            e,
            AnyExtension::FakeId0(_)
        )));
    }

    #[test]
    fn flag_options_register_extensions() {
        let mut t = Tracee::default();
        assert_eq!(handle_option_link2symlink(&mut t, None), 0);
        assert!(extension::has_extension(&t, |e| matches!(
            e,
            AnyExtension::Link2Symlink(_)
        )));
        assert_eq!(handle_option_l_upper(&mut t, None), 0);
        assert!(extension::has_extension(&t, |e| matches!(
            e,
            AnyExtension::FixSymlinkSize(_)
        )));
        assert_eq!(handle_option_h_upper(&mut t, None), 0);
        assert!(extension::has_extension(&t, |e| matches!(
            e,
            AnyExtension::HiddenFiles(_)
        )));
        assert_eq!(handle_option_p(&mut t, None), 0);
        assert!(extension::has_extension(&t, |e| matches!(
            e,
            AnyExtension::PortSwitch(_)
        )));
        assert_eq!(handle_option_sysvipc(&mut t, None), 0);
        assert!(extension::has_extension(&t, |e| matches!(
            e,
            AnyExtension::Sysvipc(_)
        )));
    }

    /// A parse_config-ready args vector: proot + given args + cmd.
    fn args(tail: &[&str]) -> Vec<String> {
        let mut v = vec!["proot".to_string()];
        v.extend(tail.iter().map(|s| s.to_string()));
        v
    }

    #[test]
    fn parse_config_finds_command_index() {
        let _g = env_lock();
        let td = TempDir::new("cli");
        td.dir("bin");
        td.file_mode("bin/echo", b"#!/bin/sh\n", 0o755);
        let root = td.path().to_str().unwrap().to_string();
        let mut t = Tracee::default();
        let v = args(&["-r", &root, "/bin/echo", "hello"]);
        let idx = parse_config(&mut t, &v).unwrap();
        assert_eq!(idx, 3); // "/bin/echo"
        assert_eq!(t.exe.as_deref(), Some("/bin/echo"));
    }

    #[test]
    fn parse_config_missing_value_fails() {
        let _g = env_lock();
        let mut t = Tracee::default();
        // "-r" as the last arg: value expected.
        let v = args(&["-r"]);
        assert!(parse_config(&mut t, &v).is_err());
        let mut t = Tracee::default();
        let v = args(&["-v"]);
        assert!(parse_config(&mut t, &v).is_err());
    }

    #[test]
    fn parse_config_unknown_option_fails() {
        let _g = env_lock();
        let mut t = Tracee::default();
        let v = args(&["--frobnicate-x", "cmd"]);
        assert!(parse_config(&mut t, &v).is_err());
    }

    #[test]
    fn parse_config_bad_separator_fails() {
        let _g = env_lock();
        let mut t = Tracee::default();
        // -b uses ':' separator semantics: "-bX" (no space sep allowed
        // after prefix match rules) — "-bx" parses as flag with junk.
        let v = args(&["-vx", "cmd"]);
        assert!(parse_config(&mut t, &v).is_err());
    }

    #[test]
    fn parse_config_combined_flags() {
        let _g = env_lock();
        let td = TempDir::new("cli");
        td.dir("bin");
        td.dir("work");
        td.file_mode("bin/echo", b"#!/bin/sh\n", 0o755);
        let root = td.path().to_str().unwrap().to_string();
        let mut t = Tracee::default();
        let v = args(&["-r", &root, "-0", "-w", "/work", "-v", "0", "/bin/echo"]);
        let idx = parse_config(&mut t, &v).unwrap();
        assert_eq!(idx, 8); // "-v" consumes "0" as its value arg.
        assert_eq!(t.fs.borrow().cwd.as_bytes(), b"/work");
        assert!(extension::has_extension(&t, |e| matches!(
            e,
            AnyExtension::FakeId0(_)
        )));
        assert_eq!(t.verbose, 0);
    }

    #[test]
    fn parse_config_single_arg_prints_usage() {
        // Just "proot" -> usage + error.
        let mut t = Tracee::default();
        assert!(parse_config(&mut t, &args(&[])).is_err());
    }

    #[test]
    fn parse_config_inline_separator() {
        let _g = env_lock();
        let td = TempDir::new("cli");
        td.dir("bin");
        td.file_mode("bin/echo", b"#!/bin/sh\n", 0o755);
        let root = td.path().to_str().unwrap().to_string();
        // -b host:guest (':'-separated value after space).
        let host = td.abs("bin");
        let bind = format!("{}:/b", String::from_utf8_lossy(&host));
        let mut t = Tracee::default();
        let v = args(&["-r", &root, "-b", &bind, "/bin/echo"]);
        assert_eq!(parse_config(&mut t, &v).unwrap(), 5);
        // /b bound into the guest namespace after initialization.
        let b = binding::get_binding(&t, crate::path::Side::Guest, b"/b");
        assert!(
            b.is_some()
                || t.fs
                    .borrow()
                    .pending
                    .iter()
                    .any(|b| b.guest.as_bytes() == b"/b")
        );
    }
}
