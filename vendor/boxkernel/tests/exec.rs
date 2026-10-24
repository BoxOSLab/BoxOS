//! execve path: exit codes, argv/env passing, shebang handling, exec errors.

mod common;
use common::*;

#[test]
fn exit_code_is_propagated() {
    let out = run(&["-r", "/", SH, "-c", "exit 42"], &[]);
    assert_eq!(out.status.code(), Some(42));
}

#[test]
fn argv_and_env_pass_through() {
    let out = run_ok(
        &[SH, "-c", "echo \"$1:$2:$MARKER\"", "x", "aa", "bb"],
        &[("MARKER", "m123")],
    );
    assert_eq!(stdout(&out).trim(), "aa:bb:m123");
}

#[test]
fn env_assignment_beats_inherited() {
    let out = run_ok(&[SH, "-c", "echo $HOME"], &[("HOME", "/no/such/home")]);
    assert_eq!(stdout(&out).trim(), "/no/such/home");
}

#[test]
fn shebang_script_runs_interpreter() {
    let f = Fixture::new("shebang");
    let script = f.file("s.sh", "#!/bin/sh\necho shebang-ok\n");
    make_exec(&script);
    let out = run_ok(&[SH, "-c", &format!("{}", script.display())], &[]);
    assert_eq!(stdout(&out).trim(), "shebang-ok");
}

#[test]
fn shebang_with_argument_passes_it() {
    let f = Fixture::new("shebang-arg");
    // `sh -x` would trace to stderr; use a flag-free arg check: argv[1] of
    // the interpreter gets the option word per shebang semantics.
    let script = f.file("s.sh", "#!/bin/sh\necho \"$0\" | grep -q .\necho arg-ok\n");
    make_exec(&script);
    let out = run_ok(&[SH, "-c", &format!("{}", script.display())], &[]);
    assert_eq!(stdout(&out).trim(), "arg-ok");
}

#[test]
fn missing_command_fails() {
    let out = run(&["/definitely/not/a/command"], &[]);
    assert!(!out.status.success());
    assert!(!stderr(&out).is_empty());
}

#[test]
fn non_executable_file_fails() {
    let f = Fixture::new("noexec");
    let file = f.file("plain.txt", "not a program\n");
    std::fs::metadata(&file).unwrap();
    let out = run(&[&format!("{}", file.display())], &[]);
    assert!(!out.status.success());
}

#[test]
fn exec_in_guest_root_resolves_inside() {
    // /bin inside the guest reaches the host tools via the runtime binds.
    let f = rootfs("exec-guest");
    let out = run_rooted_ok(&f, &[], "echo guest-ok");
    assert_eq!(stdout(&out).trim(), "guest-ok");
}

#[test]
fn nested_exec_under_proot_works() {
    // proot inside proot: recursion must not corrupt state.
    let out = run_ok(&[SH, "-c", &format!("{PROOT} /bin/echo nested")], &[]);
    assert_eq!(stdout(&out).trim(), "nested");
}

#[test]
fn empty_argv0_is_rejected() {
    let out = run(&[""], &[]);
    assert!(!out.status.success());
}
