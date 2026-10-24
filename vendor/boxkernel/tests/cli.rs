//! CLI surface: help/version, option parsing errors, no-command usage.

mod common;
use common::*;

#[test]
fn version_prints_banner_and_succeeds() {
    let out = run(&["--version"], &[]);
    assert_eq!(out.status.code(), Some(0));
    let s = stdout(&out);
    assert!(s.contains("BoxKernel"), "version output: {s}");
    assert!(s.contains("5.1.0"), "version output: {s}");
    assert!(s.contains("process_vm = yes"), "version output: {s}");
}

#[test]
fn help_lists_options() {
    let out = run(&["--help"], &[]);
    assert_eq!(out.status.code(), Some(0));
    let s = stdout(&out);
    // Detailed usage prints descriptions; check a few option texts.
    for needle in [
        "Usage",
        "guest root file-system",
        "accessible in the guest rootfs",
        "Execute guest programs through QEMU",
        "working directory",
    ] {
        assert!(s.contains(needle), "help missing {needle:?}:\n{s}");
    }
}

#[test]
fn no_args_prints_usage_and_fails() {
    let out = run(&[], &[]);
    assert!(!out.status.success());
    assert!(
        stdout(&out).contains("Usage"),
        "no usage:\n{}",
        stdout(&out)
    );
}

#[test]
fn unknown_option_is_rejected() {
    let out = run(&["--definitely-not-an-option"], &[]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("unknown option"),
        "stderr: {}",
        stderr(&out)
    );
}

#[test]
fn missing_option_value_is_rejected() {
    let out = run(&["-r"], &[]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("missing value"),
        "stderr: {}",
        stderr(&out)
    );
}

#[test]
fn wrong_separator_is_rejected() {
    // `-r` takes a space-separated value; `-r=/` must be rejected.
    let out = run(&["-r=/", SH, "-c", "true"], &[]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("separated by"),
        "stderr: {}",
        stderr(&out)
    );
}

#[test]
fn long_option_separator_works() {
    let out = run_ok(&["--rootfs=/", "/bin/true"], &[]);
    assert_eq!(stdout(&out), "");
}

#[test]
fn option_stop_at_first_command() {
    // Words after the command are argv, not options — `-z` lands in $0/$1.
    let out = run_ok(
        &["-r", "/", SH, "-c", "echo \"$0:$1:$#\"", "cmd", "-z"],
        &[],
    );
    assert_eq!(stdout(&out).trim(), "cmd:-z:1");
}
