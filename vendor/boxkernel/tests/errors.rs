//! Error paths: bad options, missing paths, unexecutable commands,
//! confinement violations — each must fail cleanly (no hang, no crash).

mod common;
use common::*;

#[test]
fn command_not_found_reports_error() {
    let out = run(&["/no/such/binary"], &[]);
    assert!(!out.status.success());
    assert!(!stderr(&out).is_empty());
}

#[test]
fn directory_as_command_fails() {
    let out = run(&["/tmp"], &[]);
    assert!(!out.status.success());
}

#[test]
fn relative_command_resolved_via_path() {
    // `sh` (no slash) must be found on PATH inside the traced exec.
    let out = run(&["sh", "-c", "echo via-path"], &[]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out).trim(), "via-path");
}

#[test]
fn bad_workdir_warns_and_falls_back() {
    // C parity: an unreachable `-w` produces a warning and cwd="/",
    // not a fatal error.
    let out = run_ok(&["-w", "/no/such/dir", SH, "-c", "echo still-ran"], &[]);
    assert_eq!(stdout(&out).trim(), "still-ran");
    assert!(
        stderr(&out).contains("can't chdir"),
        "stderr: {}",
        stderr(&out)
    );
}

#[test]
fn inaccessible_guest_path_reports_enoent() {
    let out = run(
        &[
            "-r",
            "/",
            SH,
            "-c",
            "cat /no/such/file 2>/dev/null; echo code=$?",
        ],
        &[],
    );
    // cat fails inside the tracee; the shell reports the errno path.
    assert!(out.status.success());
    assert!(stdout(&out).contains("code=1"));
}

#[test]
fn guest_escape_attempt_blocked() {
    let f = rootfs("err-esc");
    let out = run_rooted(
        &f,
        &[],
        "ls /../../../../etc/hostname >/dev/null 2>&1 && echo ESCAPED || echo contained",
    );
    assert!(out.status.success());
    assert_eq!(stdout(&out).trim(), "contained");
}

#[test]
fn tracee_exit_failure_propagates() {
    let out = run(&[SH, "-c", "false"], &[]);
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn signal_termination_propagates_status() {
    // Tracee kills itself; proot must report the termination status
    // (128+sig convention or raw — either way non-zero, not a hang).
    let out = run(&[SH, "-c", "kill -TERM $$"], &[]);
    assert!(!out.status.success());
}
