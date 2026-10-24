//! Process machinery: fork/clone tracing, wait, pipes, process trees,
//! and multi-tracee bookkeeping end-to-end.

mod common;
use common::*;

#[test]
fn forked_child_is_traced() {
    // A child spawned by the tracee runs under the same virtualization.
    let f = Fixture::new("fork");
    let file = f.file("kid.txt", "from-child\n");
    let out = run_ok(
        &[
            "-r",
            "/",
            SH,
            "-c",
            &format!("(cat {} ) & wait", file.display()),
        ],
        &[],
    );
    assert_eq!(stdout(&out), "from-child\n");
}

#[test]
fn pipeline_joins_tracees() {
    let out = run_ok(&[SH, "-c", "echo abc | tr a-z A-Z"], &[]);
    assert_eq!(stdout(&out).trim(), "ABC");
}

#[test]
fn exit_status_aggregates_last() {
    let out = run(&[SH, "-c", "exit 7"], &[]);
    assert_eq!(out.status.code(), Some(7));
}

#[test]
fn many_children_all_complete() {
    let out = run_ok(
        &[
            SH,
            "-c",
            "i=0; while [ $i -lt 8 ]; do (true) & i=$((i+1)); done; wait; echo done",
        ],
        &[],
    );
    assert_eq!(stdout(&out).trim(), "done");
}

#[test]
fn double_fork_grandchild_traced() {
    let f = Fixture::new("grand");
    let out = run_ok(
        &[
            "-r",
            "/",
            "-b",
            &format!("{}:/g", f.root.display()),
            SH,
            "-c",
            "( ( echo grandchild > /g/out.txt ) ) ; sleep 0.2; cat /g/out.txt",
        ],
        &[],
    );
    assert_eq!(stdout(&out).trim(), "grandchild");
}

#[test]
fn orphan_reaping_does_not_hang() {
    // Background a child and exit without wait — proot must not hang.
    let out = run(&[SH, "-c", "(sleep 0.3) & exit 0"], &[]);
    assert!(out.status.success());
}

#[test]
fn ttyless_background_io() {
    let out = run_ok(
        &[
            SH,
            "-c",
            "{ sleep 0.1; echo late; } & { echo early; } ; wait",
        ],
        &[],
    );
    let s = stdout(&out);
    assert!(s.contains("early") && s.contains("late"), "out: {s}");
}

#[test]
fn zombie_is_reaped() {
    // Spawn and reap repeatedly; leaked zombies would exhaust the
    // tracee table on long loops — a short loop at least proves reaping.
    let out = run_ok(
        &[
            SH,
            "-c",
            "i=0; while [ $i -lt 20 ]; do sh -c 'true'; i=$((i+1)); done; echo reaped",
        ],
        &[],
    );
    assert_eq!(stdout(&out).trim(), "reaped");
}
