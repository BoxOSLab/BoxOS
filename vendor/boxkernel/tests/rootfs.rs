//! `-r` root confinement: path translation through the rootfs binding,
//! containment, cwd, and guest write isolation.

mod common;
use common::*;

#[test]
fn guest_root_maps_to_host_dir() {
    let f = rootfs("r-map");
    f.file("only-in-guest.txt", "guest-data\n");
    let out = run_rooted_ok(&f, &[], "cat /only-in-guest.txt");
    assert_eq!(stdout(&out), "guest-data\n");
}

#[test]
fn host_file_outside_rootfs_is_invisible() {
    let f = rootfs("r-hide");
    let host = Fixture::new("r-hide-host");
    let secret = host.file("secret.txt", "nope\n");
    let out = run_rooted(
        &f,
        &[],
        &format!(
            "test -f {} && echo LEAKED || echo confined",
            secret.display()
        ),
    );
    assert!(out.status.success());
    assert_eq!(stdout(&out).trim(), "confined");
}

#[test]
fn pwd_inside_rootfs_is_root() {
    let f = rootfs("r-pwd");
    let out = run_rooted_ok(&f, &[], "pwd");
    assert_eq!(stdout(&out).trim(), "/");
}

#[test]
fn relative_cwd_translation() {
    let f = rootfs("r-cwd");
    f.dir("workdir");
    f.file("workdir/here.txt", "cwd\n");
    let out = run_rooted_ok(&f, &["-w", "/workdir"], "cat here.txt");
    assert_eq!(stdout(&out), "cwd\n");
}

#[test]
fn symlink_escape_stays_confined() {
    // A symlink in the guest pointing at a host path resolves *inside*
    // the guest, so it must not reach the host file.
    let f = rootfs("r-esc");
    let host = Fixture::new("r-esc-host");
    host.file("topsecret", "host\n");
    f.symlink(&host.root.display().to_string(), "esc");
    let out = run_rooted(&f, &[], "cat /esc/topsecret; echo rc=$?");
    assert!(out.status.success());
    let s = stdout(&out);
    assert!(!s.contains("host\n"), "out: {s}");
    assert!(s.contains("rc="), "out: {s}");
}

#[test]
fn dotdot_at_root_stays_at_root() {
    let f = rootfs("r-dotdot");
    f.file("marker.txt", "at-root\n");
    let out = run_rooted_ok(&f, &[], "cat /../marker.txt");
    assert_eq!(stdout(&out), "at-root\n");
}

#[test]
fn guest_tmp_is_writable() {
    let f = rootfs("r-tmpw");
    let out = run_rooted_ok(&f, &[], "echo hi > /tmp/x && cat /tmp/x");
    assert_eq!(stdout(&out), "hi\n");
    assert!(f.root.join("tmp/x").exists());
}

#[test]
fn nonexistent_rootfs_fails() {
    let out = run(&["-r", "/definitely/no/such/rootfs", SH, "-c", "true"], &[]);
    assert!(!out.status.success());
}

#[test]
fn rootfs_file_not_dir_fails() {
    let f = Fixture::new("r-file");
    let file = f.file("afile", "x");
    let out = run(
        &["-r", &format!("{}", file.display()), SH, "-c", "true"],
        &[],
    );
    assert!(!out.status.success());
}
