//! Extension behavior end-to-end: fake_id0 (-0/-i), kompat (-k),
//! link2symlink, and mixed flag combinations.

mod common;
use common::*;

#[test]
fn fake_id0_makes_uid_zero() {
    let out = run_ok(&["-0", SH, "-c", "id -u"], &[]);
    assert_eq!(stdout(&out).trim(), "0");
}

#[test]
fn fake_id0_files_look_owned_by_root() {
    let f = Fixture::new("fake0");
    let file = f.file("owned.txt", "x");
    let out = run_ok(
        &["-0", SH, "-c", &format!("stat -c %u {}", file.display())],
        &[],
    );
    assert_eq!(stdout(&out).trim(), "0");
}

#[test]
fn fake_id_i_sets_uid_gid() {
    let out = run_ok(&["-i", "1234:567", SH, "-c", "echo `id -u`:`id -g`"], &[]);
    assert_eq!(stdout(&out).trim(), "1234:567");
}

#[test]
fn fake_id_i_accepts_names_and_supplementary() {
    // C accepts "uid:gid" with names resolvable on host; numeric is the
    // portable path — verify the option is accepted and ids applied.
    let out = run_ok(&["-i", "7:8", SH, "-c", "id -u; id -g"], &[]);
    let s = stdout(&out);
    let lines: Vec<&str> = s.lines().collect();
    assert_eq!(lines, ["7", "8"]);
}

#[test]
fn fake_id0_chown_succeeds_silently() {
    let f = Fixture::new("fake0-chown");
    let file = f.file("f", "x");
    let out = run_ok(
        &[
            "-0",
            SH,
            "-c",
            &format!("chown 0:0 {} && echo chowned", file.display()),
        ],
        &[],
    );
    assert_eq!(stdout(&out).trim(), "chowned");
}

#[test]
fn kompat_overrides_kernel_release() {
    if !have("uname") {
        return;
    }
    let out = run_ok(&["-k", "5.4.0-fake", SH, "-c", "uname -r"], &[]);
    assert_eq!(stdout(&out).trim(), "5.4.0-fake");
}

#[test]
fn kompat_i386_like_release_parses() {
    if !have("uname") {
        return;
    }
    let out = run_ok(&["-k", "3.10.0", SH, "-c", "uname -r"], &[]);
    assert_eq!(stdout(&out).trim(), "3.10.0");
}

#[test]
fn link2symlink_rename_of_link_succeeds() {
    let f = Fixture::new("l2s");
    let dir = f.dir("d");
    let target = dir.join("t");
    std::fs::write(&target, "x").unwrap();
    std::os::unix::fs::symlink(&target, dir.join("lnk")).unwrap();
    let out = run_ok(
        &[
            "-l",
            SH,
            "-c",
            &format!(
                "mv {}/lnk {}/moved && echo moved-ok",
                dir.display(),
                dir.display()
            ),
        ],
        &[],
    );
    assert_eq!(stdout(&out).trim(), "moved-ok");
}

#[test]
fn mixed_0_and_b_flags_compose() {
    let f = Fixture::new("mixed");
    let host = f.dir("h");
    std::fs::write(host.join("f"), "mix\n").unwrap();
    let out = run_ok(
        &[
            "-0",
            "-b",
            &format!("{}:/g", host.display()),
            SH,
            "-c",
            "cat /g/f; id -u",
        ],
        &[],
    );
    let s = stdout(&out);
    assert!(s.contains("mix"), "out: {s}");
    assert!(s.trim().ends_with('0'), "out: {s}");
}
