//! Bind mounts via `-b`: path translation, detranslation of symlink
//! targets and readlink results, symlink chains, edge cases.

mod common;
use common::*;

/// `-b` with a single path binds it to itself (accessible at the same
/// guest path); `-b h:g` exposes the host path at a guest path.
#[test]
fn bind_single_path_is_visible_at_same_path() {
    let f = Fixture::new("bind-self");
    let file = f.file("data.txt", "payload\n");
    let out = run_ok(
        &[
            "-b",
            &format!("{}", file.display()),
            SH,
            "-c",
            "cat \"$0\"",
            &format!("{}", file.display()),
        ],
        &[],
    );
    assert_eq!(stdout(&out), "payload\n");
}

#[test]
fn bind_host_path_appears_at_guest_path() {
    let f = Fixture::new("bind-hg");
    let host = f.dir("hostside");
    std::fs::write(host.join("secret.txt"), "hidden\n").unwrap();
    let out = run_ok(
        &[
            "-r",
            "/",
            "-b",
            &format!("{}:/guest", host.display()),
            SH,
            "-c",
            "cat /guest/secret.txt",
        ],
        &[],
    );
    assert_eq!(stdout(&out), "hidden\n");
}

#[test]
fn bind_detranslates_readlink_absolute_target() {
    // Regression: readlink on a symlink accessed *through* a binding
    // must print the guest path, not the host path.  The referer must
    // be outside the guestfs and share the target's host binding —
    // matching the C sanity rules.
    let f = rootfs("bind-rl");
    let host = Fixture::new("bind-rl-h");
    let hdir = host.dir("hdir");
    std::fs::write(hdir.join("t"), "x").unwrap();
    std::os::unix::fs::symlink(hdir.join("t"), hdir.join("L")).unwrap();

    let out = run_rooted_ok(
        &f,
        &["-b", &format!("{}:/ced", hdir.display())],
        "readlink /ced/L",
    );
    assert_eq!(stdout(&out).trim(), "/ced/t");
}

#[test]
fn bind_detranslates_readlink_guest_target() {
    // Same, but the link's content is already the *guest* path — the
    // result must stay `/ced/t`, not leak through to the host path.
    let f = rootfs("bind-rl2");
    let host = Fixture::new("bind-rl2-h");
    let hdir = host.dir("hdir");
    std::fs::write(hdir.join("t"), "x").unwrap();
    std::os::unix::fs::symlink("/ced/t", hdir.join("L")).unwrap();

    let out = run_rooted_ok(
        &f,
        &["-b", &format!("{}:/ced", hdir.display())],
        "readlink /ced/L",
    );
    assert_eq!(stdout(&out).trim(), "/ced/t");
}

#[test]
fn readlink_outside_binding_stays_host_shaped() {
    // A referer inside the guestfs does not trigger binding
    // detranslation (C parity: `!belongs_to_guestfs(referer)` gate).
    let f = rootfs("bind-rl3");
    let host = Fixture::new("bind-rl3-h");
    let hdir = host.dir("hdir");
    std::fs::write(hdir.join("t"), "x").unwrap();
    let linkdir = f.dir("in-rootfs");
    std::os::unix::fs::symlink(hdir.join("t"), linkdir.join("L")).unwrap();

    let out = run_rooted_ok(&f, &[], "readlink /in-rootfs/L || echo unreadable");
    // Either the raw (untranslated) host-ish path or an error — but
    // never a fabricated guest path.
    let s = stdout(&out);
    assert!(!s.trim().starts_with("/ced"), "out: {s}");
}

#[test]
fn bind_dir_listing_works() {
    let f = Fixture::new("bind-ls");
    let host = f.dir("hdir");
    std::fs::write(host.join("a"), "").unwrap();
    std::fs::write(host.join("b"), "").unwrap();
    let out = run_ok(
        &[
            "-r",
            "/",
            "-b",
            &format!("{}:/g", host.display()),
            SH,
            "-c",
            "ls /g | sort | tr '\\n' ' '",
        ],
        &[],
    );
    assert_eq!(stdout(&out).trim(), "a b");
}

#[test]
fn bind_write_through_creates_host_file() {
    let f = Fixture::new("bind-wr");
    let host = f.dir("hdir");
    let out = run_ok(
        &[
            "-r",
            "/",
            "-b",
            &format!("{}:/g", host.display()),
            SH,
            "-c",
            "echo made > /g/newfile && sync",
        ],
        &[],
    );
    assert_eq!(stdout(&out), "");
    assert_eq!(
        std::fs::read_to_string(host.join("newfile")).unwrap(),
        "made\n"
    );
}

#[test]
fn bind_missing_host_path_warns_but_continues() {
    // C parity: an unsanitizable binding is dropped with a warning,
    // not fatal.
    let out = run_ok(
        &["-b", "/definitely/missing/path", SH, "-c", "echo ok"],
        &[],
    );
    assert_eq!(stdout(&out).trim(), "ok");
    assert!(
        stderr(&out).contains("can't sanitize"),
        "stderr: {}",
        stderr(&out)
    );
}

#[test]
fn bind_does_not_hide_unbound_paths() {
    let f = Fixture::new("bind-iso");
    let outside = f.file("outside.txt", "out\n");
    let out = run_ok(
        &[
            "-r",
            "/",
            "-b",
            "/tmp:/nowhere-else",
            SH,
            "-c",
            &format!("cat {}", outside.display()),
        ],
        &[],
    );
    assert_eq!(stdout(&out), "out\n");
}

#[test]
fn deeper_binding_shadows_shallower() {
    let f = Fixture::new("bind-nest");
    let shallow = f.dir("shallow");
    let deep = f.dir("deep");
    std::fs::write(shallow.join("which"), "shallow\n").unwrap();
    std::fs::write(deep.join("which"), "deep\n").unwrap();
    let out = run_ok(
        &[
            "-r",
            "/",
            "-b",
            &format!("{}:/a", shallow.display()),
            "-b",
            &format!("{}:/a/b", deep.display()),
            SH,
            "-c",
            "cat /a/b/which",
        ],
        &[],
    );
    assert_eq!(stdout(&out), "deep\n");
}

#[test]
fn binding_inside_guest_rootfs() {
    let f = rootfs("bind-rootfs");
    let host = f.dir("hostdir");
    std::fs::write(host.join("f"), "via-rootfs\n").unwrap();
    let out = run_rooted_ok(
        &f,
        &["-b", &format!("{}:/mounted", host.display())],
        "cat /mounted/f",
    );
    assert_eq!(stdout(&out), "via-rootfs\n");
}
