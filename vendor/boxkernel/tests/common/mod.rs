//! Shared integration-test harness.
#![allow(dead_code)] // each test binary uses a different subset
//!
//! Tests spawn the real `proot` binary (`CARGO_BIN_EXE_proot`) and assert
//! on stdout/stderr/exit status.  Every run is wrapped in a watchdog: a
//! hung tracee is SIGKILLed and the test panics with captured output.
//!
//! Fixtures are plain temp dirs — symlink `bin -> /bin` gives a "rootfs"
//! whose commands resolve to the host's (canonicalization follows the
//! link), which is enough to run shells inside a confined root.

use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

/// The compiled binary under test.
pub const PROOT: &str = env!("CARGO_BIN_EXE_proot");

const TIMEOUT: Duration = Duration::from_secs(60);

/// Run `proot <args>` with `env` overrides; waits up to TIMEOUT.
pub fn run(args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(PROOT);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    // Keep the test env minimal and reproducible.
    cmd.env("PROOT_TMP_DIR", std::env::temp_dir());
    wait_with_output(&mut cmd, args)
}

/// Same, asserting exit status == 0.
pub fn run_ok(args: &[&str], env: &[(&str, &str)]) -> Output {
    let out = run(args, env);
    assert!(
        out.status.success(),
        "proot {:?} failed: {}\nstdout: {}\nstderr: {}",
        args,
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

/// Same, asserting exit status != 0.
pub fn run_fail(args: &[&str], env: &[(&str, &str)]) -> Output {
    let out = run(args, env);
    assert!(
        !out.status.success(),
        "proot {:?} unexpectedly succeeded\nstdout: {}\nstderr: {}",
        args,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

fn wait_with_output(cmd: &mut Command, args: &[&str]) -> Output {
    let mut child = cmd.spawn().unwrap_or_else(|e| panic!("spawn proot: {e}"));
    let deadline = Instant::now() + TIMEOUT;
    loop {
        match child.try_wait().unwrap() {
            Some(_) => return child.wait_with_output().unwrap(),
            None if Instant::now() > deadline => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("proot {:?} timed out after {:?}", args, TIMEOUT);
            }
            None => std::thread::sleep(Duration::from_millis(25)),
        }
    }
}

/// Command's stdout as a String (asserts UTF-8 loosely).
pub fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

pub fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

// ------------------------------------------------------------------
// Fixture
// ------------------------------------------------------------------

static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// RAII temp dir with builder helpers; removed on drop.
pub struct Fixture {
    pub root: PathBuf,
}

impl Fixture {
    pub fn new(tag: &str) -> Fixture {
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("proot-itest-{}-{}-{}", std::process::id(), n, tag));
        std::fs::create_dir_all(&root).unwrap();
        Fixture { root }
    }

    /// Root usable as a `-r` value (canonicalized).
    pub fn rootfs(&self) -> String {
        self.root
            .canonicalize()
            .unwrap()
            .to_string_lossy()
            .into_owned()
    }

    pub fn dir(&self, rel: &str) -> PathBuf {
        let p = self.root.join(rel);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    pub fn file(&self, rel: &str, content: &str) -> PathBuf {
        let p = self.root.join(rel);
        if let Some(d) = p.parent() {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::write(&p, content).unwrap();
        p
    }

    pub fn symlink(&self, target: &str, rel: &str) -> PathBuf {
        let p = self.root.join(rel);
        if let Some(d) = p.parent() {
            std::fs::create_dir_all(d).unwrap();
        }
        std::os::unix::fs::symlink(target, &p).unwrap();
        p
    }

    /// `str` form of the absolute path of `rel` inside the fixture.
    pub fn p(&self, rel: &str) -> String {
        self.root.join(rel).to_string_lossy().into_owned()
    }

    /// Canonicalized absolute path (what translated host paths look like).
    pub fn canon(&self, rel: &str) -> String {
        self.root
            .join(rel)
            .canonicalize()
            .unwrap()
            .to_string_lossy()
            .into_owned()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// A rootfs fixture with the standard empty mountpoint dirs.
pub fn rootfs(tag: &str) -> Fixture {
    let f = Fixture::new(tag);
    f.dir("bin");
    f.dir("etc");
    f.dir("tmp");
    f.dir("usr");
    f.dir("lib");
    f.dir("proc");
    f.dir("dev");
    f
}

/// Arg prefix for a confined guest: `-r rootfs` plus the host runtime
/// binds the dynamic loader needs, and a safe cwd.
pub fn rooted(f: &Fixture) -> Vec<String> {
    let mut v = vec![
        "-r".to_string(),
        f.rootfs(),
        "-b".to_string(),
        "/bin".to_string(),
        "-b".to_string(),
        "/lib".to_string(),
        "-b".to_string(),
        "/lib64".to_string(),
        "-b".to_string(),
        "/usr".to_string(),
        "-b".to_string(),
        "/proc".to_string(),
        "-b".to_string(),
        "/dev".to_string(),
        "-w".to_string(),
        "/".to_string(),
    ];
    // Keep ordering stable for debugging.
    v.shrink_to_fit();
    v
}

/// Run `sh -c <script>` inside the fixture's confined rootfs.
pub fn run_rooted(f: &Fixture, extra: &[&str], script: &str) -> Output {
    let mut args = rooted(f);
    for a in extra {
        args.push((*a).to_string());
    }
    args.push("/bin/sh".to_string());
    args.push("-c".to_string());
    args.push(script.to_string());
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    run(&refs, &[])
}

pub fn run_rooted_ok(f: &Fixture, extra: &[&str], script: &str) -> Output {
    let out = run_rooted(f, extra, script);
    assert!(
        out.status.success(),
        "rooted {script:?} failed: {}\nstdout: {}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

/// `which` on the host — skip helpers for tools that may not exist.
pub fn have(tool: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|d| d.join(tool).is_file()))
        .unwrap_or(false)
}

/// `/bin/sh` exists practically everywhere; everything else is checked
/// with `have` at test time.
pub const SH: &str = "/bin/sh";

/// chmod 0755 — `file()` fixtures need it before exec.
pub fn make_exec(p: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();
}
