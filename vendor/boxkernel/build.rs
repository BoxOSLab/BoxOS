//! Build script for BoxKernel.
//!
//! 1. Generates the neutral `Sysnum` enum from `data/sysnums.list`.
//! 2. Generates per-ABI syscall-number tables from `data/sysnums-<arch>.txt`
//!    (Linux syscall ABI assignments).
//! 3. Compiles the freestanding `loader` sub-crate into a static ELF that is
//!    embedded in the main binary via `include_bytes!`.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

    println!("cargo:rerun-if-changed=data/sysnums.list");
    for arch in ["x86_64", "i386", "x32", "arm64", "arm", "sh4"] {
        println!("cargo:rerun-if-changed=data/sysnums-{}.txt", arch);
    }
    println!("cargo:rerun-if-changed=loader/src/main.rs");
    println!("cargo:rerun-if-env-changed=PROOT_LOADER");

    generate_sysnums(&manifest_dir, &out_dir);
    build_loader(&manifest_dir, &out_dir);
}

/* ------------------------------------------------------------------ */
/* Sysnum tables                                                       */
/* ------------------------------------------------------------------ */

fn generate_sysnums(manifest_dir: &Path, out_dir: &Path) {
    let list_path = manifest_dir.join("data/sysnums.list");
    let list = fs::read_to_string(&list_path).expect("read sysnums.list");

    let mut names: Vec<String> = Vec::new();
    for line in list.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("SYSNUM(") {
            if let Some(name) = rest.strip_suffix(')') {
                names.push(name.to_string());
            }
        }
    }
    // `void` is the sentinel; it is a real enum variant but has no table entry.
    names.insert(0, "void".to_string());

    let mut src = String::new();
    src.push_str("/// Neutral (ABI-agnostic) syscall identifiers.\n");
    src.push_str("/// Variant names deliberately mirror kernel syscall names.\n");
    src.push_str("#[allow(non_camel_case_types)]\n");
    src.push_str("#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]\n");
    src.push_str("#[repr(u16)]\n");
    src.push_str("pub enum Sysnum {\n");
    src.push_str("    #[default]\n");
    for name in &names {
        src.push_str(&format!("    {},\n", rust_ident(name)));
    }
    src.push_str("}\n\n");
    src.push_str("pub const NB_SYSNUMS: usize = ");
    src.push_str(&names.len().to_string());
    src.push_str(";\n\n");
    src.push_str("impl Sysnum {\n    pub fn name(self) -> &'static str {\n        match self {\n");
    for name in &names {
        src.push_str(&format!(
            "            Sysnum::{} => \"{}\",\n",
            rust_ident(name),
            name
        ));
    }
    src.push_str("        }\n    }\n}\n\n");

    for (table_const, file) in [
        ("SYSNUMS_X86_64", "x86_64"),
        ("SYSNUMS_I386", "i386"),
        ("SYSNUMS_X32", "x32"),
        ("SYSNUMS_ARM64", "arm64"),
        ("SYSNUMS_ARM", "arm"),
        ("SYSNUMS_SH4", "sh4"),
    ] {
        let tbl_path = manifest_dir.join(format!("data/sysnums-{}.txt", file));
        let tbl = fs::read_to_string(&tbl_path)
            .unwrap_or_else(|e| panic!("read {}: {}", tbl_path.display(), e));
        let mut max = 0usize;
        let mut entries: Vec<(usize, String)> = Vec::new();
        for line in tbl.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let mut it = line.split_whitespace();
            let num: usize = it.next().unwrap().parse().unwrap();
            let name = it.next().unwrap().to_string();
            entries.push((num, name));
            if num > max {
                max = num;
            }
        }
        src.push_str(&format!(
            "pub static {}: [Sysnum; {}] = {{\n    let mut t = [Sysnum::Void; {}];\n",
            table_const,
            max + 1,
            max + 1
        ));
        for (num, name) in entries {
            src.push_str(&format!(
                "    t[{}] = Sysnum::{};\n",
                num,
                rust_ident(&name)
            ));
        }
        src.push_str("    t\n};\n\n");
    }

    fs::write(out_dir.join("sysnums.rs"), src).expect("write sysnums.rs");
}

fn rust_ident(name: &str) -> String {
    // Keep the original name as a snake_case-ish variant identifier.
    // Rust permits leading underscores; uppercase variants warn but work.
    const KEYWORDS: &[&str] = &[
        "as", "async", "await", "break", "const", "continue", "crate", "dyn", "else", "enum",
        "extern", "false", "fn", "for", "gen", "if", "impl", "in", "let", "loop", "match", "mod",
        "move", "mut", "pub", "ref", "return", "self", "Self", "static", "struct", "super",
        "trait", "true", "try", "type", "union", "unsafe", "use", "where", "while", "yield",
    ];
    if name == "void" {
        "Void".to_string()
    } else if name.chars().next().is_some_and(|c| c.is_ascii_digit()) || KEYWORDS.contains(&name) {
        format!("_{}", name)
    } else {
        name.to_string()
    }
}

/* ------------------------------------------------------------------ */
/* Loader                                                              */
/* ------------------------------------------------------------------ */

/// Compile `loader/` (a `#![no_std]`/`#![no_main]` freestanding crate) into a
/// static, non-PIE ELF at the fixed LOADER_ADDRESS, like the C version does
/// with -nostdlib/-static/-Ttext.  The produced ELF file is embedded whole.
fn build_loader(manifest_dir: &Path, out_dir: &Path) {
    let loader_out = out_dir.join("loader.exe");

    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();

    // Only the host-arch loader is required for the main binary; the optional
    // 32-bit variant is built when the toolchain supports it.
    let (text_addr, gnu_target): (u64, &str) = match target_arch.as_str() {
        "x86_64" => (0x6000_0000_0000, "x86_64-unknown-linux-gnu"),
        "aarch64" => (0x0020_0000_0000, "aarch64-unknown-linux-gnu"),
        "arm" => (0x2000_0000, "armv7-unknown-linux-gnueabihf"),
        "x86" => (0xa000_0000, "i686-unknown-linux-gnu"),
        _ => panic!("unsupported host architecture for loader: {}", target_arch),
    };
    // Android toolchains ship only the `*-linux-android` standard library;
    // the freestanding loader builds fine against its `core`.
    let rustc_target = if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("android") {
        env::var("TARGET").expect("TARGET is set for build scripts")
    } else {
        gnu_target.to_string()
    };
    // Cross builds need the linker Cargo resolved for the target.
    let linker = env::var("RUSTC_LINKER").ok();

    let loader_src = manifest_dir.join("loader/src/main.rs");
    let rustc = env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());

    let mut command = Command::new(&rustc);
    if let Some(linker) = &linker {
        command.arg(format!("-Clinker={}", linker));
    }
    let status = command
        .args([
            "--edition=2024",
            "--crate-type=bin",
            "-C",
            "panic=abort",
            "-C",
            "opt-level=2",
            "-C",
            "relocation-model=static",
            // The loader runs at a fixed 48-bit address: 32-bit relocations
            // would overflow.
            "-C",
            "code-model=large",
            "-C",
            "codegen-units=1",
            "-C",
            "debuginfo=0",
            "-C",
            &format!(
                "link-args=-static -nostdlib -Wl,--build-id=none,-z,noexecstack,-z,max-page-size=16384,-Ttext=0x{:x}",
                text_addr
            ),
            "--target",
            &rustc_target,
            "-o",
        ])
        .arg(&loader_out)
        .arg(&loader_src)
        .status()
        .expect("failed to run rustc for loader");

    if !status.success() {
        // A graceful degradation: embed an empty blob so the main crate still
        // builds; the runtime will report a clear error when the loader is
        // required (e.g. never for `skip_proot_loader` paths).
        fs::write(&loader_out, b"").expect("write empty loader blob");
        println!("cargo:warning=loader build failed; embedded loader is empty");
    }

    println!("cargo:rustc-env=LOADER_ELF_PATH={}", loader_out.display());
}
