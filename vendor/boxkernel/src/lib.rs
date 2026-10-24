//! BoxKernel — a clean-room Rust re-implementation of PRoot:
//! user-space chroot, `mount --bind` and `binfmt_misc` built on ptrace(2).
//!
//! # Architecture overview
//!
//! A guest syscall flows: [`cli`] (setup) → [`tracee`] event loop
//! (`waitpid`/`ptrace` stops) → [`syscall`] translation pipeline →
//! [`path`] canonicalization + bindings → [`extension`] typed events →
//! [`execve`] for exec handling → [`sys`] as the sole libc/FFI
//! boundary. Tracee memory access goes through `tracee::mem`;
//! registers through `tracee::reg`; syscall numbers are decoded
//! ABI-aware via [`sysnum`].
//!
//! # Safety contract
//!
//! All `unsafe` is confined to [`sys`] (the only module allowed to
//! call libc) plus a few documented islands — `execve/elf.rs` union
//! accessors, `tracee/event.rs` kernel-struct reads,
//! `syscall/netlink.rs` `CStr::from_ptr`, and the freestanding
//! `loader/` sub-crate. There is no `static mut` and no `transmute`
//! anywhere; POD serialization goes through
//! `sys::as_bytes`/`sys::as_bytes_mut`.
//!
//! The behavioral specification is the C reference implementation —
//! [Termux PRoot 5.1.0](https://github.com/termux/proot) — validated
//! by running its integration suite against this binary.

pub mod arch;
pub mod cli;
pub mod execve;
pub mod extension;
pub mod fpath;
pub mod note;
pub mod path;
pub mod ptrace;
pub mod sys;
pub mod syscall;
pub mod sysnum;
pub mod tracee;

#[cfg(test)]
mod testutil;

/// Machine word of the *host* architecture PRoot runs on.
pub type Word = u64;

/// PRoot's notion of a path buffer: PATH_MAX bytes including the terminator.
pub const PATH_MAX: usize = 4096;

/// NAME_MAX as enforced by the canonicalizer.
pub const NAME_MAX: usize = 255;

/// Guest-visible mount point of the host rootfs in QEMU/mixed mode.
pub const HOST_ROOTFS: &str = "/host-rootfs";
